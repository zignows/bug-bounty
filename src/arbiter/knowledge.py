"""Knowledge layer — curated, cited, and treated as UNTRUSTED data.

Two kinds of knowledge feed the system:

  * NORMATIVE_SPEC  — a citable requirement from a spec (RFC/WHATWG),
    used mainly by the Skeptic to confirm or *refute* protocol claims
    ("this is expected behavior per <clause>").
  * DISCLOSED_REPORT — a disclosed example (e.g. from the hackerone-reports
    corpus) distilled into fields, used to *generate hypotheses*, never to
    copy-and-run payloads.

Non-negotiable contracts, enforced structurally:

  1. Every entry is UNTRUSTED data. It can never alter policy/scope or act
     as an instruction to the agents. This module only emits data.
  2. Retrieval returns the KNOWLEDGE (the distilled fields), not just a URL
     — provenance (incl. the URL) travels with it for citation.
  3. Curation > volume: only `curated` entries are served for hypothesis
     generation by default. Uncurated entries may be stored but are held
     back until vetted.
  4. Redistribution requires known provenance (source URL + license).

Bulk ingestion of a corpus (e.g. reddelexc/hackerone-reports) is a later,
separate step and is gated on the license/dedup decision; see
knowledge/README.md. This module is the shape and the store it lands in.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib

from .common import CheckResult
from .records import VulnClass

TRUST_UNTRUSTED = "untrusted"


class KnowledgeKind(str, Enum):
    NORMATIVE_SPEC = "NORMATIVE_SPEC"
    DISCLOSED_REPORT = "DISCLOSED_REPORT"


class RequirementLevel(str, Enum):
    MUST = "MUST"
    MUST_NOT = "MUST_NOT"
    SHOULD = "SHOULD"
    SHOULD_NOT = "SHOULD_NOT"
    MAY = "MAY"


@dataclass(frozen=True)
class Provenance:
    source_url: str
    source_name: str = ""
    date: str = ""            # ISO date of the source, when known
    license: str = ""         # SPDX id or short text; required to redistribute
    retrieved_at: str = ""    # when it was ingested


@dataclass(frozen=True)
class SpecAssertion:
    id: str
    clause_ref: str           # e.g. "RFC9110 §15.4.3"
    requirement_level: RequirementLevel
    text: str
    topic: str                # e.g. "redirect", "cookies", "cors"
    provenance: Provenance
    tags: tuple[str, ...] = ()
    kind: KnowledgeKind = KnowledgeKind.NORMATIVE_SPEC
    curated: bool = True      # normative text is curated by nature
    trust: str = TRUST_UNTRUSTED


@dataclass(frozen=True)
class ReportKnowledge:
    id: str
    vuln_class: VulnClass
    title: str
    preconditions: tuple[str, ...] = ()
    root_cause: str = ""
    observable_signals: tuple[str, ...] = ()
    supporting_evidence: tuple[str, ...] = ()
    impact: str = ""
    false_positives: tuple[str, ...] = ()
    mitigation: str = ""
    provenance: Provenance = Provenance(source_url="")
    tags: tuple[str, ...] = ()
    kind: KnowledgeKind = KnowledgeKind.DISCLOSED_REPORT
    curated: bool = False     # a report must be vetted before it is served
    trust: str = TRUST_UNTRUSTED


KnowledgeEntry = SpecAssertion | ReportKnowledge


def _norm_tags(tags) -> tuple[str, ...]:
    return tuple(sorted({str(t).lower().strip() for t in (tags or ()) if str(t).strip()}))


def _hid(prefix: str, *parts: str) -> str:
    digest = hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:16]
    return f"{prefix}{digest}"


def make_spec_assertion(
    clause_ref: str,
    requirement_level,
    text: str,
    topic: str,
    provenance: Provenance,
    tags=(),
) -> SpecAssertion:
    return SpecAssertion(
        id=_hid("kn_spec_", clause_ref, text),
        clause_ref=clause_ref,
        requirement_level=RequirementLevel(requirement_level),
        text=text,
        topic=topic.lower(),
        provenance=provenance,
        tags=_norm_tags(tags),
    )


def make_report_knowledge(
    vuln_class,
    title: str,
    provenance: Provenance,
    *,
    preconditions=(),
    root_cause: str = "",
    observable_signals=(),
    supporting_evidence=(),
    impact: str = "",
    false_positives=(),
    mitigation: str = "",
    tags=(),
    curated: bool = False,
) -> ReportKnowledge:
    vc = VulnClass(vuln_class)
    return ReportKnowledge(
        id=_hid("kn_rpt_", provenance.source_url, title),
        vuln_class=vc,
        title=title,
        preconditions=tuple(preconditions),
        root_cause=root_cause,
        observable_signals=tuple(observable_signals),
        supporting_evidence=tuple(supporting_evidence),
        impact=impact,
        false_positives=tuple(false_positives),
        mitigation=mitigation,
        provenance=provenance,
        tags=_norm_tags(tags),
        curated=curated,
    )


def validate_entry(entry: KnowledgeEntry) -> CheckResult:
    """Redistribution requires known provenance (source URL + license)."""
    problems: list[str] = []
    prov = entry.provenance
    if not prov.source_url.strip():
        problems.append("missing provenance.source_url")
    if not prov.license.strip():
        problems.append("missing provenance.license (required to redistribute)")
    if isinstance(entry, ReportKnowledge) and not entry.root_cause.strip():
        problems.append("report knowledge should distill a root_cause, not just a link")
    return CheckResult(not problems, tuple(problems))


class KnowledgeStore:
    """In-memory knowledge store with dedup and a curation gate.

    Retrieval returns the distilled entries themselves — never a bare URL.
    """

    def __init__(self) -> None:
        self._by_id: dict[str, KnowledgeEntry] = {}

    def add(self, entry: KnowledgeEntry) -> str:
        self._by_id.setdefault(entry.id, entry)   # idempotent dedup by id
        return entry.id

    def get(self, kid: str) -> KnowledgeEntry | None:
        return self._by_id.get(kid)

    def __contains__(self, kid: str) -> bool:
        return kid in self._by_id

    def __len__(self) -> int:
        return len(self._by_id)

    def query(
        self,
        *,
        kind: KnowledgeKind | None = None,
        vuln_class: VulnClass | None = None,
        tags=(),
        curated_only: bool = True,
    ) -> list[KnowledgeEntry]:
        want_tags = set(_norm_tags(tags))
        out: list[KnowledgeEntry] = []
        for e in self._by_id.values():
            if curated_only and not e.curated:
                continue
            if kind is not None and e.kind != kind:
                continue
            if vuln_class is not None and getattr(e, "vuln_class", None) != vuln_class:
                continue
            if want_tags and not want_tags.intersection(e.tags):
                continue
            out.append(e)
        return sorted(out, key=lambda e: e.id)


def render_for_prompt(entry: KnowledgeEntry) -> str:
    """Render an entry as distilled knowledge text + a citation line.

    The point (vs. naive RAG) is that this returns the KNOWLEDGE, not a
    pointer. The source appears only as a citation, labeled untrusted.
    """
    cite = f"[source: {entry.provenance.source_url or 'unknown'} | {entry.trust}]"
    if isinstance(entry, SpecAssertion):
        return (
            f"{entry.clause_ref} ({entry.requirement_level.value}): {entry.text}\n{cite}"
        )
    parts = [f"{entry.vuln_class.value}: {entry.title}"]
    if entry.root_cause:
        parts.append(f"root cause: {entry.root_cause}")
    if entry.observable_signals:
        parts.append("signals: " + "; ".join(entry.observable_signals))
    if entry.false_positives:
        parts.append("false positives: " + "; ".join(entry.false_positives))
    if entry.impact:
        parts.append(f"impact: {entry.impact}")
    parts.append(cite)
    return "\n".join(parts)
