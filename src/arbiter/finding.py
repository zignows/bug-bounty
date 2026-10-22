"""Finding summary — the factual output for the operator's OWN triage.

The system surfaces *what was found*, as facts: the vulnerability class,
the affected endpoint(s), the oracle's factual statement of the defect, the
computed CVSS severity, the cited evidence, and the actual recorded steps
that reproduced it. It deliberately does NOT write a report: no AI prose,
no invented impact or remediation narrative, no model-rated severity
(severity is computed from the CVSS vector). The operator reads these facts
and does the triage and the write-up themselves.
"""

from __future__ import annotations

from dataclasses import dataclass

from .common import CheckResult
from .evidence import EvidenceStore
from .oracles.cvss import score_vector
from .records import VulnClass


@dataclass(frozen=True)
class Finding:
    hypothesis_id: str
    vuln_class: VulnClass
    affected: tuple[str, ...]
    detail: str                        # the oracle's factual statement (not AI prose)
    cvss_vector: str
    base_score: float
    severity: str
    evidence_ids: tuple[str, ...]
    observed_steps: tuple[str, ...] = ()   # recorded actions/observations (facts)


def build_finding(
    *,
    hypothesis_id: str,
    vuln_class,
    affected,
    detail: str,
    cvss_vector: str,
    evidence_ids,
    observed_steps=(),
) -> Finding:
    scored = score_vector(cvss_vector)  # validates the vector; severity computed
    return Finding(
        hypothesis_id=hypothesis_id,
        vuln_class=VulnClass(vuln_class),
        affected=tuple(affected),
        detail=detail,
        cvss_vector=cvss_vector,
        base_score=scored.base_score,
        severity=scored.severity,
        evidence_ids=tuple(evidence_ids),
        observed_steps=tuple(observed_steps),
    )


def validate_finding(f: Finding, store: EvidenceStore | None = None) -> CheckResult:
    problems: list[str] = []
    if not f.affected:
        problems.append("no affected endpoint")
    if not f.detail.strip():
        problems.append("no factual detail")
    if not f.evidence_ids:
        problems.append("cites no evidence")
    if store is not None:
        missing = [e for e in f.evidence_ids if e not in store]
        if missing:
            problems.append(f"cited evidence not in store: {sorted(missing)}")
    return CheckResult(not problems, tuple(problems))


def render_summary(f: Finding) -> str:
    """A concise, factual summary for the operator's triage. Facts only."""
    lines = [
        f"[{f.severity}] {f.vuln_class.value}  (CVSS {f.base_score}  {f.cvss_vector})",
        f"affected: {', '.join(f.affected)}",
        f"finding:  {f.detail}",
    ]
    if f.observed_steps:
        lines.append("observed:")
        lines += [f"  {i}. {s}" for i, s in enumerate(f.observed_steps, 1)]
    lines.append("evidence: " + ", ".join(f.evidence_ids))
    lines.append("(facts only — triage and write-up are the operator's; "
                 "nothing here is AI-generated)")
    return "\n".join(lines)
