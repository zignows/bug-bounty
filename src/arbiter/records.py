"""Reasoning records: Analysis, ArbiterDecision, ValidationRecord.

These are the structured outputs the agents must produce (provider-
agnostic: whatever model backs a role, the control plane only accepts
this shape). The check_* functions encode two invariants in code, not in
a prompt:

  * the Skeptic must offer at least one benign explanation;
  * an Arbiter decision is accepted only if the transition is legal AND it
    cites evidence that actually exists ("no evidence -> rejected").

All records are immutable.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .evidence import EvidenceStore
from .states import State, can_transition


class VulnClass(str, Enum):
    IDOR = "IDOR"
    XSS_REFLECTED = "XSS_REFLECTED"
    XSS_STORED = "XSS_STORED"
    XSS_DOM = "XSS_DOM"
    XSS_BLIND = "XSS_BLIND"
    BUSINESS_INVARIANT = "BUSINESS_INVARIANT"
    PROTOCOL = "PROTOCOL"
    OTHER = "OTHER"


class Role(str, Enum):
    OTIMISTA = "OTIMISTA"
    CETICO = "CETICO"


class Confidence(str, Enum):
    BAIXA = "BAIXA"
    MEDIA = "MEDIA"
    ALTA = "ALTA"


@dataclass(frozen=True)
class Analysis:
    """One blind analysis by the Optimist or the Skeptic."""

    hypothesis_id: str
    author_role: Role
    vuln_class: VulnClass
    claim: str
    evidence_ids: tuple[str, ...] = ()
    benign_explanations: tuple[str, ...] = ()
    confidence: Confidence = Confidence.BAIXA
    what_would_confirm: tuple[str, ...] = ()
    what_would_refute: tuple[str, ...] = ()


@dataclass(frozen=True)
class ArbiterDecision:
    """The Arbiter's evidence-cited decision on a hypothesis."""

    hypothesis_id: str
    target_state: State
    motivating_evidence_ids: tuple[str, ...]
    rationale: str


@dataclass(frozen=True)
class ValidationRecord:
    """What the Validator actually did, under an approved limited plan."""

    hypothesis_id: str
    approved_plan_ref: str
    reproducible: bool
    actions: tuple[str, ...] = ()
    observations: tuple[str, ...] = ()
    generated_evidence_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class CheckResult:
    ok: bool
    problems: tuple[str, ...] = ()


def validate_analysis(a: Analysis) -> CheckResult:
    problems: list[str] = []
    if not a.claim.strip():
        problems.append("claim is empty")
    if not a.evidence_ids:
        problems.append("analysis cites no evidence")
    if a.author_role is Role.CETICO and not a.benign_explanations:
        problems.append("skeptic must list at least one benign explanation")
    return CheckResult(not problems, tuple(problems))


def check_decision(
    current: State,
    decision: ArbiterDecision,
    store: EvidenceStore,
) -> CheckResult:
    """Validate an Arbiter decision against the state machine and evidence.

    (Human-gate approvals are a separate record type and are not governed
    by this evidence requirement — this is for the Arbiter specifically.)
    """
    problems: list[str] = []
    if not can_transition(current, decision.target_state):
        problems.append(
            f"illegal transition {current.value} -> {decision.target_state.value}"
        )
    if not decision.motivating_evidence_ids:
        problems.append("decision cites no evidence")
    missing = [e for e in decision.motivating_evidence_ids if e not in store]
    if missing:
        problems.append(f"cited evidence not in store: {sorted(missing)}")
    if not decision.rationale.strip():
        problems.append("rationale is empty")
    return CheckResult(not problems, tuple(problems))
