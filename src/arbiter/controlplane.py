"""Control plane skeleton (deterministic, no LLM, no network).

Ties the state machine, evidence, reasoning records, budget governor and
audit log together to drive a single hypothesis's investigation. It is the
*only* thing that transitions state, spends budget and records approvals.

Invariants enforced here (in code, not by prompt):

  * An Arbiter decision is applied only if it passes records.check_decision
    (legal transition + cited evidence that exists).
  * At most one MAIS_EVIDENCIA round and one REVISAO_HUMANA round.
  * Active validation is impossible without a human approval that was
    requested in APROVADA_PARA_VALIDACAO and then granted. Passive is the
    default; the granted approval is the explicit, audited opt-in.
  * Every outcome (applied, rejected, transition, approval, charge, stop)
    is written to the append-only audit log.

The agent runner (where LLM-backed roles plug in) is intentionally not
here yet; this skeleton is the control surface those agents will call.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from .audit import AuditEventType, AuditLog
from .budget import BudgetGovernor, StopReason
from .common import CheckResult
from .evidence import EvidenceStore
from .records import Analysis, ArbiterDecision, check_decision, validate_analysis
from .scope import Scope
from .states import INITIAL, State

MAX_MAIS_EVIDENCIA_ROUNDS = 1
MAX_REVISAO_HUMANA_ROUNDS = 1


class ApprovalStatus(str, Enum):
    NOT_REQUESTED = "NOT_REQUESTED"
    PENDING = "PENDING"
    GRANTED = "GRANTED"
    DENIED = "DENIED"


@dataclass
class Investigation:
    hypothesis_id: str
    state: State = INITIAL
    mais_evidencia_rounds: int = 0
    revisao_humana_rounds: int = 0
    approval: ApprovalStatus = ApprovalStatus.NOT_REQUESTED
    approver: str = ""
    plan_ref: str = ""
    analyses: list = field(default_factory=list)


class ControlPlane:
    def __init__(
        self,
        scope: Scope,
        evidence_store: EvidenceStore,
        *,
        knowledge_store=None,
        audit: AuditLog | None = None,
        budget: BudgetGovernor | None = None,
    ) -> None:
        self.scope = scope
        self.evidence = evidence_store
        self.knowledge = knowledge_store
        self.audit = audit or AuditLog()
        self.budget = budget or BudgetGovernor(scope.limits)
        self._inv: dict[str, Investigation] = {}

    # -- investigations -----------------------------------------------------

    def open_investigation(self, hid: str) -> Investigation:
        inv = self._inv.get(hid)
        if inv is None:
            inv = Investigation(hypothesis_id=hid)
            self._inv[hid] = inv
            self.audit.append(AuditEventType.INVESTIGATION_OPENED, hid)
        return inv

    def get(self, hid: str) -> Investigation | None:
        return self._inv.get(hid)

    # -- reasoning ----------------------------------------------------------

    def record_analysis(self, analysis: Analysis) -> CheckResult:
        inv = self.open_investigation(analysis.hypothesis_id)
        res = validate_analysis(analysis)
        if res.ok:
            inv.analyses.append(analysis)
            self.audit.append(
                AuditEventType.ANALYSIS_RECORDED, analysis.hypothesis_id,
                f"{analysis.author_role.value}:{analysis.vuln_class.value}",
            )
        else:
            self.audit.append(
                AuditEventType.DECISION_REJECTED, analysis.hypothesis_id,
                "invalid analysis: " + "; ".join(res.problems),
            )
        return res

    def apply_arbiter_decision(self, decision: ArbiterDecision) -> CheckResult:
        inv = self.open_investigation(decision.hypothesis_id)
        res = check_decision(inv.state, decision, self.evidence)
        problems = list(res.problems)

        if (decision.target_state is State.MAIS_EVIDENCIA
                and inv.mais_evidencia_rounds >= MAX_MAIS_EVIDENCIA_ROUNDS):
            problems.append("MAIS_EVIDENCIA round limit reached (max 1)")
        if (decision.target_state is State.REVISAO_HUMANA
                and inv.revisao_humana_rounds >= MAX_REVISAO_HUMANA_ROUNDS):
            problems.append("REVISAO_HUMANA round limit reached (max 1)")

        if problems:
            self.audit.append(
                AuditEventType.DECISION_REJECTED, decision.hypothesis_id,
                "; ".join(problems),
            )
            return CheckResult(False, tuple(problems))

        prev = inv.state
        inv.state = decision.target_state
        if decision.target_state is State.MAIS_EVIDENCIA:
            inv.mais_evidencia_rounds += 1
        if decision.target_state is State.REVISAO_HUMANA:
            inv.revisao_humana_rounds += 1

        self.audit.append(
            AuditEventType.DECISION_APPLIED, decision.hypothesis_id, decision.rationale
        )
        self.audit.append(
            AuditEventType.STATE_TRANSITION, decision.hypothesis_id,
            f"{prev.value} -> {inv.state.value}",
        )
        return CheckResult(True, ())

    # -- human approval gate (for ACTIVE validation) ------------------------

    def request_validation_approval(self, hid: str, plan_ref: str) -> CheckResult:
        inv = self.open_investigation(hid)
        if inv.state is not State.APROVADA_PARA_VALIDACAO:
            msg = (f"approval can only be requested in APROVADA_PARA_VALIDACAO "
                   f"(now {inv.state.value})")
            self.audit.append(AuditEventType.DECISION_REJECTED, hid, msg)
            return CheckResult(False, (msg,))
        inv.approval = ApprovalStatus.PENDING
        inv.plan_ref = str(plan_ref)
        self.audit.append(AuditEventType.APPROVAL_REQUESTED, hid, str(plan_ref))
        return CheckResult(True, ())

    def grant_validation_approval(self, hid: str, approver: str) -> CheckResult:
        inv = self.open_investigation(hid)
        if inv.approval is not ApprovalStatus.PENDING:
            return CheckResult(False, (f"no pending approval for {hid}",))
        inv.approval = ApprovalStatus.GRANTED
        inv.approver = str(approver)
        self.audit.append(AuditEventType.APPROVAL_GRANTED, hid, f"by {approver}")
        return CheckResult(True, ())

    def deny_validation_approval(self, hid: str, approver: str) -> CheckResult:
        inv = self.open_investigation(hid)
        if inv.approval is not ApprovalStatus.PENDING:
            return CheckResult(False, (f"no pending approval for {hid}",))
        inv.approval = ApprovalStatus.DENIED
        inv.approver = str(approver)
        self.audit.append(AuditEventType.APPROVAL_DENIED, hid, f"by {approver}")
        return CheckResult(True, ())

    def can_validate_actively(self, hid: str) -> bool:
        inv = self._inv.get(hid)
        return bool(
            inv
            and inv.state is State.APROVADA_PARA_VALIDACAO
            and inv.approval is ApprovalStatus.GRANTED
        )

    # -- budget passthrough with audit --------------------------------------

    def charge(self, hid: str, cost_usd: float = 0.0, requests: int = 0) -> StopReason:
        reason = self.budget.charge(cost_usd, requests)
        self.audit.append(
            AuditEventType.BUDGET_CHARGE, hid, f"cost={cost_usd} req={requests}"
        )
        if reason is not StopReason.NONE:
            self.audit.append(AuditEventType.STOP_TRIGGERED, hid, reason.value)
        return reason
