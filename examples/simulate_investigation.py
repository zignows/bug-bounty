"""Deterministic simulation of one investigation driven by the control plane.

No network, no LLM — canned analyses/decisions stand in for the agents, to
show the control surface and the audit trail end to end. Run with:

    PYTHONPATH=src python3 examples/simulate_investigation.py
"""

from arbiter.controlplane import ControlPlane
from arbiter.evidence import EvidenceStore
from arbiter.knowledge import KnowledgeStore
from arbiter.records import (
    Analysis,
    ArbiterDecision,
    Confidence,
    Role,
    VulnClass,
)
from arbiter.scope import load_scope
from arbiter.states import State

HID = "h-idor-001"


def main() -> None:
    scope = load_scope("config/scope.example.json")
    evidence = EvidenceStore()
    cp = ControlPlane(scope, evidence, knowledge_store=KnowledgeStore())

    # 1) Recon recorded an observation (captured by the proxy in real runs).
    ev = evidence.record(
        "DIFFERENTIAL", "recon",
        "GET /api/orders/1042 returns user B's order for user A's session",
        summary="cross-user object access signal",
    )

    cp.open_investigation(HID)

    # 2) Optimist and Skeptic file blind analyses.
    cp.record_analysis(Analysis(
        HID, Role.OTIMISTA, VulnClass.IDOR,
        claim="order object id is accepted without an ownership check",
        evidence_ids=(ev.id,),
        confidence=Confidence.MEDIA,
        what_would_confirm=("user A reads user B's order reproducibly",),
    ))
    cp.record_analysis(Analysis(
        HID, Role.CETICO, VulnClass.IDOR,
        claim="possible IDOR, but confirm it is not a shared/public resource",
        evidence_ids=(ev.id,),
        benign_explanations=("endpoint may expose intentionally public orders",),
        what_would_refute=("same id returns 403 for a second distinct account",),
    ))

    # 3) Arbiter approves for validation, citing the evidence.
    cp.apply_arbiter_decision(ArbiterDecision(
        HID, State.APROVADA_PARA_VALIDACAO, (ev.id,),
        rationale="differential shows cross-user read; benign explanation not supported",
    ))

    # 4) Human approval gate for ACTIVE validation.
    cp.request_validation_approval(HID, plan_ref="read-only confirm with test accounts A/B")
    print("can validate actively (pending)?", cp.can_validate_actively(HID))
    cp.grant_validation_approval(HID, approver="operator")
    print("can validate actively (granted)?", cp.can_validate_actively(HID))

    # 5) Validation produced reproducible evidence -> confirm -> report.
    ev2 = evidence.record(
        "DIFFERENTIAL", "validator",
        "reproduced: A reads B's order; B's id returns 403 to a third account",
        summary="reproducible cross-user read", replayable=True,
    )
    cp.apply_arbiter_decision(ArbiterDecision(
        HID, State.CONFIRMADA, (ev.id, ev2.id),
        rationale="reproducible differential; benign explanation refuted",
    ))
    cp.apply_arbiter_decision(ArbiterDecision(
        HID, State.RELATORIO_PRONTO, (ev2.id,),
        rationale="evidence reviewed and reproducible",
    ))

    print(f"\nfinal state: {cp.get(HID).state.value}")
    print("\n--- audit log ---")
    for e in cp.audit.entries():
        print(f"{e.seq:>2} {e.type.value:<22} {e.subject:<10} {e.detail}")


if __name__ == "__main__":
    main()
