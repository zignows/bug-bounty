"""Tests for the control plane skeleton."""

import unittest

from arbiter.audit import AuditEventType
from arbiter.budget import StopReason
from arbiter.controlplane import ApprovalStatus, ControlPlane
from arbiter.evidence import EvidenceStore
from arbiter.records import ArbiterDecision, Analysis, Role, VulnClass
from arbiter.scope import Scope, Limits
from arbiter.states import State


def fresh():
    store = EvidenceStore()
    eid = store.record("OBSERVATION", "recon", "signal").id
    cp = ControlPlane(Scope(name="t"), store)
    return cp, eid


def decide(hid, target, eid, rationale="because"):
    return ArbiterDecision(hid, target, (eid,), rationale)


class Investigations(unittest.TestCase):
    def test_open_is_idempotent_and_audited(self):
        cp, _ = fresh()
        a = cp.open_investigation("h1")
        b = cp.open_investigation("h1")
        self.assertIs(a, b)
        self.assertEqual(len(cp.audit.of_type(AuditEventType.INVESTIGATION_OPENED)), 1)

    def test_record_valid_analysis(self):
        cp, _ = fresh()
        res = cp.record_analysis(Analysis("h1", Role.OTIMISTA, VulnClass.IDOR,
                                          "claim", evidence_ids=("ev_x",)))
        self.assertTrue(res.ok)
        self.assertEqual(len(cp.get("h1").analyses), 1)

    def test_record_invalid_analysis_rejected(self):
        cp, _ = fresh()
        res = cp.record_analysis(Analysis("h1", Role.CETICO, VulnClass.IDOR,
                                          "claim", evidence_ids=("ev_x",)))  # no benign
        self.assertFalse(res.ok)
        self.assertEqual(cp.get("h1").analyses, [])


class Decisions(unittest.TestCase):
    def test_happy_transition_audited(self):
        cp, eid = fresh()
        res = cp.apply_arbiter_decision(
            decide("h1", State.APROVADA_PARA_VALIDACAO, eid))
        self.assertTrue(res.ok)
        self.assertEqual(cp.get("h1").state, State.APROVADA_PARA_VALIDACAO)
        self.assertEqual(len(cp.audit.of_type(AuditEventType.STATE_TRANSITION)), 1)

    def test_no_evidence_rejected_state_unchanged(self):
        cp, _ = fresh()
        res = cp.apply_arbiter_decision(
            ArbiterDecision("h1", State.APROVADA_PARA_VALIDACAO, (), "x"))
        self.assertFalse(res.ok)
        self.assertEqual(cp.get("h1").state, State.PROPOSTA)
        self.assertTrue(cp.audit.of_type(AuditEventType.DECISION_REJECTED))

    def test_illegal_transition_rejected(self):
        cp, eid = fresh()
        res = cp.apply_arbiter_decision(decide("h1", State.CONFIRMADA, eid))
        self.assertFalse(res.ok)

    def test_mais_evidencia_round_limited(self):
        cp, eid = fresh()
        self.assertTrue(cp.apply_arbiter_decision(decide("h1", State.MAIS_EVIDENCIA, eid)).ok)
        self.assertTrue(cp.apply_arbiter_decision(decide("h1", State.PROPOSTA, eid)).ok)
        res = cp.apply_arbiter_decision(decide("h1", State.MAIS_EVIDENCIA, eid))
        self.assertFalse(res.ok)
        self.assertTrue(any("round limit" in p for p in res.problems))


class ApprovalGate(unittest.TestCase):
    def _to_approval_state(self, cp, eid):
        cp.apply_arbiter_decision(decide("h1", State.APROVADA_PARA_VALIDACAO, eid))

    def test_cannot_validate_actively_by_default(self):
        cp, eid = fresh()
        self._to_approval_state(cp, eid)
        self.assertFalse(cp.can_validate_actively("h1"))

    def test_request_only_in_right_state(self):
        cp, _ = fresh()  # still PROPOSTA
        res = cp.request_validation_approval("h1", "plan-1")
        self.assertFalse(res.ok)

    def test_full_approval_flow_enables_active(self):
        cp, eid = fresh()
        self._to_approval_state(cp, eid)
        self.assertTrue(cp.request_validation_approval("h1", "plan-1").ok)
        self.assertEqual(cp.get("h1").approval, ApprovalStatus.PENDING)
        self.assertFalse(cp.can_validate_actively("h1"))  # pending != granted
        self.assertTrue(cp.grant_validation_approval("h1", "operator").ok)
        self.assertTrue(cp.can_validate_actively("h1"))

    def test_deny_blocks_active(self):
        cp, eid = fresh()
        self._to_approval_state(cp, eid)
        cp.request_validation_approval("h1", "plan-1")
        cp.deny_validation_approval("h1", "operator")
        self.assertFalse(cp.can_validate_actively("h1"))

    def test_grant_without_request_fails(self):
        cp, eid = fresh()
        self._to_approval_state(cp, eid)
        self.assertFalse(cp.grant_validation_approval("h1", "operator").ok)


class Budget(unittest.TestCase):
    def test_charge_audits_and_reports_stop(self):
        store = EvidenceStore()
        cp = ControlPlane(Scope(name="t", limits=Limits(max_cost_usd=1.0)), store)
        self.assertIs(cp.charge("h1", 0.5), StopReason.NONE)
        self.assertIs(cp.charge("h1", 0.6), StopReason.COST)
        self.assertTrue(cp.audit.of_type(AuditEventType.STOP_TRIGGERED))
        self.assertEqual(len(cp.audit.of_type(AuditEventType.BUDGET_CHARGE)), 2)


if __name__ == "__main__":
    unittest.main()
