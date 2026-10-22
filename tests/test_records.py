"""Tests for reasoning records and their invariants."""

import unittest

from arbiter.evidence import EvidenceStore
from arbiter.records import (
    Analysis,
    ArbiterDecision,
    Confidence,
    Role,
    VulnClass,
    check_decision,
    validate_analysis,
)
from arbiter.states import State


def _store_with_one():
    store = EvidenceStore()
    ev = store.record("OBSERVATION", "recon", "signal", summary="a signal")
    return store, ev.id


class AnalysisValidation(unittest.TestCase):
    def test_optimist_ok_with_evidence(self):
        a = Analysis(
            hypothesis_id="h1",
            author_role=Role.OTIMISTA,
            vuln_class=VulnClass.IDOR,
            claim="object accessible across users",
            evidence_ids=("ev_x",),
            confidence=Confidence.MEDIA,
        )
        self.assertTrue(validate_analysis(a).ok)

    def test_empty_claim_fails(self):
        a = Analysis("h1", Role.OTIMISTA, VulnClass.IDOR, "  ", evidence_ids=("ev_x",))
        self.assertFalse(validate_analysis(a).ok)

    def test_no_evidence_fails(self):
        a = Analysis("h1", Role.OTIMISTA, VulnClass.IDOR, "claim")
        self.assertFalse(validate_analysis(a).ok)

    def test_skeptic_requires_benign_explanation(self):
        a = Analysis(
            "h1", Role.CETICO, VulnClass.IDOR, "claim", evidence_ids=("ev_x",)
        )
        res = validate_analysis(a)
        self.assertFalse(res.ok)
        self.assertTrue(any("benign" in p for p in res.problems))

    def test_skeptic_ok_with_benign_explanation(self):
        a = Analysis(
            "h1", Role.CETICO, VulnClass.IDOR, "claim",
            evidence_ids=("ev_x",),
            benign_explanations=("could be a public resource by design",),
        )
        self.assertTrue(validate_analysis(a).ok)


class DecisionChecking(unittest.TestCase):
    def test_valid_decision(self):
        store, eid = _store_with_one()
        d = ArbiterDecision(
            hypothesis_id="h1",
            target_state=State.APROVADA_PARA_VALIDACAO,
            motivating_evidence_ids=(eid,),
            rationale="differential shows cross-user access",
        )
        self.assertTrue(check_decision(State.PROPOSTA, d, store).ok)

    def test_no_evidence_rejected_by_code(self):
        store, _ = _store_with_one()
        d = ArbiterDecision("h1", State.APROVADA_PARA_VALIDACAO, (), "because")
        res = check_decision(State.PROPOSTA, d, store)
        self.assertFalse(res.ok)
        self.assertTrue(any("no evidence" in p for p in res.problems))

    def test_cited_evidence_must_exist(self):
        store, _ = _store_with_one()
        d = ArbiterDecision(
            "h1", State.APROVADA_PARA_VALIDACAO, ("ev_ghost",), "because"
        )
        res = check_decision(State.PROPOSTA, d, store)
        self.assertFalse(res.ok)
        self.assertTrue(any("not in store" in p for p in res.problems))

    def test_illegal_transition_rejected(self):
        store, eid = _store_with_one()
        d = ArbiterDecision("h1", State.CONFIRMADA, (eid,), "jumping ahead")
        res = check_decision(State.PROPOSTA, d, store)
        self.assertFalse(res.ok)
        self.assertTrue(any("illegal transition" in p for p in res.problems))

    def test_empty_rationale_rejected(self):
        store, eid = _store_with_one()
        d = ArbiterDecision("h1", State.REJEITADA, (eid,), "   ")
        self.assertFalse(check_decision(State.PROPOSTA, d, store).ok)


if __name__ == "__main__":
    unittest.main()
