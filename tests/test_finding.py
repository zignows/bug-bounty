"""Tests for the factual finding summary."""

import unittest

from arbiter.evidence import EvidenceStore
from arbiter.records import VulnClass
from arbiter.finding import build_finding, render_summary, validate_finding


def a_finding(**over):
    base = dict(
        hypothesis_id="h1",
        vuln_class=VulnClass.IDOR,
        affected=("https://api.example.com/orders/1042",),
        detail="authz differential: identity=B resource=order:1042 "
               "intended=DENIED observed=ALLOWED -> UNAUTHORIZED_ACCESS",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        evidence_ids=("ev_1",),
        observed_steps=("as B, GET /api/orders/1042", "received A's order body"),
    )
    base.update(over)
    return build_finding(**base)


class Build(unittest.TestCase):
    def test_severity_computed(self):
        f = a_finding()
        self.assertEqual(f.base_score, 6.5)
        self.assertEqual(f.severity, "Medium")

    def test_invalid_vector_rejected(self):
        with self.assertRaises(Exception):
            a_finding(cvss_vector="CVSS:3.1/AV:Z/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N")


class Validate(unittest.TestCase):
    def test_valid_ok(self):
        self.assertTrue(validate_finding(a_finding()).ok)

    def test_no_evidence_rejected(self):
        self.assertFalse(validate_finding(a_finding(evidence_ids=())).ok)

    def test_no_detail_rejected(self):
        self.assertFalse(validate_finding(a_finding(detail="   ")).ok)

    def test_no_affected_rejected(self):
        self.assertFalse(validate_finding(a_finding(affected=())).ok)

    def test_evidence_must_exist_in_store(self):
        store = EvidenceStore()
        self.assertFalse(validate_finding(a_finding(evidence_ids=("ev_ghost",)), store).ok)

    def test_evidence_present_in_store_ok(self):
        store = EvidenceStore()
        ev = store.record("DIFFERENTIAL", "validator", "repro")
        self.assertTrue(validate_finding(a_finding(evidence_ids=(ev.id,)), store).ok)


class Render(unittest.TestCase):
    def test_summary_is_factual(self):
        s = render_summary(a_finding())
        self.assertIn("[Medium] IDOR", s)
        self.assertIn("CVSS 6.5", s)
        self.assertIn("UNAUTHORIZED_ACCESS", s)   # the oracle's own statement
        self.assertIn("observed:", s)
        self.assertIn("evidence:", s)
        self.assertIn("AI-generated", s)          # the facts-only disclaimer

    def test_no_prose_fields(self):
        # a finding carries no free-prose impact/mitigation that an AI would write
        f = a_finding()
        self.assertFalse(hasattr(f, "impact"))
        self.assertFalse(hasattr(f, "mitigation"))
        self.assertFalse(hasattr(f, "summary"))


if __name__ == "__main__":
    unittest.main()
