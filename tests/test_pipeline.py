"""Tests for the analysis pipeline (wiring)."""

import unittest

from arbiter.ingest import captured
from arbiter.pipeline import AnalysisPipeline
from arbiter.oracles.authz_matrix import (
    AuthorizationMatrix,
    Identity,
    Intent,
    Observed,
    Resource,
)
from arbiter.oracles.business_invariant import (
    RequiresPrecedingSuccess,
    Flow,
    step,
)


def authz_matrix():
    m = AuthorizationMatrix()
    m.add_identity(Identity("B"))
    m.add_resource(Resource("order:1042"))
    m.set_intent("B", "order:1042", Intent.DENIED)
    return m


class Exchange(unittest.TestCase):
    def test_protocol_and_reflection_leads(self):
        p = AnalysisPipeline()
        ex = captured("GET", "https://example.com/s?q=<b>x</b>",
                      response_body="echo <b>x</b>",
                      response_headers=[("Set-Cookie", "sid=1")])
        leads = p.analyze_exchange(ex)
        oracles = {l.oracle for l in leads}
        self.assertIn("protocol", oracles)       # cookie flags
        self.assertIn("reflected-xss", oracles)
        # each lead recorded evidence
        for l in leads:
            self.assertIn(l.evidence_id, p.evidence)

    def test_dedup_across_calls(self):
        p = AnalysisPipeline()
        ex = captured("GET", "https://example.com/",
                      response_headers=[("Set-Cookie", "sid=1")])
        first = p.analyze_exchange(ex)
        self.assertTrue(first)
        second = p.analyze_exchange(ex)   # identical -> nothing new
        self.assertEqual(second, [])


class Authz(unittest.TestCase):
    def test_idor_lead(self):
        p = AnalysisPipeline()
        leads = p.analyze_authz(authz_matrix(), {("B", "order:1042"): Observed.ALLOWED})
        self.assertEqual(len(leads), 1)
        self.assertEqual(leads[0].oracle, "authz")
        self.assertIn("UNAUTHORIZED_ACCESS", leads[0].detail)

    def test_no_lead_when_denied(self):
        p = AnalysisPipeline()
        leads = p.analyze_authz(authz_matrix(), {("B", "order:1042"): Observed.DENIED})
        self.assertEqual(leads, [])


class Invariant(unittest.TestCase):
    def test_payment_bypass_lead(self):
        p = AnalysisPipeline()
        f = Flow(steps=(step("use_credits"),))   # consumed without charge
        leads = p.analyze_flow(f, [RequiresPrecedingSuccess("use_credits", "charge")])
        self.assertEqual(len(leads), 1)
        self.assertEqual(leads[0].oracle, "business-invariant")


if __name__ == "__main__":
    unittest.main()
