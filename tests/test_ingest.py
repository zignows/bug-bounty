"""Tests for the proxy-agnostic ingestion boundary."""

import unittest

from arbiter.evidence import EvidenceKind, EvidenceStore
from arbiter.ingest import captured, exchange_to_evidence


class Capture(unittest.TestCase):
    def test_headers_normalized_and_sorted(self):
        ex = captured("get", "https://example.com/",
                      request_headers={"X-B": "2", "X-A": "1"})
        self.assertEqual(ex.request_headers, (("x-a", "1"), ("x-b", "2")))

    def test_summary(self):
        ex = captured("GET", "https://example.com/", status=200)
        self.assertEqual(ex.summary(), "GET https://example.com/ -> 200")

    def test_summary_unknown_status(self):
        self.assertIn("-> ?", captured("GET", "https://example.com/").summary())

    def test_canonical_contains_request_and_response(self):
        ex = captured("POST", "https://example.com/a", status=201,
                      request_body="hello", response_body="world")
        c = ex.canonical()
        self.assertIn("POST https://example.com/a", c)
        self.assertIn("hello", c)
        self.assertIn("HTTP 201", c)
        self.assertIn("world", c)


class ToEvidence(unittest.TestCase):
    def setUp(self):
        self.store = EvidenceStore()

    def test_records_http_exchange_evidence(self):
        ex = captured("GET", "https://example.com/", status=200, source="caido")
        ev = exchange_to_evidence(ex, self.store)
        self.assertEqual(ev.kind, EvidenceKind.HTTP_EXCHANGE)
        self.assertTrue(ev.replayable)
        self.assertEqual(ev.source, "caido")
        self.assertIn(ev.id, self.store)

    def test_identical_exchange_dedups(self):
        ex = captured("GET", "https://example.com/", status=200)
        a = exchange_to_evidence(ex, self.store)
        b = exchange_to_evidence(captured("GET", "https://example.com/", status=200), self.store)
        self.assertEqual(a.id, b.id)
        self.assertEqual(len(self.store), 1)

    def test_different_body_distinct_evidence(self):
        a = exchange_to_evidence(captured("GET", "https://x.example.com/", response_body="a"), self.store)
        b = exchange_to_evidence(captured("GET", "https://x.example.com/", response_body="b"), self.store)
        self.assertNotEqual(a.id, b.id)

    def test_evidence_verifies_against_canonical(self):
        ex = captured("GET", "https://example.com/", status=200)
        ev = exchange_to_evidence(ex, self.store)
        self.assertTrue(self.store.verify(ev.id, ex.canonical()))


if __name__ == "__main__":
    unittest.main()
