"""Tests for the evidence model and store."""

import unittest
from datetime import datetime, timezone

from arbiter.evidence import (
    Evidence,
    EvidenceKind,
    EvidenceStore,
    make_evidence,
    sha256_hex,
)

FIXED = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)


class MakeEvidence(unittest.TestCase):
    def test_content_addressed_id_is_stable(self):
        a = make_evidence("OBSERVATION", "recon", "hello", now=FIXED)
        b = make_evidence("OBSERVATION", "recon", "hello", now=FIXED)
        self.assertEqual(a.id, b.id)

    def test_different_content_different_id(self):
        a = make_evidence("OBSERVATION", "recon", "hello", now=FIXED)
        b = make_evidence("OBSERVATION", "recon", "world", now=FIXED)
        self.assertNotEqual(a.id, b.id)

    def test_different_kind_different_id(self):
        a = make_evidence("OBSERVATION", "recon", "x", now=FIXED)
        b = make_evidence("HTTP_EXCHANGE", "recon", "x", now=FIXED)
        self.assertNotEqual(a.id, b.id)

    def test_hash_matches_content(self):
        ev = make_evidence("OBSERVATION", "recon", "hello", now=FIXED)
        self.assertEqual(ev.content_sha256, sha256_hex("hello"))

    def test_created_at_is_iso_utc(self):
        ev = make_evidence("OBSERVATION", "recon", "x", now=FIXED)
        self.assertEqual(ev.created_at, "2026-01-02T03:04:05+00:00")

    def test_bytes_and_str_equivalent(self):
        a = make_evidence("OBSERVATION", "recon", "x", now=FIXED)
        b = make_evidence("OBSERVATION", "recon", b"x", now=FIXED)
        self.assertEqual(a.content_sha256, b.content_sha256)

    def test_meta_is_sorted_tuple(self):
        ev = make_evidence("OBSERVATION", "recon", "x", meta={"b": "2", "a": "1"}, now=FIXED)
        self.assertEqual(ev.meta, (("a", "1"), ("b", "2")))

    def test_rejects_non_text_content(self):
        with self.assertRaises(TypeError):
            make_evidence("OBSERVATION", "recon", 123, now=FIXED)

    def test_evidence_is_frozen(self):
        ev = make_evidence("OBSERVATION", "recon", "x", now=FIXED)
        with self.assertRaises(Exception):
            ev.summary = "y"  # type: ignore[misc]


class Store(unittest.TestCase):
    def setUp(self):
        self.store = EvidenceStore()

    def test_record_and_get(self):
        ev = self.store.record("OBSERVATION", "recon", "hello", now=FIXED)
        self.assertIn(ev.id, self.store)
        self.assertEqual(self.store.get(ev.id).summary, "")

    def test_dedup_idempotent(self):
        self.store.record("OBSERVATION", "recon", "hello", now=FIXED)
        self.store.record("OBSERVATION", "recon", "hello", now=FIXED)
        self.assertEqual(len(self.store), 1)

    def test_verify_integrity(self):
        ev = self.store.record("OBSERVATION", "recon", "hello", now=FIXED)
        self.assertTrue(self.store.verify(ev.id, "hello"))
        self.assertFalse(self.store.verify(ev.id, "tampered"))

    def test_collision_with_different_content_raises(self):
        ev = make_evidence("OBSERVATION", "recon", "hello", now=FIXED)
        # forge a record reusing the id but with a different hash
        forged = Evidence(
            id=ev.id,
            kind=EvidenceKind.OBSERVATION,
            source="x",
            created_at=ev.created_at,
            content_sha256=sha256_hex("different"),
            summary="",
        )
        self.store.add(ev)
        with self.assertRaises(ValueError):
            self.store.add(forged)

    def test_missing_id_not_contained(self):
        self.assertNotIn("ev_doesnotexist", self.store)


if __name__ == "__main__":
    unittest.main()
