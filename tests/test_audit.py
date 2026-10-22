"""Tests for the append-only audit log."""

import unittest
from datetime import datetime, timezone

from arbiter.audit import AuditEvent, AuditEventType, AuditLog

FIXED = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)


class Log(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog(now=FIXED)

    def test_seq_increments(self):
        a = self.log.append(AuditEventType.INVESTIGATION_OPENED, "h1")
        b = self.log.append(AuditEventType.STATE_TRANSITION, "h1", "A -> B")
        self.assertEqual((a.seq, b.seq), (0, 1))

    def test_timestamp_iso(self):
        e = self.log.append(AuditEventType.INVESTIGATION_OPENED, "h1")
        self.assertEqual(e.at, "2026-01-02T03:04:05+00:00")

    def test_entries_is_tuple_snapshot(self):
        self.log.append(AuditEventType.INVESTIGATION_OPENED, "h1")
        snap = self.log.entries()
        self.assertIsInstance(snap, tuple)
        self.log.append(AuditEventType.STATE_TRANSITION, "h1", "x")
        self.assertEqual(len(snap), 1)  # old snapshot unchanged
        self.assertEqual(len(self.log), 2)

    def test_of_type_filter(self):
        self.log.append(AuditEventType.INVESTIGATION_OPENED, "h1")
        self.log.append(AuditEventType.STATE_TRANSITION, "h1", "x")
        self.log.append(AuditEventType.STATE_TRANSITION, "h2", "y")
        self.assertEqual(len(self.log.of_type(AuditEventType.STATE_TRANSITION)), 2)

    def test_for_subject_filter(self):
        self.log.append(AuditEventType.INVESTIGATION_OPENED, "h1")
        self.log.append(AuditEventType.INVESTIGATION_OPENED, "h2")
        self.assertEqual(len(self.log.for_subject("h1")), 1)

    def test_event_is_frozen(self):
        e = self.log.append(AuditEventType.INVESTIGATION_OPENED, "h1")
        with self.assertRaises(Exception):
            e.detail = "mutated"  # type: ignore[misc]

    def test_accepts_string_event_type(self):
        e = self.log.append("STATE_TRANSITION", "h1", "A -> B")
        self.assertEqual(e.type, AuditEventType.STATE_TRANSITION)


if __name__ == "__main__":
    unittest.main()
