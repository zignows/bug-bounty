"""Tests for finding-memory deduplication."""

import unittest

from arbiter.memory import FindingMemory, signature


class Signatures(unittest.TestCase):
    def test_stable(self):
        self.assertEqual(signature("authz", "d", "s"), signature("authz", "d", "s"))

    def test_differs_by_detail(self):
        self.assertNotEqual(signature("authz", "a"), signature("authz", "b"))

    def test_differs_by_scope(self):
        self.assertNotEqual(signature("authz", "d", "x"), signature("authz", "d", "y"))


class Memory(unittest.TestCase):
    def test_first_is_new_second_is_dup(self):
        m = FindingMemory()
        sig = signature("o", "d")
        self.assertTrue(m.register(sig))
        self.assertFalse(m.register(sig))

    def test_contains_and_len(self):
        m = FindingMemory()
        m.register(signature("o", "d"))
        self.assertIn(signature("o", "d"), m)
        self.assertEqual(len(m), 1)


if __name__ == "__main__":
    unittest.main()
