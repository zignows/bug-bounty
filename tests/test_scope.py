"""Tests for scope loading and limit validation."""

import os
import unittest

from arbiter.scope import Limits, Scope, from_dict, load_scope

CONFIG_DIR = os.path.join(os.path.dirname(__file__), "..", "config")


class ScopeLoading(unittest.TestCase):
    def test_load_json_example(self):
        scope = load_scope(os.path.join(CONFIG_DIR, "scope.example.json"))
        self.assertEqual(scope.name, "example-program")
        self.assertIn("example.com", scope.allowed_hosts)
        self.assertTrue(scope.passive_only)

    def test_requires_name(self):
        with self.assertRaises(ValueError):
            from_dict({"allowed_hosts": ["example.com"]})

    def test_defaults_are_conservative(self):
        scope = from_dict({"name": "x"})
        self.assertTrue(scope.passive_only)
        self.assertEqual(scope.allowed_schemes, ("https",))
        self.assertEqual(scope.allowed_ports, (443,))

    def test_hosts_lowercased(self):
        scope = from_dict({"name": "x", "allowed_hosts": ["Example.COM"]})
        self.assertEqual(scope.allowed_hosts, ("example.com",))

    def test_passive_is_default_even_if_absent(self):
        self.assertTrue(from_dict({"name": "x"}).passive_only)

    def test_with_active_testing_is_explicit_copy(self):
        scope = from_dict({"name": "x"})
        active = scope.with_active_testing()
        self.assertFalse(active.passive_only)
        self.assertTrue(scope.passive_only)  # original unchanged (frozen)


class LimitsValidation(unittest.TestCase):
    def test_rejects_non_positive(self):
        with self.assertRaises(ValueError):
            Limits(max_cost_usd=0)
        with self.assertRaises(ValueError):
            Limits(max_iterations=-1)

    def test_scope_is_frozen(self):
        scope = Scope(name="x")
        with self.assertRaises(Exception):
            scope.name = "y"  # type: ignore[misc]


if __name__ == "__main__":
    unittest.main()
