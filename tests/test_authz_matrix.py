"""Tests for the authorization-matrix oracle (IDOR / BOLA)."""

import unittest

from arbiter.oracles.authz_matrix import (
    AuthorizationMatrix,
    Identity,
    Intent,
    Observed,
    Resource,
    ViolationKind,
    find_violations,
    security_violations,
    to_evidence_content,
)


def matrix_AB():
    m = AuthorizationMatrix()
    m.add_identity(Identity("A", "owner"))
    m.add_identity(Identity("B", "other user"))
    m.add_identity(Identity("anon", "unauthenticated"))
    m.add_resource(Resource("order:1042", "A's order"))
    m.set_intent("A", "order:1042", Intent.ALLOWED)
    m.set_intent("B", "order:1042", Intent.DENIED)
    m.set_intent("anon", "order:1042", Intent.DENIED)
    return m


class Building(unittest.TestCase):
    def test_set_intent_requires_known_identity(self):
        m = AuthorizationMatrix()
        m.add_resource(Resource("r1"))
        with self.assertRaises(KeyError):
            m.set_intent("ghost", "r1", Intent.DENIED)

    def test_set_intent_requires_known_resource(self):
        m = AuthorizationMatrix()
        m.add_identity(Identity("A"))
        with self.assertRaises(KeyError):
            m.set_intent("A", "ghost", Intent.ALLOWED)

    def test_get_intent(self):
        m = matrix_AB()
        self.assertIs(m.get_intent("B", "order:1042"), Intent.DENIED)
        self.assertIsNone(m.get_intent("A", "nonexistent"))


class Violations(unittest.TestCase):
    def test_idor_detected(self):
        m = matrix_AB()
        obs = {("B", "order:1042"): Observed.ALLOWED}  # B should NOT read it
        v = find_violations(m, obs)
        self.assertEqual(len(v), 1)
        self.assertIs(v[0].kind, ViolationKind.UNAUTHORIZED_ACCESS)
        self.assertTrue(v[0].is_security)

    def test_no_violation_when_denied_as_intended(self):
        m = matrix_AB()
        obs = {("B", "order:1042"): Observed.DENIED}
        self.assertEqual(find_violations(m, obs), [])

    def test_owner_allowed_is_not_a_violation(self):
        m = matrix_AB()
        obs = {("A", "order:1042"): Observed.ALLOWED}
        self.assertEqual(find_violations(m, obs), [])

    def test_unexpected_denial_is_flagged_not_security(self):
        m = matrix_AB()
        obs = {("A", "order:1042"): Observed.DENIED}  # owner wrongly blocked
        v = find_violations(m, obs)
        self.assertEqual(len(v), 1)
        self.assertIs(v[0].kind, ViolationKind.UNEXPECTED_DENIAL)
        self.assertFalse(v[0].is_security)

    def test_unknown_and_missing_observations_skipped(self):
        m = matrix_AB()
        obs = {("B", "order:1042"): Observed.UNKNOWN}
        self.assertEqual(find_violations(m, obs), [])
        self.assertEqual(find_violations(m, {}), [])

    def test_string_observed_coerced(self):
        m = matrix_AB()
        v = find_violations(m, {("B", "order:1042"): "ALLOWED"})
        self.assertEqual(len(v), 1)

    def test_security_first_ordering(self):
        m = matrix_AB()
        obs = {
            ("A", "order:1042"): Observed.DENIED,   # unexpected denial
            ("anon", "order:1042"): Observed.ALLOWED,  # unauthorized access
        }
        v = find_violations(m, obs)
        self.assertIs(v[0].kind, ViolationKind.UNAUTHORIZED_ACCESS)  # security first
        self.assertEqual(len(security_violations(v)), 1)

    def test_evidence_content_describes_differential(self):
        m = matrix_AB()
        v = find_violations(m, {("B", "order:1042"): Observed.ALLOWED})[0]
        text = to_evidence_content(v)
        self.assertIn("identity=B", text)
        self.assertIn("resource=order:1042", text)
        self.assertIn("UNAUTHORIZED_ACCESS", text)


if __name__ == "__main__":
    unittest.main()
