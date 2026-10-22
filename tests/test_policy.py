"""Adversarial tests for the policy engine (scope-as-code).

Run from the repo root with:  PYTHONPATH=src python3 -m unittest -v
"""

import unittest

from arbiter.policy import (
    Decision,
    check_redirect,
    check_target,
    host_matches,
    ip_is_blocked,
)
from arbiter.scope import from_dict

SCOPE = from_dict({
    "name": "t",
    "allowed_hosts": ["example.com", "*.example.com"],
    "excluded_hosts": ["internal.example.com"],
    "third_party_denylist": ["cdn.thirdparty-example.net"],
    "allowed_schemes": ["https"],
    "allowed_ports": [443],
})


class HostMatching(unittest.TestCase):
    def test_exact(self):
        self.assertTrue(host_matches("example.com", "example.com"))

    def test_case_insensitive(self):
        self.assertTrue(host_matches("Example.COM", "example.com"))

    def test_wildcard_matches_sub(self):
        self.assertTrue(host_matches("a.example.com", "*.example.com"))
        self.assertTrue(host_matches("a.b.example.com", "*.example.com"))

    def test_wildcard_does_not_match_apex(self):
        self.assertFalse(host_matches("example.com", "*.example.com"))

    def test_wildcard_does_not_match_sibling_suffix(self):
        # the classic bypass: notexample.com must not match *.example.com
        self.assertFalse(host_matches("notexample.com", "*.example.com"))

    def test_trailing_dot_normalized(self):
        self.assertTrue(host_matches("example.com.", "example.com"))


class IpBlocking(unittest.TestCase):
    def test_metadata_v4_blocked(self):
        self.assertTrue(ip_is_blocked("169.254.169.254").denied)
        self.assertEqual(ip_is_blocked("169.254.169.254").rule, "ip_metadata")

    def test_link_local_blocked(self):
        self.assertTrue(ip_is_blocked("169.254.10.10").denied)

    def test_private_ranges_blocked(self):
        for ip in ("10.0.0.5", "192.168.1.1", "172.16.9.9"):
            self.assertTrue(ip_is_blocked(ip).denied, ip)

    def test_loopback_blocked(self):
        self.assertTrue(ip_is_blocked("127.0.0.1").denied)
        self.assertTrue(ip_is_blocked("::1").denied)

    def test_ipv6_unique_local_blocked(self):
        self.assertTrue(ip_is_blocked("fd00::1").denied)

    def test_public_allowed(self):
        self.assertTrue(ip_is_blocked("93.184.216.34").allowed)

    def test_garbage_denied(self):
        self.assertTrue(ip_is_blocked("not-an-ip").denied)


class TargetChecking(unittest.TestCase):
    def test_in_scope_apex(self):
        self.assertTrue(check_target(SCOPE, "https://example.com/").allowed)

    def test_in_scope_sub(self):
        self.assertTrue(check_target(SCOPE, "https://api.example.com/v1").allowed)

    def test_http_scheme_denied(self):
        d = check_target(SCOPE, "http://example.com/")
        self.assertTrue(d.denied)
        self.assertEqual(d.rule, "scheme_not_allowed")

    def test_offscope_host_denied(self):
        self.assertTrue(check_target(SCOPE, "https://evil.test/").denied)

    def test_excluded_host_denied(self):
        d = check_target(SCOPE, "https://internal.example.com/")
        self.assertTrue(d.denied)
        self.assertEqual(d.rule, "host_excluded")

    def test_third_party_denied(self):
        d = check_target(SCOPE, "https://cdn.thirdparty-example.net/app.js")
        self.assertTrue(d.denied)
        self.assertEqual(d.rule, "third_party")

    def test_bad_port_denied(self):
        d = check_target(SCOPE, "https://example.com:8443/")
        self.assertTrue(d.denied)
        self.assertEqual(d.rule, "port_not_allowed")

    def test_raw_ip_target_denied(self):
        d = check_target(SCOPE, "https://93.184.216.34/")
        self.assertTrue(d.denied)
        self.assertEqual(d.rule, "host_is_ip")

    def test_exclusion_beats_wildcard_allow(self):
        # internal.example.com matches *.example.com but is excluded
        self.assertTrue(check_target(SCOPE, "https://internal.example.com/x").denied)


class RedirectChecking(unittest.TestCase):
    def test_relative_redirect_stays_in_scope(self):
        d = check_redirect(SCOPE, "/next", "https://example.com/start")
        self.assertTrue(d.allowed)

    def test_absolute_offscope_redirect_denied(self):
        d = check_redirect(SCOPE, "https://evil.test/", "https://example.com/")
        self.assertTrue(d.denied)

    def test_absolute_inscope_redirect_allowed(self):
        d = check_redirect(SCOPE, "https://api.example.com/", "https://example.com/")
        self.assertTrue(d.allowed)


class DecisionShape(unittest.TestCase):
    def test_denied_property(self):
        self.assertTrue(Decision(False, "r", "d").denied)
        self.assertFalse(Decision(True, "r", "d").denied)


if __name__ == "__main__":
    unittest.main()
