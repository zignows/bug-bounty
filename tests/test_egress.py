"""Tests for the egress gate (the enforcing proxy's decision core)."""

import unittest

from arbiter.egress import EgressGate, PerHostRateLimiter
from arbiter.scope import Scope, Limits

SCOPE = Scope(
    name="t",
    allowed_hosts=("example.com", "*.example.com"),
    allowed_schemes=("https",),
    allowed_ports=(443,),
    passive_only=True,
)

RESOLV = {
    "example.com": ["93.184.216.34"],
    "api.example.com": ["93.184.216.34"],
    "rebind.example.com": ["10.0.0.5"],          # resolves to private (rebinding)
    "meta.example.com": ["169.254.169.254"],     # resolves to metadata
    "empty.example.com": [],
}


class FakeClock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


def gate(scope=SCOPE, clock=None):
    rl = PerHostRateLimiter(scope.limits.max_requests_per_second, clock=clock or FakeClock())
    return EgressGate(scope, resolver=lambda h: RESOLV.get(h, []), rate_limiter=rl)


class Passive(unittest.TestCase):
    def test_get_allowed_and_pins_ip(self):
        d = gate().check("GET", "https://example.com/x")
        self.assertTrue(d.allowed)
        self.assertEqual(d.pinned_ip, "93.184.216.34")

    def test_post_denied_in_passive(self):
        d = gate().check("POST", "https://example.com/x")
        self.assertTrue(d.denied)
        self.assertEqual(d.rule, "method_requires_active")

    def test_head_options_allowed(self):
        g = gate()
        self.assertTrue(g.check("HEAD", "https://example.com/a").allowed)
        # different path/host avoids rate-limit on same host+clock
        self.assertTrue(g.check("OPTIONS", "https://api.example.com/b").allowed)


class Active(unittest.TestCase):
    def test_post_allowed_when_scope_active(self):
        active_scope = SCOPE.with_active_testing()
        d = gate(active_scope).check("POST", "https://example.com/x", active=True)
        self.assertTrue(d.allowed)

    def test_active_flag_ignored_if_scope_passive(self):
        # caller asks for active but scope is passive-only -> still blocked
        d = gate().check("POST", "https://example.com/x", active=True)
        self.assertTrue(d.denied)
        self.assertEqual(d.rule, "method_requires_active")


class DnsAndRebinding(unittest.TestCase):
    def test_private_resolution_blocked(self):
        d = gate().check("GET", "https://rebind.example.com/x")
        self.assertTrue(d.denied)
        self.assertEqual(d.rule, "ip_private")

    def test_metadata_resolution_blocked(self):
        d = gate().check("GET", "https://meta.example.com/x")
        self.assertTrue(d.denied)
        self.assertEqual(d.rule, "ip_metadata")

    def test_empty_resolution_denied(self):
        d = gate().check("GET", "https://empty.example.com/x")
        self.assertTrue(d.denied)
        self.assertEqual(d.rule, "dns_empty")

    def test_resolver_error_is_denial(self):
        def boom(_):
            raise RuntimeError("resolver down")
        g = EgressGate(SCOPE, resolver=boom)
        d = g.check("GET", "https://example.com/x")
        self.assertTrue(d.denied)
        self.assertEqual(d.rule, "dns_error")


class ScopeAndRedirect(unittest.TestCase):
    def test_offscope_host_denied(self):
        d = gate().check("GET", "https://evil.test/x")
        self.assertTrue(d.denied)
        self.assertEqual(d.rule, "host_not_allowed")

    def test_redirect_offscope_denied(self):
        d = gate().check_redirect("GET", "https://evil.test/", "https://example.com/")
        self.assertTrue(d.denied)

    def test_redirect_relative_rechecked_and_allowed(self):
        d = gate().check_redirect("GET", "/next", "https://example.com/start")
        self.assertTrue(d.allowed)


class RateLimit(unittest.TestCase):
    def test_second_immediate_request_rate_limited(self):
        clock = FakeClock()
        g = gate(clock=clock)
        self.assertTrue(g.check("GET", "https://example.com/a").allowed)
        self.assertEqual(g.check("GET", "https://example.com/b").rule, "rate_limited")

    def test_allowed_after_interval(self):
        clock = FakeClock()
        g = gate(clock=clock)
        self.assertTrue(g.check("GET", "https://example.com/a").allowed)
        clock.t = 1.0  # default limit is 1 req/s -> 1s interval
        self.assertTrue(g.check("GET", "https://example.com/b").allowed)

    def test_rate_limit_is_per_host(self):
        clock = FakeClock()
        g = gate(clock=clock)
        self.assertTrue(g.check("GET", "https://example.com/a").allowed)
        self.assertTrue(g.check("GET", "https://api.example.com/a").allowed)  # different host


if __name__ == "__main__":
    unittest.main()
