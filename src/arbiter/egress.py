"""Egress gate — the decision core of the enforcing proxy.

This is the application-level half of the scope enforcement: every outbound
request a (future) proxy would forward is first run through here. It reuses
the policy engine and adds the parts that only make sense at request time:

  * method safety in passive mode (only read methods unless the scope is
    explicitly in active mode);
  * DNS re-resolution + IP blocking, returning the resolved IP the caller
    MUST pin the connection to (anti-DNS-rebinding: resolve, check, then
    connect to that same IP — never re-resolve for the actual connection);
  * per-host rate limiting.

It performs NO network itself: DNS resolution is injected (a callable
host -> list of IPs) so this stays deterministic and testable. The real
proxy supplies a real resolver and the socket plumbing, and a kernel-level
firewall (see deploy/) is the second, independent barrier.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit
import time

from .policy import check_redirect, check_target, ip_is_blocked
from .scope import Scope

# Methods considered read-only / non-state-changing; allowed in passive mode.
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


@dataclass(frozen=True)
class EgressDecision:
    allowed: bool
    rule: str
    detail: str
    pinned_ip: str = ""   # the IP the connection MUST use (anti-rebinding)

    @property
    def denied(self) -> bool:
        return not self.allowed


class PerHostRateLimiter:
    """Minimum-interval limiter per host (requests/sec). Injectable clock.

    Only advances a host's clock when a request is actually allowed, so a
    burst of denied attempts does not reset the window.
    """

    def __init__(self, max_rps: float, clock=time.monotonic) -> None:
        self.min_interval = (1.0 / max_rps) if max_rps and max_rps > 0 else 0.0
        self._clock = clock
        self._last: dict[str, float] = {}

    def allow(self, host: str) -> bool:
        now = self._clock()
        last = self._last.get(host)
        if last is not None and (now - last) < self.min_interval:
            return False
        self._last[host] = now
        return True


class EgressGate:
    def __init__(self, scope: Scope, resolver, rate_limiter: PerHostRateLimiter | None = None) -> None:
        self.scope = scope
        self._resolve = resolver  # callable: host -> iterable[str]
        self.rate = rate_limiter or PerHostRateLimiter(scope.limits.max_requests_per_second)

    def _active_allowed(self, requested_active: bool) -> bool:
        # A passive-only scope is a hard gate: even if the caller asks for
        # active, methods stay restricted until the scope itself is active.
        return bool(requested_active) and not self.scope.passive_only

    def check(self, method: str, url: str, *, active: bool = False) -> EgressDecision:
        d = check_target(self.scope, url)
        if d.denied:
            return EgressDecision(False, d.rule, d.detail)

        if method.upper() not in SAFE_METHODS and not self._active_allowed(active):
            return EgressDecision(
                False, "method_requires_active",
                f"{method.upper()} is state-changing; needs active mode + approval",
            )

        host = (urlsplit(url).hostname or "").lower()
        try:
            ips = [str(ip) for ip in (self._resolve(host) or [])]
        except Exception as exc:  # resolver failure is a denial, never a bypass
            return EgressDecision(False, "dns_error", f"{host}: {exc}")
        if not ips:
            return EgressDecision(False, "dns_empty", f"no address for {host}")

        for ip in ips:
            blocked = ip_is_blocked(ip)
            if blocked.denied:
                return EgressDecision(
                    False, blocked.rule,
                    f"{host} resolves to blocked {ip} ({blocked.detail})",
                )
        pinned = ips[0]

        if not self.rate.allow(host):
            return EgressDecision(False, "rate_limited", f"rate limit exceeded for {host}")

        return EgressDecision(
            True, "egress_allowed", f"{method.upper()} {url} via {pinned}", pinned_ip=pinned
        )

    def check_redirect(self, method: str, location: str, from_url: str, *, active: bool = False) -> EgressDecision:
        d = check_redirect(self.scope, location, from_url)
        if d.denied:
            return EgressDecision(False, d.rule, d.detail)
        if d.rule == "redirect_relative":
            # same origin as from_url, already in scope; re-run full egress
            # on the resolved absolute form to re-check DNS/IP and rate.
            base = urlsplit(from_url)
            target = f"{base.scheme}://{base.netloc}{location}"
            return self.check(method, target, active=active)
        return self.check(method, location, active=active)
