"""Policy engine — scope-as-code.

Pure, deterministic, offline decision functions. Given a Scope and a
candidate (a URL, a resolved IP, or a redirect target), it returns an
auditable allow/deny Decision. It performs NO network activity: DNS
resolution is the caller's job, and the resolved IP is passed back in
for checking (this is where anti-DNS-rebinding is enforced — resolve,
then check the actual IP, then connect to that same IP).

Default posture is deny. A target is allowed only if it affirmatively
matches the scope and trips none of the hard blocks.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit
import ipaddress

from .scope import Scope


@dataclass(frozen=True)
class Decision:
    allowed: bool
    rule: str      # short machine-readable reason code
    detail: str    # human-readable explanation

    @property
    def denied(self) -> bool:
        return not self.allowed


def _allow(rule: str, detail: str = "") -> Decision:
    return Decision(True, rule, detail)


def _deny(rule: str, detail: str = "") -> Decision:
    return Decision(False, rule, detail)


# ---------------------------------------------------------------------------
# Host matching
# ---------------------------------------------------------------------------

def host_matches(host: str, pattern: str) -> bool:
    """Exact match, or a single-level wildcard like '*.example.com'.

    '*.example.com' matches 'a.example.com' and 'a.b.example.com' but NOT
    the apex 'example.com'. Matching is case-insensitive.
    """
    host = host.lower().rstrip(".")
    pattern = pattern.lower().rstrip(".")
    if pattern.startswith("*."):
        suffix = pattern[1:]  # ".example.com"
        return host.endswith(suffix) and len(host) > len(suffix)
    return host == pattern


def host_in(host: str, patterns) -> bool:
    return any(host_matches(host, p) for p in patterns)


# ---------------------------------------------------------------------------
# IP blocking (metadata / private / loopback / link-local / reserved)
# ---------------------------------------------------------------------------

def ip_is_blocked(ip_str: str) -> Decision:
    """Hard-block non-public destinations regardless of scope.

    Covers loopback, RFC1918 / unique-local private ranges, link-local
    (which includes the 169.254.169.254 metadata address and IPv6
    fe80::/10), multicast, reserved and the unspecified address.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return _deny("ip_invalid", f"not an IP address: {ip_str!r}")

    # Cloud metadata endpoints live in link-local space; block explicitly
    # as well so the reason code is unambiguous in audit logs.
    if ip_str in ("169.254.169.254", "fd00:ec2::254"):
        return _deny("ip_metadata", f"cloud metadata endpoint {ip_str}")

    if ip.is_loopback:
        return _deny("ip_loopback", str(ip))
    if ip.is_link_local:
        return _deny("ip_link_local", str(ip))
    if ip.is_private:
        return _deny("ip_private", str(ip))
    if ip.is_multicast:
        return _deny("ip_multicast", str(ip))
    if ip.is_reserved:
        return _deny("ip_reserved", str(ip))
    if ip.is_unspecified:
        return _deny("ip_unspecified", str(ip))
    return _allow("ip_public", str(ip))


# ---------------------------------------------------------------------------
# Target (URL) checking
# ---------------------------------------------------------------------------

def _default_port(scheme: str) -> int | None:
    return {"https": 443, "http": 80}.get(scheme)


def check_target(scope: Scope, url: str) -> Decision:
    """Decide whether a URL is in bounds by the scope's rules.

    This does not resolve DNS. After the caller resolves the host, it must
    also run ip_is_blocked() on the resolved address before connecting.
    """
    parts = urlsplit(url)
    scheme = (parts.scheme or "").lower()
    host = (parts.hostname or "").lower()

    if not scheme:
        return _deny("no_scheme", f"missing scheme in {url!r}")
    if scheme not in scope.allowed_schemes:
        return _deny("scheme_not_allowed", f"scheme {scheme!r} not in {scope.allowed_schemes}")
    if not host:
        return _deny("no_host", f"missing host in {url!r}")

    # A literal IP in the URL bypasses host allowlists; refuse it here so
    # targeting is always by allowed hostname (and IP is checked post-DNS).
    try:
        ipaddress.ip_address(host)
        return _deny("host_is_ip", "targets must be given by allowed hostname, not raw IP")
    except ValueError:
        pass

    if host_in(host, scope.third_party_denylist):
        return _deny("third_party", f"{host} is an out-of-scope third-party asset")
    if host_in(host, scope.excluded_hosts):
        return _deny("host_excluded", f"{host} is explicitly excluded")
    if not host_in(host, scope.allowed_hosts):
        return _deny("host_not_allowed", f"{host} is not in the allowlist")

    port = parts.port if parts.port is not None else _default_port(scheme)
    if port is None:
        return _deny("no_port", f"cannot determine port for {url!r}")
    if port not in scope.allowed_ports:
        return _deny("port_not_allowed", f"port {port} not in {scope.allowed_ports}")

    return _allow("in_scope", f"{scheme}://{host}:{port}")


def check_redirect(scope: Scope, location: str, from_url: str) -> Decision:
    """A redirect is followed only if its target is itself in scope.

    Relative redirects resolve against the originating URL's host/scheme,
    so they stay in scope by construction; absolute ones are re-checked.
    """
    parts = urlsplit(location)
    if not parts.scheme and not parts.netloc:
        # relative redirect -> same origin, already in scope
        base = urlsplit(from_url)
        rebuilt = f"{base.scheme}://{base.netloc}"
        return _allow("redirect_relative", f"relative redirect under {rebuilt}")
    return check_target(scope, location)
