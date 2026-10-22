"""Protocol oracle — deterministic checks of an HTTP exchange against
normative-spec assertions.

High-signal, low-false-positive checks only (the design values few FPs):
dangerous CORS, and cookie flag hygiene on Set-Cookie. Each finding cites a
clause reference, so the Skeptic can confirm or refute against the spec.
Pure and offline: it inspects a recorded CapturedExchange, never the wire.

This oracle flags *protocol-level* misconfigurations (where a spec defines
"correct"); it is not the oracle for IDOR/logic, which is differential.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..ingest import CapturedExchange


@dataclass(frozen=True)
class ProtocolFinding:
    rule: str
    detail: str
    clause_ref: str
    severity_hint: str   # advisory only; real severity is CVSS-computed elsewhere


def _values(headers, name: str) -> list[str]:
    name = name.lower()
    return [v for k, v in headers if k == name]


def _first(headers, name: str):
    vs = _values(headers, name)
    return vs[0] if vs else None


# --- CORS -------------------------------------------------------------------

def check_cors(ex: CapturedExchange) -> list[ProtocolFinding]:
    out: list[ProtocolFinding] = []
    acao = _first(ex.response_headers, "access-control-allow-origin")
    acac = (_first(ex.response_headers, "access-control-allow-credentials") or "").lower()
    if acao is None:
        return out
    credentials = acac == "true"
    origin = _first(ex.request_headers, "origin")

    if acao == "*" and credentials:
        out.append(ProtocolFinding(
            "cors_wildcard_with_credentials",
            "Access-Control-Allow-Origin: * together with "
            "Access-Control-Allow-Credentials: true (misconfiguration)",
            "Fetch Standard — CORS protocol (credentials + wildcard)",
            "medium"))
    elif credentials and origin is not None and acao == origin:
        out.append(ProtocolFinding(
            "cors_reflects_origin_with_credentials",
            f"Access-Control-Allow-Origin reflects the request Origin "
            f"({origin!r}) with credentials allowed — any site can read "
            f"authenticated responses",
            "Fetch Standard — CORS protocol (origin reflection + credentials)",
            "high"))
    return out


# --- Cookies ----------------------------------------------------------------

def _cookie_attrs(set_cookie: str) -> set[str]:
    parts = [p.strip().lower() for p in set_cookie.split(";")[1:]]
    attrs = set()
    for p in parts:
        attrs.add(p.split("=", 1)[0].strip())
    return attrs


def _cookie_name(set_cookie: str) -> str:
    return set_cookie.split("=", 1)[0].strip()


def check_cookies(ex: CapturedExchange) -> list[ProtocolFinding]:
    out: list[ProtocolFinding] = []
    is_https = ex.url.lower().startswith("https://")
    for sc in _values(ex.response_headers, "set-cookie"):
        name = _cookie_name(sc)
        attrs = _cookie_attrs(sc)
        missing = []
        if is_https and "secure" not in attrs:
            missing.append("Secure")
        if "httponly" not in attrs:
            missing.append("HttpOnly")
        if "samesite" not in attrs:
            missing.append("SameSite")
        if missing:
            out.append(ProtocolFinding(
                "cookie_missing_flags",
                f"Set-Cookie {name!r} missing: {', '.join(missing)}",
                "RFC 6265bis — cookie attributes (Secure/HttpOnly/SameSite)",
                "high" if "HttpOnly" in missing or "Secure" in missing else "low"))
    return out


_CHECKS = (check_cors, check_cookies)


def check_exchange(ex: CapturedExchange) -> list[ProtocolFinding]:
    out: list[ProtocolFinding] = []
    for check in _CHECKS:
        out.extend(check(ex))
    out.sort(key=lambda f: f.rule)
    return out


def to_evidence_content(f: ProtocolFinding) -> str:
    return f"protocol finding [{f.rule}] ({f.severity_hint}): {f.detail} — cites {f.clause_ref}"
