"""Reflected-input oracle — a LEAD detector for reflected XSS.

Offline and conservative: it flags only when a request parameter value
that contains HTML-significant characters is reflected **unencoded** in the
response body. That is a lead worth investigating, not a confirmed XSS —
confirmation requires actual execution in a browser context, which is an
active, human-gated step handled elsewhere. If the value appears only in
escaped form, it is not flagged (that is correct output encoding).

This is deliberately NOT a DOM/stored-XSS detector: those need real JS/DOM
analysis (the collection tooling) and execution evidence.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import parse_qsl, urlsplit

from ..ingest import CapturedExchange

_HTML_SIGNIFICANT = set("<>\"'")
_MIN_LEN = 3


@dataclass(frozen=True)
class ReflectionFinding:
    parameter: str
    value_snippet: str
    context_hint: str   # "script", "attribute-or-tag", "html-body"
    detail: str


def _params(ex: CapturedExchange) -> list[tuple[str, str]]:
    out = list(parse_qsl(urlsplit(ex.url).query, keep_blank_values=True))
    body = ex.request_body or ""
    # only treat the body as form params when it clearly looks like one
    if "=" in body and "\n" not in body and "{" not in body:
        out += list(parse_qsl(body, keep_blank_values=True))
    return out


def _context_hint(body: str, idx: int) -> str:
    window = body[max(0, idx - 60):idx]
    low = window.lower()
    if "<script" in low and "</script" not in low:
        return "script"
    if window.rfind("<") > window.rfind(">"):
        return "attribute-or-tag"
    return "html-body"


def check_reflections(ex: CapturedExchange) -> list[ReflectionFinding]:
    body = ex.response_body or ""
    if not body:
        return []
    out: list[ReflectionFinding] = []
    seen: set[str] = set()
    for name, value in _params(ex):
        if len(value) < _MIN_LEN:
            continue
        if not (set(value) & _HTML_SIGNIFICANT):
            continue                      # no XSS-relevant characters
        if value in seen:
            continue
        idx = body.find(value)            # raw (unencoded) reflection only
        if idx == -1:
            continue
        seen.add(value)
        hint = _context_hint(body, idx)
        out.append(ReflectionFinding(
            parameter=name,
            value_snippet=value[:60],
            context_hint=hint,
            detail=(f"parameter {name!r} reflected UNENCODED in the response "
                    f"(context: {hint}); value contains HTML-significant characters"),
        ))
    out.sort(key=lambda r: (r.parameter, r.value_snippet))
    return out


def to_evidence_content(r: ReflectionFinding) -> str:
    return (f"reflected-input lead [{r.context_hint}]: param={r.parameter} "
            f"value={r.value_snippet!r} reflected unencoded — LEAD ONLY; XSS "
            f"confirmation requires execution in a browser (active/gated)")
