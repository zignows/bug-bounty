"""Ingestion boundary — a normalized HTTP exchange, proxy-agnostic.

Whatever collects traffic (Caido, another proxy, a replay file) maps into
this one shape; the rest of the system never depends on the collector's
format. A CapturedExchange turns into content-addressed HTTP_EXCHANGE
evidence, so the same request/response deduplicates and stays verifiable.

The collector-specific mapping (e.g. a Caido GraphQL response -> a
CapturedExchange) is a thin layer written once against a real sample, kept
out of here on purpose because that API is version-unstable.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .evidence import Evidence, EvidenceKind, EvidenceStore


def _norm_headers(headers) -> tuple[tuple[str, str], ...]:
    if not headers:
        return ()
    items = headers.items() if hasattr(headers, "items") else headers
    return tuple(sorted((str(k).lower(), str(v)) for k, v in items))


@dataclass(frozen=True)
class CapturedExchange:
    method: str
    url: str
    status: int | None = None
    request_headers: tuple[tuple[str, str], ...] = ()
    request_body: str = ""
    response_headers: tuple[tuple[str, str], ...] = ()
    response_body: str = ""
    source: str = "proxy"

    def canonical(self) -> str:
        """A stable textual form used for hashing / replay identity."""
        def block(title, headers, body):
            lines = [title]
            lines += [f"{k}: {v}" for k, v in headers]
            lines.append("")
            lines.append(body)
            return "\n".join(lines)

        req = block(f"{self.method.upper()} {self.url}",
                    self.request_headers, self.request_body)
        status = "" if self.status is None else str(self.status)
        resp = block(f"HTTP {status}", self.response_headers, self.response_body)
        return req + "\n\n===\n\n" + resp

    def summary(self) -> str:
        status = "?" if self.status is None else self.status
        return f"{self.method.upper()} {self.url} -> {status}"


def captured(
    method: str,
    url: str,
    *,
    status: int | None = None,
    request_headers=None,
    request_body: str = "",
    response_headers=None,
    response_body: str = "",
    source: str = "proxy",
) -> CapturedExchange:
    return CapturedExchange(
        method=method,
        url=url,
        status=status,
        request_headers=_norm_headers(request_headers),
        request_body=request_body,
        response_headers=_norm_headers(response_headers),
        response_body=response_body,
        source=source,
    )


def exchange_to_evidence(exchange: CapturedExchange, store: EvidenceStore) -> Evidence:
    """Record a captured exchange as replayable HTTP_EXCHANGE evidence."""
    return store.record(
        EvidenceKind.HTTP_EXCHANGE,
        source=exchange.source,
        content=exchange.canonical(),
        summary=exchange.summary(),
        replayable=True,
        meta={"status": "" if exchange.status is None else str(exchange.status)},
    )
