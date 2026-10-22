"""Evidence model — the record of what was actually observed.

Evidence is **immutable** and **content-addressed**: its id is derived
from a hash of its content, so identical content deduplicates naturally
and any later tampering is detectable. Nothing here performs network
activity; the Recon/Validator layers (future phases) produce the raw
content and the proxy supplies the ground-truth reference, then record it
here.

`CONFIRMADA` findings must rest on evidence that is observable and
reproducible; this module gives that evidence a stable, verifiable shape.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import hashlib


class EvidenceKind(str, Enum):
    HTTP_EXCHANGE = "HTTP_EXCHANGE"   # a captured request/response pair
    OBSERVATION = "OBSERVATION"       # a passive observation / parsed signal
    DIFFERENTIAL = "DIFFERENTIAL"     # comparison across identities/states
    ARTIFACT = "ARTIFACT"             # a stored replayable artifact (e.g. HAR)


def _to_bytes(content) -> bytes:
    if isinstance(content, bytes):
        return content
    if isinstance(content, str):
        return content.encode("utf-8")
    raise TypeError("evidence content must be str or bytes")


def sha256_hex(content) -> str:
    return hashlib.sha256(_to_bytes(content)).hexdigest()


@dataclass(frozen=True)
class Evidence:
    id: str
    kind: EvidenceKind
    source: str
    created_at: str              # ISO-8601 UTC
    content_sha256: str
    summary: str
    replayable: bool = False     # True when a replay artifact (HAR-like) exists
    proxy_log_ref: str = ""      # pointer into the append-only proxy log
    meta: tuple[tuple[str, str], ...] = ()


def _now_iso(now) -> str:
    if now is None:
        now = datetime.now(timezone.utc)
    if callable(now):
        now = now()
    return now.astimezone(timezone.utc).replace(microsecond=0).isoformat()


def make_evidence(
    kind,
    source: str,
    content,
    *,
    summary: str = "",
    replayable: bool = False,
    proxy_log_ref: str = "",
    meta: dict | None = None,
    now=None,
) -> Evidence:
    """Build an Evidence record, deriving a content-addressed id.

    Identical (kind, content) yields the same id, so recording the same
    observation twice is idempotent. `now` may be a datetime or a callable
    returning one (injected for deterministic tests).
    """
    kind = EvidenceKind(kind)
    digest = sha256_hex(content)
    eid = "ev_" + hashlib.sha256(f"{kind.value}:{digest}".encode()).hexdigest()[:16]
    meta_items = tuple(sorted((str(k), str(v)) for k, v in (meta or {}).items()))
    return Evidence(
        id=eid,
        kind=kind,
        source=str(source),
        created_at=_now_iso(now),
        content_sha256=digest,
        summary=str(summary),
        replayable=bool(replayable),
        proxy_log_ref=str(proxy_log_ref),
        meta=meta_items,
    )


class EvidenceStore:
    """Append-only, content-addressed evidence store (in-memory).

    No update, no delete: once recorded, evidence is immutable. Recording
    the same content twice is idempotent. An id reused with *different*
    content is a hard error (tamper / collision guard).
    """

    def __init__(self) -> None:
        self._by_id: dict[str, Evidence] = {}

    def add(self, ev: Evidence) -> str:
        existing = self._by_id.get(ev.id)
        if existing is not None and existing.content_sha256 != ev.content_sha256:
            raise ValueError(f"evidence id collision with different content: {ev.id}")
        self._by_id.setdefault(ev.id, ev)
        return ev.id

    def record(self, kind, source: str, content, **kwargs) -> Evidence:
        ev = make_evidence(kind, source, content, **kwargs)
        self.add(ev)
        return ev

    def get(self, eid: str) -> Evidence | None:
        return self._by_id.get(eid)

    def verify(self, eid: str, content) -> bool:
        """Re-check that stored evidence still matches the given content."""
        ev = self._by_id.get(eid)
        return ev is not None and ev.content_sha256 == sha256_hex(content)

    def __contains__(self, eid: str) -> bool:
        return eid in self._by_id

    def __len__(self) -> int:
        return len(self._by_id)
