"""Finding memory — deduplication across runs and investigations.

Programs reject duplicates, so the same lead must not be surfaced twice.
Membership is by a stable signature; this keeps the set of what has already
been seen. In-memory here; the control plane can persist it later.
"""

from __future__ import annotations

import hashlib


def signature(oracle: str, detail: str, scope: str = "") -> str:
    """A stable dedup signature for a lead/finding."""
    raw = "|".join((oracle, scope, detail))
    return "sig_" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


class FindingMemory:
    def __init__(self) -> None:
        self._seen: set[str] = set()

    def register(self, sig: str) -> bool:
        """Record a signature. Returns True if new, False if already seen."""
        if sig in self._seen:
            return False
        self._seen.add(sig)
        return True

    def __contains__(self, sig: str) -> bool:
        return sig in self._seen

    def __len__(self) -> int:
        return len(self._seen)
