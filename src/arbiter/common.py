"""Small shared types used across the deterministic core."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CheckResult:
    """Result of a deterministic validation: ok plus human-readable problems."""

    ok: bool
    problems: tuple[str, ...] = ()
