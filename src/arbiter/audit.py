"""Append-only audit log.

Every decision, transition, approval and budget charge the control plane
makes is recorded here, in order, immutably. There is no update or delete:
the log is the trustworthy record of what happened.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum


class AuditEventType(str, Enum):
    INVESTIGATION_OPENED = "INVESTIGATION_OPENED"
    ANALYSIS_RECORDED = "ANALYSIS_RECORDED"
    DECISION_APPLIED = "DECISION_APPLIED"
    DECISION_REJECTED = "DECISION_REJECTED"
    STATE_TRANSITION = "STATE_TRANSITION"
    APPROVAL_REQUESTED = "APPROVAL_REQUESTED"
    APPROVAL_GRANTED = "APPROVAL_GRANTED"
    APPROVAL_DENIED = "APPROVAL_DENIED"
    BUDGET_CHARGE = "BUDGET_CHARGE"
    STOP_TRIGGERED = "STOP_TRIGGERED"


def _now_iso(now) -> str:
    if now is None:
        now = datetime.now(timezone.utc)
    if callable(now):
        now = now()
    return now.astimezone(timezone.utc).replace(microsecond=0).isoformat()


@dataclass(frozen=True)
class AuditEvent:
    seq: int
    at: str
    type: AuditEventType
    subject: str      # hypothesis id, or "-" for global events
    detail: str = ""


class AuditLog:
    def __init__(self, now=None) -> None:
        self._events: list[AuditEvent] = []
        self._now = now

    def append(self, event_type, subject: str = "-", detail: str = "", *, now=None) -> AuditEvent:
        ev = AuditEvent(
            seq=len(self._events),
            at=_now_iso(now if now is not None else self._now),
            type=AuditEventType(event_type),
            subject=str(subject),
            detail=str(detail),
        )
        self._events.append(ev)
        return ev

    def entries(self) -> tuple[AuditEvent, ...]:
        return tuple(self._events)

    def of_type(self, event_type) -> tuple[AuditEvent, ...]:
        et = AuditEventType(event_type)
        return tuple(e for e in self._events if e.type == et)

    def for_subject(self, subject: str) -> tuple[AuditEvent, ...]:
        return tuple(e for e in self._events if e.subject == subject)

    def __len__(self) -> int:
        return len(self._events)
