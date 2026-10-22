"""Business-invariant oracle — generalizes "a server rule enforced on the
client". Covers the design's backlog class: client-side payment/quota
bypass, price tampering, negative quantities, coupon reuse, and skipped
steps in a multi-step flow.

The operator declares the intended invariant(s); the Recon/Validator layers
supply an observed flow (an ordered list of steps, each with attributes and
a success flag). The oracle reports the observed sequences that violate an
invariant. It is pure and offline — it inspects a recorded flow, it never
drives requests, and (per the design) any confirmation of such a finding is
an active, human-gated, test-account-only activity handled elsewhere.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class InvariantKind(str, Enum):
    MISSING_REQUIRED_STEP = "MISSING_REQUIRED_STEP"   # consumed without the prerequisite
    VALUE_OUT_OF_BOUNDS = "VALUE_OUT_OF_BOUNDS"       # price/quantity tampering
    LIMIT_EXCEEDED = "LIMIT_EXCEEDED"                 # coupon/token reused
    STATE_NOT_CHANGED = "STATE_NOT_CHANGED"           # action succeeded, balance didn't move


@dataclass(frozen=True)
class Step:
    name: str
    success: bool = True
    attrs: tuple[tuple[str, object], ...] = ()

    def get(self, key: str, default=None):
        for k, v in self.attrs:
            if k == key:
                return v
        return default


def step(name: str, success: bool = True, **attrs) -> Step:
    return Step(name=name, success=success,
                attrs=tuple(sorted(attrs.items(), key=lambda kv: kv[0])))


@dataclass(frozen=True)
class Flow:
    steps: tuple[Step, ...] = ()


@dataclass(frozen=True)
class InvariantViolation:
    invariant: str
    kind: InvariantKind
    detail: str
    step_index: int   # where detected, or -1 for a whole-flow finding


def _num(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


@dataclass(frozen=True)
class RequiresPrecedingSuccess:
    """A consuming step must be paid for by a preceding successful step.

    Counting semantics (1:1): each successful `required_step` grants one
    credit; each successful `consuming_step` spends one. A consume with no
    credit available is a violation — catching both "consumed without ever
    charging" and "consumed more times than charged".
    """

    consuming_step: str
    required_step: str

    @property
    def name(self) -> str:
        return f"requires_preceding_success({self.consuming_step}<-{self.required_step})"

    def check(self, flow: Flow) -> list[InvariantViolation]:
        out: list[InvariantViolation] = []
        credits = 0
        for i, s in enumerate(flow.steps):
            if s.name == self.required_step and s.success:
                credits += 1
            elif s.name == self.consuming_step and s.success:
                if credits <= 0:
                    out.append(InvariantViolation(
                        self.name, InvariantKind.MISSING_REQUIRED_STEP,
                        f"'{self.consuming_step}' succeeded without a preceding "
                        f"successful '{self.required_step}'", i))
                else:
                    credits -= 1
        return out


@dataclass(frozen=True)
class ValueBound:
    """A numeric/exact field on a step must stay within declared bounds."""

    step_name: str
    field: str
    minimum: float | None = None
    maximum: float | None = None
    equals: object | None = None

    @property
    def name(self) -> str:
        return f"value_bound({self.step_name}.{self.field})"

    def check(self, flow: Flow) -> list[InvariantViolation]:
        out: list[InvariantViolation] = []
        for i, s in enumerate(flow.steps):
            if s.name != self.step_name:
                continue
            value = s.get(self.field)
            if value is None:
                continue
            if self.equals is not None and value != self.equals:
                out.append(InvariantViolation(
                    self.name, InvariantKind.VALUE_OUT_OF_BOUNDS,
                    f"{self.field}={value!r} != expected {self.equals!r}", i))
                continue
            n = _num(value)
            if n is None:
                continue
            if self.minimum is not None and n < self.minimum:
                out.append(InvariantViolation(
                    self.name, InvariantKind.VALUE_OUT_OF_BOUNDS,
                    f"{self.field}={n} < min {self.minimum}", i))
            if self.maximum is not None and n > self.maximum:
                out.append(InvariantViolation(
                    self.name, InvariantKind.VALUE_OUT_OF_BOUNDS,
                    f"{self.field}={n} > max {self.maximum}", i))
        return out


@dataclass(frozen=True)
class AtMost:
    """A token/coupon value may appear at most `limit` times (reuse check)."""

    field: str
    limit: int = 1
    only_success: bool = True

    @property
    def name(self) -> str:
        return f"at_most({self.field}<={self.limit})"

    def check(self, flow: Flow) -> list[InvariantViolation]:
        out: list[InvariantViolation] = []
        counts: dict[object, int] = {}
        for i, s in enumerate(flow.steps):
            if self.only_success and not s.success:
                continue
            value = s.get(self.field)
            if value is None:
                continue
            counts[value] = counts.get(value, 0) + 1
            if counts[value] == self.limit + 1:
                out.append(InvariantViolation(
                    self.name, InvariantKind.LIMIT_EXCEEDED,
                    f"{self.field}={value!r} used more than {self.limit} time(s)", i))
        return out


@dataclass(frozen=True)
class StateMustChange:
    """After a successful step, a tracked value must move in a direction.

    Models "the action went through but the balance/credits didn't drop".
    `direction` is "decrease" (default) or "increase".
    """

    step_name: str
    before_field: str
    after_field: str
    direction: str = "decrease"

    @property
    def name(self) -> str:
        return f"state_must_{self.direction}({self.step_name}.{self.before_field}->{self.after_field})"

    def check(self, flow: Flow) -> list[InvariantViolation]:
        out: list[InvariantViolation] = []
        for i, s in enumerate(flow.steps):
            if s.name != self.step_name or not s.success:
                continue
            before = _num(s.get(self.before_field))
            after = _num(s.get(self.after_field))
            if before is None or after is None:
                continue
            moved = after < before if self.direction == "decrease" else after > before
            if not moved:
                out.append(InvariantViolation(
                    self.name, InvariantKind.STATE_NOT_CHANGED,
                    f"'{self.step_name}' succeeded but {self.before_field}={before} "
                    f"did not {self.direction} to {self.after_field}={after}", i))
        return out


def check_flow(flow: Flow, invariants) -> list[InvariantViolation]:
    """Run all invariants over the flow; return violations, ordered."""
    out: list[InvariantViolation] = []
    for inv in invariants:
        out.extend(inv.check(flow))
    out.sort(key=lambda v: (v.step_index if v.step_index >= 0 else 1_000_000, v.invariant))
    return out


def to_evidence_content(v: InvariantViolation) -> str:
    where = f"step {v.step_index}" if v.step_index >= 0 else "flow"
    return f"business-invariant violation [{v.kind.value}] {v.invariant}: {v.detail} ({where})"
