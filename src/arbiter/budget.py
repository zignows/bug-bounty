"""Budget governor — enforces the technical ceilings and stop conditions.

Tracks cost, requests, iterations, elapsed time, consecutive errors,
unexpected effects and rate-limit signals against a Scope's Limits, and
reports the first stop condition that trips. The clock is injectable so
duration checks are deterministic in tests.
"""

from __future__ import annotations

import time
from enum import Enum

from .scope import Limits


class StopReason(str, Enum):
    NONE = "NONE"
    COST = "COST"
    DURATION = "DURATION"
    ITERATIONS = "ITERATIONS"
    ERRORS = "ERRORS"
    UNEXPECTED_EFFECT = "UNEXPECTED_EFFECT"
    RATE_LIMIT = "RATE_LIMIT"


class BudgetGovernor:
    def __init__(self, limits: Limits, clock=time.monotonic) -> None:
        self.limits = limits
        self._clock = clock
        self._start = clock()
        self.cost_usd = 0.0
        self.requests = 0
        self.iterations = 0
        self.consecutive_errors = 0
        self.unexpected_effects = 0
        self._rate_limited = False

    def charge(self, cost_usd: float = 0.0, requests: int = 0) -> StopReason:
        self.cost_usd += float(cost_usd)
        self.requests += int(requests)
        return self.check()

    def tick_iteration(self) -> StopReason:
        self.iterations += 1
        return self.check()

    def record_error(self) -> StopReason:
        self.consecutive_errors += 1
        return self.check()

    def record_success(self) -> None:
        self.consecutive_errors = 0

    def record_unexpected_effect(self) -> StopReason:
        self.unexpected_effects += 1
        return self.check()

    def record_rate_limit(self) -> StopReason:
        self._rate_limited = True
        return self.check()

    def elapsed(self) -> float:
        return self._clock() - self._start

    def check(self) -> StopReason:
        lim = self.limits
        if self.cost_usd > lim.max_cost_usd:
            return StopReason.COST
        if self.iterations > lim.max_iterations:
            return StopReason.ITERATIONS
        if self.elapsed() > lim.max_duration_seconds:
            return StopReason.DURATION
        if self.consecutive_errors >= lim.consecutive_error_limit:
            return StopReason.ERRORS
        if self.unexpected_effects >= lim.unexpected_effect_limit:
            return StopReason.UNEXPECTED_EFFECT
        if self._rate_limited:
            return StopReason.RATE_LIMIT
        return StopReason.NONE

    @property
    def stopped(self) -> bool:
        return self.check() is not StopReason.NONE
