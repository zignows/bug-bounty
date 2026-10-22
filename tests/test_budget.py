"""Tests for the budget governor and stop conditions."""

import unittest

from arbiter.budget import BudgetGovernor, StopReason
from arbiter.scope import Limits


class FakeClock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


def gov(**overrides):
    limits = Limits(**overrides) if overrides else Limits()
    return BudgetGovernor(limits, clock=FakeClock())


class Stops(unittest.TestCase):
    def test_fresh_is_not_stopped(self):
        g = gov()
        self.assertFalse(g.stopped)
        self.assertIs(g.check(), StopReason.NONE)

    def test_cost_cap(self):
        g = gov(max_cost_usd=1.0)
        self.assertIs(g.charge(0.5), StopReason.NONE)
        self.assertIs(g.charge(0.6), StopReason.COST)  # 1.1 > 1.0

    def test_cost_exactly_at_limit_is_ok(self):
        g = gov(max_cost_usd=1.0)
        self.assertIs(g.charge(1.0), StopReason.NONE)

    def test_iterations_cap(self):
        g = gov(max_iterations=2)
        self.assertIs(g.tick_iteration(), StopReason.NONE)
        self.assertIs(g.tick_iteration(), StopReason.NONE)
        self.assertIs(g.tick_iteration(), StopReason.ITERATIONS)

    def test_duration_cap(self):
        clock = FakeClock()
        g = BudgetGovernor(Limits(max_duration_seconds=30), clock=clock)
        self.assertFalse(g.stopped)
        clock.t = 31
        self.assertIs(g.check(), StopReason.DURATION)

    def test_consecutive_errors(self):
        g = gov(consecutive_error_limit=3)
        g.record_error()
        g.record_error()
        self.assertIs(g.check(), StopReason.NONE)
        self.assertIs(g.record_error(), StopReason.ERRORS)

    def test_success_resets_errors(self):
        g = gov(consecutive_error_limit=3)
        g.record_error()
        g.record_error()
        g.record_success()
        self.assertIs(g.check(), StopReason.NONE)
        self.assertEqual(g.consecutive_errors, 0)

    def test_unexpected_effect(self):
        g = gov(unexpected_effect_limit=2)
        g.record_unexpected_effect()
        self.assertIs(g.record_unexpected_effect(), StopReason.UNEXPECTED_EFFECT)

    def test_rate_limit(self):
        g = gov()
        self.assertIs(g.record_rate_limit(), StopReason.RATE_LIMIT)
        self.assertTrue(g.stopped)


if __name__ == "__main__":
    unittest.main()
