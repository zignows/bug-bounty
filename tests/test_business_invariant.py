"""Tests for the business-invariant oracle."""

import unittest

from arbiter.oracles.business_invariant import (
    AtMost,
    Flow,
    InvariantKind,
    RequiresPrecedingSuccess,
    StateMustChange,
    ValueBound,
    check_flow,
    step,
    to_evidence_content,
)


def flow(*steps):
    return Flow(steps=tuple(steps))


class PaymentBypass(unittest.TestCase):
    INV = RequiresPrecedingSuccess(consuming_step="use_credits", required_step="charge")

    def test_consume_without_charge_is_violation(self):
        f = flow(step("use_credits"))
        v = self.INV.check(f)
        self.assertEqual(len(v), 1)
        self.assertIs(v[0].kind, InvariantKind.MISSING_REQUIRED_STEP)

    def test_charge_then_consume_is_ok(self):
        f = flow(step("charge", success=True), step("use_credits"))
        self.assertEqual(self.INV.check(f), [])

    def test_failed_charge_does_not_count(self):
        f = flow(step("charge", success=False), step("use_credits"))
        self.assertEqual(len(self.INV.check(f)), 1)

    def test_double_consume_single_charge_caught(self):
        f = flow(step("charge"), step("use_credits"), step("use_credits"))
        v = self.INV.check(f)
        self.assertEqual(len(v), 1)
        self.assertEqual(v[0].step_index, 2)  # the second consume

    def test_failed_consume_not_flagged(self):
        f = flow(step("use_credits", success=False))
        self.assertEqual(self.INV.check(f), [])


class ValueBounds(unittest.TestCase):
    def test_negative_quantity(self):
        inv = ValueBound("add_to_cart", "quantity", minimum=1)
        v = inv.check(flow(step("add_to_cart", quantity=-3)))
        self.assertEqual(len(v), 1)
        self.assertIs(v[0].kind, InvariantKind.VALUE_OUT_OF_BOUNDS)

    def test_price_tampering_equals(self):
        inv = ValueBound("checkout", "unit_price", equals=999)
        v = inv.check(flow(step("checkout", unit_price=1)))
        self.assertEqual(len(v), 1)

    def test_in_bounds_ok(self):
        inv = ValueBound("add_to_cart", "quantity", minimum=1, maximum=10)
        self.assertEqual(inv.check(flow(step("add_to_cart", quantity=3))), [])

    def test_missing_field_skipped(self):
        inv = ValueBound("add_to_cart", "quantity", minimum=1)
        self.assertEqual(inv.check(flow(step("add_to_cart"))), [])


class CouponReuse(unittest.TestCase):
    def test_reuse_over_limit(self):
        inv = AtMost("coupon", limit=1)
        f = flow(step("apply", coupon="SAVE50"), step("apply", coupon="SAVE50"))
        v = inv.check(f)
        self.assertEqual(len(v), 1)
        self.assertIs(v[0].kind, InvariantKind.LIMIT_EXCEEDED)
        self.assertEqual(v[0].step_index, 1)

    def test_distinct_coupons_ok(self):
        inv = AtMost("coupon", limit=1)
        f = flow(step("apply", coupon="A"), step("apply", coupon="B"))
        self.assertEqual(inv.check(f), [])

    def test_failed_attempts_not_counted(self):
        inv = AtMost("coupon", limit=1, only_success=True)
        f = flow(step("apply", coupon="X"), step("apply", coupon="X", success=False))
        self.assertEqual(inv.check(f), [])


class StateChange(unittest.TestCase):
    def test_balance_did_not_decrease(self):
        inv = StateMustChange("purchase", "balance_before", "balance_after")
        v = inv.check(flow(step("purchase", balance_before=100, balance_after=100)))
        self.assertEqual(len(v), 1)
        self.assertIs(v[0].kind, InvariantKind.STATE_NOT_CHANGED)

    def test_balance_decreased_ok(self):
        inv = StateMustChange("purchase", "balance_before", "balance_after")
        self.assertEqual(
            inv.check(flow(step("purchase", balance_before=100, balance_after=90))), [])

    def test_increase_direction(self):
        inv = StateMustChange("refund", "bal_before", "bal_after", direction="increase")
        self.assertEqual(len(inv.check(flow(step("refund", bal_before=10, bal_after=10)))), 1)


class Aggregate(unittest.TestCase):
    def test_check_flow_orders_by_step(self):
        invs = [
            RequiresPrecedingSuccess("use_credits", "charge"),
            ValueBound("add_to_cart", "quantity", minimum=1),
        ]
        f = flow(step("add_to_cart", quantity=-1), step("use_credits"))
        v = check_flow(f, invs)
        self.assertEqual(len(v), 2)
        self.assertEqual(v[0].step_index, 0)
        self.assertEqual(v[1].step_index, 1)

    def test_evidence_content(self):
        inv = RequiresPrecedingSuccess("use_credits", "charge")
        v = inv.check(flow(step("use_credits")))[0]
        text = to_evidence_content(v)
        self.assertIn("MISSING_REQUIRED_STEP", text)
        self.assertIn("step 0", text)


if __name__ == "__main__":
    unittest.main()
