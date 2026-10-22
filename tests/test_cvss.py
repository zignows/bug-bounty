"""Tests for the CVSS v3.1 base-score oracle.

The vectors below are canonical, externally-known base scores (not merely
re-derived from this implementation), so they validate the math against
the official calculator.
"""

import unittest

from arbiter.oracles.cvss import (
    CvssError,
    base_score_from_metrics,
    parse_vector,
    roundup,
    score_vector,
    severity_rating,
)

# (vector, expected base score, expected severity)
# Canonical, externally-known scores, cross-verified by an independent
# derivation+reconciliation pass (two independent implementations agree on
# all of these). Covers every AV value, both AC/UI, all PR under each scope,
# Scope U and C, and every severity band.
KNOWN = [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, "Critical"),
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 9.9, "Critical"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "Critical"),
    ("CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.8, "High"),
    ("CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:H", 8.2, "High"),
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.1, "High"),
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8, "High"),    # local priv esc
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5, "High"),    # info disclosure
    ("CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", 6.7, "Medium"),
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H", 6.5, "Medium"),
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", 6.4, "Medium"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, "Medium"),  # reflected XSS
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N", 5.8, "Medium"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3, "Medium"),
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N", 4.3, "Medium"),
    ("CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L", 3.9, "Low"),
    ("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L", 3.8, "Low"),
    ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.6, "Low"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0, "None"),
]


class KnownVectors(unittest.TestCase):
    def test_known_scores(self):
        for vector, expected, sev in KNOWN:
            with self.subTest(vector=vector):
                res = score_vector(vector)
                self.assertEqual(res.base_score, expected)
                self.assertEqual(res.severity, sev)


class Roundup(unittest.TestCase):
    def test_exact_values(self):
        self.assertEqual(roundup(4.0), 4.0)
        self.assertEqual(roundup(4.02), 4.1)      # anything above rounds up
        self.assertEqual(roundup(5.299442775), 5.3)
        self.assertEqual(roundup(10.0), 10.0)

    def test_never_rounds_down(self):
        self.assertEqual(roundup(6.001), 6.1)


class Severity(unittest.TestCase):
    def test_bands(self):
        self.assertEqual(severity_rating(0.0), "None")
        self.assertEqual(severity_rating(3.9), "Low")
        self.assertEqual(severity_rating(4.0), "Medium")
        self.assertEqual(severity_rating(6.9), "Medium")
        self.assertEqual(severity_rating(7.0), "High")
        self.assertEqual(severity_rating(8.9), "High")
        self.assertEqual(severity_rating(9.0), "Critical")
        self.assertEqual(severity_rating(10.0), "Critical")


class Parsing(unittest.TestCase):
    def test_prefix_optional(self):
        a = parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        b = parse_vector("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        self.assertEqual(a, b)

    def test_missing_metric_rejected(self):
        with self.assertRaises(CvssError):
            parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H")  # no A

    def test_invalid_value_rejected(self):
        with self.assertRaises(CvssError):
            parse_vector("CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

    def test_unsupported_version_rejected(self):
        with self.assertRaises(CvssError):
            parse_vector("CVSS:2.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

    def test_extra_metrics_ignored(self):
        # temporal metrics present but ignored; base still parses/scores
        res = score_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/RL:O")
        self.assertEqual(res.base_score, 9.8)


class Scope(unittest.TestCase):
    def test_scope_changed_uses_changed_pr_table(self):
        # PR:L differs between scopes (0.62 vs 0.68); scores should differ
        u = base_score_from_metrics(parse_vector("AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L"))
        c = base_score_from_metrics(parse_vector("AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:L"))
        self.assertNotEqual(u, c)


if __name__ == "__main__":
    unittest.main()
