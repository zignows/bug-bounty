"""Tests for the reflected-input (XSS lead) oracle."""

import unittest

from arbiter.ingest import captured
from arbiter.oracles.reflected import check_reflections


class Reflection(unittest.TestCase):
    def test_unencoded_reflection_flagged(self):
        ex = captured("GET", "https://example.com/s?q=<b>x</b>",
                      response_body="results for <b>x</b> found")
        f = check_reflections(ex)
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].parameter, "q")

    def test_encoded_reflection_not_flagged(self):
        ex = captured("GET", "https://example.com/s?q=<b>x</b>",
                      response_body="results for &lt;b&gt;x&lt;/b&gt; found")
        self.assertEqual(check_reflections(ex), [])

    def test_value_without_special_chars_ignored(self):
        ex = captured("GET", "https://example.com/s?q=hello",
                      response_body="you searched hello")
        self.assertEqual(check_reflections(ex), [])

    def test_short_value_ignored(self):
        ex = captured("GET", "https://example.com/s?q=<", response_body="<")
        self.assertEqual(check_reflections(ex), [])

    def test_not_reflected_not_flagged(self):
        ex = captured("GET", "https://example.com/s?q=\"><svg>",
                      response_body="nothing echoed here")
        self.assertEqual(check_reflections(ex), [])

    def test_body_params_parsed(self):
        ex = captured("POST", "https://example.com/c",
                      request_body="name=\"><i>", response_body="hi \"><i>")
        f = check_reflections(ex)
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].parameter, "name")

    def test_script_context_hint(self):
        ex = captured("GET", "https://example.com/p?u='-alert(1)-'",
                      response_body="<script>var u='-alert(1)-';</script>")
        f = check_reflections(ex)
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].context_hint, "script")


if __name__ == "__main__":
    unittest.main()
