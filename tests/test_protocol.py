"""Tests for the protocol oracle."""

import unittest

from arbiter.ingest import captured
from arbiter.oracles.protocol import check_cookies, check_cors, check_exchange


class Cors(unittest.TestCase):
    def test_reflect_origin_with_credentials_is_high(self):
        ex = captured(
            "GET", "https://api.example.com/me",
            request_headers=[("Origin", "https://evil.test")],
            response_headers=[
                ("Access-Control-Allow-Origin", "https://evil.test"),
                ("Access-Control-Allow-Credentials", "true"),
            ],
        )
        f = check_cors(ex)
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].rule, "cors_reflects_origin_with_credentials")
        self.assertEqual(f[0].severity_hint, "high")

    def test_wildcard_with_credentials(self):
        ex = captured(
            "GET", "https://api.example.com/me",
            response_headers=[
                ("Access-Control-Allow-Origin", "*"),
                ("Access-Control-Allow-Credentials", "true"),
            ],
        )
        f = check_cors(ex)
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].rule, "cors_wildcard_with_credentials")

    def test_wildcard_without_credentials_is_clean(self):
        ex = captured("GET", "https://api.example.com/pub",
                      response_headers=[("Access-Control-Allow-Origin", "*")])
        self.assertEqual(check_cors(ex), [])

    def test_no_cors_headers_clean(self):
        self.assertEqual(check_cors(captured("GET", "https://example.com/")), [])


class Cookies(unittest.TestCase):
    def test_all_flags_missing_on_https(self):
        ex = captured("GET", "https://example.com/",
                      response_headers=[("Set-Cookie", "sid=abc; Path=/")])
        f = check_cookies(ex)
        self.assertEqual(len(f), 1)
        self.assertIn("Secure", f[0].detail)
        self.assertIn("HttpOnly", f[0].detail)
        self.assertIn("SameSite", f[0].detail)

    def test_well_configured_cookie_clean(self):
        ex = captured("GET", "https://example.com/",
                      response_headers=[("Set-Cookie", "sid=abc; Secure; HttpOnly; SameSite=Lax")])
        self.assertEqual(check_cookies(ex), [])

    def test_multiple_cookies(self):
        ex = captured("GET", "https://example.com/", response_headers=[
            ("Set-Cookie", "a=1; Secure; HttpOnly; SameSite=Strict"),
            ("Set-Cookie", "b=2"),
        ])
        f = check_cookies(ex)
        self.assertEqual(len(f), 1)  # only the weak one
        self.assertIn("'b'", f[0].detail)

    def test_secure_not_required_on_http(self):
        ex = captured("GET", "http://example.com/",
                      response_headers=[("Set-Cookie", "a=1; HttpOnly; SameSite=Lax")])
        self.assertEqual(check_cookies(ex), [])  # Secure not expected over http


class Aggregate(unittest.TestCase):
    def test_check_exchange_combines_and_sorts(self):
        ex = captured("GET", "https://example.com/", response_headers=[
            ("Set-Cookie", "sid=x"),
            ("Access-Control-Allow-Origin", "*"),
            ("Access-Control-Allow-Credentials", "true"),
        ])
        f = check_exchange(ex)
        rules = [x.rule for x in f]
        self.assertIn("cookie_missing_flags", rules)
        self.assertIn("cors_wildcard_with_credentials", rules)
        self.assertEqual(rules, sorted(rules))


if __name__ == "__main__":
    unittest.main()
