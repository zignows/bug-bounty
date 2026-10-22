"""Tests for the opencode LLM client (offline, mocked runner)."""

import json
import unittest

from arbiter.llm import OpencodeClient, extract_json, extract_text


class ExtractText(unittest.TestCase):
    def test_ndjson_text_events_concatenated(self):
        raw = "\n".join([
            json.dumps({"type": "step_start"}),
            json.dumps({"type": "text", "text": "hello "}),
            json.dumps({"type": "text", "text": "world"}),
            json.dumps({"type": "step_finish"}),
        ])
        self.assertEqual(extract_text(raw), "hello world")

    def test_message_content_shape(self):
        raw = json.dumps({"message": {"content": [{"text": "a"}, {"text": "b"}]}})
        self.assertEqual(extract_text(raw), "ab")

    def test_plain_text_passthrough(self):
        self.assertEqual(extract_text("just text"), "just text")

    def test_empty(self):
        self.assertEqual(extract_text(""), "")


class ExtractJson(unittest.TestCase):
    def test_object_in_surrounding_text(self):
        self.assertEqual(extract_json('noise {"a": 1} tail'), {"a": 1})

    def test_nested_and_strings(self):
        obj = extract_json('{"a": {"b": "}"}, "c": [1,2]}')
        self.assertEqual(obj, {"a": {"b": "}"}, "c": [1, 2]})

    def test_invalid_returns_none(self):
        self.assertIsNone(extract_json("no json here"))
        self.assertIsNone(extract_json('{"a": '))


class ClientBehavior(unittest.TestCase):
    def test_complete_returns_extracted_text(self):
        def runner(cmd, stdin, timeout):
            return json.dumps({"type": "text", "text": "ok"})
        c = OpencodeClient(runner=runner)
        self.assertEqual(c.complete("hi", model="m"), "ok")

    def test_command_includes_model_and_agent(self):
        captured = {}
        def runner(cmd, stdin, timeout):
            captured["cmd"] = cmd
            return "{}"
        c = OpencodeClient(runner=runner)
        c.complete("hi", agent="CETICO", model="amazon-bedrock/x")
        self.assertIn("run", captured["cmd"])
        self.assertIn("amazon-bedrock/x", captured["cmd"])
        self.assertIn("CETICO", captured["cmd"])

    def test_complete_json_parses_valid(self):
        def runner(cmd, stdin, timeout):
            return json.dumps({"type": "text", "text": '{"k": 1}'})
        c = OpencodeClient(runner=runner)
        out = c.complete_json("p", lambda o: o, model="m")
        self.assertEqual(out, {"k": 1})

    def test_complete_json_retries_then_succeeds(self):
        calls = {"n": 0}
        def runner(cmd, stdin, timeout):
            calls["n"] += 1
            text = "garbage" if calls["n"] == 1 else '{"ok": true}'
            return json.dumps({"type": "text", "text": text})
        c = OpencodeClient(runner=runner)
        out = c.complete_json("p", lambda o: o, model="m", retries=2)
        self.assertEqual(out, {"ok": True})
        self.assertEqual(calls["n"], 2)

    def test_complete_json_gives_up_returns_none(self):
        def runner(cmd, stdin, timeout):
            return "never json"
        c = OpencodeClient(runner=runner)
        self.assertIsNone(c.complete_json("p", lambda o: o, model="m", retries=1))

    def test_parse_raising_is_treated_as_invalid(self):
        def runner(cmd, stdin, timeout):
            return json.dumps({"type": "text", "text": '{"bad": 1}'})
        def parse(o):
            raise ValueError("bad shape")
        c = OpencodeClient(runner=runner)
        self.assertIsNone(c.complete_json("p", parse, model="m", retries=1))


if __name__ == "__main__":
    unittest.main()
