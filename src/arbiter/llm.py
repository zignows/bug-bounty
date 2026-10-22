"""LLM client — provider-agnostic, driving opencode non-interactively.

The control plane never lets a model decide anything on its own: a model
produces a structured proposal, which code then validates and the control
plane applies. This module is the thin, testable bridge to opencode:

  * build and run `opencode run --format json` for a given agent + model;
  * extract the final assistant text from opencode's NDJSON output;
  * parse it as JSON and validate it against our record schemas, retrying
    with a re-ask on invalid output, and giving up (-> None) so the control
    plane can route to REVISAO_HUMANA.

The actual subprocess call is injected (a `runner` callable) so tests run
offline with canned output and nothing is ever executed here by default
beyond what the caller wires in.
"""

from __future__ import annotations

import json
import subprocess


def _default_runner(cmd: list[str], stdin: str, timeout: int) -> str:
    proc = subprocess.run(
        cmd, input=stdin, capture_output=True, text=True, timeout=timeout
    )
    if proc.returncode != 0:
        raise RuntimeError(f"opencode exited {proc.returncode}: {proc.stderr[:400]}")
    return proc.stdout


def extract_text(raw: str) -> str:
    """Pull the assistant text out of opencode output.

    Tolerant: opencode `--format json` emits NDJSON events; we concatenate
    any text payloads. If the output is not NDJSON (plain text), return it
    as-is.
    """
    raw = (raw or "").strip()
    if not raw:
        return ""
    chunks: list[str] = []
    saw_json = False
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        saw_json = True
        if isinstance(obj, dict):
            # common shapes: {"type":"text","text":...} or {"text":...}
            # or {"message":{"content":[{"text":...}]}}
            if isinstance(obj.get("text"), str):
                chunks.append(obj["text"])
            else:
                msg = obj.get("message") or obj.get("part") or {}
                content = msg.get("content") if isinstance(msg, dict) else None
                if isinstance(content, str):
                    chunks.append(content)
                elif isinstance(content, list):
                    for p in content:
                        if isinstance(p, dict) and isinstance(p.get("text"), str):
                            chunks.append(p["text"])
    if not saw_json:
        return raw
    return "".join(chunks).strip()


def extract_json(text: str):
    """Best-effort: parse the first balanced {...} object in `text`."""
    text = (text or "").strip()
    if not text:
        return None
    start = text.find("{")
    if start == -1:
        return None
    depth = 0
    in_str = False
    esc = False
    for i in range(start, len(text)):
        c = text[i]
        if in_str:
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = False
            continue
        if c == '"':
            in_str = True
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(text[start:i + 1])
                except json.JSONDecodeError:
                    return None
    return None


class OpencodeClient:
    def __init__(self, runner=None, binary: str = "opencode", timeout: int = 180):
        self._runner = runner or _default_runner
        self.binary = binary
        self.timeout = timeout

    def _build_cmd(self, agent: str | None, model: str | None) -> list[str]:
        cmd = [self.binary, "run", "--format", "json"]
        if model:
            cmd += ["-m", model]
        if agent:
            cmd += ["--agent", agent]
        return cmd

    def complete(self, prompt: str, *, agent: str | None = None,
                 model: str | None = None) -> str:
        raw = self._runner(self._build_cmd(agent, model), prompt, self.timeout)
        return extract_text(raw)

    def complete_json(self, prompt: str, parse, *, agent: str | None = None,
                      model: str | None = None, retries: int = 2):
        """Run, extract JSON, and `parse` it into a validated object.

        `parse(obj)` returns the validated value or raises. On invalid or
        unparseable output it re-asks up to `retries` times, then returns
        None (control plane -> REVISAO_HUMANA).
        """
        cur = prompt
        for _ in range(retries + 1):
            text = self.complete(cur, agent=agent, model=model)
            obj = extract_json(text)
            if obj is not None:
                try:
                    return parse(obj)
                except Exception:
                    pass
            cur = (prompt + "\n\nYour previous output was not valid. Return ONLY "
                   "a single JSON object matching the schema, nothing else.")
        return None
