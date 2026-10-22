# Árbitro

Foundation for a **scope-bounded, human-in-the-loop assistant for web
application bug bounty** (IDOR, XSS, authorization/logic flaws). It is a
development project; it is **not** a turnkey autonomous attacker.

Guiding principles (see `docs/DESIGN.md` for the full design):

1. **Scope is code, not a prompt.** Authorization is validated and
   enforced deterministically; the LLM cannot widen it.
2. **Determinism first.** Mechanical detection, parsing and scoring are
   code; the LLM only proposes hypotheses, prioritizes and writes.
3. **Human-in-the-loop** is a design requirement, not an add-on.
4. **Consensus is not proof.** A finding is confirmed only with
   observable, reproducible, reviewed evidence.
5. **Passive by default.** Active testing is opt-in per engagement,
   behind a human approval gate, and only within authorized scope.

Only use this against programs and assets you are **explicitly
authorized** to test.

## What's in this base (Phase 0–1)

Deterministic, offline core only — **no network, no target traffic**:

- `src/arbiter/scope.py` — the validated scope model + loader.
- `src/arbiter/policy.py` — the policy engine (scope-as-code): host
  allowlist/exclusions, scheme/port checks, hard IP blocks
  (private / loopback / link-local / cloud-metadata), redirect checks.
- `src/arbiter/states.py` — the finding state machine.
- `config/scope.example.{yaml,json}` — a fictional example scope.
- `tests/` — adversarial tests for the above.

Execution layers (recon, validation, the agent loop) are intentionally
**not** part of this base and will be added in later phases.

## Scope config

Copy an example and author your own from a program's **published,
authorized** rules (keep it local; `config/scope.local.*` is gitignored):

```bash
cp config/scope.example.yaml config/scope.local.yaml   # or .json
```

JSON scopes load with no third-party dependency. YAML scopes need the
optional `PyYAML` extra.

## Running the tests

Stdlib only — nothing to install:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```
