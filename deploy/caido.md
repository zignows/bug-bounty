# Integrating Árbitro with Caido

Caido is the collection + proxy layer; Árbitro provides scope-as-code
enforcement and the reasoning/oracles on top. **Verify specifics against
the current Caido docs — Caido's GraphQL API is explicitly not stable
across releases.**

## Topology

```
agent (sandboxed, HTTP(S)_PROXY = Caido listener)
   │
   ▼
 Caido  ──(plugin) JX Scout: collect + beautify + de-chunk JavaScript
   │  upstream proxy (Settings → Network)
   ▼
 Árbitro egress gate  (src/arbiter/egress.py)  ← scope-as-code, authoritative
   │
   ▼
 internet
   ▲
 nftables (deploy/nftables.conf): agent reaches only Caido; nobody reaches
 private/link-local/metadata
```

The egress gate sits **upstream of Caido**, so the Python policy engine
stays the single source of truth for scope. Caido's own **Scopes** are a
convenience filter for its traffic tables — never the security boundary.

## Configure

1. **Agent sandbox** → set `HTTP(S)_PROXY` to Caido's proxy listener
   (see `deploy/sandbox-run.sh`, but point it at Caido, which then points
   upstream at the gate).
2. **Caido upstream** → Settings → Network → Add Proxy → the egress gate's
   `host:port` (must be a **different port** than Caido's own listener).
   Route `*` (all hosts) upstream. Use Test, then Create.
   Ref: https://docs.caido.io/guides/upstream
3. **JX Scout** → install the plugin in Caido so chunked/lazy-loaded JS is
   collected and beautified as you browse the in-scope app.
4. **nftables** → load `deploy/nftables.conf` so the agent user can only
   reach Caido and the box can never reach private/metadata ranges.

## Reading traffic + JS back into Árbitro

Pull captured requests/responses (and JX Scout's collected JS) from Caido
and map them into `CapturedExchange` (see `src/arbiter/ingest.py`), which
records content-addressed `HTTP_EXCHANGE` evidence; oracles then run over
it.

- Caido exposes a **GraphQL API** at `/graphql` (Bearer token; short-lived
  from the client's localStorage, or longer-lived via the auth flow
  mutation). SDK: `@caido/sdk-client`; a community `caido-python` client
  exists. Refs: https://docs.caido.io/concepts/graphql ,
  https://developer.caido.io/client-sdk/guides/graphql_direct
- **Because the API is version-unstable**, the Caido-specific mapping
  (GraphQL response → `CapturedExchange`) is written against a real sample
  from your Caido version and pinned to it; it is intentionally not
  hard-coded into the core. Keep the mapping in one small adapter so a
  Caido upgrade touches only that file.

## What stays authoritative in Árbitro (not Caido)

- Scope allow/deny, DNS-rebinding pin, passive-vs-active method rules,
  rate limits → the egress gate (`egress.py`), enforced in code.
- Evidence, state machine, oracles, audit log → the control plane.

Caido/JX Scout are the eyes and hands; the scope boundary and the
confirm/deny logic are Árbitro's.
