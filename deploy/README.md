# Deploy — scope enforcement on the VPS (defense in depth)

Scope is enforced at **three independent layers**, so no single bug lets an
agent leave the authorized scope. These are templates: review and adapt
them on your VPS. **Nothing here runs from this repo.**

```
agent (CLI)                 run inside ─────────────┐
   │ HTTP(S)_PROXY                                   │ sandbox-run.sh
   ▼                                                 │ (unpriv user, RO fs,
enforcing proxy  ── calls ──► egress gate            │  proxy env, no caps)
   │                          (src/arbiter/egress.py)│
   │ only to proxy allowed by ──────────────────────┘
   ▼
nftables (deploy/nftables.conf)  ── kernel backstop: drop everything from
                                    the agent user except the proxy; drop
                                    private/link-local/metadata for all
```

## 1. Application layer — the egress gate (`src/arbiter/egress.py`)

The proxy runs every outbound request through the gate before forwarding:
scope allowlist (host/scheme/port), passive-mode method safety, DNS
re-resolution with IP blocking, and per-host rate limiting. Crucially the
gate returns a **pinned IP**: the proxy must connect to exactly that IP and
must not re-resolve the host for the actual connection — this is what closes
the DNS-rebinding window (resolve → check → connect-to-checked-IP).

This layer is tested and offline; the socket/proxy framework around it is a
later choice (an infra/dependency decision), kept out of the core on purpose.

## 2. Kernel layer — nftables (`deploy/nftables.conf`)

Independent of the application. The agent user may reach only the proxy;
every other destination is dropped, and private/link-local/metadata ranges
are dropped for everyone as a backstop. Set `AGENT_UID`, `PROXY_ADDR`,
`PROXY_PORT`, then `nft -f deploy/nftables.conf` as root.

## 3. Process layer — the sandbox (`deploy/sandbox-run.sh`)

Each agent runs as a dedicated unprivileged user, read-only filesystem
except a per-run work dir, no extra capabilities, with `HTTP(S)_PROXY`
pointed at the enforcing proxy. Uses bubblewrap; a firejail or
`systemd-run` equivalent works too.

## Order of application

1. Create the agent user and note its uid.
2. Install and load `nftables.conf` with that uid and your proxy address.
3. Start the enforcing proxy (bound to `PROXY_ADDR:PROXY_PORT`).
4. Launch agents via `sandbox-run.sh`.

Passive mode stays the global default; active testing is enabled per
engagement only after the human approval gate (see `docs/DESIGN.md`).
