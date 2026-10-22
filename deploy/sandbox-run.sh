#!/usr/bin/env bash
# Árbitro — run one agent in a constrained sandbox. TEMPLATE.
#
# Defense in depth, third layer (after the app-level egress gate and the
# nftables backstop). Each agent runs:
#   * as a dedicated unprivileged user (AGENT_UID in nftables.conf), whose
#     only allowed egress is the proxy;
#   * with HTTP(S)_PROXY pointed at the enforcing proxy, so all traffic is
#     scope-checked and logged;
#   * with a read-only filesystem except an explicit, per-run work dir;
#   * with no extra capabilities.
#
# This is a TEMPLATE: review paths, the uid, and the proxy address, and
# adapt to your VPS. It is NOT executed by this repo. Requires bubblewrap
# (bwrap). An equivalent can be built with firejail or systemd-run
# (DynamicUser=, IPAddressDeny=, etc.).
set -euo pipefail

AGENT_UID="${AGENT_UID:-6000}"
PROXY_URL="${PROXY_URL:-http://127.0.0.1:8080}"
WORKDIR="${WORKDIR:-/srv/arbiter/runs/$(id -u)-run}"     # per-run, writable
ROOTFS="${ROOTFS:-/}"                                     # bind read-only

if ! command -v bwrap >/dev/null 2>&1; then
  echo "bubblewrap (bwrap) is required; install it or adapt to your sandbox tool" >&2
  exit 1
fi

mkdir -p "$WORKDIR"

# Run the given command (the agent CLI) under the sandbox. The agent must
# honor HTTP(S)_PROXY; the kernel firewall denies any egress that bypasses it.
exec setpriv --reuid="$AGENT_UID" --regid="$AGENT_UID" --clear-groups -- \
  bwrap \
    --ro-bind "$ROOTFS" / \
    --dev /dev \
    --proc /proc \
    --tmpfs /tmp \
    --bind "$WORKDIR" "$WORKDIR" \
    --chdir "$WORKDIR" \
    --unshare-pid \
    --unshare-ipc \
    --unshare-uts \
    --new-session \
    --die-with-parent \
    --setenv HTTP_PROXY "$PROXY_URL" \
    --setenv HTTPS_PROXY "$PROXY_URL" \
    --setenv NO_PROXY "" \
    -- "$@"
