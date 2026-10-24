#!/usr/bin/env bash
# paths.sh — where Agenti's files live (docs/packaging.md § Layout). Sourced by
# every bash script; shared/paths.py is the same table for Python, and
# test_paths.py keeps the two equal. Every value can be overridden from the
# environment (tests, a staging root); nothing else hard-codes these paths.
#
#   AGENTI_LIBDIR    the code, root-owned and read-only (/usr/lib/agenti)
#   AGENTI_RUNTIME   the bundled Python and its three environments
#   AGENTI_STATE     what must work while the vault is locked: the user
#                    database, authd's sessions, TLS
#   AGENTI_ROOT      the data root: secrets, instruction edits, built agents,
#                    the engagement, runs, teams, kept outputs. The vault's
#                    mount point when the vault is enabled.
#   AGENTI_ETC       settings (api.conf, vault.conf)
# shellcheck disable=SC2034  # a table: each script uses the names it needs
AGENTI_LIBDIR="${AGENTI_LIBDIR:-/usr/lib/agenti}"
AGENTI_RUNTIME="${AGENTI_RUNTIME:-/usr/lib/agenti-runtime}"
AGENTI_STATE="${AGENTI_STATE:-/var/lib/agenti}"
AGENTI_ROOT="${AGENTI_ROOT:-$AGENTI_STATE/data}"
AGENTI_ETC="${AGENTI_ETC:-/etc/agenti}"
AGENTI_BIN="${AGENTI_BIN:-/usr/bin/agenti}"
# The only program the web tier may run as root (api_bridge.py, no arguments).
API_BRIDGE="$AGENTI_LIBDIR/api_bridge.py"

AGENT_PYTHON="$AGENTI_RUNTIME/agent/bin/python3"
API_PYTHON="$AGENTI_RUNTIME/api/bin/python3"
AUTHD_PYTHON="$AGENTI_RUNTIME/authd/bin/python3"
AGENTI_SHIPPED_AGENTS="$AGENTI_LIBDIR/agents"
AGENTI_BUILT_AGENTS="$AGENTI_ROOT/shared/agents"
AGENTI_VAULT_CONF="$AGENTI_ETC/vault.conf"
AGENTI_API_CONF="$AGENTI_ETC/api.conf"
AGENTI_IAM_DB="${AGENTI_IAM_DB:-$AGENTI_STATE/iam.db}"
AGENTI_RUNTIME_DB="${AGENTI_RUNTIME_DB:-$AGENTI_STATE/authd/runtime.db}"
# The local relay IP-scoped runs reach Anthropic through (egress_relay.py).
AGENTI_RELAY_ADDR="${AGENTI_RELAY_ADDR:-127.0.0.1:8429}"

# agenti_master_dir <agent>: the one copy of an agent's code. A shipped agent
# (the package's) wins over one built in Settings; the builder refuses a name
# a shipped agent already has, so both existing is never expected.
agenti_master_dir() {
    if [[ -d "$AGENTI_SHIPPED_AGENTS/$1" ]]; then printf '%s/%s' "$AGENTI_SHIPPED_AGENTS" "$1"
    else printf '%s/%s' "$AGENTI_BUILT_AGENTS" "$1"; fi
}

# agenti_vault_enabled: true when `agenti vault enable` has been run. The data
# root is then an encrypted container's mount point, and nothing that needs
# data may run while it is not mounted.
agenti_vault_enabled() { [[ -f "$AGENTI_VAULT_CONF" ]]; }
# agenti_data_ready: the data root can be used now (no vault, or it is unlocked).
agenti_data_ready() {
    if agenti_vault_enabled; then mountpoint -q "$AGENTI_ROOT" 2>/dev/null || return 1
    else [[ -d "$AGENTI_ROOT" ]]; fi
}
