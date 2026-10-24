#!/usr/bin/env bash
#
# set-secret.sh — install an Anthropic API key into the data root (the vault,
# when it is enabled). Run through `sudo agenti setup` or `sudo agenti <agent> set-key`.
#
# The key is read from a SILENT prompt, never from the command line, so it
# never lands in your shell history, the process table, or a log.
#
# Four tiers, an ordered fallback: per-user wins over per-agent, over org,
# over shared. Start with one key for everything and narrow later for cost
# attribution or separate Console spend caps — no code changes needed.
#
# (data root = /var/lib/agenti/data, see paths.sh)
#   set-secret.sh                      -> <data root>/shared/secrets.env              (shared)
#   set-secret.sh --org                -> <data root>/org/secrets.env                 (org-wide)
#   set-secret.sh --agent enum         -> <data root>/org/enum/secrets.env            (per-agent)
#   set-secret.sh --user alice         -> <data root>/org/users/alice/secrets.env     (per-user)
#
# PERMISSIONS DIFFER BY TIER, deliberately:
#   shared:               0640 root:agenti-shared — every service account is a
#                         member of agenti-shared.
#   org / agent / user:   0600 agenti-run:agenti-run — owned by the one account
#                         that runs the agents.
#
# Usage:  sudo ./set-secret.sh [--org | --agent <a> | --user <u>] [--show]
#
set -euo pipefail

# shellcheck source=paths.sh
source "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/paths.sh"
SHARED_GROUP="${AGENTI_SHARED_GROUP:-agenti-shared}"

# The ONE service account every agent runs as (kept identical in vault.sh,
# agenti, configure.sh and here).
SVC_USER="agenti-run"

die() { printf '\nERROR: %s\n' "$*" >&2; exit 1; }

ORG=0
AGENT=""
USER_NAME=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --org) ORG=1; shift ;;
        --agent)
            AGENT="${2:-}"
            [[ -n "$AGENT" ]] || die "--agent needs a name, e.g. --agent enum"
            shift 2 ;;
        --user)
            USER_NAME="${2:-}"
            [[ -n "$USER_NAME" ]] || die "--user needs a name, e.g. --user alice"
            shift 2 ;;
        --show) break ;;
        *) break ;;
    esac
done

if [[ -n "$USER_NAME" ]]; then
    PREFIX="$AGENTI_ROOT/org/users/$USER_NAME"
    OWNER="$SVC_USER"
    TIER="per-user ($USER_NAME)"
elif [[ -n "$AGENT" ]]; then
    PREFIX="$AGENTI_ROOT/org/$AGENT"
    OWNER="$SVC_USER"
    TIER="agent-specific ($AGENT)"
elif [[ $ORG -eq 1 ]]; then
    PREFIX="$AGENTI_ROOT/org"
    OWNER="$SVC_USER"
    TIER="org-wide"
else
    PREFIX="$AGENTI_ROOT/shared"
    OWNER=""            # shared tier: root:agenti-shared, not one account
    TIER="shared"
fi
SECRETS="$PREFIX/secrets.env"

_SHOW_FLAGS="${USER_NAME:+--user $USER_NAME }${AGENT:+--agent $AGENT }$([[ $ORG -eq 1 ]] && echo "--org " || true)"
[[ $EUID -eq 0 ]] || die "must run as root. Try: sudo $0 ${_SHOW_FLAGS}${1:-}"
if agenti_vault_enabled && ! agenti_data_ready; then
    die "the vault is locked, so no key can be written. Unlock it:  sudo agenti vault unlock"
fi
if [[ -n "$USER_NAME" ]]; then
    # Per-user dir may not exist yet — create it now so the tier is usable
    # before the user has ever launched an agent.
    mkdir -p "$PREFIX"
    chown "$SVC_USER:$SVC_USER" "$PREFIX"
    chmod 700 "$PREFIX"
fi
[[ -d "$PREFIX" ]] || die "$PREFIX does not exist.
recreate the data folders:  sudo dpkg-reconfigure agenti"
if [[ -n "$OWNER" ]]; then
    id "$OWNER" &>/dev/null || die "service account '$OWNER' missing — recreate it:  sudo dpkg-reconfigure agenti"
fi

# --- status mode ------------------------------------------------------------
if [[ "${1:-}" == "--show" ]]; then
    if [[ -f "$SECRETS" ]]; then
        mode=$(stat -c '%a' "$SECRETS"); owner=$(stat -c '%U:%G' "$SECRETS")
        echo "secrets.env ($TIER) present: mode $mode, owner $owner"
        # Show ONLY a fingerprint — never the key.
        if grep -q '^ANTHROPIC_API_KEY=' "$SECRETS"; then
            key=$(grep '^ANTHROPIC_API_KEY=' "$SECRETS" | head -1 | cut -d= -f2-)
            echo "ANTHROPIC_API_KEY set: ${key:0:7}… (${#key} chars, sha256 ${key:+$(printf '%s' "$key" | sha256sum | cut -c1-12)})"
        else
            echo "ANTHROPIC_API_KEY: NOT SET"
        fi
    else
        echo "secrets.env ($TIER) not present at $SECRETS"
    fi
    exit 0
fi

# --- write mode -------------------------------------------------------------
if [[ -f "$SECRETS" ]]; then
    echo "$SECRETS ($TIER) already exists; this will REPLACE the stored key."
    read -r -p "continue? [y/N] " reply
    [[ "$reply" =~ ^[Yy]$ ]] || { echo "aborted."; exit 0; }
fi

echo "Paste the Anthropic API key, then press Enter."
echo "(input is hidden — nothing will appear as you type)"
read -rs API_KEY
echo

[[ -n "$API_KEY" ]] || die "no key entered"
# Cheap sanity check — catches a mis-paste before you discover it at runtime.
[[ "$API_KEY" == sk-ant-* ]] || die "that does not look like an Anthropic key (expected it to start with 'sk-ant-')"
[[ "$API_KEY" != *[[:space:]]* ]] || die "the key contains whitespace — likely a bad paste"

# Write via a temp file in the same directory, then atomically move it, so
# the key is never briefly readable at a looser mode.
TMP=$(mktemp "$PREFIX/.secrets.XXXXXX")
if [[ -n "$OWNER" ]]; then
    chmod 600 "$TMP"
else
    chmod 640 "$TMP"
fi
cat > "$TMP" <<EOF
# secrets.env ($TIER) — loaded by the harness via agent_runtime.load_secrets()'s
# ordered candidate list. $( [[ -n "$OWNER" ]] && echo "0600 ${OWNER}:${OWNER}." || echo "0640 root:${SHARED_GROUP} — the service account is a member." )
# Never commit this file anywhere.
ANTHROPIC_API_KEY=${API_KEY}
EOF
if [[ -n "$OWNER" ]]; then
    chown "$OWNER:$OWNER" "$TMP"
else
    chown "root:$SHARED_GROUP" "$TMP"
fi
mv -f "$TMP" "$SECRETS"
unset API_KEY

# --- verify what we wrote ---------------------------------------------------
mode=$(stat -c '%a' "$SECRETS")
owner=$(stat -c '%U:%G' "$SECRETS")
if [[ -n "$OWNER" ]]; then
    [[ "$mode" == "600" ]]              || die "mode ended up $mode, expected 600"
    [[ "$owner" == "$OWNER:$OWNER" ]]   || die "owner ended up $owner"
else
    [[ "$mode" == "640" ]]                        || die "mode ended up $mode, expected 640"
    [[ "$owner" == "root:$SHARED_GROUP" ]]        || die "owner ended up $owner"
fi

echo "  [ OK ] $SECRETS  $owner  $mode"

# Prove the RIGHT accounts can read it and an unrelated one cannot.
if [[ -n "$OWNER" ]]; then
    if runuser -u "$OWNER" -- test -r "$SECRETS"; then
        echo "  [ OK ] readable by $OWNER"
    else
        die "$OWNER cannot read $SECRETS"
    fi
else
    # Shared tier: prove a member of the shared group can read it via group
    # membership — the actual mechanism this tier depends on, not just "the
    # mode bits look right." An actual MEMBER, not just any agenti-* account
    # (agenti-api and agenti-authd are not members).
    local_acct=$(getent group "$SHARED_GROUP" | cut -d: -f4 | tr ',' '\n' | sed -n 1p || true)
    if [[ -n "$local_acct" ]]; then
        if runuser -u "$local_acct" -- test -r "$SECRETS"; then
            echo "  [ OK ] readable by '$local_acct' via group '$SHARED_GROUP'"
        else
            die "'$local_acct' cannot read $SECRETS — check its membership in '$SHARED_GROUP'"
        fi
    fi
fi
if runuser -u nobody -- test -r "$SECRETS" 2>/dev/null; then
    die "SECRETS READABLE BY 'nobody' — permissions are wrong"
else
    echo "  [ OK ] not readable by unrelated accounts"
fi

echo
echo "secret installed ($TIER). Runs that use this tier will authenticate with it from their next start."
echo "  status:  sudo $0 ${_SHOW_FLAGS}--show"
