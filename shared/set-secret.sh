#!/usr/bin/env bash
#
# set-secret.sh — install an AI provider's API key into the data root (the
# vault, when it is enabled). Run through `sudo agenti setup` or `sudo agenti <agent> set-key`.
#
#   --provider anthropic   ANTHROPIC_API_KEY (the default)
#   --provider openai      OPENAI_API_KEY
#   --provider local       LOCAL_LLM_API_KEY, for a self-hosted model; with
#                          --base-url <http(s)://host:port/v1> its address
#                          (LOCAL_LLM_BASE_URL, not a secret but kept with it)
# Each tier's file holds every provider's key: setting one replaces only its
# own line (docs/model-providers.md).
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
# Usage:  sudo ./set-secret.sh [--provider anthropic|openai|local] [--base-url <url>]
#                               [--org | --agent <a> | --user <u>] [--show | --stdin]
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
STDIN=0        # --stdin: the key is the first line of stdin, no questions (Settings → Platform)
AGENT=""
USER_NAME=""
PROVIDER="anthropic"
BASE_URL=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --provider)
            PROVIDER="${2:-}"
            [[ "$PROVIDER" =~ ^(anthropic|openai|local)$ ]] || die "--provider is one of: anthropic, openai, local"
            shift 2 ;;
        --base-url)
            BASE_URL="${2:-}"
            python3 -c 'import sys; sys.path.insert(0,sys.argv[1]); from model_registry import validate_base_url; validate_base_url(sys.argv[2])' "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" "$BASE_URL" \
                || die "--base-url needs the model server's HTTP or HTTPS address, e.g. http://model.example.com:11434/v1"
            shift 2 ;;
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
        --stdin) STDIN=1; shift ;;
        *) break ;;
    esac
done
[[ -z "$AGENT" || "$AGENT" =~ ^[a-z0-9][a-z0-9_-]{0,63}$ ]] || die "invalid agent name"
[[ -z "$USER_NAME" || "$USER_NAME" =~ ^[a-z0-9][a-z0-9_-]{0,63}$ ]] || die "invalid user name"
tiers=$ORG
[[ -z "$AGENT" ]] || tiers=$((tiers + 1))
[[ -z "$USER_NAME" ]] || tiers=$((tiers + 1))
[[ $tiers -le 1 ]] || die "choose one tier: --org, --agent or --user"
[[ $# -eq 0 || ( $# -eq 1 && "$1" == --show ) ]] || die "unknown option '$1'; use --provider anthropic|openai|local [--base-url URL] [--org | --agent NAME | --user NAME] [--stdin | --show]"

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
case "$PROVIDER" in
    anthropic) KEY_VAR=ANTHROPIC_API_KEY; KEY_LABEL="Anthropic"; KEY_PREFIX="sk-ant-" ;;
    openai)    KEY_VAR=OPENAI_API_KEY;    KEY_LABEL="OpenAI";    KEY_PREFIX="sk-" ;;
    local)     KEY_VAR=LOCAL_LLM_API_KEY; KEY_LABEL="self-hosted model"; KEY_PREFIX="" ;;
esac
[[ -z "$BASE_URL" || "$PROVIDER" == local ]] || die "--base-url is for --provider local (a self-hosted model)"

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
        for var in ANTHROPIC_API_KEY OPENAI_API_KEY LOCAL_LLM_API_KEY; do
            if grep -q "^$var=." "$SECRETS"; then
                key=$(grep "^$var=" "$SECRETS" | head -1 | cut -d= -f2-)
                echo "$var set: ${key:0:7}… (${#key} chars, sha256 $(printf '%s' "$key" | sha256sum | cut -c1-12))"
            else
                echo "$var: NOT SET"
            fi
        done
        url=$(sed -n 's/^LOCAL_LLM_BASE_URL=//p' "$SECRETS" | head -1)
        echo "LOCAL_LLM_BASE_URL: ${url:-NOT SET}"
    else
        echo "secrets.env ($TIER) not present at $SECRETS"
    fi
    exit 0
fi

# --- write mode -------------------------------------------------------------
if [[ $STDIN -eq 1 ]]; then
    IFS= read -r API_KEY || true
else
    if [[ -f "$SECRETS" ]] && grep -q "^$KEY_VAR=." "$SECRETS"; then
        echo "$SECRETS ($TIER) already holds a $KEY_LABEL key; this will REPLACE it."
        read -r -p "continue? [y/N] " reply
        [[ "$reply" =~ ^[Yy]$ ]] || { echo "aborted."; exit 0; }
    fi
    if [[ "$PROVIDER" == local ]]; then
        echo "Paste the self-hosted model's API key, or just press Enter if it needs none."
    else
        echo "Paste the $KEY_LABEL API key, then press Enter."
    fi
    echo "(input is hidden — nothing will appear as you type)"
    read -rs API_KEY
    echo
fi

[[ -n "$API_KEY" || "$PROVIDER" == local ]] || die "no key entered"
# Cheap sanity check — catches a mis-paste before you discover it at runtime.
[[ -z "$KEY_PREFIX" || "$API_KEY" == "$KEY_PREFIX"* ]] \
    || die "that does not look like an $KEY_LABEL key (expected it to start with '$KEY_PREFIX')"
[[ "$API_KEY" != *[[:space:]]* ]] || die "the key contains whitespace — likely a bad paste"
[[ "$PROVIDER" != local || -n "$BASE_URL" ]] || grep -qs '^LOCAL_LLM_BASE_URL=.' "$SECRETS" \
    || die "a self-hosted model needs its address: add --base-url http://<host>:<port>/v1"

# Write via a temp file in the same directory, then atomically move it, so
# the key is never briefly readable at a looser mode.
TMP=$(mktemp "$PREFIX/.secrets.XXXXXX")
if [[ -n "$OWNER" ]]; then
    chmod 600 "$TMP"
else
    chmod 640 "$TMP"
fi
{
    cat <<EOF
# secrets.env ($TIER) — loaded by the harness via agent_runtime.load_secrets()'s
# ordered candidate list. $( [[ -n "$OWNER" ]] && echo "0600 ${OWNER}:${OWNER}." || echo "0640 root:${SHARED_GROUP} — the service account is a member." )
# Never commit this file anywhere.
EOF
    # Every other provider's line stays as it was; this one is replaced.
    if [[ -f "$SECRETS" ]]; then
        grep -E '^[A-Z_]+=' "$SECRETS" | grep -v "^$KEY_VAR=" \
            | { if [[ -n "$BASE_URL" ]]; then grep -v '^LOCAL_LLM_BASE_URL='; else cat; fi; } || true
    fi
    [[ -n "$API_KEY" ]] && printf '%s=%s\n' "$KEY_VAR" "$API_KEY"
    [[ -n "$BASE_URL" ]] && printf 'LOCAL_LLM_BASE_URL=%s\n' "$BASE_URL"
    true
} > "$TMP"
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
