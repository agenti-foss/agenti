#!/usr/bin/env bash
#
# set-secret.sh — install an AI provider's API key, encrypted (keystore.py:
# AES-256-GCM on disk, sealed by the TPM, the vault or a key passphrase). Run
# through `sudo agenti setup` or `sudo agenti <agent> set-key`.
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
# STORAGE: <tier>/secrets.enc, root 0600, encrypted; the unlocked copy lives
# only in the in-memory folder /run/agenti-keys (root 0700). A box upgraded
# from before 0.1.4 with no TPM and no vault keeps plain secrets.env files
# (shared 0640 root:agenti-shared, others 0600 agenti-run) until an admin sets
# a key passphrase: sudo agenti keys seal.
#
# Usage:  sudo ./set-secret.sh [--provider anthropic|openai|local] [--base-url <url>]
#                               [--org | --agent <a> | --user <u>] [--show | --stdin | --remove]
#         --stdin --passphrase-first: stdin's first line is a new key passphrase
#         (a box with no TPM and no vault, before its first key), the second the key.
#
set -euo pipefail

HERE="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
# shellcheck source=paths.sh
source "$HERE/paths.sh"

# The ONE service account every agent runs as (kept identical in vault.sh,
# agenti, configure.sh and here).
SVC_USER="agenti-run"

die() { printf '\nERROR: %s\n' "$*" >&2; exit 1; }

ORG=0
STDIN=0        # --stdin: the key is the first line of stdin, no questions (Settings → Platform)
PASS_FIRST=0   # --passphrase-first: a key passphrase line comes before the key
REMOVE=0
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
            python3 -c 'import sys; sys.path.insert(0,sys.argv[1]); from model_registry import validate_base_url; validate_base_url(sys.argv[2])' "$HERE" "$BASE_URL" \
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
        --passphrase-first) PASS_FIRST=1; shift ;;
        --remove) REMOVE=1; shift ;;
        *) break ;;
    esac
done
[[ -z "$AGENT" || "$AGENT" =~ ^[a-z0-9][a-z0-9_-]{0,63}$ ]] || die "invalid agent name"
[[ -z "$USER_NAME" || "$USER_NAME" =~ ^[a-z0-9][a-z0-9_-]{0,63}$ ]] || die "invalid user name"
tiers=$ORG
[[ -z "$AGENT" ]] || tiers=$((tiers + 1))
[[ -z "$USER_NAME" ]] || tiers=$((tiers + 1))
[[ $tiers -le 1 ]] || die "choose one tier: --org, --agent or --user"
[[ $# -eq 0 || ( $# -eq 1 && "$1" == --show ) ]] || die "unknown option '$1'; use --provider anthropic|openai|local [--base-url URL] [--org | --agent NAME | --user NAME] [--stdin | --show | --remove]"
[[ $PASS_FIRST -eq 0 || $STDIN -eq 1 ]] || die "--passphrase-first goes with --stdin"

if [[ -n "$USER_NAME" ]]; then
    REL="org/users/$USER_NAME"; TIER="per-user ($USER_NAME)"
elif [[ -n "$AGENT" ]]; then
    REL="org/$AGENT"; TIER="agent-specific ($AGENT)"
elif [[ $ORG -eq 1 ]]; then
    REL="org"; TIER="org-wide"
else
    REL="shared"; TIER="shared"
fi
PREFIX="$AGENTI_ROOT/$REL"
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
if [[ "$REL" != shared ]]; then   # the shared tier is root's, not one account's
    id "$SVC_USER" &>/dev/null || die "service account '$SVC_USER' missing — recreate it:  sudo dpkg-reconfigure agenti"
fi

# --- remove mode ------------------------------------------------------------
if [[ $REMOVE -eq 1 ]]; then
    agenti_keystore forget --tier "$REL" >/dev/null || die "the $TIER keys could not be removed"
    echo "  [ OK ] the $TIER keys are removed"
    exit 0
fi

STATUS=$(agenti_keystore status 2>/dev/null) || STATUS='{}'
KSTATE=$(printf '%s' "$STATUS" | agenti_json_field state)

# --- status mode ------------------------------------------------------------
if [[ "${1:-}" == "--show" ]]; then
    case "$KSTATE" in
        unlocked) echo "keys: encrypted ($(printf '%s' "$STATUS" | agenti_json_field seal) seal), unlocked" ;;
        locked)   die "the keys are locked, so nothing can be shown. Unlock them:  sudo agenti keys unlock" ;;
        plain)    echo "keys: NOT encrypted (set a key passphrase:  sudo agenti keys seal)" ;;
        *)        echo "keys: none saved yet" ;;
    esac
    TEXT=$(agenti_keystore get --tier "$REL" 2>/dev/null || true)
    if [[ -n "$TEXT" ]]; then
        echo "$TIER tier:"
        # Show ONLY a fingerprint — never the key.
        for var in ANTHROPIC_API_KEY OPENAI_API_KEY LOCAL_LLM_API_KEY; do
            key=$(printf '%s\n' "$TEXT" | sed -n "s/^$var=//p" | head -1)
            if [[ -n "$key" ]]; then
                echo "$var set: ${key:0:7}… (${#key} chars, sha256 $(printf '%s' "$key" | sha256sum | cut -c1-12))"
            else
                echo "$var: NOT SET"
            fi
        done
        url=$(printf '%s\n' "$TEXT" | sed -n 's/^LOCAL_LLM_BASE_URL=//p' | head -1)
        echo "LOCAL_LLM_BASE_URL: ${url:-NOT SET}"
        unset TEXT key
    else
        echo "$TIER tier: no keys"
    fi
    exit 0
fi

[[ "$KSTATE" != locked ]] || die "the API keys are locked, so no key can be written. Unlock them first:  sudo agenti keys unlock"

# --- write mode -------------------------------------------------------------
# What the tier already sets (yes/no; no key leaves keystore.py).
HAS=$(agenti_keystore has --tier "$REL" "$KEY_VAR" LOCAL_LLM_BASE_URL 2>/dev/null) || HAS='{}'
PASSPHRASE=""
if [[ $STDIN -eq 1 ]]; then
    [[ $PASS_FIRST -eq 0 ]] || IFS= read -r PASSPHRASE || true
    IFS= read -r API_KEY || true
else
    if [[ "$(printf '%s' "$HAS" | agenti_json_field "$KEY_VAR")" == True ]]; then
        echo "The $TIER tier already holds a $KEY_LABEL key; this will REPLACE it."
        read -r -p "continue? [y/N] " reply
        [[ "$reply" =~ ^[Yy]$ ]] || { echo "aborted."; exit 0; }
    fi
    if [[ "$(printf '%s' "$STATUS" | agenti_json_field needs_passphrase)" == True && "$KSTATE" == none ]]; then
        echo "This machine has no TPM chip and the vault is off, so the API keys are"
        echo "encrypted with a key passphrase. After every restart, an admin unlocks them"
        echo "(Settings → Platform, or sudo agenti keys unlock). Store it somewhere safe."
        PASSPHRASE=$(agenti_read_new_passphrase "key passphrase") || exit 1
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
[[ "$PROVIDER" != local || -n "$BASE_URL" || "$(printf '%s' "$HAS" | agenti_json_field LOCAL_LLM_BASE_URL)" == True ]] \
    || die "a self-hosted model needs its address: add --base-url http://<host>:<port>/v1"

# keystore.py replaces this provider's line(s) and keeps every other line, all
# under its own lock. Values go on stdin, never an argument or a file; an empty
# key removes that line (a self-hosted server with no key).
SET_ARGS=(set --tier "$REL")
[[ -z "$PASSPHRASE" ]] || SET_ARGS+=(--passphrase-first)
SET_ARGS+=("$KEY_VAR")
[[ -z "$BASE_URL" ]] || SET_ARGS+=(LOCAL_LLM_BASE_URL)
OUT=$({
    [[ -z "$PASSPHRASE" ]] || printf '%s\n' "$PASSPHRASE"
    printf '%s\n' "$API_KEY"
    [[ -z "$BASE_URL" ]] || printf '%s\n' "$BASE_URL"
} | agenti_keystore "${SET_ARGS[@]}" 2>/dev/null) || die "$(printf '%s' "$OUT" | agenti_json_field error)"
unset API_KEY PASSPHRASE

if [[ "$(printf '%s' "$OUT" | agenti_json_field stored)" == encrypted ]]; then
    ENC="$PREFIX/secrets.enc"
    mode=$(stat -c '%a' "$ENC"); owner=$(stat -c '%U:%G' "$ENC")
    [[ "$mode" == 600 && "$owner" == root:root ]] || die "$ENC ended up $owner $mode, expected root:root 600"
    grep -q "$KEY_PREFIX" "$ENC" 2>/dev/null && [[ -n "$KEY_PREFIX" ]] && die "$ENC holds the key in plain text"
    echo "  [ OK ] $ENC  encrypted ($(printf '%s' "$OUT" | agenti_json_field seal) seal)  $owner $mode"
else
    SECRETS="$PREFIX/secrets.env"
    echo "  [WARN] $SECRETS is NOT encrypted: this machine has no TPM and no vault, and no key"
    echo "         passphrase is set yet. Set one:  sudo agenti keys seal"
    if runuser -u nobody -- test -r "$SECRETS" 2>/dev/null; then
        die "SECRETS READABLE BY 'nobody' — permissions are wrong"
    fi
fi

echo
echo "secret installed ($TIER). Runs that use this tier will authenticate with it from their next start."
echo "  status:  sudo $0 ${_SHOW_FLAGS}--show"
