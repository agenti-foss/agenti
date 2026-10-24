#!/usr/bin/env bash
#
# vault.sh — the OPTIONAL encrypted container for Agenti's data.
#
#   Off by default: the data lives in a plain folder, the data root
#   (/var/lib/agenti/data, see paths.sh). `enable` moves it into a LUKS2
#   container file mounted at that same path; from then on the data is
#   ciphertext whenever the vault is locked, and nothing that needs data runs
#   until someone unlocks it. Code, the user database, sessions and TLS are
#   never inside: sign-in keeps working, and can say "the vault is locked".
#
# WHO WANTS IT: a drop box on a client's network, or any machine without the
# operating system's full-disk encryption (Kali's installer offers that, and it
# is the better choice where you can have it).
#
# THREAT MODEL — be honest about what this does and does not do:
#   PROTECTS against: the machine stolen or seized while powered off or locked.
#                     Reports, scan data and API keys are unrecoverable without
#                     the passphrase.
#   Does NOT protect:  a running, unlocked machine (root and the service account
#                     can read the data until lock or power-off), or anyone who
#                     can change the code or the OS while it is off (the code is
#                     outside the vault; full-disk encryption covers that).
#   No keyfile on disk, by design: the passphrase lives in your head.
#
# LIFECYCLE (vault enabled)
#   boot            -> locked: the data root is an EMPTY, IMMUTABLE folder
#                      (chattr +i), so nothing can write data to the bare disk.
#   vault unlock    -> passphrase prompt, mounts. Agents can run.
#   vault lock      -> unmounts and closes. Or pull the power.
#
# Usage (normally through `sudo agenti vault <verb>`):
#   vault.sh status
#   vault.sh enable [--size 8G]     create the container and move the data in
#   vault.sh disable                move the data back out (asks first)
#   vault.sh unlock | lock
#   vault.sh passphrase             change it (the data is not touched)
#
# NEVER handles the passphrase itself: cryptsetup prompts for it on the terminal.
set -euo pipefail

# shellcheck source=paths.sh
source "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/paths.sh"
HERE="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
CONFIGURE="$HERE/configure.sh"
DATA="$AGENTI_ROOT"
SIZE="8G"
MAPPER="agenti_vault"
IMG="$AGENTI_STATE/vault.img"
# An enabled vault records where its container is; that file IS the switch.
if [[ -f "$AGENTI_VAULT_CONF" ]]; then
    IMG=$(sed -n 's/^IMAGE=//p' "$AGENTI_VAULT_CONF" | head -n1)
    MAPPER=$(sed -n 's/^MAPPER=//p' "$AGENTI_VAULT_CONF" | head -n1)
    [[ -n "$IMG" && -n "$MAPPER" ]] || { printf '\nERROR: %s is damaged (needs IMAGE= and MAPPER= lines).\n' "$AGENTI_VAULT_CONF" >&2; exit 1; }
fi
DEV="/dev/mapper/$MAPPER"

ok()   { printf '  [ OK ] %s\n' "$*"; }
warn() { printf '  [WARN] %s\n' "$*"; }
die()  { printf '\nERROR: %s\n' "$*" >&2; exit 1; }

usage() {
    cat <<EOF
usage: sudo agenti vault <status | enable [--size 8G] | disable | unlock | lock | passphrase>

The vault is optional and off by default. Turned on, the data folder
($DATA) becomes an encrypted container you unlock after every boot.
EOF
}

case "${1:-status}" in -h|--help|help) usage; exit 0 ;; esac
[[ $EUID -eq 0 ]] || die "must run as root. Try: sudo agenti vault ${1:-status}"

is_open()    { [[ -e "$DEV" ]]; }
is_mounted() { findmnt -rn --target "$DATA" -o SOURCE 2>/dev/null | grep -qx "$DEV"; }
need_cryptsetup() {
    command -v cryptsetup >/dev/null || die "cryptsetup is not installed. Install it:  sudo apt install cryptsetup"
}
# Nothing may hold files open in the data root while it moves.
no_active_runs() {
    local active
    active=$(systemctl list-units --type=service --state=active --plain --no-legend 'agenti-*-instance@*' 2>/dev/null \
             | awk '{print $1}' || true)
    [[ -z "$active" ]] || die "agent runs are still going, so the data cannot move:
$active
stop them first:  sudo systemctl stop 'agenti-*-instance@*'"
}
# Same relative paths on both sides (lost+found aside: a fresh ext4 has one).
same_tree() {
    local a b rc=0
    a=$(mktemp); b=$(mktemp)
    ( cd "$1" && find . -mindepth 1 -path ./lost+found -prune -o -print | sort ) > "$a"
    ( cd "$2" && find . -mindepth 1 -path ./lost+found -prune -o -print | sort ) > "$b"
    if ! diff -q "$a" "$b" >/dev/null; then
        echo "  differences (< only in $1, > only in $2):" >&2
        diff "$a" "$b" | head -20 >&2
        rc=1
    fi
    rm -f "$a" "$b"
    return $rc
}
rerender_units() {
    if [[ -x "$CONFIGURE" ]]; then
        "$CONFIGURE" units >/dev/null && ok "every agent's run unit re-rendered for the new vault setting" \
            || warn "could not re-render the run units — fix with:  sudo dpkg-reconfigure agenti"
    else
        warn "$CONFIGURE is missing — re-render the run units:  sudo dpkg-reconfigure agenti"
    fi
}
provision_data() {
    [[ -x "$CONFIGURE" ]] && "$CONFIGURE" data >/dev/null 2>&1 \
        || warn "could not check the data folders — fix with:  sudo dpkg-reconfigure agenti"
}


# ---------------------------------------------------------------------------
cmd_status() {
    echo "vault status:"
    if ! agenti_vault_enabled; then
        ok "vault       OFF — data is a plain folder at $DATA"
        echo "              (turn it on:  sudo agenti vault enable;  better where possible: full-disk encryption)"
        return 0
    fi
    if [[ -f "$IMG" ]]; then
        ok "container   $IMG ($(du -h "$IMG" | cut -f1) on disk, $(stat -c '%a %U:%G' "$IMG"))"
    else
        warn "container   $IMG is MISSING but the vault is enabled ($AGENTI_VAULT_CONF) — nothing can run"
        return 0
    fi
    if is_open; then ok "LUKS        OPEN   ($DEV)"; else echo "  [LOCK] LUKS        CLOSED"; fi
    if is_mounted; then
        ok "mount       $DATA <- $DEV"
        [[ -d "$DATA/org" ]] && ok "data        $DATA/org present" \
                            || warn "data        $DATA/org missing — recreate:  sudo dpkg-reconfigure agenti"
    else
        echo "  [LOCK] mount       $DATA not mounted (nothing that needs data can run — correct while locked)"
    fi
}


# ---------------------------------------------------------------------------
# enable: plain data -> a new container, verified copy, then the plain copy is
# deleted (operator decision 2026-10-21: a kept copy left the API key readable
# on the bare disk). Any failure before that leaves the plain data exactly as
# it was.
_E_MADE_IMG=0 _E_STAGING="" _E_MOVED=0 _E_DONE=0
_enable_rollback() {
    [[ $_E_DONE -eq 1 ]] && return 0
    echo >&2; warn "enable did not complete — rolling back"
    if [[ -n "$_E_STAGING" ]] && mountpoint -q "$_E_STAGING" 2>/dev/null; then umount "$_E_STAGING" || true; fi
    [[ -n "$_E_STAGING" && -d "$_E_STAGING" ]] && rmdir "$_E_STAGING" 2>/dev/null || true
    if is_mounted; then umount "$DATA" || true; fi
    if [[ $_E_MOVED -eq 1 && -d "$DATA.pre-vault" ]]; then
        chattr -i "$DATA" 2>/dev/null || true
        rmdir "$DATA" 2>/dev/null || true
        mv "${DATA:?}.pre-vault" "$DATA" && warn "plain data restored to $DATA"
    fi
    if is_open; then cryptsetup close "$MAPPER" 2>/dev/null || true; fi
    rm -f "$AGENTI_VAULT_CONF"
    if [[ $_E_MADE_IMG -eq 1 && -f "$IMG" ]]; then rm -f "${IMG:?}" && warn "removed the partial container"; fi
    warn "rollback complete — nothing was lost; safe to re-run"
}

cmd_enable() {
    # --passphrase-stdin --yes: the GUI's path (decision 6, audit run 1), reached
    # only through `agenti vault enable --grant` after an admin re-authenticated.
    # The passphrase is one line on stdin, held in this shell's memory, handed to
    # cryptsetup on its stdin (printf is a shell builtin: never on any command
    # line) and stored nowhere.
    local from_stdin=0 assume_yes=0 pp=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --size)   [[ $# -ge 2 ]] || die "--size needs a value, e.g. --size 16G"; SIZE="$2"; shift 2 ;;
            --size=*) SIZE="${1#*=}"; shift ;;
            --passphrase-stdin) from_stdin=1; shift ;;
            --yes) assume_yes=1; shift ;;
            *) die "unknown option for enable: $1 (usage: sudo agenti vault enable [--size 8G])" ;;
        esac
    done
    [[ "$SIZE" =~ ^[1-9][0-9]*G$ ]] || die "--size must be a whole number of gigabytes, like 8G (got '$SIZE')"
    agenti_vault_enabled && die "the vault is already enabled ($AGENTI_VAULT_CONF). Status:  sudo agenti vault status"
    need_cryptsetup
    [[ -d "$DATA" ]] || die "$DATA does not exist. Recreate it first:  sudo dpkg-reconfigure agenti"
    [[ -e "$IMG" ]] && die "$IMG already exists (an old container?). Move or delete it first."
    [[ -e "$DATA.pre-vault" ]] && die "$DATA.pre-vault exists from an earlier attempt. Check it, then remove or restore it."
    no_active_runs
    local need avail
    need=$(du -sk "$DATA" | cut -f1)
    avail=$(df -Pk "$(dirname "$IMG")" | awk 'NR==2 {print $4}')
    (( avail > ${SIZE%G} * 1048576 + need )) || die "not enough free disk for a $SIZE container plus a copy of the data ($((need / 1024)) MB) in $(dirname "$IMG")."
    (( need < ${SIZE%G} * 1048576 * 9 / 10 )) || die "the data ($((need / 1024)) MB) would not fit comfortably in $SIZE. Choose a bigger --size."

    if [[ $from_stdin -eq 1 ]]; then
        IFS= read -r pp || true
        [[ ${#pp} -ge 12 ]] || die "the passphrase must be at least 12 characters"
        [[ ${#pp} -le 512 ]] || die "the passphrase must be 512 characters or fewer"
    fi
    cat <<EOF
This turns the vault on:
  - a $SIZE encrypted container is created at $IMG
  - everything in $DATA ($((need / 1024)) MB) is copied in and checked
  - from then on, after EVERY boot, someone must run:  sudo agenti vault unlock
    (until then nobody can start an agent or read a report; sign-in still works)

You will choose a passphrase. THERE IS NO RECOVERY IF YOU FORGET IT.
EOF
    if [[ $assume_yes -ne 1 ]]; then
        local reply; read -r -p "continue? [y/N] " reply
        [[ "$reply" =~ ^[Yy]$ ]] || { echo "nothing changed."; exit 0; }
    fi

    trap _enable_rollback EXIT
    install -m 0600 -o root -g root /dev/null "$IMG"; _E_MADE_IMG=1
    fallocate -l "$SIZE" "$IMG" 2>/dev/null \
        || dd if=/dev/zero of="$IMG" bs=1M count=$(( ${SIZE%G} * 1024 )) status=none
    ok "$IMG allocated (0600 root:root)"
    if [[ $from_stdin -eq 1 ]]; then
        printf '%s' "$pp" | cryptsetup luksFormat --type luks2 --batch-mode --key-file=- "$IMG" \
            || die "luksFormat failed"
        printf '%s' "$pp" | cryptsetup open --key-file=- "$IMG" "$MAPPER" \
            || die "could not open the new container"
        pp=""
    else
        echo; echo "formatting LUKS2 — choose the passphrase (asked TWICE):"
        cryptsetup luksFormat --type luks2 --batch-mode --verify-passphrase "$IMG" || die "luksFormat failed"
        echo; echo "opening it (passphrase again):"
        cryptsetup open "$IMG" "$MAPPER" || die "could not open the new container"
    fi
    mkfs.ext4 -q -L agenti-data "$DEV" || die "mkfs.ext4 failed"
    ok "encrypted filesystem created"

    _E_STAGING=$(mktemp -d)
    mount "$DEV" "$_E_STAGING" || die "could not mount the new filesystem"
    cp -a "$DATA/." "$_E_STAGING/" || die "copy failed — $DATA is untouched"
    same_tree "$DATA" "$_E_STAGING" || die "the copy does not match — $DATA is untouched"
    ok "data copied into the container and checked"
    umount "$_E_STAGING"; rmdir "$_E_STAGING"; _E_STAGING=""

    local had_key=0
    find "$DATA" -name secrets.env -size +0 -print -quit 2>/dev/null | grep -q . && had_key=1
    mv "$DATA" "$DATA.pre-vault"; _E_MOVED=1
    install -d -o root -g root -m 0751 "$DATA"
    # Locked, the data root must stay empty: nothing can create files in an
    # immutable folder, so no run or tool can quietly write data to the bare disk.
    chattr +i "$DATA" || die "chattr +i failed on $DATA (does this filesystem support it?)"
    printf '# Written by `agenti vault enable`; removing it turns the vault off.\nIMAGE=%s\nMAPPER=%s\n' \
        "$IMG" "$MAPPER" > "$AGENTI_VAULT_CONF"
    chmod 0644 "$AGENTI_VAULT_CONF"
    mount "$DEV" "$DATA" || die "could not mount the vault at $DATA"
    chown root:root "$DATA"; chmod 0751 "$DATA"
    _E_DONE=1; trap - EXIT
    ok "vault mounted at $DATA"
    rm -rf "${DATA:?}.pre-vault" && ok "the unencrypted original was deleted (the checked copy is in the vault)"
    rerender_units

    echo; echo "vault enabled."
    [[ $had_key -eq 1 ]] && cat <<EOF

  An API key was stored before the vault was on. Deleted files can survive
  on the disk until overwritten, so replace the key now (the new one is
  stored inside the vault):  sudo /usr/lib/agenti/set-secret.sh
EOF
    cat <<EOF

  After every boot:  sudo agenti vault unlock
EOF
}


# ---------------------------------------------------------------------------
cmd_disable() {
    agenti_vault_enabled || { ok "the vault is already off"; exit 0; }
    is_mounted || die "unlock the vault first so the data can be copied out:  sudo agenti vault unlock"
    no_active_runs
    local need avail stage="$AGENTI_STATE/data.plain"
    [[ -e "$stage" ]] && die "$stage exists from an earlier attempt. Check it, then remove it."
    need=$(du -sk "$DATA" | cut -f1)
    avail=$(df -Pk "$AGENTI_STATE" | awk 'NR==2 {print $4}')
    (( avail > need )) || die "not enough free disk to copy the data ($((need / 1024)) MB) out of the vault."
    cat <<EOF
This turns the vault OFF: every engagement's data ($((need / 1024)) MB) is copied
OUT of the encrypted container into a plain folder at $DATA. After that the
data is only as protected as this disk.
EOF
    local reply; read -r -p "continue? [y/N] " reply
    [[ "$reply" =~ ^[Yy]$ ]] || { echo "nothing changed."; exit 0; }

    install -d -o root -g root -m 0751 "$stage"
    cp -a "$DATA/." "$stage/" || { rm -rf "${stage:?}"; die "copy failed — the vault is untouched"; }
    rm -rf "${stage:?}/lost+found"
    same_tree "$DATA" "$stage" || { rm -rf "${stage:?}"; die "the copy does not match — the vault is untouched"; }
    ok "data copied out and checked"
    umount "$DATA" || { rm -rf "${stage:?}"; die "could not unmount $DATA (something still uses it); the vault is untouched"; }
    cryptsetup close "$MAPPER" || true
    chattr -i "$DATA" 2>/dev/null || true
    rmdir "$DATA"
    mv "$stage" "$DATA"
    chown root:root "$DATA"; chmod 0751 "$DATA"
    rm -f "$AGENTI_VAULT_CONF"
    ok "data is a plain folder at $DATA again"
    rerender_units
    cat <<EOF

vault disabled. The container still holds the old encrypted copy:
  $IMG
Delete it once you are sure you do not need it:  sudo rm $IMG
EOF
}


# ---------------------------------------------------------------------------
cmd_unlock() {
    agenti_vault_enabled || { ok "the vault is off — there is nothing to unlock (data: $DATA)"; exit 0; }
    need_cryptsetup
    [[ -f "$IMG" ]] || die "the container $IMG is missing (vault enabled in $AGENTI_VAULT_CONF)."
    if is_mounted; then ok "already unlocked and mounted at $DATA"; exit 0; fi
    if ! is_open; then
        # Do not guess a cause: a wrong passphrase, a cancelled prompt and a
        # damaged header all exit non-zero, and guessing wrong makes a harmless
        # cancel look like data loss.
        cryptsetup open "$IMG" "$MAPPER" \
            || die "vault not unlocked — wrong passphrase, cancelled, or a damaged container"
        ok "LUKS opened"
    else
        ok "LUKS already open"
    fi
    [[ -d "$DATA" ]] || { install -d -o root -g root -m 0751 "$DATA"; chattr +i "$DATA" 2>/dev/null || true; }
    # Never mount OVER files: that would hide them (and they would be unencrypted).
    if [[ -n "$(ls -A "$DATA" 2>/dev/null)" ]]; then
        cryptsetup close "$MAPPER" 2>/dev/null || true
        die "$DATA has files in it but the vault is not mounted. Mounting would hide them. Investigate before retrying."
    fi
    mount "$DEV" "$DATA" || { cryptsetup close "$MAPPER"; die "mount failed"; }
    chown root:root "$DATA"; chmod 0751 "$DATA"
    ok "mounted at $DATA"
    provision_data
    echo; echo "unlocked. Agents can run until you lock or power off."
}

cmd_lock() {
    agenti_vault_enabled || { ok "the vault is off — there is nothing to lock (data: $DATA)"; exit 0; }
    if is_mounted; then
        if ! umount "$DATA" 2>/dev/null; then
            echo "cannot unmount — something is using $DATA:" >&2
            fuser -vm "$DATA" 2>&1 | head -10 >&2 || true
            die "stop the runs (sudo systemctl stop 'agenti-*-instance@*') and retry"
        fi
        ok "unmounted $DATA"
    else
        warn "$DATA was not mounted"
    fi
    if is_open; then cryptsetup close "$MAPPER" && ok "LUKS closed — the data is ciphertext at rest"
    else warn "LUKS was not open"; fi
    echo; echo "locked. $DATA is an empty, immutable folder; nothing that needs data can start."
}

cmd_passphrase() {
    agenti_vault_enabled || die "the vault is off, so it has no passphrase. Turn it on:  sudo agenti vault enable"
    need_cryptsetup
    [[ -f "$IMG" ]] || die "the container $IMG is missing."
    printf 'Changing the vault passphrase. YOUR DATA IS NOT TOUCHED —\nLUKS rewrites a key slot, not the volume.\n\n'
    cryptsetup luksChangeKey "$IMG" || die "the passphrase was not changed"
    ok "passphrase changed"
}


verb="${1:-status}"; [[ $# -gt 0 ]] && shift
case "$verb" in
    status)     cmd_status ;;
    enable)     cmd_enable "$@" ;;
    disable)    cmd_disable ;;
    unlock)     cmd_unlock ;;
    lock)       cmd_lock ;;
    passphrase) cmd_passphrase ;;
    *) usage >&2; die "unknown vault command '$verb'" ;;
esac
