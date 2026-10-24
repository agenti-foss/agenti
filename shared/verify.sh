#!/usr/bin/env bash
#
# verify.sh — prove this machine's Agenti install is sound, changing nothing.
# Run as `sudo agenti verify` (or `sudo ./shared/deploy.sh --verify` from a
# checkout). Every privilege boundary is checked by ATTEMPTING the forbidden
# thing as the account that must not be able to do it, not by reading modes:
# a check that only looked at a file would pass the day an ACL or a parent
# folder's mode quietly breaks it.
#
#   verify.sh              everything: platform, GUI and sign-in, every agent
#   verify.sh gui          the GUI, sign-in and the API's privilege boundary
#   verify.sh agent <name> one agent's code, data and unit
#
# Exit 0 only when nothing FAILed. A WARN is something to look at that does
# not break a boundary (no API key yet, a missing optional tool).
set -euo pipefail

HERE="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
# Root-run Python below must never import from the caller's folder (audit
# run 1 F14, run 2 for the scripts that are entry points of their own):
# PYTHONSAFEPATH drops it, and the code folder is named instead.
export PYTHONSAFEPATH=1
export PYTHONPATH="$HERE"
# configure.sh, sourced: the account names, unit paths, the api.conf reader
# and the unit helpers, from the one place that creates them.
# shellcheck source=configure.sh
source "$HERE/configure.sh"
fail() { printf '  [FAIL] %s\n' "$*" >&2; }
svc_exists() { id "$SVC_USER" &>/dev/null; }

verify_platform() {
    local rc=0 u
    echo "the installation:"
    [[ -x "$AGENTI_BIN" ]] && ok "$AGENTI_BIN installed ($("$AGENTI_BIN" --version 2>/dev/null || echo '?'))" \
        || { fail "$AGENTI_BIN missing — reinstall: sudo apt install --reinstall agenti"; rc=1; }
    # The code is root's: no service account may change what runs.
    if [[ -d "$AGENTI_LIBDIR" ]]; then
        local bad; bad=$(find "$AGENTI_LIBDIR" \( ! -user root -o -perm -0002 -o \( -perm -0020 ! -group root \) \) -print -quit 2>/dev/null || true)
        [[ -z "$bad" ]] && ok "$AGENTI_LIBDIR: every file root-owned, none group- or world-writable" \
            || { fail "$bad is not root-only-writable — reinstall: sudo apt install --reinstall agenti"; rc=1; }
        for u in "$SVC_USER" "$API_USER" "$AUTHD_USER"; do
            id "$u" &>/dev/null || continue
            if runuser -u "$u" -- test -w "$AGENTI_LIBDIR" 2>/dev/null || runuser -u "$u" -- test -w "$AGENTI_LIBDIR/agenti-instance@.service" 2>/dev/null; then
                fail "CODE WRITABLE: '$u' can write $AGENTI_LIBDIR"; rc=1
            fi
        done
        [[ $rc -eq 0 ]] && ok "no service account can write the code ($SVC_USER, $API_USER, $AUTHD_USER tried)"
    else
        fail "$AGENTI_LIBDIR missing — reinstall: sudo apt install --reinstall agenti"; rc=1
    fi
    local env mod
    for env in agent:claude_agent_sdk api:fastapi authd:cryptography; do
        mod=${env#*:}; env=${env%%:*}
        "$AGENTI_RUNTIME/$env/bin/python3" -c "import $mod" 2>/dev/null \
            && ok "runtime: the $env environment imports $mod" \
            || { fail "runtime: $AGENTI_RUNTIME/$env cannot import $mod — reinstall: sudo apt install --reinstall agenti-runtime"; rc=1; }
    done
    # Anthropic's Claude Code program: fetched at install, never shipped.
    local cc
    cc=$(ls "$AGENTI_RUNTIME"/agent/lib/python3.*/site-packages/claude_agent_sdk/_bundled/claude 2>/dev/null | sed -n 1p)
    if [[ -n "$cc" && -x "$cc" ]]; then
        ok "runtime: Claude Code is installed (fetched from PyPI at install)"
    else
        fail "runtime: Claude Code is not installed, so no agent run can start — fetch it: sudo $AGENTI_RUNTIME/fetch-claude-code"; rc=1
    fi
    if "$AGENTI_RUNTIME/authd/bin/python3" -c "import fastapi" 2>/dev/null; then
        fail "runtime: authd's environment can import fastapi — it must hold cryptography only"; rc=1
    else
        ok "runtime: authd's environment holds only its own library"
    fi
    if [[ -f "$SUDOERS_DST" ]]; then
        mode=$(stat -c '%a %U:%G' "$SUDOERS_DST")
        [[ "$mode" == "440 root:root" ]] && ok "$SUDOERS_DST is 0440 root:root" \
            || { fail "$SUDOERS_DST is $mode — expected 440 root:root"; rc=1; }
        visudo -c -q -f "$SUDOERS_DST" 2>/dev/null && ok "$SUDOERS_DST parses" \
            || { fail "$SUDOERS_DST does not parse — sudo may be broken; fix: sudo dpkg-reconfigure agenti"; rc=1; }
        grep -qx "$API_USER ALL=(root) NOPASSWD: $API_BRIDGE \"\"" "$SUDOERS_DST" \
            && ok "the grant names exactly one program, with no arguments: $API_BRIDGE" \
            || { fail "$SUDOERS_DST does not grant exactly '$API_BRIDGE \"\"' — reinstall it: sudo dpkg-reconfigure agenti"; rc=1; }
    else
        fail "$SUDOERS_DST missing — the GUI can do nothing. Reinstall it: sudo dpkg-reconfigure agenti"; rc=1
    fi
    # The vault, if it is on: its empty mount point must refuse files while locked.
    if agenti_vault_enabled; then
        local img; img=$(sed -n 's/^IMAGE=//p' "$AGENTI_VAULT_CONF" | head -n1)
        [[ -f "$img" ]] && ok "vault: container $img present" || { fail "vault: enabled but $img is missing"; rc=1; }
        if [[ -e "$AGENTI_ROOT.pre-vault" ]]; then
            warn "vault: an UNENCRYPTED copy of the data from before the vault is still at $AGENTI_ROOT.pre-vault"
            warn "  delete it:  sudo rm -rf $AGENTI_ROOT.pre-vault   (then replace the API key if it was in there)"
        fi
        if agenti_data_ready; then
            ok "vault: unlocked (data mounted at $AGENTI_ROOT)"
        else
            warn "vault: LOCKED — nothing that needs data can run until:  sudo agenti vault unlock"
            if lsattr -d "$AGENTI_ROOT" 2>/dev/null | awk '{print $1}' | grep -q i; then
                ok "vault: the locked data folder is immutable (nothing can write data to the bare disk)"
            else
                fail "vault: the locked data folder $AGENTI_ROOT is NOT immutable — data could land unencrypted. Fix: sudo chattr +i $AGENTI_ROOT"; rc=1
            fi
            [[ -z "$(ls -A "$AGENTI_ROOT" 2>/dev/null)" ]] && ok "vault: the locked data folder is empty" \
                || { fail "vault: files sit in $AGENTI_ROOT while the vault is locked (unencrypted!)"; rc=1; }
        fi
    else
        ok "vault: off — data is a plain folder at $AGENTI_ROOT"
    fi
    # Decision 5 (audit run 1): an unencrypted data root is allowed, never silent.
    if agenti_data_ready; then
        local enc; enc=$(python3 "$AGENTI_LIBDIR/disk_encryption.py" "$AGENTI_ROOT" 2>/dev/null \
            | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["how"], d["device"])' 2>/dev/null || echo "unknown ?")
        case "${enc%% *}" in
            vault|full-disk) ok "data at rest: encrypted (${enc%% *}, ${enc#* })" ;;
            none) warn "DATA FROM AGENTS IS CURRENTLY NOT ENCRYPTED (${enc#* }): reports, scans, attached files and the API key are plain files. Turn on the vault: Settings → Platform → Vault, or sudo agenti vault enable" ;;
            *) warn "data at rest: could not tell whether $AGENTI_ROOT is encrypted" ;;
        esac
    fi
    if agenti_data_ready; then
        mode=$(stat -c '%a %U:%G' "$AGENTI_ROOT")
        [[ "$mode" == "751 root:root" ]] && ok "$AGENTI_ROOT is 0751 root:root (traversable, not listable)" \
            || { fail "$AGENTI_ROOT is $mode — expected 751 root:root. Fix: sudo dpkg-reconfigure agenti"; rc=1; }
    fi
    return $rc
}
verify_gui() {
    local rc=0 mode owner
    read_api_conf
    local BASE_URL CURL_TLS=""
    if [[ -n "$TLS_CERT" ]]; then BASE_URL="https://$(listen_addr "$BIND_HOST" "$BIND_PORT")"; CURL_TLS="-k"; else BASE_URL="http://$(listen_addr "$BIND_HOST" "$BIND_PORT")"; fi
    echo "the web GUI and sign-in:"

    id "$API_USER" &>/dev/null && ok "service account '$API_USER' exists" \
        || { fail "service account '$API_USER' missing"; rc=1; }

    "$API_PYTHON" -c 'import fastapi, uvicorn' 2>/dev/null && ok "the API environment imports fastapi and uvicorn" \
        || { fail "the API environment ($API_PYTHON) cannot import fastapi/uvicorn — reinstall: sudo apt install --reinstall agenti-runtime"; rc=1; }

    [[ -f "$AGENTI_LIBDIR/iam.py" ]] && ok "$AGENTI_LIBDIR/iam.py installed (shared by CLI and API)" \
                              || { fail "$AGENTI_LIBDIR/iam.py missing"; rc=1; }
    id "$AUTHD_USER" &>/dev/null && ok "service account '$AUTHD_USER' exists (the auth service)" \
        || { fail "service account '$AUTHD_USER' missing"; rc=1; }
    getent group "$SOCK_GROUP" &>/dev/null && ok "group '$SOCK_GROUP' exists (gates the auth socket)" \
        || { fail "group '$SOCK_GROUP' missing"; rc=1; }
    [[ -f "$AGENTI_LIBDIR/authd.py" ]] && ok "$AGENTI_LIBDIR/authd.py installed" \
                                || { fail "$AGENTI_LIBDIR/authd.py missing"; rc=1; }
    [[ -f "$AGENTI_LIBDIR/webauthn_lite.py" ]] && ok "$AGENTI_LIBDIR/webauthn_lite.py installed (WebAuthn/passkey parsing)" \
                                         || { fail "$AGENTI_LIBDIR/webauthn_lite.py missing"; rc=1; }
    # The QR encoder is optional at runtime (enrolment still works from the
    # secret alone), so a missing copy is a warning: a code that will not
    # render is a worse first impression than a missing file is a failure.
    [[ -f "$AGENTI_LIBDIR/qr.py" ]] && ok "$AGENTI_LIBDIR/qr.py installed (2FA QR codes)" \
                             || warn "$AGENTI_LIBDIR/qr.py missing — 2FA enrolment shows the secret without a QR code; reinstall: sudo apt install --reinstall agenti"

    # authd's dedicated venv — the one deliberate, hash-pinned dependency.
    # Checked by actually importing what verify_es256() needs, not just by
    # the file existing: an install that ran once and then had its wheel
    # cache or interpreter go stale would otherwise look fine and fail the
    # first time a real passkey login is attempted.
    if [[ -x "$AUTHD_PYTHON" ]]; then
        ok "authd's own environment is installed ($AUTHD_PYTHON)"
        if "$AUTHD_PYTHON" -c "
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes" 2>/dev/null; then
            ok "authd's environment can import cryptography's EC/hash primitives"
        else
            fail "authd's environment cannot import cryptography — WebAuthn/passkey"; rc=1
            fail "  logins and registrations will fail. Reinstall: sudo apt install --reinstall agenti-runtime"
        fi
        local authd_bound
        authd_bound=$(systemctl show agenti-authd.service -p ExecStart --value 2>/dev/null || true)
        if [[ "$authd_bound" == *"$AUTHD_PYTHON"* ]]; then
            ok "agenti-authd.service runs from its own environment"
        elif [[ -n "$authd_bound" ]]; then
            fail "agenti-authd.service does not run from $AUTHD_PYTHON — re-render it: sudo dpkg-reconfigure agenti"; rc=1
        fi
    else
        fail "$AUTHD_PYTHON is missing — WebAuthn/passkeys cannot"; rc=1
        fail "  work and agenti-authd itself will not start. Reinstall: sudo apt install --reinstall agenti-runtime"
    fi

    if [[ -f "$AGENTI_IAM_DB" ]]; then
        mode=$(stat -c '%a' "$AGENTI_IAM_DB"); owner=$(stat -c '%U:%G' "$AGENTI_IAM_DB")
        [[ "$mode" == "640" && "$owner" == "root:$AUTHD_USER" ]] \
            && ok "$AGENTI_IAM_DB is $mode $owner (authd reads it; root writes it)" \
            || { fail "$AGENTI_IAM_DB is $mode $owner — expected 640 root:$AUTHD_USER"; rc=1; }

        # THE property the split exists to protect, proven rather than
        # asserted, in both directions. Since §4 item 23 the API must not be
        # able to READ the identity store either: a process that can read
        # TOTP secrets can compute anyone's second factor, and one that can
        # read hashes can crack them offline at leisure.
        if runuser -u "$API_USER" -- test -r "$AGENTI_IAM_DB" 2>/dev/null; then
            fail "PRIVILEGE BOUNDARY BROKEN: '$API_USER' can READ $AGENTI_IAM_DB (hashes, TOTP"; rc=1
            fail "  secrets and bindings are reachable from the web tier)"
        else
            ok "'$API_USER' cannot read $AGENTI_IAM_DB (no secret or binding reaches the web tier)"
        fi
        if runuser -u "$AUTHD_USER" -- test -w "$AGENTI_IAM_DB" 2>/dev/null; then
            fail "PRIVILEGE BOUNDARY BROKEN: '$AUTHD_USER' can WRITE $AGENTI_IAM_DB"; rc=1
        else
            ok "'$AUTHD_USER' cannot write $AGENTI_IAM_DB (identity is root-only)"
        fi
        runuser -u "$AUTHD_USER" -- test -r "$AGENTI_IAM_DB" 2>/dev/null \
            && ok "'$AUTHD_USER' can read $AGENTI_IAM_DB" \
            || { fail "'$AUTHD_USER' cannot read $AGENTI_IAM_DB — nobody can log in"; rc=1; }
    else
        warn "$AGENTI_IAM_DB does not exist yet — no users are defined, so every"
        warn "  request will be refused. Create the first admin:"
        warn "    sudo agenti setup"
    fi

    if [[ -d "$AUTHD_DIR" ]]; then
        mode=$(stat -c '%a' "$AUTHD_DIR"); owner=$(stat -c '%U:%G' "$AUTHD_DIR")
        [[ "$mode" == "700" && "$owner" == "$AUTHD_USER:$AUTHD_USER" ]] \
            && ok "$AUTHD_DIR is $mode $owner (sessions, audit log, lockouts)" \
            || { fail "$AUTHD_DIR is $mode $owner — expected 700 $AUTHD_USER:$AUTHD_USER"; rc=1; }
        if runuser -u "$API_USER" -- test -x "$AUTHD_DIR" 2>/dev/null; then
            fail "PRIVILEGE BOUNDARY BROKEN: '$API_USER' can enter $AUTHD_DIR (the session store)"; rc=1
        else
            ok "'$API_USER' cannot enter $AUTHD_DIR (it cannot forge, extend or revive a session)"
        fi
    else
        fail "$AUTHD_DIR missing — recreate it: sudo dpkg-reconfigure agenti"; rc=1
    fi

    [[ -f "$API_UNIT" ]] && ok "$API_UNIT installed" \
                          || { fail "$API_UNIT missing"; rc=1; }
    [[ -f "$AUTHD_UNIT" ]] && ok "$AUTHD_UNIT installed" \
                           || { fail "$AUTHD_UNIT missing"; rc=1; }

    # The auth service: running, sandboxed as declared, and answering ONLY
    # the API account. Each is a live check against the running process.
    if command -v systemctl &>/dev/null && [[ -f "$AUTHD_UNIT" ]]; then
        if systemctl is-active --quiet agenti-authd.service; then
            ok "agenti-authd.service is active"
            local nnp; nnp=$(systemctl show agenti-authd.service -p NoNewPrivileges --value 2>/dev/null || true)
            [[ "$nnp" == "yes" ]] && ok "agenti-authd runs with NoNewPrivileges (it never escalates)" \
                || { fail "agenti-authd.service is not NoNewPrivileges=yes"; rc=1; }
            if [[ -S "$AUTHD_SOCK" ]]; then
                mode=$(stat -c '%a' "$AUTHD_SOCK"); owner=$(stat -c '%U:%G' "$AUTHD_SOCK")
                [[ "$mode" == "660" && "$owner" == "$AUTHD_USER:$SOCK_GROUP" ]] \
                    && ok "$AUTHD_SOCK is $mode $owner" \
                    || { fail "$AUTHD_SOCK is $mode $owner — expected 660 $AUTHD_USER:$SOCK_GROUP"; rc=1; }
                local pong
                pong=$(runuser -u "$API_USER" -- python3 -c "
import sys; sys.path.insert(0, '$AGENTI_LIBDIR/api')
import authd_client as c
print(c.call('ping', socket_path='$AUTHD_SOCK')['service'])" 2>&1 || true)
                [[ "$pong" == "agenti-authd" ]] && ok "'$API_USER' can reach agenti-authd over the socket" \
                    || { fail "'$API_USER' cannot talk to agenti-authd — every login will fail:"; rc=1
                         printf '         %s\n' "${pong:0:200}" >&2; }
                # Root is NOT an allowed peer. This script runs as root, so
                # connecting from here must be refused by the kernel-reported
                # peer uid — the proof that the check exists at all.
                pong=$(python3 -c "
import sys; sys.path.insert(0, '$AGENTI_LIBDIR/api')
import authd_client as c
try:
    c.call('ping', socket_path='$AUTHD_SOCK'); print('ANSWERED')
except c.AuthdError as e:
    print('refused' if e.status == 403 else f'unexpected {e.status}: {e.message}')" 2>&1 || true)
                [[ "$pong" == "refused" ]] && ok "a connection from any other uid (root, here) is refused by peer credentials" \
                    || { fail "agenti-authd answered a caller that is not '$API_USER': $pong"; rc=1; }
            else
                fail "$AUTHD_SOCK is not a socket — agenti-authd is active but not listening"; rc=1
            fi
        else
            fail "agenti-authd.service is not running — nobody can log in. Check:"; rc=1
            fail "  journalctl -u agenti-authd -n 40"
        fi
    fi

    if command -v systemctl &>/dev/null && [[ -f "$API_UNIT" ]]; then
        local bound; bound=$(systemctl show agenti-api.service -p ExecStart --value 2>/dev/null || true)
        local listen; listen=$(systemctl show agenti-api.socket -p Listen --value 2>/dev/null || true)
        local want; want=$(listen_addr "$BIND_HOST" "$BIND_PORT")
        # Only systemd (pid 1) or the GUI itself may listen there (audit run 2).
        local main others
        main=$(systemctl show -p MainPID --value agenti-api.service 2>/dev/null || echo 0)
        others=$(ss -ltnpH "sport = :$BIND_PORT" 2>/dev/null | grep -vE "pid=(1|$main)," || true)
        if [[ -n "$others" ]]; then
            fail "another program listens on the GUI's port $BIND_PORT and would receive browsers' sign-ins: $others"; rc=1
        fi
        # The relay's port: held by systemd from boot (agenti-relay.socket), and
        # only systemd or the relay may listen there (audit run 2).
        local rport="${AGENTI_RELAY_ADDR##*:}" rmain rothers
        if systemctl is-active --quiet agenti-relay.socket \
           && [[ "$(systemctl show agenti-relay.socket -p Listen --value 2>/dev/null)" == *"$AGENTI_RELAY_ADDR"* ]]; then
            ok "systemd holds the relay's port $AGENTI_RELAY_ADDR (agenti-relay.socket), from boot"
        else
            fail "agenti-relay.socket does not hold $AGENTI_RELAY_ADDR — a local program could take it and receive IP-scoped runs' model traffic. Fix: sudo dpkg-reconfigure agenti"; rc=1
        fi
        rmain=$(systemctl show -p MainPID --value agenti-relay.service 2>/dev/null || echo 0)
        rothers=$(ss -ltnpH "sport = :$rport" 2>/dev/null | grep -vE "pid=(1|$rmain)," || true)
        [[ -z "$rothers" ]] || { fail "another program listens on the relay's port $rport: $rothers"; rc=1; }
        if [[ "$listen" == *"$want"* ]]; then
            ok "systemd holds the GUI's port $want (agenti-api.socket), across restarts"
        else
            fail "agenti-api.socket does not hold $want (listening: ${listen:-nothing}) — a local process could take the port while the GUI restarts. Fix: sudo dpkg-reconfigure agenti"; rc=1
        fi
        if [[ "$bound" == *"--fd 3"* && "$bound" == *"--no-proxy-headers"* ]]; then
            ok "uvicorn serves the socket systemd hands it and never trusts a forwarding header itself"
        else
            fail "agenti-api.service does not use the held socket (--fd 3) with --no-proxy-headers — re-render it: sudo dpkg-reconfigure agenti"; rc=1
        fi

        # The pairing this whole phase rests on: a bind anyone else can reach
        # must be HTTPS, and the cookie it hands out must be Secure. Checked
        # against the RUNNING unit and a REAL response, because the failure
        # mode is a config that merely looks right.
        if ! is_loopback "$BIND_HOST"; then
            if [[ "$bound" == *"--ssl-certfile"* ]]; then
                ok "non-loopback bind is served over TLS"
            else
                fail "EXPOSED WITHOUT TLS: bound to $BIND_HOST with no certificate."; rc=1
            fi
        fi
    fi

    # The WebAuthn/passkey relying-party domain, if one is configured: the
    # first time --verify inspects certificate CONTENT rather than just
    # confirming a flag was passed. A mismatch here means every browser will
    # refuse passkey registration/login for that origin, silently, which is
    # exactly the kind of failure this check exists to catch before a real
    # device hits it.
    if [[ -n "$HOSTNAME" ]]; then
        if [[ $BEHIND_PROXY -eq 1 ]]; then
            ok "behind a local proxy: HTTPS and its certificate belong to the proxy,"
            ok "  so there is no certificate on this service to check"
        elif [[ -n "$TLS_CERT" && -f "$TLS_CERT" ]] && command -v openssl &>/dev/null; then
            local sans; sans=$(openssl x509 -in "$TLS_CERT" -noout -ext subjectAltName 2>/dev/null || true)
            if grep -q "DNS:$HOSTNAME" <<<"$sans"; then
                ok "certificate covers the configured hostname (DNS:$HOSTNAME)"
            else
                fail "certificate does NOT include DNS:$HOSTNAME in its SAN list —"; rc=1
                fail "  browsers will refuse it for that origin, and WebAuthn/passkeys"
                fail "  will not work. Re-generate: sudo rm $TLS_CERT $TLS_KEY &&"
                fail "  sudo agenti gui configure --tls --hostname $HOSTNAME"
            fi
        else
            warn "HOSTNAME is configured ($HOSTNAME) but there is no certificate on"
            warn "  record to check its SAN list against"
        fi
        if command -v systemctl &>/dev/null; then
            local envs3; envs3=$(systemctl show agenti-authd.service -p Environment --value 2>/dev/null || true)
            [[ "$envs3" == *"AGENTI_HOSTNAME=$HOSTNAME"* ]] \
                && ok "agenti-authd is configured with AGENTI_HOSTNAME=$HOSTNAME" \
                || { fail "agenti-authd.service does not set AGENTI_HOSTNAME=$HOSTNAME — re-render it: sudo dpkg-reconfigure agenti"; rc=1; }
            local origin_env; origin_env=$(grep -o 'AGENTI_ORIGIN=[^ ]*' <<<"$envs3" || true)
            if [[ -n "$origin_env" ]]; then
                ok "agenti-authd: $origin_env (every WebAuthn/passkey ceremony is checked"
                ok "  against this EXACT string, scheme+host+port, matching what a"
                ok "  browser's own location.origin sends — if this box sits behind a"
                ok "  reverse proxy or tunnel that remaps the port, this must match"
                ok "  what the BROWSER sees, not BIND_PORT; see --origin-port)"
            else
                fail "agenti-authd.service does not set AGENTI_ORIGIN — re-render it: sudo dpkg-reconfigure agenti"; rc=1
            fi
        fi
    else
        warn "no hostname configured — WebAuthn/passkeys are unavailable on this"
        warn "  deploy. See: sudo agenti gui configure --help (--hostname <your-domain>)"
    fi

    # The web tier reaches root only through the bridge (api_bridge.py): the
    # command goes as one JSON line on stdin, never as sudo arguments. These run
    # a command exactly the way the API does.
    api_agenti() {
        local line; line=$(python3 -c 'import json,sys; print(json.dumps({"argv": sys.argv[1:]}))' "$@")
        printf '%s\n' "$line" | runuser -u "$API_USER" -- sudo -n "$API_BRIDGE"
    }
    api_agenti_body() {      # the same, with this function's stdin sent as the body
        local line; line=$(python3 -c 'import json,sys; print(json.dumps({"argv": sys.argv[1:]}))' "$@")
        { printf '%s\n' "$line"; cat; } | runuser -u "$API_USER" -- sudo -n "$API_BRIDGE"
    }

    # Prove the sudoers grant actually works, not just that we printed it once.
    if api_agenti agents --json &>/dev/null; then
        ok "'$API_USER' can invoke agenti via sudo -n (sudoers grant is live)"

        # ...and prove it CANNOT reach the IAM-mutating verbs through that same
        # grant. The grant is a bare path, so sudoers itself permits any
        # arguments; the refusal lives in the CLI. That makes this check the
        # only thing standing between "documented" and "true", which is exactly
        # when a live check earns its keep.
        local out
        out=$(api_agenti admin \
              issue-key --user "$API_USER" 2>&1 || true)
        if grep -q "REFUSING" <<<"$out"; then
            ok "'$API_USER' is refused 'admin issue-key' (cannot mint itself a key)"
        else
            fail "PRIVILEGE ESCALATION: '$API_USER' was NOT refused 'admin issue-key'."; rc=1
            fail "  A compromised API process could grant itself any role."
            printf '         %s\n' "${out:0:200}" >&2
        fi

        out=$(api_agenti admin \
              bind user "$API_USER" --role admin 2>&1 || true)
        grep -q "REFUSING" <<<"$out" \
            && ok "'$API_USER' is refused 'admin bind' (cannot grant itself a role)" \
            || { fail "PRIVILEGE ESCALATION: '$API_USER' was NOT refused 'admin bind'"; rc=1; }

        # "principal" is the old name for "user" and is still accepted, so the
        # refusal has to hold under BOTH spellings (verb and flag); a refusal
        # list that knew only one of them would be a hole, not a typo.
        local _spelling
        for _spelling in "user add" "principal add" "bind principal"; do
            out=$(api_agenti admin \
                  $_spelling __deploy_verify_never_created__ --role admin 2>&1 || true)
            grep -q "REFUSING" <<<"$out" \
                && ok "'$API_USER' is refused 'admin $_spelling'" \
                || { fail "PRIVILEGE ESCALATION: '$API_USER' was NOT refused 'admin $_spelling'"; rc=1; }
        done
        out=$(api_agenti admin \
              issue-key --principal "$API_USER" 2>&1 || true)
        grep -q "REFUSING" <<<"$out" \
            && ok "'$API_USER' is refused 'admin issue-key --principal' (the old flag spelling)" \
            || { fail "PRIVILEGE ESCALATION: '$API_USER' was NOT refused 'admin issue-key --principal'"; rc=1; }

        # The other half of the same boundary, checked in the opposite
        # direction: these verbs (self + the narrow "web IAM" verbs —
        # create-user, disable-user, mint-enrolment-link, enrol-check,
        # enrol-consume — plus the read verb list-users and set-limit,
        # a settings write that is a numeric LIMIT, never a
        # permission — plus, from phase 7 of
        # the generic-launcher arc,
        # outputs-path (a download route's resolve, read-only, same
        # ownership check outputs-delete already had) and
        # tool-request-file/tool-request-list, decision 4's admin-reviewed
        # queue) are the ONLY identity-store actions the API may
        # reach; every one of them was chosen because it can only remove
        # authority or grant none at all (CLAUDE.md's "authority rule").
        # rename-user/delete-user (§4 item 59) and
        # reset-user-password/reset-user-mfa/password-reset-check/
        # password-reset-consume (added after, at the operator's request) are
        # a SECOND, narrower exception to that rule: each one genuinely
        # RESTORES or re-points authority, which is why it is reachable ONLY
        # on the strength of a real, single-use approval grant agenti-authd
        # mints after the requesting admin re-proves their own password and
        # 2FA (or a passkey) — never on a bare permission check the way
        # everything else in this table is.
        # Each call below is crafted to fail for ITS OWN reason — a bad
        # password, a name that doesn't exist, a bogus token — WITHOUT
        # mutating or leaving behind anything real (set-webauthn is the one
        # deliberate exception: its argument space is only on/off, so it's
        # called with 'off' to prove the verb reaches real iam.py logic —
        # which DOES change real, observable state on a deployment that
        # had it on, so its current value is saved before this table runs
        # and restored right after; see that save/restore just above and
        # below this loop. First shipped without the restore, and it
        # showed live: an operator turned passkeys on, hit an unrelated
        # bug, and their own --verify run while chasing it silently turned
        # passkeys back off in the middle of their own troubleshooting).
        # The one thing that must NEVER appear is refuse_iam_writes_from_api's REFUSING
        # message: if it does, one of these fell out of shared/agenti's
        # forwarding case pattern or got added to IAM_WRITE_VERBS by
        # mistake, and the GUI's
        # account page or admin Users view breaks silently until this runs.
        # set-webauthn's own probe below is a REAL, observable mutation —
        # the one deliberate exception in this table (see the comment
        # above). Save whatever it's set to now and put it back after, so
        # a --verify run never silently turns passkey sign-in back OFF for
        # a deployment where an admin has it deliberately on. Found live,
        # the hard way: this exact side effect masked a real passkey bug
        # during Phase F testing on 2026-09-24 — an operator turned
        # WebAuthn on, hit an unrelated failure, and both their own
        # follow-up --verify run and a diagnostic one run on their behalf
        # each silently flipped it back off in between attempts.
        _webauthn_before=$(api_agenti admin policy --json 2>/dev/null \
            | grep -o '"webauthn-enabled"[[:space:]]*:[[:space:]]*"[^"]*"' | grep -o '"[^"]*"$' | tr -d '"')
        [[ "$_webauthn_before" != "on" ]] && _webauthn_before="off"

        _narrow_ok=1; _narrow_n=0; _narrow_locked=0
        while IFS='|' read -r _verb _args _expect; do
            [[ -z "$_verb" ]] && continue
            _narrow_n=$((_narrow_n + 1))
            _out=$(api_agenti admin \
                   $_verb $_args --json 2>&1 </dev/null || true)
            if grep -q "the vault is locked" <<<"$_out"; then
                # A verb that reads data cannot answer while the vault is locked.
                _narrow_locked=$((_narrow_locked + 1))
            elif grep -q "REFUSING" <<<"$_out"; then
                fail "'$API_USER' was refused 'admin $_verb' — the web GUI's"
                fail "  identity features that depend on it will break."
                fail "  Check IAM_WRITE_VERBS and shared/agenti's forwarding case"
                fail "  pattern both still exempt it."
                printf '         %s\n' "${_out:0:200}" >&2
                _narrow_ok=0; rc=1
            elif ! grep -qiE "$_expect" <<<"$_out"; then
                warn "'admin $_verb' gave an unexpected response — check by hand:"
                printf '         %s\n' "${_out:0:200}" >&2
                _narrow_ok=0
            fi
        done <<VERBS
self password|$API_USER --current wrong --new x|current password is incorrect|no user named
create-user|deploy-verify-no-such-user --kind user --role operator --grant=not-a-real-grant|no such approval grant
disable-user|__deploy_verify_no_such_user__|no user named
mint-enrolment-link|__deploy_verify_no_such_user__|no user named
enrol-check|not-a-real-token|invalid or has expired
enrol-consume|not-a-real-token --new x|invalid or has expired
list-users||"name"
web-bind|deploy-verify-no-such-user --role operator --grant not-a-real-grant|no user named
web-unbind|deploy-verify-no-such-user --role operator|no user named
reset-user-password|__deploy_verify_no_such_user__ --new=x --grant=not-a-real-grant|no such approval grant
reset-user-mfa|__deploy_verify_no_such_user__ --grant=not-a-real-grant|no such approval grant
password-reset-check|not-a-real-token|invalid or has expired
password-reset-consume|not-a-real-token --new=x|invalid or has expired
bindings|--user __deploy_verify_no_such_user__|^\[\]$
policy||require-separate-approver
tool-request-file|--by __deploy_verify_no_such_user__|required
tool-request-list||^\[
passkey-commit|__deploy_verify_no_such_user__ --credential-id=x --alg=ES256 --x=abc --y=def --sign-count 0 --grant=not-a-real-grant|no user named
passkey-list|__deploy_verify_no_such_user__|^\[\]$
set-webauthn|off|webauthn_enabled
agent-build|tools|"programs"
catalog|list|"programs"
agent-build|remove deploy-verify-no-such-agent --grant=not-a-real-grant|no agent called
VERBS
        # The bridge is the ONLY way in (audit run 1, fix 2): sudo refuses the
        # CLI itself and refuses the bridge with any argument at all.
        if runuser -u "$API_USER" -- sudo -n "$AGENTI_BIN" agents --json &>/dev/null; then
            fail "PRIVILEGE BOUNDARY BROKEN: '$API_USER' can still run $AGENTI_BIN directly through sudo"; rc=1
        else
            ok "'$API_USER' cannot run $AGENTI_BIN directly — only the bridge"
        fi
        if runuser -u "$API_USER" -- sudo -n "$API_BRIDGE" agents &>/dev/null; then
            fail "PRIVILEGE BOUNDARY BROKEN: sudo lets '$API_USER' pass arguments to the bridge"; rc=1
        else
            ok "sudo refuses the bridge with arguments (nothing reaches sudo's log but its name)"
        fi
        local _probe _why
        while IFS='|' read -r _why _probe; do
            [[ -z "$_why" ]] && continue
            # shellcheck disable=SC2086
            _out=$(api_agenti $_probe 2>&1 </dev/null || true)
            if grep -q "REFUSING" <<<"$_out"; then
                ok "the bridge refuses $_why"
            else
                fail "the bridge did NOT refuse $_why: ${_out:0:160}"; rc=1
            fi
        done <<PROBES
'logs' with a journalctl option|enum logs --vacuum-time=1s --json
a trailing --help (vault)|vault lock --help
'export' (not a web verb)|enum export --json
'set-key' (not a web verb)|enum set-key --json
'admin set-limit' (not a web verb)|admin set-limit runs 1 --json
'create-user --role'|admin create-user deploy-verify-probe --kind user --role admin --json
'engagement set' without a grant|engagement set --notes deploy-verify-probe --json
'engagement approve' without a grant, under a forged name|engagement approve --by forged-admin --via cli --json
PROBES
        # A secret sent through the bridge must not land in sudo's log.
        local _mark; _mark="deploy-verify-secret-$RANDOM$RANDOM"
        api_agenti admin enrol-consume not-a-real-token --new "$_mark" --json >/dev/null 2>&1 </dev/null || true
        if journalctl _COMM=sudo --since "-2min" -o cat 2>/dev/null | grep -q "$_mark"; then
            fail "a password sent through the bridge was written to sudo's log"; rc=1
        else
            ok "a password sent through the bridge is not in sudo's log"
        fi

        # Likewise the program catalog: changing it from the API account needs a grant.
        _out=$(api_agenti admin catalog remove deploy-verify-no-such-program --json 2>&1 || true)
        if grep -q "needs a fresh re-authentication" <<<"$_out"; then
            ok "'$API_USER' cannot change the program catalog without a re-authenticated approval"
        else
            fail "'$API_USER' was NOT refused changing the program catalog without an approval grant:"
            printf '         %s\n' "${_out:0:200}" >&2
            rc=1
        fi
        # Building an agent from the API account must need a re-authenticated
        # approval grant, every time. A VALID spec is sent so the refusal can
        # only come from the missing grant, not from validation.
        _out=$(printf '%s' '{"name":"deploy-verify-probe","title":"Probe","description":"agenti verify probe.","programs":["ping"],"system_prompt":"Deploy verification probe; never built."}' \
               | api_agenti_body admin agent-build create --json 2>&1 || true)
        if grep -q "needs a fresh re-authentication" <<<"$_out"; then
            ok "'$API_USER' cannot build an agent without a re-authenticated approval"
        else
            fail "'$API_USER' was NOT refused building an agent without an approval grant:"
            printf '         %s\n' "${_out:0:200}" >&2
            rc=1
            [[ -d "$AGENTI_BUILT_AGENTS/deploy-verify-probe" ]] && \
                $AGENTI_BIN admin agent-build remove deploy-verify-probe --yes --json >/dev/null 2>&1
        fi
        if [[ "$_webauthn_before" == "on" ]]; then
            if api_agenti admin set-webauthn on >/dev/null 2>&1; then
                ok "restored webauthn-enabled=on (the set-webauthn probe above turns it off)"
            else
                fail "could not restore webauthn-enabled=on after the set-webauthn probe — passkey sign-in is now OFF; re-run: sudo agenti admin set-webauthn on"
                rc=1
            fi
        fi
        [[ $_narrow_ok -eq 1 ]] && ok "'$API_USER' can reach all $((_narrow_n - _narrow_locked)) narrow web-IAM verbs, each refused (or answered) for its own reason — not blocked at the door"
        [[ $_narrow_locked -eq 0 ]] || ok "  ($_narrow_locked more need the data folder and were skipped: the vault is locked)"
    else
        fail "'$API_USER' cannot invoke agenti via sudo -n — the sudoers grant is missing or broken."; rc=1
        fail "  Reinstall it: sudo dpkg-reconfigure agenti"
    fi

    # Live HTTP checks against the RUNNING service — the same "prove it, don't
    # assume the file looks right" standard deploy.sh's capability check uses.
    if systemctl is-active --quiet agenti-api.service; then
        ok "agenti-api.service is active"

        local listen; listen=$(ss -ltnp 2>/dev/null | grep ":$BIND_PORT " || true)
        if [[ -z "$listen" ]]; then
            fail "nothing is listening on port $BIND_PORT"; rc=1
        elif { [[ "$BIND_HOST" == *:* ]] && grep -qF "[$BIND_HOST]:$BIND_PORT" <<<"$listen"; } \
             || { [[ "$BIND_HOST" != *:* ]] && grep -qE "(^|[^0-9.])($BIND_HOST|\[::1\]):$BIND_PORT" <<<"$listen"; }; then
            ok "listening on $BIND_HOST:$BIND_PORT only"
        else
            fail "EXPOSED: something is listening on $BIND_PORT beyond $BIND_HOST:"; rc=1
            printf '         %s\n' "$listen" >&2
        fi

        # The cookie's Secure flag comes from AGENTI_TLS on the unit, so
        # that is what can be checked here. The flag as a BROWSER sees it
        # needs a successful login, which needs credentials this script
        # deliberately does not hold (same limit as the API-key path below)
        # — shared/gui_check.py logs in for real and asserts it there.
        if [[ -n "$TLS_CERT" || $BEHIND_PROXY -eq 1 ]]; then
            local envs; envs=$(systemctl show agenti-api.service -p Environment --value 2>/dev/null || true)
            if [[ "$envs" == *"AGENTI_TLS=1"* ]]; then
                ok "unit sets AGENTI_TLS=1 (session cookie will carry Secure)"
            else
                fail "browsers are on HTTPS but the unit does not set AGENTI_TLS=1 —"; rc=1
                fail "  the session cookie would be issued WITHOUT Secure over HTTPS."
            fi
        fi

        if [[ $BEHIND_PROXY -eq 1 ]]; then
            local envp; envp=$(systemctl show agenti-api.service -p Environment --value 2>/dev/null || true)
            local execp; execp=$(systemctl show agenti-api.service -p ExecStart --value 2>/dev/null || true)
            [[ "$envp" == *"AGENTI_BEHIND_PROXY=1"* && "$envp" == *"AGENTI_HOSTNAME=$HOSTNAME"* ]] \
                && ok "unit trusts a local proxy (AGENTI_BEHIND_PROXY=1, host $HOSTNAME)" \
                || { fail "--behind-proxy is configured but the unit lacks AGENTI_BEHIND_PROXY/AGENTI_HOSTNAME — re-render it: sudo dpkg-reconfigure agenti"; rc=1; }
            [[ "$execp" == *"--no-proxy-headers"* ]] \
                && ok "uvicorn's own forwarded-header rewriting is off (one explicit rule instead)" \
                || { fail "unit lacks --no-proxy-headers — re-render it: sudo dpkg-reconfigure agenti"; rc=1; }
            is_loopback "$BIND_HOST" \
                && ok "proxy mode is bound to loopback only" \
                || { fail "proxy mode but bound to $BIND_HOST — anyone on that network could forge the client-address header"; rc=1; }
            # A request addressed to some OTHER name must be refused: that is
            # what stops DNS rebinding and a misrouted proxy vhost.
            local hcode
            hcode=$(curl -s $CURL_TLS -o /dev/null -w '%{http_code}' -H "Host: not-this-deploy.invalid" \
                    "$BASE_URL/login.html" 2>/dev/null || echo 000)
            [[ "$hcode" == "400" ]] \
                && ok "a request for a foreign Host header is refused (400)" \
                || { fail "a foreign Host header returned $hcode — expected 400"; rc=1; }
        fi

        local envs2; envs2=$(systemctl show agenti-api.service -p Environment --value 2>/dev/null || true)
        [[ "$envs2" == *"AGENTI_AUTHD_SOCKET=$AUTHD_SOCK"* ]] \
            && ok "unit points the API at $AUTHD_SOCK" \
            || { fail "agenti-api.service does not set AGENTI_AUTHD_SOCKET=$AUTHD_SOCK"; rc=1; }

        local code
        code=$(curl -s $CURL_TLS -o /dev/null -w '%{http_code}' \
               "$BASE_URL/auth/me" 2>/dev/null || echo 000)
        [[ "$code" == "401" ]] && ok "unauthenticated request rejected (401)" \
            || { fail "unauthenticated /auth/me returned $code — expected 401"; rc=1; }

        local docs_code oa_code
        docs_code=$(curl -s $CURL_TLS -o /dev/null -w '%{http_code}' "$BASE_URL/docs/search?q=pass" 2>/dev/null || echo 000)
        [[ "$docs_code" == "401" ]] && ok "the help pages need a sign-in (/docs/search without one: 401)" \
            || { fail "unauthenticated /docs/search returned $docs_code — expected 401"; rc=1; }
        oa_code=$(curl -s $CURL_TLS -o /dev/null -w '%{http_code}' "$BASE_URL/openapi.json" 2>/dev/null || echo 000)
        [[ "$oa_code" == "404" ]] && ok "FastAPI's route map is off (/openapi.json: 404)" \
            || { fail "/openapi.json returned $oa_code — expected 404 (docs_url/openapi_url must stay None)"; rc=1; }
        if [[ -f "$AGENTI_LIBDIR/help_docs.py" ]] \
           && python3 "$AGENTI_LIBDIR/help_docs.py" --dir "$AGENTI_LIBDIR/help" --json list 2>/dev/null | grep -q '"count": [1-9]'; then
            ok "the help pages are installed and readable (agenti docs)"
        else
            fail "the help pages did not list — reinstall: sudo apt install --reinstall agenti"; rc=1
        fi

        local fake_key="agk_deadbeef_notarealkey"   # gitleaks:allow (a made-up key that must be refused)
        code=$(curl -s $CURL_TLS -o /dev/null -w '%{http_code}' \
               -H "Authorization: Bearer $fake_key" \
               "$BASE_URL/auth/me" 2>/dev/null || echo 000)
        [[ "$code" == "401" ]] && ok "invalid key rejected (401)" \
            || { fail "/auth/me with an invalid key returned $code — expected 401"; rc=1; }

        # The web GUI is served by this same process (main.py mounts it
        # last). Unauthenticated on purpose — it is the login page.

        if [[ -d "$AGENTI_LIBDIR/api/gui" ]]; then
            local body
            body=$(curl -s $CURL_TLS "$BASE_URL/login.html" 2>/dev/null || true)
            if grep -qi "<title>Agenti" <<<"$body"; then
                ok "web GUI served at $BASE_URL/ (login page reachable)"
            else
                fail "web GUI installed at $AGENTI_LIBDIR/api/gui but /login.html did not return the login page"; rc=1
            fi
        else
            warn "no web GUI installed ($AGENTI_LIBDIR/api/gui missing) — API only"
        fi

        # No key is stored on disk to test the authenticated path with — that
        # is the point of per-user keys (they exist only where their owner
        # put them). So verify what CAN be checked without holding a
        # credential, and say plainly what it does not cover.
        local np
        np=$(python3 "$AGENTI_LIBDIR/iam.py" --json user list 2>/dev/null \
             | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))' 2>/dev/null || echo 0)
        if [[ "$np" -gt 0 ]]; then
            ok "$np user(s) defined — authenticated calls are testable with a real key"
        else
            warn "no users defined yet — every request will be refused. Run:"
            warn "    sudo agenti setup"
        fi
    else
        warn "agenti-api.service is not running — start it with: sudo agenti gui start"
        warn "  (the live HTTP checks below it were skipped)"
    fi

    # The retention timer (decision 7): "active" for a .timer unit means
    # armed and waiting for its next trigger, not "currently running" — a
    # oneshot .service between runs is normally inactive, which is correct.
    if systemctl is-active --quiet agenti-retention.timer; then
        ok "agenti-retention.timer is armed (daily retention sweep)"
    else
        fail "agenti-retention.timer is not active — the 30-day sweep will not run"; rc=1
    fi
    return $rc
}


verify_agent_code() {
    local AGENT="$1" rc=0 MASTER_DIR
    MASTER_DIR=$(agenti_master_dir "$AGENT")
    echo "$AGENT: code ($MASTER_DIR):"

    if [[ -d "$MASTER_DIR" ]]; then
        # Tested by ATTEMPTING a write as the service account — not just
        # reading mode bits, so ACLs/group slips are caught too.
        if svc_exists; then
            if runuser -u "$SVC_USER" -- test -w "$MASTER_DIR" 2>/dev/null; then
                fail "$MASTER_DIR IS WRITABLE by $SVC_USER — the agent could rewrite its own code"; rc=1
            else
                ok "$MASTER_DIR not writable by $SVC_USER (code immutable)"
            fi
            runuser -u "$SVC_USER" -- test -r "$MASTER_DIR/${AGENT}-agent.py" 2>/dev/null \
                && ok "$MASTER_DIR readable by $SVC_USER" \
                || { fail "$MASTER_DIR/${AGENT}-agent.py not readable by $SVC_USER"; rc=1; }
        else
            fail "service account '$SVC_USER' does not exist — recreate it: sudo dpkg-reconfigure agenti"; rc=1
        fi
    else
        fail "$MASTER_DIR missing"; rc=1
    fi

    local LIB_DIR="$AGENTI_LIBDIR"
    if [[ -d "$LIB_DIR" ]]; then
        if svc_exists; then
            runuser -u "$SVC_USER" -- test -w "$LIB_DIR" 2>/dev/null \
                && { fail "$LIB_DIR IS WRITABLE by $SVC_USER — the shared harness could be rewritten"; rc=1; } \
                || ok "$LIB_DIR not writable by $SVC_USER (harness immutable, checked ONCE for every agent)"
        fi
    else
        fail "$LIB_DIR missing"; rc=1
    fi


    return $rc
}


verify_agent_data() {
    local AGENT="$1" rc=0 ORG_DIR="$AGENTI_ROOT/org" CAPFILE
    CAPFILE="$(agenti_master_dir "$AGENT")/$AGENT.capabilities"; [[ -f "$CAPFILE" ]] || CAPFILE=""
    local agent_dir="$ORG_DIR/$AGENT"
    echo "$AGENT: data ($agent_dir):"

    if ! svc_exists; then
        fail "service account '$SVC_USER' missing — recreate it: sudo dpkg-reconfigure agenti"; rc=1
        return $rc
    fi
    if [[ ! -d "$agent_dir/instances" ]]; then
        warn "$agent_dir is not provisioned yet — sudo agenti $AGENT provision"
        return 0
    fi

    # Every user's run slot (CLAUDE.md §4 item 71): the per-run inputs are
    # root-owned (an agent cannot set its own target or budget), and its
    # working directories are writable by the service account.
    local wdirs=(scans reports state) slot nslots=0 f d
    for slot in "$agent_dir/instances"/*/; do
        [[ -d "$slot" ]] || continue
        nslots=$((nslots + 1)); slot="${slot%/}"
        for f in run-target run-config.json run-launched-by; do
            [[ -e "$slot/$f" ]] || continue
            if runuser -u "$SVC_USER" -- test -w "$slot/$f" 2>/dev/null; then
                fail "$slot/$f IS WRITABLE by $SVC_USER — that run could set its own $f"; rc=1
            fi
        done
        for d in "${wdirs[@]}"; do
            runuser -u "$SVC_USER" -- test -w "$slot/$d" 2>/dev/null \
                || { fail "$slot/$d not writable by $SVC_USER"; rc=1; }
        done
        # The instruction snapshot: readable by the run, never changeable by it.
        if [[ -d "$slot/run-context" ]]; then
            if runuser -u "$SVC_USER" -- test -w "$slot/run-context" 2>/dev/null; then
                fail "$slot/run-context IS WRITABLE by $SVC_USER — a run could rewrite its own instructions"; rc=1
            fi
            for f in "$slot/run-context"/*.md; do
                [[ -e "$f" ]] || continue
                runuser -u "$SVC_USER" -- test -w "$f" 2>/dev/null \
                    && { fail "$f IS WRITABLE by $SVC_USER"; rc=1; }
            done
        fi
    done
    [[ $rc -eq 0 ]] && ok "$nslots run slot(s): inputs and instruction snapshot root-owned, working directories writable"
    # The stored instruction files (every user's memory, the org policy) are
    # root-only; a run sees only its own snapshot.
    if [[ -d "$ORG_DIR/context" ]] && runuser -u "$SVC_USER" -- test -r "$ORG_DIR/context" 2>/dev/null \
            && runuser -u "$SVC_USER" -- test -x "$ORG_DIR/context" 2>/dev/null; then
        fail "$ORG_DIR/context is readable by $SVC_USER — every user's memory would be visible to every run"; rc=1
    elif [[ -d "$ORG_DIR/context" ]]; then
        ok "stored instruction files are unreadable by $SVC_USER (runs see only their own snapshot)"
    fi

    for f in engagement.json approval.json; do
        if [[ -e "$ORG_DIR/$f" ]]; then
            if runuser -u "$SVC_USER" -- test -w "$ORG_DIR/$f" 2>/dev/null; then
                fail "$ORG_DIR/$f IS WRITABLE by $SVC_USER — the engagement could be altered by an agent"; rc=1
            else
                ok "$ORG_DIR/$f root-owned (no agent can write it)"
            fi
        else
            if [[ $f == engagement.json ]]; then
                warn "no engagement yet — set one: Settings → Engagement, or sudo agenti engagement set --help"
            else
                warn "the engagement is not approved yet — an admin approves it: Settings → Engagement, or sudo agenti engagement approve"
            fi
        fi
    done

    # The live grant, read from the run-slot template (systemd loads an
    # instance of it on demand; "verify" names no real slot).
    local instance_unit="agenti-${AGENT}-instance@verify.service"
    if command -v systemctl &>/dev/null; then
        local loadstate; loadstate=$(systemctl show "$instance_unit" -p LoadState --value 2>/dev/null || true)
        if [[ "$loadstate" != "loaded" ]]; then
            warn "capabilities: $instance_unit not loaded by systemd yet — cannot verify the live grant"
        else
            local requested=() ambient_only=() cap against
            if [[ -n "$CAPFILE" ]]; then
                while IFS= read -r cap; do requested+=("$cap"); done < <(_read_capfile "$CAPFILE")
                against="${AGENT}.capabilities"
            else
                # No .capabilities file: nothing narrows the template, so its
                # ceiling is the grant (enum and trafficmon need all of it).
                read -ra requested < <(sed -n 's/^AmbientCapabilities=//p' "$AGENTI_LIBDIR/agenti-instance@.service" | tail -n1)
                against="the template's ceiling (no ${AGENT}.capabilities)"
            fi
            # Mirror render_capability_dropin's own split EXACTLY (same
            # capability-dropin.sh, same $SANDBOX_CAP): SANDBOX_CAP
            # (CAP_SYS_ADMIN) is bounding-set-only, never ambient — bwrap
            # only ever exercises it inside its own namespace. Comparing
            # "requested" against BOTH live sets unsplit made every
            # file-analysis agent fail verify even when correctly deployed
            # (found live 2026-10-08 on cracker: bounding=[cap_sys_admin],
            # correct, flagged as a mismatch anyway).
            for cap in "${requested[@]}"; do [[ "$cap" == "$SANDBOX_CAP" ]] || ambient_only+=("$cap"); done
            local want_amb want_bnd got_amb got_bnd
            want_amb=$(printf '%s\n' "${ambient_only[@]-}" | tr 'A-Z' 'a-z' | sed '/^$/d' | sort -u)
            want_bnd=$(printf '%s\n' "${requested[@]-}" | tr 'A-Z' 'a-z' | sed '/^$/d' | sort -u)
            got_amb=$(systemctl show "$instance_unit" -p AmbientCapabilities --value 2>/dev/null \
                     | tr ' ' '\n' | tr 'A-Z' 'a-z' | sort -u)
            got_bnd=$(systemctl show "$instance_unit" -p CapabilityBoundingSet --value 2>/dev/null \
                     | tr ' ' '\n' | tr 'A-Z' 'a-z' | sort -u)
            if [[ "$want_amb" == "$got_amb" && "$want_bnd" == "$got_bnd" ]]; then
                ok "capabilities: systemd's live grant matches $against (${requested[*]:-none})"
            else
                fail "capabilities: ambient=[$got_amb] bounding=[$got_bnd] but $against requests [${requested[*]:-none}] — re-render it: sudo dpkg-reconfigure agenti"; rc=1
            fi
        fi
    fi

    # Team chat stays with the team: a solo slot ("verify" is one) must bind
    # no part of teams/ — only a team slot's own team.conf binds one channel.
    if command -v systemctl &>/dev/null \
            && [[ "$(systemctl show "$instance_unit" -p LoadState --value 2>/dev/null)" == "loaded" ]]; then
        if systemctl show "$instance_unit" -p BindPaths -p ReadWritePaths --value 2>/dev/null | grep -q "/org/teams"; then
            fail "a solo run of $AGENT can reach org/teams/ (other users' team chat) — re-render it: sudo dpkg-reconfigure agenti"; rc=1
        else
            ok "team chat: a solo run of $AGENT sees no part of org/teams/"
        fi
        # Each run its own PID namespace: no run reads another's /proc/<pid>/
        # (working folder, environment, command line). Audit run 1, N12.
        local ppids; ppids=$(systemctl show "$instance_unit" -p PrivatePIDs --value 2>/dev/null || true)
        if [[ "$ppids" == "yes" ]]; then
            ok "processes: each run of $AGENT has its own PID namespace (other runs are invisible)"
        elif [[ -z "$ppids" ]]; then
            warn "processes: this systemd ($(systemctl --version | sed -n '1s/^systemd \([0-9]*\).*/\1/p')) has no PrivatePIDs (needs 257+): runs of $AGENT can see each other's /proc entries. Upgrade systemd for full run isolation."
        else
            fail "processes: runs of $AGENT share one PID namespace (PrivatePIDs=$ppids) — re-render it: sudo dpkg-reconfigure agenti"; rc=1
        fi
    fi

    return $rc
}


verify_agent() {
    local AGENT="$1" rc=0
    verify_agent_code "$AGENT" || rc=1
    echo
    verify_agent_data "$AGENT" || rc=1
    echo
    local SECRETS="$AGENTI_ROOT/shared/secrets.env"

    if [[ -f "$SECRETS" ]]; then
        local mode; mode=$(stat -c '%a' "$SECRETS")
        [[ "$mode" == "640" ]] && ok "shared secrets.env mode 640 ($SHARED_GROUP-readable)" \
                               || warn "shared secrets.env mode $mode — expected 640"
    else
        warn "no shared API key yet — set one:  sudo agenti setup"
    fi

    if [[ -x "$AGENT_PYTHON" ]]; then
        if svc_exists; then
            runuser -u "$SVC_USER" -- "$AGENT_PYTHON" -c 'import claude_agent_sdk' 2>/dev/null \
                && ok "claude_agent_sdk importable by $SVC_USER" \
                || { fail "claude_agent_sdk not importable by $SVC_USER"; rc=1; }
        fi
    fi

    # Binaries are checked PER AGENT — a fixed recon list would mean a
    # passive agent verifies green while tcpdump is absent.
    local binlist core
    case "$AGENT" in
        enum)        binlist="nmap nikto gobuster dig whatweb enum4linux-ng rpcclient smbclient netexec ping"; core="nmap" ;;
        # zeek is deliberately absent: trafficmon uses it only when present, and the
        # Kali package is uninstallable on this box (pins libc6 << 2.38; see
        # preflight.py's AGENT_TOOLS and trafficmon.deps), so listing it only made
        # every verify end in a warning nobody could act on.
        trafficmon)  binlist="tcpdump tshark dumpcap suricata"; core="tcpdump" ;;
        research)    binlist="none"; core="" ;;
        cracker)     binlist="john hashcat"; core="" ;;
        exploit)     binlist="msfrpcd"; core="msfrpcd" ;;
        *)           binlist=""; core="" ;;
    esac
    if [[ -z "$binlist" ]]; then
        binlist=$(python3 -I -c 'import json, sys
m = json.load(open(sys.argv[1], encoding="utf-8"))
print(" ".join(p["name"] for p in m.get("programs", []) if isinstance(p, dict) and p.get("name")))' \
            "$(agenti_master_dir "$AGENT")/manifest.json" 2>/dev/null) || binlist=""
    fi
    if [[ "$binlist" == "none" ]]; then
        ok "no external binaries required for '$AGENT' (pure Python)"
    elif [[ -z "$binlist" ]]; then
        warn "no binary list defined for agent '$AGENT' — tools unchecked"
        warn "  add one to the case statement in verify.sh so this is not a blind spot"
    else
        local missing=()
        for b in $binlist; do command -v "$b" &>/dev/null || missing+=("$b"); done
        if [[ ${#missing[@]} -eq 0 ]]; then
            ok "all allow-listed binaries present ($binlist)"
        else
            warn "missing allow-listed binaries: ${missing[*]}"
            if [[ -n "$core" && " ${missing[*]} " == *" $core "* ]]; then
                fail "$core missing — core tool for '$AGENT'"; rc=1
            fi
        fi
    fi
    ok "raw-socket privilege comes from the agent's run-slot unit, not setcap (by design)"

    return $rc
}


verify_main() {
    local rc=0 a what="${1:-all}"
    case "$what" in -h|--help|help) sed -n '3,16p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; return 0 ;; esac
    [[ $EUID -eq 0 ]] || die "verify needs root (it tests each account's access): sudo agenti verify"
    case "$what" in
        all)
            verify_platform || rc=1; echo
            verify_gui || rc=1; echo
            if agenti_data_ready; then
                while read -r a; do [[ -n "$a" ]] && { verify_agent "$a" || rc=1; echo; }; done < <(installed_agents)
            else
                warn "the vault is locked: the agents' data was not checked (unlock, then re-run)"
            fi ;;
        gui)   verify_gui || rc=1 ;;
        agent) [[ -n "${2:-}" ]] || die "usage: sudo agenti verify agent <name>"
               verify_agent "$2" || rc=1 ;;
        *) die "usage: sudo agenti verify [gui | agent <name>]" ;;
    esac
    echo
    if [[ $rc -eq 0 ]]; then echo "verify PASSED"; else echo "verify FAILED (see the FAIL lines above)" >&2; fi
    return $rc
}

verify_main "$@"
