#!/usr/bin/env bash
#
# configure.sh — set this machine up for Agenti. Idempotent; safe to re-run.
#
# The ONE implementation of "configure the system" (docs/packaging.md), used by:
#   the package's postinst / prerm              install [--first], remove
#   a developer's deploy from a checkout        shared/deploy.sh runs `install`
#   agenti vault enable | disable | unlock      units, data
#   agenti gui configure ...                    gui
# so a package install and a developer's deploy can never configure the
# machine two different ways. Installed as /usr/lib/agenti/configure.sh.
#
#   configure.sh install [--first]   accounts, folders, user database, sudoers
#                                    grant, every unit; --first also starts the
#                                    GUI and the retention timer and enables
#                                    them on boot (a later run restarts what
#                                    is already running, nothing more)
#   configure.sh units               re-render every unit (after a vault change)
#   configure.sh data                make sure the data folders exist (after unlock)
#   configure.sh gui [options]       how the GUI is reached; `configure.sh gui --help`
#   configure.sh remove              stop everything Agenti runs; remove its units
#                                    and sudoers grant. Settings, accounts, data stay.
# (Purging is the package's postrm alone: by then this file is already gone.)
#
# NEVER: enables an agent's run unit (a box must not resume scanning after a
# power cycle), touches the vault passphrase, or handles an API key.
set -euo pipefail

HERE="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
# Root-run Python below must never import from the caller's folder (audit
# run 1 F14, run 2 for the scripts that are entry points of their own):
# PYTHONSAFEPATH drops it, and the code folder is named instead.
export PYTHONSAFEPATH=1
export PYTHONPATH="$HERE"
# shellcheck source=paths.sh
source "$HERE/paths.sh"

SVC_USER="agenti-run"          # every agent run (also in agenti, vault.sh, set-secret.sh)
SHARED_GROUP="agenti-shared"   # the service account reads code-adjacent data and the shared key through it
API_USER="agenti-api"          # the web tier: owns nothing, reaches root only through sudoers
AUTHD_USER="agenti-authd"      # login, sessions, authorization; the only reader of iam.db
SOCK_GROUP="agenti-sock"       # the auth socket, and nothing else
SYSTEMD_DIR="${SYSTEMD_DIR:-/etc/systemd/system}"
SUDOERS_SRC="$AGENTI_LIBDIR/agenti-api.sudoers"
SUDOERS_DST="/etc/sudoers.d/agenti-api"
AUTHD_DIR="$AGENTI_STATE/authd"
TLS_DIR="$AGENTI_STATE/tls"
AUTHD_SOCK="/run/agenti/authd.sock"
API_UNIT="$SYSTEMD_DIR/agenti-api.service"
API_SOCKET="$SYSTEMD_DIR/agenti-api.socket"
AUTHD_UNIT="$SYSTEMD_DIR/agenti-authd.service"
RETENTION_SERVICE="$SYSTEMD_DIR/agenti-retention.service"
RETENTION_TIMER="$SYSTEMD_DIR/agenti-retention.timer"
RELAY_UNIT="$SYSTEMD_DIR/agenti-relay.service"
RELAY_SOCKET="$SYSTEMD_DIR/agenti-relay.socket"

ok()   { printf '  [ OK ] %s\n' "$*"; }
warn() { printf '  [WARN] %s\n' "$*"; }
die()  { printf '\nERROR: %s\n' "$*" >&2; exit 1; }
step() { printf '\n%s\n' "$*"; }

# capability-dropin.sh: the only code that writes an agent's unit files.
# shellcheck source=capability-dropin.sh
source "$HERE/capability-dropin.sh"

have_systemd() { [[ -d /run/systemd/system ]] && command -v systemctl >/dev/null; }
reload() { have_systemd && systemctl daemon-reload || true; }


# ---------------------------------------------------------------------------
# API settings (/etc/agenti/api.conf), parsed key by key — never sourced: a
# root-owned file today, a shell injection the day it is not.
# ---------------------------------------------------------------------------
BIND_HOST="127.0.0.1" BIND_PORT="8420" TLS_CERT="" TLS_KEY="" HOSTNAME="" ORIGIN_PORT=""
BEHIND_PROXY=0 CLIENT_IP_HEADER=""
read_api_conf() {
    [[ -f "$AGENTI_API_CONF" ]] || return 0
    local k v
    while IFS='=' read -r k v; do
        case "$k" in
            BIND_HOST) BIND_HOST="$v" ;;  BIND_PORT) BIND_PORT="$v" ;;
            TLS_CERT) TLS_CERT="$v" ;;    TLS_KEY) TLS_KEY="$v" ;;
            HOSTNAME) HOSTNAME="$v" ;;    ORIGIN_PORT) ORIGIN_PORT="$v" ;;
            BEHIND_PROXY) [[ "$v" == 1 ]] && BEHIND_PROXY=1 ;;
            CLIENT_IP_HEADER) CLIENT_IP_HEADER="$v" ;;
        esac
    done < "$AGENTI_API_CONF"
}
write_api_conf() {
    install -d -o root -g root -m 0755 "$AGENTI_ETC"
    {
        echo "# How the Agenti GUI is reached. Change it with: sudo agenti gui configure --help"
        printf 'BIND_HOST=%s\nBIND_PORT=%s\nTLS_CERT=%s\nTLS_KEY=%s\nHOSTNAME=%s\nORIGIN_PORT=%s\nBEHIND_PROXY=%s\nCLIENT_IP_HEADER=%s\n' \
            "$BIND_HOST" "$BIND_PORT" "$TLS_CERT" "$TLS_KEY" "$HOSTNAME" "$ORIGIN_PORT" "$BEHIND_PROXY" "$CLIENT_IP_HEADER"
    } > "$AGENTI_API_CONF.tmp"
    chmod 0644 "$AGENTI_API_CONF.tmp"; mv "$AGENTI_API_CONF.tmp" "$AGENTI_API_CONF"
}
is_loopback() { case "$1" in 127.0.0.1|::1) return 0 ;; *) return 1 ;; esac; }
# <address> <port> as systemd and URLs want it: an IPv6 address in brackets.
listen_addr() { if [[ "$1" == *:* ]]; then printf '[%s]:%s' "$1" "$2"; else printf '%s:%s' "$1" "$2"; fi; }
# A strict domain check: the value reaches openssl's comma-separated SAN list
# and a systemd Environment= line, so a comma or space is refused, not
# escaped. A bare IP is refused too: WebAuthn needs a real domain.
valid_hostname() {
    local h="$1" label="[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    [[ ${#h} -ge 1 && ${#h} -le 253 ]] || return 1
    [[ "$h" =~ ^[0-9]+(\.[0-9]+){3}$ ]] && return 1
    local re="^${label}(\\.${label})+\$"
    [[ "$h" =~ $re ]]
}
# A literal address only: a name ('localhost') or an out-of-range IPv4 was
# accepted before and rendered a socket systemd refused to load, so nothing
# held the GUI's port (audit run 2).
valid_bind() {
    local o
    if [[ "$1" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]]; then
        for o in "${BASH_REMATCH[@]:1}"; do (( 10#$o <= 255 )) || return 1; done
        return 0
    fi
    [[ "$1" == *:* && "$1" =~ ^[0-9A-Fa-f:.]{2,45}$ ]]
}


# ---------------------------------------------------------------------------
# accounts
# ---------------------------------------------------------------------------
ensure_group() { getent group "$1" >/dev/null || { groupadd --system "$1"; ok "created group $1"; }; }
ensure_user() {
    local u="$1" groups="$2"
    if ! id "$u" &>/dev/null; then
        useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin "$u"
        ok "created service account $u (nologin, no home)"
    fi
    local g
    for g in $groups; do
        id -nG "$u" | tr ' ' '\n' | grep -qx "$g" || usermod -aG "$g" "$u"
    done
}
configure_accounts() {
    step "service accounts:"
    ensure_group "$SHARED_GROUP"; ensure_group "$SOCK_GROUP"
    ensure_user "$SVC_USER" "$SHARED_GROUP"
    # Neither of these joins the other's group: agenti-api in agenti-authd's
    # group could read iam.db, which is the thing this split keeps from it.
    ensure_user "$API_USER" "$SOCK_GROUP"
    ensure_user "$AUTHD_USER" "$SOCK_GROUP"
    ok "$SVC_USER (runs agents), $API_USER (web tier), $AUTHD_USER (sign-in)"
}


# ---------------------------------------------------------------------------
# state outside the data root: works while the vault is locked
# ---------------------------------------------------------------------------
configure_state() {
    step "state ($AGENTI_STATE):"
    install -d -o root -g root -m 0755 "$AGENTI_STATE"
    # The user database: root writes it (the CLI), authd reads it, the API
    # cannot open it at all. Created empty: no user exists until
    # `agenti setup` makes the first admin, so every request fails closed.
    if [[ ! -f "$AGENTI_IAM_DB" ]]; then
        AGENTI_IAM_DB="$AGENTI_IAM_DB" python3 -c "
import sys; sys.path.insert(0, sys.argv[1])
import iam; iam.open_iam(readonly=False).close()" "$AGENTI_LIBDIR" \
            || die "could not create the user database at $AGENTI_IAM_DB"
        ok "created an empty user database (no users yet: run  sudo agenti setup)"
    fi
    chown root:"$AUTHD_USER" "$AGENTI_IAM_DB"; chmod 0640 "$AGENTI_IAM_DB"
    # Sessions, lockouts, replay records, the authz audit log: authd's own,
    # in its own folder (SQLite creates its -wal/-shm files beside the db).
    install -d -o "$AUTHD_USER" -g "$AUTHD_USER" -m 0700 "$AUTHD_DIR"
    chown "$AUTHD_USER:$AUTHD_USER" "$AUTHD_DIR"; chmod 0700 "$AUTHD_DIR"
    # The folder belongs to agenti-authd, which could plant a link here
    # (runtime.db-x -> /etc/shadow): a plain chown/chmod would follow it and
    # hand authd any file on the system (audit run 1, F18). Each file is opened
    # without following links, must be a regular file, and is changed through
    # that open descriptor, so nothing can be swapped in between.
    python3 - "$AUTHD_DIR" "$(id -u "$AUTHD_USER")" "$(id -g "$AUTHD_USER")" <<'PYFIX'
import os, stat, sys
d, uid, gid = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
dfd = os.open(d, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
for name in os.listdir(dfd):
    if not name.startswith("runtime.db"):
        continue
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dfd)
    except OSError:
        continue                      # a link, or gone: never touched
    try:
        if stat.S_ISREG(os.fstat(fd).st_mode):
            os.fchown(fd, uid, gid)
            os.fchmod(fd, 0o600)
    finally:
        os.close(fd)
os.close(dfd)
PYFIX
    # Free-form operator text for an admin to triage: root only. Never truncated.
    [[ -f "$AGENTI_STATE/tool-requests.jsonl" ]] \
        || install -o root -g root -m 0640 /dev/null "$AGENTI_STATE/tool-requests.jsonl"
    ok "user database 0640 root:$AUTHD_USER, sessions 0700 $AUTHD_USER"
}


# ---------------------------------------------------------------------------
# the data root: secrets, instruction edits, built agents, the engagement,
# runs. Only while it is usable (always, unless the vault is on and locked).
# ---------------------------------------------------------------------------
configure_data() {
    step "data ($AGENTI_ROOT):"
    if agenti_vault_enabled && ! agenti_data_ready; then
        warn "the vault is locked — the data folders are checked at the next  sudo agenti vault unlock"
        return 0
    fi
    install -d -o root -g root -m 0751 "$AGENTI_ROOT"
    chown root:root "$AGENTI_ROOT"; chmod 0751 "$AGENTI_ROOT"
    install -d -o root -g root -m 0751 "$AGENTI_ROOT/shared"
    chown root:root "$AGENTI_ROOT/shared"; chmod 0751 "$AGENTI_ROOT/shared"
    # Built agents: world-listable so `agenti agents` works without root.
    install -d -o root -g root -m 0755 "$AGENTI_BUILT_AGENTS"
    # Every edited instruction file and every user's memory: root only.
    install -d -o root -g root -m 0700 "$AGENTI_ROOT/shared/context"
    if [[ -f "$AGENTI_ROOT/shared/secrets.env" ]]; then
        chown root:"$SHARED_GROUP" "$AGENTI_ROOT/shared/secrets.env"; chmod 0640 "$AGENTI_ROOT/shared/secrets.env"
    fi
    install -d -o root -g "$SVC_USER" -m 0750 "$AGENTI_ROOT/org"
    install -d -o root -g "$SVC_USER" -m 0750 "$AGENTI_ROOT/org/teams"
    local a n=0
    while read -r a; do
        [[ -n "$a" ]] || continue
        "$AGENTI_BIN" "$a" provision --json >/dev/null 2>&1 && n=$((n + 1)) \
            || warn "$a: could not prepare its data folder (sudo agenti $a provision says why)"
    done < <(installed_agents)
    ok "data folders ready ($n agents)"
}


# ---------------------------------------------------------------------------
# units
# ---------------------------------------------------------------------------
installed_agents() {
    local d n
    for d in "$AGENTI_SHIPPED_AGENTS"/*/ "$AGENTI_BUILT_AGENTS"/*/; do
        [[ -d "$d" ]] || continue
        n=$(basename "$d")
        [[ -f "$d/$n-agent.py" ]] && printf '%s\n' "$n"
    done | sort -u
}

configure_agent_units() {
    step "agent run units:"
    local src="$AGENTI_LIBDIR/agenti-instance@.service" a capf n=0
    [[ -f "$src" ]] || die "$src is missing. Reinstall: sudo apt install --reinstall agenti"
    while read -r a; do
        [[ -n "$a" ]] || continue
        render_slot_template "$a" "$SVC_USER" "$src" >/dev/null || die "could not render the run unit for $a"
        capf="$(agenti_master_dir "$a")/$a.capabilities"
        [[ -f "$capf" ]] || capf=""
        render_capability_dropin "$a" "$capf" >/dev/null || die "could not render the capability drop-in for $a"
        n=$((n + 1))
    done < <(installed_agents)
    # An agent the package no longer ships (and nobody built) loses its unit,
    # unless a run of it is still going. Skipped while the vault is locked:
    # built agents are invisible then.
    if agenti_data_ready; then
        local f agent
        for f in "$SYSTEMD_DIR"/agenti-*-instance@.service; do
            [[ -f "$f" ]] || continue
            agent=$(slot_template_agent "$f")
            [[ -n "$agent" && ! -f "$(agenti_master_dir "$agent")/$agent-agent.py" ]] || continue
            if have_systemd && systemctl list-units --state=active --plain --no-legend "agenti-$agent-instance@*" 2>/dev/null | grep -q .; then
                warn "$agent is no longer installed but a run of it is still going; its unit stays until it ends"
                continue
            fi
            rm -rf "${f:?}" "${f%@.service}"@*.service.d
            ok "removed the unit of $agent (no longer installed)"
        done
    fi
    reload
    ok "$n agent run unit(s): rendered, never enabled (a run starts only when someone starts it)"
}

configure_service_units() {
    step "GUI and maintenance units:"
    read_api_conf
    # uvicorn never rewrites the client address from a forwarding header: any
    # local process is a loopback peer and could otherwise pick the address
    # the login throttle sees (audit run 1, F33). Behind a proxy,
    # api/proxytrust.py applies one explicit rule instead.
    local uvicorn_tls=" --no-proxy-headers" api_env="" authd_env="" scheme=http port
    if [[ -n "$TLS_CERT" ]]; then
        uvicorn_tls=" --no-proxy-headers --ssl-certfile $TLS_CERT --ssl-keyfile $TLS_KEY"
        api_env="Environment=AGENTI_TLS=1"
        scheme=https
    elif [[ $BEHIND_PROXY -eq 1 ]]; then
        # The browser is on HTTPS (the proxy holds the certificate), so the
        # cookie is Secure even though this hop is loopback HTTP.
        api_env="Environment=AGENTI_TLS=1
Environment=AGENTI_BEHIND_PROXY=1
Environment=AGENTI_CLIENT_IP_HEADER=$CLIENT_IP_HEADER
Environment=AGENTI_HOSTNAME=$HOSTNAME"
        scheme=https
    fi
    # The relying party for passkeys: the bare domain, and the exact origin a
    # browser puts in clientDataJSON (no port when it is the scheme's default).
    if [[ -n "$HOSTNAME" ]]; then
        port="${ORIGIN_PORT:-$BIND_PORT}"
        [[ $BEHIND_PROXY -eq 1 && -z "$ORIGIN_PORT" ]] && port=443
        if [[ ( "$scheme" == https && "$port" == 443 ) || ( "$scheme" == http && "$port" == 80 ) ]]; then
            authd_env="Environment=AGENTI_HOSTNAME=$HOSTNAME
Environment=AGENTI_ORIGIN=$scheme://$HOSTNAME"
        else
            authd_env="Environment=AGENTI_HOSTNAME=$HOSTNAME
Environment=AGENTI_ORIGIN=$scheme://$HOSTNAME:$port"
        fi
    fi

    cat > "$AUTHD_UNIT" <<EOF
# Rendered by $AGENTI_LIBDIR/configure.sh — DO NOT hand-edit.
# Regenerate: sudo dpkg-reconfigure agenti   (settings: sudo agenti gui configure --help)
[Unit]
Description=Agenti authd — privileged login, session and authorization service
After=network.target
Before=agenti-api.service

[Service]
Type=exec
User=$AUTHD_USER
Group=$AUTHD_USER
SupplementaryGroups=$SOCK_GROUP
# /run/agenti, created for us; the SOCKET is the gate (0660
# $AUTHD_USER:$SOCK_GROUP, set by authd.py) and the kernel peer-uid check
# inside authd.py is the gate behind that.
RuntimeDirectory=agenti
RuntimeDirectoryMode=0755
ExecStart=$AUTHD_PYTHON $AGENTI_LIBDIR/authd.py --socket $AUTHD_SOCK --allow-user $API_USER --socket-group $SOCK_GROUP
Environment=AGENTI_IAM_DB=$AGENTI_IAM_DB
Environment=AGENTI_RUNTIME_DB=$AGENTI_RUNTIME_DB
Environment=PYTHONUNBUFFERED=1
$authd_env
Restart=on-failure
RestartSec=5

# This process never calls sudo and writes exactly one folder, so every
# restriction below costs nothing.
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=$AUTHD_DIR
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_UNIX
RestrictNamespaces=yes
RestrictRealtime=yes
LockPersonality=yes
SystemCallArchitectures=native
CapabilityBoundingSet=
UMask=0077

[Install]
WantedBy=multi-user.target
EOF

    # systemd, not uvicorn, holds the GUI's port, from boot and across every
    # restart, upgrade and crash: a local process waiting for the port to come
    # free could otherwise take it and serve the real origin, receiving users'
    # session cookies (audit run 1, F09). uvicorn is handed the socket (--fd 3).
    cat > "$API_SOCKET" <<EOF
# Rendered by $AGENTI_LIBDIR/configure.sh — DO NOT hand-edit.
# Regenerate: sudo dpkg-reconfigure agenti   (settings: sudo agenti gui configure --help)
[Unit]
Description=Agenti API — the GUI's listening port, held by systemd

[Socket]
ListenStream=$(listen_addr "$BIND_HOST" "$BIND_PORT")
Accept=no
FreeBind=yes
NoDelay=yes
Service=agenti-api.service

[Install]
WantedBy=sockets.target
EOF

    cat > "$API_UNIT" <<EOF
# Rendered by $AGENTI_LIBDIR/configure.sh — DO NOT hand-edit.
# Regenerate: sudo dpkg-reconfigure agenti   (settings: sudo agenti gui configure --help)
[Unit]
Description=Agenti API — thin read/control layer over the agenti CLI
After=network.target agenti-authd.service agenti-api.socket
Wants=agenti-authd.service
Requires=agenti-api.socket

[Service]
Type=exec
User=$API_USER
Group=$API_USER
# Only for the auth socket. The API holds no store and no identity file.
SupplementaryGroups=$SOCK_GROUP
WorkingDirectory=$AGENTI_LIBDIR/api
# The address is the socket unit's (agenti-api.socket: $BIND_HOST:$BIND_PORT).
ExecStart=$API_PYTHON -m uvicorn main:app --fd 3 --app-dir $AGENTI_LIBDIR/api$uvicorn_tls
Environment=AGENTI_AUTHD_SOCKET=$AUTHD_SOCK
Environment=AGENTI_BIN=$AGENTI_BIN
$api_env
Restart=on-failure
RestartSec=5

# THINNER than the other units, on purpose. NoNewPrivileges would stop sudo
# (setuid) from running at all, and ProtectSystem is inherited by the root
# 'agenti' child, which must write run files and render units. The real
# confinement: this account owns nothing, and its one route to root is one
# sudoers line naming one binary ($AGENTI_BIN), which carries every scope,
# vault and preflight gate with it and logs every use.
ProtectHome=yes
PrivateTmp=yes

# [Install] on purpose (unlike an agent's run unit): this serves pages and
# scans nothing. An agent run still needs someone to start it.
[Install]
WantedBy=multi-user.target
EOF

    cat > "$RETENTION_SERVICE" <<EOF
# Rendered by $AGENTI_LIBDIR/configure.sh — DO NOT hand-edit.
[Unit]
Description=Agenti retention sweep — delete run working data and history older than 30 days
After=network.target

[Service]
Type=oneshot
# Fails, visibly, while the vault is locked: a month of locked vault should
# show a sweep that has not run, not "everything is fine".
ExecStart=$AGENTI_BIN admin retention-sweep
EOF
    cat > "$RETENTION_TIMER" <<EOF
# Rendered by $AGENTI_LIBDIR/configure.sh — DO NOT hand-edit.
[Unit]
Description=Run the Agenti retention sweep daily

[Timer]
OnCalendar=daily
RandomizedDelaySec=1800
Persistent=true

[Install]
WantedBy=timers.target
EOF
    # systemd holds the relay's port from boot, as it holds the GUI's: while the
    # relay was down any local user could take 127.0.0.1:8429 and receive every
    # IP-scoped run's model traffic (audit run 2; operator decision 5). The
    # socket starts no code; the relay runs on the first connection.
    cat > "$RELAY_SOCKET" <<EOF
# Rendered by $AGENTI_LIBDIR/configure.sh — DO NOT hand-edit.
[Unit]
Description=Agenti relay — its loopback port, held by systemd

[Socket]
ListenStream=$AGENTI_RELAY_ADDR
Accept=no
FreeBind=yes
Service=agenti-relay.service

[Install]
WantedBy=sockets.target
EOF
    cat > "$RELAY_UNIT" <<EOF
# Rendered by $AGENTI_LIBDIR/configure.sh — DO NOT hand-edit.
[Unit]
Description=Agenti relay — the one way out of an IP-scoped run that is not a target (Anthropic API only)
After=network.target agenti-relay.socket
Requires=agenti-relay.socket
# No [Install]: started by its socket on a run's first connection.

[Service]
ExecStart=$AGENT_PYTHON $AGENTI_LIBDIR/egress_relay.py --fd 3
Restart=on-failure
RestartSec=2
DynamicUser=yes
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=yes
RestrictRealtime=yes
LockPersonality=yes
SystemCallArchitectures=native
CapabilityBoundingSet=
MemoryMax=256M
TasksMax=256
EOF
    chmod 0644 "$AUTHD_UNIT" "$API_UNIT" "$API_SOCKET" "$RETENTION_SERVICE" "$RETENTION_TIMER" "$RELAY_UNIT" "$RELAY_SOCKET"
    reload
    if is_loopback "$BIND_HOST"; then ok "GUI on $(listen_addr "$BIND_HOST" "$BIND_PORT") (this machine only${HOSTNAME:+; public name $HOSTNAME})"
    else ok "GUI on https://$(listen_addr "$BIND_HOST" "$BIND_PORT") — reachable from that network (password + 2FA protect it)"; fi
}


# ---------------------------------------------------------------------------
# the sudoers grant: validated BEFORE it can affect sudo at all
# ---------------------------------------------------------------------------
configure_sudoers() {
    step "sudoers grant for $API_USER:"
    [[ -f "$SUDOERS_SRC" ]] || die "$SUDOERS_SRC is missing. Reinstall: sudo apt install --reinstall agenti"
    command -v visudo >/dev/null || die "visudo is missing (the sudo package). Install it: apt install sudo"
    # A syntax error in ANY file under /etc/sudoers.d breaks sudo for everyone.
    # So: checked first, written under a name sudo ignores (it skips names with
    # a dot), then renamed into place in one step.
    visudo -c -q -f "$SUDOERS_SRC" || die "$SUDOERS_SRC does not parse — NOT installed. This is a packaging bug; report it."
    install -d -o root -g root -m 0750 /etc/sudoers.d
    install -o root -g root -m 0440 "$SUDOERS_SRC" "$SUDOERS_DST.agenti-new"
    mv "$SUDOERS_DST.agenti-new" "$SUDOERS_DST"
    ok "$SUDOERS_DST: $API_USER may run exactly $API_BRIDGE as root, with no arguments (checked with visudo)"
}


# ---------------------------------------------------------------------------
# bytecode: compiled once here, by root, for both interpreters that import the
# code (the system python3 the CLI's helpers run on, and the bundled one runs
# use), so nothing has to write a cache at run time. cmd_remove deletes the
# caches again, so a purge leaves no file dpkg does not know about.
# ---------------------------------------------------------------------------
compile_code() {
    local py
    for py in python3 "$AGENT_PYTHON"; do
        command -v "$py" >/dev/null || [[ -x "$py" ]] || continue
        "$py" -m compileall -q -x '/gui/' "$AGENTI_LIBDIR" >/dev/null 2>&1 || true
    done
}
clean_bytecode() { find "$AGENTI_LIBDIR" -name __pycache__ -type d -prune -exec rm -rf {} + 2>/dev/null || true; }


# ---------------------------------------------------------------------------
# starting things
# ---------------------------------------------------------------------------
start_services() {
    local first="$1"
    have_systemd || { warn "systemd is not running here — nothing was started"; return 0; }
    if [[ $first -eq 1 ]]; then
        systemctl enable --quiet agenti-authd.service agenti-api.socket agenti-api.service agenti-retention.timer \
            agenti-relay.socket
        systemctl stop agenti-relay.service 2>/dev/null || true     # a relay still holding the port itself
        systemctl restart agenti-relay.socket
        systemctl restart agenti-authd.service
        systemctl stop agenti-api.service 2>/dev/null || true     # a uvicorn still holding the port itself
        systemctl restart agenti-api.socket
        systemctl restart agenti-api.service agenti-retention.timer
    else
        # An upgrade restarts what runs (or crashed), nothing more: if someone
        # turned the GUI off (agenti gui disable), it stays off. The port is
        # held by agenti-api.socket throughout; an install from before the
        # socket existed hands it over once, here.
        local u
        if systemctl is-active --quiet agenti-api.service && ! systemctl is-active --quiet agenti-api.socket; then
            systemctl stop agenti-api.service
            systemctl enable --now --quiet agenti-api.socket
            systemctl start agenti-api.service
        fi
        # The relay's port too, on every upgrade (a relay from before its socket
        # existed binds the port itself and is replaced here).
        if ! systemctl is-active --quiet agenti-relay.socket; then
            systemctl stop agenti-relay.service 2>/dev/null || true
            systemctl enable --now --quiet agenti-relay.socket
        else
            systemctl enable --quiet agenti-relay.socket
            systemctl try-restart agenti-relay.service 2>/dev/null || true
        fi
        for u in agenti-authd.service agenti-api.service agenti-retention.timer; do
            if systemctl is-active --quiet "$u" || systemctl is-failed --quiet "$u"; then
                systemctl reset-failed "$u" 2>/dev/null || true
                systemctl restart "$u"
            fi
        done
    fi
    sleep 2
    if systemctl is-active --quiet agenti-api.service; then
        read_api_conf
        ok "the GUI is running: $( [[ -n "$TLS_CERT" ]] && echo https || echo http )://$(listen_addr "$BIND_HOST" "$BIND_PORT")"
    elif [[ $first -eq 1 ]]; then
        warn "the GUI did not start — see:  journalctl -u agenti-api -u agenti-authd -n 40"
    fi
}


# ---------------------------------------------------------------------------
# configure.sh gui — how the GUI is reached
# ---------------------------------------------------------------------------
gui_usage() {
    cat <<EOF
usage: sudo agenti gui configure [options]     (current settings: $AGENTI_API_CONF)

  --bind <address>        listen on this address instead of 127.0.0.1 (needs TLS)
  --port <port>           listen on this port (default 8420)
  --tls                   generate a self-signed certificate (reused later)
  --tls-cert <path> --tls-key <path>   use a certificate you already have
  --no-tls                plain HTTP again (loopback only)
  --hostname <domain>     the real domain people use, e.g. agenti.example.com;
                          needed for passkeys (browsers refuse a bare IP)
  --no-hostname           forget it
  --origin-port <port>    the port a BROWSER sees for --hostname when something
                          in front remaps it (443 = the scheme's default)
  --no-origin-port        assume the browser sees --port directly
  --behind-proxy          RECOMMENDED for internet access: a proxy or tunnel on
                          THIS machine (Cloudflare Tunnel, nginx, Caddy) holds
                          the certificate and forwards over loopback. Needs
                          --hostname; refused with --tls or a network --bind.
  --client-ip-header <h>  the header your proxy puts the caller's address in
                          (default CF-Connecting-IP; nginx/Caddy: X-Forwarded-For)
  --no-behind-proxy       serve browsers directly again

Changes are saved, the GUI is restarted, and every later upgrade keeps them.
Full guide: docs/remote-access.md
EOF
}

cmd_gui() {
    read_api_conf
    local gen_tls=0 changed=0
    [[ $# -gt 0 ]] || { gui_usage; exit 0; }
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help) gui_usage; exit 0 ;;
            --bind)   [[ $# -ge 2 ]] || die "--bind needs an address, e.g. --bind 192.168.1.10"
                      valid_bind "$2" || die "--bind '$2' is not an IP address. Give the address itself:
127.0.0.1 or ::1 (this machine only), or this machine's LAN address, e.g. 192.168.1.20"; BIND_HOST="$2"; shift 2 ;;
            --port)   [[ $# -ge 2 && "$2" =~ ^[0-9]{2,5}$ && "$2" -ge 1 && "$2" -le 65535 ]] || die "--port needs a port number, e.g. --port 8420"
                      BIND_PORT="$2"; shift 2 ;;
            --tls)    gen_tls=1; shift ;;
            --tls-cert) [[ $# -ge 2 ]] || die "--tls-cert needs a path"; TLS_CERT="$2"; shift 2 ;;
            --tls-key)  [[ $# -ge 2 ]] || die "--tls-key needs a path";  TLS_KEY="$2";  shift 2 ;;
            --no-tls) TLS_CERT=""; TLS_KEY=""; gen_tls=0; shift ;;
            --hostname) [[ $# -ge 2 ]] || die "--hostname needs a domain, e.g. --hostname agenti.example.com"
                        HOSTNAME="$2"; shift 2 ;;
            --no-hostname) HOSTNAME=""; shift ;;
            --origin-port) [[ $# -ge 2 && "$2" =~ ^[0-9]{2,5}$ ]] || die "--origin-port needs a port number, e.g. --origin-port 443"
                           ORIGIN_PORT="$2"; shift 2 ;;
            --no-origin-port) ORIGIN_PORT=""; shift ;;
            --behind-proxy) BEHIND_PROXY=1; shift ;;
            --no-behind-proxy) BEHIND_PROXY=0; CLIENT_IP_HEADER=""; shift ;;
            --client-ip-header) [[ $# -ge 2 && "$2" =~ ^[A-Za-z][A-Za-z0-9-]{0,63}$ ]] \
                                    || die "--client-ip-header needs an HTTP header name, e.g. X-Forwarded-For"
                                CLIENT_IP_HEADER="$2"; shift 2 ;;
            *) gui_usage >&2; die "unknown option '$1'" ;;
        esac
        changed=1
    done
    [[ $changed -eq 1 ]] || { gui_usage; exit 0; }

    if [[ -n "$HOSTNAME" ]]; then
        valid_hostname "$HOSTNAME" || die "--hostname '$HOSTNAME' is not a domain name.
Letters, digits, hyphens and dots, e.g. agenti.example.com — not an IP address
(passkeys need a real domain) and not a wildcard."
    fi
    if [[ $BEHIND_PROXY -eq 1 ]]; then
        is_loopback "$BIND_HOST" || die "--behind-proxy needs a loopback bind (127.0.0.1), not '$BIND_HOST'.
Only the proxy on this machine may reach the GUI; a header naming the caller's
address can be trusted from it alone. Add: --bind 127.0.0.1"
        [[ -z "$TLS_CERT" && $gen_tls -eq 0 ]] || die "--behind-proxy and --tls do not combine: the proxy holds the
certificate and this hop is loopback. Add --no-tls, or drop --behind-proxy."
        [[ -n "$HOSTNAME" ]] || die "--behind-proxy needs --hostname <your public domain> (the only Host the GUI
answers to, and what passkeys are bound to)."
        [[ -n "$CLIENT_IP_HEADER" ]] || CLIENT_IP_HEADER="CF-Connecting-IP"
    else
        CLIENT_IP_HEADER=""
    fi
    if [[ $gen_tls -eq 1 && -z "$TLS_CERT" ]]; then
        TLS_CERT="$TLS_DIR/api.crt"; TLS_KEY="$TLS_DIR/api.key"
    fi
    if [[ -n "$TLS_CERT" || -n "$TLS_KEY" ]]; then
        [[ -n "$TLS_CERT" && -n "$TLS_KEY" ]] || die "--tls-cert and --tls-key go together."
        [[ "$TLS_CERT" == /* && "$TLS_KEY" == /* && "$TLS_CERT$TLS_KEY" != *[[:space:]]* ]] \
            || die "the certificate and key need absolute paths without spaces."
    fi
    # Generated only when asked AND absent: a fresh certificate makes every
    # device that trusted the old one warn again, with no explanation.
    if [[ $gen_tls -eq 1 && ! -f "$TLS_CERT" ]]; then
        command -v openssl >/dev/null || die "openssl is needed to make a certificate (apt install openssl)."
        install -d -o root -g "$API_USER" -m 0750 "$TLS_DIR"
        local host sans fp
        host="$(hostname -s 2>/dev/null || echo agenti)"
        sans="DNS:$host,DNS:localhost,IP:127.0.0.1"
        is_loopback "$BIND_HOST" || sans="$sans,IP:$BIND_HOST"
        [[ -n "$HOSTNAME" ]] && sans="$sans,DNS:$HOSTNAME"
        # 398 days: Safari refuses anything longer.
        openssl req -x509 -newkey rsa:2048 -nodes -days 398 -keyout "$TLS_KEY" -out "$TLS_CERT" \
            -subj "/CN=agenti-$host" -addext "subjectAltName=$sans" 2>/dev/null \
            || die "openssl could not make the certificate."
        fp=$(openssl x509 -in "$TLS_CERT" -noout -fingerprint -sha256 2>/dev/null | sed 's/^.*=//' || true)
        ok "made a self-signed certificate for $sans (valid 398 days)"
        [[ -n "$fp" ]] && printf '         SHA-256 fingerprint: %s\n         Compare it with what the browser shows the first time.\n' "$fp"
    fi
    if [[ -n "$TLS_CERT" ]]; then
        [[ -f "$TLS_CERT" && -f "$TLS_KEY" ]] || die "certificate or key missing ($TLS_CERT / $TLS_KEY). Make one:  sudo agenti gui configure --tls"
        if [[ "$TLS_KEY" == "$TLS_DIR/"* ]]; then
            chown root:"$API_USER" "$TLS_DIR" "$TLS_KEY" "$TLS_CERT"
            chmod 0750 "$TLS_DIR"; chmod 0640 "$TLS_KEY"; chmod 0644 "$TLS_CERT"
        fi
        runuser -u "$API_USER" -- test -r "$TLS_KEY" 2>/dev/null || die "$API_USER cannot read $TLS_KEY (check it and every folder above it)."
    fi
    if ! is_loopback "$BIND_HOST" && [[ -z "$TLS_CERT" ]]; then
        die "refusing to listen on '$BIND_HOST' without TLS: a session cookie over plain HTTP
can be read by anyone on that network. Add --tls (or --tls-cert/--tls-key),
or put a proxy in front: --behind-proxy --hostname <domain>."
    fi
    write_api_conf
    ok "saved $AGENTI_API_CONF"
    configure_service_units
    if have_systemd; then
        # A new address or port: the socket is re-bound (the one moment the
        # port changes hands, done by root, deliberately).
        systemctl stop agenti-api.service
        systemctl restart agenti-api.socket
        systemctl restart agenti-authd.service agenti-api.service
        sleep 2
        systemctl is-active --quiet agenti-api.service \
            || die "the GUI did not come back up. See:  journalctl -u agenti-api -u agenti-authd -n 40"
        ok "the GUI restarted with the new settings"
    fi
    if [[ $BEHIND_PROXY -eq 1 ]]; then
        printf '\n  Point the proxy for %s at  http://127.0.0.1:%s  (docs/remote-access.md).\n' "$HOSTNAME" "$BIND_PORT"
    fi
}


# ---------------------------------------------------------------------------
# remove
# ---------------------------------------------------------------------------
cmd_remove() {
    step "stopping Agenti and removing its units:"
    if have_systemd; then
        systemctl stop 'agenti-*-instance@*.service' 2>/dev/null || true
        systemctl disable --now --quiet agenti-api.service agenti-api.socket agenti-authd.service agenti-retention.timer \
            agenti-relay.socket 2>/dev/null || true
        systemctl stop agenti-retention.service agenti-relay.service 2>/dev/null || true
    fi
    local p
    while read -r p; do rm -rf "${p:?}"; done < <(all_unit_paths)
    rm -f "$API_UNIT" "$API_SOCKET" "$AUTHD_UNIT" "$RETENTION_SERVICE" "$RETENTION_TIMER" "$RELAY_UNIT" "$RELAY_SOCKET" "$SUDOERS_DST" "$SUDOERS_DST.agenti-new"
    clean_bytecode
    reload
    ok "stopped; units and the sudoers grant removed (settings, accounts and data kept)"
    # With Agenti gone nothing could lock the vault again, so it is locked now
    # (operator decision 2026-10-21). Nothing is deleted.
    if agenti_vault_enabled; then
        local img; img=$(sed -n 's/^IMAGE=//p' "$AGENTI_VAULT_CONF" | sed -n 1p)
        if "$AGENTI_LIBDIR/vault.sh" lock >/dev/null 2>&1; then
            ok "the vault is locked; the data stays encrypted in ${img:-the vault image}"
        else
            warn "the vault could not be locked (something is still using $AGENTI_ROOT); it locks at the next reboot"
        fi
        cat <<EOF
  To read the data again: reinstall Agenti and run  sudo agenti vault unlock
  or, without Agenti, with your passphrase:
    sudo cryptsetup open ${img:-/var/lib/agenti/vault.img} agenti_vault
    sudo mount /dev/mapper/agenti_vault /mnt
EOF
    fi
}

# ---------------------------------------------------------------------------
# The header comment, however long it grows.
usage() { awk 'NR > 2 && /^#/ { sub(/^# ?/, ""); print; next } NR > 2 { exit }' "${BASH_SOURCE[0]}"; }

configure_main() {
    local cmd="${1:-}"; [[ $# -gt 0 ]] && shift
    case "$cmd" in -h|--help|help|"") usage; exit 0 ;; esac
    [[ "$cmd" == gui && ( "${1:-}" == -h || "${1:-}" == --help || $# -eq 0 ) ]] && { gui_usage; exit 0; }
    [[ $EUID -eq 0 ]] || die "must run as root (sudo)."
    case "$cmd" in
        install)
            local first=0; [[ "${1:-}" == "--first" ]] && first=1
            configure_accounts
            configure_state
            [[ -f "$AGENTI_API_CONF" ]] || { write_api_conf; ok "wrote $AGENTI_API_CONF (this machine only, port $BIND_PORT)"; }
            configure_sudoers
            configure_data
            configure_agent_units
            configure_service_units
            compile_code
            start_services "$first"
            ;;
        units)  configure_agent_units; configure_service_units ;;
        data)   configure_data ;;
        gui)    cmd_gui "$@" ;;
        remove) cmd_remove ;;
        *) usage >&2; die "unknown command '$cmd'" ;;
    esac
}

# Sourced (verify.sh does, for the names and helpers above): define, do nothing.
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then configure_main "$@"; fi
