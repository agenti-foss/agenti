#!/usr/bin/env bash
#
# capability-dropin.sh — the shared systemd-unit helpers for agent run slots,
# sourced by deploy.sh, vault.sh and the agenti CLI so the three can never
# render a unit fragment differently.
#
# Every agent run uses one unit template per agent,
# agenti-<agent>-instance@.service, where %i is the run slot
# (CLAUDE.md §4 item 71). Two kinds of drop-in sit on top of it:
#   - capabilities.conf on the TEMPLATE (…-instance@.service.d/) — narrows
#     what every slot of that agent may do. A property of the agent's code,
#     so every slot gets the same one.
#   - team.conf on ONE team slot (…-instance@<owner>.team-<team>.service.d/)
#     — binds that team's channel file into the run, and nothing else of
#     teams/. Written by the CLI at team start/resume (see team_dropin).
#
# CONTRACT for whichever script sources this file:
#   - `ok()`, `warn()` and `die()` must already be defined.
#   - paths.sh is sourced here if the caller has not already done so.
#   - `set -euo pipefail` may be active in the caller; nothing below leaves a
#     failure it means to ignore unguarded.
#
# PUBLIC:
#   TEMPLATE_CAPS, SANDBOX_CAP, SANDBOX_RELAX_BOOLEANS
#   slot_template_unit <agent>                       -> unit file name
#   render_slot_template <agent> <acct> <src>        idempotent; prints path if written
#   slot_template_agent <unit-file>                  -> the agent it runs
#   all_unit_paths                                   -> every agent unit file/drop-in dir
#   write_dropin <unit> <name> <content>             idempotent; reloads on change
#   remove_dropin <unit> <name>                      idempotent; reloads on change
#   render_capability_dropin <agent> [<capfile>]
#   team_dropin <agent> <slot>                       -> content, or empty for a solo slot

SYSTEMD_DIR="${SYSTEMD_DIR:-/etc/systemd/system}"

# The path table (paths.sh), unless the sourcing script already loaded it.
if ! declare -F agenti_master_dir >/dev/null; then
    # shellcheck source=paths.sh
    source "$(dirname "${BASH_SOURCE[0]}")/paths.sh"
fi

# TEMPLATE_CAPS must match agenti-instance@.service's own AmbientCapabilities /
# CapabilityBoundingSet exactly — it is the CEILING a drop-in may only
# narrow, never widen (the same narrowing-only rule §1 states for -t on
# run-target, applied here to Linux capabilities).
TEMPLATE_CAPS="CAP_NET_RAW CAP_NET_ADMIN"

# BOUNDING-SET-ONLY, never ambient. shared/sandbox.py's bubblewrap needs
# CAP_SYS_ADMIN present in the calling process's capability BOUNDING set for
# its own unprivileged user-namespace mount setup (tmpfs, bind mounts) to
# succeed — capabilities(7)/user_namespaces(7): a namespace inherits its
# creator's bounding set UNCHANGED, and a capability dropped from the
# bounding set can never be regained, even by "root" inside a brand-new
# namespace that process itself created. It must NEVER also be granted as an
# AMBIENT capability: bwrap only ever exercises it INSIDE the harmless
# namespace it creates for itself, never against the host directly, and
# making it ambient would make it actively effective on the agent process
# itself before bwrap even runs. NoNewPrivileges=yes (set on every agent's
# unit) already blocks every OTHER path that could turn "present in the
# bounding set" into "actually usable against the host".
#
# Only a file-analysis agent asks for it (its .capabilities file names
# CAP_SYS_ADMIN and nothing else, so it also drops the raw-socket
# capabilities recon agents need). Found by testing on the box, not by
# reading documentation; the two booleans below are the whole reason it
# works.
SANDBOX_CAP="CAP_SYS_ADMIN"

# Two hardening booleans that must ALSO be relaxed alongside $SANDBOX_CAP,
# never separately: RestrictSUIDSGID=yes matches a documented systemd/seccomp
# bug that spuriously ENOSYS's bubblewrap's mkdir/tmpfs setup calls;
# ProtectKernelTunables=yes blocks bubblewrap mounting its own /proc. Neither
# directive that confines an agent to its own directory is touched.
SANDBOX_RELAX_BOOLEANS="RestrictSUIDSGID ProtectKernelTunables"

slot_template_unit() { printf 'agenti-%s-instance@.service' "$1"; }

_reload_systemd() {
    command -v systemctl >/dev/null 2>&1 && systemctl daemon-reload 2>/dev/null || true
}

# render_slot_template <agent> <service-account> <template-src>
# Installs agenti-<agent>-instance@.service from the template, with the paths
# from paths.sh and the agent's own code folder (shipped or built). The vault
# assertion is kept only while the vault is enabled, so `agenti vault
# enable|disable` re-renders every template.
# Content-compared: prints the unit path only when it actually wrote it.
# Returns 1 (writing nothing) when the template source is missing.
# The agents whose runs may open raw packet sockets (AF_PACKET): a capture
# needs them, and nothing else does. Every other agent's template drops them.
PACKET_CAPTURE_AGENTS="trafficmon"

render_slot_template() {
    local agent="$1" acct="$2" src="$3"
    [[ -f "$src" ]] || return 1
    local path; path="$SYSTEMD_DIR/$(slot_template_unit "$agent")"
    local master v; master=$(agenti_master_dir "$agent")
    for v in "$AGENTI_ROOT" "$AGENTI_LIBDIR" "$master" "$AGENT_PYTHON"; do
        [[ "$v" == /* && "$v" != *[#[:space:]]* ]] || { warn "$agent: refusing to render a unit with the path '$v'"; return 1; }
    done
    local gate='/^AssertPathIsMountPoint=/d'
    agenti_vault_enabled && gate=''
    local rendered
    local packet=''
    [[ " $PACKET_CAPTURE_AGENTS " == *" $agent "* ]] && packet='s/^RestrictAddressFamilies=\(.*\)$/RestrictAddressFamilies=\1 AF_PACKET/;'
    rendered=$(sed "${gate:+$gate;}${packet}s/__SVC_USER__/$acct/g; s/__AGENT__/$agent/g; s#__ROOT__#$AGENTI_ROOT#g; s#__LIBDIR__#$AGENTI_LIBDIR#g; s#__MASTER__#$master#g; s#__PYTHON__#$AGENT_PYTHON#g" "$src")
    [[ -f "$path" && "$(cat "$path")" == "$rendered" ]] && return 0
    printf '%s\n' "$rendered" > "$path"
    chown root:root "$path"; chmod 0644 "$path"
    _reload_systemd
    printf '%s\n' "$path"
}

# The agent a rendered slot template belongs to, read from the file itself.
slot_template_agent() { sed -n 's/^Environment=AGENT_NAME=//p' "$1" | head -n1; }

# all_unit_paths: every systemd file that belongs to an agent — each slot
# template and its template- and slot-level drop-in directories.
all_unit_paths() {
    local f d
    for f in "$SYSTEMD_DIR"/agenti-*-instance@.service; do
        [[ -f "$f" ]] || continue
        printf '%s\n' "$f"
        for d in "${f%@.service}"@*.service.d; do [[ -d "$d" ]] && printf '%s\n' "$d"; done
    done
    return 0
}

# write_dropin <unit> <name> <content>: installs $SYSTEMD_DIR/<unit>.d/<name>.conf
# (root:root 0644). Content-compared, so calling it on every start is cheap and
# only a real change costs a daemon-reload.
write_dropin() {
    local unit="$1" name="$2" content="$3"
    local dir="$SYSTEMD_DIR/$unit.d" file="$SYSTEMD_DIR/$unit.d/$name.conf"
    if [[ -f "$file" ]] && [[ "$(cat "$file")" == "$content" ]]; then
        return 0
    fi
    install -d -o root -g root -m 0755 "$dir"
    printf '%s\n' "$content" > "$file"
    chown root:root "$file"; chmod 0644 "$file"
    _reload_systemd
}

# remove_dropin <unit> <name>: removes it, and the .d directory once empty.
remove_dropin() {
    local dir="$SYSTEMD_DIR/$1.d" file="$SYSTEMD_DIR/$1.d/$2.conf"
    [[ -f "$file" ]] || return 0
    rm -f "$file"
    rmdir "$dir" 2>/dev/null || true
    _reload_systemd
}

# Prints one capability per line: strips comments/blanks, trims whitespace.
# An empty file (or comments-only) prints nothing, meaning "no capabilities
# needed" — a valid, deliberate declaration, not an error.
_read_capfile() {
    local f="$1" line
    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line%%#*}"
        line="${line//[[:space:]]/}"
        [[ -n "$line" ]] && printf '%s\n' "$line"
    done < "$f"
}

render_capability_dropin() {
    local agent="$1" capfile="${2:-}"
    local unit; unit=$(slot_template_unit "$agent")

    if [[ -z "$capfile" || ! -f "$capfile" ]]; then
        if [[ -f "$SYSTEMD_DIR/$unit.d/capabilities.conf" ]]; then
            remove_dropin "$unit" capabilities
            warn "$agent: removed a capability drop-in — no ${agent}.capabilities file found"
            warn "  (the agent now gets the template default: $TEMPLATE_CAPS)"
        fi
        return 0
    fi

    local requested=() cap
    while IFS= read -r cap; do requested+=("$cap"); done < <(_read_capfile "$capfile")

    for cap in "${requested[@]}"; do
        [[ " $TEMPLATE_CAPS $SANDBOX_CAP " == *" $cap "* ]] || die \
"$capfile requests '$cap', which the agent unit template does not grant
(template allows: $TEMPLATE_CAPS, plus $SANDBOX_CAP for agents that use
shared/sandbox.py). A capability drop-in may only NARROW the template ceiling,
never widen it — add '$cap' to agenti-instance@.service's own
AmbientCapabilities/CapabilityBoundingSet first if every agent genuinely needs
it, or remove it from $capfile if it was a typo."
    done

    # $SANDBOX_CAP is bounding-set-only: split what goes AMBIENT (the real,
    # exercised network capabilities) from the full BOUNDING set.
    local ambient_caps=() bounding_caps=() wants_sandbox=0
    for cap in "${requested[@]}"; do
        bounding_caps+=("$cap")
        if [[ "$cap" == "$SANDBOX_CAP" ]]; then wants_sandbox=1; else ambient_caps+=("$cap"); fi
    done
    local ambient_line="${ambient_caps[*]:-}" bounding_line="${bounding_caps[*]:-}"

    if [[ "$bounding_line" == "$TEMPLATE_CAPS" ]]; then
        # Exactly the template default: no override needed.
        remove_dropin "$unit" capabilities
        ok "$agent: ${agent}.capabilities requests the full template default ($TEMPLATE_CAPS) — no drop-in needed"
        return 0
    fi

    local rendered; rendered=$({
        echo "# Rendered from $(basename "$capfile") — DO NOT hand-edit;"
        echo "# regenerate with: sudo dpkg-reconfigure agenti"
        echo "# Narrows the template's AmbientCapabilities/CapabilityBoundingSet"
        echo "# ($TEMPLATE_CAPS) for every run slot of this agent — a drop-in can only"
        echo "# remove from that baseline plus $SANDBOX_CAP, never add."
        echo "[Service]"
        echo "AmbientCapabilities="       # reset the template's list first —
        echo "CapabilityBoundingSet="     # systemd: empty assignment clears it,
                                          # a later non-empty one then APPENDS.
        [[ -n "$ambient_line" ]] && echo "AmbientCapabilities=$ambient_line"
        [[ -n "$bounding_line" ]] && echo "CapabilityBoundingSet=$bounding_line"
        if [[ $wants_sandbox -eq 1 ]]; then
            echo "# $SANDBOX_CAP was requested — bundled with these, never separately"
            echo "# (see SANDBOX_RELAX_BOOLEANS in capability-dropin.sh)."
            local b
            for b in $SANDBOX_RELAX_BOOLEANS; do echo "$b=no"; done
        fi
    })
    write_dropin "$unit" capabilities "$rendered"
    if [[ -n "$bounding_line" ]]; then
        ok "$agent: capability drop-in installed — ambient: ${ambient_line:-none}, bounding: $bounding_line"
    else
        ok "$agent: capability drop-in installed — no capabilities granted at all"
    fi
    [[ $wants_sandbox -eq 1 ]] && ok "$agent:   plus sandbox support: ${SANDBOX_RELAX_BOOLEANS// /, }=no"
    return 0
}

# team_dropin <agent> <slot>: the team.conf a team slot needs, or
# nothing for a solo slot. A team member always runs in the owner's
# "<owner>.team-<team>" slot (owner and copy labels never contain '.'), so the
# team is read from the slot NAME — never from a file the agent can see.
#
# The template hides the whole org directory and binds back no part of
# teams/; this binds back exactly ONE file, this team's channel, read-write
# (it is chattr +a, so appending is all anyone can do to it). Another team's
# channel, or a solo run's view of teams/, simply does not exist.
team_dropin() {
    local agent="$1" slot="$2"
    [[ "$slot" == *.team-* ]] || return 0
    local team="${slot#*.team-}"
    local dir="$AGENTI_ROOT/org/teams/$team.d"
    local own="$dir/member-$agent.jsonl"
    cat <<EOF
# Rendered by the agenti CLI at team start/resume — DO NOT hand-edit.
# Team "$team": this run reads the whole channel (the operator's file and every
# member's) and may append to its OWN file only. Nothing else under teams/.
[Service]
BindReadOnlyPaths=$dir
BindPaths=$own
ReadWritePaths=$own
EOF
}

# scope_dropin <networks...>: the kernel fence for one IP-scoped run (audit run
# 1, fix 1b). Every packet the run sends or receives must be to/from one of the
# run's approved networks or this machine; systemd enforces it with a cgroup
# BPF filter, so no check in Agenti's own code and no misbehaving tool can get
# around it. The Claude CLI reaches Anthropic through the local relay
# (egress_relay.py), the only non-target way out. bpf() is refused so nothing
# in the run can touch packet filters. Link-layer traffic (ARP on the local
# segment) is below IP and not covered.
# <owner>: the owner's own API key (org/users/<owner>/secrets.env), read by
# systemd as root before the run's namespace exists and loaded LAST, so it wins
# over the agent, org and shared keys (audit run 1, N01: the per-user tier was
# documented but never reached a run). "-": no file, no change.
userkey_dropin() {
    cat <<EOF2
# Rendered by the agenti CLI at start/resume — DO NOT hand-edit.
# The run owner's own API key, when they have one, wins over every other tier.
[Service]
EnvironmentFile=-$AGENTI_ROOT/org/users/$1/secrets.env
EOF2
}

scope_dropin() {
    local relay="${AGENTI_RELAY_ADDR:-127.0.0.1:8429}"
    cat <<EOF2
# Rendered by the agenti CLI at start/resume — DO NOT hand-edit.
# This run may reach only: $* (and this machine).
[Unit]
Requires=agenti-relay.socket
After=agenti-relay.socket
[Service]
IPAddressDeny=any
IPAddressAllow=localhost $*
Environment=AGENTI_RELAY=http://$relay
SystemCallFilter=~bpf
EOF2
}
