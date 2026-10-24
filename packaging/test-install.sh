#!/usr/bin/env bash
#
# test-install.sh — install, upgrade, remove and purge the packages on a CLEAN
# machine, the way a stranger would, and check every step. CI runs it as root
# inside fresh kalilinux/kali-rolling, debian:trixie and ubuntu:24.04
# containers (package.yml); it must never run on a real install, because it
# deletes Agenti from the machine it runs on.
#
#   packaging/test-install.sh <dist-dir>     (agenti-runtime_*.deb and agenti_*_all.deb)
#
# Containers have no running systemd, so nothing is started; configure.sh says
# so and carries on. What is checked is everything the package itself
# promises: files, accounts, modes, the sudoers grant, units rendered (and a
# run unit never enabled), the CLI working without root, and that remove keeps
# the data while purge asks before deleting it.
set -euo pipefail

DIST="${1:-}"
[[ -d "$DIST" ]] || { echo "usage: packaging/test-install.sh <dist-dir>" >&2; exit 2; }
[[ $EUID -eq 0 ]] || { echo "must run as root (inside a throwaway container)" >&2; exit 2; }
[[ -f /.dockerenv || -n "${CI:-}" ]] || { echo "refusing: this deletes Agenti from the machine. Run it in a throwaway container." >&2; exit 2; }
DIST="$(cd "$DIST" && pwd)"
RUNTIME=$(ls "$DIST"/agenti-runtime_*_"$(dpkg --print-architecture)".deb | head -n1)
AGENTI=$(ls "$DIST"/agenti_*_all.deb | head -n1)

n=0
pass() { n=$((n + 1)); printf '  [ OK ] %s\n' "$*"; }
fail() { printf '  [FAIL] %s\n' "$*" >&2; exit 1; }
expect() { local what="$1"; shift; if "$@"; then pass "$what"; else fail "$what"; fi; }
mode() { stat -c '%a %U:%G' "$1"; }

export DEBIAN_FRONTEND=noninteractive
echo "== install ($(. /etc/os-release && echo "$PRETTY_NAME"))"
apt-get update -qq
apt-get install -y -qq --no-install-recommends "$RUNTIME" "$AGENTI" >/tmp/install.log 2>&1 \
    || { tail -40 /tmp/install.log >&2; fail "apt-get install"; }
grep -q 'sudo agenti setup' /tmp/install.log && pass "the install ends by naming the next command (sudo agenti setup)"
expect "agenti --version works without root" su -s /bin/sh nobody -c "agenti --version"
expect "the bundled agent Python imports the SDK" /usr/lib/agenti-runtime/agent/bin/python3 -c "import claude_agent_sdk"
expect "postinst fetched Claude Code from PyPI and its SHA-256 matches the pin" sh -c \
    'f=$(ls /usr/lib/agenti-runtime/agent/lib/python3.*/site-packages/claude_agent_sdk/_bundled/claude) && [ -x "$f" ] && grep -q "^sha256=$(sha256sum "$f" | cut -d" " -f1)$" /usr/lib/agenti-runtime/claude-code.pin'
expect "the package itself does not ship Claude Code" sh -c '! dpkg -L agenti-runtime | grep -q "_bundled/claude$"'
expect "the bundled API Python imports FastAPI" /usr/lib/agenti-runtime/api/bin/python3 -c "import fastapi, uvicorn"
expect "authd's Python has cryptography and NOT FastAPI" sh -c \
    '/usr/lib/agenti-runtime/authd/bin/python3 -c "import cryptography" && ! /usr/lib/agenti-runtime/authd/bin/python3 -c "import fastapi" 2>/dev/null'
expect "the help pages work without root" su -s /bin/sh nobody -c "agenti docs search passkey >/dev/null"
expect "the shipped agents are listed without root" sh -c "su -s /bin/sh nobody -c 'agenti agents --json' | grep -q '\"enum\"'"
for u in agenti-run agenti-api agenti-authd; do expect "account $u exists" id "$u"; done
expect "the user database is 0640 root:agenti-authd" test "$(mode /var/lib/agenti/iam.db)" = "640 root:agenti-authd"
expect "authd's session folder is 0700 agenti-authd" test "$(mode /var/lib/agenti/authd)" = "700 agenti-authd:agenti-authd"
expect "the data root is 0751 root:root" test "$(mode /var/lib/agenti/data)" = "751 root:root"
expect "the organisation folder exists" test -d /var/lib/agenti/data/org/teams
expect "the sudoers grant is installed, 0440, and parses" sh -c \
    'test "$(stat -c %a /etc/sudoers.d/agenti-api)" = 440 && visudo -c -q -f /etc/sudoers.d/agenti-api'
expect "the API account cannot read the user database" sh -c '! su -s /bin/sh agenti-api -c "cat /var/lib/agenti/iam.db" >/dev/null 2>&1'
expect "no service account can write the code" sh -c \
    'for u in agenti-run agenti-api agenti-authd; do su -s /bin/sh $u -c "touch /usr/lib/agenti/x" 2>/dev/null && exit 1; done; exit 0'
expect "each shipped agent has a run unit" sh -c \
    'for a in enum research trafficmon; do test -f /etc/systemd/system/agenti-$a-instance@.service || exit 1; done'
expect "vault off: the run units do not assert a mount" sh -c '! grep -q AssertPathIsMountPoint /etc/systemd/system/agenti-enum-instance@.service'
expect "the run units point at the bundled Python and the code folder" \
    grep -q '^ExecStart=/usr/lib/agenti-runtime/agent/bin/python3 /usr/lib/agenti/agents/enum/enum-agent.py$' /etc/systemd/system/agenti-enum-instance@.service
expect "no run unit is enabled" sh -c '! ls /etc/systemd/system/*.wants/ 2>/dev/null | grep -q instance'
expect "the GUI and retention units are rendered" test -f /etc/systemd/system/agenti-api.service -a -f /etc/systemd/system/agenti-retention.timer
expect "the GUI settings default to this machine only" grep -qx 'BIND_HOST=127.0.0.1' /etc/agenti/api.conf
expect "the API account cannot run the CLI directly, only the bridge" sh -c \
    '! su -s /bin/sh agenti-api -c "sudo -n /usr/bin/agenti agents" >/dev/null 2>&1'
expect "the bridge refuses a console-only verb for the API account" sh -c \
    'printf "%s\n" "{\"argv\":[\"vault\",\"status\"]}" | su -s /bin/sh agenti-api -c "sudo -n /usr/lib/agenti/api_bridge.py" 2>&1 | grep -q REFUSING'

expect "the code is precompiled (root never has to write a cache at run time)" \
    sh -c 'ls /usr/lib/agenti/__pycache__/iam.*.pyc >/dev/null'

echo "== upgrade (the same version again: every step must be idempotent)"
echo "kept" > /var/lib/agenti/data/org/marker
dpkg -i "$AGENTI" >/tmp/upgrade.log 2>&1 || { tail -30 /tmp/upgrade.log >&2; fail "dpkg -i (upgrade)"; }
expect "data survives an upgrade" grep -qx kept /var/lib/agenti/data/org/marker
expect "the user database is untouched" test "$(mode /var/lib/agenti/iam.db)" = "640 root:agenti-authd"

echo "== remove"
apt-get remove -y -qq agenti >/dev/null
expect "units are gone" sh -c '! ls /etc/systemd/system/agenti-* >/dev/null 2>&1'
expect "the sudoers grant is gone" test ! -e /etc/sudoers.d/agenti-api
expect "settings and data stay" test -f /etc/agenti/api.conf -a -f /var/lib/agenti/data/org/marker

echo "== purge, answering No (the default, and what automation gets)"
apt-get purge -y -qq agenti >/tmp/purge.log 2>&1
expect "settings are gone" test ! -e /etc/agenti
expect "the data is KEPT" test -f /var/lib/agenti/data/org/marker -a -f /var/lib/agenti/iam.db
expect "the accounts are kept (they own that data)" id agenti-run
expect "purge says how to delete the data by hand" grep -q 'sudo rm -rf /var/lib/agenti' /tmp/purge.log

echo "== purge, answering Yes"
apt-get install -y -qq --no-install-recommends "$AGENTI" >/dev/null
echo "agenti agenti/purge-data boolean true" | debconf-set-selections
apt-get purge -y -qq agenti >/dev/null
expect "all data is gone" test ! -e /var/lib/agenti
expect "the accounts are gone" sh -c '! id agenti-run 2>/dev/null && ! id agenti-api 2>/dev/null && ! id agenti-authd 2>/dev/null'
expect "nothing is left under /usr/lib/agenti (no stray bytecode either)" test ! -e /usr/lib/agenti
apt-get purge -y -qq agenti-runtime >/dev/null
expect "purging agenti-runtime removes the fetched Claude Code too (nothing left)" test ! -e /usr/lib/agenti-runtime

echo; echo "$n checks passed"
