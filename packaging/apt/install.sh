#!/bin/sh
# Agenti installer: adds Agenti's apt repository and installs Agenti.
#
#   curl -fsSL https://apt.agenti-foss.org/install.sh | sudo sh
#
# What it does, all of which can be done by hand (docs/help/installing.md):
#   1. downloads the release key and refuses it unless its fingerprint is
#      2D6F 55F9 385B 8C76 0C2E 95BD 8111 66F5 1B2D AE49;
#   2. saves it as /usr/share/keyrings/agenti-archive-keyring.asc;
#   3. adds /etc/apt/sources.list.d/agenti.sources, trusted ONLY with that key;
#   4. apt-get update, then apt-get install agenti (apt picks amd64 or arm64).
# Set AGENTI_NO_INSTALL=1 to stop after step 3.
set -eu

FPR=2D6F55F9385B8C760C2E95BD811166F51B2DAE49
BASE=https://apt.agenti-foss.org
KEYRING=/usr/share/keyrings/agenti-archive-keyring.asc
SOURCES=/etc/apt/sources.list.d/agenti.sources

die() { echo "agenti install: $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run it as root: curl -fsSL $BASE/install.sh | sudo sh"
command -v apt-get >/dev/null || die "this installer needs apt (Kali or Debian)."
arch=$(dpkg --print-architecture)
case "$arch" in
    amd64|arm64) ;;
    *) die "no Agenti packages for '$arch' yet (amd64 and arm64 only)." ;;
esac

missing=""
command -v curl >/dev/null || missing="$missing curl"
command -v gpg >/dev/null || missing="$missing gpg"
if [ -n "$missing" ]; then
    echo "Installing what the installer needs:$missing"
    apt-get update -q && apt-get install -y -q $missing \
        || die "could not install$missing. Install them yourself (sudo apt install$missing) and run this again."
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -m 0700 "$tmp/gnupg"; GNUPGHOME="$tmp/gnupg"; export GNUPGHOME
# A wrong clock is the usual cause of both a "certificate is not yet valid"
# download and a "not live until" package list (a restored VM, a dual-boot PC).
clock_die() {
    grep -q -i -e "not live until" -e "not yet valid" -e "not valid yet" -e "certificate has expired" "$1" \
        && die "this machine's clock is wrong (it reads $(date -u '+%Y-%m-%d %H:%M UTC')). Fix it: sudo timedatectl set-ntp true  (check: date -u), then run this again."
    return 0
}
if ! curl -fsSL "$BASE/agenti-release-key.asc" -o "$tmp/key.asc" 2>"$tmp/curl.log"; then
    cat "$tmp/curl.log" >&2; clock_die "$tmp/curl.log"
    die "could not download $BASE/agenti-release-key.asc. Check the network and try again."
fi
got=$(gpg --show-keys --with-colons "$tmp/key.asc" 2>/dev/null | awk -F: '/^fpr/{print $10; exit}')
[ "$got" = "$FPR" ] || die "the downloaded key's fingerprint is '${got:-unreadable}', not $FPR. Not trusting it; nothing was changed."

install -m 0644 "$tmp/key.asc" "$KEYRING"
cat > "$SOURCES" <<EOF
Types: deb
URIs: $BASE
Suites: stable
Components: main
Signed-By: $KEYRING
EOF
echo "Added Agenti's apt repository ($SOURCES), trusted only with key $FPR."

[ "${AGENTI_NO_INSTALL:-0}" = 1 ] && { echo "AGENTI_NO_INSTALL=1: stopping here. Install with: sudo apt install agenti"; exit 0; }
if ! apt-get update -q >"$tmp/update.log" 2>&1; then
    cat "$tmp/update.log" >&2; clock_die "$tmp/update.log"
    die "apt-get update failed; see the messages above. The repository stays configured: fix the cause, then: sudo apt update && sudo apt install agenti"
fi
cat "$tmp/update.log"
apt-get install -y agenti || die "installing agenti failed; see the messages above. Try again with: sudo apt install agenti"
echo
echo "Agenti is installed. Updates arrive with the usual: sudo apt update && sudo apt upgrade"
