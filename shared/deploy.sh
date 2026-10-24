#!/usr/bin/env bash
#
# deploy.sh — install THIS checkout on this machine, exactly the way the
# package does: the same file list (packaging/install-tree.sh), the same
# system setup (configure.sh, the package's postinst), the same checks
# (verify.sh). For developers; everyone else installs the package
# (docs/packaging.md).
#
#   sudo ./shared/deploy.sh               install the working tree, configure, verify
#   sudo ./shared/deploy.sh --verify      check only, change nothing (= sudo agenti verify)
#   sudo ./shared/deploy.sh --open-only   leave out the plugins' (agenti-<agent>) files even
#                                         when this checkout has them
#
# Installs the WORKING TREE: another session's unfinished edits ship with
# yours. Check `git status` first.
#
# Needs agenti-runtime (the bundled Python) installed:
#   packaging/build-runtime.sh dist/  &&  sudo apt install ./dist/agenti-runtime_*.deb
set -euo pipefail

HERE="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
# Root-run Python below must never import from the caller's folder (audit
# run 1 F14, run 2 for the scripts that are entry points of their own):
# PYTHONSAFEPATH drops it, and the code folder is named instead.
export PYTHONSAFEPATH=1
export PYTHONPATH="$HERE"
REPO="$(dirname "$HERE")"
# shellcheck source=paths.sh
source "$HERE/paths.sh"

ok()   { printf '  [ OK ] %s\n' "$*"; }
die()  { printf '\nERROR: %s\n' "$*" >&2; exit 1; }

open_only=0
case "${1:-}" in
    -h|--help) sed -n '3,18p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    --verify)  [[ $EUID -eq 0 ]] || die "must run as root: sudo $0 --verify"
               [[ -x "$AGENTI_LIBDIR/verify.sh" ]] || die "nothing is installed yet (no $AGENTI_LIBDIR/verify.sh). Deploy first: sudo $0"
               exec "$AGENTI_LIBDIR/verify.sh" ;;
    --open-only) open_only=1 ;;
    "") ;;
    *) die "unknown option '$1' (try --help)" ;;
esac
[[ $EUID -eq 0 ]] || die "must run as root: sudo $0"

for env in agent api authd; do
    [[ -x "$AGENTI_RUNTIME/$env/bin/python3" ]] || die "the bundled Python ($AGENTI_RUNTIME) is not installed. Build and install it once:
  packaging/build-runtime.sh dist/
  sudo apt install ./dist/agenti-runtime_*.deb"
done

stage=$(mktemp -d "${TMPDIR:-/tmp}/agenti-deploy.XXXXXX")
trap 'rm -rf "${stage:?}"' EXIT
echo "staging $REPO:"
"$REPO/packaging/install-tree.sh" "$REPO" "$stage"
if [[ $open_only -eq 0 ]]; then
    # Every closed agent whose private repo is overlaid on this checkout.
    for conf in "$REPO"/packaging/plugins/*.conf; do
        [[ -f "$conf" ]] && "$REPO/packaging/install-tree.sh" "$REPO" "$stage" --edition "$(basename "$conf" .conf)"
    done
fi

echo; echo "installing:"
# The code folder is replaced whole, so a file deleted from the checkout does
# not linger on the box as stale, importable code.
if command -v rsync >/dev/null; then
    rsync -a --delete "$stage/usr/lib/agenti/" "$AGENTI_LIBDIR/"
else
    rm -rf "${AGENTI_LIBDIR:?}"
    cp -a "$stage/usr/lib/agenti" "$AGENTI_LIBDIR"
fi
install -m 0755 "$stage/usr/bin/agenti" "$AGENTI_BIN"
mkdir -p /usr/share/doc/agenti
cp -a "$stage/usr/share/doc/agenti/." /usr/share/doc/agenti/
chown -R root:root "$AGENTI_LIBDIR" /usr/share/doc/agenti "$AGENTI_BIN"
ok "$AGENTI_LIBDIR and $AGENTI_BIN from the working tree"

first=""
[[ -f /etc/systemd/system/agenti-api.service ]] || first="--first"
"$AGENTI_LIBDIR/configure.sh" install $first

echo
"$AGENTI_LIBDIR/verify.sh" || die "deployed, but verify FAILED — see the FAIL lines above"
