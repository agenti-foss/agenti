#!/usr/bin/env bash
#
# build-deb.sh — build the agenti package (and, with --edition <plugin>, that
# closed agent's own package, agenti-<plugin>: packaging/plugins/<plugin>.conf).
#
#   packaging/build-deb.sh <version> <out-dir> [--edition open|<plugin>]
#
#   <version>   X.Y.Z for a release (release.yml passes the tag), or "dev" for
#               a local build: shared/VERSION with "-" made "~" (so 0.1.0~dev
#               sorts before the real 0.1.0)
#
# Architecture "all": the code is Python and bash. The CPU-specific part, the
# bundled Python, is agenti-runtime (build-runtime.sh), which this Depends on.
# No root: files are placed by install-tree.sh into a temporary root and packed
# with --root-owner-group. No debhelper on purpose: dh_installsystemd would
# enable units, and an agent's run unit is never enabled; the maintainer
# scripts in packaging/debian/ call configure.sh instead.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(dirname "$HERE")"
die() { printf '\nerror: %s\n' "$*" >&2; exit 1; }
ok()  { printf '  [ OK ] %s\n' "$*"; }

VERSION="${1:-}"; OUT="${2:-}"; EDITION=open
[[ -n "$VERSION" && -n "$OUT" ]] || die "usage: packaging/build-deb.sh <X.Y.Z | dev> <out-dir> [--edition open|<plugin>]"
shift 2
while [[ $# -gt 0 ]]; do
    case "$1" in
        --edition) [[ $# -ge 2 ]] || die "--edition needs open or a plugin name"; EDITION="$2"; shift 2 ;;
        --edition=*) EDITION="${1#*=}"; shift ;;
        *) die "unknown option $1" ;;
    esac
done
[[ "$EDITION" == open || -f "$HERE/plugins/$EDITION.conf" ]] \
    || die "--edition must be open or a plugin with packaging/plugins/<plugin>.conf, not '$EDITION'"
if [[ "$VERSION" == dev ]]; then
    VERSION=$(tr -d ' \n' < "$REPO/shared/VERSION"); VERSION="${VERSION//-/\~}"
fi
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(~[a-z0-9.]+)?$ ]] || die "'$VERSION' is not a version like 1.2.3 (or 1.2.3~dev)"
for t in dpkg-deb gzip md5sum python3; do command -v "$t" >/dev/null || die "$t is not installed"; done

# shellcheck source=package.conf
source "$HERE/package.conf"
RUNTIME_VERSION=$(tr -d ' \n' < "$HERE/runtime/VERSION")
RUNTIME_MAJOR="${RUNTIME_VERSION%%.*}"
PLUGIN_API=$(tr -d ' \n' < "$REPO/shared/PLUGIN_API_VERSION")
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$REPO" log -1 --format=%ct 2>/dev/null || date +%s)}"

mkdir -p "$OUT"; OUT="$(cd "$OUT" && pwd)"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/agenti-deb.XXXXXX")
trap 'rm -rf "${WORK:?}"' EXIT
ROOT="$WORK/root"

# Each agent's apt needs (<agent>-agent/<agent>.deps) become Recommends: apt
# installs them by default, and a name a distribution lacks never blocks the
# install.
recommends_of() {
    local a f out=()
    for a in "$@"; do
        f="$REPO/$a-agent/$a.deps"
        [[ -f "$f" ]] || continue
        while IFS= read -r line; do
            line="${line%%#*}"; line="${line//[[:space:]]/}"
            [[ -n "$line" ]] && out+=("$line")
        done < "$f"
    done
    printf '%s\n' "${out[@]}" | awk 'NF && !seen[$0]++' | paste -sd, - | sed 's/,/, /g'
}

if [[ "$EDITION" == open ]]; then
    PKG=agenti
    "$HERE/install-tree.sh" "$REPO" "$ROOT" >/dev/null
    # A broken sudoers file breaks sudo for the whole machine; configure.sh
    # checks it again before installing it, but it must never ship broken.
    if command -v visudo >/dev/null; then
        visudo -c -q -f "$ROOT/usr/lib/agenti/agenti-api.sudoers" || die "agenti-api.sudoers does not parse"
    fi
    DEPENDS="agenti-runtime (>= $RUNTIME_VERSION), agenti-runtime (<< $((RUNTIME_MAJOR + 1))), python3 (>= 3.11), systemd, sudo, bubblewrap, libseccomp2, openssl, e2fsprogs, iproute2, curl, debconf (>= 0.5) | debconf-2.0"
    RECOMMENDS="cryptsetup, $(recommends_of enum research trafficmon)"
    RELATIONS="Provides: agenti-plugin-api-$PLUGIN_API"
    DESCRIPTION="Self-hosted, agentic security testing for one team
 Agenti runs Claude-based agents for network enumeration, OSINT research,
 traffic monitoring and file analysis against an engagement's approved scope
 only. Scope, tool allow-lists and approvals live in root-owned files the
 agents cannot change; every decision is logged; each run is isolated by its
 own systemd unit. A web GUI and a CLI (agenti) drive it.
 .
 After installing, run: sudo agenti setup"
    SCRIPTS=(postinst prerm postrm config templates)
else
    PKG=agenti-$EDITION
    "$HERE/install-tree.sh" "$REPO" "$ROOT" --edition "$EDITION" >/dev/null
    PLUGIN_AGENTS=(); PLUGIN_SUMMARY=""; PLUGIN_DESCRIPTION=""
    # shellcheck source=/dev/null
    source "$HERE/plugins/$EDITION.conf"
    [[ -n "$PLUGIN_SUMMARY" && -n "$PLUGIN_DESCRIPTION" ]] || die "packaging/plugins/$EDITION.conf needs PLUGIN_SUMMARY and PLUGIN_DESCRIPTION"
    [[ -d "$HERE/debian/$PKG" ]] || die "packaging/debian/$PKG/ (its maintainer scripts) is missing"
    DEPENDS="agenti-plugin-api-$PLUGIN_API, agenti (>= ${VERSION%%~*}~)"
    RECOMMENDS="$(recommends_of "${PLUGIN_AGENTS[@]}")"
    RELATIONS=""
    DESCRIPTION="$PLUGIN_SUMMARY
$PLUGIN_DESCRIPTION"
    SCRIPTS=(postinst postrm)
    install -d -m 0755 "$ROOT/usr/share/doc/$PKG"
    cat > "$ROOT/usr/share/doc/$PKG/copyright" <<EOF
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: $PKG

Files: *
Copyright: 2026 Agenti contributors
License: proprietary
 Licensed to the customer named in their agreement. Not for redistribution.
EOF
fi

# The changelog Debian expects in every package's doc folder.
doc="$ROOT/usr/share/doc/$PKG"
install -d -m 0755 "$doc"
{
    printf '%s (%s) unstable; urgency=medium\n\n' "$PKG" "$VERSION"
    printf '  * Release %s. Notes: https://github.com/agenti-foss/agenti/releases\n\n' "$VERSION"
    printf ' -- %s  %s\n' "$MAINTAINER" "$(date -u -R -d "@$SOURCE_DATE_EPOCH")"
} | gzip -9n > "$doc/changelog.gz"
chmod 0644 "$doc/changelog.gz"

# lintian: deliberate, with the reason.
if [[ $PKG == agenti ]]; then
    install -d -m 0755 "$ROOT/usr/share/lintian/overrides"
    cat > "$ROOT/usr/share/lintian/overrides/agenti" <<'EOF'
# debconf asks nothing at install time (config is empty); the one question is
# asked by postrm on purge. Loading debconf in postinst would also take over
# its output, which prints the first-run instructions.
agenti: postinst-does-not-load-confmodule
EOF
    chmod 0644 "$ROOT/usr/share/lintian/overrides/agenti"
fi

install -d -m 0755 "$ROOT/DEBIAN"
for s in "${SCRIPTS[@]}"; do
    install -m "$([[ $s == templates ]] && echo 0644 || echo 0755)" "$HERE/debian/$PKG/$s" "$ROOT/DEBIAN/$s"
done
find "$ROOT" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
size=$(du -sk "$ROOT/usr" | cut -f1)
{
    echo "Package: $PKG"
    echo "Version: $VERSION"
    echo "Architecture: all"
    echo "Maintainer: $MAINTAINER"
    echo "Installed-Size: $size"
    echo "Depends: $DEPENDS"
    [[ -n "$RECOMMENDS" ]] && echo "Recommends: $RECOMMENDS"
    [[ -n "$RELATIONS" ]] && echo "$RELATIONS"
    echo "Section: admin"
    echo "Priority: optional"
    echo "Homepage: $HOMEPAGE"
    echo "Description: $DESCRIPTION"
} > "$ROOT/DEBIAN/control"
(cd "$ROOT" && find usr -type f -print0 | sort -z | xargs -0 md5sum > DEBIAN/md5sums)
chmod 0644 "$ROOT/DEBIAN/control" "$ROOT/DEBIAN/md5sums"
deb="$OUT/${PKG}_${VERSION}_all.deb"
dpkg-deb --root-owner-group -Zxz --build "$ROOT" "$deb" >/dev/null
ok "$(basename "$deb")  $(du -h "$deb" | cut -f1), $(find "$ROOT/usr" -type f | wc -l) files, $((size / 1024)) MB installed"
