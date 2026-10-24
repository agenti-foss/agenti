#!/usr/bin/env bash
#
# build-runtime.sh — build agenti-runtime_<version>_<arch>.deb: a standalone
# CPython and the three hash-pinned Python environments Agenti runs on.
#
#   packaging/build-runtime.sh <out-dir> [--cache <dir>] [--keep]
#
# Builds for THIS machine's CPU type (amd64 or arm64); CI runs it once on each.
# Needs curl, sha256sum, tar, dpkg-deb and network access to GitHub and PyPI.
# No root: the tree is assembled in a temporary folder and packed with
# --root-owner-group. --keep leaves that folder in place and prints its path.
#
# WHAT GOES IN, AND WHERE (all under /usr/lib/agenti-runtime):
#   python/   CPython from python-build-standalone, pinned with its SHA-256 in
#             runtime/python.pin. Independent of the distribution's python3, so
#             a Kali Python upgrade can never break Agenti.
#   agent/    the Claude Agent SDK (every agent run and its preflight)
#   api/      FastAPI + uvicorn (agenti-api.service)
#   authd/    cryptography only (agenti-authd.service), kept apart on purpose
# Each environment installs exactly its runtime/<env>.lock: pip
# --require-hashes --no-deps --only-binary :all:, so nothing but the reviewed
# wheels is installed and nothing is compiled.
#
# WHY THE PATH REWRITE: a venv records absolute paths (pyvenv.cfg, its python
# symlinks, script shebangs). They are built in the temporary folder, checked
# there, then rewritten to /usr/lib/agenti-runtime; the build fails if any
# text file still names the temporary folder.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RT="$HERE/runtime"
DEST=/usr/lib/agenti-runtime

die()  { printf '\nerror: %s\n' "$*" >&2; exit 1; }
step() { printf '\n==> %s\n' "$*"; }
ok()   { printf '  [ OK ] %s\n' "$*"; }

usage() {
    cat <<USAGE
usage: packaging/build-runtime.sh <out-dir> [--cache <dir>] [--keep]

Builds agenti-runtime_<version>_<arch>.deb for this machine's CPU type into
<out-dir>. --cache keeps downloads between builds (default
\${XDG_CACHE_HOME:-~/.cache}/agenti-build); --keep leaves the build folder.
USAGE
}

OUT="" CACHE="${XDG_CACHE_HOME:-$HOME/.cache}/agenti-build" KEEP=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help) usage; exit 0 ;;
        --cache)   [[ $# -ge 2 ]] || die "--cache needs a folder"; CACHE="$2"; shift 2 ;;
        --cache=*) CACHE="${1#*=}"; shift ;;
        --keep)    KEEP=1; shift ;;
        -*)        usage >&2; die "unknown option $1" ;;
        *)         [[ -z "$OUT" ]] || die "one output folder only (got '$OUT' and '$1')"; OUT="$1"; shift ;;
    esac
done
[[ -n "$OUT" ]] || { usage >&2; die "give an output folder, e.g. packaging/build-runtime.sh dist/"; }
for t in curl sha256sum tar dpkg-deb dpkg realpath; do
    command -v "$t" >/dev/null || die "$t is not installed (sudo apt install curl coreutils tar dpkg)"
done

# shellcheck source=package.conf
source "$HERE/package.conf"
VERSION=$(tr -d ' \n' < "$RT/VERSION")
ARCH=$(dpkg --print-architecture)
PYVER=$(sed -n 's/^PYTHON_VERSION=//p' "$RT/python.pin")
RELEASE=$(sed -n 's/^RELEASE=//p' "$RT/python.pin")
read -r _ PYFILE PYSHA < <(awk -v a="$ARCH" '$1 == a' "$RT/python.pin") \
    || die "runtime/python.pin has no line for '$ARCH' (supported: $(awk 'NF==3{printf "%s ", $1}' "$RT/python.pin"))"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "runtime/VERSION '$VERSION' is not X.Y.Z"

export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$HERE" log -1 --format=%ct 2>/dev/null || date +%s)}"
# Nothing from the builder's own pip settings may change what is installed.
export PIP_CONFIG_FILE=/dev/null PIP_DISABLE_PIP_VERSION_CHECK=1 PYTHONDONTWRITEBYTECODE=1
unset PYTHONPATH PYTHONHOME

mkdir -p "$OUT" "$CACHE"
OUT="$(cd "$OUT" && pwd)"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/agenti-runtime.XXXXXX")
cleanup() {
    if [[ $KEEP -eq 1 ]]; then printf '\nbuild folder kept: %s\n' "$WORK"
    else rm -rf "${WORK:?}"; fi
}
trap cleanup EXIT
ROOT="$WORK/root"
R="$ROOT$DEST"

step "agenti-runtime $VERSION for $ARCH (CPython $PYVER)"

# --- 1. CPython ------------------------------------------------------------
tarball="$CACHE/$PYFILE"
if [[ ! -f "$tarball" ]]; then
    url="https://github.com/astral-sh/python-build-standalone/releases/download/$RELEASE/${PYFILE//+/%2B}"
    curl -fsSL --retry 3 -o "$tarball.part" "$url" || die "could not download $url"
    mv "$tarball.part" "$tarball"
fi
# Checked every time, cached or not.
if ! echo "$PYSHA  $tarball" | sha256sum -c --quiet -; then
    rm -f "${tarball:?}"
    die "$PYFILE does not match the SHA-256 in runtime/python.pin — deleted; nothing was built"
fi
ok "CPython $PYVER ($PYFILE, SHA-256 checked)"
mkdir -p "$R"
tar -xzf "$tarball" -C "$R"
PY="$R/python/bin/python3"
"$PY" -c "import sys; v='.'.join(map(str, sys.version_info[:3])); assert v == '$PYVER', v" \
    || die "the unpacked Python is not $PYVER"

# --- 2. the three environments --------------------------------------------
declare -A CHECK=(
    [agent]="import claude_agent_sdk, msgpack"
    [api]="import fastapi, uvicorn"
    [authd]="from cryptography.hazmat.primitives.asymmetric import ec; from cryptography.hazmat.primitives import hashes"
)
for env in agent api authd; do
    lock="$RT/$env.lock"
    [[ -f "$lock" ]] || die "missing $lock (generate it: packaging/runtime/lock.sh $env)"
    "$PY" -m venv --without-pip "$R/$env"
    "$PY" -m pip --python "$R/$env/bin/python3" install --quiet --require-hashes --no-deps \
        --only-binary :all: --no-compile --cache-dir "$CACHE/pip" -r "$lock" \
        || die "pip refused $env.lock (a hash mismatch, a wheel missing for $ARCH, or no network). Nothing was built."
    "$R/$env/bin/python3" -c "${CHECK[$env]}" || die "$env: the installed libraries do not import"
    ok "$env: $(grep -cE '^[a-z0-9]' "$lock") pinned packages, imports checked"
done
"$R/agent/bin/python3" - <<'PY' || die "the Agent SDK's bundled Claude Code program is missing or does not run"
import pathlib, subprocess, claude_agent_sdk
exe = pathlib.Path(claude_agent_sdk.__file__).parent / "_bundled" / "claude"
subprocess.run([str(exe), "--version"], check=True, capture_output=True, timeout=60)
PY
ok "agent: the SDK's bundled Claude Code program runs"

# --- 2b. Claude Code is fetched at install, never redistributed -------------
# The SDK is MIT; the claude program inside its wheel is Anthropic's, under
# Anthropic's own terms. The package keeps only a pin (the exact PyPI wheel,
# its SHA-256 and the program's SHA-256); postinst runs fetch-claude-code.
sdk_req=$(awk '/^claude-agent-sdk==/{p=1} p{print; if ($0 !~ /\\$/) exit}' "$RT/agent.lock")
[[ -n "$sdk_req" ]] || die "agent.lock pins no claude-agent-sdk"
mkdir -p "$WORK/sdk"
printf '%s\n' "$sdk_req" > "$WORK/sdk/req.txt"
"$PY" -m pip download --quiet --require-hashes --no-deps --only-binary :all: \
    --cache-dir "$CACHE/pip" -d "$WORK/sdk" -r "$WORK/sdk/req.txt" \
    || die "could not download the claude-agent-sdk wheel for $ARCH"
whl=$(ls "$WORK"/sdk/claude_agent_sdk-*.whl)
"$PY" - "$whl" "$R" "$ROOT" <<'PY' > "$R/claude-code.pin" || die "could not pin Claude Code"
import hashlib, json, pathlib, sys, urllib.request
whl, r, root = map(pathlib.Path, sys.argv[1:])
name, ver = "claude-agent-sdk", whl.name.split("-")[1]
meta = json.load(urllib.request.urlopen(f"https://pypi.org/pypi/{name}/{ver}/json", timeout=60))
wheel_sha = hashlib.sha256(whl.read_bytes()).hexdigest()
url = next(u["url"] for u in meta["urls"] if u["filename"] == whl.name and u["digests"]["sha256"] == wheel_sha)
exe = next(r.glob("agent/lib/python3.*/site-packages/claude_agent_sdk/_bundled/claude"))
print(f"url={url}\nwheel_sha256={wheel_sha}\nmember=claude_agent_sdk/_bundled/claude")
print(f"sha256={hashlib.sha256(exe.read_bytes()).hexdigest()}\ndest={exe.relative_to(r)}")
PY
exe=$(ls "$R"/agent/lib/python3.*/site-packages/claude_agent_sdk/_bundled/claude)
grep -q "^sha256=$(sha256sum "$exe" | cut -d' ' -f1)$" "$R/claude-code.pin" || die "the pinned program is not the one installed"
rm -f "${exe:?}"
install -m 0755 "$RT/fetch-claude-code" "$R/fetch-claude-code"
ok "Claude Code pinned (claude-code.pin), not shipped: postinst fetches it from PyPI"

# --- 3. trim what a server never uses -------------------------------------
pylib="$R/python/lib/python${PYVER%.*}"
for d in test idlelib turtledemo tkinter ensurepip; do rm -rf "${pylib:?}/$d"; done
find "${pylib:?}/site-packages" -maxdepth 1 -name 'pip*' -exec rm -rf {} +
find "${R:?}/python/bin" -maxdepth 1 \( -name 'pip*' -o -name 'idle*' \) -delete
rm -rf "${R:?}/python/share"
# Tk/Tcl (no windows on a server) and Python's build configuration and
# *-config scripts (for compiling C extensions; nothing is compiled here).
rm -rf "${R:?}"/python/lib/{tcl9,tcl9.0,tk9.0,itcl4.3.8,thread3.0.6} "${R:?}"/python/lib/libtcl9*.so \
       "${pylib:?}"/config-"${PYVER%.*}"-*
find "${pylib:?}/lib-dynload" -name '_tkinter*' -delete
find "${R:?}/python/bin" -maxdepth 1 \( -name '*-config' -o -name 'pydoc*' \) -delete
rm -rf "${R:?}/python/include"
# The launchers pip writes (uvicorn, fastapi, mcp, ...): Agenti runs
# `python3 -m <module>`, never these. And no VCS files in a package.
for env in agent api authd; do
    for f in "$R/$env/bin/"*; do
        if [[ -f "$f" && ! -L "$f" ]] && [[ "$(head -c2 "$f")" == '#!' ]]; then rm -f "${f:?}"; fi
    done
done
find "${R:?}" -name .gitignore -delete
find "${R:?}" -name __pycache__ -type d -prune -exec rm -rf {} +
for env in agent api authd; do
    "$R/$env/bin/python3" -c "${CHECK[$env]}" || die "$env: the libraries no longer import after trimming"
done
ok "trimmed (Tk, build configuration, pip's launchers); imports checked again"

# --- 4. rewrite the build folder's paths to /usr/lib/agenti-runtime --------
for env in agent api authd; do
    sed -i "s#$R#$DEST#g" "$R/$env/pyvenv.cfg"
    for f in "$R/$env/bin/"*; do
        if [[ -L "$f" ]]; then
            t=$(readlink "$f")
            [[ "$t" == "$R"/* ]] && ln -sfn "$(realpath --relative-to="$(dirname "$f")" -m "$t")" "$f"
        elif grep -qIF "$R" "$f" 2>/dev/null; then
            sed -i "s#$R#$DEST#g" "$f"
        fi
    done
done
left=$(grep -rlIF "$WORK" "$R" 2>/dev/null || true)
[[ -z "$left" ]] || die "these files still name the build folder:
$left"
ok "paths rewritten to $DEST"

# --- 5. bytecode, compiled once with the installed paths -------------------
"$PY" -m compileall -q -j0 -s "$ROOT" -p / --invalidation-mode checked-hash "$R" >/dev/null \
    || die "compileall failed (see above)"
ok "bytecode compiled (checked-hash, so file times do not matter)"

# --- 6. what is inside, for agenti verify and for people --------------------
"$PY" - "$R" "$VERSION" "$ARCH" "$PYVER" "$RELEASE" "$RT" <<'PY'
import hashlib, json, pathlib, re, sys
r, version, arch, pyver, release, rt = sys.argv[1:]
envs = {}
for env in ("agent", "api", "authd"):
    lock = pathlib.Path(rt, f"{env}.lock").read_bytes()
    pkgs = re.findall(rb"^([a-z0-9][a-z0-9._-]*)==([^ ;\\\n]+)", lock, re.M)
    envs[env] = {"lock_sha256": hashlib.sha256(lock).hexdigest(),
                 "packages": {k.decode(): v.decode() for k, v in pkgs}}
info = {"package": "agenti-runtime", "version": version, "arch": arch,
        "python": pyver, "python_build": release, "environments": envs}
pathlib.Path(r, "BUILD-INFO.json").write_text(json.dumps(info, indent=2) + "\n")
PY

# --- 7. the package ---------------------------------------------------------
# The highest glibc symbol version any bundled program needs is the Depends.
glibc="2.17"
if command -v objdump >/dev/null; then
    glibc=$(find "$R" -type f \( -name '*.so*' -o -perm -u+x \) -print0 \
        | xargs -0 objdump -T 2>/dev/null | grep -o 'GLIBC_[0-9.]*' | sed 's/GLIBC_//' \
        | sort -uV | tail -1 || true)
    [[ -n "$glibc" ]] || glibc="2.17"
fi
# Debian's copyright and changelog. Everything inside is someone else's
# software, unmodified; each part's licence ships with it.
doc="$ROOT/usr/share/doc/agenti-runtime"
install -d "$doc"
cat > "$doc/copyright" <<'COPYRIGHT'
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: agenti-runtime
Comment: Agenti's bundled Python. It contains third-party software, unmodified;
 each part keeps its own licence, shipped beside it. The exact versions are in
 /usr/lib/agenti-runtime/BUILD-INFO.json.

Files: usr/lib/agenti-runtime/python/*
Copyright: Python Software Foundation; the CPython and python-build-standalone contributors
License: PSF-2.0
 The full text, with the licences of the libraries built into this Python
 (OpenSSL, SQLite, zlib, bzip2, expat, xz, zstd, libffi, ncurses and others), is
 /usr/lib/agenti-runtime/python/lib/python3.*/LICENSE.txt.

Files: usr/lib/agenti-runtime/agent/* usr/lib/agenti-runtime/api/* usr/lib/agenti-runtime/authd/*
Copyright: the authors of each Python package
License: various
 Each package's licence is in its *.dist-info folder under
 /usr/lib/agenti-runtime/<env>/lib/python3.*/site-packages/. The Claude Agent SDK
 (MIT) needs Anthropic's Claude Code program, which is under Anthropic's own
 terms and is NOT in this package: fetch-claude-code downloads it from PyPI at
 install, checked against the SHA-256s in claude-code.pin.

Files: usr/lib/agenti-runtime/BUILD-INFO.json
Copyright: 2026 Agenti contributors
License: AGPL-3.0-only
COPYRIGHT
{
    printf 'agenti-runtime (%s) unstable; urgency=medium\n\n' "$VERSION"
    printf '  * CPython %s (python-build-standalone %s); pinned libraries: BUILD-INFO.json.\n\n' "$PYVER" "$RELEASE"
    printf ' -- %s  %s\n' "$MAINTAINER" "$(date -u -R -d "@$SOURCE_DATE_EPOCH")"
} | gzip -9n > "$doc/changelog.gz"

# lintian: what is kept as published, on purpose.
install -d "$ROOT/usr/share/lintian/overrides"
cat > "$ROOT/usr/share/lintian/overrides/agenti-runtime" <<'OVERRIDES'
# The bundled builds (python-build-standalone's CPython, the PyPI wheels) are
# shipped exactly as published, so each can be checked against the hash it is
# pinned by (packaging/runtime/).
agenti-runtime: unstripped-binary-or-object [usr/lib/agenti-runtime/*]
agenti-runtime: hardening-no-pie [usr/lib/agenti-runtime/*]
agenti-runtime: hardening-no-relro [usr/lib/agenti-runtime/*]
# CPython's own standard library file.
agenti-runtime: unusual-interpreter python [usr/lib/agenti-runtime/python/lib/python3.*/encodings/rot_13.py]
# Bytecode is compiled once at build (checked-hash), so nothing is written
# under /usr at install and dpkg removes every file on purge.
agenti-runtime: package-installs-python-pycache-dir [usr/lib/agenti-runtime/*]
# Bundling is the decision (docs/packaging.md): these libraries are copies
# inside the bundled programs, patched by rebuilding agenti-runtime, not by
# the distribution's security updates ("Keeping the runtime patched").
agenti-runtime: embedded-library * [usr/lib/agenti-runtime/*]
OVERRIDES
chmod -R u+rwX,go+rX,go-w "$ROOT"
find "$ROOT/usr/lib/agenti-runtime" -type f -name '*.so*' -exec chmod 0644 {} +
find "$ROOT" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
mkdir -p "$ROOT/DEBIAN"
size=$(du -sk "$ROOT/usr" | cut -f1)
cat > "$ROOT/DEBIAN/control" <<CONTROL
Package: agenti-runtime
Version: $VERSION
Architecture: $ARCH
Maintainer: $MAINTAINER
Installed-Size: $size
Depends: libc6 (>= $glibc), curl, ca-certificates
Section: admin
Priority: optional
Homepage: $HOMEPAGE
Description: Python runtime for Agenti
 A standalone CPython $PYVER and the three hash-pinned Python environments
 Agenti runs on: agent runs (the Claude Agent SDK), the web API (FastAPI) and
 the auth service (cryptography only). Kept in its own package so routine
 Agenti updates stay small. Installing downloads one file: Anthropic's Claude
 Code program, from PyPI, hash-checked (it is not redistributed here).
CONTROL
for s in postinst prerm; do install -m 0755 "$RT/debian/$s" "$ROOT/DEBIAN/$s"; done
(cd "$ROOT" && find usr -type f -print0 | sort -z | xargs -0 md5sum > DEBIAN/md5sums)
deb="$OUT/agenti-runtime_${VERSION}_${ARCH}.deb"
dpkg-deb --root-owner-group -Zxz --build "$ROOT" "$deb" >/dev/null
ok "$(basename "$deb")  $(du -h "$deb" | cut -f1) download, $((size / 1024)) MB installed, needs glibc >= $glibc"
