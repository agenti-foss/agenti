#!/usr/bin/env bash
#
# lock.sh — regenerate the hash-pinned lock files for agenti-runtime.
#
#   packaging/runtime/lock.sh            re-resolve every environment (newest versions)
#   packaging/runtime/lock.sh authd      just one
#
# Needs uv (https://docs.astral.sh/uv/): `pipx install uv` or `pip install uv` in
# a scratch venv, or point UV= at it. Each lock pins every package to one version
# and lists the SHA-256 of every wheel of that version, for every CPU type, so
# build-runtime.sh installs exactly these bytes and nothing else (pip
# --require-hashes). Wheels only: no package is ever built from source.
#
# A lock change is a reviewed change: read the diff (what moved, and why), run
# pip-audit on it (security.yml does weekly), bump packaging/runtime/VERSION.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UV="${UV:-uv}"
PYVER=$(sed -n 's/^PYTHON_VERSION=//p' "$HERE/python.pin")
command -v "$UV" >/dev/null || { echo "error: uv not found. Install it (pip install uv) or set UV=/path/to/uv" >&2; exit 1; }
[[ -n "$PYVER" ]] || { echo "error: PYTHON_VERSION missing from $HERE/python.pin" >&2; exit 1; }

envs=("$@"); [[ ${#envs[@]} -gt 0 ]] || envs=(agent api authd)
for e in "${envs[@]}"; do
    [[ -f "$HERE/$e.in" ]] || { echo "error: no $HERE/$e.in (environments: agent api authd)" >&2; exit 1; }
    "$UV" pip compile "$HERE/$e.in" --universal --python-version "${PYVER%.*}" \
        --only-binary :all: --generate-hashes --quiet \
        --custom-compile-command "packaging/runtime/lock.sh $e" -o "$HERE/$e.lock"
    echo "locked $e: $(grep -cE '^[a-z0-9]' "$HERE/$e.lock") packages -> $HERE/$e.lock"
done
