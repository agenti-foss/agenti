#!/usr/bin/env bash
# deb-digest.sh <dist-dir> — the one .deb a build job made, as GitHub step
# outputs: name=<file> and sha256=<digest>. release.yml signs these digests,
# reported by the job that built the file, never whatever artifacts a run holds.
set -euo pipefail
dir="${1:?usage: packaging/deb-digest.sh <dist-dir>}"
shopt -s nullglob
debs=("$dir"/*.deb)
[[ ${#debs[@]} -eq 1 ]] || { echo "expected exactly one .deb in $dir, found ${#debs[@]}" >&2; exit 1; }
name=$(basename "${debs[0]}")
[[ "$name" =~ ^[A-Za-z0-9._+~-]+\.deb$ ]] || { echo "unexpected package file name: $name" >&2; exit 1; }
printf 'name=%s\nsha256=%s\n' "$name" "$(sha256sum "${debs[0]}" | cut -d' ' -f1)"
