#!/usr/bin/env bash
# image-digests.sh — the current multi-arch digest of each container image the
# package workflow tests in. The workflow pins images by digest (code in an
# image runs where the run's artifact credential is); refresh the pins with
# this, review the change, and commit it. Reads Docker Hub only.
set -euo pipefail
for img in library/debian:trixie kalilinux/kali-rolling:latest library/ubuntu:24.04; do
    repo=${img%%:*}; tag=${img##*:}
    tok=$(curl -fsS "https://auth.docker.io/token?service=registry.docker.io&scope=repository:$repo:pull" \
          | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')
    digest=$(curl -fsSI -H "Authorization: Bearer $tok" \
             -H "Accept: application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json" \
             "https://registry-1.docker.io/v2/$repo/manifests/$tag" | tr -d '\r' | sed -n 's/^docker-content-digest: //Ip')
    printf '%-28s %s\n' "${repo#library/}:$tag" "$digest"
done
