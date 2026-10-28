#!/usr/bin/env bash
# repo.sh — build, sign and check Agenti's apt repository (apt.agenti-foss.org).
#
# The repository is a plain folder: pool/ holds the .debs, dists/stable/ the
# package lists. Only the open core's packages go in, and only from a GitHub
# release whose checksums AND build attestations verify. The one signature
# (InRelease) is made by the release key's signing subkey, which lives on the
# maintainer's YubiKey: `sign` is the only step a person must do by hand.
set -euo pipefail

FPR=2D6F55F9385B8C760C2E95BD811166F51B2DAE49
GH_REPO=agenti-foss/agenti
SUITE=stable
ARCHES=(amd64 arm64)
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
KEY="$HERE/agenti-release-key.asc"

usage() {
    cat <<EOF
Usage: packaging/apt/repo.sh <verb> <repo-dir> [args]

Verbs:
  add <repo-dir> <tag>   Download release <tag> from github.com/$GH_REPO,
                         verify SHA256SUMS and every .deb's build attestation,
                         add the .debs to pool/ and rebuild the package lists.
                         Leaves the repository UNSIGNED (InRelease removed).
  sign <repo-dir>        Sign the package lists with the release key. Needs the
                         YubiKey plugged in, its PIN, and a touch.
  check <repo-dir>       Verify the signature and every listed hash, then run
                         apt itself against the folder for each architecture
                         (${ARCHES[*]}) and show which agenti it would install.
  upload <repo-dir>      Run check, then publish the folder to the R2 bucket
                         behind apt.agenti-foss.org (.debs first, InRelease
                         last). Credentials: \$AGENTI_R2_ENV or
                         ~/.local/agenti-tools/secrets/r2-agenti-apt.env.

The folder is the whole repository; keep it (it is the record of what was published).
Example:
  packaging/apt/repo.sh add  ~/agenti-apt v0.1.0
  packaging/apt/repo.sh sign ~/agenti-apt
  packaging/apt/repo.sh check ~/agenti-apt
  packaging/apt/repo.sh upload ~/agenti-apt
EOF
}

die() { echo "repo.sh: $*" >&2; exit 1; }

need() { command -v "$1" >/dev/null || die "'$1' is not installed. Install it: sudo apt install $2"; }

cmd_add() {
    local repo=$1 tag=${2:-}
    [[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] \
        || die "add needs a release tag like v0.1.0 (got '${tag}'). See: packaging/apt/repo.sh --help"
    need gh gh; need dpkg-scanpackages dpkg-dev; need apt-ftparchive apt-utils
    local dl; dl=$(mktemp -d); trap 'rm -rf "$dl"; trap - RETURN' RETURN
    echo "Downloading release $tag from $GH_REPO…"
    gh release download "$tag" -R "$GH_REPO" -D "$dl" -p '*.deb' -p SHA256SUMS \
        || die "could not download release $tag. Does it exist? gh release list -R $GH_REPO"
    (cd "$dl" && sha256sum --quiet -c SHA256SUMS) \
        || die "a downloaded file does not match the release's SHA256SUMS; nothing was added"
    local deb name
    for deb in "$dl"/*.deb; do
        name=$(basename "$deb")
        [[ "$name" =~ ^agenti(-runtime)?_[A-Za-z0-9.+~-]+_(all|amd64|arm64)\.deb$ ]] \
            || die "unexpected file in release $tag: $name (only agenti and agenti-runtime belong here)"
        gh attestation verify "$deb" -R "$GH_REPO" \
            --signer-workflow "$GH_REPO/.github/workflows/release.yml" \
            --source-ref "refs/tags/$tag" >/dev/null \
            || die "$name has no valid build attestation from $GH_REPO's release workflow at $tag; nothing was added"
        echo "  [ OK ] $name  checksum + attestation"
    done
    mkdir -p "$repo/pool/main"
    for deb in "$dl"/*.deb; do
        name=$(basename "$deb")
        if [[ -e "$repo/pool/main/$name" ]]; then
            cmp -s "$deb" "$repo/pool/main/$name" \
                || die "pool/main/$name already exists with DIFFERENT content. A published version is never replaced; release a new version instead."
        else
            install -m 0644 "$deb" "$repo/pool/main/$name"
        fi
    done
    build_lists "$repo"
    echo "Added $tag. The repository is now UNSIGNED: run  packaging/apt/repo.sh sign $repo"
}

build_lists() {
    local repo=$1 arch dir
    rm -f "$repo/dists/$SUITE/InRelease" "$repo/dists/$SUITE/Release.gpg"
    for arch in "${ARCHES[@]}"; do
        dir="$repo/dists/$SUITE/main/binary-$arch"
        mkdir -p "$dir"
        (cd "$repo" && dpkg-scanpackages -m -a "$arch" pool /dev/null 2>/dev/null) > "$dir/Packages"
        gzip -9nkf "$dir/Packages"
    done
    (cd "$repo/dists/$SUITE" && apt-ftparchive \
        -o APT::FTPArchive::Release::Origin=Agenti \
        -o APT::FTPArchive::Release::Label=Agenti \
        -o APT::FTPArchive::Release::Suite="$SUITE" \
        -o APT::FTPArchive::Release::Codename="$SUITE" \
        -o APT::FTPArchive::Release::Architectures="${ARCHES[*]}" \
        -o APT::FTPArchive::Release::Components=main \
        -o APT::FTPArchive::Release::Description="Agenti open core (https://github.com/$GH_REPO)" \
        release . > Release.new) && mv "$repo/dists/$SUITE/Release.new" "$repo/dists/$SUITE/Release"
    install -m 0644 "$KEY" "$repo/agenti-release-key.asc"
    install -m 0644 "$HERE/install.sh" "$repo/install.sh"
}

cmd_sign() {
    local repo=$1 rel="$1/dists/$SUITE/Release"
    [[ -f "$rel" ]] || die "$rel does not exist. Build the lists first: packaging/apt/repo.sh add $repo <tag>"
    gpg --list-keys "$FPR" >/dev/null 2>&1 \
        || die "the release key is not in your keyring. Import it: gpg --import $KEY"
    gpg --card-status >/dev/null 2>&1 \
        || die "gpg cannot see the YubiKey. Plug it in; if it still fails see docs/release-signing.md § 8."
    echo "Signing $rel. Type your YubiKey PIN, then TOUCH the key when it blinks."
    gpg --local-user "$FPR" --digest-algo SHA512 --clearsign -o "$rel.InRelease.new" "$rel" \
        || { rm -f "$rel.InRelease.new"; die "signing failed (wrong PIN, no touch within ~15 s, or key unplugged). Nothing changed; run sign again."; }
    mv "$rel.InRelease.new" "$1/dists/$SUITE/InRelease"
    echo "Signed. Now check it: packaging/apt/repo.sh check $repo"
}

cmd_check() {
    local repo=$1 dists="$1/dists/$SUITE"
    need gpgv gpgv
    [[ -f "$dists/InRelease" ]] || die "$dists/InRelease does not exist: the repository is unsigned. Run: packaging/apt/repo.sh sign $repo"
    local tmp; tmp=$(mktemp -d); trap 'rm -rf "$tmp"; trap - RETURN' RETURN
    gpg --dearmor < "$KEY" > "$tmp/key.gpg"
    gpgv --keyring "$tmp/key.gpg" --output "$tmp/Release.signed" "$dists/InRelease" 2>"$tmp/gpgv.log" \
        || { cat "$tmp/gpgv.log" >&2; die "InRelease is not validly signed by the release key"; }
    cmp -s "$tmp/Release.signed" "$dists/Release" \
        || die "InRelease signs a different Release than the one in the folder; run sign again"
    echo "  [ OK ] InRelease signed by $FPR"
    # Every file Release lists must match its SHA256.
    local sum size path n=0
    while read -r sum size path; do
        [[ -f "$dists/$path" ]] || continue
        [[ $(sha256sum "$dists/$path" | cut -d' ' -f1) == "$sum" ]] \
            || die "dists/$SUITE/$path does not match its SHA256 in Release; rebuild with add and sign again"
        n=$((n + 1))
    done < <(awk '/^SHA256:/{on=1;next} /^[^ ]/{on=0} on{print $1,$2,$3}' "$dists/Release")
    echo "  [ OK ] $n package lists match Release"
    # apt itself, isolated from this machine's own apt state.
    local arch
    for arch in "${ARCHES[@]}"; do
        local a="$tmp/apt-$arch"
        mkdir -p "$a/lists/partial" "$a/cache/archives/partial" "$a/etc/sources.list.d" "$a/etc/preferences.d"
        cp "$KEY" "$a/key.asc"
        printf 'Types: deb\nURIs: file://%s\nSuites: %s\nComponents: main\nSigned-By: %s\n' \
            "$(cd "$repo" && pwd)" "$SUITE" "$a/key.asc" > "$a/etc/sources.list.d/agenti.sources"
        local opts=(-o "APT::Architecture=$arch" -o "APT::Architectures::=$arch" -o "Dir::Etc=$a/etc"
            -o "Dir::Etc::sourcelist=/dev/null" -o "Dir::State::Lists=$a/lists"
            -o "Dir::Cache=$a/cache" -o "Dir::State::status=/dev/null" -o "Debug::NoLocking=1")
        apt-get "${opts[@]}" -q update >"$tmp/update.log" 2>&1 \
            || { cat "$tmp/update.log" >&2; die "apt refused the repository for $arch"; }
        grep -qiE '^(W|E):' "$tmp/update.log" && { cat "$tmp/update.log" >&2; die "apt warned about the repository for $arch"; }
        local cand rt
        cand=$(apt-cache "${opts[@]}" policy agenti | awk '/Candidate:/{print $2}')
        rt=$(apt-cache "${opts[@]}" policy agenti-runtime | awk '/Candidate:/{print $2}')
        [[ -n "$cand" && "$cand" != "(none)" && -n "$rt" && "$rt" != "(none)" ]] \
            || die "apt on $arch finds no installable agenti/agenti-runtime"
        echo "  [ OK ] apt ($arch): agenti $cand, agenti-runtime $rt"
    done
    echo "The repository is ready to upload: packaging/apt/repo.sh upload $repo"
}

# R2 credentials: an R2 API token scoped to the one bucket, Object Read & Write.
R2_ENV=${AGENTI_R2_ENV:-$HOME/.local/agenti-tools/secrets/r2-agenti-apt.env}
R2_BUCKET=agenti-apt

r2_put() {  # r2_put <local-file> <key> <cache-control>; secrets reach curl on stdin, never argv
    local ctype=application/octet-stream
    case "$2" in
        *.deb) ctype=application/vnd.debian.binary-package ;;
        *.gz) ctype=application/gzip ;;
        *.asc|*/Release|*/InRelease|*/Packages) ctype="text/plain; charset=utf-8" ;;
        *.sh) ctype="text/x-shellscript; charset=utf-8" ;;
    esac
    printf 'user = "%s:%s"\n' "$R2_ACCESS_KEY_ID" "$R2_SECRET_ACCESS_KEY" \
        | curl -fsS -K - --aws-sigv4 "aws:amz:auto:s3" -T "$1" \
            -H "Content-Type: $ctype" -H "Cache-Control: $3" \
            "https://$R2_ACCOUNT_ID.r2.cloudflarestorage.com/$R2_BUCKET/$2" >/dev/null
}

cmd_upload() {
    local repo=$1 f key
    [[ -f "$R2_ENV" ]] || die "no R2 credentials at $R2_ENV. Create an R2 API token for bucket $R2_BUCKET (Object Read & Write) and save R2_ACCOUNT_ID, R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY there (mode 600)."
    # shellcheck disable=SC1090
    . "$R2_ENV"
    [[ -n "${R2_ACCOUNT_ID:-}" && -n "${R2_ACCESS_KEY_ID:-}" && -n "${R2_SECRET_ACCESS_KEY:-}" ]] \
        || die "$R2_ENV must set R2_ACCOUNT_ID, R2_ACCESS_KEY_ID and R2_SECRET_ACCESS_KEY"
    cmd_check "$repo"
    # Packages first, then the lists, InRelease LAST: a client never sees a
    # signed list naming a file that is not there yet.
    for f in "$repo"/pool/main/*.deb; do
        key=pool/main/$(basename "$f")
        if curl -fsI "https://apt.agenti-foss.org/$key" >/dev/null 2>&1; then
            echo "  [skip] $key (already published; versions are never replaced)"
            continue
        fi
        r2_put "$f" "$key" "public, max-age=31536000, immutable" || die "upload of $key failed; nothing after it was sent. Run upload again."
        echo "  [ up ] $key"
    done
    while read -r f; do
        key=${f#"$repo"/}
        r2_put "$f" "$key" "public, max-age=60" || die "upload of $key failed. Run upload again."
        echo "  [ up ] $key"
    done < <(find "$repo/dists" -type f ! -name InRelease | sort; echo "$repo/agenti-release-key.asc"; echo "$repo/install.sh")
    r2_put "$repo/dists/$SUITE/InRelease" "dists/$SUITE/InRelease" "public, max-age=60" \
        || die "upload of InRelease failed. Run upload again."
    echo "  [ up ] dists/$SUITE/InRelease"
    echo "Published at https://apt.agenti-foss.org (lists are cached up to 60 s)."
}

case "${1:-}" in
    -h|--help|help|"") usage; [[ -n "${1:-}" ]] ;;
    add|sign|check|upload)
        verb=$1; shift
        [[ $# -ge 1 ]] || die "$verb needs the repository folder. See: packaging/apt/repo.sh --help"
        "cmd_$verb" "$@" ;;
    *) die "unknown verb '$1'. See: packaging/apt/repo.sh --help" ;;
esac
