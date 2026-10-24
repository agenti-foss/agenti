#!/usr/bin/env bash
#
# install-tree.sh — place every file Agenti installs at its final path under a
# root folder: a package's staging tree (build-deb.sh) or the real / (a
# developer's shared/deploy.sh). ONE list of what ships, so the package and a
# deploy from a checkout can never install different files.
#
#   packaging/install-tree.sh <source-checkout> <dest-root> [--edition open|<plugin>]
#
#   --edition open (default)  the open core only: no plugin harness files, no
#                             plugin agents, no plugin help pages
#   --edition <plugin>        ONLY that plugin's files (what agenti-<plugin>
#                             installs on top of the open package)
#
# A plugin is one closed agent sold on its own (agenti-cracker, agenti-exploit).
# Its private repo is overlaid onto an open-core checkout and brings
# packaging/plugins/<plugin>.conf, which names its files (docs/open-core-split.md).
#
# Every file in shared/ must be named in exactly one list (shipped, a present
# plugin's, or development-only); an unlisted file stops the build, so a new
# module can neither be forgotten nor shipped by accident. test_packaging.py
# checks the same.
#
# Modes: folders 0755; files 0644, or 0755 when they start with "#!".
# Ownership is root's: the build packs with --root-owner-group, a deploy runs
# as root. Nothing here creates accounts, data, units or services: that is
# configure.sh's job, at install time.
set -euo pipefail

die() { printf '\nerror: %s\n' "$*" >&2; exit 1; }
ok()  { printf '  [ OK ] %s\n' "$*"; }

SRC="${1:-}"; DEST="${2:-}"; EDITION=open
[[ -n "$SRC" && -n "$DEST" ]] || die "usage: packaging/install-tree.sh <source-checkout> <dest-root> [--edition open|<plugin>]"
shift 2
while [[ $# -gt 0 ]]; do
    case "$1" in
        --edition) [[ $# -ge 2 ]] || die "--edition needs open or a plugin name"; EDITION="$2"; shift 2 ;;
        --edition=*) EDITION="${1#*=}"; shift ;;
        *) die "unknown option $1" ;;
    esac
done
SRC="$(cd "$SRC" && pwd)"
PLUGINS=()
for f in "$SRC"/packaging/plugins/*.conf; do [[ -f "$f" ]] && PLUGINS+=("$(basename "$f" .conf)"); done
[[ "$EDITION" == open || " ${PLUGINS[*]} " == *" $EDITION "* ]] \
    || die "--edition must be open or a plugin present in this checkout (${PLUGINS[*]:-none}), not '$EDITION'"
# Root-run Python below must never import from the caller's folder (audit
# run 1 F14, run 2 for the scripts that are entry points of their own):
# PYTHONSAFEPATH drops it, and the code folder is named instead.
export PYTHONSAFEPATH=1
export PYTHONPATH="$SRC/shared"
[[ -f "$SRC/shared/agenti" && -f "$SRC/shared/paths.sh" ]] || die "$SRC is not an Agenti checkout (no shared/agenti)"
mkdir -p "$DEST"; DEST="$(cd "$DEST" && pwd)"

# --- what ships --------------------------------------------------------------
# The code folder (/usr/lib/agenti): the harness every run imports, the
# root-side helpers the CLI runs, the auth service. One flat folder, the same
# shape as shared/ in the checkout.
CORE_FILES=(
    agent_builder.py agent_contract.py agent_controls.py agent_runtime.py
    analysis_programs.py analysis_runner.py api_bridge.py authd.py catalog_admin.py context_store.py
    engagement_context.py engagement_store.py gen_capabilities.py help_docs.py iam.py
    disk_encryption.py egress_relay.py network_policy.py new_agent.py outputs.py paths.py preflight.py qr.py
    recon_programs.py
    recon_runner.py
    retention.py run_coverage.py run_files.py sandbox.py sandbox_seccomp.py scope_cidr.py scope_domain.py
    scope_files.py session_runner.py state.py suricata_offline.py team_report.py
    tool_approvals.py tool_catalog.py tool_registry.py tool_settings_store.py
    update_check.py webauthn_lite.py
    paths.sh capability-dropin.sh configure.sh verify.sh vault.sh set-secret.sh
    agenti-instance@.service agenti-api.sudoers tool-catalog.json suricata-offline.yaml
    VERSION PLUGIN_API_VERSION
)
# In the checkout for developers and CI only.
DEV_FILES=( agenti ci.sh deploy.sh install-hooks.sh gui_check.py )
# Documentation, shipped under /usr/share/doc/agenti.
DOC_FILES=( engagement.example.json )
OPEN_AGENTS=( enum research trafficmon )

# The plugins' files: each conf's own lists, and the union of all of them
# (none of which may reach the open package).
plugin_lists() {  # plugin_lists <plugin>: set PLUGIN_FILES/AGENTS/HELP from its conf
    PLUGIN_FILES=(); PLUGIN_AGENTS=(); PLUGIN_HELP=()
    # shellcheck source=/dev/null
    source "$SRC/packaging/plugins/$1.conf"
}
ALL_PLUGIN_FILES=(); ALL_PLUGIN_HELP=()
for p in "${PLUGINS[@]}"; do
    plugin_lists "$p"
    for f in "${PLUGIN_FILES[@]}"; do [[ -f "$SRC/shared/$f" ]] || die "packaging/plugins/$p.conf names shared/$f, which is missing"; done
    ALL_PLUGIN_FILES+=("${PLUGIN_FILES[@]}"); ALL_PLUGIN_HELP+=("${PLUGIN_HELP[@]}")
done

# Refuse a file nobody classified.
listed=" ${CORE_FILES[*]} ${ALL_PLUGIN_FILES[*]} ${DEV_FILES[*]} ${DOC_FILES[*]} "
for f in "$SRC"/shared/*; do
    n=$(basename "$f")
    [[ -d "$f" || "$n" == test_*.py || "$n" == __pycache__ ]] && continue
    [[ "$listed" == *" $n "* ]] || die "shared/$n is in no list in packaging/install-tree.sh.
Add it to CORE_FILES (it ships), a plugin's packaging/plugins/<plugin>.conf, DOC_FILES
(shipped as documentation) or DEV_FILES (never ships)."
done

# A syntax check that writes nothing (py_compile would leave __pycache__ in
# the checkout, root-owned when this runs as root).
compiles() { python3 -c 'import sys; compile(open(sys.argv[1], "rb").read(), sys.argv[1], "exec")' "$1" 2>/dev/null; }

put() {  # put <src> <dest-relative>: one file, mode from its first two bytes
    local src="$1" dst="$DEST/$2" mode=0644
    [[ -f "$src" ]] || die "missing $src"
    [[ "$(head -c2 "$src")" == "#!" ]] && mode=0755
    install -D -m "$mode" "$src" "$dst"
}

LIB=usr/lib/agenti
agent_folder() {  # agent_folder <name>: <name>-agent/ -> usr/lib/agenti/agents/<name>/
    local a="$1" d="$SRC/$1-agent" f
    [[ -f "$d/$a-agent.py" ]] || die "$a-agent/$a-agent.py is missing"
    compiles "$d/$a-agent.py" || die "$a-agent/$a-agent.py does not compile"
    put "$d/$a-agent.py" "$LIB/agents/$a/$a-agent.py"
    for f in manifest.json "$a.capabilities"; do
        [[ -f "$d/$f" ]] && put "$d/$f" "$LIB/agents/$a/$f"
    done
    [[ -f "$d/context/system-prompt.md" ]] || die "$a-agent/context/system-prompt.md is missing (a run is refused without one)"
    for f in system-prompt.md skills.md; do
        [[ -f "$d/context/$f" ]] && put "$d/context/$f" "$LIB/agents/$a/context/$f"
    done
    # The tools descriptor, from static analysis of the code: display data,
    # built here once so nothing on the box has to generate it.
    PYTHONDONTWRITEBYTECODE=1 python3 "$SRC/shared/gen_capabilities.py" "$d/$a-agent.py" > "$DEST/$LIB/agents/$a/capabilities.json" \
        || die "gen_capabilities.py could not describe $a"
    chmod 0644 "$DEST/$LIB/agents/$a/capabilities.json"
}

if [[ "$EDITION" != open ]]; then
    plugin_lists "$EDITION"
    for f in "${PLUGIN_FILES[@]}"; do put "$SRC/shared/$f" "$LIB/$f"; done
    for a in "${PLUGIN_AGENTS[@]}"; do agent_folder "$a"; done
    for p in "${PLUGIN_HELP[@]}"; do
        put "$SRC/docs/help/$p.md" "$LIB/help/$p.md"
        # its summary and icon (index.json is the open package's)
        [[ -f "$SRC/docs/help/$p.json" ]] && put "$SRC/docs/help/$p.json" "$LIB/help/$p.json"
    done
    ok "agenti-$EDITION files: ${#PLUGIN_FILES[@]} harness file(s), agent ${PLUGIN_AGENTS[*]}, ${#PLUGIN_HELP[@]} help page(s)"
    exit 0
fi

# --- the open core ---------------------------------------------------------------
for f in "${CORE_FILES[@]}"; do
    [[ "$f" == *.py ]] && { compiles "$SRC/shared/$f" || die "shared/$f does not compile"; }
    put "$SRC/shared/$f" "$LIB/$f"
done
put "$SRC/shared/agenti" usr/bin/agenti

# The API: its code, beside it the GUI (served by the same process, same
# origin, so the session cookie works).
for f in "$SRC"/shared/api/*.py; do put "$f" "$LIB/api/$(basename "$f")"; done
gui="$DEST/$LIB/api/gui"
rm -rf "${gui:?}"
mkdir -p "$gui"
cp -r "$SRC/shared/gui/." "$gui/"
find "$gui" -type d -exec chmod 0755 {} +
find "$gui" -type f -exec chmod 0644 {} +
# Every local script and stylesheet link carries a hash of the whole GUI, so a
# browser or a CDN can never pair a new page with an old script.
ver=$(cd "$gui" && find . -type f \( -name '*.js' -o -name '*.css' -o -name '*.html' \) -print0 \
      | sort -z | xargs -0 sha256sum | sha256sum | cut -c1-10)
find "$gui" -name '*.html' -exec sed -i -E "s#(src|href)=\"((js|css)/[^\"?]+\.(js|css))\"#\\1=\"\\2?v=$ver\"#g" {} +

# The help pages (agenti docs, GUI → Docs). A plugin adds its own.
plugin_help=" ${ALL_PLUGIN_HELP[*]} "
for f in "$SRC"/docs/help/*.md; do
    n=$(basename "$f" .md)
    [[ "$plugin_help" == *" $n "* ]] && continue
    put "$f" "$LIB/help/$n.md"
done
python3 - "$SRC/docs/help/index.json" "$DEST/$LIB/help/index.json" "${ALL_PLUGIN_HELP[@]}" <<'PY'
import json, sys
src, dst, *drop = sys.argv[1:]
d = json.load(open(src))
d["pages"] = {k: v for k, v in d.get("pages", {}).items() if k not in drop}
open(dst, "w").write(json.dumps(d, indent=2, ensure_ascii=False) + "\n")
PY
chmod 0644 "$DEST/$LIB/help/index.json"

for a in "${OPEN_AGENTS[@]}"; do agent_folder "$a"; done

# Documentation Debian expects, and an example engagement for people.
doc=usr/share/doc/agenti
put "$SRC/LICENSE" "$doc/LICENSE"
put "$SRC/shared/engagement.example.json" "$doc/examples/engagement.example.json"
cat > "$DEST/$doc/copyright" <<'EOF'
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: agenti
Source: https://github.com/agenti-foss/agenti

Files: *
Copyright: 2026 Agenti contributors
License: AGPL-3.0-only
 The full text is in /usr/share/doc/agenti/LICENSE.
EOF
chmod 0644 "$DEST/$doc/copyright"

find "$DEST/usr" -type d -exec chmod 0755 {} +
find "$DEST/usr" -name __pycache__ -type d -prune -exec rm -rf {} +
ok "open core: $(find "$DEST/usr" -type f | wc -l) files under $DEST (GUI version $ver)"
