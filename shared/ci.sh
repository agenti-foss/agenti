#!/usr/bin/env bash
# ci.sh — every automated check this project has, in one place.
#
#   shared/ci.sh            lint + test (what a push must pass)
#   shared/ci.sh lint       syntax and obvious-bug checks, no tests
#   shared/ci.sh test       every shared/test_*.py suite
#   shared/ci.sh gui        every GUI page in a real browser (tests/gui/visual.js;
#                           needs node, Chrome or Chromium, and npm ci in tests/gui)
#
# GitHub Actions (.github/workflows/ci.yml) runs exactly this, so a green
# run on GitHub means the same thing as a green run at your desk. Nothing
# here needs root, the vault, systemd, a network or the Agent SDK.
#
# A check whose tool is missing is SKIPPED loudly on a laptop and FAILS on CI
# (GitHub sets CI=true): a green run that silently checked nothing is worse
# than a red one. To get every tool locally:
#   pip install ruff shellcheck-py cryptography     (and node for the GUI scripts)
set -uo pipefail

cd "$(dirname "$0")/.." || exit 2
export PYTHONDONTWRITEBYTECODE=1     # never leave __pycache__ in the checkout

FAILED=()
SKIPPED=()

note() { printf '\n== %s\n' "$*"; }
fail() { FAILED+=("$1"); printf '  FAIL  %s\n' "$1"; }
ok()   { printf '  ok    %s\n' "$1"; }

# need <tool> <what-it-checks>: 0 if the tool exists; otherwise skip (laptop)
# or fail (CI) and return 1 so the caller moves on.
need() {
    command -v "$1" >/dev/null 2>&1 && return 0
    if [[ "${CI:-}" == "true" ]]; then
        fail "$2 — '$1' is not installed on this CI runner"
    else
        SKIPPED+=("$2 (install '$1')")
        printf '  SKIP  %s — %s not installed\n' "$2" "$1"
    fi
    return 1
}

lint() {
    note "Python: syntax errors and undefined names (ruff, rules in ruff.toml)"
    if need ruff "python lint"; then
        ruff check --no-cache . && ok "ruff" || fail "ruff"
    fi

    note "Bash: syntax (bash -n) and real errors (shellcheck, errors only)"
    # Tracked AND new (not yet committed, not ignored) files: a script must be
    # checked before its first commit, not after.
    local scripts=(shared/agenti)
    mapfile -t -O 1 scripts < <(git ls-files --cached --others --exclude-standard \
                                'shared/*.sh' 'packaging/*.sh' 'packaging/**/*.sh' | sort -u)
    local s bad=0
    for s in "${scripts[@]}"; do
        bash -n "$s" || { fail "bash -n $s"; bad=1; }
    done
    [[ $bad -eq 0 ]] && ok "bash -n on ${#scripts[@]} scripts"
    if need shellcheck "shell lint"; then
        shellcheck -S error "${scripts[@]}" && ok "shellcheck" || fail "shellcheck"
    fi

    note "GUI: JavaScript syntax (node --check)"
    if need node "javascript syntax"; then
        local js n=0 jsbad=0
        while IFS= read -r js; do
            n=$((n + 1))
            node --check "$js" || { fail "node --check $js"; jsbad=1; }
        done < <(git ls-files --cached --others --exclude-standard 'shared/gui/js/*.js' 'tests/gui/*.js' | sort -u)
        [[ $jsbad -eq 0 ]] && ok "node --check on $n files"
    fi

    note "Names: the product's old name is gone from every committed file and path"
    # The word is built from two halves so this check is not itself a trace.
    local old="pen""test" hits
    hits=$( { git ls-files | grep -i -- "$old"; git ls-files -z | xargs -0 grep -Iil -- "$old"; } 2>/dev/null | sort -u )
    if [[ -z "$hits" ]]; then ok "no trace of the old name"
    else fail "the old product name is still in: $(echo "$hits" | tr '\n' ' ')"; fi

    note "Data: every committed .json file parses"
    local jf jn=0 jbad=0
    while IFS= read -r jf; do
        jn=$((jn + 1))
        python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$jf" \
            || { fail "invalid json: $jf"; jbad=1; }
    done < <(git ls-files '*.json')
    [[ $jbad -eq 0 ]] && ok "$jn json files"
}

run_tests() {
    note "Tests: every shared/test_*.py (no root, vault or network needed)"
    python3 -c 'import cryptography' 2>/dev/null \
        || { fail "tests need the 'cryptography' package (pip install cryptography)"; return; }
    local t out rc total=0 bad=0
    # The suites test THIS checkout, never an installed copy: every default
    # path (paths.sh / paths.py) points at a folder that does not exist, so
    # each lookup falls back to the source tree, and nothing can touch the
    # box's real data, user database or settings.
    local none=/nonexistent/agenti-ci
    for t in shared/test_*.py; do
        total=$((total + 1))
        out=$(AGENTI_LIBDIR=$none AGENTI_STATE=$none AGENTI_ROOT=$none/data AGENTI_ETC=$none \
              AGENTI_RUNTIME=$none timeout 300 python3 "$t" 2>&1); rc=$?
        if [[ $rc -eq 0 ]]; then
            ok "$t"
        else
            bad=$((bad + 1)); fail "$t (exit $rc)"
            printf '%s\n' "$out" | tail -25 | sed 's/^/        /'
        fi
    done
    printf '  %d suites, %d failed\n' "$total" "$bad"
}

# Every page at a phone and a desktop width, light and dark, both skins,
# against recorded API answers: fails on script errors, a page wider than the
# screen, a page that never shows its content, or an unrecorded API call.
gui_views() {
    note "GUI: every page in a real browser (tests/gui/visual.js)"
    need node "GUI views" || return 0
    if [[ ! -d tests/gui/node_modules/playwright-core ]]; then
        if [[ "${CI:-}" == "true" ]]; then fail "GUI views — run: (cd tests/gui && npm ci)"
        else SKIPPED+=("GUI views (cd tests/gui && npm ci)"); printf '  SKIP  GUI views — tests/gui needs: npm ci\n'; fi
        return 0
    fi
    node tests/gui/visual.js --out tests/gui/out && ok "GUI views (screenshots: tests/gui/out/index.html)" \
        || fail "GUI views (screenshots: tests/gui/out/index.html)"
}

case "${1:-all}" in
    lint) lint ;;
    test) run_tests ;;
    gui)  gui_views ;;
    all)  lint; run_tests ;;
    -h|--help|help) sed -n 2,19p "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "usage: shared/ci.sh [lint|test|gui|all]" >&2; exit 2 ;;
esac

echo
if [[ ${#SKIPPED[@]} -gt 0 ]]; then
    printf 'Skipped (not checked): %s\n' "${SKIPPED[*]}"
fi
if [[ ${#FAILED[@]} -gt 0 ]]; then
    printf 'FAILED: %d\n' "${#FAILED[@]}"; printf '  - %s\n' "${FAILED[@]}"
    exit 1
fi
echo "All checks passed."
