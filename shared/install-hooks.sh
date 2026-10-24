#!/usr/bin/env bash
# install-hooks.sh — turn on the repo's git hooks for this clone.
set -euo pipefail
cd "$(dirname "$0")/.."
git config core.hooksPath .githooks
echo "Git hooks enabled (.githooks/pre-commit: secret scan of staged changes)."
command -v gitleaks >/dev/null || echo "Note: gitleaks is not installed; the hook will warn on each commit until it is."
