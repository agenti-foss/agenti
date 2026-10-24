# Automated checks (CI)

Every push to `main` (the public repo; `master` in the private one), and every pull request, is checked automatically on
GitHub before anyone has to remember to. This page says what is checked, how to
run the same checks yourself, and what to do when one fails.

## What runs

Three jobs, defined in `.github/workflows/ci.yml`:

| Job | What it checks |
|---|---|
| **Lint** | Python for syntax errors and undefined names; every bash script for syntax and real errors; every GUI script for JavaScript syntax; every `.json` file parses. |
| **Tests** | Every `shared/test_*.py` suite (about 2,400 checks). None needs root, the vault, the network or the Agent SDK. |
| **Secrets scan** | The whole git history, looking for API keys, tokens and private keys that were committed by mistake. |

The checks themselves are in one script, `shared/ci.sh`. GitHub only supplies
the computer to run it on, so a green result on GitHub means the same as a
green result on your own machine.

## Security workflow and pre-commit hook

`.github/workflows/security.yml` (push, pull request, and weekly): `pip-audit`
on the three runtime lock files, CodeQL (python, javascript, `security-extended`),
and on pull requests a dependency review that fails on new moderate-or-worse
vulnerabilities. While the repo is private, GitHub will not store CodeQL's
results (code scanning is a paid add-on there; the dependency review needs it
too), so the findings are the job's `codeql-*` artifact and any finding fails
the job (operator decision 2026-10-21); the workflow comment says what to
switch back once the repo is public. `.githooks/pre-commit` scans staged changes with gitleaks and
refuses `secrets.env`, engagement configs and similar files; enable it once per
clone with `shared/install-hooks.sh`. `--no-verify` skips it; the whole-history
scan in CI cannot be skipped.

## Release workflow (publishing is OFF)

`.github/workflows/release.yml` runs on a `vX.Y.Z` tag: full checks, build and
prove the packages (`package.yml`), then sign. Each build job reports its package's
name and SHA-256 as a job output (`packaging/deb-digest.sh`); the signing job
downloads exactly those three artifacts by name, writes `SHA256SUMS` from the
reported digests, refuses any file no build job made, and attests that list
(`subject-checksums`). It never signs "every .deb in the run": any job, including
a container job running a pulled image, can upload an artifact (audit run 2). The
test images are pinned by digest; refresh them with `packaging/image-digests.sh`.
The result is kept as a workflow artifact. A public GitHub Release is created only when the
repository variable `RELEASE_PUBLISH` is `true`. Leave it unset until the
open-source audit is done. `workflow_dispatch` is a dry run and never publishes.

## Download page

`website/` is the public site for agenti-foss.org: home, download, docs, security and
report-a-bug, built by `website/build.py` and deployed by GitHub Pages from its own
repo. See `website/README.md`.

## Run it yourself

```
shared/ci.sh          # lint + tests
shared/ci.sh lint     # just lint
shared/ci.sh test     # just tests
```

It needs `ruff`, `shellcheck`, `node` and the `cryptography` package
(`pip install ruff shellcheck-py cryptography`). A tool you don't have is
skipped with a loud note on your machine, and counts as a failure on GitHub.

## When it goes red

Open the failed job on the GitHub Actions tab; the log names the file and line.
Fix it and push again; nothing else needs resetting. If the secrets scan flags
something real, **treat the secret as leaked and replace it** (removing it from
the file does not remove it from history). If it is a known-fake test value, add
its fingerprint to `.gitleaksignore` with a comment saying why it is fake.

## What this does not do yet

- It does not check the GUI visually. A real GUI check needs authd, a session and
  the CLI, none of which exist on a GitHub runner; use `shared/gui_check.py` on
  the box. A stubbed-API Playwright job is possible but not built. A self-hosted
  runner is deliberately avoided on a public repo.
- It does not deploy anything. Deploying stays a deliberate act on the box.
- It does not run the checks that need the real machine with systemd running
  (`sudo agenti verify`, `gui_check.py`). `package.yml` installs the packages on
  clean Kali, Debian and Ubuntu containers, but nothing is started there.
- The lint rules are narrow on purpose (`ruff.toml`): they find real bugs, not
  style. Widen them one rule at a time when you want to.
- To make a red result actually block a merge, turn on **branch protection** for
  `main` in the repository settings and require the three jobs.
