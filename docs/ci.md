# Automated checks (CI)

Every push to `main`, and every pull request, is checked automatically on
GitHub before anyone has to remember to. This page says what is checked, how to
run the same checks yourself, and what to do when one fails.

## What runs

Four jobs, defined in `.github/workflows/ci.yml`:

| Job | What it checks |
|---|---|
| **Lint** | Python for syntax errors and undefined names; every bash script for syntax and real errors; every GUI script for JavaScript syntax; every `.json` file parses. |
| **Tests** | Every `shared/test_*.py` suite (about 2,400 checks). None needs root, the vault, the network or the Agent SDK. |
| **Secrets scan** | The whole git history, looking for API keys, tokens and private keys that were committed by mistake. |
| **GUI views** | Every page of the web interface in a real browser (the runner's Chrome), at a phone and a desktop width, light and dark, in both skins (108 views). Fails on a script error, a page wider than the screen (it names the elements that stick out), a page that never shows its content, or an API call it has no recorded answer for. Every view is kept as a screenshot: the run's **gui-views** artifact, `index.html` inside. |

The checks themselves are in one script, `shared/ci.sh`. GitHub only supplies
the computer to run it on, so a green result on GitHub means the same as a
green result on your own machine.

## Security workflow and pre-commit hook

`.github/workflows/security.yml` (push, pull request, and weekly): `pip-audit`
on the three runtime lock files, CodeQL (python, javascript, `security-extended`),
and on pull requests in the public repo a dependency review that fails on new
moderate-or-worse vulnerabilities (GitHub offers it only on public repos, so it
is skipped in agenti-dev). CodeQL's findings are the job's `codeql-*` artifact
and any finding not reviewed in `.github/codeql-reviewed.json` fails the job
(operator decision 2026-10-21), in both repos. `.githooks/pre-commit` scans staged changes with gitleaks and
refuses `secrets.env`, engagement configs and similar files; enable it once per
clone with `shared/install-hooks.sh`. `--no-verify` skips it; the whole-history
scan in CI cannot be skipped.

## Release workflow

`.github/workflows/release.yml` runs on a `vX.Y.Z` tag, in the public repo only
(tags are pushed there, never to agenti-dev): full checks, build and
prove the packages (`package.yml`), then sign. Each build job reports its package's
name and SHA-256 as a job output (`packaging/deb-digest.sh`); the signing job
downloads exactly those three artifacts by name, writes `SHA256SUMS` from the
reported digests, refuses any file no build job made, and attests that list
(`subject-checksums`). It never signs "every .deb in the run": any job, including
a container job running a pulled image, can upload an artifact (audit run 2). The
test images are pinned by digest; refresh them with `packaging/image-digests.sh`.
The result is kept as a workflow artifact, and the GitHub Release is created
because the public repo's variable `RELEASE_PUBLISH` is `true` (unset it to make
tags build without publishing). `workflow_dispatch` is a dry run and never
publishes. The apt repository is updated and signed by hand afterwards
(`packaging/apt/repo.sh`, `docs/release-signing.md`).

## Download page

The public site for agenti-foss.org (home, download, docs, security and report-a-bug)
is its own repo, `agenti-foss/website`, built by its `build.py` and deployed by
Cloudflare Pages on every push to its `main`. Its docs are a copy of `docs/help/`
here: `python3 build.py --sync <this repo>/docs/help --check`. See its README.

## Run it yourself

```
shared/ci.sh          # lint + tests
shared/ci.sh lint     # just lint
shared/ci.sh test     # just tests
shared/ci.sh gui      # the GUI views (once: cd tests/gui && npm ci)
```

The GUI views need `node` and Chrome or Chromium (`CHROME=<path>` if it is not
at `/usr/bin/chromium` or `/usr/bin/google-chrome`); screenshots land in
`tests/gui/out/index.html`.

## The GUI views' recorded answers

No Agenti runs on a CI runner, so `tests/gui/serve.py` serves the pages from
`shared/gui/` with the real server's security headers and answers each API
call from `tests/gui/fixtures/`. Those answers are recorded from a live **test**
box (never one holding client data) with an example engagement on it:

```
cd tests/gui && npm ci
node record.js https://<test box>:8420 <admin> <password file> <totp secret file> \
     --scrub <the box's address>=198.51.100.5 --scrub <its hostname>=agenti-box
```

It opens every page in `pages.json`, keeps what the API answered, replaces each
`--scrub` text, and refuses to write anything that still holds a private
address (other than the examples the docs already use) or an API key. Record
again when the visual check says *API call(s) not recorded*, or when a page's
data changes shape. To check a new page, add it to `pages.json` with the
element that shows once it has loaded.

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

- The GUI views use recorded answers, so they prove layout and scripts, not the
  real server: sign-in, passkeys and live runs are checked on the box
  (`shared/gui_check.py`, Playwright). They do not compare pixels against a
  baseline either (fonts differ between machines): look at the screenshots
  when a change is visual. A self-hosted runner is deliberately avoided on a
  public repo.
- It does not deploy anything. Deploying stays a deliberate act on the box.
- It does not run the checks that need the real machine with systemd running
  (`sudo agenti verify`, `gui_check.py`). `package.yml` installs the packages on
  clean Kali, Debian and Ubuntu containers, but nothing is started there.
- The lint rules are narrow on purpose (`ruff.toml`): they find real bugs, not
  style. Widen them one rule at a time when you want to.
- To make a red result actually block a merge, turn on **branch protection** for
  `main` in the repository settings and require the four jobs.
