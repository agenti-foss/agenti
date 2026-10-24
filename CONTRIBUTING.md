# Contributing to Agenti

Thanks for helping. Agenti is a self-hosted security tool, so changes are held to
a higher bar than usual: a bug here can widen what an AI agent is allowed to touch.

## Before you start

- **Security problems:** do not open a public issue. Use GitHub's private
  "Report a vulnerability" on this repository.
- **Bugs and ideas:** open an issue first for anything bigger than a small fix.
- **Be authorised.** Only test Agenti against systems you own or have written
  permission to test.

## Licence and contributor agreement

Agenti's open core is licensed under the **GNU Affero General Public License v3.0**
(`LICENSE`). Some additional agents are offered separately under a commercial
licence.

To keep that possible, **every contributor must agree to the Contributor Licence
Agreement (CLA) before a pull request can be merged.** The CLA lets the project
keep distributing your contribution under the AGPL and also under its commercial
licence; you keep the copyright in your work. A bot will ask you to sign on your
first pull request. (The CLA text is being finalised; until it is published,
pull requests from outside the project cannot be merged.)

The name "Agenti" and its logo are trademarks of the project; see `TRADEMARKS.md`.

## Running the checks

```
shared/install-hooks.sh     # once per clone: scans staged changes for secrets
shared/ci.sh                # lint + every test suite (same as CI)
```

`ci.sh` needs `ruff`, `shellcheck`, `node` and `cryptography` (see the top of the
script). No root, vault, network or Agent SDK is needed. A check whose tool is
missing is skipped loudly on your machine and fails on CI.

Some properties (sandbox, systemd units, the encrypted vault) can only be checked
on a real Kali box: `sudo ./shared/deploy.sh` installs your checkout the way the
package does and ends with `sudo agenti verify`. Say in your pull request whether
you did that. How the package is built and what apt does at each step:
`docs/packaging.md`.

## Ground rules for changes

1. **CLI first.** Every operation is a CLI verb; the API shells out to it; the GUI
   calls the API. One implementation, never two.
2. **Errors say what, why and the fix.** Every failure names the exact command to
   run next. Write `--help` text as you add a verb.
3. **Do not weaken the invariants** listed on the website's Security page and in
   `docs/threat-model.md`. In particular: scope is enforced by root-owned files,
   not by the model; the web tier cannot grant authority; agents run unprivileged.
   A pull request that touches one of these needs to say so, and why.
4. **No real data in the repo.** No client names, real addresses, keys, or lab
   details. Use documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`) and
   `example.com`.
5. **Tests with the change.** New behaviour gets a suite in `shared/test_*.py`.
6. **Help text:** user-facing behaviour gets a page in `docs/help/`.

## Pull requests

Keep them small and focused. CI (lint, tests, secrets scan, dependency audit,
CodeQL) must be green. Describe what changed and how you checked it.
