# Packaging: the `.deb`

Design agreed with the operator on 2026-10-20; built the same day (steps 1–7
below); first installed on the dev box 2026-10-21 (step 8). This page is the
reference: what goes where, what apt does at each step, and the order of the work.

## Decisions (operator, 2026-10-20)

| Question | Decision |
|---|---|
| Install paths | Debian-standard: `/usr/bin/agenti`, code in `/usr/lib/agenti`, state in `/var/lib/agenti`, settings in `/etc/agenti`. Nothing under `/usr/local`. |
| Python libraries | Bundled, in a separate package: `agenti-runtime` (its own Python plus every library, hash-pinned, built per CPU type). `agenti` itself is small and architecture-independent. A Kali Python upgrade cannot break it; nothing is downloaded after `apt install`. |
| Vault | Optional, **off by default**. Data lives in `/var/lib/agenti/data`; `sudo agenti vault enable` moves it into an encrypted container mounted at that same path. Code is never inside the vault. |
| Upgrades | Automatic. Code is outside the vault, so `apt upgrade` replaces all of it; nothing waits for an unlock. |
| Purge | `apt purge agenti` asks one question (default **No**): delete all Agenti data, including the vault image and the user database? Without a terminal (automation) the answer is No and the data is kept, with the paths and delete commands printed. |
| Sudoers | The package installs `/etc/sudoers.d/agenti-api` (the API's one-binary grant, with its reasoning in the comments), checked with `visudo -c`. |
| GUI start | At install: the API and auth service start on `127.0.0.1:8420` and on every boot. Sign-in is refused until `sudo agenti setup` creates the first admin; the login page says so. |
| Security audit | After the `.deb` exists, before anything is published: install the package on a clean machine and review every privilege boundary as a stranger would deploy it. |

Implementation choices (not operator forks):

- **No debhelper.** Packages are assembled by `packaging/build-deb.sh` with
  `dpkg-deb`. `dh_installsystemd` would enable units, and agent run units are
  never enabled (safety invariant 5); maintainer scripts are written by hand.
- **Dependencies:** what the core needs is `Depends` (`systemd`, `sudo`,
  `bubblewrap`, `libseccomp2`, `openssl`, `e2fsprogs`; `util-linux` is essential,
  so always there); what one
  agent needs is `Recommends` (`nmap`, `netexec`, `tshark`, …), because several
  exist only on Kali and apt installs Recommends by default anyway.
  `cryptsetup` is `Recommends` (only the optional vault needs it).
- **Supported:** Kali rolling. Debian 13 and Ubuntu 24.04 are install-tested
  in CI, best effort.

## Packages

| Package | Architecture | Contents | Relations |
|---|---|---|---|
| `agenti` | all | CLI, harness, shipped agents (enum, research, trafficmon), API, GUI, help, units, sudoers grant | `Depends: agenti-runtime (>= R)`; `Provides: agenti-plugin-api-N` |
| `agenti-runtime` | amd64, arm64 | `/usr/lib/agenti-runtime/`: `python/` (standalone CPython) and three environments, `agent/` (Claude Agent SDK), `api/` (FastAPI, uvicorn), `authd/` (cryptography only, kept apart on purpose) | none; versioned on its own, rebuilt only when a pin changes |
| `agenti-exploit`, `agenti-cracker` (one private repo each, sold separately) | all | one closed agent, its harness files and help (`packaging/plugins/<agent>.conf`) | `Depends: agenti-plugin-api-N` |

`N` is `shared/PLUGIN_API_VERSION`. It changes only when an extension point
changes incompatibly (`docs/open-core-split.md`), so apt refuses a mismatched
pair.

## Layout

| What | Was | Now |
|---|---|---|
| CLI | `/usr/local/bin/agenti` | `/usr/bin/agenti` |
| Helpers (`iam.py`, `authd.py`, `vault.sh`, …), unit template, help | `/usr/local/lib/agenti/` | `/usr/lib/agenti/` |
| Harness | `/opt/agenti/shared/lib/` (in the vault) | `/usr/lib/agenti/lib/` |
| Shipped agents | `/opt/agenti/shared/agents/<a>/` | `/usr/lib/agenti/agents/<a>/` |
| Agents built in Settings | `/opt/agenti/shared/agents/<a>/` | `/var/lib/agenti/data/shared/agents/<a>/` |
| Reviewed program catalog | `/opt/agenti/shared/tool-catalog.json` | `/usr/lib/agenti/tool-catalog.json` (admin additions stay in data) |
| API code, GUI | `/usr/local/lib/agenti/api/` | `/usr/lib/agenti/api/` (GUI in `api/gui/`, served by the same process) |
| Python environments | `/opt/agenti/shared/venv`, `/usr/local/lib/agenti/{api/venv,authd-venv}` | `/usr/lib/agenti-runtime/{agent,api,authd}` |
| User database | `/usr/local/lib/agenti/api/iam.db` | `/var/lib/agenti/iam.db` |
| Sessions and audit (authd) | `/usr/local/lib/agenti/authd/` | `/var/lib/agenti/authd/` |
| TLS key and certificate | `/usr/local/lib/agenti/tls/` | `/var/lib/agenti/tls/` |
| API settings | `/usr/local/lib/agenti/agenti-api.conf` | `/etc/agenti/api.conf` |
| Data root (`AGENTI_ROOT`): secrets, instruction edits, engagement, runs, teams, kept outputs | `/opt/agenti/` | `/var/lib/agenti/data/` (same `shared/` + `org/` shape inside, minus the code) |
| Vault image | `/var/lib/agenti-vault.img` | `/var/lib/agenti/vault.img`, mounted at the data root when enabled |

The user database, sessions and TLS stay outside the data root so sign-in
works, and can say "the vault is locked", while it is locked.

## What apt does

- **install** (`postinst configure`): create the service accounts and groups
  (`agenti-run`, `agenti-shared`, `agenti-api`, `agenti-authd`, `agenti-sock`);
  create `/var/lib/agenti` with its modes; create an empty user database; write
  `/etc/agenti/api.conf` with loopback defaults if absent; render the units
  (API, auth service, retention timer, each agent's run-slot template and
  capability drop-in); provision each agent's data folder; start and enable
  the GUI and the retention timer. Agent run units are never enabled.
- **upgrade**: the same steps (all idempotent), then restart the API and auth
  service if they were running. Runs in progress keep going; a run started
  afterwards uses the new code.
- **remove**: stop the GUI and every agent run, remove the rendered units,
  lock the vault if it is on (operator decision 2026-10-21) and print how to
  open it again. Accounts, settings and data stay.
- **purge**: the one question above. Yes: delete `/var/lib/agenti` (vault
  image included), `/etc/agenti` and the accounts. No: delete the settings,
  keep the data and accounts, print where they are and how to delete them.

All of this is one script, `shared/configure.sh` (installed as
`/usr/lib/agenti/configure.sh`), so the package and a developer's deploy can
never configure the machine two different ways.

## First run: `sudo agenti setup`

Re-runnable; each step says when it is already done and can be skipped.

1. The first admin: password and two-factor code (a passkey can be added in
   the GUI afterwards).
2. Optional: the vault (explains what it protects and what it costs; default
   No). Before the key, so the key is written into it (2026-10-21).
3. The Anthropic API key, from a silent prompt (never argv, never a log).
4. Optional: reach the GUI from other machines: LAN with a certificate, or
   behind a proxy or tunnel (`docs/remote-access.md`).
5. Prints the address to open and the next commands.

## The vault, now optional

- `sudo agenti vault enable [--size 8G]`: create the container (you type the
  passphrase; nothing else ever sees it), copy the data in, check the copy,
  delete the unencrypted original (operator decision 2026-10-21) and mount the
  container at `/var/lib/agenti/data`. `agenti setup` asks about the vault
  before the API key, so a key set there never touches the bare disk. The empty directory underneath is made immutable
  (`chattr +i`), so with the vault locked nothing can write data to the
  unencrypted disk by mistake.
- When enabled: after a boot nothing that needs data runs until
  `sudo agenti vault unlock`; run units assert the mount, as today.
- `sudo agenti vault disable`: move the data back out (asks first).
- Recommended instead, where possible: the operating system's full-disk
  encryption (Kali's installer offers it).

## Build and CI

- `packaging/build-runtime.sh <out-dir>`: downloads the pinned standalone
  CPython (SHA-256 checked) for the build machine's CPU type, builds the three
  environments from hash-pinned lock files (`packaging/runtime/*.lock`),
  rewrites their paths to `/usr/lib/agenti-runtime`, compiles bytecode, and
  writes `agenti-runtime_<v>_<arch>.deb`.
- `packaging/build-deb.sh <version> <out-dir>`: places every file with
  `packaging/install-tree.sh`, adds the maintainer scripts, writes
  `agenti_<v>_all.deb`. The open package never contains a closed file.
- CI: `lintian` on both packages; install, upgrade, remove and purge in
  `kalilinux/kali-rolling`, `debian:trixie` and `ubuntu:24.04` containers, each
  pinned by digest (`packaging/image-digests.sh` to refresh).
- `release.yml`: `agenti` once, `agenti-runtime` on `ubuntu-24.04` and
  `ubuntu-24.04-arm`; attest exactly those three, by the digests their build jobs
  reported. Publishing stays off.
- Development on the box: `sudo ./shared/deploy.sh` runs the same
  `install-tree.sh` into `/` and the same `configure.sh`, then verifies.

## Keeping the runtime patched

Bundling means Kali's security updates do not reach what is inside
`agenti-runtime`: CPython and the libraries built into it (OpenSSL, SQLite,
zlib, bzip2, expat, xz, zstd, ncurses), the pinned Python packages, and the
pin for the Claude Code program the Agent SDK needs. They are patched only by
building a new `agenti-runtime`:

(Claude Code itself is not in the package: it is Anthropic's, under Anthropic's
terms. The build records the exact PyPI wheel it comes in and both SHA-256s in
`claude-code.pin`; postinst runs `/usr/lib/agenti-runtime/fetch-claude-code`,
which downloads that wheel, checks both hashes and installs the one file; prerm
removes it. Without network the install completes and `agenti verify` and every
run's preflight name the command.)

- a CPython or OpenSSL security release: bump `packaging/runtime/python.pin` to
  the python-build-standalone release that carries it;
- a Python package advisory (`security.yml` runs pip-audit on the three lock
  files, weekly and on every push): `packaging/runtime/lock.sh <env>`;
- then bump `packaging/runtime/VERSION` and release the runtime.

lintian flags these copies (`embedded-library`); the package overrides the tag
with this reason.

## Steps the operator does on this box

1. Add `/usr/bin/agenti` to the dev sudoers grant when the CLI moves.
2. Run the one-time move to the new layout (state to `/var/lib/agenti`, the
   existing vault pointed at the new data root). It ends with
   `sudo agenti vault unlock`, where you type the passphrase.
3. Before anything ships: remove the dev sudoers grant.

## Order of work

1. Done: this page; `PLUGIN_API_VERSION`, `agenti --version`.
2. Done: `agenti-runtime` (118 MB download, 453 MB installed, glibc >= 2.34),
   built on this box and checked at its real path.
3. Done: the layout change in the code (`paths.sh`/`paths.py`, optional vault), CI green.
4. Done: `install-tree.sh`, `configure.sh`, `verify.sh`, the new `deploy.sh`.
5. Done: `build-deb.sh`, maintainer scripts, the purge question; `test_packaging.py`.
6. Done: `agenti setup`, the login-page hint (`GET /auth/setup-status`), `agenti verify`,
   `agenti gui configure`, the `console_only` refusal.
7. Done: `package.yml` (lintian, clean-container install/purge), `release.yml`,
   `docs/install.md`, CLAUDE.md. Green on GitHub since 2026-10-21 (ce3194a):
   both runtimes, lintian, and install/upgrade/remove/purge on Kali, Debian 13
   (amd64 and arm64) and Ubuntu 24.04.
8. Done 2026-10-21: this box moved and installed from the packages; `agenti
   verify` passes, GUI check clean for an admin and two operators, a real enum
   run (isolation and capabilities checked from /proc while it ran), an
   out-of-scope target refused, a reboot with the vault locked then unlocked.
   Next: the same, as a stranger would, on a fresh Kali VM (amd64).
9. The security audit; then publishing.
