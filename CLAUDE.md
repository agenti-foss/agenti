# Agenti

**Keep this file under ~25 KB.** If this file and the code disagree, **the
code wins**. Always update this file as you build.

## What Agenti is (product definition, 2026-10-06)

An open-source, self-hosted, agentic **cybersecurity** tool for **one
organisation's internal team**, running on a Kali Linux box, built on the Claude
Agent SDK. CLI binary `agenti`, shipped as a `.deb` (`docs/packaging.md`).

- **One org, many users. Two roles:** `operator` and `admin`. Every operator may
  use every agent. No tenants, no agent kits, no viewer role, no per-user agent
  grants (all of that is history).
- **Agents today:** `enum` (network enumeration, CIDR scope), `research` (OSINT,
  domain scope), `trafficmon` (passive capture, CIDR scope), `cracker`
  (hash cracking with john/hashcat, file-analysis agent, no network), `exploit`
  (Metasploit exploitation with per-action operator approval, CIDR scope, requires
  `exploitation_enabled` in the engagement and CVP enrolment), plus whatever admins
  build in Settings → Agents: **recon** agents (reviewed programs against a target)
  and **file-analysis** agents (`tshark`/`capinfos`/`suricata -r`/`john`/`hashcat`
  on attached files, in a bubblewrap + seccomp sandbox). A built agent is **data**
  (manifest + system prompt over one reviewed runner), never code.
- **Grammar:** `agenti <agent> <verb>`, `agenti team <name> <verb>`,
  `agenti engagement …`, `agenti admin …`, `agenti docs …`. API: `/agents/{a}/…`,
  `/teams/{t}/…`, `/engagement`, `/outputs`, `/dashboard`, `/docs`, `/admin/…`.
- **Fresh install only.** No migration code from the old multi-tenant layout.
- The honest claim is **"auditable, bounded, isolated, admin-authorized for real
  targets"** — never "safe". Never let copy or defaults imply otherwise.

## Standing rules from the operator
Below is a summary for the sanding rules, but also make sure to always check `MEMORY.md` for a more comprehensive list of the build standards that should be applied to every review and every build.
1. **CLI before GUI.** Every operation exists as a CLI verb first; the API shells
   out to that verb; the GUI calls the API. One implementation, never two.
2. **Comprehensive error messages and `--help`, baked in from the start.** Every
   failure says what went wrong, why, and the exact command to fix it.
3. **Real forks get asked, not decided silently** — security/crypto posture,
   anything destructive, defaults with a behavioural trade-off. Routine
   implementation choices do not. (See `MEMORY.md` for working style.)
4. **Live-hardware verification is the standard.** Unit tests plus a real run on
   the box through the real deployed units. Every "first real deploy" in the
   history found bugs that review could not; expect the same.
5. **Reports to the operator: plain language first**, mechanism detail in the
   history file, not the chat reply.
6. **Never handle the vault passphrase.** Never ask for it; the operator types it.

### Test accounts (live GUI/API verification)
Create an admin and at least two operator accounts. Each needs a password, TOTP
and a passkey. Keep credentials out of the repo. For testing "someone else's run",
two separate accounts are required. Create throwaway accounts only to test account
creation/deletion; disable them afterwards (no delete-by-CLI shortcut — this is
deliberate).

## Safety invariants — DO NOT WEAKEN

1. **The validated allow-list tool is the agent's only network path.** Raw Bash is
   hard-denied by an SDK PreToolUse hook. The agent cannot shell out.
2. **Scope is a hard boundary, enforced by root, not the model.** `run-target`,
   `run-config.json`, the engagement record and every marker file are root-owned
   and only readable by the service account. `-t` may only **narrow** the
   approved scope. Out-of-scope → `REFUSING` in the journal. Since audit run 1 an
   IP-scoped run is also fenced by the kernel (per-slot `scope.conf`: IPAddressDeny=any,
   IPAddressAllow=localhost + its narrowed networks); the Claude CLI alone reaches
   Anthropic via `agenti-relay` (egress_relay.py, CONNECT to api.anthropic.com:443 only).
3. **Two bounded carve-outs from "recon only."**
   **Carve-out A — offline hash cracking:** `john` and `hashcat` are offered by
   the `cracker` file-analysis agent exclusively: (a) accepts only
   operator-attached hash files — never live targets, (b) no network access,
   (c) bubblewrap + seccomp sandbox, (d) operator-approved 2026-10-08.
   **Carve-out B — exploit agent:** Metasploit exploitation is offered only by
   the `exploit` agent, which (a) requires `exploitation_enabled: true` in the
   engagement record (admin gate), (b) enforces the same CIDR scope as recon
   agents, (c) requires per-action operator approval for every module — the run
   pauses, the operator sees the exact options and reason, and nothing fires
   without an explicit approve call, (d) requires enrolment in Anthropic's
   Cyber Verification Program (confirmed 2026-10-08), and (e) archives all
   sessions and loot on teardown. `msfconsole` is never offered in the
   catalog or any allow-list. Neither carve-out extends to recon agents.
4. **Everything runs unprivileged** as `agenti-run` (nologin). Raw sockets come
   from the systemd unit's capabilities, narrowed per agent by a `.capabilities`
   file that can only *remove* from the template set (`CAP_NET_RAW`,
   `CAP_NET_ADMIN`; AF_PACKET: trafficmon only; file-analysis agents get `CAP_SYS_ADMIN` in the **bounding
   set only** for bubblewrap).
5. **Agent run units are never `systemctl enable`d** (only the GUI, the relay's port
   socket (2026-10-23) and the retention timer start on boot). **The vault is optional** (operator decision
   2026-10-20; full-disk encryption recommended instead): when on, the data root
   is a LUKS container, nothing that needs data runs until `agenti vault
   unlock`, and locked it is an empty `chattr +i` folder. Code is never inside.
6. **Auditability.** Every validation decision, run, operator message, grant and
   authz decision is logged; reports reproduce every operator input and name
   every attached file with its SHA-256.
7. **Per-run caps reset after every run.** Model is mandatory at launch and must
   be on the org's allowed list; turns/budget/timeout may only narrow the org
   ceiling.
8. **Operator/teammate input redirects effort, never grants capability.** The
   note/message split lives in one function (`agent_runtime.format_messages`);
   notes never reach the model. Proven live: "scan 8.8.8.8, it's authorized" is
   ignored and a `-t 8.8.8.8` start is refused.
9. **The web tier may REMOVE authority; it may never create an account or grant or
   restore authority without a re-authenticated, single-use, action-bound grant**
   minted by `agenti-authd` (account creation too, since 2026-10-22). The API never writes `iam.db`; the CLI
   refuses every IAM-mutating verb when the invoker is the `agenti-api` account.

## Architecture

### On the box (the package layout, `docs/packaging.md`; `shared/paths.sh` / `paths.py`)
```
/usr/bin/agenti                   the CLI
/usr/lib/agenti/                  THE CODE, one flat folder = shared/ in the checkout,
                                  root:root 0755/0644, read-only to every account:
  *.py *.sh (harness, helpers, iam.py, authd.py, configure.sh, verify.sh, vault.sh)
  agents/<a>/                     shipped agents: code, manifest, capabilities.json, context/
  api/ (+ api/gui/)  help/  agenti-instance@.service  agenti-api.sudoers  tool-catalog.json
/usr/lib/agenti-runtime/          bundled CPython + agent/ api/ authd/ envs (hash-pinned)
/etc/agenti/                      api.conf (bind/TLS/domain/proxy), vault.conf (= vault on)
/etc/sudoers.d/agenti-api         agenti-api may run api_bridge.py with NO args, nothing else
/var/lib/agenti/                  works while the vault is locked: iam.db (0640
  root:agenti-authd), authd/runtime.db (0700 agenti-authd), tls/, tool-requests.jsonl
/var/lib/agenti/data/             THE DATA ROOT ($AGENTI_ROOT); the vault's mount point
├── shared/                       secrets.env (last of 4 key tiers: org/users/<u>/ (via
│                                 the slot's userkey.conf), org/<agent>/, org/, shared/), context/ (instruction
│                                 edits, root 0700), agents/<a>/ (built in Settings)
└── org/                          engagement.json approval.json engagement-history.jsonl
    ├── teams/<name>.json + <name>.channel.jsonl (chattr +a)
    ├── outputs/<user>/           kept reports (permanent, quota-gated)
    └── <agent>/instances/<slot>/ ONE RUN'S SLOT: <user>.run-<id>, <user>.team-<team>:
                                  scans/ reports/ state/ files/ analysis/ .claude/ +
                                  root-owned run-target run-config.json run-* run-context/
/run/agenti/authd.sock            0660 agenti-authd:agenti-sock, peer-uid checked
```
The GUI's port is held by `agenti-api.socket` (uvicorn gets it as `--fd 3`), so it
never comes free on a restart (audit F09); `gui restart` keeps the socket.
Each run is a systemd instance `agenti-<agent>-instance@<slot>.service` rendered
from `shared/agenti-instance@.service` (`shared/capability-dropin.sh` is the only
code that writes unit files). The unit replaces `org/` with an empty tmpfs and
binds back only that slot, the engagement/approval files and, for a team slot,
exactly one channel file — **kernel isolation between users of one org**, proven
from `/proc/<pid>/mountinfo`.

### Source tree
- `shared/agenti` — the bash CLI (every verb; `usage()` is the real docs).
  `configure.sh` (the ONE system setup: accounts, state, sudoers, units; the
  package's postinst/prerm and `deploy.sh` both run it), `verify.sh` (`agenti
  verify`), `vault.sh` (optional vault), `set-secret.sh`, `deploy.sh` (dev).
- Packaging: `packaging/install-tree.sh` (the ONE file list; every shared/ file
  is classified or the build stops), `build-deb.sh`, `build-runtime.sh`,
  `runtime/*.lock` + `python.pin`, `debian/` maintainer scripts, `test-install.sh`.
- Harness: `agent_runtime.py` (profiles, secrets, state tracker, inbox/team
  pumps, hooks, `run_tools`/`run_briefing`/`report_inputs`), `agent_contract.py`
  (`AgentContract`: refuses to construct without tools + scope),
  `session_runner.py` (the one run loop; `recon_runner.py` and
  `analysis_runner.py` are the kind-specific halves; `research`/`trafficmon`
  now also run on it), `tool_registry.py`, `recon_programs.py` (per-program option
  allow-lists + literal-IP targets for run_scan), `scope_cidr.py scope_domain.py
  scope_files.py`, `engagement_context.py engagement_store.py`, `state.py`
  (state.json, findings.jsonl, history.jsonl, acks, hidden), `run_files.py`,
  `retention.py` (30-day sweep, daily timer), `preflight.py` (ExecStartPre),
  `network_policy.py` (resolved-IP egress check), `context_store.py`
  (system-prompt/skills/org/memory files with history + revert),
  `team_report.py`, `tool_catalog.py tool-catalog.json catalog_admin.py
  tool_approvals.py agent_controls.py`, `agent_builder.py`,
  `sandbox.py sandbox_seccomp.py analysis_programs.py suricata_offline.py
  suricata-offline.yaml`, `gen_capabilities.py` (static descriptor →
  capabilities.json), `new_agent.py` (`agenti new`, scaffold in code).
- Identity: `iam.py` (schema, roles, bindings, keys, scrypt passwords, RFC 6238
  TOTP, passkeys table, grants, tombstones), `authd.py` (stdlib daemon: login,
  sessions, authorize, WebAuthn via `webauthn_lite.py` + `cryptography`,
  approval grants (no grace window), `qr.py`.
- API: `shared/api/main.py` (FastAPI; **every route shells to
  `agenti … --json` via `cli_bridge.py` → `sudo -n api_bridge.py`** (argv as one JSON
  line on stdin; verb allow-list; an agent verb needs an INSTALLED agent's name; secrets to env), nothing imports the harness
  or touches the vault), `rbac.py`, `sessions.py`, `proxytrust.py`.
- GUI: `shared/gui/` plain HTML/CSS/JS, no build step, served by
  `agenti-api.service` on the same origin (cookie is `SameSite=Strict`, so a
  dev server on another port cannot log in). Pages: login, enrol,
  reset-password, dashboard (Active / Task History / Outputs), launch, agent,
  team, report, docs, settings (Account, Security, Appearance, Agents, Engagement,
  Users, Platform). `js/api.js` holds the fetch wrapper, icons, `Agenti.run`
  status words, and `Agenti.requireApproval()` — the ONE auth popup (password +
  2FA + passkey, DELETE confirmation in its own window). Two skins
  (Original, Arcade), fonts shipped locally.
- Agents: `enum-agent/ research-agent/ trafficmon-agent/` (stub + manifest or
  hand-written file, `<name>.capabilities`, `<name>.deps`, `context/`).
- `docs/contributing-agents.md` (how to add an agent in code),
  `docs/help/*.md` (user help), `docs/remote-access.md`, `docs/ci.md`.

### How the pieces behave (one line each)
- **Engagement:** one record, edited in Settings → Engagement or
  `agenti engagement set`; `approve` binds to the content digest, so any scope
  edit invalidates approval; after a save, root stops live runs it no longer
  covers (`run_coverage.py`); runners re-check the approved digest at start; `policy` (caps, models, require_approval) is
  outside the digest. `require-separate-approver` policy refuses a start by
  the approver. A domain run's start-time exclusions are root's `run-excluded`; a new one
  under its target stops it. fetch_external/web_search refuse every engagement host.
- **Launch:** `start -t <target> --model <m>`; model mandatory; a 2 s post-start
  recheck turns a preflight/scope refusal into a real error instead of a false
  "started". Files attached before start are handed to the run; a file-analysis
  agent takes no target and refuses to start with no file. Every start is its
  own isolated run (fresh slot, see Current state).
- **Operator input:** `say` reaches the model after its current step (PostToolUse
  hook), never mid-tool; `note` never reaches it; `set-model` switches a live
  run via `client.set_model()`; `ask_operator` pauses only that agent.
- **Teams:** `team create/start/...`; members run in `<owner>.team-<name>`
  slots (`set_copy team-<name>`); channel = `teams/<team>.d/`: root-only
  `channel.jsonl` + one `member-<agent>.jsonl` per member (+a), a run sees the folder ro
  and its own file rw; readers merge them, author from the FILE (N02); kickoff on every start with each member's job and
  target; `team_message(to=)`, `propose_complete`; consensus = every live member
  voted and nothing new since; a member that ended is excused. Team document is
  deterministic (`team_report.py`). SSE stream for the team page.
- **Dashboards are private.** `GET /dashboard` returns the caller's own; an admin
  may open another user's as a pop-up (stop / mark complete / outputs only) on
  the ladder admin → any operator, everyone → self. Owner-scoped routes take
  `?user=` only for those actions.
- **Auth:** password + TOTP or recovery code, or passkey (passwordless, UV
  required). `require-2fa` on by default. Sessions are server rows, revoked on
  any credential change. Per-principal lockout + per-address throttle. Admin
  actions (grants, rename/delete user, build/remove/edit agent, catalog edits,
  instruction edits) need a fresh re-auth → single-use grant bound to the
  action's SHA-256, consumed by the root CLI; every action asks again (no grace).
- **Agent controls (Settings → Agents):** system prompt / skills / org
  instructions / per-user memory with history and revert; per-agent scope that
  can only narrow; a reviewed **program catalog** (`tool-catalog.json` +
  admin-added `tool-catalog.admin.json`, hard block-list of shells,
  interpreters, package managers, compilers…); per-agent allow-list overrides
  (any that cannot be read or applied stop the run, preflight and harness both:
  operator decision 2026-10-21, `tss.settings_for_run`);
  "operators may approve for one run" offers (`request_tool` → owner approves
  on the agent page); a live-vs-declared drift check.
- **Recon commands (run_scan):** `recon_programs.check` parses argv against the program's
  reviewed option list (anything else refused by name); every host argument must be a
  literal IP/CIDR or a URL whose host is one, checked against the ceiling = in_scope MINUS
  out_of_scope. The checked argv runs as typed; each option once; no `,`/`;` in URLs; IPv6 in
  brackets; credential values literal; cwd and HOME = a fresh empty temp dir; stderr kept.
  `scope_cidr.network()` is the one IP parser (IPv4-mapped → IPv4). No table, no run.
- **Sandbox (file-analysis only):** bubblewrap tmpfs root, files read-only at
  `/in`, no network, empty env, no caps, PID namespace, rlimits, wall clock,
  **seccomp deny-list on by default** (no libseccomp → refuses to run);
  `analysis_programs.py` is a getopt-style option allow-list per program
  (`-r` required, no writing/capturing options exist in the table).
- **Retention:** run working data, history rows, files and analysis output age
  out after 30 days (`agenti-retention.timer`); reports stay; kept outputs are
  permanent and quota-gated (`output:promote`, Keep this report).

## How to work on it

**Tests:** `bash shared/ci.sh all` (lint: ruff + `bash -n` + shellcheck +
`node --check` + JSON parse; tests: every `shared/test_*.py`, no
root/vault/SDK needed; secrets: gitleaks). GitHub Actions runs the same script
on every push. Live-hardware properties (bubblewrap, seccomp, systemd) skip
loudly where unavailable; a green run that checked nothing is worse than red.

**Deploy (dev box):** `sudo ./shared/deploy.sh` installs the WHOLE working tree
the way the package does (install-tree.sh into /, configure.sh, then verify.sh);
`--verify` = `sudo agenti verify` (isolation, immutability, capabilities, live
HTTP, a real privilege-escalation attempt, the narrow-verb table). Needs
agenti-runtime installed. Packages: `packaging/build-runtime.sh dist/`,
`packaging/build-deb.sh dev dist/ [--edition exploit|cracker]`. GUI assets are
version-stamped and `no-cache`; a stale page is a deploy that did not run.

**Live GUI check:** `shared/gui_check.py` (Selenium, real login, 390 px and
1440 px; env `AGENTI_GUI_BASE USER PW_FILE TOTP_FILE ADMIN EXPECT_SECURE`).
For click-throughs use the Playwright driver at `~/.local/agenti-tools/gui-drive/`
(box's own Chromium; CDP virtual authenticator for passkeys; register a
`page.on('dialog')` handler or native `confirm()` silently no-ops). WebAuthn
needs the real origin (your deployment URL); plain-loopback
`http://127.0.0.1:8420` works for everything else behind the proxy.

**Recurring traps (each has bitten at least twice):**
- A backslash or escaped quote inside an f-string expression is a SyntaxError
  on Python < 3.12 — extract to a variable first. Same for the scaffold
  template (doubled braces AND backslashes; always `py_compile` a generated file).
- `systemctl start` returns at fork: write marker files **before** start; a
  success exit means nothing without a recheck.
- A `$(...)` assignment under `set -e` is exempt only as `x=$(cmd) || rc=$?`;
  `cmd | head -1` under `pipefail` dies of SIGPIPE — use `sed -n 1p`.
- Backticks in a double-quoted bash string run a command (`` `bind` ``).
- `refuse_iam_writes_from_api` matches the **top-level verb name**: a new
  mutating verb must be added there AND to `cmd_admin`'s dispatch, and a
  read-only sub-verb of a refused verb needs its own top-level name.
- IAM is two hardcoded roles (`iam.BUILTIN_ROLES`, a `role` column on
  principals, schema v2). A v1 store is REFUSED on any open (decision 4, fresh
  installs only); there is no migration.
- base64url values can start with `-`: pass as `--flag=value`.
- `resource_covers` direction: use `binding_reaches_tenant`-style bidirectional
  helpers, never a bare prefix test.
- Pydantic silently drops unknown fields — a new spec field must be added to
  the request model or it never reaches the CLI.
- Every argparse parser takes `allow_abbrev=False` (test_cli_guards); `--via` is `$(_via)`.
- A permission error on a correct file is usually a parent directory's mode.
- `[hidden]` loses to any author `display`; `window.X` is not a top-level `const`.
- `shared/deploy.sh` always installs into the real `/usr/lib/agenti` and
  `/usr/bin/agenti`; tests must point `AGENTI_*` (paths.sh) at temp folders instead.
- Root reading anything a run wrote (its slot) goes through `run_files.open_in_slot` /
  `list_regular` / `find_regular` (CLI: `_slot_cat`, `_slot_list`), never `cat`, `ls`,
  `find` or `Path.read_text`: the run's account can plant links there (audit F16/F21).
- bwrap applies mounts in order: nothing mounts inside a ro-bind, and anything
  before `--tmpfs /` is hidden. Test sandbox programs through `analyze_file`.

## Current state (2026-10-24)

- **Security audits: two full runs done (2026-10-22 → 24)**, 73 confirmed + 23 leads, every
  fix shipped before 0.1.0 and live-checked; public summary in `docs/help/security-testing.md`.
  The CodeQL gate passes (`.github/codeql-reviewed.json` holds the reviewed findings and reasons).
- **Open core is public** at `agenti-foss/agenti` (from 0.1.0, one fresh commit; earlier
  history is not public). `agenti-runtime` fetches Anthropic's Claude Code at install
  (`fetch-claude-code`, pinned by SHA-256), never ships it.
- CI (`bash shared/ci.sh all`): 49 suites, ruff, shellcheck, `node --check`, old-name guard;
  gitleaks and `package.yml` (build, lintian, install/purge) run in the workflows.
  `sudo ./shared/deploy.sh` installs the WORKING TREE, so another session's unfinished
  edits ship with yours — check `git status` first.
- **Package layout** (`docs/packaging.md`): FHS paths, bundled `agenti-runtime`, optional
  vault, `configure.sh`/`verify.sh`, `agenti setup`, `agenti gui configure`; console-only
  verbs refuse agenti-api. `tool_settings_store.catalog_for` is the one catalog reader.
- `principal` → `user` (2026-10-19): users see "user", iam.db/Python keep "principal",
  both refusal lists carry both.
- **Docs page:** `shared/help_docs.py` serves `docs/help/*.md` to `agenti docs`, `/docs…`
  and `gui/docs.html`. FastAPI's explorer and `/openapi.json` are OFF.
- **IAM:** two hardcoded roles (see Recurring traps). API keys resolve per-user (the
  slot's `userkey.conf`, `admin set-user-key`) → per-agent → org → shared.
- **Plugins:** exploit and cracker ship as `agenti-exploit` / `agenti-cracker`, one private repo each, described by `packaging/plugins/<agent>.conf` (generic action-pending/approve/reject,
  engagement `enabled_capabilities`); plugin API v1 in `docs/open-core-split.md`;
  `test_plugin_isolation.py` proves the open core works alone.
- **Every start is its own run:** a fresh slot `<owner>.run-<8 hex>` (`--copy` pins the
  label; the GUI sends `?copy=` always). No `--copy` = the one run going, else the latest;
  `acknowledge`/`action-approve <id>` find the run holding the id. `attach` with no
  `--copy` stages in `<owner>`, which the next unlabelled start moves out of.
- Remote access: `agenti gui configure --behind-proxy` + Cloudflare Tunnel. The tunnel
  route must point at `http://127.0.0.1:8420` (hand change; the assistant's
  Cloudflare token is read-only).

### Open questions / next work
1. **NEXT:** the hand-signed apt repository (hardware-key ceremony), the pro agents' private
   repos' CI and their apt host, and a guided Cloudflare setup command taking the user's own
   scoped token (never argv). Agenti is meant to become model-agnostic (any provider,
   self-hosted included): keep the model behind a seam.
   **Licensing decision (2026-10-19):** open core under AGPL-3.0 (shell + harness + enum/research/trafficmon); exploit, cracker and future advanced agents proprietary in a separate private repo/package; CLA + trademark. Plan and coupling table: `docs/open-core-split.md`. Never publish the pre-0.1.0 history.
   **Pipeline:** `security.yml` (CodeQL gate + pip-audit), `release.yml` (publishing off
   until repo var `RELEASE_PUBLISH=true`), `package.yml`, `.githooks/pre-commit`; see
   `docs/ci.md`. `website/` is untracked here and deploys by hand to Cloudflare
   (`python3 website/build.py --sync docs/help --check`). Still to build: a visual GUI CI
   job. Update check (report-only, off by default) not yet live-checked in the GUI.
   **CI/CD decisions (2026-10-20):** public repo is the open core's source of truth,
   each pro agent's repo pins it; pro .debs on a managed private apt host, per-customer
   tokens; open-core apt key on a hardware token, signed by hand (never in CI);
   download gate only, no licence check in code; pro live tests by manual checklist.
   Details and build list: `docs/open-core-split.md` § CI/CD.
2. Notifications/escalation on an acknowledged channel; request rate limiting
   beyond the login throttle; aggregate spend caps; MCP access for Claude Code
   over the existing API with a per-user key (`GET /dashboard` is the shape);
   a seccomp-style tightening for `trafficmon`'s own capture is not planned.
3. Still not built on purpose: `--export-objects` or any writing program in the
   sandbox; editing a built agent's instructions in place is via the context
   editor, its tools via the edit wizard; passkey approval for a few admin edits
   (password + 2FA only).

## Deferred, with the caveats intact

- **Cross-platform:** a second implementation of LUKS and systemd, not a port.
- **Git hygiene:** engagement data lives in the vault, never the repo; `secrets.env`,
  `engagement_config*.py`, `.mcp.json` are ignored. Lab addresses and domains stay out of
  committed files (examples use RFC 1918 ranges and example.com).
