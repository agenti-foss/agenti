# Open core / closed agents: the split (plan, 2026-10-19)

Decision (operator): open-source the shell, the harness and the basic recon agents
under AGPL-3.0; keep the exploit agent, the cracker and future advanced agents
proprietary, sold as a separate edition. Name protected by trademark; contributors
sign a CLA so the project can relicense its own code.

## What is open

CLI, API, GUI, identity and authd, vault, engagement/approval records, the harness
(scope enforcement, validation, runners, sandbox, tool registry/catalog, agent
builder), and the `enum`, `research` and `trafficmon` agents. Rationale: the
safety-critical code stays auditable, and the community can build its own agents.

## What is closed (separate private repo, separate package)

`exploit-agent/`, `cracker-agent/`, `exploit_runner.py`, `msf_client.py`,
`msf_module_catalog.py`, `hash_extract.py` and their tests; their help pages.

## Why it is not a file move: coupling in the open core today

These open files reference the closed agents and must become generic extension
points before the repo can be published without them:

| Area | Files | What to do |
|---|---|---|
| CLI verbs `exploit-pending/approve/reject` | `shared/agenti` | Make "agent proposes an action, human approves" a generic verb set; the exploit agent registers into it |
| API/GUI approval flow | `shared/api/main.py`, `shared/gui/js/agent.js` | Generic pending-approval routes and banner |
| `exploitation_enabled` | `engagement_context.py`, `engagement_store.py`, `settings.js` | Keep as a generic per-engagement "enabled capabilities" list the closed edition adds to |
| Sandbox programs `john`/`hashcat` | `analysis_programs.py`, `sandbox.py`, `analysis_runner.py`, `tool-catalog.json`, `tool_registry.py` | Move the cracker's program table into the agent package; open core loads extra tables from an install directory |
| Capabilities and deploy | `gen_capabilities.py`, `packaging/install-tree.sh` | Discover agents from a directory instead of a hard-coded list |
| Policy/identity | `iam.py`, `authd.py` | Remove exploit-specific strings; approval grants stay generic |
| Docs | `docs/help/*`, `CLAUDE.md` | Move exploit/cracker pages to the closed repo |

## Order of work

1. Generic extension points in the open core (agents loaded from a directory;
   registered approval flow; program tables from files). Tests prove the open core
   works with no closed agent installed, and the closed agents work through the
   same points.
2. Move the closed files to the private repo; add a CI job there that runs the
   open core's suites against it.
3. Packaging: `agenti` (open) and `agenti-agents-pro` (closed, private apt source).
4. Site: say which agents are free and which are paid; update the Requirements
   and Licence text.
5. CLA text (lawyer-reviewed) and CLA bot; trademark registration.
6. Publish `agenti-foss/agenti` after the open-source audit.

## Risks to keep in view

- The history of the current repo contains the closed agents. Publish from a fresh
  repo (or scrubbed history), never push the existing history.
- AGPL on the open core plus a closed plug-in: a lawyer should confirm the plug-in
  boundary (the closed agents are the project's own code, so the project may license
  them separately, but any outside contribution to shared files needs the CLA).
- "Auditable" remains a true claim only if the enforcement code stays open; do not
  move scope or validation logic into the closed package.

## CI/CD and distribution (operator decisions, 2026-10-20)

| Decision | Choice |
|---|---|
| Source of truth | The public repo `agenti-foss/agenti` is where the open core is developed. Each closed agent has its own private repo (`agenti-exploit`, `agenti-cracker`; operator, 2026-10-24: sold individually) that pins it at a tag. No export or sync tooling. |
| Paid-package hosting | A managed private apt service (Cloudsmith/Gemfury class) with one token per customer. Revoking a token stops that customer's updates. |
| Signing | Two keys. The open-core apt key lives on a hardware token and the operator signs each release by hand; CI never holds it. The pro repo is signed by the managed host's per-repo key (or an uploaded one). |
| Entitlement | Download gate only. No licence check in the code. If a licence file is ever added, it must never gate scope or validation. |
| Pro live tests | A manual release checklist on the box. No self-hosted runner. |

### How it runs

- **Public CI** (`ci.yml`, `security.yml`): must pass with no closed code present
  (`test_plugin_isolation.py`). It needs no secret, so pull requests from forks work.
- **Private CI**: check out the public repo at the pinned tag, add the pro files where
  `packaging/install-tree.sh --edition <agent>` expects them (the repo brings its own
  `packaging/plugins/<agent>.conf` and `packaging/debian/agenti-<agent>/`), run `shared/ci.sh all` (open suites plus closed suites).
  A nightly, non-blocking run does the same against public `main` so an extension-point
  change shows up before a release. gitleaks and pip-audit as in public; Semgrep or
  bandit instead of CodeQL (CodeQL on a private repo needs GitHub's paid add-on).
- **Compatibility**: the open .deb declares `Provides: agenti-plugin-api-N`; the pro
  .deb declares `Depends: agenti-plugin-api-N`. N changes only when an extension point
  changes incompatibly, so apt refuses a mismatched pair.
- **Open release**: tag → `release.yml` builds and attests the .deb and the unsigned
  repo metadata → the operator downloads, checks the attestation
  (`gh attestation verify ... --signer-workflow agenti-foss/agenti/.github/workflows/release.yml --source-ref refs/tags/v<version>`, audit N11), signs `InRelease` with the hardware key, publishes.
  The key's fingerprint is published on the website's download page.
- **Pro release**: the live checklist runs on the box with both packages installed →
  tag → build a .deb holding only closed files → attest → upload to the managed host
  with an approval-gated GitHub environment token.
- **Development on the box**: two clones side by side; `shared/deploy.sh` takes the pro
  clone's path so live verification still covers both.

### The plugin API version

`shared/PLUGIN_API_VERSION` (now `1`; `agenti --version` prints it) is what the
open .deb `Provides` and the pro .deb `Depends` on. Version 1 is everything a
closed package relies on:

- the files it adds: `<agent>-agent/` folders (agent code, `manifest.json` with
  `module_catalog`, `<agent>.capabilities`, `<agent>.deps`, `context/`), harness
  modules beside the open ones, help pages in the help folder;
- the extension points: `enabled_capabilities` in the engagement,
  `analysis_programs.load_plugin_programs`, the action-approval flow
  (`pending-actions.jsonl`, `action-pending|approve|reject`, the API routes and
  the agent page's banner), authd's generic approval grants;
- the harness functions the closed modules import (`session_runner`,
  `agent_runtime`, `agent_contract`, `tool_registry`, `scope_cidr`).

Bump it, in the same change, whenever one of these changes in a way a package
built against the previous release would not survive. The private CI's run
against the pinned tag is what catches a missed bump.

### To build

1. Done 2026-10-20: `PLUGIN_API_VERSION` in the open core and the `Provides`/`Depends` pair.
2. Done 2026-10-20, split per agent 2026-10-24: `packaging/build-deb.sh` builds the open package and, with `--edition <agent>`, each closed one;
   each agent's conf, maintainer scripts and files live in its private repo.
3. `shared/deploy.sh` option for a separate plugins directory (today it installs the
   closed files from the same checkout when they are present; `--open-only` skips them).
4. The private repo's CI workflow (pinned and nightly jobs).
5. Release checklist for pro live tests; key ceremony doc (generate on the token,
   offline backup, revocation certificate, fingerprint on the website).
