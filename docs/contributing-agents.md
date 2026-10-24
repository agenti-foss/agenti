# Writing an agent in code

Most new agents don't need code. If what you want is "run these reviewed
programs against a target", build it in **Settings → Agents → Build an agent**
(see `docs/help/building-agents.md`) — that is data, runs through the same
reviewed runner as `enum`, and can't be talked into doing more.

Write an agent in code only when a program list can't express it: a different
scope kind (a domain, a log source), a custom tool, or a protocol client. This
page is the short version of how.

## The shape of an agent

Four kinds exist today, all on one shared harness:

| Agent | Kind | Scope | Tools |
|---|---|---|---|
| `enum`, a recon agent built in the GUI | recon, data-driven (`manifest.json` + a 3-line stub over `shared/recon_runner.py`) | CIDR | `run_scan`, `read_scan` |
| a file-analysis agent built in the GUI (e.g. the Pcap analyser) | analysis, data-driven (`manifest.json` + a stub over `shared/analysis_runner.py`) | the run's attached files | `analyze_file`, `read_output` |
| `research` | hand-written | domain | `fetch_page`, `read_page`, `web_search`, `fetch_external` |
| `trafficmon` | hand-written | CIDR | `list_evidence`, `read_evidence`, `capture_host` |

A hand-written agent is one file, `<name>-agent/<name>-agent.py`, built from:

- **`shared/agent_contract.py`** — `AgentContract`: the allow-list of tools, the
  scope boundary and the profiles. It refuses to be built without them. It
  also derives the MCP server and the PreToolUse hook that hard-denies every
  other tool (raw Bash included).
- **`shared/scope_cidr.py` / `scope_domain.py`** — the scope boundary. Scope is
  pluggable but never optional; a new kind is a new file with the same
  `ScopeBoundary` methods (`ceiling_from_engagement`, `narrow`, `contains`).
- **`shared/tool_registry.py`** — the vetted tools. Add yours here with its
  scope kind, whether it needs the network, and a `build(ctx)` factory.
- **`shared/agent_runtime.py`** — everything every agent shares: run-config,
  secrets, audit log, state, the operator and team channels, the report header.

## Start from the scaffold

```
agenti new <name> --scope cidr|domain --description "one line"
```

This writes `<name>-agent/` with a runnable skeleton and one stub tool. Read
`new_agent.py`'s output top to bottom; every `TODO` needs your attention.

## What must keep holding

These are the project's invariants (CLAUDE.md §1). A pull request that weakens
one will not be merged:

1. The validated allow-list tool is the agent's **only** network path. No raw
   shell, ever.
2. **Scope is enforced outside the conversation**, from root-owned files. A
   target may only *narrow* the engagement's scope.
3. **Recon is recon.** Nothing in a reviewed program list or a tool exploits,
   brute-forces or disrupts a target.
4. The agent runs unprivileged; it cannot write its own scope, caps or model.
5. A report is written on **every** outcome, including a crash or a stop.
6. Anything a person or another agent types reaches the model only as advice
   (see `agent_runtime.format_messages`); it never widens a tool or the scope.

## Tests

The suites need no root, no vault and no SDK — they install a structural fake
of `claude_agent_sdk` (see the top of `shared/test_tool_registry.py`). Add
tests for:

- every tool you add (including what it refuses);
- the scope kind's narrowing and its label-boundary edge cases;
- a descriptor check (`shared/test_capabilities.py`) so the Tools &
  permissions panel shows what your agent can really do.

Run everything: `for t in shared/test_*.py; do python3 $t || echo FAIL $t; done`.

## Deploy

From a source checkout, on the box (the bundled Python, agenti-runtime, must be
installed once: `packaging/build-runtime.sh dist/` then
`sudo apt install ./dist/agenti-runtime_*.deb`):

```
sudo ./shared/deploy.sh          # installs this checkout the way the package does
sudo ./shared/deploy.sh --verify # = sudo agenti verify
```

A new shipped agent also goes into `OPEN_AGENTS` in `packaging/install-tree.sh`
(its `<name>.deps` becomes the package's Recommends).

Then set and approve the organisation's engagement (`agenti ... engagement
set`), and launch with `agenti ... <name> start -t <target> --model <model>`.

## Adding a program to the recon kind

Recon agents (`run_scan`) don't take a program *name* on trust either. Each
program has an entry in `shared/recon_programs.py` listing the options it may be
given and what every plain argument means; a program without an entry cannot
run, and the catalog's **Add a program** refuses it.

- List only options that observe. Leave out anything that writes a file, sends
  data, uploads, executes on the target, follows redirects, uses a proxy or a
  different DNS server, reads a target list, or runs scripts that pick their own
  targets (for `nmap`: `-iL`, `-iR`, `--dns-servers`, `-oN`, `-sC`, `-A`,
  `--script` beyond the reviewed names ...).
- Every argument that names a host the program contacts must be a `target`,
  `url` or `ldapurl` value (or the program's positional kind): those are parsed
  as literal IPs and checked against the scope, exclusions included.
- Add the program's tests to `shared/test_recon_programs.py`: ordinary commands
  accepted, each dangerous option refused by name.

## Adding a program to the file-analysis kind

File-analysis agents don't take a program *name* on trust. Each program has an
entry in `shared/analysis_programs.py` listing exactly which options it accepts
and what each value must be; everything else is refused by name. Add yours
there, with its reviewed options, and a form can then offer it.

- List only options that read. Leave out anything that writes a file, captures
  live, lists the host, loads a script or runs code the input supplies (for
  `tshark`: `-w`, `-i`, `-D`, `-X`, `-F`, `--export-objects` ...).
- Mark every option that names a file as `file`: its value is then confined to
  a file attached to the run and rewritten to its sandbox path.
- Add the program's tests to `shared/test_analysis_programs.py`, including each
  dangerous option, which must fail by name.
- Programs that execute code they are handed (interpreters, scripting engines,
  password crackers) do not belong here without a deliberate decision.

The rules are defence in depth. The boundary is `shared/sandbox.py`: no network,
no vault, read-only input, hard CPU/memory/output/time limits. It needs
`bubblewrap`, and the agent's unit needs `CAP_SYS_ADMIN` in its bounding set
(`capability-dropin.sh`, applied automatically to an agent built with this
kind).
