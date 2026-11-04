# Any model: one Agenti, many AI providers

Status: design agreed 2026-11-04; phase A live-proven on Claude and OpenAI;
phase B complete and VM-proven; the small self-hosted model has limitations noted below.
This file is the plan
and the hand-off brief: whoever continues (a person, Claude Code or Codex)
starts here, then `AGENTS.md` / `CLAUDE.md`.

## What the operator asked for (decisions, 2026-11-04)

1. **One Agenti, one backbone.** Never a "Claude edition" and an "OpenAI
   edition". Everything that keeps a run safe and auditable is shared and does
   not know which model it is talking to; only a thin adapter per provider does.
2. **Providers now:** Claude (Anthropic), ChatGPT models (OpenAI), and
   self-hosted models (anything that speaks the OpenAI-compatible Chat
   Completions API: Ollama, vLLM, LM Studio, llama.cpp server, LiteLLM...).
   More later through the same seam.
3. **The OpenAI path is Agenti's own engine** (not the Codex CLI): Agenti calls
   the API and offers the model only Agenti's own checked tools. The same engine
   serves self-hosted models.
4. **API keys only** (no ChatGPT-account sign-in). Same key tiers as Claude
   today: per user, per agent, org, shared.
5. **Any model, chosen at launch.** The launch page asks for the provider
   (Claude / ChatGPT / self-hosted) and the model, listed live from the
   provider, any model name accepted. A team may mix providers: a Claude enum, a
   GPT research agent and a self-hosted cracker in one team.
6. **The console (next, after this):** a session-style view, like a Claude
   Code / Codex session (the model's steps, tool calls and outputs streaming;
   you type messages; `/model` switches model mid-run). Not a real terminal:
   a real CLI's shell mode and permission commands would step around the
   per-command checks. Today's console stays for self-hosted models.
7. **The exploit agent may run on any model, with no provider check** (it used
   to require Anthropic's Cyber Verification Program). Its other gates stay:
   `exploitation_enabled` in the engagement, CIDR scope, per-action operator
   approval, archived sessions.

## The shape

```
            launch / team (provider + model per run)
                              |
  run-config.json  ->  session_runner.run_session(Session)      <- ONE loop for every agent
                              |
              model_session.open_session(engine options)        <- picks the engine by provider
               /                         \
  engine_claude.py                 engine_openai.py
  (Claude Agent SDK, as today)     (Agenti's own loop over Chat Completions,
                                    OpenAI and self-hosted alike)
               \                         /
        the SAME tools (agent_tools.tool), the SAME guard (PreToolUse
        allow-list hook), the SAME inbox delivery (PostToolUse hook), the
        SAME ledger/report, the SAME kernel fence and egress relay
```

### What stays exactly as it is (and must)

Every safety invariant in `CLAUDE.md` holds for every provider, because none
of them lives in the model adapter:

| Invariant | Where it lives (provider-blind) |
|---|---|
| 1. Only the allow-listed tools; no shell | The model is offered only `agent_tools` tools; every call goes through the contract's PreToolUse allow-list hook first (`engine_openai` calls the same hook the SDK calls). |
| 2. Scope enforced by root and the kernel | `run_scan`'s argv checks, root-owned run files, the per-slot `IPAddressDeny` fence. Unchanged. |
| 3. Carve-outs | Unchanged, except decision 7 (no provider check for exploit). |
| 4. Unprivileged runs | Unchanged: the engine runs inside the same run unit as `agenti-run`. |
| 6. Audit | Neutral events feed the same `StateTracker`, ledger and report. |
| 7. Caps reset per run | Turns, budget and wall clock enforced for every engine (below). |
| 8. Operator input redirects, never grants | `format_messages` is the one place notes and messages are split; both engines deliver its output the same way. |

### Model names

- Written `<provider>:<model>`: `anthropic:claude-sonnet-5-5`,
  `openai:gpt-5.1`, `local:qwen3-coder:30b`. Any model name the provider
  accepts; `model_registry.parse()` checks the form only (a provider it knows,
  then `[A-Za-z0-9._:/@-]{1,128}`).
- Old names keep working: `haiku`, `sonnet`, `opus` and bare `claude-…` ids
  mean `anthropic:…`.
- The org's `allowed_models` may list any such name, or `<provider>:*` for
  every model of a provider. The default is `anthropic:*` plus the three old
  aliases, so nothing changes for an existing install until an admin adds
  another provider.
- The launch page lists what the key can use: each provider's `GET /v1/models`
  through the relay (`model_registry.list_models`), filtered by the policy.

### Providers, keys, egress

| Provider | Key (secrets tiers) | Endpoint | Engine |
|---|---|---|---|
| `anthropic` | `ANTHROPIC_API_KEY` | api.anthropic.com | `engine_claude` |
| `openai` | `OPENAI_API_KEY` | `https://api.openai.com/v1` | `engine_openai` |
| `local` | `LOCAL_LLM_API_KEY` (optional) | `LOCAL_LLM_BASE_URL`, e.g. `http://10.0.0.5:11434/v1` | `engine_openai` |

A run reaches its model only through `agenti-relay` (CONNECT to an allowed
host:port). The relay's default list becomes `api.anthropic.com:443` and
`api.openai.com:443`; a self-hosted endpoint is added by root
(`/etc/agenti/relay.conf`, `ALLOW=`), never by the web tier. The OpenAI
engine is stdlib HTTP (`urllib`, `HTTPS_PROXY` = the relay), so no new
package enters `agenti-runtime`. For a plain-HTTP self-hosted endpoint the
relay tunnels the TCP connection the same way.

### Caps for every engine

- **Turns:** the engine counts model calls; `max_turns` ends the run as the SDK
  does (`error_max_turns`).
- **Budget:** cost = tokens x price. Claude: the SDK's own figure. OpenAI:
  `model_registry.PRICES` (USD per million input/output tokens) for known
  models, plus admin-set prices in the policy (`model_prices`). A cloud model
  with no known price is **refused at start** with the command that sets one:
  an unbounded spend must never be the silent default. Self-hosted models cost
  0 (turns and the wall clock still bound them).
- **Wall clock:** unchanged (`session_runner`'s deadline).

### Events

`engine_openai` speaks two wire formats behind one loop: OpenAI's Responses
API (`provider.wire = "responses"`; its reasoning models take tools only
there; `store: false`, reasoning items come back encrypted and are returned)
and Chat Completions for self-hosted servers (`"chat"`). It yields objects
with the same class names and fields the
Claude SDK uses (`AssistantMessage` with `TextBlock`/`ToolUseBlock`,
`UserMessage` with `ToolResultBlock`, `ResultMessage`, `SystemMessage`), so
`StateTracker`, `journal_line`, `note_result` and `resource_cap_reason` read
both engines unchanged. Those classes live in `model_session.py`.

### Resume

Claude: the SDK's session id, as today. OpenAI-compatible: the engine keeps
the conversation in the run's own `state/conversation.jsonl` (root-readable,
in the slot) and a resume reloads it; its "session id" is that file's run id.

## Phases

**A. Foundations (Claude Code, 2026-11-04) — done**
- [x] `agent_tools.py`: provider-neutral `@tool` (same signature as the SDK's),
      JSON schema, conversion to SDK tools. Every `from claude_agent_sdk import tool`
      is now `from agent_tools import tool`.
- [x] `model_registry.py`: providers, `split()`/`canonical()`, old aliases,
      prices, key names, live model listing (`list_models`).
- [x] `model_session.py`: the engine interface, neutral event classes,
      `open_session()`.
- [x] `engine_claude.py`: today's SDK path behind the interface. The runners
      no longer build the Claude tool server at start-up; the engine does.
- [x] `engine_openai.py`: the loop (tools, guard hook, inbox hook, turns,
      budget, interrupt, set-model within the provider, resume), tested against
      a scripted model and through the real relay (`test_engine_openai.py`).
- [x] `session_runner.py` on `open_session()`.
- [x] Policy accepts any well-formed model and `provider:*`; `model_prices`
      (`engagement set --model-price`); relay default allows OpenAI;
      `set-secret.sh --provider openai|local [--base-url]`; `require_api_key`
      checks the run's provider.
- [x] Live, test VM, enum against the lab target (2026-11-04):
      Claude `haiku`: 6 findings, ended on its turn cap, $0.04 — unchanged.
      OpenAI `gpt-5.6-terra`: scans through the checked tool (two refused by
      the validator), 5 findings, stopped and escalated through
      `ask_operator` on an open root shell, took the operator's reply, wrote a
      completed report, ~$0.05.
      Found live: OpenAI's reasoning models refuse tools on Chat Completions,
      so the `openai` provider speaks the **Responses API** (`store: false`,
      reasoning returned encrypted); self-hosted keeps Chat Completions
      (`Provider.wire`). And a multi-query run's report showed only the last
      query's cost: engines now report `session_cost_usd`.
- [x] Live self-hosted model on the test VM: Ollama model discovery through
      the relay, then GUI-launched enum runs using `qwen3:1.7b` and
      `qwen2.5:1.5b`. Both reached Agenti's tools; malformed arguments and
      disallowed commands were refused. The first timed out; the second
      repeated an invalid command. Neither demonstrated a successful scan.
      Scripted model-server tests on the VM also cover successful tool calls,
      caps and relay denial. These tiny CPU models are not a quality benchmark.

Known gaps found while building A (resolved in B, 2026-11-04):
- [x] Resolve secrets per key across user, agent, organisation and shared tiers.
  VM proof: two regression tests as `agenti-run`, plus real root CLI writes
  with synthetic keys in a temporary data root. A private per-user Claude
  key no longer hides a broader OpenAI key. Permission checks remain; links
  and non-regular files are refused before reading.
- [x] Refuse missing provider prices, keys and addresses before a slot
  exists. VM proof: real `agenti enum start --dry-run` against temporary
  fixtures refused all three cases without creating a slot. Team start checks
  every launchable member before making slots or posting the kickoff; a real
  denied team made neither slot, and a valid mixed-provider dry run passed.
  The precheck
  reads the files systemd will use, not the launching shell's environment.
  Also fixed preflight's unconditional Anthropic key, Claude executable and
  Anthropic egress checks; these now follow the selected provider.
- [x] Provider-aware dashboard/Launch/Platform status. Proven in the live GUI
  with all three test accounts; Platform showed the OpenAI key correctly.
- [x] `agenti admin relay allow host:port`: additive, root-terminal-only,
  serialized and atomic; keeps the configured list or the cloud defaults.
  Proven live on the VM: both cloud endpoints remained after an addition.
  The API bridge refuses the relay verb.
- [x] Default allowed list includes `anthropic:*` and the old aliases.
  Existing saved policies stay unchanged. The VM's live lists were correctly
  filtered by its existing policy; wildcard/name behavior is covered by the
  engine/registry tests run on the VM.

**B. Everywhere a model is chosen (hand-off point for Codex)**

**Phase B: done (2026-11-04).** The CLI, API, GUI, team launches,
provider configuration, paid-agent adapters, scaffold and help now use the
provider-neutral backbone. Real cloud GUI runs and a mixed-provider team ran
on the test VM. Paid-agent branches passed private hosted CI against core
`6c337c6`; they remain unmerged and nothing has been published. No phase C
work has begun. A tiny self-hosted model reached the live tool guard, but it
repeated invalid commands and did not demonstrate a successful scan; see the
self-hosted proof above. Model quality and latency vary by model.

Proof:
- Full core check: 50 suites passed. Both paid agents overlaid on the new
  core: 53 suites passed. GUI checks: 114 views passed (including the opened
  model picker). A pre-existing TOTP test crossed clock windows under load;
  its replay/unused-code checks now use a fixed clock, with authentication
  behavior unchanged (228 authd checks passed).
- VM installed-code checks as `agenti-run`: secrets (2), provider/preflight
  (5), provider settings (5), engine and real relay integration (77).
  The complete deployment verification passed, with the paid agents too.
- Real GUI enum runs: Claude haiku produced 5 findings and obeyed its turn
  cap; OpenAI `gpt-5.6-terra` completed with 3 findings and a report costing
  $0.0204 under a $0.10 cap.
- Mixed-provider GUI team: Claude enum (6 findings) and OpenAI trafficmon
  (12 findings) both reached their models and obeyed their turn caps.
  The test narrowed capture to 20 seconds through the existing API field
  and generated bounded ICMP traffic to the approved lab target. An earlier
  zero-packet capture was not counted as model proof.
- Paid cracker: a real GUI OpenAI run on an attached synthetic hash completed
  with 4 findings in its offline sandbox. Exploit: a live OpenAI dry-run was
  correctly refused while the engagement's exploit capability was off.
  No exploitation was enabled or performed.
- Platform: saved a local address with an optional empty key behind a fresh
  approval, preserving cloud keys. Engagement: the GUI saved allowed names
  and preserved the configured model price. The model-price CLI alias was
  proven with the same existing price. Three test accounts have passwords,
  TOTP and registered passkeys; passwordless sign-in was also proven.
- Scaffold generated and compiled on the VM with `agent_tools` and
  `open_session`. Choosing-model help was installed and read through the CLI.

Private hosted CI passed for the development core (CI, security and package)
and for both paid-agent branches using a dedicated read-only core deploy key.
The paid changes remain in their own private repositories; do not overlay or
commit their private source into the core repository. Their CI pins the code
revision above; update the pin for a future published core release.

- [x] CLI: provider model names, live `models` list, provider keys, model-price
      policy (`admin set-policy model-price` delegates to the engagement policy).
      Proof: live cloud discovery, CLI launch/configuration checks above.
- [x] API + GUI: provider/model picker with live suggestions and typed names;
      provider/model per team member; provider keys/address and allowed model
      names/wildcards/prices in Settings. Proof: live GUI and team runs above.
- [x] Paid agents: neutral tool imports, no CVP gate, CI on the new core.
      Proof: VM cracker run and exploit dry-run above, local overlay suites,
      and passing hosted CI on both private branches. Cracker already uses
      the neutral shared analysis runner.
- [x] `new_agent.py` scaffold on `agent_tools` and `open_session`.
      Proof: generated file compiles on the VM; exception-path tests pass.
- [x] Docs: `docs/help/choosing-a-model.md`, installation guidance and the paid
      exploit guide reflect provider selection, keys, prices and the gates.
      Proof: help tests and the installed VM CLI help reader.

**C. The console (#3)**
- [ ] Stream engine events to the agent page as a session view; `/model`.

## How to test

- Unit: `shared/test_agent_tools.py`, `test_model_registry.py`,
  `test_engine_openai.py` (a local fake Chat Completions server: tool calls,
  a denied tool, max turns, budget, an operator message mid-run, resume).
- Everything else: `bash shared/ci.sh all`, then a real run on the box per
  provider (`CLAUDE.md` "How to work on it"), then `shared/ci.sh gui` for any
  page change.
