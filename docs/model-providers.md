# Any model: one Agenti, many AI providers

Status: design agreed 2026-11-04; phase A done and live-proven on Claude and OpenAI (2026-11-04); phase B next. This file is the plan
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
- [ ] Live: a self-hosted model (e.g. Ollama with a tool-calling model).

Known gaps found while building A (do these in B):
- `load_secrets` takes the FIRST tier file that exists, whole: a per-user file
  holding only a Claude key hides the org's OpenAI key. Make it per key.
  **Fixed (2026-11-04):** each key now resolves independently through the
  tiers, with explicit environment values retaining priority. Regression
  checks passed locally and on the test VM against the installed helper,
  including under the real `agenti-run` account: a user Claude key does not
  hide a broader OpenAI key, and an insecure lower-tier file is refused.
  This is helper-level proof; the Phase B launch/GUI boxes remain unticked.
- `run_coverage.py precheck` checks the model is allowed but not its price,
  key or address: an OpenAI run with no price fails at start (a report says
  why) instead of being refused before a slot exists. Add those checks there.
  **Implemented, helper-proven on the VM (2026-11-04):** the CLI passes the
  run owner; precheck resolves that owner's provider settings and refuses a
  missing cloud price/key or missing/invalid self-hosted URL before slot
  allocation. Four provider regression tests passed against the installed
  code as `agenti-run`. Also found and corrected preflight's unconditional
  Anthropic key, Claude executable and Anthropic egress checks: these now
  follow the selected provider. Full deployed-unit and GUI launch proof is
  still pending; no Phase B box is complete.
- The "no API key" banners (dashboard, Launch, Settings → Platform) look only
  at `ANTHROPIC_API_KEY`.
- `/etc/agenti/relay.conf` replaces the relay's default list: adding a
  self-hosted endpoint means listing Anthropic and OpenAI too. A root CLI verb
  (`agenti admin relay allow host:port`) should write it.
- The default `allowed_models` is still `haiku, sonnet, opus` so the current
  launch page keeps working; switch it to `anthropic:*` once the launch page
  lists models live.

**B. Everywhere a model is chosen (hand-off point for Codex)**

**In progress, session saved 2026-11-04 at the operator's request:** the first
two Known gaps have implementations and VM helper-level regression proof
(two secrets tests and five provider/preflight tests, against installed code
as `agenti-run`). Changes are deployed directly to the test VM:
`agent_runtime.py`, `run_coverage.py`, `preflight.py`, and `/usr/bin/agenti`.
No Phase B checkbox has been ticked; real deployed-unit/GUI launch proof
and the mixed-provider team run are still required. The VM currently has
no IAM users (`admin user list --json` returned `[]`); an asynchronous request
was sent asking the operator to complete first-run setup, with no answer yet.
Check readiness again next session. No provider keys were read or printed.

Local targeted suites passed: `test_secrets.py`, `test_provider_precheck.py`,
`test_run_coverage.py` (31 checks), `test_preflight.py` (56 checks).
The full `ci.sh all` run needs system Python with `cryptography` and the lint
tools on PATH. A sandboxed attempt hit socket restrictions; the unrestricted
rerun was still running when the operator requested this save. Its log is
`/tmp/agenti-phase-b-ci-unrestricted.log` on the development machine: check
its final result or rerun before relying on it. No GUI assets were changed.
Next: finish/prove the remaining Known gaps, then the Phase B checklist;
do not start phase C or publish to the public repository.

- [ ] CLI: `start --model openai:gpt-…`, `models` verb (live list),
      `set-secret` for the new keys, `admin set-policy` for `model_prices`.
- [ ] API + GUI: launch page provider + model picker (live list); team
      creation with a provider/model per member; Settings → Platform: keys per
      provider, the self-hosted endpoint, allowed models (any name, `provider:*`).
- [ ] Paid agents (`agenti-exploit`, `agenti-cracker`): move their `@tool`
      imports to `agent_tools`, drop the CVP gate (decision 7), CI on the new core.
- [ ] `new_agent.py` scaffold on `agent_tools` and `open_session`.
- [ ] Docs: `docs/help/` pages for choosing a model and connecting each provider.

**C. The console (#3)**
- [ ] Stream engine events to the agent page as a session view; `/model`.

## How to test

- Unit: `shared/test_agent_tools.py`, `test_model_registry.py`,
  `test_engine_openai.py` (a local fake Chat Completions server: tool calls,
  a denied tool, max turns, budget, an operator message mid-run, resume).
- Everything else: `bash shared/ci.sh all`, then a real run on the box per
  provider (`CLAUDE.md` "How to work on it"), then `shared/ci.sh gui` for any
  page change.
