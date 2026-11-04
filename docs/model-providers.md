# Any model: one Agenti, many AI providers

Status: design agreed 2026-11-04, phase A in progress. This file is the plan
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

`engine_openai` yields objects with the same class names and fields the
Claude SDK uses (`AssistantMessage` with `TextBlock`/`ToolUseBlock`,
`UserMessage` with `ToolResultBlock`, `ResultMessage`, `SystemMessage`), so
`StateTracker`, `journal_line`, `note_result` and `resource_cap_reason` read
both engines unchanged. Those classes live in `model_session.py`.

### Resume

Claude: the SDK's session id, as today. OpenAI-compatible: the engine keeps
the conversation in the run's own `state/conversation.jsonl` (root-readable,
in the slot) and a resume reloads it; its "session id" is that file's run id.

## Phases

**A. Foundations (Claude Code, 2026-11-04)**
- [ ] `agent_tools.py`: provider-neutral `@tool` (same signature as the SDK's),
      JSON schema, conversion to SDK tools. Every `from claude_agent_sdk import tool`
      becomes `from agent_tools import tool`.
- [ ] `model_registry.py`: providers, `parse()`, old aliases, prices, key
      names, live model listing.
- [ ] `model_session.py`: the engine interface, neutral event classes,
      `open_session()`.
- [ ] `engine_claude.py`: today's SDK path behind the interface (behaviour
      unchanged; live-checked with a real enum run).
- [ ] `engine_openai.py`: the loop (tools, guard hook, inbox hook, turns,
      budget, interrupt, set-model within the provider, resume), tested against
      a fake Chat Completions server.
- [ ] `session_runner.py` on `open_session()`.
- [ ] Policy accepts any well-formed model; relay default allows OpenAI;
      `OPENAI_API_KEY` / `LOCAL_LLM_*` in the key tiers and `set-secret`.
- [ ] A live OpenAI enum run against the lab target (needs the operator's key).

**B. Everywhere a model is chosen (hand-off point for Codex)**
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
