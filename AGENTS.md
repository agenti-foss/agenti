# Agenti — notes for coding agents (Codex and others)

**Read `CLAUDE.md` first and follow it.** Despite its name it is this
project's working agreement for any agent: what Agenti is, the safety
invariants (never weaken them), the recurring traps, and how to test. Where
it and the code disagree, the code wins; keep both accurate as you build.

## Where the work is now

The current project is **any AI model through one backbone**:
`docs/model-providers.md` has the operator's decisions, the design and the
phase checklists. Phase A (the seam, the Claude engine, the
OpenAI-compatible engine) is done; pick up at the first unticked box.

The pieces, all in `shared/`:

| File | What it is |
|---|---|
| `model_session.py` | The seam: `SessionSpec`, `open_session()`, the event classes (the Claude SDK's shapes) |
| `engine_claude.py` | Claude through the Claude Agent SDK (unchanged behaviour) |
| `engine_openai.py` | Agenti's own loop over Chat Completions: OpenAI and self-hosted |
| `model_registry.py` | `provider:model` names, providers, prices, live model lists |
| `agent_tools.py` | The provider-neutral `@tool` every agent tool uses |
| `session_runner.py` | The one run loop, now on `open_session()` |

## How to work here

- Tests: `bash shared/ci.sh all` (put `ruff`, `shellcheck`, `node` and the
  `cryptography` package on PATH first). GUI changes: also `shared/ci.sh gui`
  (needs `cd tests/gui && npm ci` once).
- A provider change is proven by a real run, not only tests: the operator
  runs the test VM; see `docs/model-providers.md` "How to test".
- One implementation, never two: CLI first, the API shells out to the CLI,
  the GUI calls the API (`CLAUDE.md` standing rules).
- Never read, print or ask for API keys, the vault passphrase or YubiKey PINs.
  Keys are set by the operator with `set-secret.sh --provider ...`.
- Lab addresses and domains never go into committed files.
- Commit in small, described steps; push only to this repo (`agenti-dev`).
  The public repo (`agenti-foss/agenti`) is published by fast-forward at
  release time only, with the operator's go-ahead.
