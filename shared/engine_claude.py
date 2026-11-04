"""
engine_claude.py — a run's session with a Claude model, through the Claude
Agent SDK (the Claude Code CLI), exactly as every run worked before the
provider seam (docs/model-providers.md). model_session.open_session picks it
for an `anthropic` model.

The session IS the SDK's client (query / receive_response / interrupt /
set_model), wrapped only so that a mid-run model switch can never leave the
provider: a run started on Claude stays on Claude.
"""
from __future__ import annotations

from claude_agent_sdk import ClaudeAgentOptions, ClaudeSDKClient, HookMatcher

import agent_runtime
import model_registry
from model_session import EngineError, SessionSpec


class _ClaudeSession:
    def __init__(self, client: ClaudeSDKClient):
        self._client = client

    async def __aenter__(self):
        await self._client.__aenter__()
        return self

    async def __aexit__(self, *exc):
        return await self._client.__aexit__(*exc)

    async def query(self, text: str) -> None:
        await self._client.query(text)

    def receive_response(self):
        return self._client.receive_response()

    async def interrupt(self) -> None:
        await self._client.interrupt()

    async def set_model(self, model: str) -> None:
        if model_registry.split(model)[0] != "anthropic":
            raise EngineError(f"this run uses Claude; '{model}' is another provider's model. "
                              f"A run keeps its provider: start a new run to use it.")
        await self._client.set_model(model_registry.canonical(model))


def open_session(spec: SessionSpec) -> _ClaudeSession:
    contract = spec.contract
    mcp_server = spec.mcp_server or contract.build_mcp_server()
    options = ClaudeAgentOptions(
        system_prompt=agent_runtime.system_prompt_file(spec.system_prompt),
        mcp_servers={contract.mcp_server_name: mcp_server},
        allowed_tools=sorted(contract.allowed_tool_names),
        # dontAsk fails closed: any tool not pre-approved above is denied (there
        # is no human to answer a prompt in an unattended run). The hook below is
        # the belt to this suspenders — it runs first and denies even if the mode
        # is ever loosened. Two independent layers, neither enumerating built-ins.
        permission_mode="dontAsk",
        setting_sources=[],  # load no user/project settings: nothing outside our own files steers a run
        hooks={"PreToolUse": [HookMatcher(hooks=[spec.pre_tool_hook])],
               "PostToolUse": [HookMatcher(hooks=[spec.post_tool_hook])]},
        model=model_registry.canonical(spec.model),
        max_turns=spec.max_turns,            # stop after N agentic turns
        max_budget_usd=spec.max_budget_usd,  # hard stop on spend
        # Attach to the previous conversation when resuming. Per-run caps are
        # deliberately NOT carried over: they are re-read from run-config.json
        # every time, so a resume can never inherit a looser budget than the
        # operator set for it (CLAUDE.md §1 invariant 7).
        resume=spec.resume,
        env=spec.env,
    )
    return _ClaudeSession(ClaudeSDKClient(options=options))
