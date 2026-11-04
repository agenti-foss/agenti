"""
model_session.py — the one seam between a run and its AI provider
(docs/model-providers.md).

session_runner asks open_session(spec) for a session and talks to it with four
calls, whichever provider is behind it:

    async with open_session(spec) as session:
        await session.query(text)                    # what to do next
        async for event in session.receive_response():  # until the model is done
            ...
        await session.interrupt()                    # abort the step in flight
        await session.set_model(model)               # same provider, new model

Events are the classes below. They carry the Claude Agent SDK's own class
names and fields, so everything that reads a run's stream (StateTracker,
journal_line, note_result, resource_cap_reason, the report) reads every engine
the same way: the Claude engine yields the SDK's objects as they are, the
OpenAI-compatible engine yields these.

Standard library only.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable


# ---- events (the Claude SDK's shapes) -------------------------------------
@dataclass
class TextBlock:
    text: str


@dataclass
class ThinkingBlock:
    thinking: str
    signature: str = ""


@dataclass
class ToolUseBlock:
    id: str
    name: str
    input: dict


@dataclass
class ToolResultBlock:
    tool_use_id: str
    content: Any
    is_error: bool = False


@dataclass
class AssistantMessage:
    content: list
    model: str = ""


@dataclass
class UserMessage:
    content: Any


@dataclass
class SystemMessage:
    subtype: str
    data: dict = field(default_factory=dict)


@dataclass
class ResultMessage:
    subtype: str                     # success | error_max_turns | error_max_budget_usd | error_during_execution
    is_error: bool
    num_turns: int
    session_id: str
    total_cost_usd: float | None = None
    result: str | None = None
    stop_reason: str | None = None
    usage: dict | None = None
    duration_ms: int = 0
    duration_api_ms: int = 0
    # The whole session so far (every query), for the report; total_cost_usd
    # and num_turns are this query's alone, as the Claude SDK counts them.
    session_cost_usd: float | None = None


# ---- what a session needs --------------------------------------------------
@dataclass
class SessionSpec:
    model: str                       # canonical (model_registry.canonical)
    system_prompt: str               # the text itself
    contract: Any                    # AgentContract: tools, tool names, MCP server name
    pre_tool_hook: Callable          # the allow-list guard (the SDK PreToolUse hook shape)
    post_tool_hook: Callable         # operator/team delivery (the SDK PostToolUse hook shape)
    max_turns: int
    max_budget_usd: float
    state_dir: Path                  # the run's state/ (an engine may keep its conversation here)
    resume: str | None = None        # a previous session id
    env: dict = field(default_factory=dict)      # the model client's environment (relay, keys)
    model_prices: dict = field(default_factory=dict)
    mcp_server: Any = None           # the Claude engine's tool server, if already built
    logger: Any = None


class EngineError(RuntimeError):
    """A run cannot reach or use its model: the message says why and what fixes it."""


def open_session(spec: SessionSpec):
    """The session for spec.model's provider (an async context manager)."""
    import model_registry
    provider = model_registry.provider_of(spec.model)
    if provider.engine == "claude":
        import engine_claude
        return engine_claude.open_session(spec)
    import engine_openai
    return engine_openai.open_session(spec, provider)
