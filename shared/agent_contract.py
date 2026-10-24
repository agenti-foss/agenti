"""
agent_contract.py — the declarative manifest each agent pack provides.

Per CLAUDE.md §3f, the platform has two halves: a reusable *harness*
(agent_runtime.py — the plumbing identical across agents) and a declarative
*contract* (this file's `AgentContract`) — the small set of things that
actually vary between agents, made explicit and required. `enum` and
`trafficmon` are the two real agents this was drawn from; treat it as
provisional until a third, non-network agent (`research`) has been built on
it — see the sequencing note in CLAUDE.md §3f for why that one is the sharp
test.

THE SAFETY PROPERTY THIS FILE EXISTS FOR: an `AgentContract` cannot be
constructed without at least one tool and a scope boundary. Not a lint rule,
not a code-review checklist item — `__post_init__` raises. A GUI "Create
Agent" flow or an `agent new <name>` scaffold that fills in this same object
therefore cannot produce an agent with no allow-list or no scope either. That
is the whole point of centralizing this here instead of leaving each agent to
remember to check it (§3b: "the safe shape is the only shape").

WHAT THIS DELIBERATELY DOES NOT DO YET: fully unify each agent's `configure()`
into one shared function. enum and trafficmon's `configure()` bodies differ in
more than one place (found while migrating them onto agent_runtime.py) — for
instance enum refuses to start the commercial profile against a data root
that doesn't exist yet, trafficmon does not. Forcing that into one shared
function now, on two data points, risks baking in an accidental one-agent
behavior as if it were universal — the AgentContract centralizes what IS
genuinely proven-identical (the tool allow-list and its hard PreToolUse deny,
which were byte-for-byte duplicated in both agents down to the docstring) and
leaves the rest for after agent #3.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Protocol, runtime_checkable


# ---------------------------------------------------------------------------
# The scope interface — see shared/scope_cidr.py for the CIDR implementation.
# Not enforced by inheritance (a future DomainScope or SourceScope need not
# import this module at all); enforced structurally, by AgentContract itself
# checking isinstance() against this @runtime_checkable Protocol. That check
# only confirms the methods exist, not that they behave correctly — it exists
# to catch "forgot to pass a scope object" or "passed the wrong kind of
# object", not to replace testing a new scope implementation.
# ---------------------------------------------------------------------------
@runtime_checkable
class ScopeBoundary(Protocol):
    def ceiling_from_engagement(self, engagement) -> Any: ...
    def narrow(self, ceiling: Any, run_target_text: str, *, required: bool) -> Any: ...
    def contains(self, target: str, scope: Any) -> tuple[bool, str]: ...
    def describe(self, scope: Any) -> str: ...


@dataclass(frozen=True)
class AgentContract:
    """The manifest. Every field maps directly to one of the required fields
    listed in CLAUDE.md §3f:

      tools / allow-list      -> tool_names, tools, mcp_server_name
      scope / authorization   -> scope
      system prompt + task    -> operational_notes, task
      profile defaults        -> profiles

    `validator rules` (the fifth field CLAUDE.md lists) is deliberately NOT a
    field here yet: enum's validator is a pure function over a shell command
    string, trafficmon has no equivalent single function (its scope check is
    inline in capture_host). Forcing one shape onto both now would be
    guessing; wait for `research` to show what's actually common.
    """

    name: str
    # Short tool names as passed to @tool(...), e.g. ("run_scan", "read_scan").
    # `tools` holds the matching @tool-decorated callables, same order —
    # both are required and must be the same length (checked below).
    tool_names: tuple[str, ...]
    tools: tuple[Callable, ...]
    mcp_server_name: str
    scope: ScopeBoundary
    profiles: dict[str, Any]
    operational_notes: str
    task: str
    mcp_server_version: str = "1.0.0"
    # Tools every agent gets regardless of its own MCP server: ToolSearch is
    # the runtime's tool-LOADER, not something that touches the network or
    # filesystem — discovering a tool's schema is not executing it, and any
    # actual call still passes through the hard deny below. See either
    # agent's own comment on this (identical reasoning, now said once).
    extra_allowed_tools: tuple[str, ...] = ("ToolSearch",)

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("AgentContract requires a name")
        if not self.tool_names or not self.tools:
            raise ValueError(
                f"{self.name}: an agent contract must declare at least one tool. "
                f"'run anything' is not a supported shape — see CLAUDE.md §3b."
            )
        if len(self.tool_names) != len(self.tools):
            raise ValueError(
                f"{self.name}: tool_names and tools must be the same length "
                f"({len(self.tool_names)} names, {len(self.tools)} callables)"
            )
        if not isinstance(self.scope, ScopeBoundary):
            raise ValueError(
                f"{self.name}: an agent contract must declare a scope boundary "
                f"implementing ScopeBoundary (ceiling_from_engagement/narrow/"
                f"contains/describe) — got {self.scope!r}. See shared/scope_cidr.py "
                f"for the CIDR implementation, or CLAUDE.md §3f for the interface."
            )
        if not self.profiles:
            raise ValueError(
                f"{self.name}: an agent contract must declare at least one profile "
                f"(model/caps defaults) — an agent with no profile has nothing to run."
            )
        if not self.mcp_server_name:
            raise ValueError(f"{self.name}: mcp_server_name is required")

    # -- derived: the qualified tool-allowlist ------------------------------
    @property
    def allowed_tool_names(self) -> frozenset[str]:
        qualified = {f"mcp__{self.mcp_server_name}__{n}" for n in self.tool_names}
        return frozenset(qualified | set(self.extra_allowed_tools))

    # -- derived: the actual MCP server object ------------------------------
    # Imports claude_agent_sdk lazily, so constructing/validating a contract
    # (everything in __post_init__ above) never requires the SDK to be
    # installed — only actually building a runnable server does. That keeps
    # the contract's safety checks unit-testable on their own.
    def build_mcp_server(self):
        from claude_agent_sdk import create_sdk_mcp_server
        return create_sdk_mcp_server(
            name=self.mcp_server_name, version=self.mcp_server_version,
            tools=list(self.tools),
        )

    # -- derived: the PreToolUse hard-deny hook ------------------------------
    # This was byte-for-byte duplicated between enum and trafficmon (down to
    # the docstring) before this migration — the ONE piece of both agents that
    # was pure boilerplate wrapping their AGENT_TOOL_ALLOWLIST set. Generating
    # it here means a third agent gets this hard boundary for free, correctly,
    # rather than needing to copy-paste it a third time.
    def make_tool_allowlist_hook(self, logger: logging.Logger) -> Callable:
        allowed = self.allowed_tool_names
        tool_desc = " / ".join(self.tool_names)

        async def enforce_tool_allowlist(input_data, tool_use_id, context):
            tool_name = input_data.get("tool_name", "")
            # An operator interrupt (agent_runtime.install_interrupt_handler)
            # aborts the in-flight tool call and asks the SDK to end the
            # turn; in the gap between those two the model may still try to
            # start another tool call. Refuse it here — the run is ending,
            # and "interrupt" must never let one more scan slip out. Lazy
            # import: the contract is importable without the harness (tests
            # do exactly that), and a missing harness just means no
            # interrupt support, not a broken hook.
            try:
                import agent_runtime as _rt
                interrupted = _rt.interrupt_requested()
            except Exception:
                interrupted = False
            if interrupted:
                logger.info("TOOL_DENIED | %s | run is being interrupted by the operator",
                            tool_name)
                return {"hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": (
                        "The operator has interrupted this run. No further tool "
                        "calls will execute; the run is ending and a partial "
                        "report will be written."),
                }}
            try:
                import engagement_context as _ec
                closed = _ec.run_window_closed()
            except Exception:
                closed = ""
            if closed:
                logger.info("TOOL_DENIED | %s | REFUSING: %s", tool_name, closed)
                return {"hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": (
                        f"REFUSING: {closed} No further tool calls will execute. "
                        f"Stop and give your final summary now."),
                }}
            if tool_name in allowed:
                return {}   # allow: pass through to the rest of the pipeline
            logger.info("TOOL_DENIED | %s | not in agent tool allow-list", tool_name)
            return {"hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": (
                    f"Tool '{tool_name}' is disabled. This agent may act ONLY "
                    f"via {tool_desc}."
                ),
            }}

        return enforce_tool_allowlist
