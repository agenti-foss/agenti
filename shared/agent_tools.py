"""
agent_tools.py — an agent's tools, written once for every model provider.

    from agent_tools import tool

    @tool("run_scan", "Run one in-scope recon command...", {"command": str})
    async def run_scan(args):
        return {"content": [{"type": "text", "text": "..."}]}

The decorator has the Claude Agent SDK's exact signature and result shape, so
a tool body never changes: what changes is that the result is a plain ToolDef
any engine can offer (docs/model-providers.md). engine_claude turns it into an
SDK MCP tool (to_sdk), engine_openai into a Chat Completions function
(json_schema). gen_capabilities.py reads the same `@tool("name", ...)` lines.

Standard library only: importing this never needs any provider's SDK.
"""
from __future__ import annotations

import typing
from dataclasses import dataclass
from typing import Any, Awaitable, Callable


@dataclass(frozen=True)
class ToolDef:
    name: str
    description: str
    input_schema: Any            # {"param": type, ...} or a full JSON schema dict
    handler: Callable[[dict], Awaitable[dict]]

    async def __call__(self, args: dict) -> dict:
        return await self.handler(args)


def tool(name: str, description: str, input_schema: Any) -> Callable[[Callable], ToolDef]:
    """@tool(name, description, schema): the same three arguments as
    claude_agent_sdk.tool."""
    def wrap(handler: Callable[[dict], Awaitable[dict]]) -> ToolDef:
        return ToolDef(name, description, input_schema, handler)
    return wrap


_JSON_TYPES = {str: "string", int: "integer", float: "number", bool: "boolean",
               list: "array", dict: "object"}


def _type_schema(t: Any) -> dict:
    if t in _JSON_TYPES:
        return {"type": _JSON_TYPES[t]}
    origin = typing.get_origin(t)
    if origin in (list, tuple):
        args = typing.get_args(t)
        return {"type": "array", "items": _type_schema(args[0]) if args else {}}
    if origin is dict:
        return {"type": "object"}
    return {"type": "string"}


def json_schema(td: ToolDef) -> dict:
    """The JSON schema of a tool's input, built the way the Claude SDK builds it
    (_build_input_schema): a dict that is already a JSON schema is used as it
    is; {"param": type} becomes an object whose every parameter is required."""
    s = td.input_schema
    if isinstance(s, dict) and isinstance(s.get("type"), str) and "properties" in s:
        return s
    if isinstance(s, dict):
        props = {k: _type_schema(v) for k, v in s.items()}
        return {"type": "object", "properties": props, "required": list(props)}
    return {"type": "object", "properties": {}}


def to_sdk(td: ToolDef):
    """The Claude Agent SDK's own tool object for one ToolDef (engine_claude)."""
    from claude_agent_sdk import SdkMcpTool
    return SdkMcpTool(name=td.name, description=td.description,
                      input_schema=td.input_schema, handler=td.handler)


def result_text(result: dict | None) -> tuple[str, bool]:
    """(text, is_error) of a tool's result, for an engine that sends text back."""
    result = result or {}
    parts = []
    for c in result.get("content") or []:
        if isinstance(c, dict) and c.get("type") == "text":
            parts.append(str(c.get("text", "")))
    return "\n".join(parts), bool(result.get("is_error") or result.get("isError"))
