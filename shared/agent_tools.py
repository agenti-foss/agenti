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
import math
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


def argument_error(td: ToolDef, args: dict) -> str | None:
    """Check required fields and their declared primitive types before calling a tool.

    Some compatible models return schema descriptions as values. Never coerce
    them into commands: give the model a useful error and let it try again.
    Domain-specific validation still happens inside the tool.
    """
    schema = json_schema(td)
    for name in schema.get("required", []):
        if name not in args:
            return f"Tool '{td.name}' requires the '{name}' argument. Send a JSON object with that field."
    types = {"string": str, "object": dict, "array": list, "boolean": bool,
             "integer": int, "number": (int, float), "null": type(None)}
    for name, value in args.items():
        declaration = (schema.get("properties") or {}).get(name) or {}
        expected = declaration.get("type") if isinstance(declaration, dict) else None
        if not isinstance(expected, str) or expected not in types:
            continue
        valid = isinstance(value, types[expected])
        if expected in ("integer", "number") and isinstance(value, bool):
            valid = False
        if expected == "number" and valid and isinstance(value, float) and not math.isfinite(value):
            valid = False
        if not valid:
            return f"Tool '{td.name}' argument '{name}' must be a JSON {expected}; send a value, not a schema description."
    return None


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
