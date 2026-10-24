#!/usr/bin/env python3
"""
gen_capabilities.py — derive an agent's tool/permission descriptor by STATIC
analysis of its source, for the operator-facing "Tools & permissions" panel
(CLAUDE.md §4 item 26, and the first concrete brick of the manifest arc §3f).

    python3 gen_capabilities.py <agent-source.py>   # prints JSON

WHY STATIC, NOT AN IMPORT. The honest thing to show the operator is what the
agent is ACTUALLY allowed to do, read straight from the same declarations
that enforce it — enum's `ALLOWED_BINARIES` is the set `validate_command`
checks against, the `@tool(...)` names are the MCP allow-list the hard-deny
hook builds from. Reading them by importing the module would pull in the
Claude Agent SDK, the engagement config and MCP-server construction, any of
which can fail for reasons that have nothing to do with the descriptor — and
this runs inside `deploy.sh`, where a failure would be a failure to deploy.
`ast` parses the file as text: no SDK, no venv, no config, no side effects,
nothing to break. It reports what the source DECLARES; the running boundary
is those same declarations, so the two cannot drift.

WHAT IT READS (all optional — a field simply absent means "this agent
doesn't have one"):
  - AGENT_NAME              the agent's name
  - every @tool(name, desc, schema) decorator IN THIS FILE -> the MCP tools
                                the model calls; OR, since phase 2 of the
                                generic-launcher arc moved enum/research/
                                trafficmon's tool bodies into
                                shared/tool_registry.py, a
                                `tool_registry.build_tools([...names...], ...)`
                                call — the literal name list is read
                                statically, then each name's purpose/schema
                                is looked up in tool_registry.REGISTRY
                                (importable with plain python3, no SDK,
                                by the same design as this file)
  - ALLOWED_BINARIES = {..}  -> the ENFORCED shell-command allow-list (enum);
                                its presence is what makes command_line_tools
                                "enforced": an agent with this set can run only
                                these programs, checked by its validator
  - DENIED_PATTERNS = [..]   -> patterns refused even on an allowed binary
  - EXTERNAL_TOOLS = [..]    -> for agents that invoke a FIXED set of external
                                programs/services rather than an allow-list
                                (trafficmon's tshark/suricata, research's HTTP
                                + Brave Search) — declared as strings or
                                (name, purpose) pairs, since there is no set to
                                derive them from
  - SCOPE = CIDRScope(..) / DomainScope(..)  -> the scope-boundary kind
  - category                 -> derived, not declared: for a registry-based
                                agent, the single category shared by every
                                tool named in its `build_tools([...])` call
                                (None if they disagree); for a manifest-
                                driven agent, manifest.json's own `category`
                                field. Phase 7's quick-launch category
                                picker (CLAUDE.md "Current plan") reads this
                                to learn which deployed agent serves a
                                category — never hardcoded per agent.

Anything it cannot parse is left out rather than guessed; the panel degrades
to "fewer facts", never to a wrong one.
"""
from __future__ import annotations

import ast
import json
import sys
from pathlib import Path


def _str_concat(node: ast.AST) -> str | None:
    """The value of a string literal, including implicit adjacent-string
    concatenation (`"a " "b"` -> "a b"), which every @tool description here
    uses to wrap long text. Returns None for anything not a plain string."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _str_concat(node.left), _str_concat(node.right)
        if left is not None and right is not None:
            return left + right
    return None


def _literal(node: ast.AST):
    """ast.literal_eval, but never raises — returns None on anything dynamic."""
    try:
        return ast.literal_eval(node)
    except (ValueError, TypeError, SyntaxError):
        return None


def _tool_decorators(tree: ast.Module) -> list[dict]:
    tools: list[dict] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef)):
            continue
        for dec in node.decorator_list:
            # @tool("name", "description", {schema})
            if not (isinstance(dec, ast.Call) and _dec_name(dec.func) == "tool"):
                continue
            args = dec.args
            name = _str_concat(args[0]) if len(args) >= 1 else None
            desc = _str_concat(args[1]) if len(args) >= 2 else None
            params: list[str] = []
            if len(args) >= 3 and isinstance(args[2], ast.Dict):
                params = [_str_concat(k) for k in args[2].keys if _str_concat(k)]
            tools.append({"name": name or node.name,
                          "purpose": (desc or "").strip(),
                          "params": params})
    return tools


def _registry_tool_names(tree: ast.Module) -> list[str] | None:
    """Find `tool_registry.build_tools([...names...], ...)` (or a bare
    `build_tools(...)` after `from tool_registry import build_tools`) and
    return its literal list of tool names, or None if no such call exists.
    This is what lets an agent that moved its tools into the shared
    registry (shared/tool_registry.py, phase 2 of the generic-launcher arc)
    still be described here without re-declaring anything."""
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and _dec_name(node.func) == "build_tools"):
            continue
        if not node.args:
            continue
        names = _literal(node.args[0])
        if isinstance(names, (list, tuple)) and all(isinstance(n, str) for n in names):
            return list(names)
    return None


def _registry_tools(names: list[str]) -> list[dict]:
    """Look up each name's purpose/schema in the actual registry. Imported
    here, not at module level, so a file with no registry-based agent never
    pays for it and a missing/broken tool_registry.py degrades to an empty
    list (a deploy-time descriptor failure must never be fatal) rather than
    crashing gen_capabilities.py."""
    try:
        import tool_registry
    except Exception:
        return []
    out = []
    for n in names:
        spec = tool_registry.REGISTRY.get(n)
        if spec is None:
            continue
        out.append({"name": n, "purpose": spec.purpose, "params": sorted(spec.schema)})
    return out


def _registry_category(names: list[str]) -> str | None:
    """The single category shared by every named tool's registry entry, or
    None if the names don't agree (or the registry can't be imported) —
    phase 7's category picker (CLAUDE.md "Current plan") reads this to learn
    which quick-launch category a deployed agent serves. Degrading to None
    on disagreement rather than guessing one: a mixed-category agent (none
    exist today) simply isn't offered as a quick-launch card for any
    category, which is the safe direction to be wrong in."""
    try:
        import tool_registry
    except Exception:
        return None
    cats = {tool_registry.REGISTRY[n].category for n in names if n in tool_registry.REGISTRY}
    return next(iter(cats)) if len(cats) == 1 else None


def _dec_name(func: ast.AST) -> str | None:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _assignments(tree: ast.Module) -> dict[str, ast.AST]:
    """Top-level `NAME = <value>` nodes, by name."""
    out: dict[str, ast.AST] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    out[t.id] = node.value
    return out


def _scope_kind(assigns: dict[str, ast.AST]) -> str | None:
    node = assigns.get("SCOPE")
    if isinstance(node, ast.Call):
        return _dec_name(node.func)
    return None


def _external_tools(assigns: dict[str, ast.AST]) -> list[dict]:
    """EXTERNAL_TOOLS as a list of {"name", "purpose"}. Accepts a list of
    strings or of (name, purpose) pairs."""
    val = _literal(assigns.get("EXTERNAL_TOOLS")) if "EXTERNAL_TOOLS" in assigns else None
    out: list[dict] = []
    if isinstance(val, (list, tuple)):
        for item in val:
            if isinstance(item, str):
                out.append({"name": item, "purpose": ""})
            elif isinstance(item, (list, tuple)) and item:
                out.append({"name": str(item[0]),
                            "purpose": str(item[1]) if len(item) > 1 else ""})
    return out


def describe(source: str) -> dict:
    tree = ast.parse(source)
    assigns = _assignments(tree)

    name = None
    if "AGENT_NAME" in assigns:
        name = _str_concat(assigns["AGENT_NAME"])

    allowed = _literal(assigns.get("ALLOWED_BINARIES")) if "ALLOWED_BINARIES" in assigns else None
    denied = _literal(assigns.get("DENIED_PATTERNS")) if "DENIED_PATTERNS" in assigns else None

    purposes = _literal(assigns.get("TOOL_PURPOSES")) if "TOOL_PURPOSES" in assigns else None
    purposes = purposes if isinstance(purposes, dict) else {}

    cli: dict = {"enforced": False, "items": [], "note": ""}
    if isinstance(allowed, (set, frozenset, list, tuple)):
        # enum: an allow-list the validator checks — the enforced answer to
        # "what command-line tools can this agent run". Names come from the
        # ENFORCED set, so the panel can never show a binary that isn't
        # actually allowed; TOOL_PURPOSES only decorates them with a
        # one-liner, and a binary with no entry there simply shows no purpose.
        cli["enforced"] = True
        cli["items"] = [{"name": b, "purpose": str(purposes.get(b, ""))}
                        for b in sorted(str(x) for x in allowed)]
        cli["note"] = ("This is the agent's command allow-list: it can run these "
                       "programs and no others. Every invocation is also scope-checked "
                       "and screened for shell metacharacters before it runs.")
    else:
        ext = _external_tools(assigns)
        if ext:
            cli["items"] = ext
            cli["note"] = ("The external programs and services this agent uses. It "
                           "does not run arbitrary shell commands; these are the fixed "
                           "tools its own code invokes.")

    registry_names = _registry_tool_names(tree)
    mcp_tools = _tool_decorators(tree)
    if not mcp_tools and registry_names:
        mcp_tools = _registry_tools(registry_names)

    category = _registry_category(registry_names) if registry_names else None
    def _const(key, limit):
        v = _literal(assigns.get(key)) if key in assigns else None
        return v.strip()[:limit] if isinstance(v, str) and v.strip() else None
    return {
        "agent": name,
        # Optional display text a hand-built agent declares (AGENT_TITLE /
        # AGENT_DESCRIPTION); a manifest-driven one carries it in manifest.json.
        "title": _const("AGENT_TITLE", 80),
        "description": _const("AGENT_DESCRIPTION", 300),
        "scope_kind": _scope_kind(assigns),
        "category": category,
        "mcp_tools": mcp_tools,
        "command_line_tools": cli,
        "denied_patterns": [str(p) for p in denied] if isinstance(denied, (list, tuple)) else [],
    }


_MANIFEST_SCOPE_LABELS = {"cidr": "CIDRScope", "domain": "DomainScope", "files": "FilesScope"}


def _manifest_supplement(agent_path: str) -> dict | None:
    """A manifest-driven agent (CLAUDE.md "Current plan", phase 5 of the
    generic-launcher arc) has no `@tool` decorators, no `build_tools([...])`
    call with a literal name list, and no `SCOPE = ...Scope(...)` assignment
    anywhere in its own source — every one of those lives in manifest.json
    instead, read at RUN time by `AgentContract.from_manifest()`. Without
    this, such an agent's Tools & permissions panel would report "none",
    exactly the regression phase 2 already found once when tools moved into
    tool_registry.py (§4 item 28) — the same shape of gap, one layer further
    out. Read alongside the agent's own source file (same directory) when
    present; a missing/unreadable/malformed manifest degrades to None
    (describe()'s own result stands unchanged), never a crash."""
    manifest_path = Path(agent_path).with_name("manifest.json")
    if not manifest_path.is_file():
        return None
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    # A manifest-driven agent's tools are usually just NAMES, looked up in
    # the shared tool_registry (enum/research/trafficmon). exploit-agent's
    # tools (request_exploit, run_session_command, list_sessions) are its
    # own, not in that registry, so its manifest.json inline-describes them
    # as {"name", "purpose"} dicts under "tools" instead — read that FIRST;
    # found live 2026-10-08: without this, the panel showed "none" for
    # exploit even though manifest.json had the real descriptions all along.
    inline_tools_raw = data.get("tools")
    inline_tools = [{"name": str(t["name"])[:64], "purpose": str(t.get("purpose") or "")[:300], "params": []}
                    for t in inline_tools_raw if isinstance(t, dict) and isinstance(t.get("name"), str)] \
                   if isinstance(inline_tools_raw, list) else []
    names = data.get("tool_names")
    names = [str(n) for n in names] if isinstance(names, list) else []
    # analysis_runner.setup() adds extract_hashes for any agent with a hash
    # cracker; declare it the same way so the Tools panel and drift check agree.
    progs_named = {p.get("name") for p in data.get("programs") or [] if isinstance(p, dict)}
    if data.get("kind") == "analysis" and progs_named & {"john", "hashcat"}:
        names = (names or ["analyze_file", "read_output"]) + \
            ([] if "extract_hashes" in names else ["extract_hashes"])
    category = data.get("category")
    category = str(category) if isinstance(category, str) and category else None
    def _text(key, limit):
        v = data.get(key)
        return v.strip()[:limit] if isinstance(v, str) and v.strip() else None
    # An agent's allow-list lives in its manifest (shared/recon_runner.py,
    # shared/analysis_runner.py), so the "command-line tools" panel is built
    # from it. A recon agent shares one fixed set of denied argument patterns;
    # a file-analysis agent has none, because its programs are not allow-listed
    # by name and pattern but by the option-by-option rules in
    # shared/analysis_programs.py, and run in a sandbox.
    cli = None
    denied: list = []
    progs = data.get("programs")
    if isinstance(progs, list) and progs:
        items = [{"name": str(p["name"])[:64], "purpose": str(p.get("purpose") or "")[:200]}
                 for p in progs if isinstance(p, dict) and isinstance(p.get("name"), str)]
        analysis = data.get("kind") == "analysis"
        cli = {"enforced": True, "items": items,
               "note": ("Each program runs in a sandbox with no network, on the run's attached files only, "
                        "and accepts only the options reviewed for it." if analysis else "")}
        if not analysis:
            try:
                import tool_registry
                denied = [str(x) for x in tool_registry.RECON_DENIED_PATTERNS]
            except Exception:
                denied = []
    elif data.get("module_catalog"):
        # Plugin agents (e.g. the exploit agent) declare a "module_catalog"
        # key in their manifest.json naming a Python module that exports a
        # MODULES dict of {fullname: spec} where spec.description is a str.
        # The panel shows the catalog items the same way a program list is shown
        # for file-analysis agents. The import is optional: if the module is
        # absent (open core without the plugin package), cli stays None.
        try:
            import importlib
            catalog_mod_name = str(data["module_catalog"])
            catalog_mod = importlib.import_module(catalog_mod_name)
            items = [{"name": fullname, "purpose": str(getattr(spec, "description", ""))[:200]}
                     for fullname, spec in sorted(catalog_mod.MODULES.items())]
            note = str(data.get("module_catalog_note") or "")
            cli = {"enforced": True, "items": items, "note": note[:500]}
        except Exception:
            cli = None
    return {
        "command_line_tools": cli,
        "denied_patterns": denied,
        "agent": _text("name", 64),
        "title": _text("title", 80),
        "description": _text("description", 300),
        # Set only on an agent built in Settings -> Agents (agent_builder.py):
        # who built it and when. Marks it as removable from the GUI.
        "built": ({"by": str(data["built"].get("by", ""))[:64], "at": str(data["built"].get("at", ""))[:40]}
                  if isinstance(data.get("built"), dict) else None),
        "mcp_tools": inline_tools or _registry_tools(names),
        "scope_kind": _MANIFEST_SCOPE_LABELS.get(str(data.get("scope_kind", ""))),
        "category": category,
    }


def describe_agent(agent_path: str) -> dict:
    """The full descriptor for one agent file: what describe() finds in its
    source, overlaid with the facts a manifest.json beside it supplies (a
    recon agent's identity, programs and scope live there, not in its stub).
    Raises OSError / SyntaxError exactly like describe() on an unreadable or
    unparseable source."""
    source = open(agent_path, encoding="utf-8").read()
    d = describe(source)
    supplement = _manifest_supplement(agent_path)
    if supplement:
        if supplement["mcp_tools"]:
            d["mcp_tools"] = supplement["mcp_tools"]
        if supplement["scope_kind"]:
            d["scope_kind"] = supplement["scope_kind"]
        if supplement["command_line_tools"]:
            d["command_line_tools"] = supplement["command_line_tools"]
            d["denied_patterns"] = supplement["denied_patterns"]
        if supplement["category"]:
            d["category"] = supplement["category"]
        if supplement["agent"] and not d.get("agent"):
            d["agent"] = supplement["agent"]
        for key in ("title", "description", "built"):
            if supplement[key]:
                d[key] = supplement[key]
    return d


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: gen_capabilities.py <agent-source.py>", file=sys.stderr)
        return 2
    try:
        d = describe_agent(argv[1])
    except OSError as e:
        print(f"cannot read {argv[1]}: {e}", file=sys.stderr)
        return 1
    except SyntaxError as e:
        print(f"cannot parse {argv[1]}: {e}", file=sys.stderr)
        return 1
    print(json.dumps(d, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
