#!/usr/bin/env python3
"""test_capabilities.py — the static tools/permissions descriptor
(shared/gen_capabilities.py, §4 item 26).

    python3 shared/test_capabilities.py

No dependencies. The point of this generator is that it reads what the agent
is ACTUALLY allowed to do, straight from the declarations that enforce it, by
static analysis — so the panel it feeds can never claim a tool the agent
cannot use. These cases pin that: the command-line list is derived from the
ENFORCED set (ALLOWED_BINARIES), a purpose entry for a binary NOT in that set
is dropped rather than shown, the @tool descriptions come through with their
adjacent-string concatenation joined, and anything dynamic degrades to absent
rather than crashing. It also runs the generator against the three real agent
sources when they are present, so a change to one that breaks the parse is
caught here.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gen_capabilities as gc  # noqa: E402

PASS = FAIL = 0


def check(label, got, want):
    global PASS, FAIL
    if got == want:
        PASS += 1; print(f"  [ OK ] {label}")
    else:
        FAIL += 1; print(f"  [FAIL] {label}\n         got  {got!r}\n         want {want!r}")


def section(t): print(f"\n=== {t} ===")


ENUM_LIKE = '''
AGENT_NAME = "sample"
SCOPE = CIDRScope(agent_name="sample")
ALLOWED_BINARIES = {"nmap", "dig", "ping"}
TOOL_PURPOSES = {
    "nmap": "port scanner",
    "dig": "dns lookups",
    "not_allowed": "should never be shown",   # not in ALLOWED_BINARIES
}
DENIED_PATTERNS = [r"[;&|]", r">|>>"]

@tool(
    "run_scan",
    "Run one in-scope command. Returns a trimmed "
    "summary and an index.",
    {"command": str},
)
async def run_scan(args):
    pass

@tool("read_scan", "Retrieve part of a saved scan.", {"file": str, "pattern": str})
async def read_scan(args):
    pass
'''

section("enum-shape: enforced allow-list, purposes, denied patterns")
d = gc.describe(ENUM_LIKE)
check("agent name", d["agent"], "sample")
check("scope kind", d["scope_kind"], "CIDRScope")
check("mcp tool names", [t["name"] for t in d["mcp_tools"]], ["run_scan", "read_scan"])
check("adjacent-string description joined",
      d["mcp_tools"][0]["purpose"], "Run one in-scope command. Returns a trimmed summary and an index.")
check("schema params captured", d["mcp_tools"][1]["params"], ["file", "pattern"])
cli = d["command_line_tools"]
check("command-line list is marked ENFORCED", cli["enforced"], True)
check("names come from the enforced set, sorted", [i["name"] for i in cli["items"]], ["dig", "nmap", "ping"])
check("purposes applied where present", {i["name"]: i["purpose"] for i in cli["items"]},
      {"dig": "dns lookups", "nmap": "port scanner", "ping": ""})
check("a purpose for a NON-allowed binary is never shown",
      any(i["name"] == "not_allowed" for i in cli["items"]), False)
check("denied patterns", d["denied_patterns"], ["[;&|]", ">|>>"])
check("note present for the enforced case", bool(cli["note"]), True)

EXTERNAL_LIKE = '''
AGENT_NAME = "watcher"
SCOPE = DomainScope(agent_name="watcher")
EXTERNAL_TOOLS = [
    ("tshark", "decodes a pcap"),
    "suricata",
]

@tool("fetch", "Fetch a page.", {"url": str})
async def fetch(args):
    pass
'''

section("external-tools shape: no allow-list, fixed programs")
d = gc.describe(EXTERNAL_LIKE)
check("scope kind", d["scope_kind"], "DomainScope")
cli = d["command_line_tools"]
check("NOT enforced (no ALLOWED_BINARIES)", cli["enforced"], False)
check("(name, purpose) pair parsed", cli["items"][0], {"name": "tshark", "purpose": "decodes a pcap"})
check("bare string parsed with empty purpose", cli["items"][1], {"name": "suricata", "purpose": ""})
check("no denied patterns", d["denied_patterns"], [])

section("degrades, never crashes, on missing / dynamic declarations")
check("empty source: no tools, no scope",
      gc.describe("x = 1\n"), {"agent": None, "title": None, "description": None, "scope_kind": None, "category": None,
                               "mcp_tools": [],
                               "command_line_tools": {"enforced": False, "items": [], "note": ""},
                               "denied_patterns": []})
check("AGENT_TITLE / AGENT_DESCRIPTION are read as display text",
      {k: gc.describe('AGENT_TITLE = "Net enum"\nAGENT_DESCRIPTION = "Maps hosts."\n')[k] for k in ("title", "description")},
      {"title": "Net enum", "description": "Maps hosts."})
d = gc.describe("ALLOWED_BINARIES = set(some_dynamic_thing)\n")
check("a dynamically-built allow-list is treated as absent, not a crash",
      d["command_line_tools"]["enforced"], False)
d = gc.describe("EXTERNAL_TOOLS = a_variable\n")
check("a dynamic EXTERNAL_TOOLS is empty, not a crash", d["command_line_tools"]["items"], [])
d = gc.describe('@tool("t", "desc")\nasync def t(args): pass\n')
check("a @tool with no schema still parses (no params)", d["mcp_tools"][0]["params"], [])
try:
    gc.describe("def broken(:\n")   # a real SyntaxError
    check("a syntax error raises SyntaxError (deploy handles it)", False, True)
except SyntaxError:
    check("a syntax error raises SyntaxError (deploy handles it)", True, True)

section("the tool_registry fallback (phase 2 of the generic-launcher arc)")
# When no @tool decorator exists directly in the source (because the tool
# bodies moved to shared/tool_registry.py), describe() must fall back to
# reading the literal name list out of a build_tools(...) call and looking
# each one up in the actual registry -- this is the exact regression this
# phase introduced and then fixed: gen_capabilities.py's static scraper
# found zero tools for all three real agents until this fallback existed.
REGISTRY_STYLE = '''
AGENT_NAME = "widget"
SCOPE = CIDRScope(agent_name="widget")
import tool_registry
TOOL_CTX = tool_registry.ToolContext(log=None)
_TOOL_NAMES, _TOOLS = tool_registry.build_tools(["run_scan", "read_scan"], TOOL_CTX)
'''
d = gc.describe(REGISTRY_STYLE)
check("falls back to the registry when no @tool decorator is present in the source",
      sorted(t["name"] for t in d["mcp_tools"]), ["read_scan", "run_scan"])
check("...with real purposes from the registry, not placeholders",
      all(t["purpose"] for t in d["mcp_tools"]), True)
check("...and real schema params", d["mcp_tools"][[t["name"] for t in d["mcp_tools"]].index("run_scan")]["params"],
      ["command"])
check("category is derived from the registry when every named tool agrees",
      d["category"], "cybersecurity")

MIXED_CATEGORY_STYLE = '''
AGENT_NAME = "widget5"
SCOPE = CIDRScope(agent_name="widget5")
import tool_registry
TOOL_CTX = tool_registry.ToolContext(log=None)
_TOOL_NAMES, _TOOLS = tool_registry.build_tools(["run_scan", "web_search"], TOOL_CTX)
'''
d = gc.describe(MIXED_CATEGORY_STYLE)
check("tools from two different categories: no single category is claimed",
      d["category"], None)

BARE_IMPORT_STYLE = '''
AGENT_NAME = "widget2"
SCOPE = DomainScope(agent_name="widget2")
from tool_registry import build_tools, ToolContext
TOOL_CTX = ToolContext(log=None)
_TOOL_NAMES, _TOOLS = build_tools(["fetch_page"], TOOL_CTX)
'''
d = gc.describe(BARE_IMPORT_STYLE)
check("also works with a bare `from tool_registry import build_tools`",
      [t["name"] for t in d["mcp_tools"]], ["fetch_page"])

NO_TOOLS_STYLE = "AGENT_NAME = \"nothing\"\nSCOPE = CIDRScope(agent_name=\"nothing\")\n"
d = gc.describe(NO_TOOLS_STYLE)
check("no @tool decorator and no registry call: empty, not a crash", d["mcp_tools"], [])

UNKNOWN_NAME_STYLE = '''
AGENT_NAME = "widget3"
SCOPE = CIDRScope(agent_name="widget3")
import tool_registry
_TOOL_NAMES, _TOOLS = tool_registry.build_tools(["run_scan", "not-a-real-tool"], TOOL_CTX)
'''
d = gc.describe(UNKNOWN_NAME_STYLE)
check("an unregistered name in the list is silently skipped, not fatal",
      [t["name"] for t in d["mcp_tools"]], ["run_scan"])

DYNAMIC_LIST_STYLE = '''
AGENT_NAME = "widget4"
SCOPE = CIDRScope(agent_name="widget4")
names = compute_names()
_TOOL_NAMES, _TOOLS = tool_registry.build_tools(names, TOOL_CTX)
'''
d = gc.describe(DYNAMIC_LIST_STYLE)
check("a dynamically-built name list degrades to no tools, not a crash", d["mcp_tools"], [])
# An @tool decorator directly in the file still wins over any registry call
# present elsewhere in the same source (the direct case is unambiguous).
BOTH_STYLE = ENUM_LIKE + '''
_TOOL_NAMES, _TOOLS = tool_registry.build_tools(["web_search"], TOOL_CTX)
'''
d = gc.describe(BOTH_STYLE)
check("a real @tool decorator in the file takes priority over any registry call",
      sorted(t["name"] for t in d["mcp_tools"]), ["read_scan", "run_scan"])


section("the real agents parse and describe themselves")
root = Path(__file__).resolve().parent.parent
# cracker is file-analysis: analysis_runner gives it analyze_file and
# read_output, plus extract_hashes because it has a hash cracker (2026-10-16).
# The descriptor used to list none, so the Tools panel hid what it really had.
if (root / "cracker-agent" / "cracker-agent.py").exists():
    check("the cracker declares the three tools its runner builds",
          sorted(t["name"] for t in gc.describe_agent(str(root / "cracker-agent" / "cracker-agent.py"))["mcp_tools"]),
          ["analyze_file", "extract_hashes", "read_output"])
else:
    print("  [skip] cracker: source not present (agenti-cracker)")
for name, want_scope, enforced, want_category, want_tools in [
        ("enum", "CIDRScope", True, "cybersecurity", True),
        ("research", "DomainScope", False, "research", True),
        ("trafficmon", "CIDRScope", False, "network-evidence", True),
        ("cracker", "FilesScope", True, "file-analysis", True),
        ("exploit", "CIDRScope", True, "exploitation", True)]:
    src = root / f"{name}-agent" / f"{name}-agent.py"
    if not src.exists():
        print(f"  [skip] {name}: source not present"); continue
    d = gc.describe_agent(str(src))   # source + the manifest beside it, as deploy.sh sees it
    check(f"{name}: names itself", d["agent"], name)
    check(f"{name}: scope kind", d["scope_kind"], want_scope)
    check(f"{name}: declares at least one MCP tool", len(d["mcp_tools"]) >= 1, want_tools)
    check(f"{name}: command-line enforced flag", d["command_line_tools"]["enforced"], enforced)
    check(f"{name}: has at least one program/service listed",
          len(d["command_line_tools"]["items"]) >= 1, True)
    check(f"{name}: category", d["category"], want_category)
    # the descriptor must be JSON-serialisable — it is written to a file
    json.dumps(d)

section("the manifest supplement (phase 5 of the generic-launcher arc): a "
       "manifest-driven agent has no @tool/build_tools/SCOPE in its own "
       "source at all -- gen_capabilities reads manifest.json alongside it")
import tempfile
import subprocess

tmp = Path(tempfile.mkdtemp(prefix="agenti-test-capabilities-"))
try:
    agent_src = tmp / "recon-demo-agent.py"
    agent_src.write_text("AGENT_NAME = \"recon-demo\"\n")   # no @tool, no SCOPE at all
    manifest = tmp / "manifest.json"
    manifest.write_text(json.dumps({
        "name": "recon-demo", "tool_names": ["run_scan", "read_scan"],
        "scope_kind": "cidr", "task": "t",
    }))
    supp = gc._manifest_supplement(str(agent_src))
    check("manifest supplement finds tool names via the real registry",
          sorted(t["name"] for t in supp["mcp_tools"]),
          sorted(["run_scan", "read_scan"]))
    check("...with real purposes, not placeholders",
          all(t["purpose"] for t in supp["mcp_tools"]), True)
    check("manifest supplement maps scope_kind to the class-name label",
          supp["scope_kind"], "CIDRScope")
    check("manifest with no 'category' field: supplement carries none",
          supp["category"], None)

    d = gc.describe(agent_src.read_text())
    check("describe() alone (no manifest awareness) sees zero tools and no scope kind",
          (d["mcp_tools"], d["scope_kind"]), ([], None))

    manifest.write_text(json.dumps({
        "name": "recon-demo", "tool_names": ["run_scan", "read_scan"],
        "scope_kind": "cidr", "task": "t", "category": "cybersecurity",
    }))
    supp_cat = gc._manifest_supplement(str(agent_src))
    check("manifest's own 'category' field is read directly, not re-derived",
          supp_cat["category"], "cybersecurity")

    # The actual end-to-end path: invoke gen_capabilities.py as a real
    # subprocess exactly the way deploy.sh does, proving main()'s merge
    # (not just the helper function) produces the enriched result.
    gen_path = Path(__file__).resolve().parent / "gen_capabilities.py"
    out = subprocess.run([sys.executable, str(gen_path), str(agent_src)],
                        capture_output=True, text=True, check=True).stdout
    merged = json.loads(out)
    check("main() merges the manifest supplement into the printed descriptor",
          sorted(t["name"] for t in merged["mcp_tools"]),
          sorted(["run_scan", "read_scan"]))
    check("...and the scope kind too", merged["scope_kind"], "CIDRScope")
    check("...and the category too", merged["category"], "cybersecurity")

    no_manifest_dir = tmp / "solo"
    no_manifest_dir.mkdir()
    solo_src = no_manifest_dir / "solo-agent.py"
    solo_src.write_text("AGENT_NAME = \"solo\"\n")
    check("no sibling manifest.json at all: supplement is None, not a crash",
          gc._manifest_supplement(str(solo_src)), None)

    bad_manifest_dir = tmp / "bad"
    bad_manifest_dir.mkdir()
    (bad_manifest_dir / "manifest.json").write_text("{not valid json")
    (bad_manifest_dir / "bad-agent.py").write_text("AGENT_NAME = \"bad\"\n")
    check("a malformed manifest.json degrades to None, never crashes deploy",
          gc._manifest_supplement(str(bad_manifest_dir / "bad-agent.py")), None)

    unknown_dir = tmp / "unknown"
    unknown_dir.mkdir()
    (unknown_dir / "manifest.json").write_text(json.dumps(
        {"tool_names": ["run_scan", "not_a_real_tool"], "scope_kind": "cidr"}))
    (unknown_dir / "u-agent.py").write_text("AGENT_NAME = \"u\"\n")
    supp2 = gc._manifest_supplement(str(unknown_dir / "u-agent.py"))
    check("an unregistered tool name in the manifest is silently skipped, not fatal",
          [t["name"] for t in supp2["mcp_tools"]], ["run_scan"])

    # exploit-agent's own tools (request_exploit, run_session_command,
    # list_sessions) are NOT in the shared tool_registry — they're inline-
    # described in manifest.json as {"name","purpose"} dicts under "tools".
    # Found live 2026-10-08: without reading that field, the Tools &
    # permissions panel showed "none" for exploit even though the real
    # descriptions were sitting in manifest.json the whole time.
    inline_dir = tmp / "inline"
    inline_dir.mkdir()
    (inline_dir / "manifest.json").write_text(json.dumps({
        "name": "exploit-demo", "scope_kind": "cidr", "kind": "exploit",
        "module_catalog": "msf_module_catalog",
        "module_catalog_note": "Test note.",
        "tools": [{"name": "request_exploit", "purpose": "Propose a module."},
                  {"name": "list_sessions", "purpose": "List open sessions."}],
    }))
    (inline_dir / "exploit-demo-agent.py").write_text("AGENT_NAME = \"exploit-demo\"\n")
    supp3 = gc._manifest_supplement(str(inline_dir / "exploit-demo-agent.py"))
    check("manifest's inline 'tools' dicts are read directly, no registry lookup needed",
          sorted(t["name"] for t in supp3["mcp_tools"]),
          sorted(["request_exploit", "list_sessions"]))
    check("...with the manifest's own purpose text, verbatim",
          next(t["purpose"] for t in supp3["mcp_tools"] if t["name"] == "request_exploit"),
          "Propose a module.")
    # module_catalog key in manifest wires up the reviewed module allow-list as the
    # command-line tool table — same "every privileged action comes from one reviewed
    # list" story as analysis_programs.py, backed by msf_module_catalog.py.
    if not (Path(__file__).resolve().parent / "msf_module_catalog.py").exists():
        print("  [skip] module_catalog table — msf_module_catalog.py (agenti-exploit) is not in this checkout")
    else:
        check("module_catalog key gets the Metasploit module catalog as its allow-list",
              supp3["command_line_tools"]["enforced"], True)
        check("...naming real, fully-qualified module paths",
              any("/" in it["name"] for it in supp3["command_line_tools"]["items"]), True)
        check("...each with a non-empty description",
              all(it["purpose"] for it in supp3["command_line_tools"]["items"]), True)
finally:
    import shutil
    shutil.rmtree(tmp, ignore_errors=True)

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
