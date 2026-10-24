#!/usr/bin/env python3
"""test_recon_runner.py — the generic recon runner (shared/recon_runner.py).

    python3 shared/test_recon_runner.py

No root, no vault, no SDK (a structural fake of claude_agent_sdk is installed
first, the same way test_tool_registry.py does it). What matters:
  * a manifest binds the runner to ONE agent and ONE program allow-list;
  * every program is re-checked at run time against the baseline list and the
    reviewed catalog — a hand-edited manifest cannot smuggle in a program the
    catalog refuses (shells, exploitation tooling, anything blocked);
  * the denied argument patterns and the tool set are fixed, never from the
    manifest;
  * the commands the run's tools will actually accept are exactly the
    manifest's programs, with the catalog's own extra refusals applied.
"""
import json
import os
import sys
import tempfile
import types
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

# ---- a structurally faithful fake of claude_agent_sdk, before any import ----
_fake = types.ModuleType("claude_agent_sdk")


def _tool(name, description, schema):
    def deco(fn):
        fn.tool_name, fn.description, fn.input_schema = name, description, schema
        return fn
    return deco


class _Stub:
    def __init__(self, *a, **k):
        pass


_fake.tool = _tool
_fake.ClaudeAgentOptions = _Stub
_fake.ClaudeSDKClient = _Stub
_fake.HookMatcher = _Stub
_fake.ResultMessage = type("ResultMessage", (), {})
_fake.create_sdk_mcp_server = lambda **kw: types.SimpleNamespace(**kw)
sys.modules["claude_agent_sdk"] = _fake

PASS = FAIL = 0


def check(label, got, want):
    global PASS, FAIL
    if got == want:
        PASS += 1; print(f"  [ OK ] {label}")
    else:
        FAIL += 1; print(f"  [FAIL] {label}\n         got  {got!r}\n         want {want!r}")


def section(t): print(f"\n=== {t} ===")


root = Path(tempfile.mkdtemp(prefix="agenti-test-recon-"))
(root / "shared").mkdir()
(root / "default").mkdir()
os.environ["AGENTI_ROOT"] = str(root)
os.environ.pop("AGENTI_INSTANCE", None)

import tool_catalog as tc  # noqa: E402

# the real shipped catalog, so the test covers what is actually deployed, in
# the code folder where the package installs it
(root / "lib").mkdir()
os.environ["AGENTI_LIBDIR"] = str(root / "lib")
CATALOG = root / "lib" / "tool-catalog.json"
CATALOG.write_text((HERE / "tool-catalog.json").read_text())
import recon_runner as rr  # noqa: E402


def write_manifest(name, programs, folder=None, **extra):
    d = root / "agents" / (folder or name); d.mkdir(parents=True, exist_ok=True)
    m = {"name": name, "title": name.title(), "description": "test", "kind": "recon",
         "scope_kind": "cidr", "tool_names": ["run_scan", "read_scan"], "programs": programs, **extra}
    p = d / "manifest.json"; p.write_text(json.dumps(m)); return p


def refuses(fn):
    try:
        fn()
    except SystemExit as e:
        return str(e)
    except rr.ManifestError as e:
        return str(e)
    return None


section("the shipped enum manifest binds the runner to enum")
(root / "agents" / "enum").mkdir(parents=True)
(root / "agents" / "enum" / "manifest.json").write_text((HERE.parent / "enum-agent" / "manifest.json").read_text())
rr.setup(root / "agents" / "enum" / "manifest.json")
check("agent name", rr.AGENT_NAME, "enum")
check("scope is a CIDR boundary", rr.SCOPE.kind, "cidr")
check("every baseline program is allowed",
      rr.ALLOWED_BINARIES, {p["name"] for p in tc.baseline_programs(tc.load_catalog(CATALOG))})
check("the tools are exactly run_scan and read_scan (plus the harness's own)",
      [n for n in rr.CONTRACT.tool_names if n in ("run_scan", "read_scan")], ["run_scan", "read_scan"])
check("ask_operator and suggest_preference are always offered",
      {"ask_operator", "suggest_preference"} <= set(rr.CONTRACT.tool_names), True)
check("no team tools for a solo run", {"team_message", "propose_complete"} & set(rr.CONTRACT.tool_names), set())
check("the denied patterns are the fixed shared constant", rr.DENIED_PATTERNS, list(rr.tool_registry.RECON_DENIED_PATTERNS))

section("a built agent: only the programs it was given")
rr.setup(write_manifest("dns-check", [{"name": "dig", "purpose": "DNS lookups"},
                                       {"name": "ping", "purpose": "reachability"}]))
check("identity follows the manifest", (rr.AGENT_NAME, rr.AGENT_TITLE), ("dns-check", "Dns-Check"))
check("allow-list is exactly the two programs", rr.ALLOWED_BINARIES, {"dig", "ping"})
check("purposes are kept for the panel", rr.TOOL_PURPOSES["dig"], "DNS lookups")

section("the catalog's own refusals apply to a catalog program baked into a manifest")
rr.setup(write_manifest("web-check", [{"name": "curl", "purpose": "fetch headers"}]))
check("curl is allowed", rr.ALLOWED_BINARIES, {"curl"})
from tool_registry import validate_shell_command  # noqa: E402
ok1, why1 = validate_shell_command("curl -I http://10.0.0.5/", allowed_binaries=rr.ALLOWED_BINARIES,
                                   denied_patterns=rr.DENIED_PATTERNS + tc.patterns_for_programs({"curl"}, tc.load_catalog(CATALOG)),
                                   scope=rr.SCOPE, scope_ceiling=rr.SCOPE.ceiling_from_engagement(
                                       types.SimpleNamespace(in_scope=["10.0.0.0/24"], out_of_scope=[])))
check("a plain header request to an in-scope host passes", ok1, True)
ok2, why2 = validate_shell_command("curl -X POST http://10.0.0.5/", allowed_binaries=rr.ALLOWED_BINARIES,
                                   denied_patterns=rr.DENIED_PATTERNS + tc.patterns_for_programs({"curl"}, tc.load_catalog(CATALOG)),
                                   scope=rr.SCOPE, scope_ceiling=rr.SCOPE.ceiling_from_engagement(
                                       types.SimpleNamespace(in_scope=["10.0.0.0/24"], out_of_scope=[])))
check("curl's own extra refusal (POST) still applies", ok2, False)

section("a hand-edited manifest cannot smuggle a program in")
for bad, why in (("bash", "block list"), ("sqlmap", "never"), ("python3", "block list"),
                 ("definitely-not-a-listed-tool", "not in the baseline")):
    msg = refuses(lambda b=bad: rr.setup(write_manifest("evil", [{"name": b, "purpose": "x"}])))
    check(f"{bad!r} refused", msg is not None and "REFUSING" in msg, True)
msg = refuses(lambda: rr.setup(write_manifest("evil", [])))
check("an empty program list refused", msg is not None, True)
msg = refuses(lambda: rr.setup(write_manifest("evil", [{"name": "nmap", "purpose": "x"}], scope_kind="domain")))
check("a non-network scope kind refused", msg is not None and "cidr" in msg, True)
msg = refuses(lambda: rr.setup(write_manifest("Bad Name", [{"name": "nmap", "purpose": "x"}], folder="bad-name")))
check("an invalid agent name refused", msg is not None, True)
msg = refuses(lambda: rr.setup(write_manifest("enum", [{"name": "nmap", "purpose": "x"}], folder="other-agent")))
check("a manifest in another agent's folder is refused", msg is not None and "must match" in msg, True)

print(f"\n{'=' * 52}\n  {PASS} passed, {FAIL} failed\n{'=' * 52}")
sys.exit(1 if FAIL else 0)
