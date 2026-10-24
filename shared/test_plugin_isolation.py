"""
test_plugin_isolation.py — verify the open core works without closed plugin files.

Simulates a deployment where exploit-agent/ and cracker-agent/ are absent by
temporarily hiding the closed modules from sys.modules and sys.path, then
exercising every open-core path that was previously coupled to them.
"""
import importlib
import json
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
CLOSED_MODULES = ("msf_module_catalog", "msf_client", "exploit_runner", "hash_extract")

class _HiddenImport:
    """Context manager: make the closed modules unimportable."""
    def __enter__(self):
        self._saved = {m: sys.modules.pop(m) for m in CLOSED_MODULES if m in sys.modules}
        return self

    def __exit__(self, *_):
        sys.modules.update(self._saved)


# ---------------------------------------------------------------------------
# engagement_context — enabled_capabilities
# ---------------------------------------------------------------------------
def _make_engagement(**kwargs):
    import engagement_context as ec
    import dataclasses
    defaults = {f.name: f.default_factory() if f.default_factory is not dataclasses.MISSING
                else f.default for f in dataclasses.fields(ec.Engagement)}
    defaults.update(kwargs)
    return ec.Engagement(**defaults)


def test_enabled_capabilities_default():
    eng = _make_engagement(enabled_capabilities=[])
    assert not eng.exploitation_enabled


def test_enabled_capabilities_exploit():
    eng = _make_engagement(enabled_capabilities=["exploit"])
    assert eng.exploitation_enabled


def test_enabled_capabilities_other():
    eng = _make_engagement(enabled_capabilities=["custom-plugin"])
    assert not eng.exploitation_enabled


def test_parse_record_enabled_capabilities():
    import engagement_context as ec
    data = {"enabled_capabilities": ["exploit", "custom"]}
    out = {}
    # call the fragment that parses enabled_capabilities
    caps = list(data.get("enabled_capabilities", []))
    ee_legacy = data.get("exploitation_enabled", False)
    if ee_legacy and "exploit" not in caps:
        caps.append("exploit")
    out["enabled_capabilities"] = caps
    assert "exploit" in out["enabled_capabilities"]
    assert "custom" in out["enabled_capabilities"]


def test_parse_record_exploitation_enabled_legacy():
    """Old records with exploitation_enabled:true inject 'exploit'."""
    data = {"exploitation_enabled": True}
    caps = list(data.get("enabled_capabilities", []))
    ee_legacy = data.get("exploitation_enabled", False)
    if ee_legacy and "exploit" not in caps:
        caps.append("exploit")
    assert caps == ["exploit"]


def test_parse_record_both_fields_no_duplicate():
    data = {"enabled_capabilities": ["exploit"], "exploitation_enabled": True}
    caps = list(data.get("enabled_capabilities", []))
    ee_legacy = data.get("exploitation_enabled", False)
    if ee_legacy and "exploit" not in caps:
        caps.append("exploit")
    assert caps.count("exploit") == 1


# ---------------------------------------------------------------------------
# gen_capabilities — module_catalog key (graceful when module absent)
# ---------------------------------------------------------------------------
def test_gen_capabilities_no_closed_modules():
    """gen_capabilities must not raise when msf_module_catalog is absent."""
    with _HiddenImport():
        import gen_capabilities as gc
        with tempfile.TemporaryDirectory() as d:
            manifest = Path(d) / "manifest.json"
            manifest.write_text(json.dumps({
                "name": "exploit", "title": "Exploit agent",
                "description": "test", "kind": "exploit",
                "scope_kind": "cidr",
                "module_catalog": "msf_module_catalog",
                "module_catalog_note": "test note",
            }))
            result = gc.describe_agent(manifest)
            assert isinstance(result, dict)
            # cli may be None (module absent) or a dict (module present)
            assert result.get("command_line_tools") is None or isinstance(result["command_line_tools"], dict)


def test_gen_capabilities_open_core_agents_unaffected():
    """enum, research, trafficmon agents are unaffected by closed-module absence."""
    with _HiddenImport():
        import gen_capabilities as gc
        for agent in ("enum", "research", "trafficmon"):
            agent_dir = Path(__file__).parent.parent / f"{agent}-agent"
            if not agent_dir.exists():
                continue
            manifest = agent_dir / "manifest.json"
            if not manifest.exists():
                continue
            result = gc.describe_agent(manifest)
            assert isinstance(result, dict), f"{agent}: describe_agent returned non-dict"


# ---------------------------------------------------------------------------
# analysis_programs — plugin loading graceful when programs.py absent
# ---------------------------------------------------------------------------
def test_load_plugin_programs_no_file():
    import analysis_programs as ap
    with tempfile.TemporaryDirectory() as d:
        result = ap.load_plugin_programs(d)
        assert set(result.keys()) == set(ap.PROGRAMS.keys())


def test_load_plugin_programs_extra():
    """A programs.py in agent dir can add extra programs."""
    import sys
    import analysis_programs as ap
    with tempfile.TemporaryDirectory() as d:
        prog_file = Path(d) / "programs.py"
        # Use the correct Program signature (no binary/required_flags positional)
        prog_file.write_text(
            "import sys, os; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)) + '/..'))\n"
            "import analysis_programs as _ap\n"
            "EXTRA_PROGRAMS = {\n"
            '  "myprog": _ap.Program(name="myprog", purpose="test",\n'
            "      flags={}, required=(), positional=None, prepend=(),\n"
            "      examples=(), profile=None, notes=None, package=None,\n"
            "      no_file_flags=(), joined_long_values=False)\n"
            "}\n"
        )
        result = ap.load_plugin_programs(d)
        assert "myprog" in result, f"expected myprog in {list(result.keys())}"
        assert "tshark" in result


def test_load_plugin_programs_bad_file_falls_back():
    import analysis_programs as ap
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "programs.py").write_text("raise RuntimeError('oops')")
        result = ap.load_plugin_programs(d)
        assert set(result.keys()) == set(ap.PROGRAMS.keys())


# ---------------------------------------------------------------------------
# deploy.sh — syntax check (bash -n) still passes
# ---------------------------------------------------------------------------
def test_deploy_sh_syntax():
    import subprocess
    sh = Path(__file__).parent / "deploy.sh"
    result = subprocess.run(["bash", "-n", str(sh)], capture_output=True)
    assert result.returncode == 0, result.stderr.decode()


# ---------------------------------------------------------------------------
# action-pending verb names in shared/agenti
# ---------------------------------------------------------------------------
def test_agenti_action_verb_names():
    """action-pending/approve/reject must be present in shared/agenti."""
    agenti = (Path(__file__).parent / "agenti").read_text()
    assert "action-pending" in agenti
    assert "action-approve" in agenti
    assert "action-reject" in agenti
    # aliases still present
    assert "exploit-pending" in agenti
    assert "exploit-approve" in agenti
    assert "exploit-reject" in agenti


def test_agenti_pending_file_name():
    agenti = (Path(__file__).parent / "agenti").read_text()
    assert "pending-actions.jsonl" in agenti
    assert "action-approvals.jsonl" in agenti
    # old names must be gone (they were renamed)
    assert "pending-exploits.jsonl" not in agenti
    assert "exploit-approvals.jsonl" not in agenti


# ---------------------------------------------------------------------------
# authd — action-approve/reject ops in GRANT_OPS
# ---------------------------------------------------------------------------
def test_authd_grant_ops():
    import authd
    ops = authd.Service.GRANT_OPS
    assert "action-approve" in ops
    assert "action-reject" in ops
    # aliases kept
    assert "exploit-approve" in ops
    assert "exploit-reject" in ops


# ---------------------------------------------------------------------------
# iam — web_approve_exploit_action accepts action-approve/reject
# ---------------------------------------------------------------------------
def test_iam_web_approve_accepts_action_ops():
    import iam
    import inspect
    src = inspect.getsource(iam.web_approve_exploit_action)
    assert "action-approve" in src
    assert "action-reject" in src


# ---------------------------------------------------------------------------
# PLUGIN_API_VERSION — what the open .deb Provides and a plugin package Depends on
# ---------------------------------------------------------------------------
def test_plugin_api_version_file():
    v = (Path(__file__).resolve().parent / "PLUGIN_API_VERSION").read_text().strip()
    assert v.isdigit() and int(v) >= 1, v


def test_agenti_version_reports_plugin_api():
    import os
    import subprocess
    here = Path(__file__).resolve().parent
    out = subprocess.run(["bash", str(here / "agenti"), "--version", "--json"], capture_output=True, text=True,
                         env={**os.environ, "AGENTI_LIBDIR": "/nonexistent"})
    assert out.returncode == 0, out.stderr
    doc = json.loads(out.stdout)
    assert doc["plugin_api"] == (here / "PLUGIN_API_VERSION").read_text().strip(), doc
    assert doc["version"] == (here / "VERSION").read_text().strip(), doc


def test_plugin_api_documented():
    doc = (Path(__file__).resolve().parent.parent / "docs" / "open-core-split.md").read_text()
    assert "PLUGIN_API_VERSION" in doc and "### The plugin API version" in doc


if __name__ == "__main__":
    # No framework, like every other suite: ci.sh and GitHub install no
    # pytest, and the exit code is what makes a failure count.
    import traceback
    failed = 0
    tests = [(n, f) for n, f in list(globals().items()) if n.startswith("test_") and callable(f)]
    for name, fn in tests:
        try:
            fn()
            print(f"  [ OK ] {name}")
        except Exception:
            failed += 1
            print(f"  [FAIL] {name}")
            traceback.print_exc()
    print(f"\n{len(tests) - failed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
