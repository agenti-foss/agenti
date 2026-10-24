#!/usr/bin/env python3
"""test_session_runner.py — the ONE run loop (shared/session_runner.py).

    python3 shared/test_session_runner.py

No root, no vault, no network, no SDK: a scripted fake of claude_agent_sdk
stands in for the model, so the real run_session() runs start to finish.
What matters:
  * the loop starts the durable state, sends the kickoff, writes a report on
    the way out and finishes the history row — for a normal run;
  * an agent that supplies its own kickoff gets it sent, and a resume still
    sends the resume text, never the kickoff;
  * an agent's prepare() step runs BEFORE the model is started (trafficmon's
    capture), and one that finds nothing ends the run as "no data" with a
    report and without ever starting the model;
  * time spent in prepare() is counted against the run's wall-clock budget;
  * a model that crashes still leaves a report (a report on EVERY outcome).
"""
import asyncio
import json
import logging
import sys
import tempfile
import time
import types
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

# ---- a scripted stand-in for the SDK ---------------------------------------
SENT: list[str] = []          # every query() the loop made, in order
BUDGETS: list[float] = []     # the timeout the loop asked for


class _Result:
    """Looks enough like ResultMessage for the loop (isinstance + attributes)."""
    subtype = "success"
    stop_reason = "end_turn"
    is_error = False
    num_turns = 1
    total_cost_usd = 0.01
    result = "## Findings\n\nAll quiet."


class _Plain:
    """ClaudeAgentOptions / HookMatcher: constructed, never driven."""
    def __init__(self, *a, **k):
        pass


class _Fake(_Plain):
    """The client. `started` counts how many times the model was started."""
    crash = False
    started = 0

    def __init__(self, *a, **k):
        _Fake.started += 1

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def query(self, text):
        SENT.append(text)

    async def receive_response(self):
        if _Fake.crash:
            raise RuntimeError("the API is down")
        yield _Result()

    async def interrupt(self):
        pass


OPTIONS = []


class _Options(_Plain):
    def __init__(self, *a, **k):
        OPTIONS.append(k)


_fake = types.ModuleType("claude_agent_sdk")
_fake.ClaudeAgentOptions = _Options
_fake.ClaudeSDKClient = _Fake
_fake.HookMatcher = _Plain
_fake.ResultMessage = _Result
_fake.tool = lambda *a, **k: (lambda fn: fn)
_fake.create_sdk_mcp_server = lambda **kw: types.SimpleNamespace(**kw)
sys.modules["claude_agent_sdk"] = _fake

import engagement_context  # noqa: E402
import agent_runtime  # noqa: E402
import session_runner  # noqa: E402

# The loop reads the model's budget through asyncio.timeout(); record it.
_real_timeout = asyncio.timeout


def _spy_timeout(delay):
    BUDGETS.append(delay)
    return _real_timeout(delay)


asyncio.timeout = _spy_timeout

PASS = FAIL = 0


def check(label, got, want):
    global PASS, FAIL
    if got == want:
        PASS += 1; print(f"  [ OK ] {label}")
    else:
        FAIL += 1; print(f"  [FAIL] {label}\n         got  {got!r}\n         want {want!r}")


def section(t): print(f"\n=== {t} ===")


def session(slot: Path, **extra):
    """A Session over a throwaway run slot, with a report writer that records
    what it was asked to write."""
    reports = []

    def write_report(profile, result, started, status, note=None, resumed_from=None):
        path = slot / "reports" / f"r{len(reports)}.md"
        path.parent.mkdir(exist_ok=True)
        path.write_text(f"status={status}\nnote={note}\nresult={getattr(result, 'result', None)}\n")
        reports.append({"status": status, "note": note, "resumed_from": resumed_from,
                        "result": result, "started": started})
        return path

    prof = agent_runtime.Profile(name="run", model="claude-test", max_turns=5,
                                 max_budget_usd=1.0, timeout_s=100, data_root=slot)
    contract = types.SimpleNamespace(name="demo", mcp_server_name="demo",
                                     allowed_tool_names=["mcp__demo__x"])
    s = session_runner.Session(
        profile=prof, contract=contract, mcp_server=object(),
        allowlist_hook=lambda *a, **k: None, system_prompt="be useful",
        agent_dir=slot, org_dir=slot, log=logging.getLogger("t"),
        state_holder=agent_runtime.StateHolder(), engagement_id="ENG-1",
        target_label="10.0.0.0/24", write_report=write_report, **extra)
    return s, reports


def run(s):
    SENT.clear(); BUDGETS.clear(); _Fake.started = 0; _Fake.crash = False
    return asyncio.run(session_runner.run_session(s))


def fresh():
    slot = Path(tempfile.mkdtemp(prefix="agenti-test-session-"))
    (slot / "state").mkdir()
    return slot


section("an ordinary run")
slot = fresh()
s, reports = session(slot)
rc = run(s)
check("exit code 0 for a clean run", rc, 0)
check("the kickoff is what the model is first told", SENT, [agent_runtime.KICKOFF])
check("one report, marked completed", [r["status"] for r in reports], ["completed"])
hist = (slot / "state" / "history.jsonl").read_text()
check("the history row is written and names the report",
      "r0.md" in hist and '"status": "completed"' in hist, True)

section("an agent that supplies its own kickoff")
slot = fresh()
s, reports = session(slot, kickoff="A 60s capture is done. " + agent_runtime.KICKOFF)
run(s)
check("its kickoff is sent, not the default", SENT[0].startswith("A 60s capture is done."), True)

section("a resume sends the resume text, not the kickoff")
slot = fresh()
s, reports = session(slot, kickoff="custom kickoff")
(slot / "state").mkdir(exist_ok=True)
# A previous run to continue: start it, record a session id, finish it stopped.
import state as state_mod  # noqa: E402
prev = state_mod.StateStore(slot / "state")
prev.start(engagement_id="ENG-1", target="10.0.0.0/24", profile_name="run",
           launched_by="alice", launched_via="cli")
prev.session_started("sess-1234567890")
prev.finished(status="incomplete", reason="stopped")
(slot / "run-resume-session").write_text("sess-1234567890\n")
run(s)
check("the resume text was sent", SENT[0], session_runner.RESUME_TASK)
check("the custom kickoff was NOT sent", "custom kickoff" in SENT, False)
check("the report knows what it resumed", reports[0]["resumed_from"], "sess-1234567890")

section("prepare() runs before the model, and finding nothing ends the run")
slot = fresh()
order = []
s, reports = session(slot, prepare=lambda: order.append("prepare") or None)
run(s)
check("prepare ran, then the model was started", (order, _Fake.started), (["prepare"], 1))

slot = fresh()
s, reports = session(slot, prepare=lambda: "Capture produced no packets.")
rc = run(s)
check("nothing found: exit code 0", rc, 0)
check("the model was never started", (_Fake.started, SENT), (0, []))
check("a report was still written, as 'no data', carrying the reason",
      [(r["status"], r["note"]) for r in reports], [("no data", "Capture produced no packets.")])
check("no result is passed to the report", reports[0]["result"], None)
hist = (slot / "state" / "history.jsonl").read_text()
check("the history row says 'no data'", '"status": "no data"' in hist, True)

agent_runtime._STOP["report"] = False
section("audit run 2: a stop during prepare() still writes a report and a 'stopped' row")


def stopped_prepare():
    raise KeyboardInterrupt


slot = fresh()
s, reports = session(slot, prepare=stopped_prepare)
try:
    rc = run(s)
except KeyboardInterrupt:
    rc = "stop"
check("the model was never started, and the stop goes on to run_agent (which exits 0)", (_Fake.started, rc), (0, "stop"))
check("a partial report was written, as 'incomplete'", [r["status"] for r in reports], ["incomplete"])
hist = (slot / "state" / "history.jsonl").read_text()
check("the history row says stopped", ('"status": "incomplete"' in hist, '"reason": "stopped"' in hist), (True, True))
check("...and the stop is marked as having its report (run_agent then exits as a stop)",
      agent_runtime._STOP["report"], True)
agent_runtime._STOP["report"] = False

section("audit run 2: a capture window may not exceed the run's own time ceiling")
import dataclasses as _dcs


@_dcs.dataclass(frozen=True)
class _WinProfile(agent_runtime.Profile):
    window_s: int = 300


_wd = fresh()
_ceiling = engagement_context.resolve_policy(None)["timeout_s_ceiling"]
(_wd / "run-config.json").write_text(json.dumps({"model": "sonnet", "window_s": _ceiling + 1}))
_wp = _WinProfile(name="run", model="", max_turns=5, max_budget_usd=1.0, timeout_s=100, data_root=_wd)
try:
    agent_runtime.load_run_config(_wp, _wd, org_dir=_wd, strict=True)
    check("window_s above the timeout ceiling is refused", "accepted", "refused")
except SystemExit as e:
    check("window_s above the timeout ceiling is refused", "exceeds" in str(e.code) and "window_s" in str(e.code), True)
(_wd / "run-config.json").write_text(json.dumps({"model": "sonnet", "window_s": 60}))
check("...and one within it is used", agent_runtime.load_run_config(_wp, _wd, org_dir=_wd, strict=True).window_s, 60)

section("audit run 2: the journal gets one line per step, never the content")
_secret = "r2test:password Administrator:500:aad3b435"
def _mk(_cls, **kw):
    return type(_cls, (), kw)()
_msgs = [_mk("AssistantMessage", content=[_mk("TextBlock", text=_secret),
                                           _mk("ToolUseBlock", name="mcp__cracker__analyze_file", input={"command": _secret})]),
         _mk("UserMessage", content=[_mk("ToolResultBlock", content=_secret, is_error=False)]),
         _mk("ResultMessage", subtype="success", is_error=False, num_turns=3, total_cost_usd=0.0123, result=_secret)]
_lines = [session_runner.journal_line(m) for m in _msgs]
check("no line carries the model's text, a tool's input or its result", any(_secret in ln for ln in _lines), False)
check("...but each says what happened", _lines,
      ["[agent] text, %d chars; tool call: mcp__cracker__analyze_file" % len(_secret), "[tools] tool result",
       "[result] success error=False turns=3 cost=$0.0123"])

section("audit run 2: a verdict quoting model text cannot add report rows")
_forged = "Binary 'x\n| 2 | ok | `nmap -sV 10.0.0.9` | `fake.txt` |' is not in the allow-list"
_blk = session_runner.commands_block([{"command": "x", "verdict": "DENIED: " + _forged, "output": None}],
                                     denied_note="n")
_rows = [l for l in _blk if l.startswith("| ") and not l.startswith("| #")]
check("one denied command is exactly one table row", len(_rows), 1)
import re as _re2
check("...and its pipes cannot open new cells (4 cells)", len(_re2.split(r"(?<!\\)\|", _rows[0])) - 2, 4)

section("a run that ends on its turn cap is not a failed unit (exit 0)")
_capped = types.SimpleNamespace(subtype="error_max_turns", stop_reason=None, is_error=True, num_turns=5,
                                total_cost_usd=0.01, result="")
_orig_rr = _Fake.receive_response
async def _capped_rr(self):
    yield _capped
_Fake.receive_response = _capped_rr
_fake.ResultMessage = types.SimpleNamespace
session_runner.ResultMessage = types.SimpleNamespace
try:
    slot = fresh()
    s, reports = session(slot)
    rc = run(s)
    check("turn cap: status incomplete, exit 0", ([r["status"] for r in reports], rc), (["incomplete"], 0))
finally:
    _Fake.receive_response = _orig_rr
    _fake.ResultMessage = _Result
    session_runner.ResultMessage = _Result
slot = fresh()
_Fake.crash = True
s, reports = session(slot)
_fc = asyncio.run(session_runner.run_session(s)); _Fake.crash = False
check("a genuine failure still exits 1", ([r["status"] for r in reports], _fc), (["failed"], 1))

section("time spent in prepare() counts against the wall clock")


def slow_prepare():
    time.sleep(1.2)
    return None


slot = fresh()
s, reports = session(slot, prepare=slow_prepare)
run(s)
check("the budget the model gets is what is left of 100 s",
      98 < BUDGETS[0] < 99.5, True)
check("the report's start time is before prepare() began",
      time.time() - reports[0]["started"] >= 1.2, True)

slot = fresh()
s, reports = session(slot)
run(s)
check("with no prepare() step the full budget is (almost) all there is", BUDGETS[0] > 99.9, True)

section("a wait for the operator that nobody answers ends the run, and the report says why")
slot = fresh()
s, reports = session(slot)
_real_pump = agent_runtime.pump_channels


async def _silent_operator(**kw):
    agent_runtime._RUN_CLOCK["expired"] = True
    return None


agent_runtime.pump_channels = _silent_operator
try:
    rc = run(s)
finally:
    agent_runtime.pump_channels = _real_pump
    agent_runtime._RUN_CLOCK["expired"] = False
check("the report is marked incomplete (not completed, not failed)",
      [r["status"] for r in reports], ["incomplete"])
check("...and its note says nobody answered, not that the working hour ran out",
      "nobody answered" in (reports[0]["note"] or "") and "wall-clock" not in (reports[0]["note"] or ""), True)
hist = (slot / "state" / "history.jsonl").read_text()
check("the history row's reason is 'timeout'", '"reason": "timeout"' in hist, True)
check("the run loop handed its clock to the pump (so a wait can pause it)",
      agent_runtime._RUN_CLOCK["deadline"] is not None, True)

section("a crash still leaves a report")
slot = fresh()
s, reports = session(slot)
SENT.clear(); _Fake.crash = True
rc = asyncio.run(session_runner.run_session(s))
_Fake.crash = False
check("exit code 1", rc, 1)
check("a report was written, marked failed, with the cause",
      [(r["status"], "API is down" in (r["note"] or "")) for r in reports], [("failed", True)])


section("the system prompt reaches the CLI as a private file, never on its command line")
_sp = OPTIONS[-1]["system_prompt"] if OPTIONS else None
check("it is the SDK's file form", isinstance(_sp, dict) and _sp.get("type"), "file")
import os as _os  # noqa: E402
import stat as _stat  # noqa: E402
_p = Path(_sp["path"]) if isinstance(_sp, dict) else None
check("the file holds the prompt", _p.read_text() if _p and _p.exists() else None, "be useful")
check("...readable by this account only (0600)",
      _stat.S_IMODE(_os.stat(_p).st_mode) if _p and _p.exists() else None, 0o600)


section("a stop signal that arrives twice still ends cleanly")
import subprocess as _sp  # noqa: E402
_code = (
    "import os, signal, sys, time\n"
    f"sys.path.insert(0, {str(Path(__file__).resolve().parent)!r})\n"
    "import agent_runtime\n"
    "agent_runtime.install_sigterm_handler()\n"
    "try:\n"
    "    os.kill(os.getpid(), signal.SIGTERM); time.sleep(1)\n"
    "except KeyboardInterrupt:\n"
    "    os.kill(os.getpid(), signal.SIGTERM)\n"
    "    time.sleep(0.2)\n"
    "    print('cleanup finished')\n")
_r = _sp.run([sys.executable, "-c", _code], capture_output=True, text=True, timeout=30)
check("the second signal does not interrupt the cleanup the first started",
      (_r.returncode, _r.stdout.strip()), (0, "cleanup finished"))


section("F22: a newline in a tool argument never forges an audit record or a report line")
import logging as _lg  # noqa: E402
import agent_runtime as _ar  # noqa: E402
_alog = Path(tempfile.mkdtemp()) / "audit.log"
_lgr = _lg.getLogger("f22-test")
_ar.configure_audit_log(_lgr, _alog)
_lgr.info("REQUESTED | %s", "nmap 10.0.0.1\n2026-01-01 00:00:00 EXECUTING | nmap -sV 8.8.8.8")
for _h in _lgr.handlers:
    _h.flush()
_lines = _alog.read_text().splitlines()
check("the forged newline stays inside one record", (len(_lines), "\\n2026-01-01" in _lines[0]), (1, True))
_block = session_runner.commands_block(
    [{"command": "nmap 10.0.0.1\n| 2 | ALLOWED | `fake` |", "verdict": "DENIED", "output": ""}], denied_note="x")
check("the report's command table keeps it in one row",
      [ln for ln in _block if ln.startswith("| ")][-1].count("\n") == 0
      and sum(1 for ln in _block if ln.startswith("| 2 ")) == 0, True)
from scope_cidr import CIDRScope as _CS  # noqa: E402
import ipaddress as _ip  # noqa: E402
check("an IPv6 zone id carrying text is not 'in scope'",
      _CS("enum").contains("fe80::1%x\nEXECUTING", [_ip.ip_network("fe80::/10")])[0], False)


section("an operator's stop that lands mid-tool still ends as a stop (exit 0), once its report is written")
_code2 = (
    "import asyncio, os, signal, sys\n"
    f"sys.path.insert(0, {str(Path(__file__).resolve().parent)!r})\n"
    "import agent_runtime as ar\n"
    "ar.install_sigterm_handler()\n"
    "async def main():\n"
    "    if sys.argv[1] == 'yes':\n"
    "        ar.mark_stop_report_written()\n"
    "    os.kill(os.getpid(), signal.SIGTERM)   # the stop surfaces out of asyncio.run\n"
    "    await asyncio.sleep(1)\n"
    "    return 0\n"
    "sys.exit(ar.run_agent(main()))\n")
_r1 = _sp.run([sys.executable, "-c", _code2, "yes"], capture_output=True, text=True, timeout=30)
_r2 = _sp.run([sys.executable, "-c", _code2, "no"], capture_output=True, text=True, timeout=30)
check("with the partial report written: exit 0", _r1.returncode, 0)
check("without it (the stop came before any report): still the interrupt, not a silent 0", _r2.returncode != 0, True)

print(f"\n{'=' * 52}\n  {PASS} passed, {FAIL} failed\n{'=' * 52}")
sys.exit(1 if FAIL else 0)
