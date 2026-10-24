"""test_interrupt.py — the operator interrupt (CLAUDE.md §4 step 6, GUI phase 2):
agent_runtime.install_interrupt_handler and friends.

    python3 shared/test_interrupt.py

No framework, no root, no vault, no SDK: sends a REAL SIGUSR1 to this very
process while a REAL child process is running, with a fake event loop and a
fake SDK client standing in for the two things the handler talks to. That
is the point — the handler's whole job is signal + process plumbing, which
is the part that cannot be verified by reading it.

WHAT IT IS FOR: `agenti <agent> interrupt` is a faster stop. The
handler must (1) terminate the in-flight tool subprocess, (2) NOT terminate
the SDK's own CLI child (which would turn a clean interrupt into an
"unexpected error" run), (3) ask the SDK to end the turn, (4) arm a fallback
that ends the run the proven `stop` way if the SDK does not, and (5) be
idempotent, because an operator will click the button twice. Each of those
is a separate silent failure mode: (1) failing means interrupt is no faster
than stop; (2) failing means every interrupt is recorded as a crash; (4)
failing means an interrupt can hang until the wall-clock backstop.
"""
import asyncio
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import agent_runtime as rt  # noqa: E402

PASS = FAIL = 0


def check(label, got, want):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print(f"  [ OK ] {label}")
    else:
        FAIL += 1
        print(f"  [FAIL] {label}\n         got  {got!r}\n         want {want!r}")


def section(t):
    print(f"\n=== {t} ===")


class FakeLoop:
    """Stands in for the running asyncio loop. call_soon_threadsafe runs the
    callback inline (the real loop would run it on its next iteration);
    create_task drives the coroutine to completion on a private loop so the
    fake client's interrupt() genuinely gets awaited."""
    def __init__(self):
        self.scheduled = 0

    def call_soon_threadsafe(self, fn, *args):
        self.scheduled += 1
        fn(*args)

    def create_task(self, coro):
        return asyncio.run(coro)


class FakeClient:
    def __init__(self):
        self.interrupts = 0

    async def interrupt(self):
        self.interrupts += 1


def _cleanup_signals():
    rt._reset_interrupt_for_tests()
    signal.signal(signal.SIGUSR1, signal.SIG_DFL)
    signal.signal(signal.SIGALRM, signal.SIG_DFL)


section("baseline")
check("interrupt_requested() is False before any signal", rt.interrupt_requested(), False)
check("terminate_tool_children() with nothing running -> []", rt.terminate_tool_children(), [])

section("SIGUSR1 mid-'tool call': tool child dies, SDK child survives, flag set, "
        "SDK interrupt requested, fallback armed")
tool = subprocess.Popen(["sleep", "60"])
# argv[0] rewritten to "claude": stands in for the SDK's CLI child, which the
# handler must skip. In production the SDK's own child registry is checked
# first; this exercises the cmdline heuristic that backs it up.
decoy = subprocess.Popen(["bash", "-c", "exec -a claude sleep 60"])
time.sleep(0.2)
kids = dict(rt._direct_children())
check("both children visible via /proc", (tool.pid in kids, decoy.pid in kids), (True, True))
check("decoy's cmdline reads as the SDK child", "claude" in kids[decoy.pid], True)

loop, client = FakeLoop(), FakeClient()
rt.install_interrupt_handler(loop, client, logger=None)
os.kill(os.getpid(), signal.SIGUSR1)
time.sleep(0.05)
check("flag set", rt.interrupt_requested(), True)
try:
    rc = tool.wait(timeout=3)
except subprocess.TimeoutExpired:
    rc = "still running"
check("tool subprocess terminated (rc = -SIGTERM)", rc, -signal.SIGTERM)
check("SDK-lookalike child NOT terminated", decoy.poll(), None)
check("client.interrupt() awaited exactly once", client.interrupts, 1)
check("scheduled through the loop, not called from the handler directly", loop.scheduled, 1)
armed = signal.getitimer(signal.ITIMER_REAL)[0]
check("fallback timer armed (~INTERRUPT_FALLBACK_S)", 0 < armed <= rt.INTERRUPT_FALLBACK_S, True)
rt.clear_interrupt_fallback()
check("clear_interrupt_fallback() disarms it", signal.getitimer(signal.ITIMER_REAL)[0], 0.0)

section("idempotent: a second SIGUSR1 changes nothing")
os.kill(os.getpid(), signal.SIGUSR1)
time.sleep(0.05)
check("client.interrupt() still once", client.interrupts, 1)
check("fallback not re-armed", signal.getitimer(signal.ITIMER_REAL)[0], 0.0)
decoy.terminate(); decoy.wait(timeout=3)
_cleanup_signals()

section("the fallback fires if the pump loop never observes the flag")
saved = rt.INTERRUPT_FALLBACK_S
rt.INTERRUPT_FALLBACK_S = 0.3
rt.install_interrupt_handler(FakeLoop(), FakeClient(), logger=None)
os.kill(os.getpid(), signal.SIGUSR1)
fired = None
try:
    time.sleep(2)
except KeyboardInterrupt as e:
    fired = str(e)
check("KeyboardInterrupt raised by the fallback (the proven stop path)",
      fired is not None and "interrupt fallback" in fired, True)
check("flag still set — the except* clause reports reason='interrupted', not 'stopped'",
      rt.interrupt_requested(), True)
rt.INTERRUPT_FALLBACK_S = saved
_cleanup_signals()

section("reset hook (tests only)")
check("after reset, flag is False again", rt.interrupt_requested(), False)

section("the contract's PreToolUse hook refuses every tool once interrupted")
# The gap this closes: between the handler killing the in-flight subprocess
# and the SDK acting on client.interrupt(), the model gets the aborted tool's
# result and may immediately start another scan. The allow-list hook is the
# one choke point every tool call passes through, so it is where "interrupt
# means no more tool calls" is enforced — structurally, not by asking nicely.
import logging  # noqa: E402
import agent_contract  # noqa: E402


class _Scope:  # the smallest thing that satisfies the ScopeBoundary Protocol
    def ceiling_from_engagement(self, engagement): return None
    def narrow(self, ceiling, run_target_text, *, required): return None
    def contains(self, target, scope): return (True, "ok")
    def describe(self, scope): return "test"


async def _noop_tool(args): return {"content": []}


contract = agent_contract.AgentContract(
    name="t", tool_names=("noop",), tools=(_noop_tool,), mcp_server_name="t",
    scope=_Scope(), profiles={"dev": object()}, operational_notes="", task="x")
hook = contract.make_tool_allowlist_hook(logging.getLogger("test"))
allowed_name = next(iter(contract.allowed_tool_names))
before = asyncio.run(hook({"tool_name": allowed_name}, "id1", None))
check("before an interrupt, an allow-listed tool passes (returns {})", before, {})
rt._interrupt_requested = True
after = asyncio.run(hook({"tool_name": allowed_name}, "id2", None))
check("after an interrupt, the SAME tool is denied",
      after.get("hookSpecificOutput", {}).get("permissionDecision"), "deny")
check("…with a reason that says why",
      "interrupted" in after["hookSpecificOutput"]["permissionDecisionReason"], True)
rt._reset_interrupt_for_tests()
check("and passes again once the flag is cleared",
      asyncio.run(hook({"tool_name": allowed_name}, "id3", None)), {})


# F04: once the engagement's window has ended, every tool call is refused.
import dataclasses as _dc  # noqa: E402
import engagement_context as _ec  # noqa: E402
_eng = _ec.engagement_from_record(_ec.normalize_record({
    "engagement_id": "W-1", "client": "c", "authorizing_party": "a", "authorizing_title": "t",
    "authorization_ref": "r", "emergency_contact": "soc@c.example", "notes": "",
    "valid_from": "2020-01-01", "valid_until": "2099-12-31",
    "scope": {"cidr": {"in_scope": ["10.0.0.0/24"]}}}), "cidr")
_ec._RUN_ENGAGEMENT = _eng
check("inside the window, the tool passes", asyncio.run(hook({"tool_name": allowed_name}, "w1", None)), {})
_ec._RUN_ENGAGEMENT = _dc.replace(_eng, valid_until="2021-01-01")
_w = asyncio.run(hook({"tool_name": allowed_name}, "w2", None))
check("F04: after the window ends mid-run, the same tool is refused, saying why",
      (_w.get("hookSpecificOutput", {}).get("permissionDecision"),
       "authorized window" in _w.get("hookSpecificOutput", {}).get("permissionDecisionReason", "")),
      ("deny", True))
_ec._RUN_ENGAGEMENT = None

print(f"\n{'=' * 52}\n  {PASS} passed, {FAIL} failed\n{'=' * 52}")
sys.exit(1 if FAIL else 0)
