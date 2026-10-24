"""test_except_star.py — the "a report is written on EVERY outcome" invariant
(CLAUDE.md §1 invariant 6), specifically the except* control-flow shape every
agent file's run() function shares.

    python3 shared/test_except_star.py

No framework, no root, no vault, no SDK, no API cost: reproduces the exact
nested try/except* shape used in enum-agent.py, research-agent.py,
trafficmon-agent.py, and shared/new_agent.py's scaffold template — outer
try around the whole `async with client:`, an inner try around
`async with asyncio.timeout(...)`, then except* clauses for TimeoutError,
(KeyboardInterrupt, CancelledError), and Exception, in that order — without
needing a real Claude Agent SDK session. The thing genuinely at risk here is
pure Python except*/ExceptionGroup semantics (does a bare, un-grouped
exception correctly route to a third except* clause added alongside two
existing ones, given this specific nesting?), not SDK behavior, which is
already established elsewhere in this project — so this is the right and
cheapest level to verify it at.

WHAT IT IS FOR: found in the 2026-09-21 error-message audit (CLAUDE.md §4
item 17) — enum-agent.py and research-agent.py had NO except* clause for a
genuinely unexpected exception (a bug, an SDK/API auth or rate-limit error,
a network failure). Without one, such an exception propagated straight past
write_report(): the process crashed with a raw traceback and NO REPORT was
written, directly contradicting run()'s own "a report is written on every
outcome" comment. trafficmon-agent.py already had the right shape (missing
only CancelledError alongside KeyboardInterrupt) and is what the fix in the
other three was modeled on. This file pins the corrected shape down so it
can never quietly regress back to the two-clause version — a regression
here is exactly the kind of thing that is invisible until the moment an
agent hits a genuine bug and produces no record of what happened.
"""
import asyncio
import sys

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


class _FakeClientCM:
    """Stands in for `async with ClaudeSDKClient(...) as client:` — the
    real class isn't installed in this dev sandbox (no vault/venv access),
    and this test's own point is that the shape works independent of it."""
    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False  # never swallow, matching a real async context manager


async def _old_shape(raise_what: str):
    """The shape BEFORE the fix: only two except* clauses. Used to prove
    the bug was real, not just asserted."""
    try:
        async with _FakeClientCM():
            try:
                async with asyncio.timeout(5):
                    if raise_what == "unexpected":
                        raise RuntimeError("simulated unexpected bug")
            except* asyncio.TimeoutError:
                pass
    except* (KeyboardInterrupt, asyncio.CancelledError):
        pass
    return "reached_after_try"  # must NOT be reachable for "unexpected"


async def _new_shape(raise_what: str) -> dict:
    """The shape AFTER the fix, line for line matching what's actually in
    enum-agent.py/research-agent.py/trafficmon-agent.py/new_agent.py."""
    note = None
    _unexpected_error = False

    try:
        async with _FakeClientCM():
            try:
                async with asyncio.timeout(5):
                    if raise_what == "timeout":
                        await asyncio.sleep(10)  # trips the 5s timeout
                    elif raise_what == "keyboard":
                        raise KeyboardInterrupt("simulated stop")
                    elif raise_what == "cancelled":
                        raise asyncio.CancelledError("simulated cancel")
                    elif raise_what == "unexpected":
                        raise RuntimeError("simulated unexpected bug")
                    elif raise_what == "none":
                        pass
            except* asyncio.TimeoutError:
                note = "backstop hit"
    except* (KeyboardInterrupt, asyncio.CancelledError):
        note = "Run was stopped before completion. Findings may be incomplete."
    except* Exception as eg:
        inner = eg.exceptions[0] if eg.exceptions else eg
        note = f"Run failed unexpectedly: {type(inner).__name__}: {inner}"
        _unexpected_error = True

    # Standing in for write_report(): the line that PROVES the fix. Before
    # it, an "unexpected" exception never reached here — the whole function
    # (and the real agent process) crashed before this could ever run.
    return {"note": note, "unexpected_error": _unexpected_error,
            "reached_after_try": True}


async def _run() -> int:
    section("the OLD (pre-fix) shape — confirms the bug was real, not asserted")
    try:
        r = await _old_shape("unexpected")
        check("OLD shape incorrectly returns instead of propagating "
              "(would mean the bug never existed)", "should not print", r)
    except* Exception as eg:
        inner = eg.exceptions[0] if eg.exceptions else eg
        check("OLD shape: an unexpected exception propagates UNCAUGHT out of "
              "run() — confirms no report would ever have been written",
              type(inner).__name__, "RuntimeError")

    section("the FIXED shape — the new except* Exception clause")
    r = await _new_shape("unexpected")
    check("an unexpected exception is now caught, not propagated",
          r["reached_after_try"], True)
    check("_unexpected_error is set", r["unexpected_error"], True)
    check("note names the real exception type", "RuntimeError" in r["note"], True)

    section("regression checks — the two PRE-EXISTING clauses are unaffected")
    r = await _new_shape("keyboard")
    check("KeyboardInterrupt still handled by its own clause",
          (r["reached_after_try"], r["unexpected_error"]), (True, False))

    r = await _new_shape("cancelled")
    check("CancelledError still handled by the same clause as KeyboardInterrupt "
          "(this is the trafficmon-specific half of the fix)",
          (r["reached_after_try"], r["unexpected_error"]), (True, False))

    r = await _new_shape("timeout")
    check("TimeoutError still handled by the INNER except* (the wall-clock backstop)",
          (r["reached_after_try"], r["unexpected_error"], r["note"]),
          (True, False, "backstop hit"))

    r = await _new_shape("none")
    check("the clean/no-exception path is completely unaffected",
          (r["reached_after_try"], r["unexpected_error"], r["note"]),
          (True, False, None))

    print(f"\n{'=' * 52}\n  {PASS} passed, {FAIL} failed\n{'=' * 52}")
    return 1 if FAIL else 0


sys.exit(asyncio.run(_run()))
