"""
session_runner.py — the ONE run loop for every manifest-driven agent (recon
agents and file-analysis agents).

Everything an agent kind has to say for itself — its tools, its scope, its
instructions, how it writes its report — is handed in as a Session. What is
here is the part that must be IDENTICAL for every agent and that has been
bitten by real bugs: starting or resuming the durable state, building the SDK
options, the outer pump loop that delivers operator and team messages between
turns, the interrupt, the wall-clock backstop, classifying how the run ended,
and — on every outcome, including a crash — writing the report.

It used to live inside recon_runner.py (and, near-verbatim, in
research-agent.py); the file-analysis kind needed the same loop, and a second
copy of this is exactly where a fix lands in one place and not the other.
"""
from __future__ import annotations

import asyncio
import logging
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from claude_agent_sdk import (
    ClaudeAgentOptions,
    ClaudeSDKClient,
    HookMatcher,
    ResultMessage,
)

import agent_runtime
import state
from agent_runtime import Profile


@dataclass
class Session:
    """What one run needs from its agent kind."""
    profile: Profile
    contract: Any                  # AgentContract (its MCP server name and tool names)
    mcp_server: Any
    allowlist_hook: Callable       # the PreToolUse hard-deny hook
    system_prompt: str
    agent_dir: Path                # this run's slot
    org_dir: Path
    log: logging.Logger
    state_holder: "agent_runtime.StateHolder"
    engagement_id: str             # recorded in history; "" for a kind with no engagement
    target_label: str              # what the run is scoped to, as one line
    # (profile, result, started, status, note=, resumed_from=) -> Path | None
    write_report: Callable
    # Optional. An agent that must collect something BEFORE the model starts
    # (trafficmon's packet capture, so the model cannot influence what was
    # captured) hands it here. Called once, after the durable state has begun
    # and before the SDK client exists; it may block. Return None to carry on,
    # or a note to end the run there as "no data" (a report is still written).
    prepare: Callable | None = None
    # The first message of a fresh run. A resume always sends RESUME_TASK.
    kickoff: str | None = None


# Sent instead of the kickoff when continuing a stopped run. Deliberately
# terse: the conversation history the SDK reloads already contains the task,
# the scope and everything found so far.
RESUME_TASK = (
    "This run was interrupted and has been resumed. Review what you have "
    "already done in this conversation, then continue from where you stopped. "
    "Do not repeat work that is already complete. Note that a tool call which "
    "was in flight when the run stopped may be missing its result — if "
    "something looks unfinished, re-run just that step."
)


def summarize_tool_content(content) -> str:
    """ToolResultBlock.content is a list of {'type': 'text', 'text': ...}
    dicts in every real run observed so far, but this is read for a status
    display, not parsed for correctness — anything unexpected degrades to a
    short repr rather than raising, since a findings-summary bug must never
    be able to take down the actual run."""
    try:
        if isinstance(content, list):
            parts = [b.get("text", "") for b in content if isinstance(b, dict)]
            text = " ".join(p for p in parts if p)
        else:
            text = str(content)
    except Exception:
        text = "<unreadable tool result>"
    text = " ".join(text.split())  # collapse newlines/whitespace
    return text[:200] + ("…" if len(text) > 200 else "")


# ---------------------------------------------------------------------------
# Report sections shared by every kind. Each returns lines to append, starting
# with its own divider, so a runner's write_report() is just the header, these
# in order, and whatever is particular to its kind.
# ---------------------------------------------------------------------------
def findings_block(findings: str | None) -> list[str]:
    L = ["", "---", "", "## Findings", ""]
    if findings:
        body = findings.strip()
        # The model frequently opens with its own "## Findings"/"# ..." heading;
        # drop a leading duplicate so the section isn't titled twice.
        body = re.sub(r"^#{1,3}\s*(findings|assessment)[^\n]*\n+", "", body,
                      count=1, flags=re.IGNORECASE)
        L.append(body)
    else:
        L.append("_No findings were produced — the run did not reach a summary._")
    return L


def _table_cell(text: str, limit: int = 600) -> str:
    """One line of inline code that cannot break a Markdown table. Real output is
    multi-line (a denial reason, a module's console): left raw, the first newline
    ended the row and everything after it spilled out as stray text, so the
    reason a command was refused (the audit-valuable part) went missing."""
    text = " ⏎ ".join(" ".join(ln.split()) for ln in str(text).splitlines() if ln.strip())
    if len(text) > limit:
        text = text[:limit // 3] + " […] " + text[-(limit - limit // 3):]
    return "`" + text.replace("`", "'").replace("|", "\\|") + "`"


def commands_block(actions: list[dict], *, denied_note: str) -> list[str]:
    """The commands the agent proposed, allowed or denied, in order. The
    denials are the audit-valuable part: they show the boundary holding."""
    L = ["", "---", "", "## Commands executed", ""]
    if not actions:
        return L + ["_No commands were executed._"]
    L += ["| # | Verdict | Command | Raw output |",
          "|---|---------|---------|------------|"]
    for i, c in enumerate(actions, 1):
        cmd = _table_cell(agent_runtime.shorten_urls(agent_runtime.one_line(c["command"])), limit=2000)
        out = _table_cell(c["output"]) if c["output"] else "—"
        # The verdict quotes model text too (a denied program's name, a URL):
        # one line, pipes escaped, or it can add forged rows (audit run 2).
        verdict = agent_runtime.shorten_urls(agent_runtime.one_line(str(c["verdict"])))[:600].replace("|", "\\|")
        L.append(f"| {i} | {verdict} | {cmd} | {out} |")
    denied = [c for c in actions if c["verdict"].startswith("DENIED")]
    if denied:
        L += ["", f"_{len(denied)} command(s) denied — {denied_note}_"]
    return L


def outputs_block(title: str, folder: str, base: Path | None, actions: list[dict]) -> list[str]:
    """The saved raw outputs the commands produced, with sizes."""
    L = ["", "---", "", f"## {title}", ""]
    files = [c["output"] for c in actions if c["output"]]
    if not (files and base):
        return L + ["_None saved._"]
    for f in files:
        fp = base / f
        size = fp.stat().st_size if fp.exists() else 0
        L.append(f"- `{folder}/{f}` ({size:,} bytes)")
    return L


def journal_line(message) -> str:
    """What the system journal gets for one SDK message: its kind, the tools it
    calls and its size, never its text. A whole message carries scan output,
    cracked passwords and session output, and the journal lives outside the
    vault, retention and purge (audit run 2; operator decision 8). The full
    record is the run's own ledger (state/findings.jsonl) and report."""
    kind = type(message).__name__
    if kind == "ResultMessage":
        cost = getattr(message, "total_cost_usd", None)
        return (f"[result] {getattr(message, 'subtype', '?')} error={getattr(message, 'is_error', '?')} "
                f"turns={getattr(message, 'num_turns', '?')}"
                + (f" cost=${cost:.4f}" if isinstance(cost, (int, float)) else ""))
    if kind == "SystemMessage":
        return f"[system] {getattr(message, 'subtype', '?')}"
    parts = []
    for block in getattr(message, "content", None) or []:
        b = type(block).__name__
        if b == "ToolUseBlock":
            parts.append(f"tool call: {getattr(block, 'name', '?')}")
        elif b == "ToolResultBlock":
            parts.append("tool result" + (" (error)" if getattr(block, "is_error", False) else ""))
        elif b == "TextBlock":
            parts.append(f"text, {len(getattr(block, 'text', '') or '')} chars")
        elif b == "ThinkingBlock":
            parts.append("thinking")
        else:
            parts.append(b)
    if isinstance(getattr(message, "content", None), str):
        parts.append(f"text, {len(message.content)} chars")
    who = {"AssistantMessage": "agent", "UserMessage": "tools"}.get(kind, kind)
    return f"[{who}] " + ("; ".join(parts) or "(empty)")


async def run_session(s: Session) -> int:
    profile, log, agent_dir = s.profile, s.log, s.agent_dir
    # Epoch-based (not monotonic): report_header() reconstructs the wall-clock
    # "Started" timestamp from this directly. NTP sync is one of preflight's
    # checks, so a mid-run clock jump is the risk being traded for a shared
    # report function — an accepted, documented trade. Taken before prepare()
    # so the run's duration and its wall-clock budget include that work.
    started = time.time()
    print(f"[{profile.model}] {s.engagement_id or 'run'} | "
          f"scope {s.target_label} | "
          f"<= {profile.max_turns} turns, "
          f"<= ${profile.max_budget_usd}, <= {profile.timeout_s}s\n")

    # Durable live status + findings (CLAUDE.md §3d, shared/state.py). Every
    # STATE.* call below is wrapped defensively (never lets a state-tracking
    # bug abort the actual run) — this is an observability layer, not a
    # safety boundary, and must degrade gracefully if the SDK's message
    # shape ever drifts from what's been directly observed.
    STATE = state.StateStore(profile.data_root / "state")
    s.state_holder.state = STATE   # ask_operator's tool closure reads this
    _used = {"turns": 0, "cost": 0.0}   # pump_channels' own cap accounting for this run
    launched_by = agent_runtime.read_launched_by(agent_dir)
    launched_via = agent_runtime.read_launched_via(agent_dir)
    # A resume continues the PREVIOUS conversation (CLAUDE.md §3d): the CLI
    # wrote the persisted SDK session id, and STATE.resume() appends to the
    # existing findings ledger instead of truncating it, so a resumed run keeps
    # everything it already found. If there is no prior state to continue,
    # resume() returns False and this falls back to a normal start rather than
    # proceeding with an empty snapshot.
    resume_session = agent_runtime.read_resume_session(agent_dir)
    try:
        resumed = False
        if resume_session:
            resumed = STATE.resume(session_id=resume_session,
                                   launched_by=launched_by, launched_via=launched_via)
            if not resumed:
                print(f"[warn] asked to resume {resume_session[:8]}… but no prior "
                      f"state was found — starting a fresh run instead")
                resume_session = None
        if not resumed:
            STATE.start(engagement_id=s.engagement_id, target=s.target_label,
                        profile_name=profile.name,
                        launched_by=launched_by, launched_via=launched_via)
        agent_runtime.log_run_attribution(log, agent_name=s.contract.name,
                                          launched_by=launched_by,
                                          launched_via=launched_via)
    except Exception as e:
        print(f"[warn] state tracking unavailable: {e}")

    if s.prepare is not None:
        try:
            early = s.prepare()
        except KeyboardInterrupt:
            # A stop during the prepare step (trafficmon's capture window) is a
            # stop like any other: a partial report, a 'stopped' history row,
            # and a teammate told (audit run 2: it used to leave nothing).
            report = s.write_report(profile, None, started, "incomplete",
                                    note="Run was stopped before the model started (during its "
                                         "preparation step). Nothing was analysed.",
                                    resumed_from=resume_session)
            if report:
                agent_runtime.mark_stop_report_written()
            try:
                STATE.finished(status="incomplete", reason="stopped",
                               report=report.name if report else None)
            except Exception as e:
                print(f"[warn] state tracking: {e}")
            agent_runtime.announce_team_member_ended(agent_dir, status="incomplete", reason="stopped")
            print("\n[STOPPED] during preparation; partial report written.")
            raise                  # run_agent ends a stop whose report is written as a stop (exit 0)
        if early:
            # Nothing to hand the model. Still a finished run with a report
            # and a history row, and a teammate is told it is over.
            report = s.write_report(profile, None, started, "no data", note=early,
                                    resumed_from=resume_session)
            try:
                STATE.finished(status="no data", report=report.name if report else None)
            except Exception as e:
                print(f"[warn] state tracking: {e}")
            agent_runtime.announce_team_member_ended(agent_dir, status="no data")
            return 0

    # The message-stream tracker lives in the harness now (CLAUDE.md §3d):
    # narration, tool calls and their results into the one ledger, in order.
    tracker = agent_runtime.StateTracker(STATE, summarize_tool_content)

    options = ClaudeAgentOptions(
        system_prompt=agent_runtime.system_prompt_file(s.system_prompt),
        mcp_servers={s.contract.mcp_server_name: s.mcp_server},
        allowed_tools=sorted(s.contract.allowed_tool_names),
        # dontAsk fails closed: any tool not pre-approved above is denied (there
        # is no human to answer a prompt in an unattended run). The hook below is
        # the belt to this suspenders — it runs first and denies even if the mode
        # is ever loosened. Two independent layers, neither enumerating built-ins.
        permission_mode="dontAsk",
        setting_sources=[],  # load no user/project settings: nothing outside our own files steers a run
        hooks=agent_runtime.build_hooks(s.allowlist_hook, HookMatcher, agent_dir=agent_dir,
                                        state=STATE, tracker=tracker, logger=log),
        model=profile.model,
        max_turns=profile.max_turns,            # stop after N agentic turns
        max_budget_usd=profile.max_budget_usd,  # hard stop on spend
        # Attach to the previous conversation when resuming. Per-run caps are
        # deliberately NOT carried over: they are re-read from run-config.json
        # every time, so a resume can never inherit a looser budget than the
        # operator set for it (CLAUDE.md §1 invariant 7).
        resume=resume_session,
        env=agent_runtime.cli_env(),
    )

    result = None
    status = "failed"
    note = None
    reason = None            # why it ended, for history.jsonl — see state.finished()
    _unexpected_error = False
    # Outer try wraps the WHOLE `async with client` statement, not just its
    # body. Verified live (not just reasoned about): a KeyboardInterrupt
    # raised mid-tool-call (`stop` landing during a tool's subprocess.run)
    # propagates once through the inner receive_response() loop AND AGAIN
    # separately when `async with client:` tears itself down afterward
    # (__aexit__ reaping the still-unwinding tool-call task re-raises it). A
    # try scoped only around the inner loop caught the first copy, printed
    # "[STOPPED]...", then let the second copy escape uncaught from
    # __aexit__ — write_report() below never ran despite the first copy
    # having been "handled". Wrapping the whole async-with closes that gap.
    try:
        async with ClaudeSDKClient(options=options) as client:
            # `agenti ... interrupt` (SIGUSR1) — a faster stop that aborts the
            # in-flight tool call instead of waiting for it. Installed here,
            # once `client` is live, because client.interrupt() needs the
            # connection. See agent_runtime.install_interrupt_handler.
            agent_runtime.install_interrupt_handler(asyncio.get_running_loop(), client, log)
            # On a resume the model already has the task and its findings so
            # far in context; re-sending the original task would restart the
            # assessment from the top and pay for it twice.
            await client.query(RESUME_TASK if resume_session
                               else (s.kickoff or agent_runtime.KICKOFF))
            try:
                # Wall-clock backstop. NOTE: this fires at the next await point
                # after the deadline, so it cannot interrupt a tool that is
                # mid-flight — an individual tool call is bounded separately by
                # its own timeout. Between them, total runtime is bounded.
                # Nested (not merged into the outer except*) because
                # client.interrupt() below needs `client` still open, which it
                # no longer is once the outer async-with has unwound.
                async with asyncio.timeout(
                        max(profile.timeout_s - (time.time() - started), 1)) as deadline:
                    # A wait for the operator's answer pauses this clock
                    # (agent_runtime.pump_channels), so a question asked early
                    # cannot use the working hour up before anyone has read it.
                    agent_runtime.bind_run_deadline(deadline)
                    # OUTER LOOP: one pass per turn cycle (CLAUDE.md §3h).
                    # Operator messages also arrive after each tool call, via
                    # the PostToolUse hook; whatever is still waiting is
                    # delivered here, at the turn boundary. A tool is never
                    # interrupted to deliver one — that would abandon its
                    # output, the failure mode behind the partial-report bug.
                    while True:
                        async for message in client.receive_response():
                            print(journal_line(message))
                            if isinstance(message, ResultMessage):
                                result = message
                                agent_runtime.note_result(message)
                            elif (type(message).__name__ == "SystemMessage"
                                    and getattr(message, "subtype", None) == "init"):
                                try:
                                    sid = (getattr(message, "data", None) or {}).get(
                                        "session_id", "")
                                    if sid:
                                        STATE.session_started(sid)
                                except Exception as e:
                                    print(f"[warn] state tracking: {e}")
                            tracker.track(message)

                        # Operator interrupt landed during that turn (or during
                        # the linger below, on the previous pass): the tool
                        # call was already aborted by the signal handler; end
                        # the run here, at the turn boundary, before spending
                        # another turn. Cancels the handler's fallback timer —
                        # the SDK-level interrupt did its job.
                        if agent_runtime.interrupt_requested():
                            agent_runtime.clear_interrupt_fallback()
                            reason = "interrupted"
                            note = ("Run was interrupted by the operator: the step in "
                                    "flight was aborted and the run ended. Findings "
                                    "are incomplete.")
                            print("\n[INTERRUPTED] ending the run at the turn boundary.")
                            break

                        followup = await agent_runtime.pump_channels(
                            agent_dir=agent_dir, state=STATE, profile=profile,
                            result=result, turn=tracker.turn, used=_used,
                            client=client, org_dir=s.org_dir, logger=log)
                        if followup is None or agent_runtime.interrupt_requested():
                            if followup is None and agent_runtime.operator_wait_expired():
                                reason = "timeout"
                                note = agent_runtime.operator_wait_note(STATE)
                                print(f"\n[BACKSTOP] {note}")
                            break
                        await client.query(followup)
            except* asyncio.TimeoutError:
                reason = "timeout"
                note = (f"Run hit the {profile.timeout_s}s wall-clock backstop and was "
                        f"interrupted. Findings below may be incomplete.")
                print(f"\n[BACKSTOP] wall-clock deadline of {profile.timeout_s}s "
                      f"reached; interrupting the agent.")
                try:
                    await client.interrupt()
                except Exception:
                    pass
    # except* (not except): see the comment above the try — this must catch
    # both a bare KeyboardInterrupt (interrupt during receive_response with no
    # tool call in flight) and one wrapped in a BaseExceptionGroup (interrupt
    # during a tool call, or during the client's own teardown). A plain
    # `except` does not match a group and lets it propagate uncaught.
    # except* matches a lone exception exactly like a plain except would, so
    # this is a strict widening.
    except* (KeyboardInterrupt, asyncio.CancelledError):
        # "interrupted" here means the SIGUSR1 handler's FALLBACK fired (the
        # SDK did not wind the turn down in time) — still the operator's
        # interrupt, and history.jsonl should say so, not "stopped".
        reason = "interrupted" if agent_runtime.interrupt_requested() else "stopped"
        note = "Run was stopped before completion. Findings may be incomplete."
        print("\n[STOPPED] interrupted; writing a partial report.")
    # A genuinely UNEXPECTED exception — a bug, an SDK/API error (auth, rate
    # limit, a network failure to Anthropic's API), anything not handled
    # above — must not propagate past write_report() below: that crashed the
    # process with NO REPORT, contradicting "a report is written on EVERY
    # outcome" (§1 invariant 6; CLAUDE.md §4 item 18).
    except* Exception as eg:
        inner = eg.exceptions[0] if eg.exceptions else eg
        reason = "error"
        note = f"Run failed unexpectedly: {type(inner).__name__}: {inner}"
        print(f"\n[ERROR] {note}")
        log.exception("run failed unexpectedly")
        _unexpected_error = True

    # ---- run summary: why it stopped and what it cost -----------------------
    print("\n--- run summary ---")
    if result is not None:
        # The SDK's num_turns counts ONE query. A run that was talked to, or sat on
        # ask_operator, is several, and the report said "Turns: 1" for a 6-turn
        # session while its cost was the whole session's (live 2026-10-19). The
        # pump has been adding every query's turns up; the larger of the two is
        # the session's.
        try:
            result.num_turns = max(int(result.num_turns or 0), int(_used["turns"]))
        except (AttributeError, TypeError, ValueError):
            pass
        cost = ("$%.4f" % result.total_cost_usd
                if result.total_cost_usd is not None else "unknown")
        print(f"  stop reason : subtype={result.subtype} "
              f"stop_reason={result.stop_reason} is_error={result.is_error}")
        print(f"  turns       : {result.num_turns} (cap {profile.max_turns})")
        print(f"  cost        : {cost} (budget ${profile.max_budget_usd})")
        # On failure, surface the actual message (e.g. auth errors) instead of
        # burying it in the raw stream. (num_turns is a finer count than the
        # max_turns unit, so we deliberately don't compare them here.)
        if result.is_error and result.result:
            print(f"  error       : {result.result}")
        clean = (result.subtype == "success" and not result.is_error)
        # A resource cap (turns or budget) ending the run with no operator
        # interrupt or exception is the organisation's own configured ceiling
        # doing exactly its job (§1 invariant 7), not a crash.
        if reason is None:
            reason = agent_runtime.resource_cap_reason(result)
            if reason:
                note = note or (
                    f"Run ended: the {'turn' if reason == 'max_turns' else 'budget'} "
                    f"cap for this run was reached before the task finished. "
                    f"Findings below reflect only what was gathered up to that point.")
        # _unexpected_error overrides: an exception AFTER a ResultMessage
        # already arrived (e.g. inside pump_channels' own client.query, or
        # anywhere between turns) must not be masked by a "clean"-looking
        # last result — the run still ended in a genuine failure.
        if _unexpected_error:
            status = "failed"
        elif reason in ("interrupted", "max_turns", "max_budget"):
            # The SDK reports an interrupted turn OR a resource-cap cutoff as
            # an error result; neither is a bug in the run — one is the
            # operator's doing, the other is the organisation's own cap.
            status = "incomplete"
        else:
            status = "completed" if (clean and not note) else \
                     ("incomplete" if clean else "failed")
    else:
        print("  no ResultMessage seen (interrupted or errored before completion).")
        # Distinguishes "operator stopped it" (incomplete — nothing actually
        # went wrong) from "it genuinely broke" (failed) — both leave
        # result as None, so _unexpected_error is the only reliable signal
        # between them.
        status = "failed" if _unexpected_error else "incomplete"
        note = note or ("The run ended before the agent produced a summary "
                        "(interrupted, or failed at startup).")
    # Only a genuine failure is a failed unit: a run that ended on its turn,
    # budget or time cap, or by the operator, did what it was configured to do
    # and wrote its report; systemd used to show those as "failed" too.
    rc = 1 if status == "failed" else 0

    # A report is written on EVERY outcome. An interrupted run still touched a
    # client network; the record of what it did matters just as much.
    report = s.write_report(profile, result, started, status, note=note,
                            resumed_from=resume_session)
    if reason in ("stopped", "interrupted") and report:
        agent_runtime.mark_stop_report_written()
    # The report first, then the terminal snapshot that names it, so a
    # history row can open ITS OWN report rather than "the latest one".
    try:
        STATE.finished(status=status, reason=reason,
                       report=report.name if report else None)
    except Exception as e:
        print(f"[warn] state tracking: {e}")
    # Tells a teammate this run is genuinely done (CLAUDE.md §4 item 47) —
    # a no-op for a solo run. Every failure/success path reaches here.
    agent_runtime.announce_team_member_ended(agent_dir, status=status, reason=reason)
    if report:
        print(f"  report      : {report}")
    return rc
