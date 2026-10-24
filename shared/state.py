"""
state.py — durable live status + per-turn findings (CLAUDE.md §3d).

What this is NOT: a reimplementation of Claude Agent SDK session persistence.
The SDK already saves the full conversation transcript to disk and supports
resuming it by session ID (see the SDK's sessions docs) — duplicating that
here would be exactly the kind of speculative, unproven-need code CLAUDE.md
warns against. This module exists for what the SDK does NOT give you:

  1. A place `status --json` can read "where is this run right now, what has
     it found so far" WITHOUT the process needing to still be alive, and
     without parsing raw stdout logs or the SDK's own transcript format
     (whose entry format is explicitly internal and can change between SDK
     releases — don't parse it directly, which is exactly why this module
     writes its own small, stable-shaped files instead).
  2. A durable findings ledger that survives past a single run, so pause/
     resume and crash recovery have something better than "freeze the OS
     process and hope" to fall back to — a future resume can summarize
     prior findings into the next prompt even when true SDK session
     continuity isn't available or appropriate (e.g. --dev iterating with a
     fresh session each time).

Two files per run directory (mirrors the existing scans/ + reports/ split —
this is neither raw tool output nor the final write-up, it's the live
record of what happened as it happened):

    state.json      current snapshot — phase, session_id, turn, target,
                     timestamps. Overwritten each update (atomic write, so a
                     crash mid-write never leaves a half-written file behind
                     — the reader always sees either the old or new value,
                     never a torn one).
    findings.jsonl   append-only ledger, one JSON object per tool call.
                     Never rewritten, so a crash loses at most the one
                     in-flight entry, never prior ones.

    history.jsonl    append-only, one JSON object per FINISHED run (written by
                     finished()). state.json only ever describes the current
                     or most recent run — start() overwrites it and truncates
                     findings.jsonl — so before this file existed there was no
                     structured record of any run but the latest one; only
                     reports/ accumulated, as unstructured text. The GUI's
                     Task History (CLAUDE.md §4 step 6) needs "every run this
                     agent has done, with its status and count", which is
                     exactly this file. A run that is stopped and resumed
                     produces more than one line with the same run_id;
                     read_history() folds them, last line wins.

Written to `profile.data_root / "state"` — same profile-relative split
scans/ and reports/ already use, so --dev and commercial runs never share a
state directory either.

Terminal `status` vocabulary (what finished() is given, and what every
reader should expect): "completed", "incomplete", "failed", and trafficmon's
"no data" (a capture window that saw nothing — a real outcome, not a
failure). `reason`, new alongside history.jsonl, says WHY a run ended when
the status alone can't: "stopped" (operator stop), "interrupted" (operator
interrupt — abort the in-flight tool call, then end), "timeout" (wall-clock
backstop), "max_turns"/"max_budget" (the engagement's own configured turn
or budget ceiling was reached with no operator or exception involved —
agent_runtime.resource_cap_reason(), CLAUDE.md §4 item 47; status is
"incomplete" here, same bucket as "interrupted", never "failed" — a cap
doing its job is not a crash), "error" (an unexpected exception), or None
for a natural end. "canceled" vs "paused" in a task-history view are
readings of this field, not statuses of their own.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

STATE_FILENAME = "state.json"
FINDINGS_FILENAME = "findings.jsonl"
HISTORY_FILENAME = "history.jsonl"
ACKS_FILENAME = "acks.jsonl"   # lives in the AGENT dir (root-owned), not state/
HIDDEN_FILENAME = "hidden.jsonl"   # same dir/ownership shape as acks.jsonl

# The fields history.jsonl carries over from state.json for each finished
# run. Deliberately a fixed list rather than "everything": the history file
# is read whole by the GUI, and a future field added to the live snapshot
# should not silently start bloating every history line.
_HISTORY_FIELDS = ("run_id", "session_id", "engagement_id", "target", "profile",
                   "launched_by", "launched_via", "turn", "findings_count",
                   "started", "resume_count", "report")


def _atomic_write(path: Path, text: str) -> None:
    """Write-then-rename: POSIX rename() is atomic, so a reader never sees a
    partially-written file, and a crash mid-write leaves the PREVIOUS good
    state.json in place rather than a truncated one."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text)
    tmp.replace(path)


@dataclass
class StateStore:
    """One instance per run. Call record_* as the run progresses. Every
    write is a full snapshot to state.json (small — a handful of fields —
    so rewriting it each time costs nothing) plus, for findings, one
    appended line to findings.jsonl."""

    state_dir: Path

    def __post_init__(self) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self._state_path = self.state_dir / STATE_FILENAME
        self._findings_path = self.state_dir / FINDINGS_FILENAME
        self._history_path = self.state_dir / HISTORY_FILENAME
        # Readable in-memory after start()/resume().
        self.run_id: str | None = None

    def start(self, *, engagement_id: str, target: str, profile_name: str,
              launched_by: str = "unknown", launched_via: str = "cli") -> None:
        """Call once, before the SDK client connects. There is no session_id
        yet — session_started() fills it in once the SDK's own init message
        arrives. `launched_by` is attribution (CLAUDE.md §3g) — the human
        identity the CLI captured (from $SUDO_USER) when it wrote
        run-launched-by, which the caller reads and passes through here;
        state.py has no notion of "who" beyond the string it's given.
        `launched_via` records whether that identity came from a terminal
        ("cli") or an authenticated API principal ("api") — kept separate so an
        audit can distinguish the two rather than inferring it from a name."""
        now = time.time()
        # Our own id for this run, minted here rather than borrowed from the
        # SDK's session_id: that one only exists once the SDK's own init
        # message arrives, and a run that fails before then still needs a
        # handle for history.jsonl and for `acknowledge` to point at.
        # Preserved across resume(), because a resumed run is the same run
        # continuing (see resume()'s own docstring).
        self.run_id = uuid.uuid4().hex[:12]
        self._write({
            "phase": "starting",
            "run_id": self.run_id,
            "session_id": None,
            "engagement_id": engagement_id,
            "target": target,
            "profile": profile_name,
            "launched_by": launched_by,
            "launched_via": launched_via,
            "turn": 0,
            "findings_count": 0,
            "started": now,
            "updated": now,
        })
        # Fresh run: previous run's findings must not bleed into this one's
        # count/status. Truncate, don't append-forever.
        self._findings_path.write_text("")

    def resume(self, *, session_id: str, launched_by: str = "unknown",
               launched_via: str = "cli") -> bool:
        """Continue an existing run instead of starting a new one.

        The difference from start() that matters: start() TRUNCATES
        findings.jsonl, because a fresh run's count must not inherit the last
        one's. A resume is the same run continuing, so the ledger is APPENDED
        to and turn/findings_count/started are preserved — otherwise resuming
        would silently erase everything the run had already found, which is
        precisely the record a resumed run most needs to keep.

        Returns False if there is no prior state to continue, so the caller can
        fall back to a normal start rather than proceeding with an empty
        snapshot."""
        st = self._read()
        if not st:
            return False
        now = time.time()
        st.update({
            "phase": "running",
            "session_id": session_id,
            "resumed_from": session_id,
            "resume_count": int(st.get("resume_count", 0)) + 1,
            "launched_by": launched_by,
            "launched_via": launched_via,
            "updated": now,
        })
        # A run recorded before run_id existed can still be resumed; give it
        # one now so its eventual history line has a handle like every other.
        st.setdefault("run_id", uuid.uuid4().hex[:12])
        st.pop("status", None)   # it is running again; the old terminal status is stale
        st.pop("reason", None)
        st.pop("ended", None)
        self._write(st)
        self.run_id = st["run_id"]
        return True

    def session_started(self, session_id: str) -> None:
        """Call once the SDK's SystemMessage(subtype='init') arrives —
        that's the first point a session_id exists to persist."""
        st = self._read()
        st["session_id"] = session_id
        st["phase"] = "running"
        st["updated"] = time.time()
        self._write(st)

    def record_finding(self, *, turn: int, tool: str, verdict: str, summary: str) -> None:
        """One entry per tool RESULT. `summary` should be short and free of
        secrets/raw output — this file is meant to be cheap to read
        entirely, not a second copy of scans/. The full tool output already
        lives in scans/ or reports/; this just indexes it. Counts towards
        findings_count, which is what the dashboard shows."""
        self._append(turn=turn, tool=tool, verdict=verdict, summary=summary, counts=True)

    def record_event(self, *, turn: int, tool: str, verdict: str, summary: str) -> None:
        """A ledger entry that is NOT a finding: what the agent said between
        tool calls (tool="agent:says", verdict="text") and what it is about
        to call (verdict="call", summary=the arguments). These make the
        console read like a terminal — what it is thinking, what it is doing
        now, what came back — without inflating the findings count, which
        stays "results the run produced". Same file, same ordering, so a
        reader never has to merge two streams by timestamp."""
        self._append(turn=turn, tool=tool, verdict=verdict, summary=summary, counts=False)

    def _append(self, *, turn: int, tool: str, verdict: str, summary: str, counts: bool) -> None:
        entry = {
            "turn": turn,
            "tool": tool,
            "verdict": verdict,
            "summary": summary,
            "ts": time.time(),
        }
        with self._findings_path.open("a") as f:
            f.write(json.dumps(entry) + "\n")
        st = self._read()
        st["turn"] = turn
        if counts:
            st["findings_count"] = st.get("findings_count", 0) + 1
        st["updated"] = time.time()
        self._write(st)

    def record_inbox(self, *, turn: int, entry: dict) -> None:
        """Put an operator note/message into the SAME ledger as tool calls, so
        the timeline reads in order: what the agent did, what it was told, what
        it did next. A separate stream would force every reader — including the
        GUI — to merge two files by timestamp and get it subtly wrong."""
        kind = entry.get("kind", "note")
        self.record_finding(
            turn=turn,
            tool=f"operator:{kind}",
            verdict="received",
            summary=f"[{entry.get('author', '?')} via {entry.get('via', '?')}] "
                    f"{entry.get('body', '')}")

    def set_awaiting_operator(self, question: str) -> None:
        """Mark this run as blocked on a question only the human operator can
        answer — a self-initiated capability (the `ask_operator` tool,
        agent_runtime.py), distinct from the operator's own unilateral
        pause/resume. One more field on the same live snapshot, so
        `status --json`/the GUI need no new endpoint to see it — the pump
        loop stops issuing further model turns while this is set (see
        agent_runtime.pump_channels), and only clears it once a reply
        actually arrives."""
        st = self._read()
        st["awaiting_operator"] = {"question": question, "asked_at": time.time()}
        st["updated"] = time.time()
        self._write(st)

    def clear_awaiting_operator(self) -> None:
        st = self._read()
        if "awaiting_operator" in st:
            del st["awaiting_operator"]
            st["updated"] = time.time()
            self._write(st)

    def read_awaiting_operator(self) -> str | None:
        """The pending question, or None. A plain read of the live snapshot —
        kept as a method (not just read_live_status() below) so the SAME
        process that just called set_awaiting_operator() can poll its own
        state without re-instantiating a StateStore."""
        return (self._read().get("awaiting_operator") or {}).get("question")

    def finished(self, *, status: str, reason: str | None = None,
                 report: str | None = None) -> None:
        """Terminal snapshot PLUS one appended line to history.jsonl.

        `report` is the file name (not path) of the report this run wrote,
        so a history row can be opened as its own report rather than "the
        latest one" — which, after any later run, is somebody else's.

        `status` is the outcome (see the module docstring for the
        vocabulary); `reason` is why it ended, when that isn't obvious from
        the status alone — "stopped"/"interrupted"/"timeout"/"max_turns"/
        "max_budget"/"error", or None for a natural end. The GUI's task
        history sorts on this: an
        operator-stopped run and a crashed run are both "incomplete"-or-
        "failed" to the report but very different things to the person
        deciding what to do next."""
        now = time.time()
        st = self._read()
        st["phase"] = "finished"
        st["status"] = status
        st["reason"] = reason
        st["ended"] = now
        st["updated"] = now
        if report:
            st["report"] = report
        self._write(st)
        # One line per finished run. Append-only, like findings.jsonl, and
        # for the same reason: a crash mid-write loses at most this line,
        # never the ones before it. A resumed run appends a second line with
        # the same run_id; read_history() keeps the last.
        line = {k: st.get(k) for k in _HISTORY_FIELDS}
        line.update({"status": status, "reason": reason, "ended": now})
        try:
            with self._history_path.open("a") as f:
                f.write(json.dumps(line) + "\n")
        except OSError:
            pass  # observability, never a reason to fail the run's own exit path

    def _write(self, fields: dict[str, Any]) -> None:
        _atomic_write(self._state_path, json.dumps(fields, indent=2))

    def _read(self) -> dict[str, Any]:
        try:
            return json.loads(self._state_path.read_text())
        except (OSError, json.JSONDecodeError):
            return {}


def _slot_text(base: Path, rel: str) -> str | None:
    """A run writes these files, and root reads them (status, dashboard,
    history, acknowledge, resume): read through run_files.open_in_slot, a
    descriptor walk from `base` that never follows a link and opens only a
    plain, singly-linked file without blocking (audit run 2; run 1 F16). Any
    refusal reads as "no data"."""
    import run_files
    try:
        fh, _size = run_files.open_in_slot(base, rel)
    except run_files.FilesError:
        return None
    with fh:
        return fh.read(run_files.MAX_READ_BYTES).decode("utf-8", errors="replace")


def _state_text(state_dir: Path, name: str) -> str | None:
    return _slot_text(state_dir.parent, f"{state_dir.name}/{name}")


def read_live_status(state_dir: Path) -> dict[str, Any] | None:
    """Read-only, for `status --json` — no SDK, no running process required.
    Returns None if no run has ever recorded state in this directory (a
    fresh deploy, or an agent pre-dating this feature)."""
    raw = _state_text(state_dir, STATE_FILENAME)
    try:
        d = json.loads(raw) if raw else None
    except json.JSONDecodeError:
        return None
    return d if isinstance(d, dict) else None


def read_findings(state_dir: Path, limit: int | None = None) -> list[dict[str, Any]]:
    """Read-only. `limit` returns only the most recent N entries — a status
    view wants "what just happened," not the full history of a long run."""
    lines = (_state_text(state_dir, FINDINGS_FILENAME) or "").splitlines()
    if limit:
        lines = lines[-limit:]
    out: list[dict[str, Any]] = []
    for line in lines:
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue  # one corrupt line (e.g. a torn write from a crash
                      # mid-append) must not lose every entry before it
    return out


def read_recent_activity(state_dir: Path, scan: int = 150, cap: int = 60) -> list[dict[str, Any]]:
    """What a dashboard card shows: the agent's LAST message, the steps it ran
    just before saying it, and anything it has done since. Everything older is
    left out — the card reads like the tail of the agent page's console, not a
    log. The boundary is the message (or operator input / question) before the
    last message. Falls back to the last few rows when the run has not spoken."""
    rows = read_findings(state_dir, limit=scan)
    boundary = ("agent:says", "ask_operator")

    def is_break(r: dict[str, Any]) -> bool:
        t = str(r.get("tool") or "")
        return t in boundary or t.startswith("operator:")

    last = next((i for i in range(len(rows) - 1, -1, -1) if rows[i].get("tool") == "agent:says"), None)
    if last is None:
        return rows[-5:]
    start = 0
    for i in range(last - 1, -1, -1):
        if is_break(rows[i]):
            start = i + 1
            break
    return rows[start:][-cap:]


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for line in (_slot_text(path.parent.parent, f"{path.parent.name}/{path.name}") or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(e, dict):
            out.append(e)
    return out


def fold_history(lines: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """One entry per run_id, the LAST line for it winning (a stop-then-resume
    writes two), most recently ended first. Lines with no run_id (pre-dating
    the field) are kept as their own entries rather than dropped — losing a
    run from the history because it predates a schema change would be the
    quiet kind of data loss this module exists to avoid."""
    by_id: dict[str, dict[str, Any]] = {}
    orphans: list[dict[str, Any]] = []
    for e in lines:
        rid = e.get("run_id")
        if rid:
            by_id[rid] = e
        else:
            orphans.append(e)
    merged = list(by_id.values()) + orphans
    merged.sort(key=lambda e: float(e.get("ended") or 0), reverse=True)
    return merged


def read_history(state_dir: Path) -> list[dict[str, Any]]:
    """Read-only, for `history --json`. Folded (see fold_history)."""
    return fold_history(_read_jsonl(state_dir / HISTORY_FILENAME))


def read_acks(agent_dir: Path) -> list[dict[str, Any]]:
    """acks.jsonl is written by the CLI as root — the agent can read it and
    cannot forge one, the same shape as inbox.jsonl (CLAUDE.md §3h). One
    line per acknowledgment: {"run_id", "by", "via", "ts"}."""
    return _read_jsonl(agent_dir / ACKS_FILENAME)


def merge_acks(history: list[dict[str, Any]],
               acks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Annotate each history entry with acknowledged / acknowledged_by /
    acknowledged_at. The FIRST ack for a run_id wins: "who reviewed this"
    should name the person who actually did, not whoever clicked last."""
    first: dict[str, dict[str, Any]] = {}
    for a in acks:
        rid = a.get("run_id")
        if rid and rid not in first:
            first[rid] = a
    out = []
    for e in history:
        e = dict(e)
        a = first.get(e.get("run_id") or "")
        e["acknowledged"] = a is not None
        e["acknowledged_by"] = a.get("by") if a else None
        e["acknowledged_at"] = a.get("ts") if a else None
        out.append(e)
    return out


def read_hidden(agent_dir: Path) -> list[dict[str, Any]]:
    """hidden.jsonl is written by the CLI as root — the agent can read it and
    cannot forge one, the identical shape to acks.jsonl (CLAUDE.md "Current
    plan" decision 5: a soft delete for Task History). One line per hide
    event: {"run_id", "by", "ts"}. This is a DISPLAY filter, never a record:
    history.jsonl, the findings ledger, reports and the audit log are never
    touched by hiding a row — see apply_hidden()."""
    return _read_jsonl(agent_dir / HIDDEN_FILENAME)


def apply_hidden(history: list[dict[str, Any]], hidden: list[dict[str, Any]], *,
                 include_hidden: bool = False) -> list[dict[str, Any]]:
    """Fold hidden.jsonl into a history list. Default (include_hidden=False,
    what `history` shows without --all): hidden rows are dropped entirely —
    a GUI operator who hid a run should not see it come back. With
    include_hidden=True (`history --all`): every row is kept, and a hidden
    one gains hidden / hidden_by / hidden_at fields, so an admin auditing
    what was hidden can see who did it and when. The FIRST hide for a
    run_id wins, the same "who actually did it" precedent merge_acks already
    set — a run can be hidden only once in any way that matters."""
    first: dict[str, dict[str, Any]] = {}
    for h in hidden:
        rid = h.get("run_id")
        if rid and rid not in first:
            first[rid] = h
    out = []
    for e in history:
        h = first.get(e.get("run_id") or "")
        if h is None:
            if include_hidden:
                # Never copy the caller's own dict in place — a row that
                # was never hidden still needs the three fields present
                # (False/None) so the GUI can render one uniform shape
                # without checking for key existence on every row, and
                # mutating history's own entries would be a surprising
                # side effect on the list the caller passed in.
                e = dict(e)
                e["hidden"] = False
                e["hidden_by"] = None
                e["hidden_at"] = None
                out.append(e)
            else:
                out.append(e)
            continue
        if not include_hidden:
            continue
        e = dict(e)
        e["hidden"] = True
        e["hidden_by"] = h.get("by")
        e["hidden_at"] = h.get("ts")
        out.append(e)
    return out
