"""test_state.py — the durable state layer, focused on resume semantics.

    python3 shared/test_state.py

No framework, no root, no vault: it builds throwaway state directories in a
temp dir. Exits non-zero on failure.

WHAT IT IS FOR: start() TRUNCATES the findings ledger and resume() APPENDS to
it, and getting that backwards is silent — a resumed run would simply lose
every finding it had already recorded, and nothing would report an error. That
one distinction is most of what is tested here.
"""
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import state  # noqa: E402

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


tmp = Path(tempfile.mkdtemp())
st = state.StateStore(tmp / "state")


def snapshot():
    return json.loads((tmp / "state" / "state.json").read_text())


def ledger_lines():
    p = tmp / "state" / "findings.jsonl"
    return [l for l in p.read_text().splitlines() if l.strip()] if p.exists() else []


section("a fresh run")
st.start(engagement_id="E1", target="10.0.0.1/32", profile_name="dev",
         launched_by="alice", launched_via="api")
st.session_started("sess-aaaa")
for i in range(1, 4):
    st.record_finding(turn=i, tool="run_scan", verdict="ok", summary=f"f{i}")
check("three findings recorded", len(ledger_lines()), 3)
check("count matches ledger", snapshot()["findings_count"], 3)
check("attribution recorded", (snapshot()["launched_by"], snapshot()["launched_via"]),
      ("alice", "api"))
check("no resume_count yet", snapshot().get("resume_count", 0), 0)
st.finished(status="incomplete")
check("terminal status set", snapshot()["status"], "incomplete")

section("resume CONTINUES the same run")
started_before = snapshot()["started"]
ok = st.resume(session_id="sess-aaaa", launched_by="bob", launched_via="cli")
check("resume returns True when there is prior state", ok, True)
check("ledger NOT truncated", len(ledger_lines()), 3)
check("findings_count preserved", snapshot()["findings_count"], 3)
check("turn preserved", snapshot()["turn"], 3)
check("started timestamp preserved", snapshot()["started"], started_before)
check("resume_count incremented", snapshot()["resume_count"], 1)
check("resumed_from recorded", snapshot()["resumed_from"], "sess-aaaa")
check("phase back to running", snapshot()["phase"], "running")
# The old terminal status must be cleared, or a resumed run reads as finished
# while it is actively running — status --json would show a stale verdict.
check("stale terminal status cleared", snapshot().get("status"), None)
check("re-attribution applied", (snapshot()["launched_by"], snapshot()["launched_via"]),
      ("bob", "cli"))

st.record_finding(turn=4, tool="run_scan", verdict="ok", summary="f4")
check("post-resume finding APPENDS", len(ledger_lines()), 4)
check("count continues from before", snapshot()["findings_count"], 4)

st.resume(session_id="sess-aaaa")
check("second resume increments again", snapshot()["resume_count"], 2)

section("start() after a resume is a CLEAN slate")
st.start(engagement_id="E2", target="10.0.0.2/32", profile_name="dev")
check("ledger truncated by start()", len(ledger_lines()), 0)
check("count reset", snapshot()["findings_count"], 0)
check("resume_count gone", snapshot().get("resume_count", 0), 0)
check("new engagement", snapshot()["engagement_id"], "E2")

section("resume with no prior state refuses rather than inventing one")
empty = state.StateStore(tmp / "empty")
check("returns False", empty.resume(session_id="sess-zzzz"), False)
check("writes no snapshot", (tmp / "empty" / "state.json").exists(), False)

section("atomicity: a torn snapshot is never observed")
# state.json is written write-then-rename, so a reader either sees the previous
# good snapshot or the new one, never a half-written file.
st.start(engagement_id="E3", target="x", profile_name="dev")
for i in range(50):
    st.record_finding(turn=i, tool="t", verdict="ok", summary="s")
    json.loads((tmp / "state" / "state.json").read_text())  # raises if torn
check("50 rapid writes all parse", snapshot()["findings_count"], 50)

# ---------------------------------------------------------------------------
# GUI phase 2 (CLAUDE.md §4 step 6): run_id, history.jsonl, acknowledgments.
# state.json only ever holds the latest run; history.jsonl is what a Task
# History view reads. The silent failure modes here: a resume minting a NEW
# run_id (the same run would appear twice in history), finished() not
# appending (a run vanishes from history the moment the next one starts),
# and the fold keeping the FIRST line for a resumed run instead of the last
# (history would show the run as "incomplete" forever after it finished).
# ---------------------------------------------------------------------------
section("run_id: minted by start(), preserved by resume(), fresh per start()")
h = state.StateStore(tmp / "hist")
h.start(engagement_id="H1", target="10.1.0.0/24", profile_name="dev")
rid1 = json.loads((tmp / "hist" / "state.json").read_text())["run_id"]
check("start() mints a 12-hex run_id", (len(rid1), all(c in "0123456789abcdef" for c in rid1)),
      (12, True))
check("start() also sets it as a readable in-memory attribute (§ generic-"
     "launcher runner-parity: a resuming workspace agent reads THIS to "
     "reuse its own per-run directory, without re-parsing state.json)",
      h.run_id, rid1)
h.session_started("sess-h1")
h.finished(status="incomplete", reason="stopped")
h.resume(session_id="sess-h1")
check("resume() keeps the same run_id",
      json.loads((tmp / "hist" / "state.json").read_text())["run_id"], rid1)
check("resume() also keeps the in-memory attribute in sync", h.run_id, rid1)
check("resume() clears the stale terminal fields",
      [k in json.loads((tmp / "hist" / "state.json").read_text())
       for k in ("status", "reason", "ended")], [False, False, False])
h.finished(status="completed", reason=None)
h.start(engagement_id="H2", target="10.2.0.0/24", profile_name="dev")
rid2 = json.loads((tmp / "hist" / "state.json").read_text())["run_id"]
check("a new start() mints a different run_id", rid2 != rid1, True)
check("...and updates the in-memory attribute to match", h.run_id, rid2)
h.finished(status="failed", reason="error")

section("run_id: a fresh StateStore has none until start()/resume() is called")
fresh = state.StateStore(tmp / "fresh-rid")
check("no run_id before start()/resume()", fresh.run_id, None)
ok2 = fresh.resume(session_id="sess-none")
check("resume() with no prior state returns False and sets nothing",
      (ok2, fresh.run_id), (False, None))

section("history.jsonl: one line per finished(), folded by run_id, last wins")
raw = [json.loads(l) for l in (tmp / "hist" / "history.jsonl").read_text().splitlines()]
check("three finished() calls -> three raw lines", len(raw), 3)
check("raw lines carry status/reason/ended", all("status" in r and "reason" in r and "ended" in r
                                                 for r in raw), True)
folded = state.read_history(tmp / "hist")
check("folded to one entry per run_id", len(folded), 2)
check("newest ended first", [e["run_id"] for e in folded], [rid2, rid1])
by_id = {e["run_id"]: e for e in folded}
check("the resumed run shows its LAST outcome, not its first",
      (by_id[rid1]["status"], by_id[rid1]["reason"]), ("completed", None))
check("resume_count carried into history", by_id[rid1]["resume_count"], 1)
check("the failed run keeps its reason", (by_id[rid2]["status"], by_id[rid2]["reason"]),
      ("failed", "error"))
check("finished() also wrote the terminal snapshot",
      (snapshot_h := json.loads((tmp / "hist" / "state.json").read_text()))["phase"], "finished")
check("snapshot has reason + ended", ("reason" in snapshot_h, "ended" in snapshot_h), (True, True))

section("history.jsonl: a corrupt line and a pre-run_id line are tolerated, not fatal")
with (tmp / "hist" / "history.jsonl").open("a") as f:
    f.write('{"this is not json\n')
    f.write(json.dumps({"status": "completed", "ended": 1.0, "target": "legacy"}) + "\n")
folded = state.read_history(tmp / "hist")
check("corrupt line skipped, legacy line kept as its own entry", len(folded), 3)
check("legacy (no run_id) entry sorts by its ended time (oldest, last)",
      folded[-1].get("target"), "legacy")
check("read_history on a dir with no history file -> []", state.read_history(tmp / "nope"), [])

section("merge_acks: first ack wins, unacked rows say so, unknown run_ids ignored")
acks = [
    {"run_id": rid1, "by": "alice", "via": "api", "ts": 10.0},
    {"run_id": rid1, "by": "bob", "via": "cli", "ts": 11.0},       # second ack: ignored
    {"run_id": "not-a-run", "by": "mallory", "via": "cli", "ts": 12.0},
]
merged = state.merge_acks(state.read_history(tmp / "hist"), acks)
m = {e.get("run_id"): e for e in merged}
check("acked run: acknowledged=True, by the FIRST acknowledger",
      (m[rid1]["acknowledged"], m[rid1]["acknowledged_by"], m[rid1]["acknowledged_at"]),
      (True, "alice", 10.0))
check("unacked run: acknowledged=False, by=None",
      (m[rid2]["acknowledged"], m[rid2]["acknowledged_by"]), (False, None))
check("merge does not mutate the input rows",
      "acknowledged" in state.read_history(tmp / "hist")[0], False)
check("read_acks on a dir with no acks.jsonl -> []", state.read_acks(tmp / "hist"), [])
(tmp / "hist" / "acks.jsonl").write_text(json.dumps(acks[0]) + "\nnot json\n")
check("read_acks skips a corrupt line", len(state.read_acks(tmp / "hist")), 1)

section("apply_hidden: soft-delete for Task History (CLAUDE.md 'Current "
        "plan' decision 5) — a display filter, never a record")
check("read_hidden on a dir with no hidden.jsonl -> []", state.read_hidden(tmp / "hist"), [])
hidden = [
    {"run_id": rid1, "by": "alice", "ts": 20.0},
    {"run_id": rid1, "by": "bob", "ts": 21.0},          # second hide of the same run: ignored
    {"run_id": "not-a-run", "by": "mallory", "ts": 22.0},
]
# base_history also carries the legacy, pre-run_id row from the section
# above — real production data, kept deliberately (fold_history never drops
# it), so every check below keys off .get("run_id") rather than assuming
# every row has one.
base_history = state.read_history(tmp / "hist")
default_view = state.apply_hidden(base_history, hidden)
check("default (include_hidden=False): the hidden run is dropped entirely, "
      "everything else (including the legacy no-run_id row) stays",
      sorted(e.get("run_id") or "" for e in default_view),
      sorted(e.get("run_id") or "" for e in base_history if e.get("run_id") != rid1))
check("...and history.jsonl on disk is completely untouched by hiding",
      len(state.read_history(tmp / "hist")), len(base_history))
all_view = state.apply_hidden(base_history, hidden, include_hidden=True)
check("--all keeps every row, including the hidden one and the legacy one",
      len(all_view), len(base_history))
am = {e["run_id"]: e for e in all_view if e.get("run_id")}
check("the hidden row is annotated with WHO hid it, the FIRST hider winning "
      "(the same 'who actually did it' rule merge_acks already uses)",
      (am[rid1]["hidden"], am[rid1]["hidden_by"], am[rid1]["hidden_at"]),
      (True, "alice", 20.0))
check("a never-hidden row still carries the three fields, all falsy, so the "
      "GUI can render one uniform shape without checking key existence",
      (am[rid2]["hidden"], am[rid2]["hidden_by"], am[rid2]["hidden_at"]),
      (False, None, None))
check("apply_hidden does not mutate the input rows",
      "hidden" in base_history[0], False)
check("an unknown run_id in hidden.jsonl (a typo, a run since purged) never "
      "shrinks the result — mallory's bogus entry above changed nothing",
      len(all_view), len(base_history))
(tmp / "hist" / "hidden.jsonl").write_text(json.dumps(hidden[0]) + "\nnot json\n")
check("read_hidden skips a corrupt line", len(state.read_hidden(tmp / "hist")), 1)
idx = [e.get("run_id") for e in all_view].index(rid1)
check("merge_acks and apply_hidden compose (a hidden row can also be acked)",
      state.merge_acks(all_view, [{"run_id": rid1, "by": "carol", "ts": 30.0}])[idx]
          ["acknowledged"], True)


# ---------------------------------------------------------------------------
section("record_event: in the ledger, in order, NOT counted as a finding")
ev = state.StateStore(tmp / "events")
ev.start(engagement_id="E", target="10.0.0.0/24", profile_name="dev", launched_by="t")
ev.record_event(turn=1, tool="agent:says", verdict="text", summary="I will scan the host.")
ev.record_event(turn=1, tool="run_scan", verdict="call", summary="nmap -sV 10.0.0.5")
ev.record_finding(turn=1, tool="run_scan", verdict="ok", summary="3 open ports")
ev.record_event(turn=2, tool="agent:says", verdict="text", summary="Done.")
rows = state.read_findings(tmp / "events")
check("four ledger rows, in order", [r["tool"] for r in rows], ["agent:says", "run_scan", "run_scan", "agent:says"])
check("...with their verdicts", [r["verdict"] for r in rows], ["text", "call", "ok", "text"])
live = state.read_live_status(tmp / "events")
check("findings_count counts only the result", live["findings_count"], 1)
check("turn advances on an event too", live["turn"], 2)

section("finished(report=): the history row names its own report")
ev.finished(status="completed", reason=None, report="E-20260922-101010.md")
h = state.read_history(tmp / "events")
check("history carries the report file name", h[-1].get("report"), "E-20260922-101010.md")
check("live snapshot carries it too", state.read_live_status(tmp / "events").get("report"), "E-20260922-101010.md")
ev2 = state.StateStore(tmp / "events2")
ev2.start(engagement_id="E", target="x", profile_name="dev", launched_by="t")
ev2.finished(status="failed", reason="error")
check("no report -> key absent, not None-as-string", state.read_history(tmp / "events2")[-1].get("report"), None)

# ---------------------------------------------------------------------------
section("StateTracker: the SDK message stream -> ledger entries (agent_runtime)")
import agent_runtime  # noqa: E402  (same directory)

class TextBlock:
    def __init__(self, text): self.text = text
class ToolUseBlock:
    def __init__(self, id, name, input): self.id, self.name, self.input = id, name, input
class ToolResultBlock:
    def __init__(self, tool_use_id, content, is_error=False):
        self.tool_use_id, self.content, self.is_error = tool_use_id, content, is_error
class AssistantMessage:
    def __init__(self, content): self.content = content
class UserMessage:
    def __init__(self, content): self.content = content
class ResultMessage:
    pass

def summarize(content):   # the agents' own summarisers collapse whitespace too
    return " ".join(" ".join(b.get("text", "") for b in content if isinstance(b, dict)).split())[:200]

tr_store = state.StateStore(tmp / "tracker")
tr_store.start(engagement_id="E", target="x", profile_name="dev", launched_by="t")
warnings = []
tr = agent_runtime.StateTracker(tr_store, summarize, log_warn=warnings.append)
tr.track(AssistantMessage([TextBlock("Let me   scan\nthe host."),
                           ToolUseBlock("t1", "run_scan", {"command": "nmap -sV 10.0.0.5"})]))
check("turn counted on the assistant message", tr.turn, 1)
tr.track(UserMessage([ToolResultBlock("t1", [{"type": "text", "text": "PORT STATE\n22/tcp open"}])]))
tr.track(AssistantMessage([ToolUseBlock("t2", "read_scan", {"file": "a.txt", "pattern": "open"})]))
tr.track(UserMessage([ToolResultBlock("t2", [{"type": "text", "text": "boom"}], is_error=True)]))
tr.track(ResultMessage())
tr.track(AssistantMessage([TextBlock("   "), TextBlock("x" * 2500)]))
rows = state.read_findings(tmp / "tracker")
check("rows: says, call, result, call, error-result, says",
      [(r["tool"], r["verdict"]) for r in rows],
      [("agent:says", "text"), ("run_scan", "call"), ("run_scan", "ok"),
       ("read_scan", "call"), ("read_scan", "error"), ("agent:says", "text")])
check("narration keeps its line breaks, tidied", rows[0]["summary"], "Let me scan\nthe host.")
check("single-argument call shows the bare value", rows[1]["summary"], "nmap -sV 10.0.0.5")
check("multi-argument call shows key=value", rows[3]["summary"], "file=a.txt, pattern=open")
check("result summarised by the agent's own summariser", rows[2]["summary"], "PORT STATE 22/tcp open")
check("result carries the CALL's turn, not the current one", rows[2]["turn"], 1)
check("blank narration skipped, long narration clipped", (len(rows), rows[5]["summary"].endswith("…"),
      len(rows[5]["summary"])), (6, False, 2500))
check("a narration over the limit is clipped with an ellipsis", (lambda: (
    tr.track(AssistantMessage([TextBlock("y" * (agent_runtime.NARRATION_MAX_CHARS + 50))])),
    (lambda r: (r["summary"].endswith("…"), len(r["summary"])))(state.read_findings(tmp / "tracker")[-1]))[1])(),
      (True, agent_runtime.NARRATION_MAX_CHARS + 1))
check("tidy_narration drops runs of blank lines and trailing spaces",
      agent_runtime.tidy_narration("a  \n\n\n\nb   c\n"), "a\n\nb c")
check("only results count as findings", state.read_live_status(tmp / "tracker")["findings_count"], 2)
check("an unmatched result falls back to '?' at the current turn", (lambda: (
    tr.track(UserMessage([ToolResultBlock("nope", [{"type": "text", "text": "late"}])])),
    state.read_findings(tmp / "tracker")[-1]["tool"])[1])(), "?")
tr.track(object())
check("an unknown message type is ignored, no warning", warnings, [])
class Weird:
    content = property(lambda self: (_ for _ in ()).throw(RuntimeError("boom")))
tr.track(type("AssistantMessage", (Weird,), {})())
check("a broken message warns instead of raising", len(warnings) == 1 and "could not process" in warnings[0], True)
none_tr = agent_runtime.StateTracker(None, summarize, log_warn=warnings.append)
none_tr.track(AssistantMessage([TextBlock("hi")]))
check("a tracker with no store still counts turns and never warns", (none_tr.turn, len(warnings)), (1, 1))
check("summarize_tool_input: non-dict", agent_runtime.summarize_tool_input("plain"), "plain")
check("summarize_tool_input: clipped", len(agent_runtime.summarize_tool_input({"a": "y" * 400})),
      agent_runtime.CALL_SUMMARY_MAX_CHARS + 1)

section("operator_notes_section(since=): only this run's input reaches its report")
import json as _json
adir = tmp / "notes-agent"; adir.mkdir()
(adir / "inbox.jsonl").write_text("\n".join(_json.dumps(e) for e in [
    {"id": 1, "ts": 1000.0, "author": "old", "via": "cli", "kind": "note", "body": "from a previous run"},
    {"id": 2, "ts": 2000.5, "author": "now", "via": "api", "kind": "message", "body": "this run"},
    {"id": 3, "ts": 2500.0, "author": "now", "via": "api", "kind": "note", "body": "also this run"},
]) + "\n")
lines_all = agent_runtime.operator_notes_section(adir)
lines_run = agent_runtime.operator_notes_section(adir, since=2000.0)
check("no filter: every entry ever (the old behaviour)", sum(1 for l in lines_all if l.startswith("- **")), 3)
check("since=start: only entries from this run", sum(1 for l in lines_run if l.startswith("- **")), 2)
check("...the old one is gone", any("previous run" in l for l in lines_run), False)
check("...one second of slack for a note sent as the run started",
      sum(1 for l in agent_runtime.operator_notes_section(adir, since=2001.0) if l.startswith("- **")), 2)
check("since with nothing in range: no section at all", agent_runtime.operator_notes_section(adir, since=9999.0), [])

section("StateStore.set_awaiting_operator / clear / read (ask_operator, "
        "the agent-initiated pause)")
aw = state.StateStore(tmp / "awaiting")
aw.start(engagement_id="E", target="T", profile_name="dev")
check("nothing pending at the start of a run", aw.read_awaiting_operator(), None)
aw.set_awaiting_operator("which credential should I try next?")
check("read_awaiting_operator() returns the question", aw.read_awaiting_operator(),
      "which credential should I try next?")
snap = json.loads((tmp / "awaiting" / "state.json").read_text())
check("it is a real field on the live snapshot (status --json sees it for free)",
      snap["awaiting_operator"]["question"], "which credential should I try next?")
check("...with a timestamp", "asked_at" in snap["awaiting_operator"], True)
aw.clear_awaiting_operator()
check("clear_awaiting_operator() removes it", aw.read_awaiting_operator(), None)
check("clearing an already-clear flag is a harmless no-op",
      aw.clear_awaiting_operator() or aw.read_awaiting_operator(), None)
aw.set_awaiting_operator("a second question, later in the same run")
check("can be set again after being cleared", aw.read_awaiting_operator(),
      "a second question, later in the same run")

section("read_recent_activity: the last message + the steps around it, nothing older")
ra = tmp / "recent"
(ra / "state").mkdir(parents=True)
def _w(rows):
    (ra / "state" / "findings.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))
call = lambda n: {"turn": n, "tool": "nmap", "verdict": "call", "summary": f"step {n}"}
say = lambda n, t: {"turn": n, "tool": "agent:says", "verdict": "say", "summary": t}
_w([call(1), say(2, "first thought"), call(3), call(4), say(5, "last thought"), call(6)])
got = [r["turn"] for r in state.read_recent_activity(ra / "state")]
check("keeps steps before the last message, the message, and what came after", got, [3, 4, 5, 6])
_w([call(1), call(2)])
check("a run that has not spoken yet falls back to its last rows",
      [r["turn"] for r in state.read_recent_activity(ra / "state")], [1, 2])
_w([say(1, "a"), {"turn": 2, "tool": "operator:message", "verdict": "call", "summary": "hi"}, call(3), say(4, "b")])
check("operator input is a boundary too", [r["turn"] for r in state.read_recent_activity(ra / "state")], [3, 4])
check("no findings file -> empty", state.read_recent_activity(tmp / "nowhere"), [])

print(f"\n{'=' * 52}\n  {PASS} passed, {FAIL} failed\n{'=' * 52}")
sys.exit(1 if FAIL else 0)
