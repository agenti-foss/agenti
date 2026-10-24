"""test_inbox.py — the operator inbox (CLAUDE.md §3h).

    python3 shared/test_inbox.py

No framework, no root, no vault. Exits non-zero on failure.

WHAT IT IS FOR: `agenti note` promises its caller that a note is recorded but
never reaches the model. That promise lives in exactly one function —
format_messages — and if it ever regressed, nothing would visibly break: notes
would simply start steering the agent, silently. That is the property most of
this file exists to pin down.
"""
import json
import sys
import tempfile
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


tmp = Path(tempfile.mkdtemp())
agent_dir = tmp / "agent"
state_dir = tmp / "agent" / "state"
agent_dir.mkdir(parents=True)
state_dir.mkdir(parents=True)
inbox = agent_dir / "inbox.jsonl"


def append(kind, body, author="alice", via="cli"):
    entries = rt.read_inbox(agent_dir)
    entry = {"id": len(entries) + 1, "ts": time.time(), "author": author,
             "via": via, "kind": kind, "body": body}
    with inbox.open("a") as fh:
        fh.write(json.dumps(entry) + "\n")
    return entry


section("reading an empty / missing inbox")
check("missing file reads as empty", rt.read_inbox(agent_dir), [])
check("nothing pending", rt.pending_inbox(agent_dir, state_dir), [])
check("consumed id starts at 0", rt.read_consumed_id(state_dir), 0)
check("no report section when empty", rt.operator_notes_section(agent_dir), [])

section("NOTES ARE NEVER SENT TO THE MODEL")
append("note", "client confirmed this host is in scope")
pending = rt.pending_inbox(agent_dir, state_dir)
check("the note IS pending (so it gets recorded)", len(pending), 1)
check("but format_messages sends NOTHING", rt.format_messages(pending), None)

append("message", "focus on the SMB shares")
pending = rt.pending_inbox(agent_dir, state_dir)
text = rt.format_messages(pending)
check("a message produces prompt text", text is not None, True)
check("the message body IS in the prompt", "focus on the SMB shares" in text, True)
check("the note body is NOT in the prompt", "client confirmed" in text, False)
check("the prompt states scope is unchanged",
      "do NOT expand what you are" in text.replace("\n", " "), True)

append("note", "second note, also private")
pending = rt.pending_inbox(agent_dir, state_dir)
text = rt.format_messages(pending)
check("still no note leakage with several entries",
      ("second note" in text) or ("client confirmed" in text), False)

section("consumed-id bookkeeping")
rt.write_consumed_id(state_dir, 3)
check("consumed id persists", rt.read_consumed_id(state_dir), 3)
check("nothing pending once consumed", rt.pending_inbox(agent_dir, state_dir), [])
append("message", "a later message")
pending = rt.pending_inbox(agent_dir, state_dir)
check("only the NEW entry is pending", [e["body"] for e in pending], ["a later message"])
check("delivered entries are not re-sent",
      "focus on the SMB shares" in (rt.format_messages(pending) or ""), False)

section("malformed input cannot break a run")
with inbox.open("a") as fh:
    fh.write("this is not json\n")
    fh.write('{"no_id": true}\n')
    fh.write("\n")
append("message", "after the garbage")
entries = rt.read_inbox(agent_dir)
check("garbage lines skipped, good ones kept",
      [e["body"] for e in entries][-1], "after the garbage")
check("entry count excludes malformed", len(entries), 5)

section("report section reproduces EVERYTHING, notes included")
lines = rt.operator_notes_section(agent_dir)
body = "\n".join(lines)
check("notes appear in the report", "client confirmed this host is in scope" in body, True)
check("messages appear in the report", "focus on the SMB shares" in body, True)
check("author is attributed", "alice" in body, True)
check("the scope caveat is stated", "cannot widen" in body, True)

section("linger is read from root-owned run-config, and defaults to 0")
check("no run-config -> 0", rt.read_linger_s(agent_dir), 0)
(agent_dir / "run-config.json").write_text(json.dumps({"profile": "dev", "linger_s": 45}))
check("reads the configured value", rt.read_linger_s(agent_dir), 45)
(agent_dir / "run-config.json").write_text(json.dumps({"profile": "dev"}))
check("absent key -> 0 (unattended runs never linger)", rt.read_linger_s(agent_dir), 0)
(agent_dir / "run-config.json").write_text(json.dumps({"linger_s": -30}))
check("negative clamped to 0", rt.read_linger_s(agent_dir), 0)
(agent_dir / "run-config.json").write_text("{ not json")
check("malformed run-config -> 0", rt.read_linger_s(agent_dir), 0)

section("a fresh start does not see steering sent before it began")
import os
d2 = Path(tempfile.mkdtemp()); st2 = d2 / "state"; st2.mkdir()
now = time.time()
(d2 / "inbox.jsonl").write_text(
    json.dumps({"id": 1, "ts": now - 86400 * 7, "kind": "message", "text": "old"}) + "\n"
    + json.dumps({"id": 2, "ts": now + 1, "kind": "message", "text": "new"}) + "\n")
(d2 / "run-config.json").write_text("{}")
check("stale entry dropped, fresh kept", [e["id"] for e in rt.pending_inbox(d2, st2)], [2])
(d2 / "run-resume-session").write_text("sid\n")
check("a resume still delivers what was said while stopped", [e["id"] for e in rt.pending_inbox(d2, st2)], [1, 2])

print(f"\n{'=' * 52}\n  {PASS} passed, {FAIL} failed\n{'=' * 52}")
sys.exit(1 if FAIL else 0)
