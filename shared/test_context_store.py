#!/usr/bin/env python3
"""test_context_store.py — instruction files, their history, the per-run
snapshot, and the prompt builder that layers them.

    python3 shared/test_context_store.py

No root, no vault. The properties that matter: the edited copy wins over the
shipped default and reset brings the default back; every save is recoverable;
a run without a system prompt is refused; folders the store creates are not
readable by anyone else; and the builder keeps every layer below the ones
above it, in a fixed order.
"""
import json
import os
import stat
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import context_store as cs  # noqa: E402
import agent_runtime as rt  # noqa: E402

PASS = FAIL = 0


def check(label, got, want):
    global PASS, FAIL
    if got == want:
        PASS += 1; print(f"  [ OK ] {label}")
    else:
        FAIL += 1; print(f"  [FAIL] {label}\n         got  {got!r}\n         want {want!r}")


def raises(fn):
    try:
        fn(); return None
    except cs.StoreError as e:
        return str(e)


root = Path(tempfile.mkdtemp())
(root / "org").mkdir()
master = root / "shared" / "agents" / "enum" / "context"
master.mkdir(parents=True)
(master / "system-prompt.md").write_text("## Objective\nship default\n")

print("\n=== default vs edited ===")
d = cs.show(root, "system-prompt", agent="enum")
check("shipped default is what applies at first", (d["source"], d["text"]), ("default", "## Objective\nship default\n"))
r = cs.set_text(root, "system-prompt", "edited v1\n", by="alice", agent="enum")
check("an edit wins", (r["source"], r["text"], r["unchanged"]), ("edited", "edited v1\n", False))
check("saving the same text again is a no-op", cs.set_text(root, "system-prompt", "edited v1\n", by="alice", agent="enum")["unchanged"], True)
cs.set_text(root, "system-prompt", "edited v2\n", by="bob", agent="enum")
h = cs.history(root, "system-prompt", agent="enum")["history"]
check("history lists every save, newest first", [x["by"] for x in h], ["bob", "alice"])
check("...and the previous edit was archived", bool(h[0]["replaced"]), True)
check("an old version can be read back", cs.version_text(root, "system-prompt", h[0]["replaced"], agent="enum"), "edited v1\n")
cs.revert(root, "system-prompt", h[0]["replaced"], by="carol", agent="enum")
check("revert makes it current again", cs.show(root, "system-prompt", agent="enum")["text"], "edited v1\n")
cs.reset(root, "system-prompt", by="carol", agent="enum")
check("reset goes back to the shipped default", cs.show(root, "system-prompt", agent="enum")["source"], "default")

print("\n=== validation ===")
check("an empty system prompt is refused", "required" in (raises(lambda: cs.set_text(root, "system-prompt", "  \n", by="x", agent="enum")) or ""), True)
check("over the size limit is refused", "limit" in (raises(lambda: cs.set_text(root, "skills", "x" * (cs.MAX_BYTES + 1), by="x", agent="enum")) or ""), True)
check("a NUL byte is refused", raises(lambda: cs.set_text(root, "skills", "a\x00b", by="x", agent="enum")) is not None, True)
check("a path-like agent name is refused", raises(lambda: cs.show(root, "skills", agent="../etc")) is not None, True)
check("a path-like user name is refused", raises(lambda: cs.show(root, "memory", agent="enum", user="../../x")) is not None, True)
check("a bad version id is refused", raises(lambda: cs.version_text(root, "skills", "../x", agent="enum")) is not None, True)

print("\n=== storage is private ===")
cs.set_text(root, "memory", "tables please\n", by="op1", agent="enum", user="op1")
for p in (root / "org" / "context", root / "org" / "context" / "memory", root / "org" / "context" / "memory" / "enum"):
    check(f"{p.relative_to(root)} is 0700", stat.S_IMODE(p.stat().st_mode), 0o700)
f = root / "org" / "context" / "memory" / "enum" / "op1.md"
check("the file itself is 0600", stat.S_IMODE(f.stat().st_mode), 0o600)

print("\n=== the per-run snapshot ===")
cs.set_text(root, "org", "Acme policy: no scans after 18:00.\n", by="t")
cs.set_text(root, "platform-skills", "Prefer targeted greps.\n", by="g")
slot = root / "org" / "enum" / "instances" / "op1"
slot.mkdir(parents=True)
r = cs.snapshot(root, agent="enum", owner="op1", dest=slot, group=None)
check("files snapshotted: system prompt, org policy, platform skills, this user's memory",
      sorted(r["files"]), ["memory", "org", "platform-skills", "system-prompt"])
check("an unset file is simply absent", (slot / "run-context" / "skills.md").exists(), False)
check("the snapshot is not writable by others (0640)", stat.S_IMODE((slot / "run-context" / "org.md").stat().st_mode), 0o640)
r2 = cs.snapshot(root, agent="enum", owner="op2", dest=slot, group=None)
check("another user's memory is never included", "memory" in r2["files"], False)
check("...and a stale memory file from an earlier snapshot is removed", (slot / "run-context" / "memory.md").exists(), False)
(master / "system-prompt.md").unlink()
check("no system prompt anywhere -> the run is refused",
      "no system prompt" in (raises(lambda: cs.snapshot(root, agent="enum", owner="op1", dest=slot, group=None)) or ""), True)
(master / "system-prompt.md").write_text("## Objective\nship default\n")
cs.snapshot(root, agent="enum", owner="op1", dest=slot, group=None)

print("\n=== the prompt builder ===")
ctx = rt.load_run_context(slot)
text = rt.compose_instructions(ctx)
order = [text.index(t) for t in ("AGENT INSTRUCTIONS", "ORGANISATION POLICY", "SKILLS (all agents)", "OPERATOR PREFERENCES")]
check("layers appear highest priority first", order == sorted(order), True)
check("operator preferences are framed as unable to widen anything", "can widen your scope" in text, True)
check("the report names each file's version", any("system-prompt.md" in l and "sha256" in l for l in rt.context_versions_markdown(ctx)), True)
empty = root / "org" / "enum" / "instances" / "nobody"; empty.mkdir()
try:
    rt.load_run_context(empty); got = "loaded"
except rt.RunContextError:
    got = "refused"
check("a run folder with no snapshot is refused", got, "refused")

print("\n=== the hash a grant is bound to ===")
import iam  # noqa: E402
sample = "line one\nline two\n"
check("iam's grant hash equals the hash the store records",
      iam.context_text_sha256(sample), cs._sha(cs.validate_text(sample)))
check("CRLF and LF text hash the same (the API normalises, the store normalises)",
      iam.context_text_sha256("a\r\nb\n"), iam.context_text_sha256("a\nb\n"))
cs.set_text(root, "skills", "x\n", by="u", agent="enum")
cs.append_text(root, "skills", "y", by="u", agent="enum")
check("append adds after the existing text", cs.show(root, "skills", agent="enum")["text"], "x\n\ny\n")


print("\n=== memory suggestions from the agent ===")
import time as _t
sl = root / "org" / "enum" / "instances" / "op9"; (sl / "state").mkdir(parents=True)
(sl / "state" / "memory-proposals.jsonl").write_text(
    json.dumps({"ts": _t.time(), "text": "Likes tables."}) + "\n"
    + "not json\n"
    + json.dumps({"ts": _t.time(), "text": "   "}) + "\n"
    + json.dumps({"ts": "x", "text": "bad ts"}) + "\n"
    + json.dumps({"ts": _t.time(), "text": "y" * 900}) + "\n")
r = cs.list_proposals(root, agent="enum", user="op9")
check("valid suggestions listed, junk skipped", len(r["proposals"]), 2)
check("an over-long suggestion is cut to the limit", max(len(p["text"]) for p in r["proposals"]), cs.MAX_PROPOSAL_CHARS)
pid = r["proposals"][0]["id"]
check("nothing is in the preferences before approval", cs.show(root, "memory", agent="enum", user="op9")["source"], "none")
cs.decide_proposal(root, agent="enum", user="op9", pid=pid, decision="approve", by="op9")
check("approving appends it to the preferences", "Likes tables." in cs.show(root, "memory", agent="enum", user="op9")["text"], True)
check("...and it is no longer pending", pid in [p["id"] for p in cs.list_proposals(root, agent="enum", user="op9")["proposals"]], False)
check("deciding twice is refused", raises(lambda: cs.decide_proposal(root, agent="enum", user="op9", pid=pid, decision="approve", by="op9")) is not None, True)
pid2 = cs.list_proposals(root, agent="enum", user="op9")["proposals"][0]["id"]
before = cs.show(root, "memory", agent="enum", user="op9")["text"]
cs.decide_proposal(root, agent="enum", user="op9", pid=pid2, decision="dismiss", by="op9")
check("dismissing changes nothing in the preferences", cs.show(root, "memory", agent="enum", user="op9")["text"], before)
check("a made-up id is refused", raises(lambda: cs.decide_proposal(root, agent="enum", user="op9", pid="0" * 12, decision="approve", by="op9")) is not None, True)
check("another user never sees these", cs.list_proposals(root, agent="enum", user="op1")["proposals"], [])

# audit run 2: a FIFO planted as the proposals file must be skipped at once, not hang root
import os as _os, threading as _th
fs = root / "org" / "enum" / "instances" / "op6"; (fs / "state").mkdir(parents=True)
_os.mkfifo(fs / "state" / "memory-proposals.jsonl")
_done = []
_w = _th.Thread(target=lambda: _done.append(cs.list_proposals(root, agent="enum", user="op6")), daemon=True)
_w.start(); _w.join(5)
check("a FIFO in place of the proposals file is skipped promptly, not waited on",
      (_w.is_alive(), _done[0]["proposals"] if _done else None), (False, []))

# the file is written by the agent, so root must not follow what it points at
secret = root / "secret.txt"; secret.write_text(json.dumps({"ts": _t.time(), "text": "STOLEN"}) + "\n")
sl2 = root / "org" / "enum" / "instances" / "op8"; (sl2 / "state").mkdir(parents=True)
(sl2 / "state" / "memory-proposals.jsonl").symlink_to(secret)
check("a proposals file that is a symlink is ignored, not followed",
      cs.list_proposals(root, agent="enum", user="op8")["proposals"], [])
sl3 = root / "org" / "enum" / "instances" / "op7"; sl3.mkdir()
other = root / "elsewhere"; (other).mkdir(); (other / "memory-proposals.jsonl").write_text(json.dumps({"ts": _t.time(), "text": "STOLEN2"}) + "\n")
(sl3 / "state").symlink_to(other)
check("a state/ folder that is a symlink is ignored too",
      cs.list_proposals(root, agent="enum", user="op7")["proposals"], [])

print(f"\n{'=' * 52}\n  {PASS} passed, {FAIL} failed\n{'=' * 52}")
import shutil; shutil.rmtree(root, ignore_errors=True)
sys.exit(1 if FAIL else 0)
