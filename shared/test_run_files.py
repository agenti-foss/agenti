"""test_run_files.py — files an operator attaches to a run.

    python3 shared/test_run_files.py

No framework, no root, no vault, no real SDK. Exits non-zero on failure.

WHAT MATTERS HERE: a file must reach exactly the run it was meant for (the
run going now, or the next one), never an unrelated later run; a failed
start must not swallow files; nothing outside the slot can be reached by a
file name; limits refuse before anything is half-written; and the agent can
read a large text file a piece at a time but not open a binary one.
"""
import asyncio
import io
import json
import os
import subprocess
import sys
import tempfile
import time
import types
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

_fake = types.ModuleType("claude_agent_sdk")
_fake.tool = lambda name, desc, schema: (lambda fn: types.SimpleNamespace(name=name, handler=fn))
sys.modules["claude_agent_sdk"] = _fake

import agent_runtime as ar  # noqa: E402
import retention  # noqa: E402
import run_files as rf  # noqa: E402

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


def refused(fn, *a, **kw):
    try:
        fn(*a, **kw)
    except rf.FilesError as e:
        return str(e)
    return None


def put(slot, data: bytes, name, mode="pending", by="alice"):
    return rf.attach(io.BytesIO(data), [("enum", mode, Path(slot))], name=name, by=by)


tmp = Path(tempfile.mkdtemp(prefix="run-files-test-"))
slot = tmp / "enum" / "instances" / "alice"
slot.mkdir(parents=True)

section("names")
check("a path is cut to its last part", rf.safe_name("../../etc/passwd"), "passwd")
check("a Windows path too", rf.safe_name("C:\\Users\\me\\cap 1.pcap"), "cap_1.pcap")
check("odd characters become _", rf.safe_name("ré sumé (2).txt"), "r_sum_2_.txt")
check("a leading dot is dropped (no hidden files)", rf.safe_name(".bashrc"), "bashrc")
long = rf.safe_name("a" * 150 + ".pcapng")
check("a long name keeps its extension, 100 chars max", (len(long), long.endswith(".pcapng")), (100, True))
check("nothing usable is refused", bool(refused(rf.safe_name, "../..")), True)

section("attaching before a run: it waits, then goes with the next start")
r = put(slot, b"line one\nline two\nsecret=abc\n", "notes.txt")
check("stored under its own name", r["name"], "notes.txt")
check("it waits for the next run", (r["live"], [e["name"] for e in rf.pending_files(slot)]), (False, ["notes.txt"]))
check("its SHA-256 is recorded", r["sha256"], __import__("hashlib").sha256(b"line one\nline two\nsecret=abc\n").hexdigest())
r2 = put(slot, b"other", "notes.txt")
check("a second file of the same name never replaces the first", r2["name"], "notes-2.txt")
check("no run has files yet", rf.run_files(slot), [])
b = rf.begin_run(slot)
check("start: the waiting files become this run's", sorted(b["files"]), ["notes-2.txt", "notes.txt"])
check("...and nothing waits any more", rf.pending_files(slot), [])
check("the marker names this run's folder", (slot / "run-files").read_text().strip(), b["run_dir"])
check("the agent sees them", sorted(e["name"] for e in rf.run_files(slot)), ["notes-2.txt", "notes.txt"])

section("a later start with nothing attached shows NO files")
time.sleep(1.1)  # a new run folder name is time-stamped to the second
b2 = rf.begin_run(slot)
check("no run folder", b2["run_dir"], None)
check("the new run is not shown the old run's files", rf.run_files(slot), [])
check("the old run's files stay on disk until the sweep", (rf.files_root(slot) / b["run_dir"] / "notes.txt").exists(), True)

section("attaching to a run going now")
put(slot, b"hello", "late.log", mode="run")
check("a run with no files gets a folder on the spot", [e["name"] for e in rf.run_files(slot)], ["late.log"])
msg = rf.agent_message(["late.log"])
check("the agent is told in fixed wording", ("late.log" in msg, "read_file" in msg), (True, True))

section("a start that fails gives its files back")
put(slot, b"pcap bytes\x00\x01", "cap.pcap")
b3 = rf.begin_run(slot)
check("they went to the run", b3["files"], ["cap.pcap"])
back = rf.unbegin(slot)
check("unbegin: they wait again", ([e["name"] for e in rf.pending_files(slot)], back["returned"]), (["cap.pcap"], ["cap.pcap"]))
check("...and no run claims them", rf.run_files(slot), [])

section("a resume picks up files attached while it was stopped")
rf.begin_run(slot)                         # a run with cap.pcap
put(slot, b"more context", "extra.txt")
a = rf.adopt_pending(slot)
check("they join the resumed run", a["moved"], ["extra.txt"])
check("the run now has both", sorted(e["name"] for e in rf.run_files(slot)), ["cap.pcap", "extra.txt"])
check("nothing to adopt is a no-op", rf.adopt_pending(slot)["moved"], [])

section("taking back a waiting file")
put(slot, b"oops", "wrong.csv")
check("removed", rf.remove_pending([slot], "wrong.csv")["removed"], 1)
check("an unknown one is refused", bool(refused(rf.remove_pending, [slot], "nope.txt")), True)
check("a path is refused", bool(refused(rf.remove_pending, [slot], "../run-files")), True)
check("a run's own files are not removable this way", bool(refused(rf.remove_pending, [slot], "extra.txt")), True)

section("limits refuse before anything is written")
old_max = rf.MAX_FILE_BYTES
rf.MAX_FILE_BYTES = 10
check("too big", "limit" in (refused(put, slot, b"x" * 11, "big.bin") or ""), True)
rf.MAX_FILE_BYTES = old_max
check("no half-written file is left", [p.name for p in rf.pending_dir(slot).iterdir() if p.name.startswith(".incoming")], [])
check("empty is refused", "empty" in (refused(put, slot, b"", "e.txt") or ""), True)
old_run = rf.MAX_RUN_BYTES
rf.MAX_RUN_BYTES = 20
put(slot, b"x" * 15, "first.bin")
check("a run's total is capped", "per run" in (refused(put, slot, b"x" * 10, "second.bin") or ""), True)
rf.MAX_RUN_BYTES = old_run
rf.remove_pending([slot], "first.bin")

section("a team: one file, every member, stored once")
s2 = tmp / "research" / "instances" / "alice.team-p"
s1 = tmp / "enum" / "instances" / "alice.team-p"
s1.mkdir(parents=True), s2.mkdir(parents=True)
t = rf.attach(io.BytesIO(b"shared notes"), [("enum", "run", s1), ("research", "pending", s2)],
              name="brief.md", by="alice")
check("placed for both members", [(p["member"], p["mode"]) for p in t["placed"]],
      [("enum", "run"), ("research", "pending")])
f1 = rf.run_dir(s1) / "brief.md"
f2 = rf.pending_dir(s2) / "brief.md"
check("one copy on disk (hard links)", (f1.stat().st_ino == f2.stat().st_ino, f1.stat().st_nlink), (True, 2))
check("the team wording says so", "for the team" in t["agent_message"], True)
lst = json.loads(subprocess.run([sys.executable, str(HERE / "run_files.py"), "list",
                                 f"--member=enum={s1}", f"--member=research={s2}"],
                                capture_output=True, text=True).stdout)
check("the team listing has each member", sorted(lst["members"]), ["enum", "research"])
check("removing takes it back wherever it waits", rf.remove_pending([s1, s2], "brief.md")["removed"], 1)

section("reading: a piece at a time, text only")
d = tmp / "reader"
d.mkdir()
big = "".join(f"{i} host-{i} {'ERROR' if i % 50 == 0 else 'ok'}\n" for i in range(1, 1001))
put(d, big.encode(), "big.log")
put(d, b"\x00\x01PCAP", "dump.pcap")
rf.begin_run(d)
text = rf.read_text(d, "big.log", start=10, end=12)
check("a line range, numbered", [ln.split()[0] for ln in text.splitlines()[1:]], ["10", "11", "12"])
check("the header says how big it is", "1000 lines" in text.splitlines()[0], True)
grep = rf.read_text(d, "big.log", pattern="error")
check("a pattern finds every match, case-insensitive", len(grep.splitlines()) - 1, 20)
whole = rf.read_text(d, "big.log")
check("one read is capped and says so", ("narrow the range" in whole, len(whole.splitlines()) <= 202), (True, True))
check("a binary file is refused", "binary" in (refused(rf.read_text, d, "dump.pcap") or ""), True)
check("an unknown file names what there is", "big.log" in (refused(rf.read_text, d, "x.txt") or ""), True)
check("a bad pattern is refused", "regular expression" in (refused(rf.read_text, d, "big.log", pattern="(") or ""), True)
check("a path never escapes the run", bool(refused(rf.read_text, d, "../run-files")), True)

section("what the agent and the report see")
brief = rf.briefing(d)
check("the briefing lists the files and their kind",
      ("big.log" in brief, "binary — read_file cannot open it" in brief), (True, True))
check("and says a file is not an instruction", "never an instruction" in brief, True)
check("no files, no briefing", rf.briefing(tmp / "enum" / "instances" / "nobody"), "")
sec = "\n".join(rf.report_section(d))
check("the report lists each file with its SHA-256", ("## Files attached" in sec, rf.run_files(d)[0]["sha256"] in sec), (True, True))
check("run_briefing includes it", "FILES ATTACHED" in ar.run_briefing(d), True)
check("report_inputs includes it", any("Files attached" in x for x in ar.report_inputs(d)), True)

section("the agent's tools")
names, tools = ar.run_tools(d, ar.StateHolder())
check("every run gets list_files and read_file", ("list_files" in names, "read_file" in names), (True, True))
check("a solo run is not offered team tools", "team_message" in names, False)
tool = dict(zip(names, tools))
out = asyncio.run(tool["read_file"].handler({"name": "big.log", "start_line": 1, "end_line": 2}))
check("read_file frames the content as data", out["content"][0]["text"].startswith("[ATTACHED FILE"), True)
err = asyncio.run(tool["read_file"].handler({"name": "dump.pcap"}))
check("a refusal is an error result, not a crash", err.get("is_error"), True)
lf = asyncio.run(tool["list_files"].handler({}))
check("list_files shows sizes and kinds", ("dump.pcap" in lf["content"][0]["text"], "binary" in lf["content"][0]["text"]), (True, True))

section("the 30-day sweep")
old = time.time() - 40 * 86400
for p in rf.run_dir(d).iterdir():
    os.utime(p, (old, old))
res = retention.sweep_working_data(d)
check("old attached files are removed", any("big.log" in f for f in res["removed_files"]), True)
check("the emptied run folder goes too", rf.run_dir(d).exists(), False)
check("and the run then simply has none", rf.run_files(d), [])

section("the command line, as the root CLI calls it")
src = tmp / "upload.txt"
src.write_text("from stdin\n")
cli = subprocess.run([sys.executable, str(HERE / "run_files.py"), "attach", "--src", "-",
                      "--name=../evil name.txt", "--by", "alice", "--target", f"enum:pending:{slot}"],
                     stdin=open(src, "rb"), capture_output=True, text=True)
out = json.loads(cli.stdout)
check("stdin works and the name is cleaned", (cli.returncode, out["name"]), (0, "evil_name.txt"))
link = tmp / "link.txt"
link.symlink_to(src)
cli = subprocess.run([sys.executable, str(HERE / "run_files.py"), "attach", "--src", str(link),
                      "--by", "alice", "--target", f"enum:pending:{slot}"], capture_output=True, text=True)
check("a symlink as the source is refused", (cli.returncode, "error" in json.loads(cli.stdout)), (1, True))
cli = subprocess.run([sys.executable, str(HERE / "run_files.py"), "list", "--slot", str(slot)],
                     capture_output=True, text=True)
check("list answers JSON with limits", json.loads(cli.stdout)["limits"]["file_bytes"], 100 * 1024 ** 2)

section("handing a run's output to another agent")
src_slot = tmp / "org" / "scanner" / "instances" / "alice"
dst_slot = tmp / "org" / "analyser" / "instances" / "alice"
for d_ in (src_slot, dst_slot):
    for sub in ("reports", "analysis", "scans", "state"):
        (d_ / sub).mkdir(parents=True, exist_ok=True)
(src_slot / "reports" / "scan-1.md").write_text("# Report\nfound hash 31d6cfe0d16ae931b73c59d7e0c089c0\n")
(src_slot / "analysis" / "tshark_1.txt").write_text("frame 9968\n")
(src_slot / "scans" / "nmap_1.txt").write_text("22/tcp open\n")
(src_slot / "run-config.json").write_text(json.dumps(
    {"model": "haiku", "max_turns": 12, "max_budget_usd": 0.5, "timeout_s": 300, "linger_s": 5, "secret": "x"}))
(src_slot / "run-target").write_text("10.0.0.0/24\n")
rf.attach(io.BytesIO(b"\x00" * 40), [("scanner", "pending", src_slot)], name="cap.pcap", by="alice")
rf.begin_run(src_slot)

src = rf.sources(src_slot)
check("sources lists the report, both kinds of saved output and the attached file",
      ([e["name"] for e in src["reports"]], sorted(e["name"] for e in src["outputs"]), [e["name"] for e in src["files"]]),
      (["scan-1.md"], ["nmap_1.txt", "tshark_1.txt"], ["cap.pcap"]))
check("...with the folder each output came from", sorted((e["name"], e["folder"]) for e in src["outputs"]),
      [("nmap_1.txt", "scans"), ("tshark_1.txt", "analysis")])
check("it reports the model and caps the run used, and nothing else from run-config.json",
      src["config"], {"model": "haiku", "max_turns": 12, "max_budget_usd": 0.5, "timeout_s": 300})
# Found live 2026-10-08: sending enum's output to exploit always said "needs
# a target" even though enum's own target was sitting in run-target the
# whole time — nothing ever read it to hand it along. "Send output" (the
# GUI's Open Launch path) reads this to prefill the destination's target.
check("it reports the SOURCE run's own target, trimmed", src["target"], "10.0.0.0/24")
check("a run with no target file (file-analysis agent) reports an empty target, not an error",
      rf.sources(dst_slot)["target"], "")
check("a run with nothing yet has empty lists, not an error",
      rf.sources(tmp / "nowhere")["reports"], [])

res = rf.send(src_slot, ["report:scan-1.md", "output:tshark_1.txt", "file:cap.pcap"],
              [("analyser", "pending", dst_slot)], by="alice (sent from scanner)")
check("all three arrive in the receiving run's waiting files",
      sorted(e["name"] for e in rf.pending_files(dst_slot)), ["cap.pcap", "scan-1.md", "tshark_1.txt"])
check("...with the content intact", (rf.pending_dir(dst_slot) / "scan-1.md").read_text().startswith("# Report"), True)
check("...recording who sent it and from where",
      {e["by"] for e in rf.pending_files(dst_slot)}, {"alice (sent from scanner)"})
check("...and the SHA-256 of what was sent", rf.pending_files(dst_slot)[0]["sha256"] is not None, True)
check("the sender's own run is untouched", sorted(e["name"] for e in rf.run_files(src_slot)), ["cap.pcap"])
check("the result says what was sent and gives the receiver's notice",
      (len(res["sent"]), res["failed"], "attached" in res["agent_message"]), (3, [], True))
res = rf.send(src_slot, ["report:scan-1.md"], [("analyser", "pending", dst_slot)], by="alice (sent from scanner)")
check("sending the same name again keeps both, numbering the second (never overwrites)",
      sorted(e["name"] for e in rf.pending_files(dst_slot) if e["name"].startswith("scan-1")),
      ["scan-1-2.md", "scan-1.md"])

# one that cannot be sent does not stop the rest
res = rf.send(src_slot, ["output:nmap_1.txt", "output:missing.txt"], [("analyser", "pending", dst_slot)], by="alice")
check("a missing item is reported while the others still go",
      ([x["name"] for x in res["sent"]], [f["item"] for f in res["failed"]]), (["nmap_1.txt"], ["output:missing.txt"]))
check("nothing sendable is an error that names the item",
      "missing.txt" in (refused(rf.send, src_slot, ["output:missing.txt"], [("analyser", "pending", dst_slot)], by="a") or ""), True)
check("no items is an error", refused(rf.send, src_slot, [], [("analyser", "pending", dst_slot)], by="a") is not None, True)
for bad in ("report:../state/x", "report:/etc/passwd", "output:a/b", "nonsense:x", "report:", "report", "file:.hidden"):
    check(f"a malformed item {bad!r} is refused",
          refused(rf.send, src_slot, [bad], [("analyser", "pending", dst_slot)], by="a") is not None, True)
check("an attached file that is not part of this run cannot be named",
      refused(rf.send, src_slot, ["file:other.pcap"], [("analyser", "pending", dst_slot)], by="a") is not None, True)

# the sending AGENT writes reports/, analysis/ and scans/: links in there must not be followed
(src_slot / "reports" / "link.md").symlink_to("/etc/hostname")
check("a symlink in the report folder is not listed", "link.md" in [e["name"] for e in rf.sources(src_slot)["reports"]], False)
check("...and cannot be sent",
      refused(rf.send, src_slot, ["report:link.md"], [("analyser", "pending", dst_slot)], by="a") is not None, True)
elsewhere = tmp / "elsewhere"
elsewhere.mkdir()
(elsewhere / "secret.txt").write_text("not yours\n")
os.rename(src_slot / "analysis", src_slot / "analysis.real")
(src_slot / "analysis").symlink_to(elsewhere)
check("a saved-output FOLDER swapped for a symlink is not followed either",
      (rf.sources(src_slot)["outputs"] and any(e["name"] == "secret.txt" for e in rf.sources(src_slot)["outputs"])), False)
check("...and its contents cannot be sent",
      refused(rf.send, src_slot, ["output:secret.txt"], [("analyser", "pending", dst_slot)], by="a") is not None, True)
os.unlink(src_slot / "analysis")
os.rename(src_slot / "analysis.real", src_slot / "analysis")

# a run going now: the file joins it
live = tmp / "org" / "analyser" / "instances" / "bob"
(live / "reports").mkdir(parents=True)
rf.attach(io.BytesIO(b"x"), [("analyser", "pending", live)], name="seed.txt", by="bob")
rf.begin_run(live)
res = rf.send(src_slot, ["report:scan-1.md"], [("analyser", "run", live)], by="bob (sent from scanner)")
check("sent to a run going now, it joins that run and says so",
      (res["live"], "scan-1.md" in {e["name"] for e in rf.run_files(live)}), (True, True))

# the command line, as the CLI calls it
cli = subprocess.run([sys.executable, str(HERE / "run_files.py"), "sources", "--slot", str(src_slot)],
                     capture_output=True, text=True)
check("sources answers JSON", (cli.returncode, "reports" in json.loads(cli.stdout)), (0, True))
carol = tmp / "org" / "analyser" / "instances" / "carol"
carol.mkdir(parents=True)
cli = subprocess.run([sys.executable, str(HERE / "run_files.py"), "send", "--slot", str(src_slot),
                      "--item", "output:tshark_1.txt", "--by", "carol (sent from scanner)",
                      "--target", f"analyser:pending:{carol}"],
                     capture_output=True, text=True)
check("send works from the command line", (cli.returncode, json.loads(cli.stdout)["sent"][0]["name"]), (0, "tshark_1.txt"))
cli = subprocess.run([sys.executable, str(HERE / "run_files.py"), "send", "--slot", str(src_slot),
                      "--item", "report:nope.md", "--by", "carol", "--target", f"analyser:pending:{dst_slot}"],
                     capture_output=True, text=True)
check("...and a refusal is JSON with an error and a non-zero exit", (cli.returncode, "error" in json.loads(cli.stdout)), (1, True))

section("every start is its own run: waiting files move to the fresh slot")
# `attach` with no --copy stages into the owner's plain slot; the next
# unlabelled start creates a NEW slot and takes those files with it.
stage = tmp / "org" / "analyser" / "instances" / "dave"
fresh = tmp / "org" / "analyser" / "instances" / "dave.run-1a2b3c4d"
for d_ in (stage, fresh):
    (d_ / "reports").mkdir(parents=True)
rf.attach(io.BytesIO(b"hash1\n"), [("analyser", "pending", stage)], name="h1.txt", by="dave")
rf.attach(io.BytesIO(b"hash2\n"), [("analyser", "pending", stage)], name="h2.txt", by="dave")
res = rf.transfer_pending(stage, fresh)
check("both waiting files move", sorted(res["moved"]), ["h1.txt", "h2.txt"])
check("...they are waiting in the new slot",
      sorted(e["name"] for e in rf.pending_files(fresh)), ["h1.txt", "h2.txt"])
check("...and gone from the staging slot", rf.pending_files(stage), [])
check("...with their content intact", (rf.pending_dir(fresh) / "h1.txt").read_bytes(), b"hash1\n")
check("nothing waiting is a harmless no-op", rf.transfer_pending(stage, fresh)["moved"], [])
cli = subprocess.run([sys.executable, str(HERE / "run_files.py"), "transfer-pending",
                      "--from", str(stage), "--to", str(fresh)], capture_output=True, text=True)
check("transfer-pending works from the command line", (cli.returncode, json.loads(cli.stdout)["moved"]), (0, []))


section("F16: root reads what a run wrote without following a link")
import outputs as _outputs  # noqa: E402
_slot = Path(tempfile.mkdtemp()) / "alice.run-0001"
(_slot / "reports").mkdir(parents=True)
(_slot / "scans" / "sub").mkdir(parents=True)
(_slot / "state").mkdir()
_secret = _slot.parent / "shadow"
_secret.write_text("root:SECRET\n")
(_slot / "reports" / "real.md").write_text("# r\n**Status:** done\n")
(_slot / "reports" / "evil.md").symlink_to(_secret)
os.link(_secret, _slot / "reports" / "hard.md")
(_slot / "state" / "findings.jsonl").symlink_to(_secret)
(_slot / "scans" / "out.txt").write_text("scan\n")
(_slot / "scans" / "linked").symlink_to(_slot.parent)
(_slot.parent / "out.txt").write_text("outside\n")


def _refused(rel):
    try:
        fh, _ = rf.open_in_slot(_slot, rel)
        fh.close()
        return False
    except rf.FilesError:
        return True


check("a plain report opens", _refused("reports/real.md"), False)
check("a symlinked report is refused", _refused("reports/evil.md"), True)
check("a hard link to another file is refused", _refused("reports/hard.md"), True)
check("a symlinked findings file is refused", _refused("state/findings.jsonl"), True)
check("a path through a linked folder is refused", _refused("scans/linked/out.txt"), True)
check("'..' is refused", _refused("../shadow"), True)
check("the listing shows only the plain report",
      [r["name"] for r in rf.list_regular(_slot, "reports", ".md")], ["real.md"])
check("find never enters a linked folder",
      rf.find_regular(_slot, "scans", "out.txt"), ["scans/out.txt"])
_dest = _slot.parent / "kept"
try:
    _outputs.promote_output(_slot / "reports", "evil.md", _dest, approve=lambda n: None)
    _kept = "copied"
except _outputs.OutputsError:
    _kept = "refused"
check("keeping a symlinked report is refused", _kept, "refused")
check("...and nothing was copied", list(_dest.glob("*")) if _dest.exists() else [], [])
_got, _n = _outputs.promote_output(_slot / "reports", "real.md", _dest, approve=lambda n: None)
check("keeping the plain report works", (_got.read_text().startswith("# r"), _n == _got.stat().st_size), (True, True))
# audit run 2: the quota sees the size of what is copied, and a file that grows mid-copy is not kept
_seen = []
def _deny(n):
    _seen.append(n)
    raise _outputs.OutputsError("over quota")
try:
    _outputs.promote_output(_slot / "reports", "real.md", _dest, approve=_deny)
    check("a refused quota keeps nothing", "kept", "refused")
except _outputs.OutputsError:
    check("a refused quota keeps nothing", (_seen == [(_slot / "reports" / "real.md").stat().st_size],
          len(list(_dest.glob("*")))), (True, 1))
(_slot / "reports" / "grow.md").write_text("# small\n")
def _grow(n):
    with open(_slot / "reports" / "grow.md", "a") as g:
        g.write("x" * 100000)
try:
    _outputs.promote_output(_slot / "reports", "grow.md", _dest, approve=_grow)
    check("a report that grows after the quota check is not kept", "kept", "refused")
except _outputs.OutputsError as e:
    check("a report that grows after the quota check is not kept", ("grew" in str(e), len(list(_dest.glob("grow*")))), (True, 0))
_cli = subprocess.run([sys.executable, str(Path(rf.__file__)), "cat", "--slot", str(_slot),
                       "--path", "reports/evil.md"], capture_output=True, text=True)
check("`run_files.py cat` refuses the link and prints none of it",
      (_cli.returncode != 0, "SECRET" in _cli.stdout), (True, False))

print(f"\n{'=' * 52}\n  {PASS} passed, {FAIL} failed\n{'=' * 52}")
sys.exit(1 if FAIL else 0)
