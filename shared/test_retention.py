#!/usr/bin/env python3
"""test_retention.py — the 30-day working-data sweep (shared/retention.py,
CLAUDE.md decision 7 of the generic-launcher arc).

    python3 shared/test_retention.py

No dependencies, no root. Builds a real fake agent directory (scans/,
pages/, evidence/, reports/, state/history.jsonl) in a temp dir, backdates
some files' mtimes for real with os.utime, and proves the sweep only
removes what it should by checking the actual filesystem afterward — not by
reading the sweep's own report of what it did.
"""
import json
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import retention  # noqa: E402

PASS = FAIL = 0


def check(label, got, want):
    global PASS, FAIL
    if got == want:
        PASS += 1; print(f"  [ OK ] {label}")
    else:
        FAIL += 1; print(f"  [FAIL] {label}\n         got  {got!r}\n         want {want!r}")


def section(t): print(f"\n=== {t} ===")


def age(path: Path, days: float, now: float) -> None:
    t = now - days * 86400
    os.utime(path, (t, t))


tmp = Path(tempfile.mkdtemp(prefix="agenti-test-retention-"))
try:
    now = time.time()
    agent_dir = tmp / "enum"
    for d in ("scans", "evidence", "reports", "state"):
        (agent_dir / d).mkdir(parents=True)

    old_scan = agent_dir / "scans" / "old-scan.txt"; old_scan.write_text("old")
    age(old_scan, 40, now)
    new_scan = agent_dir / "scans" / "new-scan.txt"; new_scan.write_text("new")
    age(new_scan, 5, now)
    old_evidence = agent_dir / "evidence" / "old.pcap"; old_evidence.write_bytes(b"x" * 500)
    age(old_evidence, 31, now)
    boundary_scan = agent_dir / "scans" / "exactly-30.txt"; boundary_scan.write_text("boundary")
    age(boundary_scan, 30, now)

    old_report = agent_dir / "reports" / "old-report.md"; old_report.write_text("# Old Report")
    age(old_report, 90, now)

    section("sweep_working_data — real file removal by mtime, reports untouched")
    r = retention.sweep_working_data(agent_dir, now=now, retention_days=30)
    check("the genuinely old scan file is actually gone from disk",
          old_scan.exists(), False)
    check("the recent scan file survives", new_scan.exists(), True)
    check("an old evidence file is swept too",
          old_evidence.exists(), False)
    check("a file exactly AT the cutoff (mtime == cutoff) is KEPT, not removed "
          "(the comparison is `>= cutoff` survives, strictly older is removed)",
          boundary_scan.exists(), True)
    check("reports/ is never touched, no matter how old",
          old_report.exists(), True)
    check("the summary reports the right bytes freed",
          r["bytes_freed"], len(b"old") + 500)
    check("the summary lists the removed files by agent-relative path",
          sorted(r["removed_files"]),
          sorted(["scans/old-scan.txt", "evidence/old.pcap"]))

    section("sweep_working_data — dry_run changes nothing on disk")
    agent_dir2 = tmp / "research"
    (agent_dir2 / "pages").mkdir(parents=True)
    stale = agent_dir2 / "pages" / "stale.html"; stale.write_text("<html></html>")
    age(stale, 60, now)
    r2 = retention.sweep_working_data(agent_dir2, now=now, retention_days=30, dry_run=True)
    check("dry_run reports the file it WOULD remove", r2["removed_files"], ["pages/stale.html"])
    check("...but the file is still actually there", stale.exists(), True)
    check("a real (non-dry-run) sweep afterward actually removes it",
          retention.sweep_working_data(agent_dir2, now=now, retention_days=30)["removed_files"],
          ["pages/stale.html"])
    check("...and now it's really gone", stale.exists(), False)

    section("sweep_history — pruned by the exact `ended` timestamp, atomically")
    state_dir = agent_dir / "state"
    lines = [
        {"run_id": "old1", "ended": now - 40 * 86400, "status": "completed"},
        {"run_id": "recent1", "ended": now - 5 * 86400, "status": "completed"},
        {"run_id": "old2", "ended": now - 31 * 86400, "status": "failed"},
        {"run_id": "boundary", "ended": now - 30 * 86400, "status": "completed"},
    ]
    (state_dir / "history.jsonl").write_text("\n".join(json.dumps(e) for e in lines) + "\n")
    r3 = retention.sweep_history(state_dir, now=now, retention_days=30)
    check("two old entries pruned", r3["pruned"], 2)
    check("two entries kept (recent + boundary)", r3["kept"], 2)
    remaining_ids = [json.loads(l)["run_id"]
                    for l in (state_dir / "history.jsonl").read_text().splitlines() if l.strip()]
    check("the SPECIFIC entries kept are the right ones",
          sorted(remaining_ids), sorted(["recent1", "boundary"]))
    check("...and the pruned ones are really gone",
          set(remaining_ids).isdisjoint({"old1", "old2"}), True)

    section("sweep_history — dry_run, missing file, malformed lines, empty result")
    state_dir2 = tmp / "state2"; state_dir2.mkdir()
    check("no history.jsonl at all: a clean no-op, not an error",
          retention.sweep_history(state_dir2, now=now, retention_days=30),
          {"kept": 0, "pruned": 0, "dry_run": False})

    state_dir3 = tmp / "state3"; state_dir3.mkdir()
    (state_dir3 / "history.jsonl").write_text(
        json.dumps({"run_id": "x", "ended": now - 40 * 86400}) + "\n"
        "{not valid json at all\n"
        + json.dumps({"run_id": "y", "ended": now - 1 * 86400}) + "\n")
    r4 = retention.sweep_history(state_dir3, now=now, retention_days=30, dry_run=True)
    check("dry_run reports what would be pruned", r4["pruned"], 1)
    check("a malformed line is KEPT (never silently discarded by this sweep)",
          "not valid json" in (state_dir3 / "history.jsonl").read_text(), True)
    check("dry_run really changed nothing on disk",
          len((state_dir3 / "history.jsonl").read_text().splitlines()), 3)
    r5 = retention.sweep_history(state_dir3, now=now, retention_days=30)
    check("the real sweep prunes the old entry but keeps the malformed line and the recent one",
          r5["pruned"], 1)
    remaining = (state_dir3 / "history.jsonl").read_text().splitlines()
    check("malformed line survived the real sweep too", any("not valid json" in l for l in remaining), True)
    check("the recent entry survived", any('"y"' in l for l in remaining), True)
    check("the old entry did not", all('"x"' not in l for l in remaining), True)

    state_dir4 = tmp / "state4"; state_dir4.mkdir()
    (state_dir4 / "history.jsonl").write_text(
        json.dumps({"run_id": "allold", "ended": now - 99 * 86400}) + "\n")
    retention.sweep_history(state_dir4, now=now, retention_days=30)
    check("pruning EVERY line leaves an empty (not missing, not malformed) file",
          (state_dir4 / "history.jsonl").read_text(), "")

    section("sweep_agent — both sweeps together, real end to end")
    agent_dir3 = tmp / "trafficmon"
    (agent_dir3 / "evidence").mkdir(parents=True)
    (agent_dir3 / "state").mkdir(parents=True)
    old_ev = agent_dir3 / "evidence" / "old.pcap"; old_ev.write_bytes(b"y" * 10)
    age(old_ev, 45, now)
    (agent_dir3 / "state" / "history.jsonl").write_text(
        json.dumps({"run_id": "c1", "ended": now - 50 * 86400}) + "\n")
    result = retention.sweep_agent(agent_dir3, now=now, retention_days=30)
    check("working data swept", old_ev.exists(), False)
    check("history swept", result["history"]["run"]["pruned"], 1)

    section("F21: a folder swapped for a link mid-sweep cannot redirect a delete outside the slot")
    import os as _os
    import tempfile as _tf
    _base = Path(_tf.mkdtemp())
    _slot = _base / "slot"; (_slot / "scans" / "sub").mkdir(parents=True)
    _outside = _base / "outside"; _outside.mkdir()
    (_outside / "victim.conf").write_text("must survive")
    _decoy = _slot / "scans" / "sub" / "victim.conf"; _decoy.write_text("old")
    _os.utime(_decoy, (time.time() - 40 * 86400,) * 2)
    _real_stat = _os.stat
    _swapped = {"done": False}


    def _swap_after_check(*a, **k):
        r = _real_stat(*a, **k)
        if a and a[0] == "victim.conf" and not _swapped["done"]:
            _swapped["done"] = True
            _os.rename(_slot / "scans" / "sub", _slot / "scans" / "sub.moved")
            _os.symlink(_outside, _slot / "scans" / "sub")
        return r


    retention.os.stat = _swap_after_check
    try:
        retention.sweep_working_data(_slot)
    finally:
        retention.os.stat = _real_stat
    check("the swap happened during the sweep", _swapped["done"], True)
    check("the file outside the slot survives", (_outside / "victim.conf").exists(), True)
    check("only the run's own old file was deleted", (_slot / "scans" / "sub.moved" / "victim.conf").exists(), False)
    _link = _slot / "scans" / "link-out"; _os.symlink(_outside, _link)
    retention.sweep_working_data(_slot, now=time.time() + 400 * 86400)
    check("a link already in place is never walked", (_outside / "victim.conf").exists(), True)


    section("F37: malformed history rows are kept and never stop the sweep; links are never followed")
    _t = Path(tempfile.mkdtemp(prefix="ret-f37-"))
    (_t / "state").mkdir()
    _now = time.time()
    (_t / "state" / "history.jsonl").write_text("\n".join([
        json.dumps({"ended": _now - 90 * 86400}),       # old: pruned
        json.dumps(["a", "list"]),                       # not an object: kept
        json.dumps({"ended": "yesterday"}),              # not a number: kept
        json.dumps({"ended": _now}),                     # recent: kept
    ]) + "\n")
    _r = retention.sweep_history(_t / "state", now=_now)
    check("one old row pruned, the odd rows and the recent one kept", (_r["pruned"], _r["kept"]), (1, 3))
    _victim = _t / "victim.txt"; _victim.write_text("untouched\n")
    (_t / "state" / "history.jsonl.tmp").symlink_to(_victim)
    (_t / "state" / "history.jsonl").write_text(json.dumps({"ended": _now - 90 * 86400}) + "\n" + json.dumps({"ended": _now}) + "\n")
    retention.sweep_history(_t / "state", now=_now)
    check("a link planted at the temporary name is replaced, not written through", _victim.read_text(), "untouched\n")
    _hf = _t / "state" / "history.jsonl"
    _hf.write_text(json.dumps({"ended": _now - 90 * 86400}) + "\n" + json.dumps({"ended": _now}) + "\n")
    _hf.chmod(0o664)
    retention.sweep_history(_t / "state", now=_now)
    check("the rewritten history keeps its mode (the run still appends to it)", oct(_hf.stat().st_mode & 0o777), "0o664")
    (_t / "state" / "history.jsonl").unlink()
    (_t / "state" / "history.jsonl").symlink_to(_victim)
    check("a history file that is a link is not read or rewritten",
          (retention.sweep_history(_t / "state", now=_now)["kept"], _victim.read_text()), (0, "untouched\n"))

    print(f"\n{PASS} passed, {FAIL} failed")
    sys.exit(1 if FAIL else 0)
finally:
    shutil.rmtree(tmp, ignore_errors=True)
