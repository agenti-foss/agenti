"""
retention.py — the 30-day working-data sweep.

CLAUDE.md "Current plan", decision 7 of the generic-launcher arc: "task
history and run working data auto-delete after 30 days ... regardless of
agent." One rule, deliberately simple — the operator explicitly rejected a
more elaborate "30 days or 50 runs" version of this in favor of just the
date.

WHAT COUNTS AS "WORKING DATA", AND WHAT DOES NOT
--------------------------------------------------
The raw scan/page/evidence output an agent's tools save to disk while a run
is happening (enum's scans/, research's pages/, trafficmon's evidence/),
and the files an operator attached to a run (files/), age out by file
MODIFICATION TIME, independent of which run produced it.
These directories are FLAT and shared
across every run of an agent, not one-per-run, so "age out the individual
files by mtime" is the correct unit here, not "delete run N's directory."

Task HISTORY (state/history.jsonl, shared/state.py) ages out by its own
`ended` timestamp, which is exact — no mtime guessing needed.

`reports/` is NEVER touched by this module. CLAUDE.md's own plan calls a
report an OUTPUT, kept indefinitely under a completely different rule
(decision 8) — the same thing a client engagement report already was before
this phase existed. Promoting a report into the permanent Outputs store
(shared/outputs.py's promote_output, gated by shared/iam.py's
outputs_check) is how an operator opts a specific file into that indefinite
lifecycle; nothing here does it automatically, and nothing here can delete
anything already promoted, since a promoted copy lives in a completely
different directory tree.

`findings.jsonl`/`state.json` only ever describe the CURRENT run and are
truncated/overwritten by StateStore.start() on every new run — they never
accumulate historical data that needs sweeping, so this module does not
touch them either.

DELIBERATELY OUT OF SCOPE, STATED PLAINLY: `.claude/`, the SDK's own session
transcripts. Their file format is explicitly internal/unstable (see
state.py's own module docstring: "don't parse it directly"), and this
module does not touch it either, for the same reason plus one more: a wrong
guess at its internal layout risks corrupting a still-resumable session,
which is a worse outcome than working data staying on disk a while past
its nominal 30 days. Left for a future pass once that structure has been
verified directly against a real deployment, not assumed from outside.
"""

from __future__ import annotations

import json
import os
import stat
import time
from pathlib import Path
from typing import Any

import state as state_mod

__all__ = ["DEFAULT_RETENTION_DAYS", "WORKING_DATA_SUBDIRS",
          "sweep_working_data", "sweep_history", "sweep_agent"]

DEFAULT_RETENTION_DAYS = 30

# Sub-directories, relative to an agent's own directory, that hold run
# working data for at least one of the real agent shapes today. A directory
# that does not exist for a given agent is simply skipped — this list is a
# deliberate superset, not agent-specific knowledge duplicated here.
WORKING_DATA_SUBDIRS = (
    "scans",
    "pages",
    "evidence",
    "analysis",    # saved output of a file-analysis agent's programs
    "files",       # files an operator attached to a run (run_files.py)
)


def _atomic_write(path: Path, text: str) -> None:
    """Root replacing a file in a folder the run's account can write: the
    temporary file is created fresh (O_EXCL|O_NOFOLLOW), so a link planted at
    its name is removed, never written through (audit run 1, F21 family)."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    try:
        os.unlink(tmp)            # removes a planted link itself, not its target
    except FileNotFoundError:
        pass
    # The replacement keeps the original's owner and mode: the run appends to
    # this file, and a root-owned copy would stop it doing so.
    try:
        old = os.stat(path, follow_symlinks=False)
        owner, mode = (old.st_uid, old.st_gid), stat.S_IMODE(old.st_mode)
    except OSError:
        owner, mode = None, 0o600
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(text)
        if owner and os.geteuid() == 0:
            os.fchown(fh.fileno(), *owner)
        os.fchmod(fh.fileno(), mode)
    os.replace(tmp, path)


def _read_plain(path: Path) -> str | None:
    """The text of a plain file the run wrote, never following a link (None
    for a link or anything that is not a regular file)."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return None
    with os.fdopen(fd, "rb") as fh:
        if not stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
            return None
        return fh.read().decode("utf-8", errors="replace")


def sweep_working_data(agent_dir: Path, *, now: float | None = None,
                       retention_days: int = DEFAULT_RETENTION_DAYS,
                       dry_run: bool = False) -> dict[str, Any]:
    """Delete files older than `retention_days` (by mtime) inside every
    working-data subdirectory that exists under `agent_dir`. Never touches
    `reports/` or `.claude/` — see the module docstring. With dry_run=True
    nothing is actually deleted, but the summary reports exactly what would
    have been."""
    now = time.time() if now is None else now
    cutoff = now - retention_days * 86400
    removed: list[str] = []
    bytes_freed = 0
    # Every folder below the slot is written by the run's account, which could
    # swap one for a link between this sweep's age check and its delete. So
    # the walk goes by directory descriptor, never enters a link, and deletes
    # by name relative to the descriptor it just checked (audit run 1, F21).
    try:
        slot_fd = os.open(agent_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError:
        slot_fd = None
    for rel in WORKING_DATA_SUBDIRS if slot_fd is not None else ():
        try:
            walk = os.fwalk(rel, dir_fd=slot_fd, follow_symlinks=False)
            for root, _dirs, files, rfd in walk:
                for name in files:
                    try:
                        st = os.stat(name, dir_fd=rfd, follow_symlinks=False)
                    except OSError:
                        continue
                    if not stat.S_ISREG(st.st_mode) or st.st_mtime >= cutoff:
                        continue
                    removed.append(str(Path(root) / name))
                    bytes_freed += st.st_size
                    if not dry_run:
                        try:
                            os.unlink(name, dir_fd=rfd)
                        except OSError:
                            pass
        except OSError:
            continue
    if slot_fd is not None:
        os.close(slot_fd)
    if not dry_run:
        _drop_empty_file_dirs(agent_dir / "files")
    return {"removed_files": removed, "bytes_freed": bytes_freed, "dry_run": dry_run}


def _drop_empty_file_dirs(root: Path) -> None:
    """A run's files folder whose files have all aged out goes too (its index
    on its own describes nothing). The pending folder is kept."""
    if not root.is_dir():
        return
    for d in root.iterdir():
        if d.name == "pending" or not d.is_dir():
            continue
        if any(p.is_file() and not p.name.startswith(".") for p in d.iterdir()):
            continue
        for p in d.iterdir():
            p.unlink(missing_ok=True)
        try:
            d.rmdir()
        except OSError:
            pass


def sweep_history(state_dir: Path, *, now: float | None = None,
                  retention_days: int = DEFAULT_RETENTION_DAYS,
                  dry_run: bool = False) -> dict[str, Any]:
    """Prune history.jsonl entries whose `ended` timestamp is older than the
    retention window. Rewrites the file atomically — a crash mid-sweep
    leaves it exactly as it was before this call, never half-written, the
    same write-then-rename state.py itself uses. A line with no `ended`
    field at all (should not happen, but a corrupt or pre-history-field
    line must not become unremovable forever) is treated as ELIGIBLE for
    removal rather than kept indefinitely; a line that fails to PARSE at
    all is kept — this sweep must never be the reason a not-yet-understood
    but possibly valid record disappears."""
    now = time.time() if now is None else now
    cutoff = now - retention_days * 86400
    path = state_dir / state_mod.HISTORY_FILENAME
    text = _read_plain(path)
    if text is None:
        return {"kept": 0, "pruned": 0, "dry_run": dry_run}
    lines = text.splitlines()
    kept_lines: list[str] = []
    pruned = 0
    for line in lines:
        line = line.strip()
        if not line:
            continue
        # A row that is not a JSON object with a numeric "ended" is kept as it
        # is and never stops the sweep (audit run 1, F37: one such row raised
        # and every slot after it went unswept).
        try:
            e = json.loads(line)
            if not isinstance(e, dict):
                raise ValueError("not an object")
            ended = e.get("ended")
            ended = None if ended is None else float(ended)
        except (json.JSONDecodeError, TypeError, ValueError):
            kept_lines.append(line)
            continue
        if ended is not None and ended >= cutoff:
            kept_lines.append(line)
        else:
            pruned += 1
    if not dry_run and pruned:
        _atomic_write(path, ("\n".join(kept_lines) + "\n") if kept_lines else "")
    return {"kept": len(kept_lines), "pruned": pruned, "dry_run": dry_run}


def sweep_agent(agent_dir: Path, *, now: float | None = None,
                retention_days: int = DEFAULT_RETENTION_DAYS,
                dry_run: bool = False) -> dict[str, Any]:
    """Run both sweeps for one agent directory. Used to walk both a --dev
    and a commercial state/ directory separately (CLAUDE.md "Current
    plan"); there is one profile now, so one state/ directory."""
    result: dict[str, Any] = {
        "working_data": sweep_working_data(agent_dir, now=now,
                                           retention_days=retention_days, dry_run=dry_run),
        "history": {},
    }
    sdir = agent_dir / "state"
    if sdir.is_dir():
        result["history"]["run"] = sweep_history(
            sdir, now=now, retention_days=retention_days, dry_run=dry_run)
    return result
