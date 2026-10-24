#!/usr/bin/env python3
"""tool_approvals.py — an agent asks to use a catalog program it does not have,
and its operator says yes or no for THIS RUN (CLAUDE.md "Current plan" phase 7).
Root-side, stdlib.

THE FLOW
  1. The agent calls request_tool(program, reason). That writes one line to
     <slot>/state/tool-requests.jsonl — the only place it can write — and
     pauses the run until the operator answers, like ask_operator does.
  2. The operator sees the request on the agent page and decides. The API
     calls the root CLI, which calls decide() here.
  3. decide() — only for a program the admin listed as `approvable` for this
     agent, still in the catalog, and not already allowed — writes the grant
     <slot>/run-tool-grants.json (root-owned, read-only to the run) and logs
     the decision in <slot>/run-tool-decisions.json. Then the CLI delivers a
     plain message into the run's inbox, which is what wakes the agent.

WHAT A GRANT IS, AND IS NOT
  It lasts for this run only: `agenti start` deletes it, exactly as it clears
  every other per-run setting (CLAUDE.md §1 invariant 7). A resume keeps it.
  It adds ONE program from the reviewed catalog; scope, the denied patterns
  and that program's own argument rules all still apply to every command. It
  cannot name anything the admin did not offer, and the run re-checks the
  grant against the admin's current settings on every command, so withdrawing
  the offer takes effect at once.

The request file is written by the agent, so it is untrusted input: it is read
here as root without following links, size-capped, and every field re-checked.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import time
from pathlib import Path

import context_store as cs
import tool_catalog as tc

REQUESTS_FILE = "tool-requests.jsonl"
GRANTS_FILE = "run-tool-grants.json"
DECISIONS_FILE = "run-tool-decisions.json"
MAX_REASON = 300
MAX_READ = 50


class RequestError(Exception):
    pass


def _gid(group: str | None):
    if not group:
        return None
    import grp
    try:
        return grp.getgrnam(group).gr_gid
    except KeyError:
        raise RequestError(f"unknown group {group!r}")


def _write_root_owned(path: Path, text: str, gid) -> None:
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        tmp.write_text(text, encoding="utf-8")
        os.chmod(tmp, 0o640)
        if os.geteuid() == 0 and gid is not None:
            os.chown(tmp, 0, gid)
        os.replace(tmp, path)
    except OSError as e:
        tmp.unlink(missing_ok=True)
        raise RequestError(f"cannot write {path}: {e}")


def _read_json(path: Path) -> dict:
    try:
        v = json.loads(path.read_text(encoding="utf-8"))
        return v if isinstance(v, dict) else {}
    except (OSError, ValueError):
        return {}


def _context(shared_dir: Path, org_dir: Path, agent: str):
    """(catalog, settings, effective baseline) for this agent."""
    import tool_settings_store as tss
    base, _p = tss.baseline(shared_dir, agent)
    catalog = tss.catalog_for(shared_dir)
    raw = tss.read_settings(tss.settings_path(org_dir, agent))
    try:
        settings = tc.validate_settings(raw, catalog, base)
    except tc.CatalogError:
        settings = {"enable": [], "disable": [], "approvable": []}
    return catalog, settings, tc.effective_binaries(base, settings, catalog)


def _decisions(slot: Path) -> dict:
    return _read_json(slot / DECISIONS_FILE)


def pending(slot: Path, *, shared_dir: Path, org_dir: Path, agent: str) -> list[dict]:
    """Requests this run's agent made that nobody has decided yet and that are
    still decidable (the program is still offered). Newest last. An agent with
    no shell allow-list (research, trafficmon) can never ask, so it has none."""
    import tool_settings_store as tss
    try:
        catalog, settings, effective = _context(shared_dir, org_dir, agent)
    except tss.StoreError:
        return []
    offered = tc.approvable_programs(settings, catalog, effective)
    decided = _decisions(slot)
    raw = cs._safe_read_bytes(slot, f"state/{REQUESTS_FILE}")
    out = []
    if not raw:
        return out
    for line in raw.decode("utf-8", errors="replace").splitlines()[-MAX_READ:]:
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if not isinstance(row, dict):
            continue
        prog, reason, ts = row.get("program"), row.get("reason"), row.get("ts")
        if not (isinstance(prog, str) and tc.NAME_RE.match(prog) and isinstance(ts, (int, float))):
            continue
        reason = " ".join(str(reason or "").split())[:MAX_REASON]
        rid = hashlib.sha256(f"{slot.name}|{ts}|{prog}|{reason}".encode()).hexdigest()[:12]
        if rid in decided:
            continue
        entry = tc.catalog_entry(catalog, prog)
        out.append({"id": rid, "program": prog, "reason": reason, "ts": ts,
                    "purpose": (entry or {}).get("purpose", ""),
                    "offered": prog in offered})
    out.sort(key=lambda r: r["ts"])
    return out


def decide(slot: Path, *, shared_dir: Path, org_dir: Path, agent: str, rid: str,
           decision: str, by: str, group: str | None) -> dict:
    if decision not in ("approve", "deny"):
        raise RequestError("decision must be approve or deny")
    if not re.fullmatch(r"[0-9a-f]{12}", rid or ""):
        raise RequestError("not a request id")
    req = {r["id"]: r for r in pending(slot, shared_dir=shared_dir, org_dir=org_dir, agent=agent)}
    if rid not in req:
        raise RequestError("that request is no longer pending (already decided, or from a run that was removed)")
    r = req[rid]
    gid = _gid(group)
    if decision == "approve":
        if not r["offered"]:
            raise RequestError(
                f"{r['program']} is not something operators may approve for this agent right now "
                f"(an admin has not offered it, or already enabled it). Ask an admin.")
        grants = _read_json(slot / GRANTS_FILE)
        progs = sorted(set(grants.get("programs", [])) | {r["program"]})
        _write_root_owned(slot / GRANTS_FILE,
                          json.dumps({"programs": progs, "updated_at": time.time(), "updated_by": by}, indent=1) + "\n", gid)
    decided = _decisions(slot)
    decided[rid] = {"decision": decision, "program": r["program"], "by": by, "ts": time.time()}
    _write_root_owned(slot / DECISIONS_FILE, json.dumps(decided, indent=1) + "\n", gid)
    return {"ok": True, "id": rid, "decision": decision, "program": r["program"]}


def clear(slot: Path) -> None:
    """A fresh start begins with no grants and no decisions."""
    for name in (GRANTS_FILE, DECISIONS_FILE):
        (slot / name).unlink(missing_ok=True)


def _main(argv) -> int:
    import argparse
    ap = argparse.ArgumentParser(allow_abbrev=False, prog="tool_approvals.py")
    ap.add_argument("--shared-dir", required=True)
    ap.add_argument("--org-dir", required=True)
    ap.add_argument("--agent", required=True)
    ap.add_argument("--slot-dir", required=True)
    ap.add_argument("--group", default=None)
    sub = ap.add_subparsers(dest="verb", required=True)
    sub.add_parser("pending", allow_abbrev=False)
    d = sub.add_parser("decide", allow_abbrev=False)
    d.add_argument("id"); d.add_argument("decision", choices=("approve", "deny")); d.add_argument("--by", required=True)
    sub.add_parser("clear", allow_abbrev=False)
    a = ap.parse_args(argv)
    slot = Path(a.slot_dir)
    try:
        if a.verb == "pending":
            out = {"ok": True, "requests": pending(slot, shared_dir=Path(a.shared_dir),
                                                   org_dir=Path(a.org_dir), agent=a.agent)}
        elif a.verb == "decide":
            out = decide(slot, shared_dir=Path(a.shared_dir), org_dir=Path(a.org_dir),
                         agent=a.agent, rid=a.id, decision=a.decision, by=a.by, group=a.group)
        else:
            clear(slot); out = {"ok": True}
    except Exception as e:   # RequestError, CatalogError, StoreError: one JSON error shape for the CLI wrapper
        print(json.dumps({"ok": False, "error": str(e)}))
        return 2
    print(json.dumps(out, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
