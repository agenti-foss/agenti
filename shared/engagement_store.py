#!/usr/bin/env python3
"""
engagement_store.py — the root-side reader/writer for a organisation's engagement
record (CLAUDE.md "Current plan", phase 1 of the cybersecurity refocus).

Invoked by `shared/agenti` (as root) for `agenti engagement
show|set|approve|history`, and — through the same verbs — by the API and
the GUI. It owns exactly two files in the organisation's directory, plus an
append-only history:

    org/engagement.json           the record (engagement_context.py's
                                       schema) — root:<service group> 0640,
                                       written atomically (tmp + rename)
    org/approval.json             an admin's approval OF THAT CONTENT:
                                       engagement_id + the record's digest +
                                       who/when. Editing the record makes
                                       it stale by construction — see
                                       engagement_context.approval_status()
    org/engagement-history.jsonl  one line per set/approve: who, when,
                                       what changed

Everything the record MEANS lives in engagement_context.py (validation,
the per-kind view, the digest); this file only handles argv, merging an
edit into the existing record, and putting files on disk with the right
ownership. Standard library only, runs under the system python3 from the
code folder — like vault.sh and iam.py it has to work while the vault is
locked.

Merge semantics for `set`, chosen so the GUI's full form and a one-flag
CLI edit both do the obvious thing:
  * metadata flags (--client, --valid-until, ...) that are NOT given keep
    their current value; on first creation the core ones are required.
  * a scope kind's lists are replaced only where flags for it are given
    (--cidr-in replaces the CIDR in_scope, leaves its out_of_scope alone);
    --replace-scope <kind> makes the given flags the WHOLE truth for that
    kind, empty if none were given (what the GUI sends), and --clear-scope
    <kind> is the same with nothing.
  * nothing is written when the result equals what is already stored, so
    re-saving an unchanged form never churns updated_at or the history.
  * operational policy (--require-approval, the three ceiling flags,
    --allowed-models) merges per FIELD, like the metadata flags — giving
    one never touches the others — except --allowed-models itself, which
    always replaces the whole list (a curated pick, never an incremental
    add). Deliberately excluded from the approval digest: see
    engagement_context.record_digest()'s own docstring.

Output is one JSON object on stdout (or --format text for a human), exit
0 on success and 2 on a refused input — every failure is reported as data,
never a traceback, matching every other JSON-emitting verb in the project.
"""
from __future__ import annotations

import argparse
import grp
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import engagement_context as ec  # noqa: E402

__all__ = ["main", "StoreError"]

_META_FLAGS = {
    "engagement_id": "--engagement-id", "client": "--client",
    "authorizing_party": "--authorizing-party", "authorizing_title": "--authorizing-title",
    "authorization_ref": "--authorization-ref", "valid_from": "--valid-from",
    "valid_until": "--valid-until", "emergency_contact": "--emergency-contact",
    "notes": "--notes",
}
_CREATE_REQUIRED = ("engagement_id", "client", "authorizing_party", "authorizing_title",
                    "authorization_ref", "valid_from", "valid_until")


class StoreError(Exception):
    pass


class _JsonAwareArgumentParser(argparse.ArgumentParser):
    """A parse error is raised by argparse before any of this file's own
    handling runs, so it would otherwise print usage to stderr and exit 2
    with NOTHING on stdout — breaking the one-stream contract every caller
    relies on (the same fix iam.py and new_agent.py already carry)."""

    def error(self, message):
        print(json.dumps({"ok": False, "error": f"invalid arguments: {message}"}))
        sys.exit(2)


# ---------------------------------------------------------------------------
# files
# ---------------------------------------------------------------------------
def _gid(group: str | None) -> int | None:
    if not group:
        return None
    try:
        return grp.getgrnam(group).gr_gid
    except KeyError:
        raise StoreError(f"unknown group {group!r} — is the service account provisioned?")


def _own(path: Path, gid: int | None) -> None:
    """root:<service group> 0640: the service account (the
    agent process, preflight) can READ it, nothing but root can write it —
    the same shape as run-target and inbox.jsonl. Skipped when not running
    as root (the unit tests), where the file simply stays the caller's."""
    os.chmod(path, 0o640)
    if os.geteuid() == 0 and gid is not None:
        os.chown(path, 0, gid)


def _atomic_write(path: Path, text: str, gid: int | None) -> None:
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        tmp.write_text(text, encoding="utf-8")
        _own(tmp, gid)
        os.replace(tmp, path)
    except OSError as e:
        tmp.unlink(missing_ok=True)
        raise StoreError(f"cannot write {path}: {e}")


def _append_history(path: Path, row: dict, gid: int | None) -> None:
    try:
        existed = path.exists()
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
        if not existed:
            _own(path, gid)
    except OSError as e:
        raise StoreError(f"cannot append to {path}: {e}")


def _read_history(path: Path, n: int | None) -> list[dict]:
    rows: list[dict] = []
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue      # one corrupt line must not hide the rest
    except OSError:
        return []
    return rows[-n:] if n else rows


# ---------------------------------------------------------------------------
# the verbs
# ---------------------------------------------------------------------------
def _paths(args) -> tuple[Path, Path, Path, Path, Path]:
    org_dir = Path(args.org_dir)
    if not org_dir.is_dir():
        raise StoreError(f"organisation directory {org_dir} does not exist (vault unlocked? provisioned?)")
    shared_dir = Path(args.shared_dir) if args.shared_dir else org_dir.parent / "shared"
    return (org_dir, shared_dir,
            org_dir / ec.ORG_ENGAGEMENT_FILENAME,
            org_dir / ec.APPROVAL_FILENAME,
            org_dir / ec.ENGAGEMENT_HISTORY_FILENAME)


def _load_existing(rec_path: Path) -> tuple[dict | None, str | None]:
    """(record, None) when a valid record exists, (None, None) when there is
    none, and (None, why) when a file exists but is unreadable or invalid.
    An invalid file must not be a dead end: `set` treats it as absent (so
    the same command that creates a record repairs it, and the history says
    so), `show` reports the fault, and `approve` refuses until it is fixed."""
    if not rec_path.exists():
        return None, None
    try:
        return ec.read_record(rec_path), None
    except ec.EngagementError as e:
        return None, str(e)


def cmd_show(args) -> dict:
    org_dir, shared_dir, rec_path, appr_path, hist_path = _paths(args)
    out: dict = {"ok": True, "path": str(rec_path),
                 "exists": rec_path.exists(), "record": None, "digest": None,
                 "approval": None, "view": None}
    record, invalid = _load_existing(rec_path)
    if record is not None:
        out["record"] = record
        out["digest"] = ec.record_digest(record)
    if invalid:
        out["invalid"] = (f"{invalid} — re-set it with every core field "
                          f"(sudo agenti engagement set --engagement-id ... ) "
                          f"to replace it")
    approval = ec.read_approval(appr_path)
    out["approval"] = None if (approval is None or approval.get("_invalid")) else approval
    out["approval_status"] = ec.approval_status(record, approval)
    out["history"] = _read_history(hist_path, args.n)
    if args.scope_kind and record is not None:
        eng = ec.engagement_from_record(record, args.scope_kind)
        out["view"] = {"scope_kind": args.scope_kind, "in_scope": eng.in_scope,
                       "out_of_scope": eng.out_of_scope, "usable": bool(eng.in_scope)}
        if args.agent:
            # What THIS agent would actually be held to: the organisation scope
            # narrowed by the agent's own scope (never wider).
            av = _agent_scope_view(org_dir, rec_path, args.agent, args.scope_kind)
            out["view"].update({"in_scope": av["effective_in_scope"], "usable": bool(av["effective_in_scope"]),
                                "narrowed": av["narrowed"], "agent_in_scope": av["agent_in_scope"],
                                "org_in_scope": av["org_in_scope"], "error": av["effective_error"]})
    elif args.scope_kind:
        out["view"] = {"scope_kind": args.scope_kind, "in_scope": [], "out_of_scope": [],
                       "usable": False}
    # The EFFECTIVE policy (organisation override narrowing the platform default),
    # always present even for a brand-new install with no record at all —
    # what the launch page/CLI error messages read to say "here's what's
    # actually allowed", never the raw (possibly-empty) record.get("policy").
    out["effective_policy"] = ec.resolve_policy(record)
    return out


def _merge_scope(existing: dict, args) -> dict:
    scope = {k: {"in_scope": list(v["in_scope"]), "out_of_scope": list(v["out_of_scope"])}
             for k, v in existing.items()}
    given = {"cidr": (args.cidr_in, args.cidr_out), "domain": (args.domain_in, args.domain_out)}
    replace = set(args.replace_scope or []) | set(args.clear_scope or [])
    for kind, (ins, outs) in given.items():
        if kind in replace:
            scope[kind] = {"in_scope": list(ins or []), "out_of_scope": list(outs or [])}
            continue
        if ins:
            scope[kind]["in_scope"] = list(ins)
        if outs:
            scope[kind]["out_of_scope"] = list(outs)
    return scope


def _merge_policy(existing: dict, args) -> dict:
    """Each field is independent and untouched unless a flag for it was
    given — the metadata-flag shape, not the scope kinds' replace-by-kind
    one, since there's no natural "kind" to key a full-replace off here.
    Each ceiling has its own --clear-* flag (mirroring --clear-allowed-
    models) since "leave it blank" already means "don't touch it" — there
    has to be a separate way to say "revert this to the platform default"
    once a ceiling has actually been set."""
    policy = dict(existing)
    if args.require_approval is not None:
        policy["require_approval"] = args.require_approval
    if args.clear_max_turns_ceiling:
        policy.pop("max_turns_ceiling", None)
    elif args.max_turns_ceiling is not None:
        policy["max_turns_ceiling"] = args.max_turns_ceiling
    if args.clear_max_budget_ceiling:
        policy.pop("max_budget_usd_ceiling", None)
    elif args.max_budget_usd_ceiling is not None:
        policy["max_budget_usd_ceiling"] = args.max_budget_usd_ceiling
    if args.clear_timeout_ceiling:
        policy.pop("timeout_s_ceiling", None)
    elif args.timeout_s_ceiling is not None:
        policy["timeout_s_ceiling"] = args.timeout_s_ceiling
    if args.clear_allowed_models:
        policy.pop("allowed_models", None)
    elif args.allowed_models:
        policy["allowed_models"] = list(args.allowed_models)
    return policy


def cmd_set(args) -> dict:
    org_dir, shared_dir, rec_path, appr_path, hist_path = _paths(args)
    gid = _gid(args.group)
    existing, invalid = _load_existing(rec_path)
    created = existing is None
    if (args.via == "api" and args.require_approval is False
            and ((existing or {}).get("policy") or {}).get("require_approval", True)):
        # The approval requirement sits outside the digest, so switching it
        # off from the web would let one admin skip approval altogether and
        # defeat require-separate-approver (audit run 1, F10). Turning it ON
        # from the web is fine; OFF is a console decision, like every policy.
        raise StoreError(
            "turning off engagement approval is a console-only decision: it lets runs start "
            "without anyone approving the scope. At the server, as root:\n"
            "  sudo agenti engagement set --no-require-approval")

    base: dict = dict(existing) if existing else {
        "emergency_contact": "", "notes": "", "capture_payloads": False,
        "enabled_capabilities": [],
        "retention_days": 0, "redact": [], "scope": ec.empty_scope(), "policy": {}}
    if created:
        missing = [_META_FLAGS[f] for f in _CREATE_REQUIRED if getattr(args, f) is None]
        if missing:
            why = (f"the organisation already has an engagement file that cannot be read "
                   f"({invalid}), so replacing it" if invalid else
                   f"the organisation has no engagement yet, so creating one")
            raise StoreError(f"{why} needs every core field: missing {', '.join(missing)}")
        # every kind must be explicit on create: an empty record is refused
        # by normalize_record anyway, this only makes the message specific
    new = dict(base)
    for field in _META_FLAGS:
        value = getattr(args, field)
        if value is not None:
            new[field] = value
    if args.capture_payloads is not None:
        new["capture_payloads"] = args.capture_payloads
    # --exploitation-enabled/--no-exploitation-enabled: legacy alias
    if getattr(args, "exploitation_enabled", None) is not None:
        caps = list(new.get("enabled_capabilities", []))
        if args.exploitation_enabled and "exploit" not in caps:
            caps.append("exploit")
        elif not args.exploitation_enabled and "exploit" in caps:
            caps.remove("exploit")
        new["enabled_capabilities"] = caps
    # --enable-capability/--disable-capability
    if getattr(args, "enable_capability", None):
        caps = list(new.get("enabled_capabilities", []))
        for c in args.enable_capability:
            if c not in caps:
                caps.append(c)
        new["enabled_capabilities"] = caps
    if getattr(args, "disable_capability", None):
        caps = list(new.get("enabled_capabilities", []))
        for c in args.disable_capability:
            if c in caps:
                caps.remove(c)
        new["enabled_capabilities"] = caps
    if args.retention_days is not None:
        new["retention_days"] = args.retention_days
    if args.clear_redact:
        new["redact"] = []
    elif args.redact:
        new["redact"] = list(args.redact)
    new["scope"] = _merge_scope(base["scope"], args)
    new["policy"] = _merge_policy(base.get("policy") or {}, args)
    for name in ec.AUDIT_FIELDS:
        new.pop(name, None)
    normalized = ec.normalize_record(new)          # EngagementError names the field

    changed: list[str] = []
    if existing is not None:
        old_auth = {k: v for k, v in existing.items() if k not in ec.AUDIT_FIELDS}
        for k in normalized:
            if k == "scope":
                for kind in ec.SCOPE_KINDS:
                    if old_auth["scope"][kind] != normalized["scope"][kind]:
                        changed.append(f"scope.{kind}")
            elif old_auth.get(k) != normalized[k]:
                changed.append(k)
    digest = ec.record_digest(normalized)
    if existing is not None and not changed:
        return {"ok": True, "path": str(rec_path),
                "engagement_id": normalized["engagement_id"], "digest": digest,
                "created": False, "changed": [], "unchanged": True,
                "approval_status": ec.approval_status(normalized, ec.read_approval(appr_path)),
                "effective_policy": ec.resolve_policy(normalized)}

    now = time.time()
    normalized["updated_at"] = now
    normalized["updated_by"] = args.by
    normalized["updated_via"] = args.via
    _atomic_write(rec_path, json.dumps(normalized, indent=2, ensure_ascii=False) + "\n", gid)
    row = {"ts": now, "by": args.by, "via": args.via, "action": "set",
           "engagement_id": normalized["engagement_id"], "digest": digest,
           "created": created, "changed": changed if not created else ["(created)"]}
    if invalid:
        row["replaced_invalid"] = invalid
    _append_history(hist_path, row, gid)
    out = {"ok": True, "path": str(rec_path),
           "engagement_id": normalized["engagement_id"], "digest": digest,
           "created": created, "changed": changed if not created else ["(created)"],
           "approval_status": ec.approval_status(normalized, ec.read_approval(appr_path)),
           "effective_policy": ec.resolve_policy(normalized)}
    if invalid:
        out["replaced_invalid"] = invalid
    return out



def _agent_scope_view(org_dir: Path, rec_path: Path, agent: str, kind: str) -> dict:
    """Organisation ceiling, the agent's own narrowing, and the overlap a run enforces."""
    record, invalid = _load_existing(rec_path)
    org_in = out_org = []
    if record is not None:
        eng = ec.engagement_from_record(record, kind)
        org_in, out_org = eng.in_scope, eng.out_of_scope
    path = ec.agent_scope_path(org_dir, agent)
    effective, error, own = list(org_in), None, None
    try:
        own = ec.read_agent_scope(path, kind)
        if record is not None:
            eng2 = ec.apply_agent_scope(eng, own, kind)
            effective = list(eng2.in_scope)
    except ec.EngagementError as e:
        effective, error = [], str(e)
    return {"agent": agent, "scope_kind": kind, "org_in_scope": org_in,
            "org_out_of_scope": out_org,
            "agent_in_scope": (own or {}).get("in_scope", []),
            "agent_out_of_scope": (own or {}).get("out_of_scope", []),
            "effective_in_scope": effective, "effective_error": error,
            "narrowed": bool(own and own["in_scope"])}


def cmd_agent_scope_show(args) -> dict:
    org_dir, _s, rec_path, _a, _h = _paths(args)
    out = {"ok": True, }
    out.update(_agent_scope_view(org_dir, rec_path, args.agent, args.scope_kind))
    return out


def cmd_agent_scope_set(args) -> dict:
    """Replace the agent's own scope (both lists; empty in_scope = inherit the
    organisation's). Refused if any in_scope entry is wider than the organisation's."""
    org_dir, _s, rec_path, _a, hist_path = _paths(args)
    gid = _gid(args.group)
    record, invalid = _load_existing(rec_path)
    if record is None:
        raise StoreError(f"the organisation has no usable engagement yet, so there is "
                         f"no scope to narrow. Set the engagement first.")
    agent_dir = org_dir / args.agent
    if not agent_dir.is_dir():
        raise StoreError(f"agent '{args.agent}' has no instance in the organisation yet "
                         f"(run: agenti {args.agent} provision)")
    new = ec.normalize_agent_scope({"in_scope": args.in_scope or [],
                                    "out_of_scope": args.out_of_scope or []}, args.scope_kind)
    eng = ec.engagement_from_record(record, args.scope_kind)
    ec.check_agent_scope_narrows(args.scope_kind, eng.in_scope, new["in_scope"])
    path = ec.agent_scope_path(org_dir, args.agent)
    old = ec.read_agent_scope(path, args.scope_kind) or {"in_scope": [], "out_of_scope": []}
    if old["in_scope"] == new["in_scope"] and old["out_of_scope"] == new["out_of_scope"]:
        out = {"ok": True, "unchanged": True}
        out.update(_agent_scope_view(org_dir, rec_path, args.agent, args.scope_kind))
        return out
    now = time.time()
    new.update({"updated_at": now, "updated_by": args.by, "updated_via": args.via})
    _atomic_write(path, json.dumps(new, indent=2, ensure_ascii=False) + "\n", gid)
    _append_history(hist_path, {"ts": now, "by": args.by, "via": args.via, "action": "agent-scope",
                                "agent": args.agent, "scope_kind": args.scope_kind,
                                "in_scope": new["in_scope"], "out_of_scope": new["out_of_scope"]}, gid)
    out = {"ok": True, "unchanged": False}
    out.update(_agent_scope_view(org_dir, rec_path, args.agent, args.scope_kind))
    return out


def cmd_approve(args) -> dict:
    org_dir, shared_dir, rec_path, appr_path, hist_path = _paths(args)
    gid = _gid(args.group)
    record, invalid = _load_existing(rec_path)
    if invalid:
        raise StoreError(
            f"the organisation's engagement file cannot be read ({invalid}) — nothing to "
            f"approve until it is re-set:\n"
            f"  sudo agenti engagement set --engagement-id <id> --client <name> ...")
    if record is None:
        raise StoreError(
            f"the organisation has no engagement to approve — set one first:\n"
            f"  sudo agenti engagement set --engagement-id <id> --client <name> ...")
    if args.engagement_id and args.engagement_id != record["engagement_id"]:
        raise StoreError(
            f"the engagement on record for '{org_dir.name}' is '{record['engagement_id']}', "
            f"not '{args.engagement_id}' — approve what is actually there:\n"
            f"  sudo agenti engagement approve")
    digest = ec.record_digest(record)
    if args.expect_digest and args.expect_digest != digest:
        # The approver reviewed one version; the record on disk is another
        # (edited in between). An approval must sign what was reviewed
        # (audit run 1, F25).
        raise StoreError(
            "the engagement changed after you opened it for review, so this approval was not "
            "recorded. Reload it, review the current version and approve again.")
    now = time.time()
    approval = {"engagement_id": record["engagement_id"], "digest": digest,
                "approved_by": args.by, "approved_at": now, "via": args.via}
    _atomic_write(appr_path, json.dumps(approval, indent=2) + "\n", gid)
    _append_history(hist_path, {"ts": now, "by": args.by, "via": args.via, "action": "approve",
                                "engagement_id": record["engagement_id"], "digest": digest}, gid)
    return {"ok": True, "path": str(appr_path),
            "approval": approval, "approval_status": ec.approval_status(record, approval)}


def cmd_history(args) -> dict:
    org_dir, _, _, _, hist_path = _paths(args)
    return {"ok": True, "history": _read_history(hist_path, args.n)}


def cmd_import(args) -> dict:
    """Replace the record wholesale from a JSON blob (a file, or stdin) —
    for a restore-from-backup, or a one-off migration script that has
    already built the record and just needs it written atomically with a
    history entry. Refuses to overwrite an existing record unless --force
    is given, so it can never be an accident.
    Goes through the SAME normalize_record()/atomic-write/history-append
    path as `set` — a migration must be held to the identical validation a
    hand-typed edit is, not a separate, looser one."""
    org_dir, shared_dir, rec_path, appr_path, hist_path = _paths(args)
    gid = _gid(args.group)
    existing, _invalid = _load_existing(rec_path)
    if existing is not None and not args.force:
        raise StoreError(
            f"the organisation already has an engagement (id "
            f"{existing['engagement_id']!r}) — import refuses to overwrite it "
            f"without --force")
    try:
        raw = Path(args.file).read_text(encoding="utf-8") if args.file else sys.stdin.read()
        data = json.loads(raw)
    except OSError as e:
        raise StoreError(f"could not read {args.file}: {e}")
    except json.JSONDecodeError as e:
        raise StoreError(f"the record to import is not valid JSON: {e}")
    if isinstance(data, dict):
        for name in ec.AUDIT_FIELDS:
            data.pop(name, None)
    normalized = ec.normalize_record(data)
    digest = ec.record_digest(normalized)
    now = time.time()
    normalized["updated_at"] = now
    normalized["updated_by"] = args.by
    normalized["updated_via"] = args.via
    _atomic_write(rec_path, json.dumps(normalized, indent=2, ensure_ascii=False) + "\n", gid)
    _append_history(hist_path, {
        "ts": now, "by": args.by, "via": args.via, "action": "import",
        "engagement_id": normalized["engagement_id"], "digest": digest,
        "source": args.source or "import", "replaced": existing is not None}, gid)
    return {"ok": True, "path": str(rec_path),
            "engagement_id": normalized["engagement_id"], "digest": digest,
            "replaced": existing is not None,
            "approval_status": ec.approval_status(normalized, ec.read_approval(appr_path))}


def cmd_digest(args) -> dict:
    org_dir, _, rec_path, _, _ = _paths(args)
    record, invalid = _load_existing(rec_path)
    if invalid:
        raise StoreError(f"the organisation's engagement file cannot be read: {invalid}")
    if record is None:
        raise StoreError(f"the organisation has no engagement yet")
    return {"ok": True, "engagement_id": record["engagement_id"],
            "digest": ec.record_digest(record)}


# ---------------------------------------------------------------------------
# text rendering (the CLI's human output; JSON is the default)
# ---------------------------------------------------------------------------
def _when(ts) -> str:
    if not isinstance(ts, (int, float)):
        return "?"
    return time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(ts))


def _render_text(verb: str, out: dict) -> str:
    lines: list[str] = []

    if verb.startswith("agent-scope"):
        if out.get("unchanged"):
            lines.append("no change.")
        lines.append(f"agent '{out['agent']}' in the organisation  ({out['scope_kind']} scope)")
        lines.append(f"  org allows    : {', '.join(out['org_in_scope']) or '(nothing)'}")
        lines.append(f"  agent narrows : {', '.join(out['agent_in_scope']) or '(no narrowing — inherits the organisation)'}")
        if out["agent_out_of_scope"]:
            lines.append(f"  agent excludes: {', '.join(out['agent_out_of_scope'])}")
        lines.append(f"  a run enforces: {', '.join(out['effective_in_scope']) or '(NOTHING)'}")
        if out.get("effective_error"):
            lines.append(f"  ! {out['effective_error']}")
        return "\n".join(lines)
    if verb == "show":
        rec = out.get("record")
        if not rec and out.get("invalid"):
            lines.append(f"the organisation has an engagement file that cannot be used: {out['invalid']}")
            return "\n".join(lines)
        if not rec:
            lines.append(f"the organisation has no engagement yet.")
            lines.append(f"  set one:  sudo agenti engagement set --engagement-id <id> --client <name> \\")
            lines.append(f"              --authorizing-party <who> --authorizing-title <title> --authorization-ref <ref> \\")
            lines.append(f"              --valid-from YYYY-MM-DD --valid-until YYYY-MM-DD --cidr-in '<cidr>' [--domain-in '<domain>']")
            return "\n".join(lines)
        lines.append(f"engagement :")
        for k in ("engagement_id", "client"):
            lines.append(f"  · {k:18} {rec[k]}")
        lines.append(f"  · {'authorized_by':18} {rec['authorizing_party']} ({rec['authorizing_title']})")
        lines.append(f"  · {'authorization_ref':18} {rec['authorization_ref']}")
        lines.append(f"  · {'valid':18} {rec['valid_from']} to {rec['valid_until']}")
        lines.append(f"  · {'emergency_contact':18} {rec['emergency_contact'] or '(none)'}")
        for kind in ec.SCOPE_KINDS:
            part = rec["scope"][kind]
            ins = ", ".join(part["in_scope"]) or "(none — no agent of this kind can run here)"
            lines.append(f"  · {kind + ' in scope':18} {ins}")
            if part["out_of_scope"]:
                lines.append(f"  · {kind + ' out of scope':18} {', '.join(part['out_of_scope'])}")
        dh = rec.get("capture_payloads"), rec.get("retention_days"), rec.get("redact")
        lines.append(f"  · {'data handling':18} payloads {'permitted' if dh[0] else 'not captured'}, "
                     f"retention {dh[1] or 'destroy on close'}, redact {', '.join(dh[2]) if dh[2] else '(none)'}")
        if rec.get("notes"):
            lines.append(f"  · {'notes':18} {rec['notes']}")
        pol = out.get("effective_policy") or {}
        if pol:
            models = ", ".join(pol.get("allowed_models") or []) or "(none)"
            lines.append(f"  · {'policy':18} approval "
                         + ("required" if pol.get("require_approval") else "not required")
                         + f", caps up to {pol.get('max_turns_ceiling')} turns / "
                         f"${pol.get('max_budget_usd_ceiling')} / {pol.get('timeout_s_ceiling')}s, "
                         f"models: {models}")
        st = out.get("approval_status", {})
        mark = "APPROVED" if st.get("current") else ("STALE" if st.get("approved") else "NOT APPROVED")
        lines.append(f"  · {'approval':18} {mark} — {st.get('reason', '')}")
        if not st.get("current"):
            lines.append(f"      approve:  sudo agenti engagement approve")
        lines.append(f"  · {'digest':18} {out.get('digest')}")
        view = out.get("view")
        if view:
            lines.append(f"\n  as a {view['scope_kind']}-scoped agent sees it: "
                         + (", ".join(view["in_scope"]) if view["in_scope"] else "(nothing authorized for this kind)"))
        lines.append("\n  a -t target may only NARROW an in-scope entry, never widen it.")
        hist = out.get("history") or []
        if hist:
            lines.append("\n  recent changes:")
            for row in hist[-5:]:
                extra = ""
                if row.get("action") == "set":
                    extra = " (" + ", ".join(row.get("changed") or []) + ")"
                lines.append(f"    · {_when(row.get('ts'))}  {row.get('action', '?'):8} {row.get('engagement_id', '?')} by {row.get('by', '?')}{extra}")
        return "\n".join(lines)
    if verb == "set":
        if out.get("unchanged"):
            return f"engagement '{out['engagement_id']}'  is unchanged — nothing written."
        what = "created" if out.get("created") else "updated (" + ", ".join(out.get("changed") or []) + ")"
        lines.append(f"engagement '{out['engagement_id']}'  {what}.")
        st = out.get("approval_status", {})
        if not st.get("current") and (out.get("effective_policy") or {}).get("require_approval", True):
            lines.append(f"  approval: {st.get('reason')}")
            lines.append(f"  an approval is required before a run can start:")
            lines.append(f"    sudo agenti engagement approve")
        return "\n".join(lines)
    if verb == "approve":
        a = out["approval"]
        lines.append(f"approved engagement '{a['engagement_id']}'  (by {a['approved_by']}).")
        lines.append("  bound to the record's current content — editing the engagement again will need a fresh approval.")
        return "\n".join(lines)
    if verb == "history":
        rows = out.get("history") or []
        if not rows:
            return f"no engagement history  yet."
        for row in rows:
            extra = ""
            if row.get("action") == "set":
                extra = " (" + ", ".join(row.get("changed") or []) + ")"
            lines.append(f"  {_when(row.get('ts'))}  {row.get('action', '?'):8} {row.get('engagement_id', '?')} by {row.get('by', '?')}{extra}")
        return "\n".join(lines)
    if verb == "digest":
        return f"{out['engagement_id']}  {out['digest']}"
    if verb == "import":
        return (f"imported engagement '{out['engagement_id']}' "
                + (" (replaced the existing one)" if out.get("replaced") else "") + ".")
    return json.dumps(out)


# ---------------------------------------------------------------------------
def _build_parser() -> argparse.ArgumentParser:
    ap = _JsonAwareArgumentParser(allow_abbrev=False, prog="engagement_store.py",
                                  description="read/write the organisation's engagement record (root)")
    ap.add_argument("--org-dir", required=True, help="the organisation directory, e.g. /var/lib/agenti/data/org")
    ap.add_argument("--shared-dir", default=None, help="the platform shared dir (default: <root>/shared)")
    ap.add_argument("--group", default=None, help="the service group for file ownership")
    ap.add_argument("--format", choices=("json", "text"), default="json")
    sub = ap.add_subparsers(dest="verb", required=True)

    s = sub.add_parser("show", allow_abbrev=False, help="the record, its digest, approval status and history")
    s.add_argument("--scope-kind", choices=ec.SCOPE_KINDS, default=None,
                   help="also include the view one agent of this kind would get")
    s.add_argument("--agent", default=None,
                   help="with --scope-kind: the view that agent is held to (organisation scope narrowed by its own)")
    s.add_argument("-n", type=int, default=20)

    s = sub.add_parser("set", allow_abbrev=False, help="create or update the record (metadata merged, scope per kind)")
    s.add_argument("--by", required=True)
    s.add_argument("--via", choices=("cli", "api"), default="cli")
    for field, flag in _META_FLAGS.items():
        s.add_argument(flag, dest=field, default=None)
    g = s.add_mutually_exclusive_group()
    g.add_argument("--capture-payloads", dest="capture_payloads", action="store_true", default=None)
    g.add_argument("--no-capture-payloads", dest="capture_payloads", action="store_false")
    s.add_argument("--enable-capability", dest="enable_capability", action="append",
                   metavar="NAME",
                   help="add a capability gate to the engagement (e.g. 'exploit')")
    s.add_argument("--disable-capability", dest="disable_capability", action="append",
                   metavar="NAME",
                   help="remove a capability gate from the engagement")
    g2 = s.add_mutually_exclusive_group()
    g2.add_argument("--exploitation-enabled", dest="exploitation_enabled",
                    action="store_true", default=None,
                    help="alias for --enable-capability exploit")
    g2.add_argument("--no-exploitation-enabled", dest="exploitation_enabled",
                    action="store_false",
                    help="alias for --disable-capability exploit")
    s.add_argument("--retention-days", type=int, default=None)
    s.add_argument("--redact", action="append", default=None)
    s.add_argument("--clear-redact", action="store_true")
    s.add_argument("--cidr-in", action="append", default=None, metavar="ENTRY")
    s.add_argument("--cidr-out", action="append", default=None, metavar="ENTRY")
    s.add_argument("--domain-in", action="append", default=None, metavar="ENTRY")
    s.add_argument("--domain-out", action="append", default=None, metavar="ENTRY")
    s.add_argument("--replace-scope", action="append", choices=ec.SCOPE_KINDS, default=None,
                   help="the given --<kind>-in/--<kind>-out flags are the WHOLE scope of this kind")
    s.add_argument("--clear-scope", action="append", choices=ec.SCOPE_KINDS, default=None,
                   help="remove every entry of this kind")
    # Operational policy (CLAUDE.md "Current plan": caps/model choice replace
    # the retired --dev/commercial split). Each ceiling flag is independent —
    # giving one never touches the others, matching the metadata flags'
    # merge-by-default shape, not the scope kinds' replace-by-kind one.
    g = s.add_mutually_exclusive_group()
    g.add_argument("--require-approval", dest="require_approval", action="store_true", default=None)
    g.add_argument("--no-require-approval", dest="require_approval", action="store_false")
    s.add_argument("--max-turns-ceiling", type=int, default=None)
    s.add_argument("--clear-max-turns-ceiling", action="store_true",
                   help="revert to the platform default turns ceiling")
    s.add_argument("--max-budget-ceiling", dest="max_budget_usd_ceiling", type=float, default=None)
    s.add_argument("--clear-max-budget-ceiling", action="store_true",
                   help="revert to the platform default budget ceiling")
    s.add_argument("--timeout-ceiling", dest="timeout_s_ceiling", type=int, default=None)
    s.add_argument("--clear-timeout-ceiling", action="store_true",
                   help="revert to the platform default timeout ceiling")
    s.add_argument("--allowed-models", action="append", default=None, metavar="NAME",
                   help="repeatable; replaces the WHOLE allowed-model list (a curated pick, "
                        "not an incremental add) — e.g. --allowed-models haiku --allowed-models sonnet")
    s.add_argument("--clear-allowed-models", action="store_true",
                   help="revert to the platform default model list")

    s = sub.add_parser("agent-scope-show", allow_abbrev=False, help="organisation scope, one agent's own narrowing, and the overlap a run enforces")
    s.add_argument("--agent", required=True)
    s.add_argument("--scope-kind", choices=ec.SCOPE_KINDS, required=True)

    s = sub.add_parser("agent-scope-set", allow_abbrev=False, help="replace one agent's own (narrower) scope here")
    s.add_argument("--agent", required=True)
    s.add_argument("--scope-kind", choices=ec.SCOPE_KINDS, required=True)
    s.add_argument("--by", required=True)
    s.add_argument("--via", choices=("cli", "api"), default="cli")
    s.add_argument("--in", dest="in_scope", action="append", default=[], metavar="ENTRY",
                   help="an entry the agent may touch (repeatable; none = inherit the organisation's)")
    s.add_argument("--out", dest="out_of_scope", action="append", default=[], metavar="ENTRY",
                   help="an extra exclusion (repeatable)")

    s = sub.add_parser("approve", allow_abbrev=False, help="record an admin's approval of the record as it stands")
    s.add_argument("--by", required=True)
    s.add_argument("--via", choices=("cli", "api"), default="cli")
    s.add_argument("--engagement-id", default=None, help="refuse unless the record has this id")
    s.add_argument("--expect-digest", default=None,
                   help="refuse unless the record's digest is this one (what the approver reviewed)")

    s = sub.add_parser("history", allow_abbrev=False, help="who changed or approved what, when")
    s.add_argument("-n", type=int, default=50)

    sub.add_parser("digest", allow_abbrev=False, help="the record's content digest")

    s = sub.add_parser("import", allow_abbrev=False, help="replace the record from a JSON file/stdin (migration/restore)")
    s.add_argument("--by", required=True)
    s.add_argument("--via", choices=("cli", "api"), default="cli")
    s.add_argument("--file", default=None, help="read the record from this file instead of stdin")
    s.add_argument("--force", action="store_true", help="overwrite an existing record")
    s.add_argument("--source", default=None, help="a short label for the history row")
    return ap


def main(argv: list[str]) -> int:
    args = _build_parser().parse_args(argv)
    handler = {"show": cmd_show, "set": cmd_set, "approve": cmd_approve,
               "history": cmd_history, "digest": cmd_digest,
               "import": cmd_import,
               "agent-scope-show": cmd_agent_scope_show,
               "agent-scope-set": cmd_agent_scope_set}[args.verb]
    try:
        out = handler(args)
    except (StoreError, ec.EngagementError) as e:
        # A FAILURE is always {"ok": false, "error": ...} on stdout,
        # regardless of --format — the one-stream convention every other
        # JSON-emitting verb in this project keeps (shared/agenti's own
        # die()). --format text only shapes a SUCCESS; the caller is
        # shared/agenti's own wrapper, which parses this exact field to
        # build its own die() message, not a human reading raw output
        # directly. Text mode used to print "ERROR: ..." to stderr and
        # leave stdout EMPTY, which broke that parse and produced a
        # doubled "error: ERROR: ..." message — found by actually running
        # a text-mode failure, not by reading the code.
        print(json.dumps({"ok": False, "error": str(e)}))
        return 2
    if args.format == "text":
        print(_render_text(args.verb, out))
    else:
        print(json.dumps(out, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
