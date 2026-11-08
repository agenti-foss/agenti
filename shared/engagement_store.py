#!/usr/bin/env python3
"""
engagement_store.py — the root-side reader/writer for a organisation's engagement
record (CLAUDE.md "Current plan", phase 1 of the cybersecurity refocus).

Invoked by `shared/agenti` (as root) for `agenti engagement
show|set|approve|approve-pending|reject-pending|withdraw-pending|history`,
and — through the same verbs — by the API and the GUI. It owns these files
in the organisation's directory:

    org/engagement.json           the record (engagement_context.py's
                                       schema) — root:<service group> 0640,
                                       written atomically (tmp + rename)
    org/approval.json             an admin's approval OF THAT CONTENT:
                                       engagement_id + the record's digest +
                                       who/when. Editing the record makes
                                       it stale by construction — see
                                       engagement_context.approval_status()
    org/engagement-pending.json   a change waiting for a second admin (only
                                       while the platform policy
                                       engagement-second-approver is on)
    org/engagement-history.jsonl  one line per change, approval, proposal
                                       and decision: who, when, what
    org/.engagement.lock          root-only; every write holds it

Two ways a save goes, chosen by the platform policy the CLI passes in
(--second-approver, read from iam.db; nobody else may supply it):
  * off (the default): the save writes the record AND records the saver's
    approval of exactly what was saved, in one step. One confirmation.
  * on: the save becomes a PENDING change; the approved record stays in
    force, and runs are held to the stricter of the two
    (engagement_context.stricter_of). A different admin approves it (it
    becomes the record, approved, in one step) or rejects it; its author may
    withdraw it. A later save replaces it, and its saver becomes its author.
Caps, models and prices are outside the digest and apply at once either
way: they are an operational choice, not a re-authorization.

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
  * operational policy (the three ceiling flags, --allowed-models, prices)
    merges per FIELD, like the metadata flags — giving one never touches
    the others — except --allowed-models itself, which always replaces the
    whole list (a curated pick, never an incremental add).

Output is one JSON object on stdout (or --format text for a human), exit
0 on success and 2 on a refused input — every failure is reported as data,
never a traceback, matching every other JSON-emitting verb in the project.
"""
from __future__ import annotations

import argparse
import contextlib
import fcntl
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
    "valid_from": "--valid-from",
    "valid_until": "--valid-until", "emergency_contact": "--emergency-contact",
    "notes": "--notes",
}
_CREATE_REQUIRED = ("engagement_id", "client", "authorizing_party", "authorizing_title",
                    "valid_from", "valid_until")
LOCK_FILENAME = ".engagement.lock"


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


def _remove(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
    except OSError as e:
        raise StoreError(f"cannot remove {path}: {e}")


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


@contextlib.contextmanager
def _locked(org_dir: Path):
    """One writer at a time: two saves used to race their read-modify-write
    (found 2026-11-06). root-only 0600; the unit tests get their own."""
    path = org_dir / LOCK_FILENAME
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


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


def _pending_path(org_dir: Path) -> Path:
    return org_dir / ec.PENDING_FILENAME


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


def _load_pending(org_dir: Path) -> tuple[dict | None, str | None]:
    """Like _load_existing, for the pending change: an unusable file is
    reported (and refuses runs, engagement_context.read_pending) but never a
    dead end — a save replaces it, and any admin may reject it."""
    try:
        return ec.read_pending(_pending_path(org_dir)), None
    except ec.EngagementError as e:
        return None, str(e)


def _auth(record: dict) -> dict:
    return {k: v for k, v in record.items() if k not in ec.AUDIT_FIELDS and k != "policy"}


def _changed(old: dict | None, new: dict) -> list[str]:
    """The authorization fields that differ (policy is never one of them;
    exploitation_enabled is derived from enabled_capabilities, so it is not
    named twice)."""
    if old is None:
        return ["(created)"]
    a, b = _auth(old), _auth(new)
    out: list[str] = []
    for k in b:
        if k == "exploitation_enabled":
            continue
        if k == "scope":
            out += [f"scope.{kind}" for kind in ec.SCOPE_KINDS if a["scope"][kind] != b["scope"][kind]]
        elif a.get(k) != b[k]:
            out.append(k)
    return out


def _approve_record(appr_path: Path, record: dict, *, by: str, via: str, kind: str,
                    gid: int | None, proposed_by: str | None = None) -> dict:
    approval = {"engagement_id": record["engagement_id"], "digest": ec.record_digest(record),
                "approved_by": by, "approved_at": time.time(), "via": via, "kind": kind}
    if proposed_by:
        approval["proposed_by"] = proposed_by
    _atomic_write(appr_path, json.dumps(approval, indent=2) + "\n", gid)
    return approval


def _write_record(rec_path: Path, record: dict, *, by: str, via: str, gid: int | None) -> dict:
    rec = {k: v for k, v in record.items() if k not in ec.AUDIT_FIELDS}
    rec.update({"updated_at": time.time(), "updated_by": by, "updated_via": via})
    _atomic_write(rec_path, json.dumps(rec, indent=2, ensure_ascii=False) + "\n", gid)
    return rec


def _pending_view(pending: dict, live: dict | None, approvers: list[str],
                  second_approver: str | None) -> dict:
    """What GET /engagement shows of a pending change."""
    live_digest = ec.record_digest(live) if live is not None else None
    author = pending.get("author", "")
    out = {k: pending.get(k) for k in ("digest", "base_digest", "author", "authors",
                                       "authored_at", "opened_at", "via")}
    out["record"] = pending["record"]
    out["stale"] = pending.get("base_digest") != live_digest
    out["changed"] = _changed(live, pending["record"])
    # Unknown (None) when the CLI could not read the policy; with the policy
    # off its author may approve it too.
    out["approvers_available"] = (None if second_approver is None else
                                  True if second_approver == "off" else
                                  any(a != author for a in approvers))
    if live is not None:
        view: dict = {"scope": {}}
        for kind in ec.SCOPE_KINDS:
            live_e = ec.engagement_from_record(live, kind)
            pend_e = ec.engagement_from_record(pending["record"], kind)
            m = ec.stricter_of(live_e, pend_e, kind)
            view["scope"][kind] = {"in_scope": m.in_scope, "out_of_scope": m.out_of_scope}
            view.update({"valid_from": m.valid_from, "valid_until": m.valid_until,
                         "capture_payloads": m.capture_payloads,
                         "enabled_capabilities": m.enabled_capabilities})
        out["in_force_now"] = view
    return out


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
    pending, pending_invalid = _load_pending(org_dir)
    approvers = sorted(set(args.approver or []))
    out["second_approver"] = args.second_approver
    out["approvers_count"] = len(approvers) if args.second_approver is not None else None
    out["pending"] = _pending_view(pending, record, approvers, args.second_approver) if pending else None
    out["pending_invalid"] = pending_invalid
    if args.scope_kind and record is not None:
        eng = ec.engagement_from_record(record, args.scope_kind)
        error = None
        if pending is not None and eng.in_scope:
            try:
                eng = ec.stricter_of(eng, ec.engagement_from_record(pending["record"], args.scope_kind),
                                     args.scope_kind)
            except ec.EngagementError as e:
                error = str(e)
        out["view"] = {"scope_kind": args.scope_kind, "in_scope": eng.in_scope,
                       "out_of_scope": eng.out_of_scope, "usable": bool(eng.in_scope),
                       "narrowed_by_pending": pending is not None}
        if error:
            out["view"]["error"] = error
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
    # What a ceiling's Reset goes back to (the GUI's placeholder), not the
    # value in force — which may itself be an override.
    out["platform_default_policy"] = dict(ec.PLATFORM_DEFAULT_POLICY)
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
    policy = {k: v for k, v in existing.items() if k not in ec.RETIRED_POLICY_KEYS}
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
    prices = {} if args.clear_model_prices else dict(policy.get("model_prices") or {})
    for name in args.clear_model_price or []:
        prices.pop(name, None)
        prices.pop(ec.canonical_model(name), None)
    for spec in args.model_price or []:
        name, sep, pair = spec.rpartition("=")
        try:
            inp, out = (float(x) for x in pair.split(","))
        except ValueError:
            sys.exit(f"--model-price '{spec}': write <model>=<input>,<output> in US dollars per "
                     f"million tokens, e.g. --model-price openai:gpt-5.1=1.25,10")
        if not sep or not name:
            sys.exit(f"--model-price '{spec}': write <model>=<input>,<output>")
        prices[name] = [inp, out]
    if prices:
        policy["model_prices"] = prices
    else:
        policy.pop("model_prices", None)
    return policy


def _merged_record(base: dict | None, invalid: str | None, args) -> dict:
    """`base` with the flags given applied, validated (normalize_record and
    the save-time exclusion check). On first creation the core flags are
    required."""
    created = base is None
    start: dict = dict(base) if base else {
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
    new = dict(start)
    for field in ec.LEGACY_RECORD_FIELDS:   # retired: a save drops it
        new.pop(field, None)
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
    new["scope"] = _merge_scope(start["scope"], args)
    new["policy"] = _merge_policy(start.get("policy") or {}, args)
    for name in ec.AUDIT_FIELDS:
        new.pop(name, None)
    normalized = ec.normalize_record(new)          # EngagementError names the field
    ec.check_exclusions(normalized)
    return normalized


def _check_set_preconditions(args, live: dict | None, pending: dict | None) -> None:
    if args.require_approval is not None:
        raise StoreError(
            "--require-approval/--no-require-approval are retired: a run always needs an "
            "approved engagement, and a save records its own approval (or, with the "
            "engagement-second-approver policy on, waits for another admin). Nothing was changed.")
    if args.authorization_ref is not None:
        raise StoreError(
            "--authorization-ref is retired: the engagement no longer has a Reference field. "
            "Put a statement-of-work or rules-of-engagement number in --notes if you want it "
            "kept. Nothing was changed.")
    if args.expect_second_approver and args.expect_second_approver != args.second_approver:
        raise StoreError(
            f"the second-approver policy is now {args.second_approver}, not "
            f"{args.expect_second_approver} as when you opened the engagement — reload it and "
            f"save again. Nothing was changed.")
    if args.base_digest:
        now = pending["digest"] if pending else (ec.record_digest(live) if live else "none")
        if args.base_digest != now:
            raise StoreError(
                "the engagement changed after you opened it (someone saved, approved or "
                "withdrew a change), so this save was not recorded. Reload it and make your "
                "change again.")


def cmd_set(args) -> dict:
    org_dir, shared_dir, rec_path, appr_path, hist_path = _paths(args)
    gid = _gid(args.group)
    with _locked(org_dir):
        live, invalid = _load_existing(rec_path)
        pending, pending_invalid = _load_pending(org_dir)
        _check_set_preconditions(args, live, pending)
        if args.second_approver == "on":
            return _set_pending(args, org_dir, rec_path, appr_path, hist_path, gid,
                                live, invalid, pending, pending_invalid)
        return _set_direct(args, org_dir, rec_path, appr_path, hist_path, gid,
                           live, invalid, pending)


def _result(rec_path: Path, appr_path: Path, record: dict, **extra) -> dict:
    out = {"ok": True, "path": str(rec_path), "engagement_id": record["engagement_id"],
           "digest": ec.record_digest(record),
           "approval_status": ec.approval_status(record, ec.read_approval(appr_path)),
           "effective_policy": ec.resolve_policy(record)}
    out.update(extra)
    return out


def _set_direct(args, org_dir, rec_path, appr_path, hist_path, gid, live, invalid, pending) -> dict:
    """Policy off: write the record, and the saver's approval of it."""
    normalized = _merged_record(live, invalid, args)
    created = live is None
    changed = _changed(live, normalized) if not created else ["(created)"]
    policy_changed = live is not None and (live.get("policy") or {}) != normalized["policy"]
    status = ec.approval_status(live if live is not None else None, ec.read_approval(appr_path))
    now = time.time()
    wrote = approved = False
    if created or changed or not status.get("current"):
        # Approval first: a crash between the two writes leaves the record
        # "stale" (runs refused), never approved content that isn't on disk.
        _approve_record(appr_path, normalized, by=args.by, via=args.via, kind="save", gid=gid)
        approved = True
    if created or changed or policy_changed:
        _write_record(rec_path, normalized, by=args.by, via=args.via, gid=gid)
        wrote = True
        row = {"ts": now, "by": args.by, "via": args.via, "action": "set",
               "engagement_id": normalized["engagement_id"], "digest": ec.record_digest(normalized),
               "created": created, "changed": changed or ["policy"]}
        if invalid:
            row["replaced_invalid"] = invalid
        _append_history(hist_path, row, gid)
    if approved:
        _append_history(hist_path, {"ts": now, "by": args.by, "via": args.via, "action": "approve",
                                    "kind": "save", "engagement_id": normalized["engagement_id"],
                                    "digest": ec.record_digest(normalized),
                                    **({} if wrote else {"unchanged": True})}, gid)
    if pending is not None:
        _remove(_pending_path(org_dir))
        _append_history(hist_path, {"ts": now, "by": args.by, "via": args.via,
                                    "action": "pending-cleared", "reason": "superseded by a direct save",
                                    "author": pending.get("author"), "digest": pending["digest"]}, gid)
    if not wrote and not approved:
        return _result(rec_path, appr_path, normalized, created=False, changed=[],
                       unchanged=True, pending=None, second_approver="off")
    out = _result(rec_path, appr_path, normalized, created=created,
                  changed=changed if (created or changed) else (["policy"] if policy_changed else []),
                  approved=approved, pending=None, second_approver="off")
    if invalid:
        out["replaced_invalid"] = invalid
    return out


def _set_pending(args, org_dir, rec_path, appr_path, hist_path, gid,
                 live, invalid, pending, pending_invalid) -> dict:
    """Policy on: the change waits for another admin; caps/models apply now."""
    base = pending["record"] if pending else live
    normalized = _merged_record(base, invalid if base is None else None, args)
    now = time.time()
    if live is not None and (live.get("policy") or {}) != normalized["policy"]:
        # Caps, models and prices are outside the approval: they apply at once.
        live = _write_record(rec_path, {**live, "policy": normalized["policy"]},
                             by=args.by, via=args.via, gid=gid)
        _append_history(hist_path, {"ts": now, "by": args.by, "via": args.via, "action": "set",
                                    "engagement_id": live["engagement_id"],
                                    "digest": ec.record_digest(live), "created": False,
                                    "changed": ["policy"]}, gid)
    digest = ec.record_digest(normalized)
    pend_path = _pending_path(org_dir)
    if live is not None and digest == ec.record_digest(live):
        # Saved back to exactly the version in force: nothing waits any more.
        if pending is not None or pending_invalid:
            _remove(pend_path)
            _append_history(hist_path, {"ts": now, "by": args.by, "via": args.via,
                                        "action": "pending-cleared",
                                        "reason": "saved back to the version in force",
                                        **({"author": pending.get("author"), "digest": pending["digest"]}
                                           if pending else {})}, gid)
            return _result(rec_path, appr_path, live, created=False, changed=[], pending=None,
                           cleared=True, second_approver="on")
        return _result(rec_path, appr_path, live, created=False, changed=[], unchanged=True,
                       pending=None, second_approver="on")
    if pending is not None and digest == pending["digest"]:
        if pending["record"].get("policy") != normalized["policy"]:
            _atomic_write(pend_path, json.dumps({**pending, "record": normalized}, indent=2,
                                                ensure_ascii=False) + "\n", gid)
        res = (_result(rec_path, appr_path, live) if live is not None
               else {"ok": True, "engagement_id": normalized["engagement_id"]})
        res.update({"created": False, "changed": [], "unchanged": True, "second_approver": "on",
                    "pending": {"digest": digest, "author": pending.get("author")}})
        return res
    authors = [a for a in (pending or {}).get("authors", []) if a != args.by] + [args.by]
    doc = {"format": 1, "record": normalized, "digest": digest,
           "base_digest": ec.record_digest(live) if live is not None else None,
           "author": args.by, "authors": authors, "authored_at": now,
           "opened_at": (pending or {}).get("opened_at", now), "via": args.via}
    _atomic_write(pend_path, json.dumps(doc, indent=2, ensure_ascii=False) + "\n", gid)
    changed = _changed(live, normalized)
    row = {"ts": now, "by": args.by, "via": args.via, "action": "propose",
           "engagement_id": normalized["engagement_id"], "digest": digest,
           "base_digest": doc["base_digest"], "changed": changed, "record": normalized}
    if pending is not None:
        row.update({"replaces": pending["digest"], "replaces_author": pending.get("author")})
    if pending_invalid:
        row["replaced_invalid_pending"] = pending_invalid
    _append_history(hist_path, row, gid)
    res = (_result(rec_path, appr_path, live) if live is not None
           else {"ok": True, "path": str(rec_path), "engagement_id": normalized["engagement_id"]})
    res.update({"created": live is None, "changed": changed, "second_approver": "on",
                "pending": {"digest": digest, "author": args.by, "authors": authors}})
    return res


def _agent_scope_view(org_dir: Path, rec_path: Path, agent: str, kind: str) -> dict:
    """Organisation ceiling, the agent's own narrowing, and the overlap a run
    enforces — including a pending change's narrowing (what runs are held to)."""
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
            pending = ec.read_pending(_pending_path(org_dir))
            if pending is not None and eng.in_scope:
                eng = ec.hold_to_pending(eng, pending, kind)
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
    with _locked(org_dir):
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
    """Approve the record IN FORCE as it stands (an upgraded install's old,
    unapproved record; an import). With the second-approver policy on, its
    last saver may not."""
    org_dir, shared_dir, rec_path, appr_path, hist_path = _paths(args)
    gid = _gid(args.group)
    with _locked(org_dir):
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
        if args.second_approver == "on" and record.get("updated_by") == args.by:
            raise StoreError(
                f"the engagement-second-approver policy is on, and {args.by} saved this version "
                f"last — another admin approves it. Nothing was approved.")
        approval = _approve_record(appr_path, record, by=args.by, via=args.via, kind="direct", gid=gid)
        _append_history(hist_path, {"ts": approval["approved_at"], "by": args.by, "via": args.via,
                                    "action": "approve", "kind": "direct",
                                    "engagement_id": record["engagement_id"], "digest": digest}, gid)
    return {"ok": True, "path": str(appr_path),
            "approval": approval, "approval_status": ec.approval_status(record, approval)}


def _need_pending(org_dir: Path, expect: str | None, *, allow_invalid: bool = False) -> tuple[dict | None, str | None]:
    pending, why = _load_pending(org_dir)
    if pending is None and not (why and allow_invalid):
        raise StoreError(
            "there is no engagement change waiting for approval" +
            (f" that can be used ({why})" if why else "") + " — nothing was changed.")
    if pending is not None and expect and expect != pending["digest"]:
        raise StoreError(
            "the pending engagement change was replaced after you opened it (someone saved over "
            "it, or it was withdrawn), so nothing was changed. Reload it and review the current "
            "version.")
    return pending, why


def cmd_approve_pending(args) -> dict:
    org_dir, shared_dir, rec_path, appr_path, hist_path = _paths(args)
    gid = _gid(args.group)
    with _locked(org_dir):
        pending, _why = _need_pending(org_dir, args.expect_digest)
        live, invalid = _load_existing(rec_path)
        live_digest = ec.record_digest(live) if live is not None else None
        author = pending.get("author", "")
        if pending.get("base_digest") != live_digest:
            raise StoreError(
                f"{author}'s change was made against an older version of the engagement, so it "
                f"cannot be approved as it stands. Save it again on top of the current version, "
                f"or reject it. Nothing was approved.")
        if args.second_approver == "on" and args.by == author:
            raise StoreError(
                f"the engagement-second-approver policy is on: {author} made this change, so "
                f"another admin approves it. Nothing was approved.")
        record = pending["record"]
        if args.engagement_id and args.engagement_id != record["engagement_id"]:
            raise StoreError(
                f"the pending change is for '{record['engagement_id']}', not "
                f"'{args.engagement_id}'. Nothing was approved.")
        if live is not None:
            record = {**record, "policy": live.get("policy") or {}}   # caps/models already apply
        approval = _approve_record(appr_path, record, by=args.by, via=args.via,
                                   kind="second-approver", gid=gid, proposed_by=author)
        _write_record(rec_path, record, by=author, via=pending.get("via") or args.via, gid=gid)
        _remove(_pending_path(org_dir))
        _append_history(hist_path, {"ts": approval["approved_at"], "by": args.by, "via": args.via,
                                    "action": "approve-pending", "author": author,
                                    "engagement_id": record["engagement_id"],
                                    "digest": pending["digest"], "replaced_digest": live_digest,
                                    "changed": _changed(live, record)}, gid)
    return {"ok": True, "path": str(rec_path), "engagement_id": record["engagement_id"],
            "digest": pending["digest"], "approval": approval, "author": author,
            "approval_status": ec.approval_status(record, approval)}


def cmd_reject_pending(args) -> dict:
    org_dir, shared_dir, rec_path, appr_path, hist_path = _paths(args)
    gid = _gid(args.group)
    with _locked(org_dir):
        pending, why = _need_pending(org_dir, args.expect_digest, allow_invalid=True)
        author = (pending or {}).get("author", "")
        if pending is not None and args.by == author:
            raise StoreError(
                f"you made this change, so withdraw it instead of rejecting it:\n"
                f"  sudo agenti engagement withdraw-pending")
        _remove(_pending_path(org_dir))
        row = {"ts": time.time(), "by": args.by, "via": args.via, "action": "reject-pending",
               "author": author or None, "digest": (pending or {}).get("digest")}
        if args.reason:
            row["reason"] = args.reason
        if why:
            row["invalid"] = why
        _append_history(hist_path, row, gid)
    return {"ok": True, "rejected": True, "author": author or None,
            "digest": (pending or {}).get("digest")}


def cmd_withdraw_pending(args) -> dict:
    org_dir, shared_dir, rec_path, appr_path, hist_path = _paths(args)
    gid = _gid(args.group)
    with _locked(org_dir):
        pending, _why = _need_pending(org_dir, args.expect_digest)
        author = pending.get("author", "")
        if args.by != author:
            raise StoreError(
                f"only {author}, who made this change, can withdraw it; another admin rejects "
                f"it instead:\n  sudo agenti engagement reject-pending")
        _remove(_pending_path(org_dir))
        _append_history(hist_path, {"ts": time.time(), "by": args.by, "via": args.via,
                                    "action": "withdraw-pending", "digest": pending["digest"]}, gid)
    return {"ok": True, "withdrawn": True, "digest": pending["digest"]}


def cmd_history(args) -> dict:
    org_dir, _, _, _, hist_path = _paths(args)
    return {"ok": True, "history": _read_history(hist_path, args.n)}


def cmd_import(args) -> dict:
    """Replace the record wholesale from a JSON blob (a file, or stdin) —
    for a restore-from-backup, or a one-off migration script that has
    already built the record and just needs it written atomically with a
    history entry. Refuses to overwrite an existing record unless --force
    is given, so it can never be an accident. Clears a pending change.
    Goes through the SAME normalize_record()/atomic-write/history-append
    path as `set` — a migration must be held to the identical validation a
    hand-typed edit is, not a separate, looser one."""
    org_dir, shared_dir, rec_path, appr_path, hist_path = _paths(args)
    gid = _gid(args.group)
    with _locked(org_dir):
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
        ec.check_exclusions(normalized)
        digest = ec.record_digest(normalized)
        now = time.time()
        _write_record(rec_path, normalized, by=args.by, via=args.via, gid=gid)
        _append_history(hist_path, {
            "ts": now, "by": args.by, "via": args.via, "action": "import",
            "engagement_id": normalized["engagement_id"], "digest": digest,
            "source": args.source or "import", "replaced": existing is not None}, gid)
        pending, _pinv = _load_pending(org_dir)
        if pending is not None or _pinv:
            _remove(_pending_path(org_dir))
            _append_history(hist_path, {"ts": now, "by": args.by, "via": args.via,
                                        "action": "pending-cleared", "reason": "replaced by an import",
                                        "author": (pending or {}).get("author")}, gid)
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


def _history_line(row: dict) -> str:
    action = row.get("action", "?")
    extra = ""
    if action in ("set", "propose", "approve-pending"):
        changed = [c for c in (row.get("changed") or []) if c != "(created)"]
        extra = " (created)" if row.get("created") else (" (" + ", ".join(changed) + ")" if changed else "")
    if action in ("approve-pending", "reject-pending") and row.get("author"):
        extra += f" — change by {row['author']}"
    if action == "pending-cleared":
        extra = f" ({row.get('reason', '')})"
    return (f"{_when(row.get('ts'))}  {action:16} {row.get('engagement_id', '') or ''} "
            f"by {row.get('by', '?')}{extra}")


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
        pend = out.get("pending")
        if not rec and out.get("invalid"):
            lines.append(f"the organisation has an engagement file that cannot be used: {out['invalid']}")
            return "\n".join(lines)
        if not rec and pend:
            lines.append(f"the organisation's first engagement, proposed by {pend['author']}, is waiting "
                         f"for another admin's approval:")
            lines.append(f"  approve:  sudo agenti engagement approve-pending --expect-digest {pend['digest']}")
            lines.append(f"  reject:   sudo agenti engagement reject-pending --expect-digest {pend['digest']}")
            return "\n".join(lines)
        if not rec:
            lines.append(f"the organisation has no engagement yet.")
            lines.append(f"  set one:  sudo agenti engagement set --engagement-id <id> --client <name> \\")
            lines.append(f"              --authorizing-party <who> --authorizing-title <title> \\")
            lines.append(f"              --valid-from YYYY-MM-DD --valid-until YYYY-MM-DD --cidr-in '<cidr>' [--domain-in '<domain>']")
            return "\n".join(lines)
        lines.append(f"engagement :")
        for k in ("engagement_id", "client"):
            lines.append(f"  · {k:18} {rec[k]}")
        lines.append(f"  · {'authorized_by':18} {rec['authorizing_party']} ({rec['authorizing_title']})")
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
            lines.append(f"  · {'policy':18} caps up to {pol.get('max_turns_ceiling')} turns / "
                         f"${pol.get('max_budget_usd_ceiling')} / {pol.get('timeout_s_ceiling')}s, "
                         f"models: {models}")
        st = out.get("approval_status", {})
        mark = "APPROVED" if st.get("current") else ("STALE" if st.get("approved") else "NOT APPROVED")
        lines.append(f"  · {'approval':18} {mark} — {st.get('reason', '')}")
        if not st.get("current"):
            lines.append(f"      approve:  sudo agenti engagement approve")
        lines.append(f"  · {'digest':18} {out.get('digest')}")
        if pend:
            lines.append(f"\n  a change by {pend['author']} ({_when(pend.get('authored_at'))}) is waiting for "
                         f"another admin's approval: {', '.join(pend.get('changed') or [])}")
            lines.append("    until it is approved, runs must fit both versions.")
            if pend.get("stale"):
                lines.append("    ! it was made against an older version: save it again, or reject it.")
            lines.append(f"    approve:  sudo agenti engagement approve-pending --expect-digest {pend['digest']}")
            lines.append(f"    reject:   sudo agenti engagement reject-pending --expect-digest {pend['digest']}")
            lines.append(f"    withdraw: sudo agenti engagement withdraw-pending  (its author)")
        if out.get("pending_invalid"):
            lines.append(f"\n  ! {out['pending_invalid']}")
        view = out.get("view")
        if view:
            lines.append(f"\n  as a {view['scope_kind']}-scoped agent sees it: "
                         + (", ".join(view["in_scope"]) if view["in_scope"] else "(nothing authorized for this kind)"))
        lines.append("\n  a -t target may only NARROW an in-scope entry, never widen it.")
        hist = out.get("history") or []
        if hist:
            lines.append("\n  recent changes:")
            for row in hist[-5:]:
                lines.append("    · " + _history_line(row))
        return "\n".join(lines)
    if verb == "set":
        pend = out.get("pending")
        if out.get("cleared"):
            return ("saved back to the version in force: the pending change was cleared, nothing "
                    "is waiting for approval now.")
        if out.get("unchanged"):
            return f"engagement '{out['engagement_id']}'  is unchanged — nothing written."
        what = "created" if out.get("created") else "updated (" + ", ".join(out.get("changed") or []) + ")"
        if pend:
            lines.append(f"engagement '{out['engagement_id']}'  change saved, waiting for another admin's "
                         f"approval ({', '.join(out.get('changed') or [])}).")
            lines.append("  until it is approved, runs must fit both the version in force and this one.")
            lines.append(f"  another admin approves it:  sudo agenti engagement approve-pending "
                         f"--expect-digest {pend['digest']}")
            return "\n".join(lines)
        lines.append(f"engagement '{out['engagement_id']}'  {what}" +
                     (", and approved as saved." if out.get("approved") else "."))
        return "\n".join(lines)
    if verb == "approve":
        a = out["approval"]
        lines.append(f"approved engagement '{a['engagement_id']}'  (by {a['approved_by']}).")
        lines.append("  bound to the record's current content — editing the engagement again will need a fresh approval.")
        return "\n".join(lines)
    if verb == "approve-pending":
        return (f"approved {out['author']}'s change: engagement '{out['engagement_id']}' is now in "
                f"force, approved by {out['approval']['approved_by']}.")
    if verb == "reject-pending":
        return f"rejected the pending change{' by ' + out['author'] if out.get('author') else ''}."
    if verb == "withdraw-pending":
        return "withdrew your pending change."
    if verb == "history":
        rows = out.get("history") or []
        if not rows:
            return f"no engagement history  yet."
        return "\n".join("  " + _history_line(row) for row in rows)
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
    policy_help = ("the platform's engagement-second-approver policy, as root read it from "
                   "iam.db (the CLI passes it; nobody else may)")

    s = sub.add_parser("show", allow_abbrev=False, help="the record, its digest, approval status and history")
    s.add_argument("--scope-kind", choices=ec.SCOPE_KINDS, default=None,
                   help="also include the view one agent of this kind would get")
    s.add_argument("--agent", default=None,
                   help="with --scope-kind: the view that agent is held to (organisation scope narrowed by its own)")
    s.add_argument("-n", type=int, default=20)
    s.add_argument("--second-approver", choices=("on", "off"), default=None, help=policy_help)
    s.add_argument("--approver", action="append", default=None, metavar="NAME",
                   help="an account that may approve (repeatable; only counts come out)")

    s = sub.add_parser("set", allow_abbrev=False, help="create or update the record (metadata merged, scope per kind)")
    s.add_argument("--by", required=True)
    s.add_argument("--via", choices=("cli", "api"), default="cli")
    s.add_argument("--second-approver", choices=("on", "off"), required=True, help=policy_help)
    s.add_argument("--expect-second-approver", choices=("on", "off"), default=None,
                   help="refuse unless the policy is still what the saver saw")
    s.add_argument("--base-digest", default=None, metavar="HEX|none",
                   help="refuse unless the version being edited (the pending change, else the record) "
                        "still has this digest")
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
    # Retired 2026-11-06 (a run always needs an approved engagement): still
    # parsed, so an old script gets a sentence instead of "unknown argument".
    g = s.add_mutually_exclusive_group()
    g.add_argument("--require-approval", dest="require_approval", action="store_true", default=None,
                   help=argparse.SUPPRESS)
    g.add_argument("--no-require-approval", dest="require_approval", action="store_false",
                   help=argparse.SUPPRESS)
    s.add_argument("--authorization-ref", dest="authorization_ref", default=None,
                   help=argparse.SUPPRESS)   # retired 2026-11-07, same reason
    # Operational policy: each ceiling flag is independent — giving one never
    # touches the others, matching the metadata flags' merge-by-default
    # shape, not the scope kinds' replace-by-kind one.
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
    s.add_argument("--model-price", action="append", default=None, metavar="MODEL=IN,OUT",
                   help="what a cloud model costs, US dollars per million input and output tokens "
                        "(e.g. openai:gpt-5.1=1.25,10). The budget cap of a run on an OpenAI model "
                        "needs it; Claude's spend comes from the Claude SDK, a self-hosted model is free")
    s.add_argument("--clear-model-price", action="append", default=None, metavar="MODEL",
                   help="forget one model's price")
    s.add_argument("--clear-model-prices", action="store_true", help="clear all prices before applying --model-price entries")
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

    s = sub.add_parser("approve", allow_abbrev=False, help="record an admin's approval of the record in force, as it stands")
    s.add_argument("--by", required=True)
    s.add_argument("--via", choices=("cli", "api"), default="cli")
    s.add_argument("--second-approver", choices=("on", "off"), required=True, help=policy_help)
    s.add_argument("--engagement-id", default=None, help="refuse unless the record has this id")
    s.add_argument("--expect-digest", default=None,
                   help="refuse unless the record's digest is this one (what the approver reviewed)")

    s = sub.add_parser("approve-pending", allow_abbrev=False,
                       help="approve the change waiting for a second admin: it becomes the record, approved")
    s.add_argument("--by", required=True)
    s.add_argument("--via", choices=("cli", "api"), default="cli")
    s.add_argument("--second-approver", choices=("on", "off"), required=True, help=policy_help)
    s.add_argument("--engagement-id", default=None)
    s.add_argument("--expect-digest", default=None,
                   help="refuse unless the pending change's digest is this one (what the approver reviewed)")

    s = sub.add_parser("reject-pending", allow_abbrev=False, help="reject the change waiting for approval")
    s.add_argument("--by", required=True)
    s.add_argument("--via", choices=("cli", "api"), default="cli")
    s.add_argument("--expect-digest", default=None)
    s.add_argument("--reason", default=None, help="a short note for the history")

    s = sub.add_parser("withdraw-pending", allow_abbrev=False, help="withdraw your own change waiting for approval")
    s.add_argument("--by", required=True)
    s.add_argument("--via", choices=("cli", "api"), default="cli")
    s.add_argument("--expect-digest", default=None)

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
               "approve-pending": cmd_approve_pending, "reject-pending": cmd_reject_pending,
               "withdraw-pending": cmd_withdraw_pending,
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
