#!/usr/bin/env python3
"""tool_settings_store.py — the root-side reader/writer for one agent's
allow-list OVERRIDE (CLAUDE.md "Current plan" phase 6):
which catalog programs an admin added, which of the agent's own baseline
programs an admin removed. Mirrors shared/engagement_store.py's agent-scope
verbs: an atomic root-owned JSON file plus an append-only history.

File: org/<agent>/tool-settings.json, root:<service group> 0640 — the
agent reads it, only root writes it. Validation goes through
shared/tool_catalog.py so this file and shared/agent_runtime.py (which
applies the settings at run start) can never disagree about what's allowed.

    python3 tool_settings_store.py --org-dir ... --agent enum show
    python3 tool_settings_store.py --org-dir ... --agent enum set \
        --enable curl --enable sslscan --disable ping --by alice
"""
from __future__ import annotations

import argparse
import grp
import json
import os
import sys
import time
from pathlib import Path

import paths
import tool_catalog as tc

SETTINGS_FILENAME = "tool-settings.json"
HISTORY_FILENAME = "tool-settings-history.jsonl"


class StoreError(Exception):
    pass


def _gid(group: str | None) -> int | None:
    if not group:
        return None
    try:
        return grp.getgrnam(group).gr_gid
    except KeyError:
        raise StoreError(f"unknown group {group!r} — is the service account provisioned?")


def _own(path: Path, gid: int | None) -> None:
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


def settings_path(org_dir: Path, agent: str) -> Path:
    return Path(org_dir) / agent / SETTINGS_FILENAME


def _history_path(org_dir: Path, agent: str) -> Path:
    return Path(org_dir) / agent / HISTORY_FILENAME


def read_settings(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {"enable": [], "disable": [], "approvable": []}
    except (OSError, ValueError) as e:
        raise StoreError(f"cannot read {path}: {e}")


def _master_dir(shared_dir: Path, agent: str) -> Path:
    """A shipped agent's code folder, else one built in Settings (under the
    data root's shared/)."""
    shipped = paths.shipped_agents() / agent
    return shipped if shipped.is_dir() else Path(shared_dir) / "agents" / agent


def catalog_for(shared_dir: Path, *, strict: bool = False) -> dict:
    """The reviewed catalog (shipped with the code) plus the admin's additions
    (the data root's shared/). Every reader of the catalog goes through here:
    the two files live in different folders, so a path built by hand finds
    neither."""
    return tc.load_catalog(paths.catalog_file(), Path(shared_dir) / tc.ADMIN_CATALOG_FILENAME, strict=strict)


def settings_for_run(org_dir: Path, shared_dir: Path, agent: str, base: set) -> tuple[dict, dict]:
    """(catalog, validated settings) exactly as a run applies them. No settings
    file means no admin changes. Raises tc.CatalogError or StoreError when they
    cannot be applied, and the run then refuses to start (operator decision
    2026-10-21). Used by agent_runtime.resolve_tool_allowlist and by preflight."""
    catalog = catalog_for(shared_dir, strict=True)
    raw = read_settings(settings_path(Path(org_dir), agent))
    return catalog, tc.validate_settings(raw, catalog, base)


def has_enforced_list(shared_dir: Path, agent: str) -> bool:
    """Whether this agent runs programs from a list an admin may change (enum
    and recon agents built in Settings)."""
    try:
        caps = json.loads((_master_dir(shared_dir, agent) / "capabilities.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    return bool((caps.get("command_line_tools") or {}).get("enforced"))


def baseline(shared_dir: Path, agent: str) -> tuple[set[str], dict[str, str]]:
    """This agent's own enforced allow-list, from its (world-readable)
    capabilities.json — the SAME descriptor the operator-facing Tools panel
    reads, so "baseline" here can never claim more than the code grants."""
    caps_path = _master_dir(shared_dir, agent) / "capabilities.json"
    try:
        caps = json.loads(caps_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise StoreError(f"no tools descriptor for '{agent}' (reinstall: sudo apt install --reinstall agenti)")
    except (OSError, ValueError) as e:
        raise StoreError(f"cannot read {caps_path}: {e}")
    cli = caps.get("command_line_tools") or {}
    if not cli.get("enforced"):
        raise StoreError(
            f"'{agent}' has no enforced shell allow-list — it calls a fixed set of "
            f"programs that can't be changed. There is nothing here for an admin to add to "
            f"or remove from.")
    items = cli.get("items") or []
    names = {i["name"] for i in items if i.get("name")}
    purposes = {i["name"]: i.get("purpose", "") for i in items if i.get("name")}
    return names, purposes


def view(org_dir: Path, shared_dir: Path, agent: str) -> dict:
    base, purposes = baseline(shared_dir, agent)
    catalog = catalog_for(shared_dir)
    settings_error = None
    try:
        raw = read_settings(settings_path(org_dir, agent))
    except StoreError as e:
        # Runs of this agent refuse to start until it is replaced; saving
        # this agent's program list (cmd_set) replaces it.
        raw, settings_error = {}, f"{e} — runs of {agent} refuse to start until an admin saves its program list again"
    try:
        settings = tc.validate_settings(raw, catalog, base)
    except tc.CatalogError:
        # A catalog entry an admin once enabled may have been retired since;
        # don't let a stale file make this verb unusable — report it as-is
        # and let `set` fail loudly if asked to write it back unchanged.
        settings = {"enable": sorted(set(raw.get("enable", [])) & tc.catalog_names(catalog)),
                   "approvable": sorted(set(raw.get("approvable", [])) & tc.catalog_names(catalog)),
                   "disable": sorted(set(raw.get("disable", [])) & base)}
    effective = tc.effective_binaries(base, settings, catalog)
    return {
        "agent": agent,
        "settings_error": settings_error,
        "baseline": sorted(base),
        "settings": settings,
        "effective": sorted(effective),
        "added": sorted(effective - base),
        "removed": sorted(base - effective),
        "approvable": sorted(tc.approvable_programs(settings, catalog, effective)),
        "purposes": tc.effective_purposes(purposes, settings, catalog),
        "extra_denied_patterns": sorted(set(tc.extra_denied_patterns(settings, catalog)
                                            + tc.builtin_extra_denied(catalog, effective))),
        # Each program with whether it is installed on this server right now
        # (an enabled program that is not installed fails at run time).
        "catalog": [{**p, "installed": bool(tc.which_program(p.get("name", ""))),
                     "install_hint": None if tc.which_program(p.get("name", "")) else f"sudo apt install {p.get('name', '')}"}
                    for p in catalog.get("programs", []) if isinstance(p, dict)],
    }


def cmd_show(args) -> dict:
    out = view(Path(args.org_dir), Path(args.shared_dir), args.agent)
    hist = _history_path(Path(args.org_dir), args.agent)
    rows = []
    if hist.exists():
        for line in hist.read_text(encoding="utf-8").splitlines()[-args.n:]:
            try:
                rows.append(json.loads(line))
            except ValueError:
                continue
    out["history"] = rows[::-1]
    out["ok"] = True
    return out


def cmd_set(args) -> dict:
    org_dir, shared_dir = Path(args.org_dir), Path(args.shared_dir)
    base, _purposes = baseline(shared_dir, args.agent)
    catalog = catalog_for(shared_dir)
    new = tc.validate_settings({"enable": args.enable or [], "disable": args.disable or [],
                                "approvable": args.approvable or []}, catalog, base)
    path = settings_path(org_dir, args.agent)
    try:
        old = read_settings(path)
    except StoreError:
        old = {"unreadable": True}          # always replaced
    if (old.get("enable", []) == new["enable"] and old.get("disable", []) == new["disable"]
            and old.get("approvable", []) == new["approvable"]):
        out = view(org_dir, shared_dir, args.agent)
        out.update({"ok": True, "unchanged": True})
        return out
    gid = _gid(args.group)
    _atomic_write(path, json.dumps(new, indent=2) + "\n", gid)
    row = {"ts": time.time(), "by": args.by, "via": args.via,
          "enable": new["enable"], "disable": new["disable"], "approvable": new["approvable"]}
    hist = _history_path(org_dir, args.agent)
    existed = hist.exists()
    with open(hist, "a", encoding="utf-8") as f:
        f.write(json.dumps(row, ensure_ascii=False) + "\n")
    if not existed:
        _own(hist, gid)
    out = view(org_dir, shared_dir, args.agent)
    out.update({"ok": True, "unchanged": False})
    return out


def _build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(allow_abbrev=False, prog="tool_settings_store.py")
    ap.add_argument("--org-dir", required=True)
    ap.add_argument("--shared-dir", default=None)
    ap.add_argument("--agent", required=True)
    ap.add_argument("--group", default=None)
    sub = ap.add_subparsers(dest="verb", required=True)
    s = sub.add_parser("show", allow_abbrev=False); s.add_argument("-n", type=int, default=30)
    s = sub.add_parser("set", allow_abbrev=False)
    s.add_argument("--enable", action="append", default=[])
    s.add_argument("--disable", action="append", default=[])
    s.add_argument("--approvable", action="append", default=[])
    s.add_argument("--by", required=True)
    s.add_argument("--via", choices=("cli", "api"), default="cli")
    return ap


def main(argv: list[str]) -> int:
    args = _build_parser().parse_args(argv)
    if not args.shared_dir:
        args.shared_dir = str(Path(args.org_dir).parent / "shared")
    try:
        out = (cmd_show if args.verb == "show" else cmd_set)(args)
    except (StoreError, tc.CatalogError) as e:
        print(json.dumps({"ok": False, "error": str(e)}))
        return 2
    print(json.dumps(out, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
