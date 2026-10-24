#!/usr/bin/env python3
"""catalog_admin.py — a global admin adds, edits and removes command-line
programs in the tool catalog from the GUI (Settings -> Agents -> Programs).

Reviewed programs (tool-catalog.json in the code folder, replaced by every
upgrade) are read-only here. What an admin adds goes to the data root's
shared/tool-catalog.admin.json, which an upgrade never touches and
tool_catalog.load_catalog() merges in.

Adding a program is the one act that widens what an agent could ever run, so:
  * the program must be INSTALLED on this server (never "type it and hope");
  * it is refused outright if it is a shell, interpreter, privilege or system
    tool, or on the never-allowed list (tool_catalog.BLOCKED_PROGRAMS), by the
    typed name AND by what it resolves to;
  * the API reaches this only with a re-authenticated approval bound to the
    SHA-256 of the exact entry (authd 'edit-catalog');
  * every change is appended to tool-catalog.history.jsonl.
Adding to the catalog does NOT give any agent the program: an admin still has
to switch it on per agent (Controls -> tool allow-list).

    catalog_admin.py --root /var/lib/agenti/data list
    catalog_admin.py --root /var/lib/agenti/data check < entry.json
    catalog_admin.py --root /var/lib/agenti/data add    --by NAME < entry.json
    catalog_admin.py --root /var/lib/agenti/data update --by NAME < entry.json
    catalog_admin.py --root /var/lib/agenti/data remove NAME --by NAME
    catalog_admin.py --root /var/lib/agenti/data history [-n N]
Every subcommand prints one JSON object; failures are {"ok": false, "error"}.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import paths  # noqa: E402
import recon_programs  # noqa: E402
import tool_catalog as tc  # noqa: E402

HISTORY_FILENAME = "tool-catalog.history.jsonl"


def _shared(root: Path) -> Path:
    return root / "shared"


def _reviewed() -> Path:
    """The reviewed catalog: the installed one, else the source tree's."""
    p = paths.catalog_file()
    return p if p.is_file() else HERE / "tool-catalog.json"


def _base(root: Path) -> dict:
    """The reviewed catalog alone (no overlay)."""
    p = _reviewed()
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise tc.CatalogError(f"cannot read the reviewed tool catalog: {e}")
    for pr in data.get("programs", []):
        if isinstance(pr, dict):
            pr["source"] = "reviewed"
    return data


def _overlay_path(root: Path) -> Path:
    return _shared(root) / tc.ADMIN_CATALOG_FILENAME


def _read_overlay(root: Path) -> list[dict]:
    try:
        d = json.loads(_overlay_path(root).read_text(encoding="utf-8"))
        return [e for e in d.get("programs", []) if isinstance(e, dict)]
    except (OSError, ValueError):
        return []


def _write_overlay(root: Path, programs: list[dict]) -> None:
    path = _overlay_path(root)
    fd, tmp = tempfile.mkstemp(prefix=".catalog-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump({"version": 1, "programs": programs}, f, indent=2, ensure_ascii=False)
            f.write("\n")
        os.chmod(tmp, 0o644)
        try:
            os.chown(tmp, 0, 0)
        except PermissionError:
            pass
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _history(root: Path, row: dict) -> None:
    p = _shared(root) / HISTORY_FILENAME
    new = not p.exists()
    with open(p, "a", encoding="utf-8") as f:
        f.write(json.dumps(row, ensure_ascii=False) + "\n")
    if new:
        try:
            os.chmod(p, 0o644)
        except OSError:
            pass


def entry_sha256(entry: dict) -> str:
    blob = json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _hint(name: str) -> str:
    return f"sudo apt install {name}"


def listing(root: Path) -> dict:
    base = _base(root)
    merged = tc.load_catalog(_reviewed(), _shared(root) / tc.ADMIN_CATALOG_FILENAME)
    rows = []
    for p in merged["programs"]:
        path = tc.which_program(p["name"])
        rows.append({**p, "installed": bool(path), "path": path, "install_hint": None if path else _hint(p["name"]),
                     "has_rules": recon_programs.program_for(p["name"]) is not None})
    return {"ok": True, "programs": rows,
            "groups": sorted({r.get("group", "other") for r in rows})}


def check(root: Path, entry, *, updating: bool = False) -> dict:
    base = _base(root)
    taken = {p["name"] for p in base["programs"]}
    admin_names = {e.get("name") for e in _read_overlay(root)}
    if updating:
        if not isinstance(entry, dict) or entry.get("name") in taken:
            raise tc.CatalogError("a reviewed program cannot be edited here — only programs an admin added.")
        if not isinstance(entry, dict) or entry.get("name") not in admin_names:
            raise tc.CatalogError(f"no admin-added program called '{(entry or {}).get('name')}'.")
        clean = tc.validate_entry(entry, base)
    else:
        clean = tc.validate_entry(entry, base, existing=taken | admin_names)
    path = tc.check_installed(clean["name"])
    if not updating and recon_programs.program_for(clean["name"]) is None:
        # Since audit run 1 a recon program runs only with a reviewed list of
        # the options it may take (recon_programs.py); adding one without that
        # list would offer agents a program they can never run.
        raise tc.CatalogError(
            f"Agenti has no reviewed argument rules for '{clean['name']}', so no agent could run it. "
            f"Every option a recon program accepts is reviewed in code, so a typo or a crafted "
            f"instruction cannot widen what it does. Programs with rules: "
            f"{', '.join(recon_programs.names())}. To ask for '{clean['name']}', open an issue "
            f"(docs: Contributing agents).")
    return {"ok": True, "entry": clean, "sha256": entry_sha256(clean), "path": path}


def add(root: Path, entry, *, by: str) -> dict:
    out = check(root, entry)
    clean = out["entry"]
    rows = _read_overlay(root)
    rows.append({**clean, "added_by": by, "added_at": time.time()})
    _write_overlay(root, rows)
    _history(root, {"ts": time.time(), "by": by, "action": "add", "name": clean["name"], "entry": clean})
    return {"ok": True, "added": clean["name"], "path": out["path"]}


def update(root: Path, entry, *, by: str) -> dict:
    out = check(root, entry, updating=True)
    clean = out["entry"]
    rows = _read_overlay(root)
    old = next((e for e in rows if e.get("name") == clean["name"]), {})
    rows = [e for e in rows if e.get("name") != clean["name"]]
    rows.append({**clean, "added_by": old.get("added_by", by), "added_at": old.get("added_at", time.time())})
    _write_overlay(root, rows)
    _history(root, {"ts": time.time(), "by": by, "action": "update", "name": clean["name"], "entry": clean})
    return {"ok": True, "updated": clean["name"]}


def users_of(root: Path, name: str) -> list[str]:
    """Every <agent> whose tool-settings.json still switches this
    program on (always-allowed or offered to operators)."""
    out = []
    for tf in sorted(root.glob("*/*/tool-settings.json")):
        if tf.parent.parent.name == "shared":
            continue
        try:
            d = json.loads(tf.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if name in (d.get("enable") or []) or name in (d.get("approvable") or []):
            out.append(f"{tf.parent.parent.name}/{tf.parent.name}")
    return out


def remove(root: Path, name: str, *, by: str) -> dict:
    base_names = {p["name"] for p in _base(root)["programs"]}
    if name in base_names:
        raise tc.CatalogError(f"'{name}' is a reviewed program and cannot be removed here.")
    rows = _read_overlay(root)
    if not any(e.get("name") == name for e in rows):
        raise tc.CatalogError(f"no admin-added program called '{name}'.")
    inuse = users_of(root, name)
    if inuse:
        raise tc.CatalogError(f"'{name}' is still switched on for {', '.join(inuse)}. "
                              f"Turn it off there first (Controls -> tool allow-list).")
    _write_overlay(root, [e for e in rows if e.get("name") != name])
    _history(root, {"ts": time.time(), "by": by, "action": "remove", "name": name})
    return {"ok": True, "removed": name}


def history(root: Path, n: int) -> dict:
    p = _shared(root) / HISTORY_FILENAME
    rows = []
    if p.exists():
        for line in p.read_text(encoding="utf-8").splitlines()[-n:]:
            try:
                rows.append(json.loads(line))
            except ValueError:
                continue
    return {"ok": True, "history": rows[::-1]}


def _stdin():
    try:
        return json.loads(sys.stdin.read(100_000))
    except ValueError as e:
        raise tc.CatalogError(f"the entry is not valid JSON: {e}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(allow_abbrev=False, description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", default=str(paths.data_root()))
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list", allow_abbrev=False); sub.add_parser("check", allow_abbrev=False)
    for c in ("add", "update"):
        q = sub.add_parser(c, allow_abbrev=False); q.add_argument("--by", required=True)
    q = sub.add_parser("remove", allow_abbrev=False); q.add_argument("name"); q.add_argument("--by", required=True)
    q = sub.add_parser("history", allow_abbrev=False); q.add_argument("-n", type=int, default=50)
    sub.add_parser("check-update", allow_abbrev=False)
    a = ap.parse_args(argv)
    root = Path(a.root)
    try:
        if a.cmd == "list":
            out = listing(root)
        elif a.cmd == "check":
            out = check(root, _stdin())
        elif a.cmd == "check-update":
            out = check(root, _stdin(), updating=True)
        elif a.cmd == "add":
            out = add(root, _stdin(), by=a.by)
        elif a.cmd == "update":
            out = update(root, _stdin(), by=a.by)
        elif a.cmd == "remove":
            out = remove(root, a.name, by=a.by)
        else:
            out = history(root, a.n)
    except tc.CatalogError as e:
        print(json.dumps({"ok": False, "error": str(e)}))
        return 1
    print(json.dumps(out, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
