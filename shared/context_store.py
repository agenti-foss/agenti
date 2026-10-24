#!/usr/bin/env python3
"""context_store.py — the instruction files that shape an agent's behaviour,
with edit history, and the snapshot a run actually reads. Root-side, stdlib.

THE FILES (each plain text, at most MAX_BYTES):

  system-prompt   per agent      REQUIRED. What the agent is for and how it works.
  skills          per agent      optional. Techniques it may try with its existing tools.
  platform-skills platform-wide  optional. The same, for every agent.
  org             organisation   optional. The organisation's own policies and context.
  memory          per agent and user
                                 optional. One user's preferences for that agent.

WHERE THEY LIVE. Edited copies are under directories only root can enter:

  <root>/shared/context/agents/<agent>/{system-prompt,skills}.md
  <root>/shared/context/platform/skills.md
  <root>/org/context/org.md
  <root>/org/context/memory/<agent>/<user>.md

system-prompt and skills also ship a DEFAULT with the agent's code, at
<agent's code folder>/context/<name>.md (the package's agents folder for a
shipped agent, <root>/shared/agents/<agent>/ for one built in Settings). The edited copy wins; `reset`
deletes it and the default applies again. Every save first archives what it
replaces under a `.versions/` directory beside the file, with one history line
(who, when, how, the content hash), so `revert` can bring any version back.

WHAT A RUN READS. Never these directories. Before each start the root CLI calls
`snapshot`, which writes the effective files into the run's own folder as
`run-context/<name>.md` plus `run-context/versions.json` (each file's source
and sha256). That folder is root-owned and only readable by the service
account, so an agent can read its instructions but cannot write, replace or
delete them, and the report records exactly which versions it ran with.

NONE OF THESE FILES WIDENS ANYTHING. They are text the model reads. Scope,
tools, caps and isolation are enforced in code and root-owned files; the
prompt builder (agent_runtime.compose_instructions) tells the model the same.
"""
from __future__ import annotations

import argparse
import grp
import hashlib
import json
import os
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import paths as agenti_paths  # noqa: E402  (where Agenti's files live)

MAX_BYTES = 20_000
KINDS = ("system-prompt", "skills", "platform-skills", "org", "memory")
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
USER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@-]{0,63}$")
# The snapshot's file names, in the order the prompt builder layers them.
SNAPSHOT_ORDER = ("system-prompt", "org", "platform-skills", "skills", "memory")
SNAPSHOT_DIR = "run-context"


class StoreError(Exception):
    pass


def _need(value, pattern, what):
    if not value or not pattern.match(value):
        raise StoreError(f"invalid {what} {value!r}")
    return value


def paths(root: Path, kind: str, *, agent: str = "", user: str = "") -> tuple[Path, Path | None]:
    """(edited copy, shipped default or None) for one file."""
    root = Path(root)
    if kind not in KINDS:
        raise StoreError(f"unknown file {kind!r} — one of: {', '.join(KINDS)}")
    if kind in ("system-prompt", "skills"):
        _need(agent, NAME_RE, "agent name")
        return (root / "shared" / "context" / "agents" / agent / f"{kind}.md",
                agenti_paths.master_dir(agent, root) / "context" / f"{kind}.md")
    if kind == "platform-skills":
        return root / "shared" / "context" / "platform" / "skills.md", None
    if kind == "org":
        return root / "org" / "context" / "org.md", None
    _need(agent, NAME_RE, "agent name")
    _need(user, USER_RE, "user name")
    return root / "org" / "context" / "memory" / agent / f"{user}.md", None


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _read(path: Path | None) -> str | None:
    if path is None:
        return None
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    except OSError as e:
        raise StoreError(f"cannot read {path}: {e}")


def effective(edited: Path, default: Path | None) -> tuple[str, str]:
    """(text, source) — source is 'edited', 'default' or 'none'."""
    t = _read(edited)
    if t is not None:
        return t, "edited"
    t = _read(default)
    if t is not None:
        return t, "default"
    return "", "none"


def validate_text(text: str) -> str:
    if "\x00" in text:
        raise StoreError("the text contains a NUL byte")
    text = text.replace("\r\n", "\n")
    size = len(text.encode("utf-8"))
    if size > MAX_BYTES:
        raise StoreError(f"the text is {size:,} bytes; the limit is {MAX_BYTES:,} "
                         f"(every byte is sent to the model on every run)")
    return text


def _versions_dir(edited: Path) -> Path:
    return edited.parent / ".versions" / edited.stem


def _private_dirs(path: Path) -> None:
    """Create every MISSING directory down to `path` as 0700, so no agent
    account can enter any of them (the org folder is group-readable by the
    service account; a 0755 context/ inside it would leak org.md and every
    user's memory to every run)."""
    missing = []
    p = Path(path)
    while not p.exists():
        missing.append(p)
        p = p.parent
    for d in reversed(missing):
        d.mkdir(mode=0o700)
        os.chmod(d, 0o700)


def _write(path: Path, text: str) -> None:
    _private_dirs(path.parent)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        tmp.write_text(text, encoding="utf-8")
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except OSError as e:
        tmp.unlink(missing_ok=True)
        raise StoreError(f"cannot write {path}: {e}")


def _history_row(edited: Path, row: dict) -> None:
    vd = _versions_dir(edited)
    _private_dirs(vd)
    with open(vd / "history.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps(row, ensure_ascii=False) + "\n")


def _archive(edited: Path, text: str, sha: str) -> str:
    vd = _versions_dir(edited)
    _private_dirs(vd)
    vid = f"{int(time.time() * 1000)}-{sha[:12]}"
    (vd / f"{vid}.md").write_text(text, encoding="utf-8")
    os.chmod(vd / f"{vid}.md", 0o600)
    return vid


def show(root, kind, **who) -> dict:
    edited, default = paths(root, kind, **who)
    text, source = effective(edited, default)
    return {"ok": True, "kind": kind, **who, "source": source, "text": text,
            "sha256": _sha(text) if source != "none" else None,
            "bytes": len(text.encode("utf-8")), "max_bytes": MAX_BYTES,
            "has_default": default is not None and default.exists(),
            "required": kind == "system-prompt"}


def set_text(root, kind, text: str, *, by: str, via: str = "cli", note: str = "",
             **who) -> dict:
    edited, default = paths(root, kind, **who)
    text = validate_text(text)
    old_text, old_source = effective(edited, default)
    if kind == "system-prompt" and not text.strip():
        raise StoreError("the system prompt is required and cannot be empty "
                         "(use reset to go back to the shipped default)")
    if old_source != "none" and old_text == text:
        return {**show(root, kind, **who), "unchanged": True}
    archived = _archive(edited, old_text, _sha(old_text)) if old_source == "edited" else None
    _write(edited, text)
    _history_row(edited, {"ts": time.time(), "by": by, "via": via, "action": "set",
                          "sha256": _sha(text), "bytes": len(text.encode("utf-8")),
                          "replaced": archived, "note": note[:200]})
    return {**show(root, kind, **who), "unchanged": False}


def append_text(root, kind, text: str, *, by: str, via: str = "cli", note: str = "", **who) -> dict:
    """Add `text` to the end of an existing file (used to apply an approved
    memory suggestion). Same size limit and history as set."""
    edited, default = paths(root, kind, **who)
    old, _src = effective(edited, default)
    joined = (old.rstrip("\n") + "\n\n" if old.strip() else "") + text.strip() + "\n"
    return set_text(root, kind, joined, by=by, via=via, note=note or "appended", **who)


def reset(root, kind, *, by: str, via: str = "cli", **who) -> dict:
    edited, default = paths(root, kind, **who)
    old = _read(edited)
    if old is None:
        return {**show(root, kind, **who), "unchanged": True}
    archived = _archive(edited, old, _sha(old))
    edited.unlink()
    _history_row(edited, {"ts": time.time(), "by": by, "via": via, "action": "reset",
                          "replaced": archived})
    return {**show(root, kind, **who), "unchanged": False}


def history(root, kind, n: int = 50, **who) -> dict:
    edited, _d = paths(root, kind, **who)
    rows = []
    try:
        for line in (_versions_dir(edited) / "history.jsonl").read_text(encoding="utf-8").splitlines():
            try:
                rows.append(json.loads(line))
            except ValueError:
                continue
    except FileNotFoundError:
        pass
    return {"ok": True, "kind": kind, **who, "history": rows[-n:][::-1]}


def version_text(root, kind, version: str, **who) -> str:
    edited, _d = paths(root, kind, **who)
    if not re.match(r"^\d+-[0-9a-f]{12}$", version or ""):
        raise StoreError(f"invalid version id {version!r}")
    t = _read(_versions_dir(edited) / f"{version}.md")
    if t is None:
        raise StoreError(f"no saved version {version}")
    return t


def revert(root, kind, version: str, *, by: str, via: str = "cli", **who) -> dict:
    return set_text(root, kind, version_text(root, kind, version, **who),
                    by=by, via=via, note=f"revert to {version}", **who)



# ---------------------------------------------------------------------------
# Memory suggestions: an agent may SUGGEST a line for its user's preferences
# (agent_runtime.make_suggest_preference_tool). It writes the suggestion into
# its own run's state/ folder — the only place it can write. Nothing changes
# until that user approves it; approval appends it to memory.md through the
# normal history. The agent-written file is untrusted: it is read here as
# root, so it is opened without following links, only if it really lies
# inside the slot, size-capped, and every field is re-validated.
# ---------------------------------------------------------------------------
PROPOSALS_FILE = "memory-proposals.jsonl"
MAX_PROPOSAL_CHARS = 300
MAX_PROPOSALS_READ = 50


def _safe_read_bytes(slot: Path, rel: str, cap: int = 64_000) -> bytes | None:
    """Read a file the AGENT can write (its own state/ folder) as root through
    run_files.open_in_slot: a descriptor walk that never follows a link and
    opens only a plain, singly-linked file without blocking. A FIFO planted
    here used to hang the root reader and the web request behind it (audit
    run 2)."""
    import run_files
    try:
        fh, _size = run_files.open_in_slot(slot, rel)
    except run_files.FilesError:
        return None
    with fh:
        return fh.read(cap)


def _user_slots(root: Path, agent: str, user: str) -> list[Path]:
    base = Path(root) / "org" / agent / "instances"
    if not base.is_dir():
        return []
    return sorted(p for p in base.iterdir()
                  if p.is_dir() and not p.is_symlink()
                  and (p.name == user or p.name.startswith(user + ".")) and ".team-" not in p.name)


def _decided_path(root: Path, agent: str, user: str) -> Path:
    return Path(root) / "org" / "context" / "memory-decisions" / agent / f"{user}.json"


def _decided(root, agent, user) -> dict:
    try:
        return json.loads(_decided_path(root, agent, user).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def list_proposals(root, *, agent: str, user: str) -> dict:
    _need(agent, NAME_RE, "agent name"); _need(user, USER_RE, "user name")
    decided = _decided(root, agent, user)
    out = []
    for slot in _user_slots(Path(root), agent, user):
        raw = _safe_read_bytes(slot, f"state/{PROPOSALS_FILE}")
        if not raw:
            continue
        for line in raw.decode("utf-8", errors="replace").splitlines()[-MAX_PROPOSALS_READ:]:
            try:
                row = json.loads(line)
            except ValueError:
                continue
            text = row.get("text") if isinstance(row, dict) else None
            ts = row.get("ts") if isinstance(row, dict) else None
            if not isinstance(text, str) or not text.strip() or not isinstance(ts, (int, float)):
                continue
            text = " ".join(text.split())[:MAX_PROPOSAL_CHARS]
            pid = hashlib.sha256(f"{slot.name}|{ts}|{text}".encode()).hexdigest()[:12]
            if pid in decided:
                continue
            out.append({"id": pid, "text": text, "ts": ts, "slot": slot.name})
    out.sort(key=lambda r: r["ts"])
    return {"ok": True, "agent": agent, "user": user, "proposals": out}


def decide_proposal(root, *, agent: str, user: str, pid: str,
                    decision: str, by: str, via: str = "api") -> dict:
    if decision not in ("approve", "dismiss"):
        raise StoreError("decision must be approve or dismiss")
    if not re.fullmatch(r"[0-9a-f]{12}", pid or ""):
        raise StoreError("not a suggestion id")
    pending = {p["id"]: p for p in list_proposals(root, agent=agent, user=user)["proposals"]}
    if pid not in pending:
        raise StoreError("that suggestion is no longer pending (already decided, or the run that made it was removed)")
    if decision == "approve":
        append_text(root, "memory", pending[pid]["text"], by=by, via=via,
                    note="approved agent suggestion", agent=agent, user=user)
    path = _decided_path(root, agent, user)
    decided = _decided(root, agent, user)
    decided[pid] = {"decision": decision, "by": by, "ts": time.time(), "text": pending[pid]["text"]}
    _write(path, json.dumps(decided, indent=1))
    return {"ok": True, "id": pid, "decision": decision}


def snapshot(root, *, agent: str, owner: str, dest: Path,
             group: str | None) -> dict:
    """Write this run's effective files into <dest>/run-context/. Refuses when
    there is no system prompt. Old snapshot files are replaced as a whole."""
    dest = Path(dest)
    if not dest.is_dir():
        raise StoreError(f"run folder {dest} does not exist")
    gid = grp.getgrnam(group).gr_gid if group else None
    picked = {
        "system-prompt": paths(root, "system-prompt", agent=agent),
        "skills": paths(root, "skills", agent=agent),
        "platform-skills": paths(root, "platform-skills"),
        "org": paths(root, "org"),
    }
    if owner and USER_RE.match(owner):
        picked["memory"] = paths(root, "memory", agent=agent, user=owner)
    out_dir = dest / SNAPSHOT_DIR
    out_dir.mkdir(exist_ok=True)
    os.chmod(out_dir, 0o750)
    if os.geteuid() == 0 and gid is not None:
        os.chown(out_dir, 0, gid)
    versions: dict = {}
    for name in SNAPSHOT_ORDER:
        target = out_dir / f"{name}.md"
        if name not in picked:
            target.unlink(missing_ok=True)
            continue
        text, source = effective(*picked[name])
        if name == "system-prompt" and not text.strip():
            raise StoreError(
                f"agent '{agent}' has no system prompt, so it cannot run. A global admin "
                f"writes one in Settings → Agents, or reinstall the package to restore its "
                f"shipped default:  sudo apt install --reinstall agenti")
        if source == "none" or not text.strip():
            target.unlink(missing_ok=True)
            continue
        tmp = out_dir / f".{name}.tmp"
        tmp.write_text(text, encoding="utf-8")
        os.chmod(tmp, 0o640)
        if os.geteuid() == 0 and gid is not None:
            os.chown(tmp, 0, gid)
        os.replace(tmp, target)
        versions[name] = {"source": source, "sha256": _sha(text),
                          "bytes": len(text.encode("utf-8"))}
    vtmp = out_dir / ".versions.json.tmp"
    vtmp.write_text(json.dumps({"agent": agent, "owner": owner,
                                "taken_at": time.time(), "files": versions}, indent=2))
    os.chmod(vtmp, 0o640)
    if os.geteuid() == 0 and gid is not None:
        os.chown(vtmp, 0, gid)
    os.replace(vtmp, out_dir / "versions.json")
    return {"ok": True, "files": versions}


def _main(argv) -> int:
    ap = argparse.ArgumentParser(allow_abbrev=False, prog="context_store.py",
                                 description="read/write an agent's instruction files (root)")
    ap.add_argument("--root", default=str(agenti_paths.data_root()))
    sub = ap.add_subparsers(dest="verb", required=True)

    def who(p):
        p.add_argument("kind", choices=KINDS)
        p.add_argument("--agent", default="")
        p.add_argument("--user", default="")

    p = sub.add_parser("show", allow_abbrev=False); who(p)
    p = sub.add_parser("set", allow_abbrev=False); who(p)
    p.add_argument("--by", required=True); p.add_argument("--via", default="cli")
    p.add_argument("--file", default="-", help="read the new text from this file ('-' = stdin)")
    p.add_argument("--note", default="")
    p = sub.add_parser("append", allow_abbrev=False); who(p)
    p.add_argument("--by", required=True); p.add_argument("--via", default="cli")
    p.add_argument("--file", default="-"); p.add_argument("--note", default="")
    p = sub.add_parser("reset", allow_abbrev=False); who(p)
    p.add_argument("--by", required=True); p.add_argument("--via", default="cli")
    p = sub.add_parser("history", allow_abbrev=False); who(p); p.add_argument("-n", type=int, default=50)
    p = sub.add_parser("version", allow_abbrev=False); who(p); p.add_argument("version")
    p = sub.add_parser("revert", allow_abbrev=False); who(p); p.add_argument("version")
    p.add_argument("--by", required=True); p.add_argument("--via", default="cli")
    p = sub.add_parser("proposals", allow_abbrev=False)
    p.add_argument("--agent", required=True)
    p.add_argument("--user", required=True)
    p = sub.add_parser("decide", allow_abbrev=False)
    p.add_argument("--agent", required=True)
    p.add_argument("--user", required=True); p.add_argument("id")
    p.add_argument("decision", choices=("approve", "dismiss"))
    p.add_argument("--by", required=True); p.add_argument("--via", default="api")
    p = sub.add_parser("snapshot", allow_abbrev=False)
    p.add_argument("--agent", required=True)
    p.add_argument("--owner", default=""); p.add_argument("--dest", required=True)
    p.add_argument("--group", default=None)

    a = ap.parse_args(argv)
    try:
        if a.verb == "proposals":
            out = list_proposals(a.root, agent=a.agent, user=a.user)
        elif a.verb == "decide":
            out = decide_proposal(a.root, agent=a.agent, user=a.user, pid=a.id,
                                  decision=a.decision, by=a.by, via=a.via)
        elif a.verb == "snapshot":
            out = snapshot(a.root, agent=a.agent, owner=a.owner,
                           dest=Path(a.dest), group=a.group)
        else:
            w = {k: v for k, v in (("agent", a.agent), ("user", a.user)) if v}
            if a.verb == "show":
                out = show(a.root, a.kind, **w)
            elif a.verb == "set":
                raw = sys.stdin.read() if a.file == "-" else Path(a.file).read_text(encoding="utf-8")
                out = set_text(a.root, a.kind, raw, by=a.by, via=a.via, note=a.note, **w)
            elif a.verb == "append":
                raw = sys.stdin.read() if a.file == "-" else Path(a.file).read_text(encoding="utf-8")
                out = append_text(a.root, a.kind, raw, by=a.by, via=a.via, note=a.note, **w)
            elif a.verb == "reset":
                out = reset(a.root, a.kind, by=a.by, via=a.via, **w)
            elif a.verb == "history":
                out = history(a.root, a.kind, a.n, **w)
            elif a.verb == "version":
                out = {"ok": True, "version": a.version,
                       "text": version_text(a.root, a.kind, a.version, **w)}
            else:
                out = revert(a.root, a.kind, a.version, by=a.by, via=a.via, **w)
    except (StoreError, OSError, UnicodeDecodeError, KeyError) as e:
        print(json.dumps({"ok": False, "error": str(e)}))
        return 2
    print(json.dumps(out, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
