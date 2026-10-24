#!/usr/bin/env python3
"""agent_builder.py — build (or remove) a whole agent from a short spec,
for Settings -> Agents -> "Build an agent".

A built agent is DATA, never code. There are two kinds (KINDS below):

  recon     probes hosts and networks inside the organisation's engagement
            scope. It may run reviewed command-line programs chosen from the
            baseline recon list and the reviewed catalog
            (shared/tool-catalog.json), nothing on the catalog's block list
            (shells, interpreters, exploitation tooling...). Run by
            shared/recon_runner.py, the same code enum runs.
  analysis  analyses FILES an operator attaches to a run (packet captures
            today), in a sandbox. It may use the programs listed in
            shared/analysis_programs.py, each with its own reviewed option
            rules. It touches no network and needs no engagement. Run by
            shared/analysis_runner.py.

The spec names a kind, a short name, a display title, a one-line description,
the programs, and the system prompt (system-prompt.md).

What gets written to shared/agents/<name>/ is a fixed three-line stub that
calls the kind's runner, a manifest.json, the capability descriptor and the
shipped system prompt (and, for analysis, the .capabilities file that gives it
the sandbox). Nothing typed into the form ever becomes code: the stub is a
constant per kind, every field is stored as JSON data, the tools are fixed per
kind, and the runner re-checks every program at run time.

The root CLI calls this (agenti admin agent-build ...); it never runs as the
API account. Every subcommand prints one JSON object; failures are
{"ok": false, "error": "..."} with exit 1.

    agent_builder.py --root /var/lib/agenti/data catalog
    agent_builder.py --root /var/lib/agenti/data check            < spec.json
    agent_builder.py --root /var/lib/agenti/data write --by NAME  < spec.json
    agent_builder.py --root /var/lib/agenti/data describe NAME
    agent_builder.py --root /var/lib/agenti/data delete-files NAME
"""
from __future__ import annotations

import argparse
import grp
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unicodedata
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import paths  # noqa: E402  (where Agenti's files live)

NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
# Words the CLI or the API already uses where an agent name goes (mirrors
# api/cli_bridge.py's RESERVED_NAMES) plus the vault's own folders.
RESERVED = frozenset({
    "shared", "lost+found", "list", "lib", "agents",
    "new", "admin", "vault", "gui", "help", "docs", "setup", "verify",
    "team", "outputs", "tool-requests",
    "engagement", "dashboard", "principals", "users", "bindings", "principal-history",
    "user-history", "rename",
    "context", "instances", "copies",
})
MAX_TITLE = 60
MAX_DESCRIPTION = 200
MAX_PROMPT_BYTES = 20000
MIN_PROMPT_CHARS = 20
SHARED_GROUP = "agenti-shared"

_STUB = '''#!/usr/bin/env python3
"""{{name}} — built in Settings -> Agents. Its programs and description are in
manifest.json beside this file; shared/{runner}.py runs it. This file is
the same for every built agent of its kind and is never edited by hand.
"""
import sys
from pathlib import Path

import {runner}

if __name__ == "__main__":
    sys.exit({runner}.main(Path(__file__).resolve().parent / "manifest.json"))
'''

# One entry per kind of agent a form can build. Adding a kind is a developer
# act (a runner, its tools, its rules), never something a spec can do.
KINDS = {
    "recon": {
        "title": "Network recon",
        "blurb": "Probes hosts and networks inside the organisation's engagement scope with reviewed "
                 "command-line programs. Started with a target.",
        "stub": _STUB.format(runner="recon_runner"),
        "scope_kind": "cidr",
        "category": "cybersecurity",
        "tool_names": ["run_scan", "read_scan"],
        "capabilities": None,          # keeps the unit's default (raw sockets, for nmap)
    },
    "analysis": {
        "title": "File analysis",
        "blurb": "Analyses files you attach to a run, such as a packet capture, in a sandbox with no "
                 "network. Needs no target or engagement.",
        "stub": _STUB.format(runner="analysis_runner"),
        "scope_kind": "files",
        "category": "file-analysis",
        "tool_names": ["analyze_file", "read_output"],
        # The unit gets CAP_SYS_ADMIN in its bounding set (for bubblewrap) and
        # loses the raw-socket capabilities it has no use for.
        "capabilities": "CAP_SYS_ADMIN",
    },
}
DEFAULT_KIND = "recon"


class BuildError(Exception):
    pass


# ---------------------------------------------------------------------------
# where things are
# ---------------------------------------------------------------------------
def _lib_dirs(root: Path):
    return [d for d in (paths.libdir(), HERE) if d.is_dir()]


def _import_catalog_module(root: Path):
    """tool_catalog from the installed code folder, falling back to the
    source tree beside this file. Pure stdlib."""
    for d in _lib_dirs(root):
        if (d / "tool_catalog.py").is_file():
            if str(d) not in sys.path:
                sys.path.insert(0, str(d))
            import tool_catalog  # noqa: E402
            return tool_catalog
    raise BuildError("tool_catalog.py is not installed. Reinstall: sudo apt install --reinstall agenti")


def _load_catalog(root: Path):
    tc = _import_catalog_module(root)
    for p in (paths.catalog_file(), HERE / "tool-catalog.json"):
        if p.is_file():
            try:
                return tc, tc.load_catalog(p, root / "shared" / tc.ADMIN_CATALOG_FILENAME)
            except tc.CatalogError as e:
                raise BuildError(str(e))
    raise BuildError("tool-catalog.json is not installed. Reinstall: sudo apt install --reinstall agenti")


def master_dir(root: Path, name: str) -> Path:
    """Where an agent built here lives: the data root, never the package's
    own (read-only) agents folder."""
    return paths.built_agents(root) / name


# ---------------------------------------------------------------------------
# the catalog: what the form may offer
# ---------------------------------------------------------------------------
def offered_programs(root: Path) -> list[dict]:
    """Every program a built agent may be given: the baseline recon list, then
    the reviewed catalog, then admin-added entries — each with whether it is
    installed on this server right now."""
    tc, cat = _load_catalog(root)
    rows = []
    for b in tc.baseline_programs(cat):
        rows.append({"name": b["name"], "group": b["group"], "purpose": b["purpose"], "source": "baseline"})
    for p in cat.get("programs", []):
        if isinstance(p, dict) and p.get("name"):
            rows.append({"name": p["name"], "group": str(p.get("group") or ""),
                         "purpose": str(p.get("purpose") or ""), "source": str(p.get("source") or "reviewed")})
    for r in rows:
        r["installed"] = bool(tc.which_program(r["name"]))
    return rows


def _analysis_module(root: Path):
    """analysis_programs from the installed code folder, falling back
    to the source tree beside this file. Pure stdlib."""
    for d in _lib_dirs(root):
        if (d / "analysis_programs.py").is_file():
            if str(d) not in sys.path:
                sys.path.insert(0, str(d))
            import analysis_programs
            return analysis_programs
    raise BuildError("analysis_programs.py is not installed. Reinstall: sudo apt install --reinstall agenti")


def offered_analysis_programs(root: Path) -> list[dict]:
    """The programs a file-analysis agent may be given: the ones with reviewed
    option rules in analysis_programs.py, and whether each is installed."""
    return [{"name": p["name"], "group": "analysis", "purpose": p["purpose"], "source": "reviewed",
             "installed": p["installed"], "examples": p["examples"],
             "package": p.get("package") or p["name"]}
            for p in _analysis_module(root).offered()]


def programs_for(root: Path, kind: str) -> list[dict]:
    return offered_analysis_programs(root) if kind == "analysis" else offered_programs(root)


def catalog(root: Path) -> dict:
    """What the form may offer. `programs` is the recon list (kept as it was,
    for older callers); `kinds` carries each kind's own list and wording."""
    kinds = []
    for kid, k in KINDS.items():
        kinds.append({"id": kid, "title": k["title"], "blurb": k["blurb"],
                      "programs": programs_for(root, kid)})
    return {"ok": True, "programs": offered_programs(root), "kinds": kinds,
            "limits": {"title": MAX_TITLE, "description": MAX_DESCRIPTION,
                       "prompt_bytes": MAX_PROMPT_BYTES, "name": 32}}


# ---------------------------------------------------------------------------
# validating a spec — everything that can refuse, before anything is written
# ---------------------------------------------------------------------------
def _one_line(value, field: str, limit: int, *, required: bool) -> str:
    if value is None:
        value = ""
    if not isinstance(value, str):
        raise BuildError(f"{field} must be text.")
    value = " ".join(value.split())
    if required and not value:
        raise BuildError(f"{field} is required.")
    if len(value) > limit:
        raise BuildError(f"{field} is too long ({len(value)} characters; the limit is {limit}).")
    if any(unicodedata.category(c) in ("Cc", "Cf") for c in value):
        raise BuildError(f"{field} contains control characters.")
    return value


def normalize(raw, root: Path, *, for_create: bool = True) -> dict:
    """The one canonical form of a spec. The approval grant is bound to the
    SHA-256 of exactly this, so the API asking for approval and the root CLI
    building the agent must arrive at the same bytes."""
    if not isinstance(raw, dict):
        raise BuildError("the spec must be a JSON object.")
    unknown = set(raw) - {"kind", "name", "title", "description", "programs", "system_prompt"}
    if unknown:
        raise BuildError(f"unknown field(s): {', '.join(sorted(unknown))}.")
    kind = raw.get("kind", DEFAULT_KIND)
    if kind not in KINDS:
        raise BuildError(f"the kind must be one of: {', '.join(KINDS)} (not {kind!r}).")
    name = raw.get("name")
    if not isinstance(name, str) or not NAME_RE.match(name):
        raise BuildError("the short name must be 1-32 characters: lowercase letters, digits "
                         "and hyphens, starting with a letter (e.g. invoice-helper).")
    if name in RESERVED:
        raise BuildError(f"'{name}' is reserved (the CLI or web API already uses it). Pick another short name.")
    if for_create and (master_dir(root, name).exists() or (paths.shipped_agents() / name).exists()):
        raise BuildError(f"an agent called '{name}' already exists. Pick another short name.")
    title = _one_line(raw.get("title"), "The name", MAX_TITLE, required=True)
    description = _one_line(raw.get("description"), "The description", MAX_DESCRIPTION, required=True)

    programs = raw.get("programs")
    if not isinstance(programs, list) or not programs or not all(isinstance(t, str) for t in programs):
        raise BuildError("pick at least one program.")
    offered = {p["name"]: p for p in programs_for(root, kind)}
    for t in programs:
        if t not in offered:
            if kind == "analysis":
                raise BuildError(f"'{t}' is not a program a file-analysis agent may run. The reviewed "
                                 f"ones are: {', '.join(sorted(offered))}. A developer adds a program "
                                 f"with its option rules to shared/analysis_programs.py.")
            raise BuildError(f"'{t}' is not a program a built agent may run. Only the baseline recon "
                             f"programs and the reviewed catalog are offered (an admin can add one in "
                             f"Settings -> Agents -> Program catalog).")
        if not offered[t]["installed"]:
            pkg = offered[t].get("package") or t              # capinfos ships in the tshark package
            raise BuildError(f"'{t}' is not installed on this server (sudo apt install {pkg}), "
                             f"so an agent built with it could not run it.")
    # Offered order, no duplicates: the same choice always hashes the same.
    order = [n for n in offered if n in set(programs)]

    prompt = raw.get("system_prompt")
    if not isinstance(prompt, str):
        raise BuildError("the instructions (system prompt) are required.")
    prompt = prompt.replace("\r\n", "\n").strip() + "\n"
    if len(prompt.strip()) < MIN_PROMPT_CHARS:
        raise BuildError(f"the instructions are too short — say what the agent is for, what it "
                         f"should produce, and anything it must not do (at least {MIN_PROMPT_CHARS} characters).")
    if len(prompt.encode("utf-8")) > MAX_PROMPT_BYTES:
        raise BuildError(f"the instructions are too long (limit {MAX_PROMPT_BYTES:,} bytes).")
    if "\x00" in prompt:
        raise BuildError("the instructions contain a NUL character.")

    return {"kind": kind, "name": name, "title": title, "description": description,
            "programs": order, "system_prompt": prompt}


def spec_sha256(spec: dict) -> str:
    blob = json.dumps(spec, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def manifest_for(spec: dict, root: Path, *, by: str) -> dict:
    kind = spec["kind"]
    k = KINDS[kind]
    purposes = {p["name"]: p["purpose"] for p in programs_for(root, kind)}
    return {
        "name": spec["name"],
        "title": spec["title"],
        "description": spec["description"],
        "kind": kind,
        "scope_kind": k["scope_kind"],
        "tool_names": list(k["tool_names"]),
        "category": k["category"],
        "programs": [{"name": n, "purpose": purposes.get(n, "")} for n in spec["programs"]],
        "built": {"by": by, "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())},
    }


# ---------------------------------------------------------------------------
# writing the master copy
# ---------------------------------------------------------------------------
def _gen_capabilities() -> Path:
    for d in (HERE, paths.libdir()):
        if (d / "gen_capabilities.py").is_file():
            return d / "gen_capabilities.py"
    raise BuildError("gen_capabilities.py is not installed. Reinstall: sudo apt install --reinstall agenti")


def _write_descriptor_files(tmp: Path, spec: dict, root: Path, man: dict, *, with_stub: bool = True) -> None:
    """manifest.json and the generated capabilities.json (and, for a new
    agent, the constant stub of its kind). Shared by write() and update()."""
    name = spec["name"]
    if with_stub:
        (tmp / f"{name}-agent.py").write_text(KINDS[spec["kind"]]["stub"].format(name=name))
    (tmp / "manifest.json").write_text(json.dumps(man, indent=2, ensure_ascii=False) + "\n")
    env = dict(os.environ, PYTHONPATH=os.pathsep.join(str(p) for p in _lib_dirs(root)))
    out = subprocess.run([sys.executable, str(_gen_capabilities()), str(tmp / f"{name}-agent.py")],
                         capture_output=True, text=True, timeout=60, env=env)
    if out.returncode != 0:
        raise BuildError(f"could not describe the agent: {out.stderr.strip()[:300]}")
    desc = json.loads(out.stdout)
    listed = [i.get("name") for i in (desc.get("command_line_tools") or {}).get("items") or []]
    if listed != spec["programs"]:
        raise BuildError("could not describe the agent's programs (is the code installed? "
                         "sudo apt install --reinstall agenti)")
    (tmp / "capabilities.json").write_text(out.stdout)


def _write_capabilities_file(tmp: Path, spec: dict) -> None:
    """The <name>.capabilities file a shipped agent carries, for a hand-built
    agent: what the unit may be granted. A recon agent has none (it keeps the
    unit default). A file-analysis agent asks for CAP_SYS_ADMIN, bounding set
    only, which is what lets bubblewrap build its sandbox, and by naming
    nothing else gives up the raw-socket capabilities. render_capability_dropin
    (capability-dropin.sh) turns it into the unit drop-in."""
    caps = KINDS[spec["kind"]]["capabilities"]
    path = tmp / f"{spec['name']}.capabilities"
    if not caps:
        path.unlink(missing_ok=True)
        return
    path.write_text("# Written by agent_builder.py for a file-analysis agent. CAP_SYS_ADMIN is for\n"
                    "# bubblewrap's sandbox (bounding set only, never ambient); naming nothing else\n"
                    "# drops the raw-socket capabilities this agent has no use for.\n"
                    f"{caps}\n")
    os.chown(path, 0, 0)
    os.chmod(path, 0o644)


def write(spec: dict, root: Path, *, by: str) -> dict:
    """Write shared/agents/<name>/ atomically: everything is built in a hidden
    sibling folder and renamed into place, so a half-built agent is never
    visible to `agenti agents` or the unit."""
    agents = root / "shared" / "agents"
    final = master_dir(root, spec["name"])
    if final.exists():
        raise BuildError(f"an agent called '{spec['name']}' already exists.")
    try:
        gid = grp.getgrnam(SHARED_GROUP).gr_gid
    except KeyError:
        raise BuildError(f"the {SHARED_GROUP} group does not exist — reconfigure: sudo dpkg-reconfigure agenti")
    tmp = Path(tempfile.mkdtemp(prefix=f".build-{spec['name']}-", dir=agents))
    try:
        name = spec["name"]
        man = manifest_for(spec, root, by=by)
        _write_descriptor_files(tmp, spec, root, man)
        _write_capabilities_file(tmp, spec)
        ctx = tmp / "context"
        ctx.mkdir()
        (ctx / "system-prompt.md").write_text(spec["system_prompt"])

        # Readable by the service account (via the shared group), writable by root only.
        for p in (tmp / f"{name}-agent.py", tmp / "manifest.json"):
            os.chown(p, 0, gid); os.chmod(p, 0o640)
        os.chown(tmp / "capabilities.json", 0, 0); os.chmod(tmp / "capabilities.json", 0o644)
        os.chown(ctx, 0, 0); os.chmod(ctx, 0o700)
        os.chown(ctx / "system-prompt.md", 0, 0); os.chmod(ctx / "system-prompt.md", 0o600)
        os.chown(tmp, 0, gid); os.chmod(tmp, 0o751)
        os.rename(tmp, final)
    except BaseException:
        shutil.rmtree(tmp, ignore_errors=True)
        raise
    return {"ok": True, "name": spec["name"], "title": spec["title"], "master_dir": str(final),
            "programs": spec["programs"]}


# ---------------------------------------------------------------------------
# editing a built agent: name stays, everything else but the instructions may
# change (instructions have their own editor with history and revert)
# ---------------------------------------------------------------------------
def normalize_update(raw, root: Path) -> dict:
    if not isinstance(raw, dict):
        raise BuildError("the spec must be a JSON object.")
    if "system_prompt" in raw:
        raise BuildError("instructions are edited in the control centre, not here.")
    # The kind is fixed when an agent is built: a recon agent cannot become a
    # file-analysis one (different runner, tools and unit privileges). So the
    # kind is read from the agent itself, and a spec that names another is refused.
    existing = describe_built(root, raw.get("name"))
    if raw.get("kind", existing["kind"]) != existing["kind"]:
        raise BuildError(f"'{existing['name']}' is a {existing['kind']} agent; its kind cannot be changed. "
                         f"Build a new agent of the other kind instead.")
    full = normalize({**raw, "kind": existing["kind"], "system_prompt": "x" * MIN_PROMPT_CHARS},
                     root, for_create=False)
    full.pop("system_prompt")
    return full


def update(spec: dict, root: Path, *, by: str) -> dict:
    """Rewrite manifest.json and capabilities.json for a built agent, atomically (the whole folder is swapped). A run already in
    progress keeps what it started with; the next start uses the new settings."""
    name = spec["name"]
    old = describe_built(root, name)
    agents = root / "shared" / "agents"
    final = master_dir(root, name)
    try:
        gid = grp.getgrnam(SHARED_GROUP).gr_gid
    except KeyError:
        raise BuildError(f"the {SHARED_GROUP} group does not exist — reconfigure: sudo dpkg-reconfigure agenti")
    tmp = Path(tempfile.mkdtemp(prefix=f".update-{name}-", dir=agents))
    shutil.rmtree(tmp)
    backup = agents / f".replaced-{name}-{os.getpid()}"
    try:
        shutil.copytree(final, tmp, symlinks=True)
        man = manifest_for({**spec, "system_prompt": ""}, root, by=old["built"].get("by", by))
        man["built"] = {**old["built"], "updated_by": by,
                        "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
        _write_descriptor_files(tmp, spec, root, man, with_stub=False)
        _write_capabilities_file(tmp, spec)
        os.chown(tmp / "manifest.json", 0, gid); os.chmod(tmp / "manifest.json", 0o640)
        os.chown(tmp / "capabilities.json", 0, 0); os.chmod(tmp / "capabilities.json", 0o644)
        os.chown(tmp, 0, gid); os.chmod(tmp, 0o751)
        os.rename(final, backup)
        try:
            os.rename(tmp, final)
        except BaseException:
            os.rename(backup, final)
            raise
        shutil.rmtree(backup, ignore_errors=True)
    except BaseException:
        shutil.rmtree(tmp, ignore_errors=True)
        raise
    return {"ok": True, "name": name, "title": spec["title"], "master_dir": str(final),
            "programs": spec["programs"]}


# ---------------------------------------------------------------------------
# removing
# ---------------------------------------------------------------------------
def describe_built(root: Path, name: str) -> dict:
    """What `remove` needs to know, and the refusal when the agent was not
    built here: a hand-built agent (enum, research, ...) is removed by
    deleting its source and redeploying, never from the GUI."""
    if not isinstance(name, str) or not NAME_RE.match(name):
        raise BuildError("invalid agent name.")
    md = master_dir(root, name)
    if not md.is_dir() or md.is_symlink():
        raise BuildError(f"no agent called '{name}' is deployed.")
    try:
        man = json.loads((md / "manifest.json").read_text())
    except (OSError, ValueError):
        man = {}
    if not isinstance(man.get("built"), dict):
        raise BuildError(f"'{name}' was not built in Settings -> Agents, so it cannot be removed "
                         f"there. A hand-built agent is retired by removing its source and redeploying.")
    return {"ok": True, "name": name, "title": man.get("title") or name,
            "description": man.get("description") or "",
            "kind": man.get("kind") if man.get("kind") in KINDS else DEFAULT_KIND,
            "built": man["built"], "programs": [p.get("name") for p in man.get("programs", [])
                                                if isinstance(p, dict)]}


def delete_files(root: Path, name: str) -> dict:
    describe_built(root, name)
    removed = []
    for p in (master_dir(root, name), root / "shared" / "context" / "agents" / name):
        if p.is_symlink():
            p.unlink(); removed.append(str(p))
        elif p.is_dir():
            # Both live under root-owned 0751/0700 parents; refuse anything
            # that resolved somewhere else.
            if p.resolve().parent not in (master_dir(root, "x").resolve().parent,
                                          (root / "shared" / "context" / "agents").resolve()):
                raise BuildError(f"refusing to delete {p}: it resolves outside the vault's agent folders.")
            shutil.rmtree(p); removed.append(str(p))
    return {"ok": True, "name": name, "removed": removed}


# ---------------------------------------------------------------------------
def _read_stdin_json():
    data = sys.stdin.read(200_000)
    try:
        return json.loads(data)
    except ValueError as e:
        raise BuildError(f"the spec is not valid JSON: {e}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(allow_abbrev=False, description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", default=str(paths.data_root()))
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("catalog", allow_abbrev=False, help="the programs a built agent may be given")
    sub.add_parser("check", allow_abbrev=False, help="validate a spec (stdin) and print it normalized, with its SHA-256")
    sub.add_parser("check-update", allow_abbrev=False, help="validate an edit (stdin, no instructions) and print its SHA-256")
    u = sub.add_parser("update", allow_abbrev=False, help="apply an edit to a built agent (root)")
    u.add_argument("--by", required=True)
    w = sub.add_parser("write", allow_abbrev=False, help="write a validated spec's master copy (root)")
    w.add_argument("--by", required=True)
    d = sub.add_parser("describe", allow_abbrev=False, help="what removing a built agent would remove")
    d.add_argument("name")
    x = sub.add_parser("delete-files", allow_abbrev=False, help="delete a built agent's master copy and edited instructions (root)")
    x.add_argument("name")
    a = ap.parse_args(argv)
    root = Path(a.root)
    try:
        if a.cmd == "catalog":
            out = catalog(root)
        elif a.cmd == "check":
            spec = normalize(_read_stdin_json(), root)
            out = {"ok": True, "spec": spec, "sha256": spec_sha256(spec)}
        elif a.cmd == "check-update":
            spec = normalize_update(_read_stdin_json(), root)
            out = {"ok": True, "spec": spec, "sha256": spec_sha256(spec)}
        elif a.cmd == "update":
            out = update(normalize_update(_read_stdin_json(), root), root, by=a.by)
        elif a.cmd == "write":
            spec = normalize(_read_stdin_json(), root)
            out = write(spec, root, by=a.by)
        elif a.cmd == "describe":
            out = describe_built(root, a.name)
        else:
            out = delete_files(root, a.name)
    except BuildError as e:
        print(json.dumps({"ok": False, "error": str(e)}))
        return 1
    print(json.dumps(out, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
