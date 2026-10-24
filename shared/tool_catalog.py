#!/usr/bin/env python3
"""tool_catalog.py — which programs an admin may add to (or take from) an
agent that runs shell commands, and how an agent's effective allow-list is
worked out. Pure, stdlib.

Used by three callers that must agree: context_store (validate a save),
agent_runtime (apply it at run start) and agent_controls (show it).

THE MODEL
  baseline   the programs the agent's own CODE allows (enum's ALLOWED_BINARIES)
  catalog    shared/tool-catalog.json — reviewed, recon-only, read-only to
             everyone; the ONLY source of names an admin may ADD
  settings   what an admin chose for this agent, stored as
             {"enable": [...], "disable": [...], "approvable": [...]}
  effective  (baseline - disable) | (enable & catalog names)
  approvable catalog programs that are NOT effective but that the run's
             operator may approve for ONE run (phase 7). Never anything
             outside the catalog, never something already effective.

An admin can therefore REMOVE anything the code allows, but ADD only a name
the catalog lists. There is no way to type an arbitrary program name into
the allow-list — that would hand the agent a general-purpose shell, which is
exactly the boundary CLAUDE.md §1 invariant 1 exists to hold. Settings are
re-validated here at run time (never trusted as already-correct), so a
catalog entry removed later cannot keep granting what it used to.

extra_denied patterns (one program, or 'rules_for_built_in_programs' for a
baseline program like netexec/smbclient) are ADDED to the agent's own
DENIED_PATTERNS for the run — narrowing only, never replacing anything.
"""
from __future__ import annotations

import json
import os
import re
import shutil
from pathlib import Path

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$")

# Programs a global admin adds in the GUI live in a SEPARATE file beside the
# reviewed one, so a redeploy (which rewrites tool-catalog.json) never erases
# them. load_catalog() merges the two; every admin entry is re-validated on
# every load, so a hand-edited or stale overlay can never grant more than the
# rules below allow.
ADMIN_CATALOG_FILENAME = "tool-catalog.admin.json"
SEARCH_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# Programs that can NEVER be offered to an agent, whoever asks: anything that
# is itself a shell or interpreter, runs other programs, escalates privilege,
# changes files or the system, moves data over a network, or compiles code.
# Allowing one of these would turn the agent's allow-list into a general
# shell, which is the one boundary CLAUDE.md §1 invariant 1 exists to hold.
# The catalog's own "never_in_this_catalog" list (offensive tooling) is
# refused too. Matched on the typed name AND on what it resolves to, so a
# symlink or alternatives entry cannot smuggle one in under another name.
BLOCKED_PROGRAMS = frozenset("""
sh bash dash zsh ksh csh tcsh fish ash busybox rbash
python python2 python3 perl ruby php node nodejs lua luajit tclsh wish awk gawk mawk nawk sed
java jshell go rustc cargo gcc cc g++ clang tcc make cmake as ld
sudo su doas pkexec runuser setpriv nsenter chroot unshare capsh newgrp sg login
env xargs find exec nohup timeout nice ionice time watch script screen tmux strace ltrace gdb
parallel at batch crontab systemd-run run-parts flock
rm mv cp ln dd chmod chown chgrp truncate shred mkfifo mknod install rsync tar unzip zip cpio
mount umount losetup systemctl service init reboot shutdown poweroff halt kill pkill killall
apt apt-get dpkg aptitude pip pip3 npm gem snap flatpak
nc ncat netcat socat ssh scp sftp telnet ftp tftp wget rsh rlogin openssl
vi vim nvim nano ed ex emacs less more
useradd userdel usermod groupadd passwd chpasswd visudo iptables nft ip ifconfig modprobe insmod
pwsh irb jrunscript julia octave rscript r expect unbuffer rlwrap stdbuf setsid taskset chrt
sqlite3 mysql mariadb psql duckdb git man pager view rview rvim vimdiff
""".split())


def _name_forms(name: str) -> set[str]:
    """`name` and the plain program it is a version or variant of: python3.14
    -> python3/python, vim.basic -> vim, nc.openbsd -> nc, tclsh8.6 -> tclsh
    (audit run 1, F39: an exact-name block-list missed every one of these)."""
    n = name.lower()
    forms = {n}
    base = re.sub(r"\.[a-z]+$", "", n)              # alternatives: vim.basic, nc.openbsd
    forms.add(base)
    for f in list(forms):
        stripped = re.sub(r"[-_.]?\d+(\.\d+)*$", "", f)   # versions: python3.14, tclsh8.6, php8.2
        forms.add(stripped)
        forms.add(re.sub(r"\d+$", "", stripped))
    return {f for f in forms if f}


def is_blocked(name: str, refused=BLOCKED_PROGRAMS) -> bool:
    low = {r.lower() for r in refused}
    return bool(_name_forms(name) & low)


class CatalogError(Exception):
    pass


def _refused_names(base: dict) -> set[str]:
    never = base.get("never_in_this_catalog", [])
    return set(BLOCKED_PROGRAMS) | {n for n in never if isinstance(n, str)}


def which_program(name: str) -> str | None:
    """The absolute path of an installed program, or None. Looks only in the
    standard system directories (never the caller's own PATH)."""
    found = shutil.which(name, path=SEARCH_PATH)
    if found:
        return found
    # The same program under the name the distribution installs it as (Kali
    # ships impacket's GetUserSPNs.py as impacket-GetUserSPNs), so it is not
    # reported missing when it is there.
    import recon_programs
    prog = recon_programs.program_for(name)
    for alt in (prog.aliases if prog else ()):
        found = shutil.which(alt, path=SEARCH_PATH)
        if found:
            return found
    return None


def resolved_name(path: str | None) -> str | None:
    return os.path.basename(os.path.realpath(path)) if path else None


def validate_entry(entry, base: dict, *, existing: set[str] | None = None) -> dict:
    """A clean admin-added catalog entry, or CatalogError saying exactly why
    not. `base` is the reviewed catalog (its never-list feeds the block-list);
    `existing` is the set of names already taken."""
    if not isinstance(entry, dict):
        raise CatalogError("a program entry must be an object")
    unknown = set(entry) - {"name", "group", "purpose", "extra_denied"}
    if unknown:
        raise CatalogError(f"unknown field(s): {', '.join(sorted(unknown))}")
    name = entry.get("name")
    if not isinstance(name, str) or not NAME_RE.match(name):
        raise CatalogError("the program name may use letters, digits and . _ + - only (no paths, no spaces)")
    refused = _refused_names(base)
    if is_blocked(name, refused):
        raise CatalogError(f"'{name}' can never be offered to an agent: it is a shell, interpreter, "
                           f"privilege or system tool, or on the never-allowed list. Allowing it would "
                           f"give the agent a general-purpose shell.")
    if existing and name in existing:
        raise CatalogError(f"'{name}' is already in the catalog.")
    group = (entry.get("group") or "other")
    if not isinstance(group, str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,23}", group):
        raise CatalogError("the group must be lowercase letters, digits and hyphens (24 at most)")
    purpose = entry.get("purpose")
    if not isinstance(purpose, str) or not purpose.strip():
        raise CatalogError("say what the program is for, in one line (it is shown to the model and to admins)")
    purpose = " ".join(purpose.split())
    if len(purpose) > 200 or any(ord(c) < 32 for c in purpose):
        raise CatalogError("the purpose must be one line of 200 characters or fewer")
    pats = entry.get("extra_denied") or []
    if not isinstance(pats, list) or len(pats) > 20 or not all(isinstance(x, str) and 0 < len(x) <= 300 for x in pats):
        raise CatalogError("blocked-argument patterns: up to 20, each 1-300 characters")
    for pat in pats:
        try:
            re.compile(pat)
        except re.error as e:
            raise CatalogError(f"'{pat}' is not a valid pattern: {e}")
    return {"name": name, "group": group, "purpose": purpose, "extra_denied": list(pats)}


def check_installed(name: str) -> str:
    """The resolved path of `name`, or CatalogError with the install hint.
    Also refuses a program that RESOLVES to a blocked one."""
    path = which_program(name)
    if not path:
        raise CatalogError(f"'{name}' is not installed on this server. Install it first "
                           f"(sudo apt install {name}), then add it here.")
    real = resolved_name(path)
    if real and is_blocked(real):
        raise CatalogError(f"'{name}' is the same program as '{real}', which can never be offered to an agent.")
    return path


def load_catalog(path: Path, admin_path: Path | None = None, *, strict: bool = False) -> dict:
    """The reviewed catalog at `path` (shipped, read-only) merged with the
    admin's additions at `admin_path` (data root's shared/; default: beside
    `path`, which is how a test lays them out). A missing additions file means
    none. With `strict` (what a run uses), an additions file that exists but
    cannot be read is an error; otherwise it counts as none, so the admin
    screens can still open and rewrite it."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise CatalogError(f"no tool catalog at {path}")
    except (OSError, ValueError) as e:
        raise CatalogError(f"cannot read the tool catalog at {path}: {e}")
    if not isinstance(data, dict) or not isinstance(data.get("programs"), list):
        raise CatalogError(f"{path} is not a valid tool catalog")
    for p in data["programs"]:
        if isinstance(p, dict):
            p.setdefault("source", "reviewed")
    # The admin overlay: merged in, each entry re-validated; an invalid or
    # duplicate one is skipped rather than failing every agent's start.
    ov_path = Path(admin_path or Path(path).with_name(ADMIN_CATALOG_FILENAME))
    try:
        ov = json.loads(ov_path.read_text(encoding="utf-8"))
        if not isinstance(ov, dict) or not isinstance(ov.get("programs", []), list):
            raise ValueError("not a program list")
        extra = ov.get("programs", [])
    except FileNotFoundError:
        extra = []
    except (OSError, ValueError) as e:
        if strict:
            raise CatalogError(f"the admin's program additions ({ov_path}) cannot be read: {e}. "
                               f"An admin can rewrite the file by adding a program again in "
                               f"Settings → Agents → Program catalog")
        extra = []
    taken = catalog_names(data)
    for e in extra:
        try:
            clean = validate_entry({k: e.get(k) for k in ("name", "group", "purpose", "extra_denied")
                                    if isinstance(e, dict) and k in e}, data, existing=taken)
        except CatalogError:
            continue
        clean["source"] = "admin"
        if isinstance(e, dict):
            clean["added_by"] = str(e.get("added_by", ""))[:64]
            clean["added_at"] = e.get("added_at")
        data["programs"].append(clean)
        taken.add(clean["name"])
    return data


def baseline_programs(catalog: dict) -> list[dict]:
    """The baseline recon programs (enum's own list), as {name, group,
    purpose} — what a recon agent's manifest may name without the admin
    having added anything. Read from the catalog file so enum and every
    built agent draw from ONE reviewed list."""
    out = []
    for p in catalog.get("baseline_programs", []):
        if isinstance(p, dict) and isinstance(p.get("name"), str) and p["name"]:
            out.append({"name": p["name"], "group": str(p.get("group") or ""),
                        "purpose": str(p.get("purpose") or "")})
    return out


def catalog_names(catalog: dict) -> set[str]:
    return {p["name"] for p in catalog.get("programs", []) if isinstance(p, dict) and p.get("name")}


def catalog_entry(catalog: dict, name: str) -> dict | None:
    for p in catalog.get("programs", []):
        if isinstance(p, dict) and p.get("name") == name:
            return p
    return None


def validate_settings(data, catalog: dict, baseline: set[str]) -> dict:
    """A clean {"enable", "disable", "approvable"} (each a sorted list) or
    raise CatalogError naming exactly what's wrong. `enable` and
    `approvable` entries must be in the catalog; `disable` entries must be in
    the baseline (removing a name that was never there is meaningless and
    probably a typo worth catching). A program cannot be both enabled and
    approvable: enabled already means always allowed."""
    if not isinstance(data, dict):
        raise CatalogError("tool settings must be a JSON object")
    unknown = set(data) - {"enable", "disable", "approvable"}
    if unknown:
        raise CatalogError(f"unknown field(s) in tool settings: {', '.join(sorted(unknown))}")
    names = catalog_names(catalog)
    out = {}
    for key, pool, label in (("enable", names, "the catalog"),
                             ("approvable", names, "the catalog"),
                             ("disable", baseline, "this agent's own code")):
        items = data.get(key, [])
        if not isinstance(items, list) or not all(isinstance(x, str) for x in items):
            raise CatalogError(f"{key!r} must be a list of program names")
        bad = [x for x in items if not NAME_RE.match(x)]
        if bad:
            raise CatalogError(f"not a valid program name: {', '.join(bad)}")
        not_allowed = sorted(set(items) - pool)
        if not_allowed:
            raise CatalogError(
                f"cannot {'allow operators to approve' if key == 'approvable' else key} "
                f"{', '.join(not_allowed)} — not in {label}. "
                + ("Request it added to the catalog instead." if key != "disable" else ""))
        out[key] = sorted(set(items))
    both = sorted(set(out["enable"]) & set(out["approvable"]))
    if both:
        raise CatalogError(f"{', '.join(both)} cannot be both always-enabled and approvable — "
                           f"enabled already means always allowed")
    return out


def effective_binaries(baseline: set[str], settings: dict, catalog: dict) -> set[str]:
    names = catalog_names(catalog)
    enabled = {n for n in settings.get("enable", []) if n in names}
    disabled = set(settings.get("disable", []))
    return (baseline - disabled) | enabled


def effective_purposes(baseline_purposes: dict, settings: dict, catalog: dict) -> dict:
    """Purpose text for the operator-facing panel: baseline purposes, minus
    anything disabled, plus the catalog's own purpose for anything enabled."""
    disabled = set(settings.get("disable", []))
    out = {k: v for k, v in baseline_purposes.items() if k not in disabled}
    for n in settings.get("enable", []):
        entry = catalog_entry(catalog, n)
        if entry:
            out[n] = entry.get("purpose", "")
    return out


def extra_denied_patterns(settings: dict, catalog: dict) -> list[str]:
    """Argument patterns to refuse, beyond the agent's own DENIED_PATTERNS,
    for whichever catalog-sourced programs ended up enabled. Built-in
    programs needing their OWN narrowing live in rules_for_built_in_programs
    and apply whenever that program is still part of the effective set."""
    out: list[str] = []
    for n in settings.get("enable", []):
        entry = catalog_entry(catalog, n)
        if entry:
            out.extend(entry.get("extra_denied", []))
    return out


def builtin_extra_denied(catalog: dict, effective: set[str]) -> list[str]:
    rules = catalog.get("rules_for_built_in_programs", {})
    out: list[str] = []
    for name, patterns in rules.items():
        if name in effective:
            out.extend(patterns)
    return out


def approvable_programs(settings: dict, catalog: dict, effective: set[str]) -> set[str]:
    """Programs an operator may approve for one run: admin-listed, still in
    the catalog, and not already effective (nothing to approve if it is)."""
    names = catalog_names(catalog)
    return {n for n in settings.get("approvable", []) if n in names} - set(effective)


def granted_programs(grants, settings: dict, catalog: dict, effective: set[str]) -> set[str]:
    """Which programs a run's grant file actually authorizes RIGHT NOW. The
    file is written by root, but it is re-checked here against the current
    settings and catalog (never trusted as already-correct): a grant for a
    program the admin has since stopped offering, or that left the catalog,
    grants nothing."""
    if not isinstance(grants, dict):
        return set()
    wanted = grants.get("programs", [])
    if not isinstance(wanted, list):
        return set()
    allowed = approvable_programs(settings, catalog, effective)
    return {n for n in wanted if isinstance(n, str) and n in allowed}


def patterns_for_programs(names: set[str], catalog: dict) -> list[str]:
    """extra_denied argument patterns for specific catalog programs."""
    out: list[str] = []
    for n in sorted(names):
        entry = catalog_entry(catalog, n)
        if entry:
            out.extend(entry.get("extra_denied", []))
    return out
