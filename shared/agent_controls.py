#!/usr/bin/env python3
"""agent_controls.py — everything that controls, manages or restricts ONE agent
for this organisation, gathered for the GUI's per-agent control centre (Settings →
Agents), plus a DRIFT CHECK: does what systemd is actually enforcing right now
match what the deploy files declare?

Root-side, stdlib only, read-only. shared/agenti runs it (`agenti
<agent> controls --json`); the API reaches it only through that verb, and only
for a global admin.

Each section says whether the admin can change it from the GUI (`editable`) and
where. Settings that ARE the boundary (capabilities, isolation,
the pre-tool-call guard) are `editable: False` on purpose: if a web page could
change them, a stolen admin session could switch them off. They change only by
a deploy at a terminal; the control centre shows them, and the drift check
proves they are what is really running.

Drift rows are `ok`, `fail` (declared and live disagree), or `unknown` (the
unit is not loaded, so there is nothing live to compare). A box where nothing
has run yet is not a failure.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

# The same ceilings capability-dropin.sh enforces. Kept in step by
# test_agent_controls.py, which reads them out of that file.
TEMPLATE_CAPS = ("CAP_NET_RAW", "CAP_NET_ADMIN")
# A file-analysis agent's sandbox capability: bounding set only, never ambient,
# and it comes with two booleans relaxed (capability-dropin.sh SANDBOX_CAP,
# SANDBOX_RELAX_BOOLEANS). Ignoring that made the drift check report a correct
# file-analysis deploy as a failure (found during audit run 1).
SANDBOX_CAP = "CAP_SYS_ADMIN"
SANDBOX_RELAX_BOOLEANS = ("RestrictSUIDSGID", "ProtectKernelTunables")

# Directives the drift check compares. Expected values come from the template
# file itself, so changing the template changes what "correct" means.
CHECKED_DIRECTIVES = ("NoNewPrivileges", "ProtectSystem", "ProtectHome", "PrivateTmp",
                      "ProtectKernelModules", "ProtectControlGroups", "LockPersonality",
                      "RestrictSUIDSGID", "ProtectKernelTunables", "TasksMax")

GUARDS = [
    "The model has no shell. It can only call the tools listed here; every built-in tool is "
    "refused by the allow-list and again by a check that runs before each tool call.",
    "Scope is checked inside each tool against root-owned files, never against the prompt.",
    "Network tools check the address a name actually resolves to, so a name that points "
    "inside the network is refused.",
    "The run's scope, settings and code are read-only to the agent's own account.",
    "Turns, spend and wall-clock time are hard caps that reset on every run.",
    "Every tool call, refusal and operator message is written to the audit log and the report.",
]


def _read_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def template_directives(text: str) -> dict[str, str]:
    """First `Key=value` for each checked directive, comments skipped."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        if key in CHECKED_DIRECTIVES + ("AmbientCapabilities", "CapabilityBoundingSet",
                                        "RestrictAddressFamilies", "ReadWritePaths",
                                        "BindReadOnlyPaths", "BindPaths",
                                        "TemporaryFileSystem") and key not in out:
            out[key] = value.strip()
    return out


def read_capfile(path: Path) -> list[str] | None:
    """Capabilities an agent asks for, or None when it has no file (= the full
    template grant). An empty-but-present file means "none"."""
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError:
        return None
    caps = []
    for line in raw.splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            caps.append(line)
    return caps


def expected_privileges(template: dict[str, str], requested: list[str] | None) -> dict:
    """What the live unit SHOULD report for capabilities, derived the way
    capability-dropin.sh renders them."""
    caps = list(TEMPLATE_CAPS) if requested is None else list(requested)
    bnd = caps
    amb = [c for c in caps if c != SANDBOX_CAP]
    expected = {k: template.get(k, "") for k in CHECKED_DIRECTIVES}
    if SANDBOX_CAP in caps:
        for k in SANDBOX_RELAX_BOOLEANS:
            expected[k] = "no"
    # systemd prints booleans as yes/no whatever the file said
    for k, v in list(expected.items()):
        if v.lower() in ("yes", "true", "1", "on"):
            expected[k] = "yes"
        elif v.lower() in ("no", "false", "0", "off"):
            expected[k] = "no"
    expected["AmbientCapabilities"] = " ".join(sorted(c.lower() for c in amb))
    expected["CapabilityBoundingSet"] = " ".join(sorted(c.lower() for c in bnd))
    return expected


def live_properties(unit: str) -> dict | None:
    """`systemctl show` for the unit, or None when systemd cannot load it."""
    props = list(CHECKED_DIRECTIVES) + ["AmbientCapabilities", "CapabilityBoundingSet",
                                        "LoadState", "UnitFileState"]
    cmd = ["systemctl", "show", unit] + [a for p in props for a in ("-p", p)]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if r.returncode != 0:
        return None
    out = {}
    for line in r.stdout.splitlines():
        k, _, v = line.partition("=")
        out[k] = v.strip()
    if out.get("LoadState") != "loaded":
        return None
    return out


def _norm(prop: str, value: str) -> str:
    if prop in ("AmbientCapabilities", "CapabilityBoundingSet"):
        return " ".join(sorted(value.lower().split()))
    return value.strip()


def drift_checks(expected: dict, live: dict | None) -> list[dict]:
    rows = []
    names = list(CHECKED_DIRECTIVES) + ["AmbientCapabilities", "CapabilityBoundingSet"]
    for name in names:
        want = expected.get(name, "")
        if live is None:
            rows.append({"name": name, "declared": want, "live": None, "status": "unknown"})
            continue
        got = _norm(name, live.get(name, ""))
        rows.append({"name": name, "declared": want, "live": got,
                     "status": "ok" if got == _norm(name, want) else "fail"})
    # Invariant (CLAUDE.md §1.5): never enabled, so a power cycle never resumes a scan.
    state = None if live is None else live.get("UnitFileState", "")
    if live is None:
        rows.append({"name": "never starts on boot", "declared": "not enabled", "live": None,
                     "status": "unknown"})
    else:
        rows.append({"name": "never starts on boot", "declared": "not enabled", "live": state or "static",
                     "status": "fail" if state == "enabled" else "ok"})
    return rows


def build(args) -> dict:
    sys.path.insert(0, args.libdir)
    import engagement_context as ec
    import engagement_store as es

    org_dir, master = Path(args.org_dir), Path(args.master_dir)
    caps = _read_json(master / "capabilities.json") or {}
    kind_label = (caps.get("scope_kind") or "").strip()
    kind = {"CIDRScope": "cidr", "DomainScope": "domain"}.get(kind_label, "")

    out: dict = {"agent": args.agent, "sections": []}

    # --- identity ------------------------------------------------------------
    out["sections"].append({
        "id": "identity", "title": "What it is", "editable": False,
        "rows": [["Scope kind", kind_label or "—"],
                 ["Category", caps.get("category") or "—"]]})

    # --- scope ---------------------------------------------------------------
    if kind:
        rec_path = org_dir / ec.ORG_ENGAGEMENT_FILENAME
        try:  # the store's own view, so these numbers can never differ from the CLI's
            view = es._agent_scope_view(org_dir, rec_path, args.agent, kind)
        except Exception as e:         # a broken record must show up, not hide the page
            view = {"effective_error": str(e), "org_in_scope": [], "agent_in_scope": [],
                    "effective_in_scope": [], "org_out_of_scope": [], "agent_out_of_scope": []}
        out["scope"] = view
        out["sections"].append({
            "id": "scope", "title": "Scope", "editable": True, "edit_where": "Agent scope panel below",
            "rows": [["Organisation allows", ", ".join(view["org_in_scope"]) or "nothing"],
                     ["This agent narrows to", ", ".join(view["agent_in_scope"]) or "no narrowing (inherits the organisation)"],
                     ["A run is held to", ", ".join(view["effective_in_scope"]) or "NOTHING — runs are refused"],
                     ["Always excluded", ", ".join(view["org_out_of_scope"] + view["agent_out_of_scope"]) or "—"]]})

    # --- instruction files ----------------------------------------------------
    try:
        import context_store as cs
        root = org_dir.parent
        rows = []
        for kind, who, label in (("system-prompt", {"agent": args.agent}, "System prompt (required)"),
                                 ("skills", {"agent": args.agent}, "Skills — this agent"),
                                 ("platform-skills", {}, "Skills — every agent"),
                                 ("org", {}, "Organisation policy")):
            d = cs.show(root, kind, **who)
            what = {"edited": "edited", "default": "shipped default", "none": "not set"}[d["source"]]
            rows.append([label, f"{what}" + (f", {d['bytes']:,} bytes" if d["source"] != "none" else "")])
        mem_dir = root / "org" / "context" / "memory" / args.agent
        n = len(list(mem_dir.glob("*.md"))) if mem_dir.is_dir() else 0
        rows.append(["Operator preferences (memory)", f"{n} user(s) have one; each run reads only its launcher's"])
        out["sections"].append({"id": "instructions", "title": "Instructions the agent reads",
                                "editable": True, "edit_where": "editors coming (phase 4); CLI: agenti admin context",
                                "rows": rows})
    except Exception as e:
        out["sections"].append({"id": "instructions", "title": "Instructions the agent reads",
                                "editable": False, "rows": [["could not read", str(e)]]})

    # --- run limits ----------------------------------------------------------
    rec = None
    try:
        rec = ec.read_record(org_dir / ec.ORG_ENGAGEMENT_FILENAME)
    except ec.EngagementError:
        pass
    pol = ec.resolve_policy(rec)
    out["sections"].append({
        "id": "limits", "title": "Run limits (set for the organisation)", "editable": True,
        "edit_where": "Settings → Engagement",
        "rows": [["Admin approval required", "yes" if pol.get("require_approval") else "no"],
                 ["Max turns", str(pol.get("max_turns_ceiling"))],
                 ["Max spend per run", f"${pol.get('max_budget_usd_ceiling')}"],
                 ["Max run time", f"{pol.get('timeout_s_ceiling')} s"],
                 ["Allowed models", ", ".join(pol.get("allowed_models") or []) or "—"]]})

    # --- tools ---------------------------------------------------------------
    mcp = caps.get("mcp_tools") or []
    cli = caps.get("command_line_tools") or {}
    tool_rows = [[t.get("name", "?"), t.get("purpose") or ""] for t in mcp] or [["(none declared)", ""]]
    out["sections"].append({"id": "tools", "title": "Tools the agent can call", "editable": False,
                            "edit_where": "built agents: Settings → Agents → Edit; hand-built: deploy only", "rows": tool_rows})
    items = cli.get("items") or []
    denied = list(caps.get("denied_patterns") or [])
    if cli.get("enforced"):
        # An enforced shell allow-list (enum today) can carry an admin's own
        # override (CLAUDE.md "Current plan" phase 6) — show the EFFECTIVE
        # set, not the static baseline, so this page can never understate
        # what a run can actually do.
        try:
            import tool_catalog as tcat
            import tool_settings_store as tss
            baseline = {i["name"] for i in items if i.get("name")}
            purposes = {i["name"]: i.get("purpose", "") for i in items if i.get("name")}
            catalog = tss.catalog_for(org_dir.parent / "shared")
            raw = tss.read_settings(tss.settings_path(org_dir, args.agent))
            settings = tcat.validate_settings(raw, catalog, baseline)
            effective = tcat.effective_binaries(baseline, settings, catalog)
            eff_purposes = tcat.effective_purposes(purposes, settings, catalog)
            rows = [[n, eff_purposes.get(n, "")] for n in sorted(effective)]
            added, removed = sorted(effective - baseline), sorted(baseline - effective)
            note = []
            if added:
                note.append(f"added by an admin: {', '.join(added)}")
            if removed:
                note.append(f"removed by an admin: {', '.join(removed)}")
            offered = sorted(tcat.approvable_programs(settings, catalog, effective))
            if offered:
                note.append(f"operators may approve, per run: {', '.join(offered)}")
            out["sections"].append({
                "id": "programs", "title": "Programs it may run (enforced allow-list)",
                "editable": True, "edit_where": "Settings → Agents → Tool allow-list",
                "rows": rows, "note": "; ".join(note) if note else None})
            denied += list(set(tcat.extra_denied_patterns(settings, catalog)
                               + tcat.builtin_extra_denied(catalog, effective)))
        except Exception as e:
            out["sections"].append({"id": "programs", "title": "Programs it may run (enforced allow-list)",
                                    "editable": False,
                                    "rows": [[i.get("name", "?"), i.get("purpose") or ""] for i in items],
                                    "note": f"could not read the admin override: {e}"})
    elif items:
        out["sections"].append({"id": "programs", "title": "External programs and services it uses",
                                "editable": False,
                                "rows": [[i.get("name", "?"), i.get("purpose") or ""] for i in items]})
    if denied:
        out["sections"].append({"id": "denied", "title": "Command patterns always refused",
                                "editable": False, "rows": [[str(d), ""] for d in denied]})

    # --- privileges, isolation, guards, drift -------------------------------
    tpl_path = Path(args.libdir) / "agenti-instance@.service"
    try:
        template = template_directives(tpl_path.read_text(encoding="utf-8"))
    except OSError:
        template = {}
    requested = read_capfile(master / f"{args.agent}.capabilities")
    expected = expected_privileges(template, requested)
    out["sections"].append({
        "id": "privileges", "title": "Privileges and isolation", "editable": False,
        "edit_where": "deploy only (it is the boundary)",
        "rows": [["Linux capabilities", expected["AmbientCapabilities"] or "none"],
                 ["Capability ceiling", expected["CapabilityBoundingSet"] or "none"],
                 ["Can never gain new privileges", expected.get("NoNewPrivileges") or "?"],
                 ["Whole system read-only", expected.get("ProtectSystem") or "?"],
                 ["Max processes", expected.get("TasksMax") or "?"],
                 ["Network address families", template.get("RestrictAddressFamilies", "?")]]})
    out["sections"].append({
        "id": "isolation", "title": "What a run can see and write", "editable": False,
        "edit_where": "deploy only (it is the boundary)",
        "rows": [["Organisation folder", "replaced by an empty read-only one; only the items below are put back"],
                 ["Writable", "its own run folder only (plus its team's chat channel, append-only, when it runs on a team)"],
                 ["Read-only", "the engagement and approval, this agent's scope file, and the model API key files"],
                 ["Its code and the shared library", "read-only (outside every writable path)"]]})
    out["sections"].append({"id": "guards", "title": "Guards that always apply", "editable": False,
                            "rows": [[g, ""] for g in GUARDS]})

    unit = f"agenti-{args.agent}-instance@verify.service"
    live = live_properties(unit)
    checks = drift_checks(expected, live)
    failed = [c for c in checks if c["status"] == "fail"]
    out["drift"] = {"checked_at_unit": unit, "loaded": live is not None, "checks": checks,
                    "ok": not failed, "failed": len(failed),
                    "summary": ("systemd is not enforcing this agent yet (no run has loaded its unit)"
                                if live is None else
                                "everything systemd enforces matches what was deployed" if not failed else
                                f"{len(failed)} setting(s) differ from what was installed — re-render: sudo dpkg-reconfigure agenti")}
    return out


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(allow_abbrev=False, prog="agent_controls.py")
    ap.add_argument("--agent", required=True)
    ap.add_argument("--org-dir", required=True)
    ap.add_argument("--master-dir", required=True)
    ap.add_argument("--libdir", required=True)
    args = ap.parse_args(argv)
    try:
        print(json.dumps(build(args), ensure_ascii=False))
    except Exception as e:
        print(json.dumps({"ok": False, "error": f"could not assemble the controls: {e}"}))
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
