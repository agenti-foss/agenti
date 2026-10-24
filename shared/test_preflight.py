#!/usr/bin/env python3
"""test_preflight.py — shared/preflight.py's engagement, approval and
immutability checks against the organisation engagement record (CLAUDE.md
"Current plan", phase 1 of the cybersecurity refocus), plus the
manifest-driven exemption from phase 5 of the generic-launcher arc.

    python3 shared/test_preflight.py

Narrow on purpose: it does NOT re-test clock, encryption, secrets, tools
or egress — none of that changed. It pins the checks whose failure would
be SILENT and dangerous: a start passing without a required approval, an
approval surviving an edit to the scope it approved, the organisation's own
require_approval policy field not actually being consulted, or a
manifest-driven agent refusing to start over an engagement it never had.

No root, no vault: preflight.py's module-level paths are plain attributes
computed from environment variables at import time — reassigned here to a
throwaway layout that mirrors the real one, MASTER copy split from run
SLOT: <root>/shared/agents/<agent>/ (code, manifest.json, capabilities.json)
is separate from <root>/org/<agent>/instances/<slot>/ (run-target,
run-config.json — pure runtime state) and <root>/org/engagement.json.
The approval itself is written by the REAL shared/engagement_store.py as a
subprocess, so this also proves the two agree on the digest. Permission
assertions (os.access) are meaningless for root, who can write anything:
under uid 0 those specific checks are reported as SKIPPED, not passed.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import preflight  # noqa: E402
import engagement_context as ec  # noqa: E402

PASS = FAIL = SKIP = 0


def check(label, got, want):
    global PASS, FAIL
    if got == want:
        PASS += 1; print(f"  [ OK ] {label}")
    else:
        FAIL += 1; print(f"  [FAIL] {label}\n         got  {got!r}\n         want {want!r}")


def skip(label):
    global SKIP
    SKIP += 1; print(f"  [SKIP] {label}")


def section(t): print(f"\n=== {t} ===")


def last():
    preflight.results.clear()
    return preflight.results


def run_check(fn):
    preflight.results.clear()
    fn()
    return preflight.results[-1]


IS_ROOT = os.geteuid() == 0
STORE = HERE / "engagement_store.py"

tmp = Path(tempfile.mkdtemp(prefix="agenti-test-preflight-"))
try:
    # ---- a realistic layout ------------------------------------------------
    root = tmp / "root"
    org_dir = root / "org"; shared_dir = root / "shared"
    agent_dir = org_dir / "enum"                      # the INSTANCE (runtime state)
    master_dir = shared_dir / "agents" / "enum"          # the MASTER copy (code)
    for d in (agent_dir, master_dir, shared_dir):
        d.mkdir(parents=True, exist_ok=True)
    preflight.AGENTI_ROOT = root
    preflight.AGENT_NAME = "enum"
    preflight.ORG_DIR = org_dir
    preflight.SHARED_DIR = shared_dir
    preflight.DATA_ROOT = agent_dir
    preflight.MASTER_DIR = master_dir

    def store(*argv):
        p = subprocess.run([sys.executable, str(STORE), "--org-dir", str(org_dir),
                            "--shared-dir", str(shared_dir), *argv], capture_output=True, text=True)
        assert p.returncode == 0, p.stdout + p.stderr
        return json.loads(p.stdout)

    section("agent_scope_kind(): from capabilities.json (a MASTER-copy artifact — phase 2), None when unknown")
    check("no capabilities.json: None", preflight.agent_scope_kind(), None)
    (master_dir / "capabilities.json").write_text(json.dumps({"scope_kind": "CIDRScope"}))
    check("CIDRScope -> cidr", preflight.agent_scope_kind(), "cidr")
    (master_dir / "capabilities.json").write_text(json.dumps({"scope_kind": "DomainScope"}))
    check("DomainScope -> domain", preflight.agent_scope_kind(), "domain")
    (master_dir / "capabilities.json").write_text(json.dumps({"scope_kind": "SomeFutureScope"}))
    check("an unknown scope class -> None (no engagement kind)", preflight.agent_scope_kind(), None)
    (master_dir / "capabilities.json").write_text(json.dumps({"scope_kind": "CIDRScope"}))

    section("check_engagement(): a run against the organisation record")
    ok, _, detail = run_check(preflight.check_engagement)
    check("no engagement record: FAILS", ok, False)
    check("...naming the set command and the GUI page",
          ("sudo agenti engagement set" in detail and "Settings" in detail), True)
    ok, _, detail = run_check(preflight.check_approval)
    check("approval defers to the engagement check when the record is missing", (ok, "engagement check" in detail), (True, True))

    core = ["--engagement-id", "ACME-01", "--client", "Acme", "--authorizing-party", "Jane",
            "--authorizing-title", "CISO", "--authorization-ref", "SOW-1",
            "--valid-from", "2020-01-01", "--valid-until", "2099-12-31"]
    store("set", "--by", "alice", *core, "--cidr-in", "10.0.0.0/24 (lab)")
    ok, _, detail = run_check(preflight.check_engagement)
    check("record with a cidr entry, cidr agent: PASSES", ok, True)
    check("...detail names id, window and the kind count",
          ("ACME-01" in detail and "1 cidr scope entries" in detail), True)

    (master_dir / "capabilities.json").write_text(json.dumps({"scope_kind": "DomainScope"}))
    ok, _, detail = run_check(preflight.check_engagement)
    check("the SAME record for a domain agent: FAILS (no domain entries)", ok, False)
    check("...naming the kind and the flag that adds entries", ("no domain scope entries" in detail and "--domain-in" in detail), True)
    store("set", "--by", "alice", "--domain-in", "acme.example (web)")
    ok, _, detail = run_check(preflight.check_engagement)
    check("after adding a domain entry the domain agent PASSES", (ok, "1 domain scope entries" in detail), (True, True))
    (master_dir / "capabilities.json").write_text(json.dumps({"scope_kind": "CIDRScope"}))

    (master_dir / "capabilities.json").unlink()
    ok, _, detail = run_check(preflight.check_engagement)
    check("scope kind unknown: still PASSES on a valid record, says the kind is unknown",
          (ok, "unknown" in detail and "cidr" in detail and "domain" in detail), (True, True))
    (master_dir / "capabilities.json").write_text(json.dumps({"scope_kind": "CIDRScope"}))

    store("set", "--by", "alice", "--valid-from", "2000-01-01", "--valid-until", "2000-12-31")
    ok, _, detail = run_check(preflight.check_engagement)
    check("expired window: FAILS naming the window", (ok, "outside its authorized window" in detail), (False, True))
    store("set", "--by", "alice", "--valid-from", "2020-01-01", "--valid-until", "2099-12-31")

    (org_dir / ec.ORG_ENGAGEMENT_FILENAME).write_text("{broken")
    ok, _, detail = run_check(preflight.check_engagement)
    check("corrupt record: FAILS naming the path", (ok, "not valid JSON" in detail), (False, True))
    store("set", "--by", "alice", *core, "--replace-scope", "cidr", "--cidr-in", "10.0.0.0/24 (lab)",
          "--replace-scope", "domain", "--domain-in", "acme.example (web)")

    section("check_approval(): bound to the record's content")
    ok, _, detail = run_check(preflight.check_approval)
    check("no approval: FAILS", ok, False)
    check("...naming the approve command", "sudo agenti engagement approve" in detail, True)
    check("...and the reason", "no approval on record" in detail, True)
    store("approve", "--by", "alice")
    ok, _, detail = run_check(preflight.check_approval)
    check("approved: PASSES naming the approver", (ok, "alice" in detail), (True, True))
    store("set", "--by", "alice", "--notes", "one more host is fragile")
    ok, _, detail = run_check(preflight.check_approval)
    check("AN EDIT AFTER APPROVAL: FAILS", ok, False)
    check("...saying it changed after alice approved it", ("changed after" in detail and "alice" in detail), True)
    store("set", "--by", "alice", "--notes", "")
    ok, _, detail = run_check(preflight.check_approval)
    check("reverting the edit restores the exact content: PASSES again (digest, not timestamp)", ok, True)
    store("set", "--by", "alice", "--cidr-in", "10.0.0.0/24 (lab)", "--cidr-in", "10.0.1.0/24 (new)")
    ok, _, _ = run_check(preflight.check_approval)
    check("widening the scope after approval: FAILS", ok, False)
    store("approve", "--by", "bob")
    ok, _, detail = run_check(preflight.check_approval)
    check("a fresh approval of the widened scope: PASSES naming bob", (ok, "bob" in detail), (True, True))
    (org_dir / ec.APPROVAL_FILENAME).write_text("garbage")
    ok, _, detail = run_check(preflight.check_approval)
    check("an unreadable approval file: FAILS closed", (ok, "unreadable" in detail), (False, True))
    store("approve", "--by", "bob")

    section("check_approval(): the organisation's own require_approval policy field (CLAUDE.md \"Current plan\" — replaces the retired --dev exemption)")
    store("set", "--by", "alice", "--no-require-approval")
    (org_dir / ec.APPROVAL_FILENAME).unlink()
    ok, _, detail = run_check(preflight.check_approval)
    check("policy off: PASSES with NO approval at all", (ok, "not required" in detail), (True, True))
    store("set", "--by", "alice", "--require-approval")
    ok, _, detail = run_check(preflight.check_approval)
    check("policy back on, still no approval: FAILS again", ok, False)
    store("approve", "--by", "bob")
    ok, _, detail = run_check(preflight.check_approval)
    check("approved again: PASSES", (ok, "bob" in detail), (True, True))

    section("check_code_immutable(): the MASTER copy, engagement record and approval must be unwritable")
    if IS_ROOT:
        skip("permission assertions: this test runs as root, for whom every file is writable "
             "(os.access cannot express root's real deployed posture) — proven on the box instead")
    else:
        for f in (org_dir / ec.ORG_ENGAGEMENT_FILENAME, org_dir / ec.APPROVAL_FILENAME):
            f.chmod(0o400)
        master_dir.chmod(0o500)
        try:
            ok, _, detail = run_check(preflight.check_code_immutable)
            check("MASTER_DIR, engagement.json and approval.json all read-only: PASSES", ok, True)
            check("...naming the files it checked", ("engagement.json" in detail and "approval.json" in detail), True)
            (org_dir / ec.ORG_ENGAGEMENT_FILENAME).chmod(0o600)
            ok, _, detail = run_check(preflight.check_code_immutable)
            check("a WRITABLE engagement.json: FAILS", (ok, "engagement.json" in detail and "WRITABLE" in detail), (False, True))
            (org_dir / ec.ORG_ENGAGEMENT_FILENAME).chmod(0o400)
            (org_dir / ec.APPROVAL_FILENAME).chmod(0o600)
            ok, _, detail = run_check(preflight.check_code_immutable)
            check("a WRITABLE approval.json: FAILS", (ok, "approval.json" in detail), (False, True))
            (org_dir / ec.APPROVAL_FILENAME).chmod(0o400)
        finally:
            master_dir.chmod(0o700)
            for f in (org_dir / ec.ORG_ENGAGEMENT_FILENAME, org_dir / ec.APPROVAL_FILENAME):
                f.chmod(0o600)
    if IS_ROOT:
        skip("a missing engagement record's immutability check (root: os.access(MASTER_DIR, W_OK) is "
             "always True for root, so the very first line of check_code_immutable short-circuits "
             "before it ever inspects which config file is missing — meaningless under this uid)")
    else:
        # master_dir must actually be read-only here — otherwise
        # check_code_immutable returns on its very FIRST line (MASTER_DIR
        # writable) before it ever looks at which config file is missing,
        # which would make this assertion pass for the wrong reason.
        moved = org_dir / "engagement.json.aside"
        (org_dir / ec.ORG_ENGAGEMENT_FILENAME).rename(moved)
        master_dir.chmod(0o500)
        try:
            ok, _, detail = run_check(preflight.check_code_immutable)
            check("a missing engagement record: FAILS closed naming the set command",
                  (ok, "engagement set" in detail), (False, True))
        finally:
            master_dir.chmod(0o700)
        moved.rename(org_dir / ec.ORG_ENGAGEMENT_FILENAME)

    # ---- check_scans(): the agent's own scans/ directory --------------------
    section("check_scans(): targets (and creates) the agent's scans/ directory")
    preflight.DATA_ROOT = agent_dir; preflight.MASTER_DIR = master_dir
    preflight.SCANS_DIR = agent_dir / "scans"
    assert not preflight.SCANS_DIR.exists(), "fixture bug: scans/ should not pre-exist"
    ok, _, detail = run_check(preflight.check_scans)
    check("scans/ is checked and created",
          (ok, str(preflight.SCANS_DIR) in detail), (True, True))

    # ------------------------------------------------------------------
    section("DATA_ROOT follows AGENTI_INSTANCE (concurrent same-type instances)")
    # Run in a SUBPROCESS, not by reassigning attributes: DATA_ROOT is an
    # import-time computation, so this is the only way to exercise the real
    # resolution systemd triggers — and it cannot disturb the module state
    # every section above reassigned. A wrong answer here would be SILENT
    # and serious: a named instance would read and write the DEFAULT slot's
    # run-target/state/reports, so two concurrent runs of one agent would
    # quietly trample each other instead of being isolated.
    def data_root_with(env_extra):
        env = {**os.environ, "AGENTI_ROOT": "/var/lib/agenti/data",
               "AGENT_NAME": "enum"}
        env.pop("AGENTI_INSTANCE", None)
        env.update(env_extra)
        p = subprocess.run([sys.executable, "-c",
                            "import preflight; print(preflight.DATA_ROOT)"],
                           capture_output=True, text=True, env=env, cwd=str(HERE))
        assert p.returncode == 0, p.stdout + p.stderr
        return p.stdout.strip()

    check("no AGENTI_INSTANCE: the flat default slot",
          data_root_with({}), "/var/lib/agenti/data/org/enum")
    check("AGENTI_INSTANCE set to the flat dir (what the default unit sets): unchanged",
          data_root_with({"AGENTI_INSTANCE": "/var/lib/agenti/data/org/enum"}),
          "/var/lib/agenti/data/org/enum")
    check("AGENTI_INSTANCE set to a NAMED slot: that slot, not the default one",
          data_root_with({"AGENTI_INSTANCE": "/var/lib/agenti/data/org/enum/instances/b"}),
          "/var/lib/agenti/data/org/enum/instances/b")

    def master_with(libdir):
        return subprocess.run([sys.executable, "-c", "import preflight; print(preflight.MASTER_DIR)"],
                              capture_output=True, text=True, cwd=str(HERE),
                              env={**os.environ, "AGENTI_ROOT": "/var/lib/agenti/data", "AGENTI_LIBDIR": libdir,
                                   "AGENT_NAME": "enum",
                                   "AGENTI_INSTANCE": "/var/lib/agenti/data/org/enum/instances/b"}).stdout.strip()

    check("MASTER_DIR is NOT instance-aware (code is shared by every slot); built agents live in the data root",
          master_with("/nonexistent"), "/var/lib/agenti/data/shared/agents/enum")
    shipped = tmp / "lib"
    (shipped / "agents" / "enum").mkdir(parents=True)
    check("a shipped agent's MASTER_DIR is the package's code folder",
          master_with(str(shipped)), str(shipped / "agents" / "enum"))

    section("check_tools(): a built recon agent's programs come from its manifest")
    built_master = tmp / "built-master"; built_master.mkdir()
    preflight.MASTER_DIR = built_master
    preflight.AGENT_NAME = "web-recon"
    check("no manifest and no checklist: unchecked, not a failure",
          run_check(preflight.check_tools)[0], True)
    (built_master / "manifest.json").write_text(json.dumps(
        {"name": "web-recon", "programs": [{"name": "definitely-not-installed-xyz", "purpose": "x"}]}))
    check("the manifest's programs are the checklist", preflight._manifest_tools(),
          (None, ["definitely-not-installed-xyz"]))
    ok, _, detail = run_check(preflight.check_tools)
    check("a missing program is reported but is not a failure (run_scan says 'not installed')",
          (ok, "definitely-not-installed-xyz" in detail), (True, True))
    (built_master / "manifest.json").write_text("{not json")
    check("an unreadable manifest degrades to unchecked", preflight._manifest_tools(), None)

    section("a file-analysis agent: no engagement, no approval, but a sandbox")
    fa_master = tmp / "fa-master"; fa_master.mkdir()
    fa_slot = tmp / "fa-slot"; fa_slot.mkdir()
    (fa_master / "capabilities.json").write_text(json.dumps({"scope_kind": "FilesScope"}))
    (fa_master / "manifest.json").write_text(json.dumps(
        {"name": "pcap", "kind": "analysis", "programs": [{"name": "tshark", "purpose": "decode"}]}))
    saved = (preflight.MASTER_DIR, preflight.DATA_ROOT, preflight.AGENT_NAME, preflight.ORG_DIR)
    preflight.MASTER_DIR, preflight.DATA_ROOT, preflight.AGENT_NAME = fa_master, fa_slot, "pcap"
    preflight.ORG_DIR = tmp / "org-with-no-engagement"          # there is none, on purpose
    check("the scope kind is read as 'files'", preflight.agent_scope_kind(), "files")
    ok, label, detail = run_check(preflight.check_engagement)
    check("the engagement check does not apply (and does not fail for want of one)",
          (ok, "not applicable" in detail), (True, True))
    ok, label, detail = run_check(preflight.check_approval)
    check("the approval check does not apply", (ok, "not applicable" in detail), (True, True))
    if IS_ROOT:
        skip("code-immutable for a files agent (root can write anything)")
    else:
        fa_master.chmod(0o555)          # like a real deploy: root-owned, not writable by the agent
        ok, label, detail = run_check(preflight.check_code_immutable)
        check("code-immutable passes with no engagement.json (only the code must be read-only)",
              (ok, "no engagement" in detail), (True, True))
        fa_master.chmod(0o755)
        ok, label, detail = run_check(preflight.check_code_immutable)
        check("...and still fails if the agent's code is writable", ok, False)
    ok, label, detail = run_check(preflight.check_scans)
    check("the writable-output check targets analysis/, not scans/",
          (ok, (fa_slot / "analysis").is_dir(), (fa_slot / "scans").exists()), (True, True, False))
    n_before = len(preflight.results)
    preflight.AGENT_NAME = "enum"
    (fa_master / "capabilities.json").write_text(json.dumps({"scope_kind": "CIDRScope"}))
    preflight.results.clear()
    preflight.check_sandbox()
    check("check_sandbox does nothing for an agent that is not a file-analysis agent", preflight.results, [])
    (fa_master / "capabilities.json").write_text(json.dumps({"scope_kind": "FilesScope"}))
    preflight.results.clear()
    preflight.check_sandbox()
    sb = preflight.results[-1] if preflight.results else None
    if sb is not None and not sb[0] and "refuse" in sb[2].lower():
        skip("the sandbox probe (this host refuses unprivileged user namespaces)")
    else:
        check("check_sandbox runs the real probe for a file-analysis agent", sb is not None and sb[1] == "sandbox", True)
    preflight.MASTER_DIR, preflight.DATA_ROOT, preflight.AGENT_NAME, preflight.ORG_DIR = saved

    section("check_tool_settings(): the admin's program changes apply, or the start stops")
    pf_lib = tmp / "pf-lib"; pf_lib.mkdir()
    (pf_lib / "tool-catalog.json").write_text(json.dumps({"programs": [
        {"name": "curl", "group": "web", "purpose": "fetch", "extra_denied": []}]}))
    saved_lib = os.environ.get("AGENTI_LIBDIR")
    os.environ["AGENTI_LIBDIR"] = str(pf_lib)
    ts_master = shared_dir / "agents" / "ts-recon"; ts_master.mkdir(parents=True)
    (ts_master / "capabilities.json").write_text(json.dumps({"command_line_tools": {
        "enforced": True, "items": [{"name": "nmap", "purpose": "s"}, {"name": "ping", "purpose": "p"}]}}))
    (org_dir / "ts-recon").mkdir()
    settings_file = org_dir / "ts-recon" / "tool-settings.json"
    preflight.AGENT_NAME = "ts-recon"
    ok, label, detail = run_check(preflight.check_tool_settings)
    check("no settings file: passes, nothing changed", (ok, label, "none made" in detail), (True, "tool-settings", True))
    settings_file.write_text(json.dumps({"enable": ["curl"], "disable": ["ping"]}))
    ok, _, detail = run_check(preflight.check_tool_settings)
    check("valid changes: passes and says what they are", (ok, detail.endswith("(1 added, 1 removed)")), (True, True))
    settings_file.write_text("{ broken")
    ok, _, detail = run_check(preflight.check_tool_settings)
    check("a corrupt settings file FAILS, with the fix on its own line",
          (ok, "\n" in detail and "tool-settings set" in detail), (False, True))
    settings_file.write_text(json.dumps({"enable": ["curl"]}))
    (shared_dir / "tool-catalog.admin.json").write_text("not json")
    check("a corrupt file of the admin's program additions FAILS",
          run_check(preflight.check_tool_settings)[0], False)
    (shared_dir / "tool-catalog.admin.json").unlink()
    preflight.AGENT_NAME = "no-such-agent"
    preflight.results.clear(); preflight.check_tool_settings()
    check("an agent with no changeable program list adds no line", preflight.results, [])
    if saved_lib is None:
        os.environ.pop("AGENTI_LIBDIR", None)
    else:
        os.environ["AGENTI_LIBDIR"] = saved_lib

    print(f"\n{PASS} passed, {FAIL} failed" + (f", {SKIP} skipped (root)" if SKIP else ""))
    sys.exit(1 if FAIL else 0)
finally:
    shutil.rmtree(tmp, ignore_errors=True)
