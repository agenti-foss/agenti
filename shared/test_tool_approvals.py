#!/usr/bin/env python3
"""test_tool_approvals.py — an operator allowing ONE catalog program for ONE run
(CLAUDE.md "Current plan" phase 7): shared/tool_approvals.py (list requests,
record decisions, write the grant), the catalog helpers that decide what a
grant is worth (shared/tool_catalog.py), and the call-time reader the running
agent uses (agent_runtime.make_run_grants_reader).

    python3 shared/test_tool_approvals.py

No root, no vault, no SDK. The properties that matter:
  * an operator can only approve what an ADMIN offered — and nothing outside
    the catalog, nothing already enabled;
  * a grant is for one run, and is re-checked against the admin's CURRENT
    settings every time, so withdrawing the offer takes effect at once;
  * the request file is written by the agent, so it is read as untrusted.
"""
import json
import os
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import tool_approvals as ta  # noqa: E402
import tool_catalog as tc  # noqa: E402
import agent_runtime as rt  # noqa: E402

PASS = FAIL = 0


def check(label, got, want):
    global PASS, FAIL
    if got == want:
        PASS += 1; print(f"  [ OK ] {label}")
    else:
        FAIL += 1; print(f"  [FAIL] {label}\n         got  {got!r}\n         want {want!r}")


def section(t): print(f"\n=== {t} ===")


def raises(fn):
    try:
        fn(); return None
    except Exception as e:
        return str(e)


CATALOG = {"programs": [
    {"name": "curl", "group": "web", "purpose": "fetch", "extra_denied": ["-X"]},
    {"name": "sslscan", "group": "tls", "purpose": "tls", "extra_denied": []},
    {"name": "whois", "group": "network", "purpose": "who", "extra_denied": []}]}
BASE = {"nmap", "ping"}

section("catalog helpers: what may be approved, what a grant is worth")
S = tc.validate_settings({"approvable": ["curl", "sslscan"]}, CATALOG, BASE)
eff = tc.effective_binaries(BASE, S, CATALOG)
check("approvable programs are NOT effective until approved", eff, BASE)
check("operators may approve exactly what the admin listed", tc.approvable_programs(S, CATALOG, eff), {"curl", "sslscan"})
check("a program the admin did not offer is not approvable", "whois" in tc.approvable_programs(S, CATALOG, eff), False)
check("always-enabled and approvable cannot overlap",
      "both" in (raises(lambda: tc.validate_settings({"enable": ["curl"], "approvable": ["curl"]}, CATALOG, BASE)) or ""), True)
check("a non-catalog name cannot be offered",
      raises(lambda: tc.validate_settings({"approvable": ["not-in-catalog"]}, CATALOG, BASE)) is not None, True)
check("a program already effective is not approvable (nothing to approve)",
      tc.approvable_programs({"approvable": ["nmap"]}, CATALOG, BASE), set())
check("a grant is honoured for an offered program", tc.granted_programs({"programs": ["curl"]}, S, CATALOG, eff), {"curl"})
check("a grant for a program NOT offered grants nothing", tc.granted_programs({"programs": ["whois"]}, S, CATALOG, eff), set())
S2 = tc.validate_settings({"approvable": []}, CATALOG, BASE)
check("withdrawing the offer revokes an existing grant at once",
      tc.granted_programs({"programs": ["curl"]}, S2, CATALOG, BASE), set())
check("a malformed grant file grants nothing", tc.granted_programs({"programs": "curl"}, S, CATALOG, eff), set())
check("granted programs bring their own argument rules", tc.patterns_for_programs({"curl"}, CATALOG), ["-X"])

section("a real layout on disk")
root = Path(tempfile.mkdtemp())
shared = root / "shared"; (shared / "agents" / "enum").mkdir(parents=True)
# The installed layout: the reviewed catalog lives with the CODE, not in the
# data root's shared/ (a catalog there is ignored; it was the old place).
(root / "lib").mkdir()
(root / "lib" / "tool-catalog.json").write_text(json.dumps(CATALOG))
os.environ["AGENTI_LIBDIR"] = str(root / "lib")
(shared / "agents" / "enum" / "capabilities.json").write_text(json.dumps({"command_line_tools": {
    "enforced": True, "items": [{"name": "nmap", "purpose": "s"}, {"name": "ping", "purpose": "p"}]}}))
org = root / "org"; (org / "enum" / "instances" / "op1" / "state").mkdir(parents=True)
slot = org / "enum" / "instances" / "op1"
(org / "enum" / "tool-settings.json").write_text(json.dumps({"approvable": ["curl"]}))


def ask(program, reason="need headers", ts=None):
    with open(slot / "state" / "tool-requests.jsonl", "a") as f:
        f.write(json.dumps({"ts": ts or time.time(), "program": program, "reason": reason}) + "\n")


def pend():
    return ta.pending(slot, shared_dir=shared, org_dir=org, agent="enum")


check("nothing pending before the agent asks", pend(), [])
ask("curl"); ask("whois", "not offered"); ask("curl; rm -rf /", "bad name")
(slot / "state" / "tool-requests.jsonl").open("a").write("not json\n" + json.dumps({"ts": "x", "program": "curl"}) + "\n")
p = pend()
check("valid requests listed; junk and unsafe names skipped", sorted(r["program"] for r in p), ["curl", "whois"])
check("each says whether the admin actually offered it", {r["program"]: r["offered"] for r in p}, {"curl": True, "whois": False})
curl_id = next(r["id"] for r in p if r["program"] == "curl")
who_id = next(r["id"] for r in p if r["program"] == "whois")

check("approving something NOT offered is refused",
      "not something operators may approve" in (raises(lambda: ta.decide(slot, shared_dir=shared, org_dir=org, agent="enum",
                                                                           rid=who_id, decision="approve", by="op1", group=None)) or ""), True)
check("...and wrote no grant", (slot / ta.GRANTS_FILE).exists(), False)
check("a made-up id is refused", raises(lambda: ta.decide(slot, shared_dir=shared, org_dir=org, agent="enum",
                                                          rid="0" * 12, decision="approve", by="op1", group=None)) is not None, True)
r = ta.decide(slot, shared_dir=shared, org_dir=org, agent="enum", rid=curl_id, decision="approve", by="op1", group=None)
check("approving an offered program succeeds", (r["ok"], r["program"]), (True, "curl"))
check("the grant file names it", json.loads((slot / ta.GRANTS_FILE).read_text())["programs"], ["curl"])
check("the grant file is not writable by the group or others", oct(os.stat(slot / ta.GRANTS_FILE).st_mode & 0o777), "0o640")
check("the request is no longer pending", curl_id in [x["id"] for x in pend()], False)
check("deciding the same request twice is refused",
      raises(lambda: ta.decide(slot, shared_dir=shared, org_dir=org, agent="enum", rid=curl_id,
                               decision="approve", by="op1", group=None)) is not None, True)
ask("curl", "again later", ts=time.time() + 5)
r2 = next(x for x in pend() if x["reason"] == "again later")
ta.decide(slot, shared_dir=shared, org_dir=org, agent="enum", rid=r2["id"], decision="deny", by="op1", group=None)
check("declining records a decision but changes no grant",
      json.loads((slot / ta.GRANTS_FILE).read_text())["programs"], ["curl"])

section("what the running agent sees, at call time")
reader = rt.make_run_grants_reader(agent_dir=slot, org_dir=org, shared_dir=shared, agent="enum", baseline=BASE)
check("an approved program is usable, with its own argument rules", reader(), ({"curl"}, ["-X"]))
(org / "enum" / "tool-settings.json").write_text(json.dumps({"approvable": []}))
check("the admin withdrawing the offer stops it immediately", reader(), (set(), []))
(org / "enum" / "tool-settings.json").write_text(json.dumps({"approvable": ["curl"]}))
check("restoring the offer restores it (the grant file is still the operator's)", reader()[0], {"curl"})
(slot / ta.GRANTS_FILE).write_text("{ broken")
check("a corrupt grant file means nothing extra, never more access", reader(), (set(), []))
ta.clear(slot)
check("a fresh start clears grants and decisions",
      (slot / ta.GRANTS_FILE).exists() or (slot / ta.DECISIONS_FILE).exists(), False)
check("with no grant file the agent gets nothing extra", reader(), (set(), []))
check("offered_programs reflects the admin's list for building request_tool",
      rt.offered_programs(org_dir=org, shared_dir=shared, agent="enum", baseline=BASE), {"curl"})
(org / "enum" / "tool-settings.json").write_text(json.dumps({}))
check("nothing offered -> the request_tool capability does not exist",
      rt.offered_programs(org_dir=org, shared_dir=shared, agent="enum", baseline=BASE), set())

section("the admin's allow-list override reaches a run (agent_runtime.resolve_tool_allowlist)")
(org / "enum" / "tool-settings.json").write_text(json.dumps({"disable": ["ping"]}))
check("a program the admin removed is gone from the run's allow-list",
      rt.resolve_tool_allowlist(org_dir=org, shared_dir=shared, agent="enum",
                                baseline=BASE, denied_patterns=[])[0], BASE - {"ping"})
(org / "enum" / "tool-settings.json").write_text(json.dumps({"enable": ["curl"]}))
check("a catalog program the admin added is in it, with its argument rules",
      rt.resolve_tool_allowlist(org_dir=org, shared_dir=shared, agent="enum",
                                baseline=BASE, denied_patterns=[]), (BASE | {"curl"}, ["-X"]))
(org / "enum" / "tool-settings.json").write_text(json.dumps({}))


def resolve():
    return rt.resolve_tool_allowlist(org_dir=org, shared_dir=shared, agent="enum",
                                     baseline=BASE, denied_patterns=[])


def refused(fn):
    try:
        fn()
    except rt.ToolSettingsError as e:
        return str(e)
    return None


section("settings that cannot be applied stop the run (operator decision 2026-10-21)")
(org / "enum" / "tool-settings.json").unlink()
check("no settings file = no admin changes: the baseline, no refusal", resolve()[0], BASE)
(org / "enum" / "tool-settings.json").write_text("{ broken")
msg = refused(resolve) or ""
check("a corrupt settings file refuses (it used to fall back to the full baseline)",
      ("cannot be applied" in msg, "tool-settings set" in msg), (True, True))
(org / "enum" / "tool-settings.json").write_text(json.dumps({"enable": ["nc"]}))
check("a setting naming a program that is not in the catalog refuses", bool(refused(resolve)), True)
(org / "enum" / "tool-settings.json").write_text(json.dumps({"disable": ["ping"]}))
(shared / "tool-catalog.admin.json").write_text("not json")
check("a corrupt file of the admin's program additions refuses", "additions" in (refused(resolve) or ""), True)
(shared / "tool-catalog.admin.json").unlink()
os.environ["AGENTI_LIBDIR"] = str(root / "no-such-lib")
check("a missing reviewed catalog refuses, and says to reinstall",
      "reinstall" in (refused(resolve) or ""), True)
os.environ["AGENTI_LIBDIR"] = str(root / "lib")
check("...and with everything readable again, the removal applies", resolve()[0], BASE - {"ping"})
(org / "enum" / "tool-settings.json").write_text(json.dumps({}))

section("the agent-written request file is untrusted")
(org / "enum" / "tool-settings.json").write_text(json.dumps({"approvable": ["curl"]}))
secret = root / "elsewhere.jsonl"
secret.write_text(json.dumps({"ts": time.time(), "program": "curl", "reason": "STOLEN"}) + "\n")
slot2 = org / "enum" / "instances" / "op2"; (slot2 / "state").mkdir(parents=True)
(slot2 / "state" / "tool-requests.jsonl").symlink_to(secret)
check("a request file that is a symlink is ignored, not followed",
      ta.pending(slot2, shared_dir=shared, org_dir=org, agent="enum"), [])
slot3 = org / "enum" / "instances" / "op3"; slot3.mkdir()
(root / "other-dir").mkdir(); (root / "other-dir" / "tool-requests.jsonl").write_text(
    json.dumps({"ts": time.time(), "program": "curl", "reason": "STOLEN"}) + "\n")
(slot3 / "state").symlink_to(root / "other-dir")
check("a state/ folder that is a symlink is ignored too",
      ta.pending(slot3, shared_dir=shared, org_dir=org, agent="enum"), [])
slot4 = org / "enum" / "instances" / "op4"; (slot4 / "state").mkdir(parents=True)
(slot4 / "state" / "tool-requests.jsonl").write_text(
    json.dumps({"ts": time.time(), "program": "curl", "reason": "x" * 5000}) + "\n")
check("an enormous reason is cut to the limit",
      len(ta.pending(slot4, shared_dir=shared, org_dir=org, agent="enum")[0]["reason"]), ta.MAX_REASON)

print(f"\n{'=' * 52}\n  {PASS} passed, {FAIL} failed\n{'=' * 52}")
import shutil; shutil.rmtree(root, ignore_errors=True)
sys.exit(1 if FAIL else 0)
