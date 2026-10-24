#!/usr/bin/env python3
"""test_agent_controls.py — the control-centre assembler and its drift check.

    python3 shared/test_agent_controls.py

No root, no systemd: live properties are passed in as dicts. What matters most
is that the drift check can actually FAIL — a check that can only ever pass is
worse than none, so each kind of disagreement is forced here.
"""
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import agent_controls as ac  # noqa: E402

PASS = FAIL = 0


def check(label, got, want):
    global PASS, FAIL
    if got == want:
        PASS += 1; print(f"  [ OK ] {label}")
    else:
        FAIL += 1; print(f"  [FAIL] {label}\n         got  {got!r}\n         want {want!r}")


tpl = ac.template_directives((HERE / "agenti-instance@.service").read_text())

print("\n=== constants stay in step with capability-dropin.sh ===")
sh = (HERE / "capability-dropin.sh").read_text()
check("template caps", tuple(re.search(r'^TEMPLATE_CAPS="([^"]+)"', sh, re.M).group(1).split()), ac.TEMPLATE_CAPS)

print("\n=== expected values come from the template ===")
check("template says no new privileges", tpl.get("NoNewPrivileges"), "yes")
check("template ceiling is the same list", tpl.get("AmbientCapabilities"), " ".join(ac.TEMPLATE_CAPS))
check("sandbox capability in step with capability-dropin.sh",
      re.search(r'^SANDBOX_CAP="([^"]+)"', sh, re.M).group(1), ac.SANDBOX_CAP)
check("sandbox relaxations in step with capability-dropin.sh",
      tuple(re.search(r'^SANDBOX_RELAX_BOOLEANS="([^"]+)"', sh, re.M).group(1).split()), ac.SANDBOX_RELAX_BOOLEANS)
_exp = ac.expected_privileges(tpl, ["CAP_SYS_ADMIN"])
check("a file-analysis agent: CAP_SYS_ADMIN in the ceiling only, never ambient",
      (_exp["AmbientCapabilities"], _exp["CapabilityBoundingSet"]), ("", "cap_sys_admin"))
check("...and the two sandbox booleans are expected off",
      (_exp["RestrictSUIDSGID"], _exp["ProtectKernelTunables"]), ("no", "no"))

print("\n=== expected privileges per capability file ===")
e = ac.expected_privileges(tpl, None)
check("no file -> the full template grant", (e["AmbientCapabilities"], e["RestrictSUIDSGID"]),
      ("cap_net_admin cap_net_raw", "yes"))
e = ac.expected_privileges(tpl, [])
check("empty file -> no capabilities at all", (e["AmbientCapabilities"], e["CapabilityBoundingSet"]), ("", ""))
e = ac.expected_privileges(tpl, ["CAP_NET_RAW"])
check("a narrowed file -> just that capability, ambient and bounding",
      (e["AmbientCapabilities"], e["CapabilityBoundingSet"]), ("cap_net_raw", "cap_net_raw"))
check("...and no hardening boolean is relaxed",
      (e["RestrictSUIDSGID"], e["ProtectKernelTunables"], e["ProtectKernelModules"]), ("yes", "yes", "yes"))

print("\n=== the drift check can fail ===")
good = {k: v for k, v in ac.expected_privileges(tpl, None).items()}
live = dict(good); live.update({"LoadState": "loaded", "UnitFileState": "static"})
rows = ac.drift_checks(good, live)
check("matching live state -> all ok", {r["status"] for r in rows}, {"ok"})
bad = dict(live); bad["NoNewPrivileges"] = "no"
check("a weakened boolean fails", [r["name"] for r in ac.drift_checks(good, bad) if r["status"] == "fail"], ["NoNewPrivileges"])
bad = dict(live); bad["AmbientCapabilities"] = "cap_net_admin cap_net_raw cap_sys_admin"
check("an extra live capability fails", [r["name"] for r in ac.drift_checks(good, bad) if r["status"] == "fail"], ["AmbientCapabilities"])
bad = dict(live); bad["AmbientCapabilities"] = "cap_net_raw cap_net_admin"
check("capability ORDER does not cause a false alarm", {r["status"] for r in ac.drift_checks(good, bad)}, {"ok"})
bad = dict(live); bad["UnitFileState"] = "enabled"
check("a unit that starts on boot fails", [r["name"] for r in ac.drift_checks(good, bad) if r["status"] == "fail"], ["never starts on boot"])
check("unit not loaded -> unknown, not a failure", {r["status"] for r in ac.drift_checks(good, None)}, {"unknown"})

print("\n=== the page reads the installed layout (shipped agent, data root elsewhere) ===")
import argparse  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402
import tempfile  # noqa: E402
tmp = Path(tempfile.mkdtemp())
lib, data = tmp / "usr-lib-agenti", tmp / "var-lib-agenti-data"
(lib / "agents" / "enum" / "context").mkdir(parents=True)
(lib / "tool-catalog.json").write_text(json.dumps({"programs": [
    {"name": "sslscan", "group": "tls", "purpose": "tls", "extra_denied": []}]}))
(data / "shared").mkdir(parents=True)
(data / "shared" / "tool-catalog.admin.json").write_text(json.dumps({"programs": [   # an admin's addition
    {"name": "curl", "group": "web", "purpose": "fetch", "extra_denied": ["-X"]}]}))
(lib / "agents" / "enum" / "capabilities.json").write_text(json.dumps({"command_line_tools": {
    "enforced": True, "items": [{"name": "nmap", "purpose": "scan"}, {"name": "ping", "purpose": "reach"}]}}))
(lib / "agents" / "enum" / "context" / "system-prompt.md").write_text("shipped\n")
(data / "shared" / "context" / "agents" / "enum").mkdir(parents=True)
(data / "shared" / "context" / "agents" / "enum" / "system-prompt.md").write_text("the admin's edit\n")
(data / "org" / "enum").mkdir(parents=True)
(data / "org" / "enum" / "tool-settings.json").write_text(json.dumps({"disable": ["ping"], "enable": ["curl"]}))
os.environ["AGENTI_LIBDIR"] = str(lib)
page = ac.build(argparse.Namespace(agent="enum", org_dir=str(data / "org"),
                                   master_dir=str(lib / "agents" / "enum"), libdir=str(HERE)))
sec = {x["id"]: x for x in page["sections"]}
check("an edited system prompt shows as edited (found under the data root, not beside the code)",
      sec["instructions"]["rows"][0][1].split(",")[0], "edited")
check("the program list is the EFFECTIVE one: reviewed catalog from the code folder, the admin's "
      "additions and override from the data root",
      [r[0] for r in sec["programs"]["rows"]], ["curl", "nmap"])
check("...and it says what the admin changed", sec["programs"]["note"],
      "added by an admin: curl; removed by an admin: ping")

print(f"\n{'=' * 52}\n  {PASS} passed, {FAIL} failed\n{'=' * 52}")
sys.exit(1 if FAIL else 0)
