#!/usr/bin/env python3
"""test_run_coverage.py — which live runs an engagement change takes cover
from (shared/run_coverage.py, audit run 1 F04: stop only what lost cover).

    python3 shared/test_run_coverage.py

No root, no systemd: builds a real org folder with an engagement record and
asks the same function the CLI asks after every engagement change."""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import engagement_context as ec  # noqa: E402
import run_coverage  # noqa: E402

PASS = FAIL = 0


def check(label, got, want):
    global PASS, FAIL
    if got == want:
        PASS += 1; print(f"  [ OK ] {label}")
    else:
        FAIL += 1; print(f"  [FAIL] {label}\n         got  {got!r}\n         want {want!r}")


def section(t): print(f"\n=== {t} ===")


def record(**over):
    d = {"engagement_id": "COV-1", "client": "Acme", "authorizing_party": "Jane",
         "authorizing_title": "CISO", "authorization_ref": "SOW-1",
         "valid_from": "2020-01-01", "valid_until": "2099-12-31",
         "emergency_contact": "soc@acme.example", "notes": "",
         "scope": {"cidr": {"in_scope": ["10.0.0.0/24"], "out_of_scope": []},
                   "domain": {"in_scope": ["acme.example"], "out_of_scope": []}}}
    d.update(over)
    return d


org = Path(tempfile.mkdtemp(prefix="agenti-test-coverage-"))


def save(rec):
    (org / ec.ORG_ENGAGEMENT_FILENAME).write_text(json.dumps(rec))


def why(agent, kind, target):
    return run_coverage.why_uncovered(org, agent, kind, target)


section("a run the record still covers keeps going")
save(record())
check("enum on 10.0.0.5 is covered", why("enum", "cidr", "10.0.0.5"), "")
save(record(notes="a typo fixed after approval"))
check("an edit that still covers it (notes) does not stop it", why("enum", "cidr", "10.0.0.5"), "")
save(record(scope={"cidr": {"in_scope": ["10.0.0.0/16"]}, "domain": {"in_scope": ["acme.example"]}}))
check("a wider scope (awaiting approval) does not stop it", why("enum", "cidr", "10.0.0.5"), "")
check("trafficmon with no target is covered by the whole ceiling", why("trafficmon", "cidr", ""), "")

section("a run that lost cover is named, with the reason")
save(record(scope={"cidr": {"in_scope": ["10.0.1.0/24"]}, "domain": {"in_scope": ["acme.example"]}}))
check("scope cut: the target is out", why("enum", "cidr", "10.0.0.5").startswith("its target is no longer in scope"), True)
save(record(scope={"cidr": {"in_scope": ["10.0.0.0/24"], "out_of_scope": ["10.0.0.5"]},
                   "domain": {"in_scope": ["acme.example"]}}))
check("the target is now excluded", "no longer in scope" in why("enum", "cidr", "10.0.0.5"), True)
check("...a neighbour that is not excluded is still covered", why("enum", "cidr", "10.0.0.6"), "")
save(record(valid_until="2021-01-01"))
check("the window ended", "authorized window" in why("enum", "cidr", "10.0.0.5"), True)
save(record())
check("exploit with the capability off is stopped", why("exploit", "cidr", "10.0.0.5"),
      "the engagement no longer enables 'exploit'")
save(record(enabled_capabilities=["exploit"]))
check("...and covered while it is on", why("exploit", "cidr", "10.0.0.5"), "")
save(record(scope={"cidr": {"in_scope": ["10.0.0.0/24"]}, "domain": {"in_scope": ["other.example"]}}))
check("domain: research on acme.example after the domain was dropped",
      "no longer in scope" in why("research", "domain", "acme.example"), True)
check("a file-analysis kind is never stopped", why("cracker", "files", ""), "")

section("the command line the CLI runs")
tf = org / "run-target"; tf.write_text("10.0.0.5\n")
save(record(scope={"cidr": {"in_scope": ["10.0.1.0/24"]}, "domain": {"in_scope": ["acme.example"]}}))
r = subprocess.run([sys.executable, str(HERE / "run_coverage.py"), "check", "--org-dir", str(org),
                    "--agent", "enum", "--kind", "cidr", "--target-file", str(tf)], capture_output=True, text=True)
check("exit 3 and one line of reason when uncovered",
      (r.returncode, len(r.stdout.strip().splitlines())), (3, 1))
save(record())
r = subprocess.run([sys.executable, str(HERE / "run_coverage.py"), "check", "--org-dir", str(org),
                    "--agent", "enum", "--kind", "cidr", "--target-file", str(tf)], capture_output=True, text=True)
check("exit 0 and 'covered' when covered", (r.returncode, r.stdout.strip()), (0, "covered"))

section("audit run 2: a domain exclusion added UNDER a live run's target stops it")
dom = lambda out: record(scope={"cidr": {"in_scope": ["10.0.0.0/24"]},
                                "domain": {"in_scope": ["acme.example"], "out_of_scope": out}})
save(dom(["payroll.acme.example"]))
check("a new exclusion under the target: stopped",
      "payroll.acme.example is now excluded" in why("research", "domain", "acme.example"), True)
check("...the same exclusion in force at start: covered",
      run_coverage.why_uncovered(org, "research", "domain", "acme.example",
                                 frozenset({"payroll.acme.example"})), "")
check("...a run on a sibling the exclusion does not touch: covered",
      why("research", "domain", "www.acme.example"), "")
r = subprocess.run([sys.executable, str(HERE / "run_coverage.py"), "exclusions", "--org-dir", str(org),
                    "--agent", "research"], capture_output=True, text=True)
check("'exclusions' prints the effective list for the run-excluded marker",
      (r.returncode, r.stdout.split()), (0, ["payroll.acme.example"]))
dtf = org / "d-run-target"; dtf.write_text("acme.example\n")
mark = org / "run-excluded"; mark.write_text(r.stdout)
cli = [sys.executable, str(HERE / "run_coverage.py"), "check", "--org-dir", str(org), "--agent", "research",
       "--kind", "domain", "--target-file", str(dtf)]
check("the CLI: covered with the start-time marker",
      subprocess.run(cli + ["--excluded-file", str(mark)], capture_output=True).returncode, 0)
check("...and stopped with no marker (fails closed)",
      subprocess.run(cli + ["--excluded-file", str(org / "missing")], capture_output=True).returncode, 3)

section("precheck: a start that would be refused is refused before a run slot exists")
pre = lambda kind, target, model: run_coverage.why_refused(org, "enum" if kind == "cidr" else "research",
                                                           kind, target, model)
save(record(policy={"require_approval": False}))
check("in scope, an allowed model: nothing to say", pre("cidr", "10.0.0.5", "sonnet"), [])
check("a domain run in scope: nothing to say", pre("domain", "www.acme.example", "sonnet"), [])
check("out of scope: one reason, phrased for a start",
      [r.split(":")[0] for r in pre("cidr", "192.0.2.1", "sonnet")], ["the target is not in scope"])
check("a wider range than the engagement: refused",
      len(pre("cidr", "10.0.0.0/16", "sonnet")), 1)
check("a model off the list: refused, naming the allowed ones",
      "Allowed:" in " ".join(pre("cidr", "10.0.0.5", "gpt-4")), True)
check("both wrong: both reasons", len(pre("cidr", "192.0.2.1", "gpt-4")), 2)
check("a file-analysis agent: only the model is checked", run_coverage.why_refused(org, "cracker", "files", "", "sonnet"), [])
save(record(valid_until="2021-01-01", policy={"require_approval": False}))
check("outside the engagement's dates: refused", len(pre("cidr", "10.0.0.5", "sonnet")), 1)
save(record())
check("approval required and missing: refused, naming the command",
      "sudo agenti engagement approve" in " ".join(pre("cidr", "10.0.0.5", "sonnet")), True)
save(record(policy={"require_approval": False}))
r = subprocess.run([sys.executable, str(HERE / "run_coverage.py"), "precheck", "--org-dir", str(org),
                    "--agent", "enum", "--kind", "cidr", "--target", "192.0.2.1", "--model", "gpt-4"],
                   capture_output=True, text=True)
check("the CLI: exit 3 and one reason per line", (r.returncode, len(r.stdout.strip().splitlines())), (3, 2))
r = subprocess.run([sys.executable, str(HERE / "run_coverage.py"), "precheck", "--org-dir", str(org),
                    "--agent", "enum", "--kind", "cidr", "--target", "10.0.0.5", "--model", "sonnet"],
                   capture_output=True, text=True)
check("...exit 0 and 'ok'", (r.returncode, r.stdout.strip()), (0, "ok"))

print(f"\n{'=' * 52}\n  {PASS} passed, {FAIL} failed\n{'=' * 52}")
sys.exit(1 if FAIL else 0)
