#!/usr/bin/env python3
"""test_agent_builder.py — building an agent from the GUI (shared/agent_builder.py):
the two kinds (network recon, file analysis) and the runner each one uses.

    python3 shared/test_agent_builder.py

No root, no vault, no SDK: the master copy is written into a temp tree with
chown stubbed out, and "which programs are installed" is stubbed so the test
does not depend on this machine's toolbox. The properties that matter:
  * only baseline and reviewed-catalog programs are ever offered or accepted;
  * every field is validated, and the spec has ONE canonical form, so the
    approval hash the API asks for equals the one the root CLI recomputes;
  * what is written is data plus a constant stub — nothing typed becomes code;
  * a hand-built agent can never be removed through this path.
"""
import grp
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import agent_builder as ab  # noqa: E402

PASS = FAIL = 0


def check(label, got, want):
    global PASS, FAIL
    if got == want:
        PASS += 1; print(f"  [ OK ] {label}")
    else:
        FAIL += 1; print(f"  [FAIL] {label}\n         got  {got!r}\n         want {want!r}")


def section(t): print(f"\n=== {t} ===")


def refused(fn, needle=""):
    try:
        fn()
    except ab.BuildError as e:
        return needle.lower() in str(e).lower()
    return False


root = Path(tempfile.mkdtemp(prefix="agenti-test-builder-"))
(root / "shared" / "agents").mkdir(parents=True)
(root / "shared" / "context" / "agents").mkdir(parents=True)
(root / "shared" / "tool-catalog.json").write_text((HERE / "tool-catalog.json").read_text())

# Pretend exactly these programs are installed.
tc = ab._import_catalog_module(root)
INSTALLED = {"nmap", "dig", "ping", "curl", "whois"}
tc.which_program = lambda n: f"/usr/bin/{n}" if n in INSTALLED else None
ap = ab._analysis_module(root)
ANALYSIS_INSTALLED = {"tshark", "capinfos", "suricata"}
ap.binary_path = lambda n: f"/usr/bin/{n}" if n in ANALYSIS_INSTALLED else None

section("the catalog offers the baseline and reviewed programs, and says what is installed")
cat = ab.catalog(root)
byname = {p["name"]: p for p in cat["programs"]}
check("the baseline recon programs are offered", {"nmap", "dig", "ping", "smbclient", "netexec"} <= set(byname), True)
check("reviewed catalog programs are offered too", {"curl", "whois", "sslscan"} <= set(byname), True)
check("each says where it came from", {byname["nmap"]["source"], byname["curl"]["source"]}, {"baseline", "reviewed"})
check("installed is reported per program", (byname["nmap"]["installed"], byname["sslscan"]["installed"]), (True, False))
check("nothing on the block list is ever offered",
      {"bash", "sh", "python3", "msfconsole", "sqlmap", "hydra"} & set(byname), set())

GOOD = {"name": "web-recon", "title": "Web recon", "description": "Looks at web servers.",
        "programs": ["whois", "curl", "nmap", "curl"],
        "system_prompt": "You look at web servers.\r\nReport headers and open ports.   \n\n"}

section("validation")
spec = ab.normalize(GOOD, root)
check("programs are de-duplicated and put in offered order", spec["programs"], ["nmap", "curl", "whois"])
check("line endings normalized, trailing space trimmed, one final newline",
      spec["system_prompt"], "You look at web servers.\nReport headers and open ports.\n")
check("the same choice in any order hashes the same",
      ab.spec_sha256(ab.normalize({**GOOD, "programs": ["curl", "nmap", "whois"]}, root)), ab.spec_sha256(spec))
check("a different prompt hashes differently",
      ab.spec_sha256(ab.normalize({**GOOD, "system_prompt": GOOD["system_prompt"] + "More.\n"}, root))
      != ab.spec_sha256(spec), True)
bad = lambda **kw: (lambda: ab.normalize({**GOOD, **kw}, root))
check("a bad short name is refused", refused(bad(name="Web Recon"), "short name"), True)
check("a reserved name is refused", refused(bad(name="admin"), "reserved"), True)
check("an empty title is refused", refused(bad(title="  "), "name is required"), True)
check("control characters in the description are refused", refused(bad(description="a‮b"), "control"), True)
check("no programs is refused", refused(bad(programs=[]), "at least one program"), True)
check("a shell is refused even if sent by hand", refused(bad(programs=["bash"]), "not a program"), True)
check("an exploitation tool is refused", refused(bad(programs=["sqlmap"]), "not a program"), True)
check("an invented program is refused", refused(bad(programs=["totally-made-up"]), "not a program"), True)
check("a listed program that is not installed is refused, with the apt command",
      refused(bad(programs=["sslscan"]), "sudo apt install sslscan"), True)
check("a tiny prompt is refused", refused(bad(system_prompt="hi"), "too short"), True)
check("a huge prompt is refused", refused(bad(system_prompt="x" * 25000), "too long"), True)
check("an unknown field is refused", refused(lambda: ab.normalize({**GOOD, "code": "import os"}, root), "unknown field"), True)
check("the old 'tools' and 'agent_kit' fields are gone",
      refused(lambda: ab.normalize({**GOOD, "agent_kit": "math"}, root), "unknown field"), True)

section("writing the master copy (chown stubbed)")
real_chown, real_getgrnam = os.chown, grp.getgrnam
os.chown = lambda *a, **k: None
grp.getgrnam = lambda name: SimpleNamespace(gr_gid=os.getgid())
try:
    out = ab.write(spec, root, by="alice")
finally:
    os.chown, grp.getgrnam = real_chown, real_getgrnam
md = root / "shared" / "agents" / "web-recon"
check("written into shared/agents/<name>", out["master_dir"], str(md))
stub = (md / "web-recon-agent.py").read_text()
check("the stub is the constant template (nothing from the form in it but the name)",
      stub, ab.KINDS["recon"]["stub"].format(name="web-recon"))
check("no title, description or prompt text leaked into code", "Web recon" in stub or "web servers" in stub, False)
check("the stub runs the shared recon runner", "recon_runner.main" in stub, True)
man = json.loads((md / "manifest.json").read_text())
check("manifest: a network recon agent with the fixed tools",
      (man["kind"], man["scope_kind"], man["tool_names"]), ("recon", "cidr", ["run_scan", "read_scan"]))
check("manifest records who built it", man["built"]["by"], "alice")
check("manifest carries the chosen programs, with purposes",
      [(p["name"], bool(p["purpose"])) for p in man["programs"]], [("nmap", True), ("curl", True), ("whois", True)])
check("the system prompt is shipped as the agent's default", (md / "context" / "system-prompt.md").read_text(), spec["system_prompt"])
check("there is no .capabilities file (a recon agent keeps the unit's default)",
      (md / "web-recon.capabilities").exists(), False)
caps = json.loads((md / "capabilities.json").read_text())
check("descriptor lists the programs, the tools and marks it built",
      ([i["name"] for i in caps["command_line_tools"]["items"]], [t["name"] for t in caps["mcp_tools"]], caps["built"]["by"]),
      (["nmap", "curl", "whois"], ["run_scan", "read_scan"], "alice"))
check("descriptor says the program list is enforced", caps["command_line_tools"]["enforced"], True)
check("no half-built folders left behind", [p.name for p in (root / "shared" / "agents").iterdir()], ["web-recon"])
check("building the same name twice is refused", refused(lambda: ab.normalize(GOOD, root), "already exists"), True)
check("modes: stub and manifest 0640, folder 0751",
      (oct(md.stat().st_mode & 0o777), oct((md / "manifest.json").stat().st_mode & 0o777)), ("0o751", "0o640"))

section("editing a built agent")
os.chown = lambda *a, **k: None
grp.getgrnam = lambda name: SimpleNamespace(gr_gid=os.getgid())
try:
    edit = ab.normalize_update({"name": "web-recon", "title": "Web auditor", "description": "Audits web servers.",
                                "programs": ["dig", "nmap"]}, root)
    check("an edit has no instructions in it", "system_prompt" in edit, False)
    check("an edit with instructions is refused",
          refused(lambda: ab.normalize_update({**edit, "system_prompt": "x" * 40}, root), "control centre"), True)
    check("a hand-built agent cannot be edited",
          refused(lambda: ab.normalize_update({**edit, "name": "enum"}, root), "not built")
          or refused(lambda: ab.normalize_update({**edit, "name": "enum"}, root), "no agent"), True)
    h0 = ab.spec_sha256(edit)
    before_prompt = (md / "context" / "system-prompt.md").read_text()
    out = ab.update(edit, root, by="bob")
finally:
    os.chown, grp.getgrnam = real_chown, real_getgrnam
man = json.loads((md / "manifest.json").read_text())
check("title and programs changed", (man["title"], [p["name"] for p in man["programs"]]), ("Web auditor", ["nmap", "dig"]))
check("who built it is kept, who edited it recorded", (man["built"]["by"], man["built"]["updated_by"]), ("alice", "bob"))
check("the instructions and stub are untouched",
      ((md / "context" / "system-prompt.md").read_text() == before_prompt,
       (md / "web-recon-agent.py").read_text() == ab.KINDS["recon"]["stub"].format(name="web-recon")), (True, True))
caps = json.loads((md / "capabilities.json").read_text())
check("the descriptor follows the new programs",
      [i["name"] for i in caps["command_line_tools"]["items"]], ["nmap", "dig"])
check("no leftover temp folders",
      sorted(p.name for p in (root / "shared" / "agents").iterdir() if p.name.startswith(".")), [])
check("the same edit hashes the same", ab.spec_sha256(ab.normalize_update({**edit}, root)), h0)

section("removing")
check("a built agent can be described for removal", ab.describe_built(root, "web-recon")["title"], "Web auditor")
hand = root / "shared" / "agents" / "enum"; hand.mkdir()
(hand / "manifest.json").write_text(json.dumps({"name": "enum"}))
check("a hand-built agent is refused", refused(lambda: ab.describe_built(root, "enum"), "not built"), True)
check("an unknown agent is refused", refused(lambda: ab.describe_built(root, "ghost"), "no agent"), True)
(root / "shared" / "context" / "agents" / "web-recon").mkdir(parents=True)
r = ab.delete_files(root, "web-recon")
check("delete removes the master copy and its edited instructions",
      (md.exists(), (root / "shared/context/agents/web-recon").exists(), len(r["removed"])), (False, False, 2))
check("the hand-built agent is untouched", hand.exists(), True)

section("the kinds")
check("there are two kinds a form can build", sorted(ab.KINDS), ["analysis", "recon"])
cat = ab.catalog(root)
kinds = {k["id"]: k for k in cat["kinds"]}
check("the catalog describes both, each with its own programs",
      (sorted(kinds), sorted(p["name"] for p in kinds["analysis"]["programs"])),
      (["analysis", "recon"], ["capinfos", "hashcat", "john", "suricata", "tshark"]))
check("the analysis list has only the reviewed analysis programs — nothing from the recon list",
      {p["name"] for p in kinds["analysis"]["programs"]} & {p["name"] for p in kinds["recon"]["programs"]}, set())
check("the old top-level `programs` is still the recon list", {p["name"] for p in cat["programs"]} >= {"nmap", "curl"}, True)
check("a kind not in KINDS is refused", refused(lambda: ab.normalize({**GOOD, "kind": "exploit"}, root), "kind must be"), True)
check("a spec with no kind is a recon agent (as every existing caller sends)", ab.normalize(GOOD, root)["kind"], "recon")

section("file analysis: validation")
PCAP = {"kind": "analysis", "name": "pcap-analyser", "title": "Pcap analyser",
        "description": "Reads packet captures.", "programs": ["tshark", "capinfos"],
        "system_prompt": "You read a packet capture and report credentials sent in clear text."}
pspec = ab.normalize(PCAP, root)
check("a file-analysis spec is accepted", (pspec["kind"], pspec["programs"]), ("analysis", ["tshark", "capinfos"]))
badp = lambda **kw: (lambda: ab.normalize({**PCAP, **kw}, root))
check("a recon program is refused for a file-analysis agent", refused(badp(programs=["nmap"]), "not a program a file-analysis agent"), True)
check("...and the refusal lists the reviewed ones", refused(badp(programs=["nmap"]), "capinfos, hashcat, john, suricata, tshark"), True)
check("a shell is refused here too", refused(badp(programs=["bash"]), "not a program"), True)
check("an analysis program is refused for a recon agent", refused(lambda: ab.normalize({**GOOD, "programs": ["tshark"]}, root), "not a program"), True)
ANALYSIS_INSTALLED.discard("tshark")
check("a program that is not installed is refused, naming the package that has it",
      refused(badp(programs=["tshark"]), "sudo apt install tshark"), True)
ANALYSIS_INSTALLED.discard("capinfos")
check("...including capinfos, which ships in the tshark package",
      refused(badp(programs=["capinfos"]), "sudo apt install tshark"), True)
ANALYSIS_INSTALLED.discard("suricata")
check("...and suricata, which is its own package",
      refused(badp(programs=["suricata"]), "sudo apt install suricata"), True)
ANALYSIS_INSTALLED.add("suricata")
ANALYSIS_INSTALLED.update({"tshark", "capinfos", "suricata"})
check("the kind is part of the approved spec: the same agent as recon hashes differently",
      ab.spec_sha256(ab.normalize({**PCAP, "name": "x-agent", "programs": ["tshark"]}, root))
      != ab.spec_sha256({**ab.normalize({**PCAP, "name": "x-agent", "programs": ["tshark"]}, root), "kind": "recon"}), True)

section("file analysis: writing the master copy")
os.chown = lambda *a, **k: None
grp.getgrnam = lambda name: SimpleNamespace(gr_gid=os.getgid())
try:
    ab.write(pspec, root, by="alice")
finally:
    os.chown, grp.getgrnam = real_chown, real_getgrnam
pd = root / "shared" / "agents" / "pcap-analyser"
pstub = (pd / "pcap-analyser-agent.py").read_text()
check("the stub is the analysis runner's constant", (pstub == ab.KINDS["analysis"]["stub"].format(name="pcap-analyser"),
      "analysis_runner.main" in pstub, "recon_runner" in pstub), (True, True, False))
pman = json.loads((pd / "manifest.json").read_text())
check("manifest: a file-analysis agent with its own tools and scope",
      (pman["kind"], pman["scope_kind"], pman["tool_names"], pman["category"]),
      ("analysis", "files", ["analyze_file", "read_output"], "file-analysis"))
check("manifest carries the chosen programs", [p["name"] for p in pman["programs"]], ["tshark", "capinfos"])
check("the .capabilities file asks for the sandbox capability and nothing else",
      [ln.strip() for ln in (pd / "pcap-analyser.capabilities").read_text().splitlines()
       if ln.strip() and not ln.startswith("#")], ["CAP_SYS_ADMIN"])
pcaps = json.loads((pd / "capabilities.json").read_text())
check("the descriptor says files scope, the analysis tools, no denied-pattern list, and a sandbox note",
      (pcaps["scope_kind"], [t["name"] for t in pcaps["mcp_tools"]], pcaps["denied_patterns"],
       "sandbox" in pcaps["command_line_tools"]["note"]),
      ("FilesScope", ["analyze_file", "read_output"], [], True))
check("describe says what kind it is", ab.describe_built(root, "pcap-analyser")["kind"], "analysis")

section("file analysis: editing")
os.chown = lambda *a, **k: None
grp.getgrnam = lambda name: SimpleNamespace(gr_gid=os.getgid())
try:
    pedit = ab.normalize_update({"name": "pcap-analyser", "title": "Pcap analyser v2",
                                 "description": "Reads captures.", "programs": ["tshark"]}, root)
    check("an edit that does not name the kind keeps the agent's own", pedit["kind"], "analysis")
    check("an edit cannot change the kind",
          refused(lambda: ab.normalize_update({"name": "pcap-analyser", "kind": "recon", "title": "T",
                                               "description": "d", "programs": ["nmap"]}, root), "cannot be changed"), True)
    ab.update(pedit, root, by="bob")
finally:
    os.chown, grp.getgrnam = real_chown, real_getgrnam
check("after an edit it is still the analysis stub and still has its capabilities file",
      ((pd / "pcap-analyser-agent.py").read_text() == ab.KINDS["analysis"]["stub"].format(name="pcap-analyser"),
       (pd / "pcap-analyser.capabilities").is_file()), (True, True))
check("the new program list took effect",
      [p["name"] for p in json.loads((pd / "manifest.json").read_text())["programs"]], ["tshark"])
ab.delete_files(root, "pcap-analyser")

section("enum is a stub over the same runner")
s = (HERE.parent / "enum-agent" / "enum-agent.py").read_text()
check("enum-agent.py is a stub over recon_runner", ("recon_runner.main" in s, len(s.splitlines()) < 20), (True, True))

print(f"\n{'=' * 52}\n  {PASS} passed, {FAIL} failed\n{'=' * 52}")
shutil.rmtree(root, ignore_errors=True)
sys.exit(1 if FAIL else 0)
