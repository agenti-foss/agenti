#!/usr/bin/env python3
"""test_analysis_runner.py — the generic file-analysis runner
(shared/analysis_runner.py).

    python3 shared/test_analysis_runner.py

No root, no vault, no SDK (a structural fake of claude_agent_sdk is installed
first, as test_recon_runner.py does). What matters:
  * a manifest binds the runner to ONE agent and a list of analysis programs,
    and a hand-edited manifest cannot add a program the rules do not know;
  * the agent has analyze_file, read_output and the shared tools — and none of
    the recon tools (no run_scan, nothing that can reach a network);
  * it takes no target: a leftover run-target stops the run;
  * configure() needs no engagement, resolves the model and caps against the
    organisation's policy, and builds the instructions the model will read;
  * the report names the attached files with their SHA-256, leaves out the
    engagement lines it does not have, and is written even for a run that
    produced nothing.
"""
import io
import json
import os
import sys
import tempfile
import types
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

_fake = types.ModuleType("claude_agent_sdk")


def _tool(name, description, schema):
    def deco(fn):
        fn.tool_name, fn.description, fn.input_schema = name, description, schema
        return fn
    return deco


class _Stub:
    def __init__(self, *a, **k):
        pass


_fake.tool = _tool
_fake.ClaudeAgentOptions = _Stub
_fake.ClaudeSDKClient = _Stub
_fake.HookMatcher = _Stub
_fake.ResultMessage = type("ResultMessage", (), {})
_fake.create_sdk_mcp_server = lambda **kw: types.SimpleNamespace(**kw)
sys.modules["claude_agent_sdk"] = _fake

PASS = FAIL = 0


def check(label, got, want):
    global PASS, FAIL
    if got == want:
        PASS += 1; print(f"  [ OK ] {label}")
    else:
        FAIL += 1; print(f"  [FAIL] {label}\n         got  {got!r}\n         want {want!r}")


def section(t): print(f"\n=== {t} ===")


root = Path(tempfile.mkdtemp(prefix="agenti-test-analysis-"))
(root / "shared").mkdir()
(root / "org").mkdir()
os.environ["AGENTI_ROOT"] = str(root)
os.environ.pop("AGENTI_INSTANCE", None)
os.environ.pop("ANTHROPIC_API_KEY", None)

import analysis_runner as ar  # noqa: E402
import run_files  # noqa: E402


def write_manifest(name, programs, folder=None, **extra):
    d = root / "agents" / (folder or name); d.mkdir(parents=True, exist_ok=True)
    m = {"name": name, "title": "Pcap Analyser", "description": "test", "kind": "analysis",
         "scope_kind": "files", "tool_names": ["analyze_file", "read_output"],
         "programs": programs, **extra}
    p = d / "manifest.json"; p.write_text(json.dumps(m)); return p


def refuses(fn):
    try:
        fn()
    except SystemExit as e:
        return str(e)
    except ar.ManifestError as e:
        return str(e)
    return None


section("a manifest binds the runner to one agent and its programs")
ar.setup(write_manifest("pcap", [{"name": "tshark", "purpose": "decode"}, {"name": "capinfos", "purpose": "summarise"}]))
check("identity follows the manifest", (ar.AGENT_NAME, ar.AGENT_TITLE), ("pcap", "Pcap Analyser"))
check("the scope boundary is the attached files", ar.SCOPE.kind, "files")
check("the programs are exactly the two", ar.PROGRAMS, {"tshark", "capinfos"})
check("analyze_file and read_output are offered",
      [n for n in ar.CONTRACT.tool_names if n in ("analyze_file", "read_output")], ["analyze_file", "read_output"])
check("list_files, read_file and ask_operator come with every agent",
      {"list_files", "read_file", "ask_operator"} <= set(ar.CONTRACT.tool_names), True)
check("none of the recon tools exist", {"run_scan", "read_scan", "fetch_page"} & set(ar.CONTRACT.tool_names), set())
check("no team tools for a solo run", {"team_message", "propose_complete"} & set(ar.CONTRACT.tool_names), set())
analyze = next(t for n, t in zip(ar.CONTRACT.tool_names, ar.CONTRACT.tools) if n == "analyze_file")
check("the model is told about exactly the programs it has",
      "tshark" in analyze.description and "capinfos" in analyze.description, True)

ar.setup(write_manifest("only-info", [{"name": "capinfos", "purpose": "summarise"}]))
analyze = next(t for n, t in zip(ar.CONTRACT.tool_names, ar.CONTRACT.tools) if n == "analyze_file")
check("an agent given one program is told about one program",
      ("capinfos" in analyze.description, "tshark" in analyze.description), (True, False))

section("a hand-edited manifest cannot widen the agent")
for bad in ("bash", "python3", "nmap", "wireshark", "tcpdump"):
    msg = refuses(lambda b=bad: ar.setup(write_manifest("evil", [{"name": b, "purpose": "x"}])))
    check(f"{bad!r} refused as not an analysis program", msg is not None and "not an analysis program" in msg, True)
check("an empty program list refused", refuses(lambda: ar.setup(write_manifest("evil", []))) is not None, True)
msg = refuses(lambda: ar.setup(write_manifest("evil", [{"name": "tshark", "purpose": "x"}], scope_kind="cidr")))
check("a network recon manifest is not run by this runner", msg is not None and "file-analysis" in msg, True)
msg = refuses(lambda: ar.setup(write_manifest("evil", [{"name": "tshark", "purpose": "x"}], kind="recon")))
check("a manifest of another kind is refused", msg is not None, True)
msg = refuses(lambda: ar.setup(write_manifest("evil", [{"name": "tshark", "purpose": "x"}], folder="other")))
check("a manifest in another agent's folder is refused", msg is not None and "must match" in msg, True)

section("configure(): no engagement, no target, an explicit model")
ar.setup(write_manifest("pcap", [{"name": "tshark", "purpose": "decode"}, {"name": "capinfos", "purpose": "summarise"}]))
slot = root / "org" / "pcap" / "instances" / "alice"
slot.mkdir(parents=True)
os.environ["AGENTI_INSTANCE"] = str(slot)
ar.setup(root / "agents" / "pcap" / "manifest.json")        # re-bind to the slot
rc = slot / "run-context"; rc.mkdir()
(rc / "versions.json").write_text("{}")
(rc / "system-prompt.md").write_text("Find any credentials in the capture and report them.\n")
prof = ar.PROFILES["run"]

msg = refuses(lambda: ar.configure(prof))
check("a run with no model is refused, naming the allowed models",
      msg is not None and "no model was specified" in msg and "haiku" in msg.lower(), True)

(slot / "run-config.json").write_text(json.dumps({"model": "haiku"}))
msg = refuses(lambda: ar.configure(prof))
check("without an API key it refuses before doing anything", msg is not None and "ANTHROPIC_API_KEY" in msg, True)

os.environ["ANTHROPIC_API_KEY"] = "test-key-not-real"
(slot / "run-target").write_text("10.0.0.5\n")
msg = refuses(lambda: ar.configure(prof))
check("a leftover target stops the run — this kind takes none", msg is not None and "takes no target" in msg, True)
(slot / "run-target").unlink()

(slot / "run-config.json").write_text(json.dumps({"model": "haiku", "max_turns": 999999}))
msg = refuses(lambda: ar.configure(prof))
check("a cap above the organisation's ceiling is refused", msg is not None and "ceiling" in msg, True)

(slot / "run-config.json").write_text(json.dumps({"model": "haiku", "max_turns": 7}))
final = ar.configure(prof)
check("with no engagement at all, configure() succeeds", final.max_turns, 7)
check("the model is the resolved id", final.model.startswith("claude-"), True)
check("the analysis and reports folders exist", ((slot / "analysis").is_dir(), (slot / "reports").is_dir()), (True, True))
check("the instructions begin with the file-analysis preamble", ar.SYSTEM_PROMPT.startswith("You are a file-analysis agent"), True)
check("...and carry the admin's own instructions", "Find any credentials in the capture" in ar.SYSTEM_PROMPT, True)
check("...with the credentials rule keyed to those instructions",
      "ask you to find or recover credentials" in ar.SYSTEM_PROMPT, True)
check("the instructions never describe an engagement scope to stay within",
      "IN SCOPE" in ar.SYSTEM_PROMPT or "ENGAGEMENT" in ar.SYSTEM_PROMPT, False)

section("the report")
run_files.attach(io.BytesIO(b"\x00" * 64), [("pcap", "pending", slot)], name="cap.pcap", by="alice")
run_files.begin_run(slot)
ar.EXECUTED_COMMANDS.append({"command": "tshark -r cap.pcap -w x", "verdict": "DENIED: -w", "output": None})
ar.EXECUTED_COMMANDS.append({"command": "capinfos cap.pcap", "verdict": "ok", "output": "capinfos_1.txt"})
(slot / "analysis" / "capinfos_1.txt").write_text("Number of packets: 1\n")
import time  # noqa: E402
path = ar.write_report(final, None, time.time() - 5, "incomplete", findings="The password is hunter2 (frame 9).",
                       note="ended early")
text = path.read_text()
check("a report is written even though no run produced a result", path.exists(), True)
check("the title names the agent, with no engagement id", text.startswith("# Pcap Analyser — Analysis Report\n"), True)
check("no client/authorization lines (there is no engagement)", ("**Client:**" in text, "Authorized by" in text), (False, False))
check("the scope line says what was analysed", "**Scope analysed (this run):**" in text, True)
import hashlib  # noqa: E402
check("the attached file is listed with its real SHA-256",
      "cap.pcap" in text and hashlib.sha256(b"\x00" * 64).hexdigest() in text, True)
check("the findings are included as the agent wrote them", "hunter2" in text, True)
check("the commands table shows the refusal and the success",
      ("DENIED: -w" in text, "capinfos_1.txt" in text), (True, True))
check("the saved output is listed with its size", "analysis/capinfos_1.txt" in text, True)
check("the note is kept", "ended early" in text, True)

# ---------------------------------------------------------------------------
# A cracking agent, end to end through the real tools. Run 183c7543fd9d
# (2026-10-16) had the hashes and still cracked nothing: every john/hashcat
# call failed in the sandbox, and behind that, john was passed by bare name
# (it lives in /usr/sbin, off the sandbox PATH). Unit tests of the parser and
# the sandbox each passed; only this layer, the tool the model calls, shows it.
# The cracker is a closed agent (agenti-cracker): its hash_extract.py is present
# only where its private repo is overlaid on the open core.
if not (Path(__file__).resolve().parent / "hash_extract.py").exists():
    print("\n  [SKIP] the cracking agent — hash_extract.py (agenti-cracker) is not in this checkout. "
          "THIS SECTION PROVED NOTHING.")
else:
    section("a cracking agent: extract_hashes, then john on what it made")
    import asyncio  # noqa: E402
    import sandbox  # noqa: E402
    import analysis_programs  # noqa: E402
    ar.EXECUTED_COMMANDS.clear()
    cslot = root / "org" / "crack" / "instances" / "alice"
    cslot.mkdir(parents=True)
    os.environ["AGENTI_INSTANCE"] = str(cslot)
    ar.setup(write_manifest("crack", [{"name": "john", "purpose": "crack"}, {"name": "hashcat", "purpose": "crack"}]))
    check("an agent with a hash cracker also gets extract_hashes", "extract_hashes" in ar.CONTRACT.tool_names, True)
    (cslot / "run-context").mkdir()
    (cslot / "run-context" / "versions.json").write_text("{}")
    (cslot / "run-context" / "system-prompt.md").write_text("Crack the hashes.\n")
    (cslot / "run-config.json").write_text(json.dumps({"model": "haiku", "max_turns": 5}))
    crun = ar.configure(ar.PROFILES["run"])
    dump = ("...#....priv_passwd_get_sam_hashes...N!Administrator:500:aad3b435b51404eeaad3b435b51404ee:"
            "8846f7eaee8fb117ad06bdd830b7586c:::\n")
    run_files.attach(io.BytesIO(dump.encode()), [("crack", "pending", cslot)], name="dump.txt", by="alice")
    run_files.begin_run(cslot)
    _tools = dict(zip(ar.CONTRACT.tool_names, ar.CONTRACT.tools))


    def call(name, args):
        t = _tools[name]
        return asyncio.run(getattr(t, "handler", t)(args))


    r = call("extract_hashes", {"file": "dump.txt"})
    made = "hashes-dump-nt.txt"
    check("extract_hashes writes a clean NT file from a noisy line",
          (cslot / "analysis" / "hashes" / made).read_text(), "Administrator:8846f7eaee8fb117ad06bdd830b7586c\n")
    check("...tells the model its name and the john command", made in r["content"][0]["text"], True)
    check("...and the report ledger carries its SHA-256",
          any(a["output"] == f"hashes/{made}" and "sha256" in a["verdict"] for a in ar.EXECUTED_COMMANDS), True)
    r = call("extract_hashes", {"file": "../../etc/passwd"})
    check("it reads only attached files", r.get("is_error"), True)
    r = call("analyze_file", {"command": "john --format=NT --wordlist=/wordlists/nope.txt " + made})
    if analysis_programs.binary_path("john"):
        check("a wordlist that does not exist is refused before anything runs, with what does",
              r.get("is_error") and "does not exist on this host" in r["content"][0]["text"], True)
    else:
        # Without john the call stops one step earlier, at "not installed".
        check("(john is not installed here) the call is refused as not installed",
              r.get("is_error") and "not installed on this host" in r["content"][0]["text"], True)
        print("  [SKIP] the missing-wordlist answer — john is not installed here. THIS CHECK PROVED NOTHING.")
    probe = sandbox.run(["/bin/true"], "light") if sandbox.available() else None
    if not (probe and probe.ok and analysis_programs.binary_path("john")):
        print("  [SKIP] john in the sandbox — bubblewrap or john unavailable here. "
              "THE LIVE HALF OF THIS SECTION PROVED NOTHING.")
    else:
        r = call("analyze_file", {"command": "john --list=formats"})
        check("john runs in the sandbox by its real path (no 'execvp john')",
              (r.get("is_error"), "execvp" in r["content"][0]["text"]), (None, False))
        r = call("analyze_file", {"command": f"john --format=NT --show {made}"})
        check("john reads the derived hash file", "1 left" in r["content"][0]["text"]
              or "password hash" in r["content"][0]["text"], True)
        # A real crack, both programs: a one-word list holding the password whose
        # NT hash is in the dump (8846f7ea… is NT("password")).
        wl = root / "wordlists"
        wl.mkdir()
        (wl / "tiny.txt").write_text("letmein\npassword\n")
        _mounts = analysis_programs.WORDLIST_MOUNTS
        analysis_programs.WORDLIST_MOUNTS = ((str(wl), "/wordlists"),)
        try:
            call("analyze_file", {"command": f"john --format=NT --wordlist=/wordlists/tiny.txt {made}"})
            r = call("analyze_file", {"command": f"john --format=NT --show {made}"})
            check("john cracks it, and --show names the account", "Administrator:password" in r["content"][0]["text"], True)
            if analysis_programs.binary_path("hashcat"):
                r = call("analyze_file", {"command": f"hashcat -m 1000 -a 0 --wordlist=/wordlists/tiny.txt --username {made}"})
                check("hashcat cracks it too, and its 'exhausted' exit is not an error", r.get("is_error"), None)
                check("...writing hash:password to cracked.txt",
                      (cslot / "analysis" / "cracked.txt").read_text().strip(),
                      "8846f7eaee8fb117ad06bdd830b7586c:password")
                (cslot / "analysis" / "hashcat.pot").unlink(missing_ok=True)
                (cslot / "analysis" / "cracked.txt").unlink(missing_ok=True)
                r = call("analyze_file", {"command": f"hashcat -m 1000 -a 0 --wordlist=/wordlists/tiny.txt {made}"})
                check("hashcat on an extracted NT file works without --username (the dispatcher adds it)",
                      (r.get("is_error"), (cslot / "analysis" / "cracked.txt").exists()), (None, True))
        finally:
            analysis_programs.WORDLIST_MOUNTS = _mounts

    import tool_registry  # noqa: E402
    _p = analysis_programs.parse_command(f"john --format=NT --incremental {made}", {"dump.txt"}, derived={made})
    check("a cracking run stops itself a minute before the sandbox would kill it",
          tool_registry._cracker_extra_flags(_p, "cracker"), ["--max-run-time=1740"])
    _p = analysis_programs.parse_command(f"john --show {made}", {"dump.txt"}, derived={made})
    check("...but --show is not a cracking run", tool_registry._cracker_extra_flags(_p, "cracker"), [])
    _p = analysis_programs.parse_command(f"hashcat -m 1000 -a 3 --mask=?d?d {made}", {"dump.txt"}, derived={made})
    check("hashcat gets --runtime and, on an extracted file, --username",
          tool_registry._cracker_extra_flags(_p, "cracker"), ["--runtime=1740", "--username"])


print(f"\n{'=' * 52}\n  {PASS} passed, {FAIL} failed\n{'=' * 52}")
sys.exit(1 if FAIL else 0)
