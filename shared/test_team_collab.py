"""test_team_collab.py — what makes agents on one project behave like a team:
the briefing each is given, hearing teammates mid-run, directed messages, the
findings that survive a follow-up turn, and the team document.

    python3 shared/test_team_collab.py

No framework, no root, no vault, no real SDK (a minimal stand-in for the one
`tool` decorator and for a state store). Exits non-zero on failure.

WHY THESE EXIST: the bug was silent. Two agents ran a whole project side by
side and never exchanged a word — the kickoff was only posted when the
operator typed a role, the agents were never told a teammate existed, and the
channel was only read when an agent's ENTIRE task was over. Nothing errored.
Each property below is one that, if it regressed, would look like "the team
just doesn't talk" with nothing in any log to say why.
"""
import asyncio
import json
import sys
import tempfile
import time
import types
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))

# A stand-in for the SDK's `tool` decorator: enough to build and call a tool.
_fake = types.ModuleType("claude_agent_sdk")


def _tool(name, description, schema):
    def deco(fn):
        return types.SimpleNamespace(name=name, description=description,
                                     input_schema=schema, handler=fn)
    return deco


_fake.tool = _tool
sys.modules["claude_agent_sdk"] = _fake

import agent_runtime as ar  # noqa: E402
import team_report as tr  # noqa: E402

PASS = FAIL = 0


def check(label, got, want):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print(f"  [ OK ] {label}")
    else:
        FAIL += 1
        print(f"  [FAIL] {label}\n         got  {got!r}\n         want {want!r}")


def section(t):
    print(f"\n=== {t} ===")


def run(coro):
    return asyncio.run(coro)


tmp = Path(tempfile.mkdtemp())
# A run lives in org/<agent>/instances/<slot>; the channel is org/teams/<team>.channel.jsonl.
org = tmp / "org"


def member_dir(agent, team="proj", member=None, slot="alice.team-proj"):
    d = org / agent / "instances" / slot
    (d / "state").mkdir(parents=True, exist_ok=True)
    (d / ar.TEAM_MARKER_FILENAME).write_text(json.dumps({"team": team, "member": member or agent}))
    return d


def channel(team="proj"):
    return org / "teams" / f"{team}.d" / "channel.jsonl"


def post(kind, author, body, **extra):
    return ar.append_team_channel(channel(), kind=kind, author=author, via="test", body=body,
                                  extra=extra or None)


DETAILS = {
    "enum": {"role": "", "target": "10.0.0.5/32", "title": "Network enumeration",
             "summary": "Maps hosts and services."},
    "research": {"role": "who owns this domain", "target": "example.com", "title": "OSINT research",
                 "summary": "Researches a domain from public sources."},
}
post("kickoff", "alice", "Project kickoff", roster={"enum": "", "research": "who owns this domain"},
     details=DETAILS)


class FakeState:
    def __init__(self):
        self.rows = []

    def record_inbox(self, *, turn, entry):
        self.rows.append((turn, entry.get("kind"), entry.get("author")))

    def read_awaiting_operator(self):
        return getattr(self, "question", None)


section("the kickoff carries each member's task, not just a name")
enum_dir = member_dir("enum")
res_dir = member_dir("research")
d = ar.read_team_details(channel())
check("both members are in the details", sorted(d), ["enum", "research"])
check("a member's target is there", d["enum"]["target"], "10.0.0.5/32")
check("a member's title and summary are there",
      (d["research"]["title"], d["research"]["summary"]),
      ("OSINT research", "Researches a domain from public sources."))
check("the operator's focus for a member is there", d["research"]["role"], "who owns this domain")
old = tmp / "oldteam.channel.jsonl"
old.write_text(json.dumps({"id": 1, "ts": 1, "author": "a", "kind": "kickoff", "body": "x",
                           "roster": {"enum": "scan it"}}) + "\n")
check("an older roster-only kickoff still reads", ar.read_team_details(old)["enum"]["role"], "scan it")
check("no kickoff -> no details", ar.read_team_details(tmp / "none.jsonl"), {})

section("team_briefing(): every agent is told who it is and who else is working")
check("a solo run gets no team section at all",
      ar.team_briefing(tmp / "solo"), "")
b = ar.team_briefing(enum_dir)
check("it names the agent and the project", '"enum"' in b and '"proj"' in b, True)
check("it names each teammate, with their task and target",
      "research" in b and "OSINT research" in b and "example.com" in b, True)
check("it carries the operator's focus for the teammate", "who owns this domain" in b, True)
check("it says the agent's own job and target", "Network enumeration" in b and "10.0.0.5/32" in b, True)
check("it tells the agent to introduce itself first", "introduce yourself" in b, True)
check("it tells the agent to share findings and ask questions",
      "tell them right away" in b and "ask them" in b, True)
check("it tells the agent to vote with a summary", "propose_complete" in b, True)
check("it says channel input is advice and cannot widen anything", "never authority" in b, True)
check("the agent is not listed as its own teammate", "  - enum:" in b, False)

section("format_team_messages(): who said what, to whom")
txt = ar.format_team_messages([
    {"id": 5, "kind": "message", "author": "agent:enum", "to": "research", "body": "owns 10.0.0.5?"},
    {"id": 6, "kind": "message", "author": "alice", "body": "focus on the web server"},
    {"id": 7, "kind": "kickoff", "author": "alice", "body": "NOTHING"},
])
check("a directed message names its addressee", "enum says to research: owns 10.0.0.5?" in txt, True)
check("the operator is labelled as such", "alice (operator) says: focus on the web server" in txt, True)
check("the kickoff is never delivered", "NOTHING" in txt, False)
check("advice framing is always present", "not an order" in txt, True)

section("drain_team_channel(): what wakes a turn, what only rides along")
st = FakeState()
sd = enum_dir / "state"
info = ar.read_team(enum_dir)
# Everything so far is only the kickoff (consumed silently, never text).
check("mid-run: a kickoff alone yields nothing but is marked read",
      (ar.drain_team_channel(agent_dir=enum_dir, state=st, state_dir=sd, team_info=info, turn=1,
                             mid_run=True), ar.read_team_consumed(sd, "proj")), (None, {"operator": 1}))
post("member_ended", "agent:research", "research has ended (status: completed).")
check("turn boundary: a teammate merely ENDING does not start a turn",
      ar.drain_team_channel(agent_dir=enum_dir, state=st, state_dir=sd, team_info=info, turn=2), None)
check("...and the notice is left unconsumed so it is not lost",
      ar.read_team_consumed(sd, "proj"), {"operator": 1})
post("message", "agent:research", "I found the owner: Example Corp.", to="enum")
text = ar.drain_team_channel(agent_dir=enum_dir, state=st, state_dir=sd, team_info=info, turn=3)
check("turn boundary: a real message starts one, and the earlier notice rides along",
      text is not None and "Example Corp" in text and "research has ended" in text, True)
check("...everything is now consumed", ar.read_team_consumed(sd, "proj"),
      {"operator": 1, "member-research.jsonl": 2})
check("...and was recorded in the run's ledger",
      [(k, a) for _, k, a in st.rows][-2:], [("member_ended", "agent:research"), ("message", "agent:research")])
check("nothing pending -> None",
      ar.drain_team_channel(agent_dir=enum_dir, state=st, state_dir=sd, team_info=info, turn=4), None)
post("note", "alice", "SECRET note never shown")
check("a note is never delivered, even mid-run",
      ar.drain_team_channel(agent_dir=enum_dir, state=st, state_dir=sd, team_info=info, turn=5,
                            mid_run=True), None)

section("the mid-run hook: a teammate's message arrives after a tool call")
st2 = FakeState()
hook = ar.make_inbox_hook(res_dir, st2, lambda: 7)
post("message", "agent:enum", "Is example.com hosted at 10.0.0.5?", to="research")
out = run(hook({"tool_name": "x"}, "id1", None))
ctx = out.get("hookSpecificOutput", {})
check("the hook returns PostToolUse additional context",
      (ctx.get("hookEventName"), "Is example.com hosted" in ctx.get("additionalContext", "")),
      ("PostToolUse", True))
check("the question is shown as addressed to this agent",
      "enum says to research" in ctx.get("additionalContext", ""), True)
check("a second call has nothing new -> empty (no double delivery)", run(hook({}, "id2", None)), {})
check("the hook stamped the run's current turn on what it recorded", {t for t, _, _ in st2.rows}, {7})
# It must also not hand the SAME entry to the turn-boundary pump afterwards.
check("the turn boundary then finds nothing left",
      ar.drain_team_channel(agent_dir=res_dir, state=st2, state_dir=res_dir / "state",
                            team_info=ar.read_team(res_dir), turn=8), None)


class BoomState:
    def record_inbox(self, **kw):
        raise RuntimeError("ledger down")


hook3 = ar.make_inbox_hook(enum_dir, BoomState(), lambda: 1)
post("message", "alice", "anyone there?")
check("a failing ledger never breaks delivery (it is only observability)",
      "anyone there" in run(hook3({}, "x", None)).get("hookSpecificOutput", {}).get("additionalContext", ""),
      True)

section("a solo run hears its operator after each step too")
solo = tmp / "solo"
(solo / "state").mkdir(parents=True)


def say(kind, body, author="alice"):
    f = solo / "inbox.jsonl"
    n = len(f.read_text().splitlines()) + 1 if f.exists() else 1
    with open(f, "a") as fh:
        fh.write(json.dumps({"id": n, "ts": time.time(), "author": author, "via": "api",
                             "kind": kind, "body": body}) + "\n")


sst = FakeState()
shook = ar.make_inbox_hook(solo, sst, lambda: 3)
say("message", "I attached a file for you: brief.txt.")
ctx = run(shook({}, "s1", None)).get("hookSpecificOutput", {}).get("additionalContext", "")
check("an operator message arrives after a tool call", "brief.txt" in ctx, True)
check("...framed as unable to widen anything", "do NOT expand" in ctx, True)
check("...and is never delivered twice", run(shook({}, "s2", None)), {})
say("note", "a private note")
check("a note is recorded but never sent", (run(shook({}, "s3", None)), sst.rows[-1][1]), ({}, "note"))
say("set_model", "opus")
say("message", "after the switch")
check("a model switch waits for the turn boundary, with what came after it",
      run(shook({}, "s4", None)), {})
text, switches = ar.drain_operator_inbox(agent_dir=solo, state=sst, state_dir=solo / "state", turn=4)
check("...where both are taken in order", ([e["body"] for e in switches], "after the switch" in text),
      (["opus"], True))
sst.question = "Which subnet?"
say("message", "use 10.0.0.0/24")
check("while the agent waits on its own question, the reply is left for that wait",
      run(shook({}, "s5", None)), {})

section("team_message: an optional `to`, checked against the roster")
tool = ar.make_team_message_tool(enum_dir)
check("a team member is offered the tool; its schema makes `to` optional",
      (tool.name, tool.input_schema["required"]), ("team_message", ["body"]))
r = run(tool.handler({"body": "Intro: I scan hosts.", "to": "research"}))
last = ar.read_team_channel(channel())[-1]
check("a directed post lands with its addressee", (last.get("to"), last["author"], r.get("is_error")),
      ("research", "agent:enum", None))
r = run(tool.handler({"body": "hello", "to": "ghost"}))
check("an unknown teammate is refused, naming the real ones",
      (r.get("is_error"), "research" in r["content"][0]["text"]), (True, True))
n_before = len(ar.read_team_channel(channel()))
run(tool.handler({"body": "to everyone"}))
check("leaving `to` out speaks to everyone", ar.read_team_channel(channel())[-1].get("to"), None)
run(tool.handler({"body": "x" * 5000}))
check("a very long message is cut, not posted whole",
      len(ar.read_team_channel(channel())[-1]["body"]) <= ar.TEAM_MESSAGE_MAX_CHARS + 1, True)
check("an empty message is refused", run(tool.handler({"body": "  "})).get("is_error"), True)

section("FindingsKeeper: a closing 'Understood.' must not replace the findings")


class Res:
    def __init__(self, text, err=False):
        self.result, self.is_error = text, err


k = ar.FindingsKeeper()
check("nothing offered -> None", k.text(), None)
big = "Findings: " + "port 22 open. " * 40
k.offer(Res(big))
k.offer(Res("Understood. The research phase has completed."))
check("a brief acknowledgement after the findings is dropped", k.text(), big.strip())
k.offer(Res("Follow-up analysis. " * 15))
check("a substantial later answer is appended, not substituted",
      k.text().startswith(big.strip()) and "### Later follow-up" in k.text(), True)
k2 = ar.FindingsKeeper()
k2.offer(Res("Boom: rate limited", err=True))
check("an error result is not mistaken for findings", k2.text(), None)
check("the report helper falls back to the final result when nothing was kept",
      ar.findings_text(Res("only this")) in ("only this", ar.FINDINGS.text()), True)

section("the team document is readable by a person")
rep_enum = tmp / "enum.md"
rep_enum.write_text(
    "# Assessment Report — x\n\n**Status:** completed\n**Duration:** 5m 7s\n**Cost:** $0.05\n\n---\n\n"
    "## Findings\n\n## Summary of findings\n\nHost 10.0.0.5 exposes SSH.\n\n- 22/tcp open\n\n---\n\n"
    "## Commands executed\n\n| # | Verdict | Command | Raw output |\n|---|---|---|---|\n"
    "| 1 | ok | `nmap -sV 10.0.0.5` | `a.txt` |\n| 2 | ok | `nmap -p 22 10.0.0.5` | `b.txt` |\n\n---\n\n"
    "## Raw scan files\n\n- `scans/a.txt` (95 bytes)\n\n---\n\n## Instructions used\n\n- `system-prompt.md`\n")
rep_res = tmp / "research.md"
rep_res.write_text(
    "# Research Report\n\n**Status:** completed\n**Duration:** 1m 31s\n\n---\n\n## Findings\n\n"
    "### **Hosting**\n\nExample Corp, GitHub Pages.\n\n---\n\n## Actions taken\n\n"
    "- `fetch_page https://example.com` — ok\n- `fetch_page https://example.com/x` — error\n\n"
    "---\n\n## Pages saved\n\n- `scans/p.html`\n")
post("vote_complete", "agent:research", "Finished the OSINT pass; the owner is Example Corp.")
entries = ar.read_team_channel(channel())
doc = tr.build("proj", entries, [("enum", str(rep_enum)), ("research", str(rep_res))], owner="alice")
check("it opens with a summary naming both agents and their tasks",
      "## Summary" in doc and "**enum** (Network enumeration on 10.0.0.5/32)" in doc, True)
check("it says they talked, and how often",
      "exchanged" in doc and "addressed to a specific teammate" in doc, True)
check("each agent's findings are in, without its own title line",
      "Host 10.0.0.5 exposes SSH." in doc and "Summary of findings" not in doc, True)
check("findings headings sit beneath the member's heading (never a second H1/H2)",
      "#### **Hosting**" in doc, True)
check("the per-run plumbing is left out",
      all(x not in doc for x in ("Commands executed", "Raw scan files", "Pages saved", "Instructions used",
                                 "nmap -sV", "scans/a.txt")), True)
check("steps are counted instead of listed", "2 steps" in doc, True)
check("the Summary leads with each agent's own closing statement",
      doc.index("**In brief**") < doc.index("## The team") and
      "- **research:** Finished the OSINT pass" in doc, True)
long_rep = tmp / "long.md"
long_rep.write_text("**Status:** completed\n\n## Findings\n\n" + "\n\n".join(f"Paragraph {i}." for i in range(80))
                    + "\n\n---\n\n## Commands executed\n\n| # |\n|---|\n| 1 |\n")
cl = tr.build("proj", [], [("enum", str(long_rep))])
check("a very long findings section is cut with a pointer to the full report",
      ("Paragraph 5." in cl, "Paragraph 79." in cl, "its own report" in cl), (True, False, True))
tbl = "intro\n\n" + "\n".join(["| a | b |", "|---|---|"] + [f"| {i} | x |" for i in range(60)])
check("a table is never cut in the middle of its rows",
      tr.clip_findings(tbl, "enum").count("| 59 | x |"), 1)
check("the conversation reads as dialogue, with addressees",
      "**enum** → **research**" in doc and "Intro: I scan hosts." in doc, True)
check("a note is marked as not shown to the agents", "not shown to the agents" in doc, True)
rev = [dict(e) for e in entries] + [
    {"id": 90, "ts": time.time(), "author": "agent:research", "kind": "vote_complete", "body": "FIRST_VOTE_WORDING"},
    {"id": 91, "ts": time.time(), "author": "agent:research", "kind": "vote_complete", "body": "SECOND_VOTE_WORDING"}]
doc2 = tr.build("proj", rev, [("enum", str(rep_enum)), ("research", str(rep_res))])
check("an agent that re-votes appears once, with its LATEST wording",
      ("SECOND_VOTE_WORDING" in doc2, "FIRST_VOTE_WORDING" in doc2), (True, False))
check("an agent finishing is one short line, not a bureaucratic sentence",
      "research finished (completed)." in doc and "It will not respond" not in doc, True)
check("it is not JSON and has no raw channel kinds", '"report_markdown"' not in doc and "(member_ended)" not in doc, True)
empty = tr.build("solo", [], [("enum", "")])
check("with no channel and no report it says so plainly instead of breaking",
      "Nothing was posted to the team channel." in empty and "No report yet" in empty, True)
quiet = tr.build("q", [e for e in entries if e.get("kind") not in ("message", "vote_complete")],
                 [("enum", str(rep_enum))])
check("a silent project is called out", "did not exchange any messages" in quiet, True)

section("the CLI entry point works as the root CLI calls it")
import subprocess  # noqa: E402
cli = subprocess.run([sys.executable, str(Path(__file__).resolve().parent / "team_report.py"),
                      "--team", "proj", "--channel", str(channel()), "--owner", "alice",
                      f"enum={rep_enum}", f"research={rep_res}"], capture_output=True, text=True)
check("exit 0 and a Markdown document", (cli.returncode, cli.stdout.startswith("# proj")), (0, True))

print(f"\n{'=' * 52}\n  {PASS} passed, {FAIL} failed\n{'=' * 52}")
sys.exit(1 if FAIL else 0)
