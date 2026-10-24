"""test_team_consensus.py — role/kickoff, completion consensus, and the two
new team primitives (propose_complete, ask_operator) added on top of the
existing team channel (CLAUDE.md's teams-in-the-GUI plan).

    python3 shared/test_team_consensus.py

No framework, no root, no vault, no SDK: pure-function tests against
agent_runtime.py, the same standard shared/test_team_channel.py already
sets for this file. Exits non-zero on failure.

WHAT IT IS FOR: team_consensus() is the one function that decides whether a
multi-agent project is "done" — every consensus display (an agent's own
standby loop inside pump_channels, and the GUI's team console) calls this
SAME function, so a bug here is a bug everywhere completion is computed.
The property that matters most and is easiest to get wrong: a vote must
become STALE the instant real new information (a `message`) lands after
it — that is the entire mechanism behind "stand by until new information
is shared, and check if it is valuable" from the operator's own spec.

What this file does NOT test: make_propose_complete_tool()'s and
make_ask_operator_tool()'s actual TOOL OBJECTS when a team/state is live
(needs claude_agent_sdk's real @tool decorator, not installed in this dev
sandbox — same limitation test_team_channel.py already documents for
make_team_message_tool). Both were verified live instead, with a
structurally-faithful fake SDK module, end to end: a real team member
composing team_message + propose_complete + ask_operator, calling
propose_complete for real and confirming the exact vote_complete entry it
appends — see the build log for the transcript.
"""
import json
import sys
import tempfile
import time
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import agent_runtime as ar  # noqa: E402
import state  # noqa: E402

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


tmp = Path(tempfile.mkdtemp())
org_dir = tmp / "opt" / "agenti" / "default"
agent_dir = org_dir / "enum"
agent_dir.mkdir(parents=True)
channel = ar.team_channel_path(agent_dir, "proj1")


def write_channel(entries):
    channel.parent.mkdir(parents=True, exist_ok=True)
    channel.write_text("\n".join(json.dumps(e) for e in entries) + ("\n" if entries else ""))


section("team_consensus(): the core completion computation")
check("no entries, two members -> nobody voted", ar.team_consensus([], ["a", "b"]),
      {"complete": False, "members": {
          "a": {"voted": False, "stale": False, "vote_id": None, "ended": False},
          "b": {"voted": False, "stale": False, "vote_id": None, "ended": False}}})

entries_both_voted = [
    {"id": 1, "kind": "kickoff", "author": "alice"},
    {"id": 2, "kind": "vote_complete", "author": "agent:a"},
    {"id": 3, "kind": "vote_complete", "author": "agent:b"},
]
r = ar.team_consensus(entries_both_voted, ["a", "b"])
check("both voted, no message since -> complete", r["complete"], True)
check("...neither vote is stale", (r["members"]["a"]["stale"], r["members"]["b"]["stale"]),
      (False, False))

entries_new_message = entries_both_voted + [
    {"id": 4, "kind": "message", "author": "agent:a", "body": "actually, one more thing"}]
r2 = ar.team_consensus(entries_new_message, ["a", "b"])
check("a message after both votes -> no longer complete", r2["complete"], False)
check("...BOTH votes are now stale (new info affects the whole team)",
      (r2["members"]["a"]["stale"], r2["members"]["b"]["stale"]), (True, True))

entries_a_revotes = entries_new_message + [
    {"id": 5, "kind": "vote_complete", "author": "agent:a"}]
r3 = ar.team_consensus(entries_a_revotes, ["a", "b"])
check("a re-votes after the new message -> a's vote is fresh again",
      r3["members"]["a"]["stale"], False)
check("...b's OLD vote is still stale", r3["members"]["b"]["stale"], True)
check("...still not complete (b hasn't reconsidered)", r3["complete"], False)

section("team_consensus(): only 'message' entries invalidate a vote")
entries_note_and_vote = entries_both_voted + [
    {"id": 4, "kind": "note", "author": "agent:a", "body": "internal note, never delivered"}]
r4 = ar.team_consensus(entries_note_and_vote, ["a", "b"])
check("a NOTE after voting does not make votes stale", r4["complete"], True)

entries_kickoff_after_vote = entries_both_voted + [
    {"id": 4, "kind": "kickoff", "author": "alice", "roster": {"a": "x", "b": "y"}}]
r5 = ar.team_consensus(entries_kickoff_after_vote, ["a", "b"])
check("a second KICKOFF does not itself make votes stale", r5["complete"], True)

section("team_consensus(): a member who never votes blocks consensus forever")
r6 = ar.team_consensus(entries_both_voted, ["a", "b", "c"])
check("a third, silent member -> never complete", r6["complete"], False)
check("...c correctly shown as never having voted", r6["members"]["c"]["voted"], False)


section("team_consensus(): a genuinely ENDED member is excused, not blocking (CLAUDE.md §4 item 47)")
# The real bug this closes: a project with `a` voted complete and `b`
# crashed before ever voting used to stay incomplete FOREVER — nothing
# distinguished "b is slow" from "b is gone".
entries_b_ended_never_voted = [
    {"id": 1, "kind": "vote_complete", "author": "agent:a"},
    {"id": 2, "kind": "member_ended", "author": "agent:b", "body": "b has ended (status: failed)"},
]
r7 = ar.team_consensus(entries_b_ended_never_voted, ["a", "b"])
check("a voted, b ended without voting -> complete anyway", r7["complete"], True)
check("...b is shown as ended, not voted", r7["members"]["b"], {"voted": False, "stale": False, "vote_id": None, "ended": True})
check("...a's own entry is unaffected", r7["members"]["a"]["voted"], True)

entries_b_ended_then_restarted = entries_b_ended_never_voted + [
    {"id": 3, "kind": "message", "author": "agent:b", "body": "restarted, back to work"}]
r8 = ar.team_consensus(entries_b_ended_then_restarted, ["a", "b"])
check("b posts again after ending (a restart) -> no longer excused",
      r8["members"]["b"]["ended"], False)
check("...back to blocking consensus, same as any silent member", r8["complete"], False)

entries_a_ends_after_voting = entries_both_voted + [
    {"id": 4, "kind": "member_ended", "author": "agent:a", "body": "a has ended (status: completed)"}]
r9 = ar.team_consensus(entries_a_ends_after_voting, ["a", "b"])
check("a member_ended AFTER a's own vote doesn't retroactively un-vote it",
      r9["members"]["a"]["voted"], True)
check("...and stays complete (both members accounted for)", r9["complete"], True)

entries_both_ended = [
    {"id": 1, "kind": "member_ended", "author": "agent:a", "body": "a has ended (status: failed)"},
    {"id": 2, "kind": "member_ended", "author": "agent:b", "body": "b has ended (status: failed)"},
]
r10 = ar.team_consensus(entries_both_ended, ["a", "b"])
check("every member ended, nobody ever voted -> still complete (both excused)",
      r10["complete"], True)


section("resource_cap_reason(): a THIRD outcome category alongside interrupted/error")
class _R:
    def __init__(self, subtype): self.subtype = subtype
check("error_max_turns -> 'max_turns'", ar.resource_cap_reason(_R("error_max_turns")), "max_turns")
check("error_max_budget_usd -> 'max_budget'", ar.resource_cap_reason(_R("error_max_budget_usd")), "max_budget")
check("a clean success -> None", ar.resource_cap_reason(_R("success")), None)
check("an interrupted/aborted result -> None (has its own reason already)",
      ar.resource_cap_reason(_R("error_during_execution")), None)
check("result is None -> None", ar.resource_cap_reason(None), None)


section("caps_exhausted(): recognizes a budget cutoff too, not just turns")
class _RB:
    subtype = "error_max_budget_usd"
    num_turns = 3
    total_cost_usd = 0.5


class _FakeProfileCaps:
    max_turns = 100
    max_budget_usd = 100.0


check("a budget-exhausted result is caught via the subtype, not just the tally",
      ar.caps_exhausted({"turns": 0, "cost": 0.0}, _FakeProfileCaps(), _RB()),
      "the budget cap was reached")


section("read_roster(): the kickoff entry's structured roster field")
check("no channel at all -> None", ar.read_roster(tmp / "nope.jsonl"), None)
write_channel([])
check("empty channel -> None", ar.read_roster(channel), None)
write_channel([{"id": 1, "kind": "message", "author": "x", "body": "no kickoff here"}])
check("a channel with no kickoff entry -> None", ar.read_roster(channel), None)
write_channel([
    {"id": 1, "kind": "kickoff", "author": "alice", "body": "...", "roster": {"a": "internal"}},
    {"id": 2, "kind": "message", "author": "agent:a", "body": "hi"},
    {"id": 3, "kind": "kickoff", "author": "alice", "body": "...", "roster": {"a": "internal", "b": "external"}},
])
check("the LATEST kickoff's roster wins, not the first",
      ar.read_roster(channel), {"a": "internal", "b": "external"})


section("read_role(): the per-agent run-role marker, read-only")
check("no run-role file -> None", ar.read_role(agent_dir), None)
(agent_dir / ar.TEAM_ROLE_FILENAME).write_text("internal network assessment\n")
check("run-role file -> its stripped contents", ar.read_role(agent_dir),
      "internal network assessment")
(agent_dir / ar.TEAM_ROLE_FILENAME).write_text("   \n")
check("whitespace-only run-role -> None, not an empty string", ar.read_role(agent_dir), None)
(agent_dir / ar.TEAM_ROLE_FILENAME).write_text("internal network assessment\n")


section("format_team_messages(): votes are delivered; the kickoff lives in the briefing")
entries = [
    {"id": 1, "kind": "kickoff", "author": "alice", "body": "roster: a=internal, b=external"},
    {"id": 2, "kind": "note", "author": "agent:a", "body": "SECRET internal note"},
    {"id": 3, "kind": "message", "author": "agent:b", "body": "starting the external scan"},
    {"id": 4, "kind": "vote_complete", "author": "agent:a", "body": "internal scan done, no findings"},
]
text = ar.format_team_messages(entries)
check("the kickoff is NOT re-delivered (the roster is already in the agent's instructions)",
      "roster: a=internal" in text, False)
check("a plain message is delivered", "starting the external scan" in text, True)
check("a vote's reasoning is delivered", "internal scan done, no findings" in text, True)
check("...and labelled as a vote, not a plain message",
      "says the project is complete" in text, True)
check("a note is STILL never delivered — the one property this file exists "
      "to protect, extended to two more kinds", "SECRET internal note" in text, False)
check("nothing but a note -> None (unchanged behavior)",
      ar.format_team_messages([entries[1]]), None)

section("format_team_messages(): member_ended is delivered too (CLAUDE.md §4 item 47)")
entries_ended = [
    {"id": 1, "kind": "member_ended", "author": "agent:b",
     "body": "b has ended (status: failed, reason: max_turns). It will not respond, vote, or post further."},
]
ended_text = ar.format_team_messages(entries_ended)
check("a member_ended entry is delivered (not silently dropped)",
      ended_text is not None and "will not respond" in ended_text, True)
check("...rendered as a system fact, not as if the ended member 'said' it",
      "[system]" in ended_text, True)


section("announce_team_member_ended(): posts to the real channel, no-ops for a solo run")
solo_dir = tmp / "solo_agent"
solo_dir.mkdir()
# No run-team marker at all -> read_team() returns None -> must be a silent
# no-op, same "not even offered" shape make_team_message_tool() already has.
ar.announce_team_member_ended(solo_dir, status="completed")
check("a solo run's directory gets no teams/ sibling created at all",
      (solo_dir.parent / "teams").exists(), False)

team_member_dir = tmp / "opt2" / "default" / "trafficmon"
team_member_dir.mkdir(parents=True)
(team_member_dir / ar.TEAM_MARKER_FILENAME).write_text(
    json.dumps({"team": "proj2", "member": "trafficmon"}))
ar.announce_team_member_ended(team_member_dir, status="incomplete", reason="max_turns")
posted = ar.read_team_channel(ar.team_channel_path(team_member_dir, "proj2"))
check("exactly one entry landed on the real channel file", len(posted), 1)
check("...kind is member_ended", posted[0]["kind"], "member_ended")
check("...author is non-forgeable — from the marker, not caller-suppliable",
      posted[0]["author"], "agent:trafficmon")
check("...names both the status and the reason",
      "incomplete" in posted[0]["body"] and "max_turns" in posted[0]["body"], True)

# A second call (e.g. a resumed run that ends again) must not raise or
# corrupt the append-only channel — just adds a second entry.
ar.announce_team_member_ended(team_member_dir, status="completed")
posted2 = ar.read_team_channel(ar.team_channel_path(team_member_dir, "proj2"))
check("a second end-of-run announcement appends cleanly", len(posted2), 2)

# The exact scenario this whole feature exists for, end to end: a's vote
# plus b's real announce_team_member_ended() call together reach 'complete'.
consensus_dir_a = tmp / "opt3" / "default" / "enum"
consensus_dir_a.mkdir(parents=True)
proj3_channel = ar.team_channel_path(consensus_dir_a, "proj3")
ar.append_team_channel(proj3_channel, kind="vote_complete", author="agent:enum",
                       via="tool", body="done")
consensus_dir_b = tmp / "opt3" / "default" / "research"
consensus_dir_b.mkdir(parents=True)
(consensus_dir_b / ar.TEAM_MARKER_FILENAME).write_text(
    json.dumps({"team": "proj3", "member": "research"}))
ar.announce_team_member_ended(consensus_dir_b, status="failed")
final = ar.team_consensus(ar.read_team_channel(proj3_channel), ["enum", "research"])
check("END TO END: a real vote + a real crash announcement -> the project "
      "reaches complete, the exact case that used to hang forever",
      final["complete"], True)


section("append_team_channel(): the new `extra` field, used by the CLI's kickoff")
extra_channel = tmp / "extra.channel.jsonl"
gid = ar.append_team_channel(extra_channel, kind="kickoff", author="alice", via="cli",
                             body="Team kickoff", extra={"roster": {"a": "internal"}})
check("append_team_channel returns the new id", gid, 1)
written = json.loads(extra_channel.read_text().splitlines()[0])
check("the extra field is merged into the entry", written.get("roster"), {"a": "internal"})
check("the ordinary fields are untouched", (written["kind"], written["author"], written["body"]),
      ("kickoff", "alice", "Team kickoff"))

gid2 = ar.append_team_channel(extra_channel, kind="message", author="agent:a", via="tool",
                              body="hello")
written2 = json.loads(ar.team_member_channel_path(extra_channel, "a").read_text().splitlines()[0])
check("a normal append (no extra) carries no stray fields",
      set(written2.keys()), {"id", "ts", "author", "via", "kind", "body"})


section("StateHolder: the mutable box ask_operator's tool closure reads")
holder = ar.StateHolder()
check("starts empty", holder.state, None)
fake_state_dir = tmp / "holder-state"
real_state = state.StateStore(fake_state_dir)
holder.state = real_state
check("can be filled in after construction (run() does this once a "
      "StateStore exists)", holder.state is real_state, True)


section("propose_complete tool: solo run offers nothing, matching team_message")
check("no run-team marker -> make_propose_complete_tool returns None",
      ar.make_propose_complete_tool(agent_dir), None)


section("pump_channels(): the shared pump's new control-flow paths, end to end")
# `asyncio.sleep` is patched to fire synchronously so these run instantly and
# to inject events mid-poll (a reply, a teammate's vote, new information) —
# proving the actual control flow, not just the pieces it's built from.
import asyncio
from unittest.mock import patch


class _FakeProfile:
    def __init__(self, data_root, max_turns=10, max_budget_usd=1.0):
        self.data_root = data_root
        self.max_turns = max_turns
        self.max_budget_usd = max_budget_usd


async def _pump_tests():
    pc_tmp = Path(tempfile.mkdtemp())

    # ---- ask_operator: wait for a reply, then deliver it and clear the flag ----
    solo_dir = pc_tmp / "solo"; solo_dir.mkdir()
    st = state.StateStore(solo_dir / "state")
    st.start(engagement_id="E", target="T", profile_name="dev")
    st.set_awaiting_operator("which host should I try next?")

    calls = {"n": 0}

    async def sleep_then_reply(_):
        calls["n"] += 1
        if calls["n"] == 2:
            (solo_dir / "inbox.jsonl").write_text(json.dumps(
                {"id": 1, "ts": time.time(), "author": "alice", "via": "cli",
                 "kind": "message", "body": "try 10.0.0.5"}) + "\n")

    with patch("agent_runtime.asyncio.sleep", sleep_then_reply):
        result = await ar.pump_channels(agent_dir=solo_dir, state=st, profile=_FakeProfile(solo_dir),
                                        result=None, turn=1, used={"turns": 0, "cost": 0.0})
    check("ask_operator: the reply is delivered once it arrives",
          result is not None and "try 10.0.0.5" in result, True)
    check("ask_operator: the flag is cleared after the reply", st.read_awaiting_operator(), None)
    check("ask_operator: it actually polled (didn't just return instantly)", calls["n"], 2)

    # ---- ask_operator: caps already exhausted -> ends immediately, no wait ----
    solo2 = pc_tmp / "solo2"; solo2.mkdir()
    st2 = state.StateStore(solo2 / "state")
    st2.start(engagement_id="E", target="T", profile_name="dev")
    st2.set_awaiting_operator("stuck")
    result2 = await ar.pump_channels(agent_dir=solo2, state=st2, profile=_FakeProfile(solo2, max_turns=1),
                                     result=None, turn=1, used={"turns": 5, "cost": 0.0})
    check("ask_operator: already-exhausted caps end the run instead of waiting", result2, None)

    # ---- standby: a teammate's vote arriving mid-wait is delivered, not
    # silently swallowed -- then the NEXT pump call recognizes consensus ----
    tdir = pc_tmp / "org"; tdir.mkdir()
    a_dir = tdir / "a"; a_dir.mkdir()
    b_dir = tdir / "b"; b_dir.mkdir()
    (a_dir / "run-team").write_text(json.dumps({"team": "proj", "member": "a"}))
    (b_dir / "run-team").write_text(json.dumps({"team": "proj", "member": "b"}))
    proj_channel = ar.team_channel_path(a_dir, "proj")
    ar.append_team_channel(proj_channel, kind="kickoff", author="alice", via="cli", body="kickoff",
                           extra={"roster": {"a": "role-a", "b": "role-b"}})
    ar.append_team_channel(proj_channel, kind="vote_complete", author="agent:a", via="tool", body="a is done")

    st_a = state.StateStore(a_dir / "state")
    st_a.start(engagement_id="E", target="T", profile_name="dev")
    # Simulate "a" having already read the kickoff during its earlier
    # working turns (long before it voted) — otherwise the FIRST thing
    # delivered here would just be the kickoff itself, not exercise standby.
    ar.write_team_consumed(a_dir / "state", "proj", ar.read_team_channel(proj_channel))

    polls = {"n": 0}

    async def sleep_then_teammate_votes(_):
        polls["n"] += 1
        if polls["n"] == 2:
            ar.append_team_channel(proj_channel, kind="vote_complete", author="agent:b",
                                   via="tool", body="b is done too")

    with patch("agent_runtime.asyncio.sleep", sleep_then_teammate_votes):
        result3 = await ar.pump_channels(agent_dir=a_dir, state=st_a, profile=_FakeProfile(a_dir),
                                         result=None, turn=1, used={"turns": 0, "cost": 0.0})
    check("standby: a teammate's fresh vote is delivered as one more turn "
          "(not silently swallowed)", result3 is not None and "b is done too" in result3, True)

    async def sleep_noop(_):
        pass
    with patch("agent_runtime.asyncio.sleep", sleep_noop):
        result3b = await ar.pump_channels(agent_dir=a_dir, state=st_a, profile=_FakeProfile(a_dir),
                                          result=None, turn=2, used={"turns": 0, "cost": 0.0})
    check("standby: consensus is recognized and the run ends on the very "
          "next cycle (no more content pending)", result3b, None)

    # ---- standby: genuinely new information breaks the wait and nudges
    # reconsideration, rather than looping past it ----
    c_dir = tdir / "c"; c_dir.mkdir()
    d_dir = tdir / "d"; d_dir.mkdir()
    (c_dir / "run-team").write_text(json.dumps({"team": "proj2", "member": "c"}))
    (d_dir / "run-team").write_text(json.dumps({"team": "proj2", "member": "d"}))
    channel2 = ar.team_channel_path(c_dir, "proj2")
    ar.append_team_channel(channel2, kind="kickoff", author="alice", via="cli", body="kickoff",
                           extra={"roster": {"c": "role-c", "d": "role-d"}})
    ar.append_team_channel(channel2, kind="vote_complete", author="agent:c", via="tool", body="c is done")
    st_c = state.StateStore(c_dir / "state")
    st_c.start(engagement_id="E", target="T", profile_name="dev")
    ar.write_team_consumed(c_dir / "state", "proj2", ar.read_team_channel(channel2))

    async def sleep_then_new_info(_):
        ar.append_team_channel(channel2, kind="message", author="agent:d", via="tool",
                               body="actually wait, found something new")

    with patch("agent_runtime.asyncio.sleep", sleep_then_new_info):
        result4 = await ar.pump_channels(agent_dir=c_dir, state=st_c, profile=_FakeProfile(c_dir),
                                         result=None, turn=1, used={"turns": 0, "cost": 0.0})
    check("standby: new information breaks the wait and is delivered",
          result4 is not None and "found something new" in result4, True)
    check("standby: it also nudges reconsideration of the now-stale vote",
          "reconsider" in result4.lower(), True)

    # ---- set-model: live model switching via the SAME inbox say/note use
    # (CLAUDE.md "Current plan") — applied through client.set_model(), never
    # sent to the model as text, re-checked against the org's CURRENT
    # policy at the moment of the switch, not what was true at launch. ----
    class _FakeClient:
        def __init__(self):
            self.calls = []
        async def set_model(self, model):
            self.calls.append(model)

    def _write_org_policy(org_dir, allowed_models):
        org_dir.mkdir(parents=True, exist_ok=True)
        rec = {
            "engagement_id": "E-1", "client": "Acme", "authorizing_party": "Jane",
            "authorizing_title": "CISO", "authorization_ref": "SOW-1",
            "valid_from": "2020-01-01", "valid_until": "2099-12-31",
            "scope": {"cidr": {"in_scope": ["10.0.0.0/24"], "out_of_scope": []},
                     "domain": {"in_scope": [], "out_of_scope": []}},
            "policy": {"allowed_models": allowed_models},
        }
        (org_dir / "engagement.json").write_text(json.dumps(rec))

    e_dir = pc_tmp / "e"; e_dir.mkdir()
    org_dir = pc_tmp / "org-e"
    _write_org_policy(org_dir, ["haiku", "sonnet"])
    st_e = state.StateStore(e_dir / "state")
    st_e.start(engagement_id="E", target="T", profile_name="run")
    (e_dir / "inbox.jsonl").write_text(json.dumps(
        {"id": 1, "ts": time.time(), "author": "alice", "via": "cli",
         "kind": "set_model", "body": "sonnet"}) + "\n")
    client_e = _FakeClient()

    async def sleep_end(_):
        pass
    with patch("agent_runtime.asyncio.sleep", sleep_end):
        result5 = await ar.pump_channels(agent_dir=e_dir, state=st_e, profile=_FakeProfile(e_dir),
                                         result=None, turn=1, used={"turns": 0, "cost": 0.0},
                                         client=client_e, org_dir=org_dir)
    check("set-model: an allowed alias resolves to the canonical id and is "
          "applied to the live client", client_e.calls, ["claude-sonnet-5"])
    check("set-model: never delivered to the model as text (it has no 'message' kind)",
          result5, None)

    f_dir = pc_tmp / "f"; f_dir.mkdir()
    _write_org_policy(pc_tmp / "org-f", ["haiku"])
    st_f = state.StateStore(f_dir / "state")
    st_f.start(engagement_id="E", target="T", profile_name="run")
    (f_dir / "inbox.jsonl").write_text(json.dumps(
        {"id": 1, "ts": time.time(), "author": "alice", "via": "cli",
         "kind": "set_model", "body": "opus"}) + "\n")
    client_f = _FakeClient()
    with patch("agent_runtime.asyncio.sleep", sleep_end):
        await ar.pump_channels(agent_dir=f_dir, state=st_f, profile=_FakeProfile(f_dir),
                               result=None, turn=1, used={"turns": 0, "cost": 0.0},
                               client=client_f, org_dir=pc_tmp / "org-f")
    check("set-model: a model NOT on the org's current allowed list is "
          "refused — client.set_model() is never called", client_f.calls, [])

    g_dir = pc_tmp / "g"; g_dir.mkdir()
    st_g = state.StateStore(g_dir / "state")
    st_g.start(engagement_id="E", target="T", profile_name="run")
    (g_dir / "inbox.jsonl").write_text(json.dumps(
        {"id": 1, "ts": time.time(), "author": "alice", "via": "cli",
         "kind": "set_model", "body": "sonnet"}) + "\n")
    with patch("agent_runtime.asyncio.sleep", sleep_end):
        await ar.pump_channels(agent_dir=g_dir, state=st_g, profile=_FakeProfile(g_dir),
                               result=None, turn=1, used={"turns": 0, "cost": 0.0},
                               client=None, org_dir=pc_tmp / "org-g")
    check("set-model: no live client reference given -> never crashes the run",
          True, True)


asyncio.run(_pump_tests())


section("waiting for the operator: its own 24-hour cap, and it does not spend the run's working clock")
_real_sleep = asyncio.sleep


async def _wait_clock_tests():
    wc_tmp = Path(tempfile.mkdtemp())

    def fresh(name):
        d = wc_tmp / name; d.mkdir()
        s = state.StateStore(d / "state")
        s.start(engagement_id="E", target="T", profile_name="dev")
        s.set_awaiting_operator("what is LHOST, and where do I find it?")
        ar._RUN_CLOCK.update({"deadline": None, "waited_s": 0.0, "expired": False})
        return d, s

    check("the cap is 24 hours", ar.OPERATOR_WAIT_CAP_S, 24 * 3600)

    # ---- a wait pauses the working clock and gives back exactly what was left ----
    d, s = fresh("pause")
    seen = {}
    async with asyncio.timeout(100) as deadline:
        ar.bind_run_deadline(deadline)
        loop = asyncio.get_running_loop()
        before = deadline.when() - loop.time()

        calls = {"n": 0}

        async def sleep_then_reply(_):
            calls["n"] += 1
            if calls["n"] == 1:
                seen["during"] = deadline.when() - loop.time()   # the clock, mid-wait
            if calls["n"] == 2:
                (d / "inbox.jsonl").write_text(json.dumps(
                    {"id": 1, "ts": time.time(), "author": "alice", "via": "cli",
                     "kind": "message", "body": "it is 10.0.0.9"}) + "\n")

        with patch("agent_runtime.asyncio.sleep", sleep_then_reply):
            got = await ar.pump_channels(agent_dir=d, state=s, profile=_FakeProfile(d),
                                         result=None, turn=1, used={"turns": 0, "cost": 0.0})
        after = deadline.when() - loop.time()
    check("the reply is delivered", got is not None and "10.0.0.9" in got, True)
    check("mid-wait the working deadline sat ~24 h out, so the hour cannot fire while a human is away",
          seen["during"] > ar.OPERATOR_WAIT_CAP_S, True)
    check("after the reply the working clock has what it had before (within a second)",
          abs(after - before) < 1.0, True)
    check("...and the wait did not expire", ar.operator_wait_expired(), False)

    # ---- the wait that nobody answers ends the run, and says so ----
    d2, s2 = fresh("expire")
    old_cap = ar.OPERATOR_WAIT_CAP_S
    ar.OPERATOR_WAIT_CAP_S = 0.05
    try:
        async def short_sleep(_):
            await _real_sleep(0.03)
        async with asyncio.timeout(100) as deadline2:
            ar.bind_run_deadline(deadline2)
            with patch("agent_runtime.asyncio.sleep", short_sleep):
                got2 = await ar.pump_channels(agent_dir=d2, state=s2, profile=_FakeProfile(d2),
                                              result=None, turn=1, used={"turns": 0, "cost": 0.0})
            left = deadline2.when() - asyncio.get_running_loop().time()
        check("an unanswered wait ends the run (returns None)", got2, None)
        check("...and flags it as the operator's silence, not a crash", ar.operator_wait_expired(), True)
        check("...the waited time is counted", ar.operator_wait_used() >= 0.05, True)
        check("...the working clock was handed back, not left 24 h out", left < 101, True)
        note = ar.operator_wait_note(s2)
        check("the note names the question that went unanswered",
              "nobody answered" in note and "what is LHOST" in note, True)

        # the total is per run: a second question gets only what is left
        s2.set_awaiting_operator("another question")
        with patch("agent_runtime.asyncio.sleep", short_sleep):
            got3 = await ar.pump_channels(agent_dir=d2, state=s2, profile=_FakeProfile(d2),
                                          result=None, turn=2, used={"turns": 0, "cost": 0.0})
        check("a wait after the allowance is spent ends at once (and a clock that already "
              "finished does not crash it)", got3, None)
    finally:
        ar.OPERATOR_WAIT_CAP_S = old_cap

    # ---- a runner that never bound a clock still works (old behaviour, no crash) ----
    d4, s4 = fresh("unbound")
    n = {"n": 0}

    async def reply_second_poll(_):
        n["n"] += 1
        if n["n"] == 2:
            (d4 / "inbox.jsonl").write_text(json.dumps(
                {"id": 1, "ts": time.time(), "author": "alice", "via": "cli",
                 "kind": "message", "body": "ok"}) + "\n")
    with patch("agent_runtime.asyncio.sleep", reply_second_poll):
        got4 = await ar.pump_channels(agent_dir=d4, state=s4, profile=_FakeProfile(d4),
                                      result=None, turn=1, used={"turns": 0, "cost": 0.0})
    check("with no bound clock the wait still ends on the reply", got4 is not None, True)

    # ---- the report says how long the human kept the agent waiting ----
    ar._RUN_CLOCK.update({"deadline": None, "waited_s": 3525.0, "expired": False})
    prof = types.SimpleNamespace(model="m", max_turns=10, max_budget_usd=1.0)
    head = ar.report_header(title="T", engagement=None, status="completed", agent_name="enum",
                            profile=prof, scope_label="scanned", scope_desc="x",
                            started=time.time() - 4000, result=None)
    check("the report header shows the time waited for the operator",
          any(ln.startswith("**Waited for the operator:** 58m 45s") for ln in head), True)
    ar._RUN_CLOCK.update({"deadline": None, "waited_s": 0.0, "expired": False})
    head0 = ar.report_header(title="T", engagement=None, status="completed", agent_name="enum",
                             profile=prof, scope_label="scanned", scope_desc="x",
                             started=time.time() - 60, result=None)
    check("...and nothing about it when there was no wait",
          any("Waited for the operator" in ln for ln in head0), False)

asyncio.run(_wait_clock_tests())

print(f"\n{'=' * 52}\n  {PASS} passed, {FAIL} failed\n{'=' * 52}")
sys.exit(1 if FAIL else 0)
