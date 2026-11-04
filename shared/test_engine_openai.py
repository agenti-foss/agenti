#!/usr/bin/env python3
"""test_engine_openai.py — the OpenAI-compatible engine, against a scripted
model (no network, no key): the tool loop, the allow-list guard, operator
delivery, caps, prices, resume, interrupt, and a real HTTP round trip through
the actual egress relay (agenti-relay's CONNECT tunnel). Also agent_tools and
model_registry, which the engine stands on."""
import asyncio
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import agent_tools  # noqa: E402
import engine_openai  # noqa: E402
import model_registry as mr  # noqa: E402
from model_session import EngineError, SessionSpec  # noqa: E402

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


# ---------------------------------------------------------------------------
section("agent_tools: one tool definition, every engine")


@agent_tools.tool("run_scan", "Run one scan.", {"command": str})
async def run_scan(args):
    RAN.append(args)
    return {"content": [{"type": "text", "text": f"scanned: {args['command']}"}]}


@agent_tools.tool("note", "Write a note.", {"type": "object", "properties": {"text": {"type": "string"}},
                                          "required": []})
async def note(args):
    return {"content": [{"type": "text", "text": "noted"}], "is_error": False}

RAN: list = []
check("the decorator keeps name, description and handler", (run_scan.name, run_scan.description), ("run_scan", "Run one scan."))
check("{param: type} becomes an object schema, every parameter required",
      agent_tools.json_schema(run_scan),
      {"type": "object", "properties": {"command": {"type": "string"}}, "required": ["command"]})
check("a full JSON schema is kept as it is", agent_tools.json_schema(note)["required"], [])
check("result_text joins the text parts", agent_tools.result_text({"content": [{"type": "text", "text": "a"}, {"type": "text", "text": "b"}]}), ("a\nb", False))
check("...and reads the error flag", agent_tools.result_text({"content": [], "is_error": True}), ("", True))

# ---------------------------------------------------------------------------
section("model_registry: names, providers, policy entries, prices")
for name, want in (("sonnet", ("anthropic", "claude-sonnet-5")),
                   ("claude-sonnet-5-5", ("anthropic", "claude-sonnet-5-5")),
                   ("anthropic:claude-fable-5-1", ("anthropic", "claude-fable-5-1")),
                   ("openai:gpt-5.1", ("openai", "gpt-5.1")),
                   ("local:qwen3:32b", ("local", "qwen3:32b")),
                   ("local:meta-llama/Llama-3.3-70B-Instruct", ("local", "meta-llama/Llama-3.3-70B-Instruct"))):
    check(f"split({name})", mr.split(name), want)
for bad in ("", "gpt-5", "openai:", "openai:-x", "nope:model", "openai:has space", "openai:" + "x" * 200):
    try:
        mr.split(bad)
        check(f"'{bad[:30]}' is refused", False, True)
    except mr.ModelNameError:
        check(f"'{bad[:30]}' is refused", True, True)
check("a Claude model's canonical form stays the bare id", mr.canonical("anthropic:sonnet"), "claude-sonnet-5")
check("any other provider's keeps its prefix", mr.canonical("openai:gpt-5.1"), "openai:gpt-5.1")
check("provider:* is a valid policy entry", mr.valid_policy_entry("openai:*"), True)
check("an unknown provider's * is not", mr.valid_policy_entry("nope:*"), False)
check("openai:* allows any OpenAI model", mr.allowed("openai:gpt-9", ["openai:*"]), True)
check("...and no Claude model", mr.allowed("sonnet", ["openai:*"]), False)
check("an alias in the list allows its model by id", mr.allowed("claude-sonnet-5", ["sonnet"]), True)
check("an exact entry allows only itself", mr.allowed("openai:gpt-5.1-mini", ["openai:gpt-5.1"]), False)
check("a self-hosted model is free", mr.price_for("local:llama3", {}), (0.0, 0.0))
check("a cloud model with no stated price has none", mr.price_for("openai:gpt-5.1", {}), None)
check("a stated price is found by any spelling", mr.price_for("openai:gpt-5.1", {"openai:gpt-5.1": [1.25, 10]}), (1.25, 10.0))
check("cost is tokens x price per million", round(mr.cost_usd((2.0, 8.0), 1_000_000, 500_000), 6), 6.0)


def fake_opener(payload, status=200):
    class R:
        def __init__(self):
            self.status = status
        def read(self, n=-1):
            return json.dumps(payload).encode()
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False
    return lambda req, timeout=0: R()


check("list_models names a provider's models the Agenti way",
      mr.list_models("openai", api_key="k", opener=fake_opener({"data": [{"id": "gpt-5.1"}, {"id": "gpt-5.1-mini"}]})),
      ["openai:gpt-5.1", "openai:gpt-5.1-mini"])
check("...Claude's as bare ids", mr.list_models("anthropic", api_key="k", opener=fake_opener({"data": [{"id": "claude-sonnet-5-5"}]})),
      ["claude-sonnet-5-5"])

# ---------------------------------------------------------------------------
# A scripted model: each reply in turn, every request recorded.
class Script:
    def __init__(self, replies):
        self.replies = list(replies)
        self.requests = []

    def __call__(self, url, body, headers, relay, timeout):
        self.requests.append({"url": url, "body": json.loads(json.dumps(body)), "headers": headers, "relay": relay})
        return self.replies.pop(0)


def say(text, pin=100, pout=50):
    return {"choices": [{"message": {"role": "assistant", "content": text}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": pin, "completion_tokens": pout}}


def call(*calls, text="", pin=100, pout=50):
    return {"choices": [{"message": {"role": "assistant", "content": text or None, "tool_calls": [
        {"id": f"c{i}", "type": "function", "function": {"name": n, "arguments": a}}
        for i, (n, a) in enumerate(calls)]}, "finish_reason": "tool_calls"}],
        "usage": {"prompt_tokens": pin, "completion_tokens": pout}}


DENIED = []
DELIVER: list = []


async def guard(input_data, tool_use_id, context):
    if input_data["tool_name"] == "mcp__recon__note":
        DENIED.append(input_data["tool_name"])
        return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                       "permissionDecisionReason": "Tool 'note' is disabled."}}
    return {}


async def inbox(input_data, tool_use_id, context):
    if DELIVER:
        return {"hookSpecificOutput": {"hookEventName": "PostToolUse", "additionalContext": DELIVER.pop(0)}}
    return {}


CONTRACT = SimpleNamespace(tools=[run_scan, note], mcp_server_name="recon")
TMP = Path(tempfile.mkdtemp())


def spec(**kw):
    base = dict(model="openai:gpt-5.1", system_prompt="You are a recon agent.", contract=CONTRACT,
                pre_tool_hook=guard, post_tool_hook=inbox, max_turns=10, max_budget_usd=1.0,
                state_dir=TMP, env={"OPENAI_API_KEY": "sk-test"},
                model_prices={"openai:gpt-5.1": [1.0, 2.0]})
    base.update(kw)
    return SessionSpec(**base)


def provider(name="openai"):
    """The loop tests speak the chat wire (any provider may); the Responses wire,
    OpenAI's own, has its own section below."""
    import dataclasses
    return dataclasses.replace(mr.PROVIDERS[name], wire="chat")


async def run(sess, text="go"):
    events = []
    async with sess:
        await sess.query(text)
        async for e in sess.receive_response():
            events.append(e)
    return events


def kinds(events):
    return [type(e).__name__ for e in events]


# ---------------------------------------------------------------------------
section("the tool loop: call, result, answer")
RAN.clear()
s = Script([call(("run_scan", '{"command": "nmap -sV 10.0.0.1"}'), text="Scanning."), say("Done: 1 host.")])
sess = engine_openai.OpenAISession(spec(), provider(), post=s)
ev = asyncio.run(run(sess))
check("events in the Claude SDK's shapes, in order", kinds(ev),
      ["SystemMessage", "AssistantMessage", "UserMessage", "AssistantMessage", "ResultMessage"])
check("the init event carries the session id", bool(ev[0].data.get("session_id")), True)
check("the tool ran with the model's arguments", RAN, [{"command": "nmap -sV 10.0.0.1"}])
use = [b for b in ev[1].content if type(b).__name__ == "ToolUseBlock"][0]
check("the tool call is recorded under the guard's name", use.name, "mcp__recon__run_scan")
check("the tool's output went back to the model",
      s.requests[1]["body"]["messages"][-1], {"role": "tool", "tool_call_id": "c0", "content": "scanned: nmap -sV 10.0.0.1"})
check("the model was offered exactly the agent's tools",
      [t["function"]["name"] for t in s.requests[0]["body"]["tools"]], ["run_scan", "note"])
check("the system prompt leads the conversation", s.requests[0]["body"]["messages"][0],
      {"role": "system", "content": "You are a recon agent."})
check("the model id is sent without its provider prefix", s.requests[0]["body"]["model"], "gpt-5.1")
check("the key goes in the Authorization header", s.requests[0]["headers"], {"Authorization": "Bearer sk-test"})
r = ev[-1]
check("the result: success, its text, two turns", (r.subtype, r.is_error, r.result, r.num_turns), ("success", False, "Done: 1 host.", 2))
check("cost = tokens x the stated price", r.total_cost_usd, round(2 * (100 * 1.0 + 50 * 2.0) / 1e6, 6))

section("the guard: a refused tool never runs, and the model is told why")
RAN.clear()
DENIED.clear()
s = Script([call(("note", '{"text": "x"}')), say("ok")])
ev = asyncio.run(run(engine_openai.OpenAISession(spec(), provider(), post=s)))
check("the guard saw the call", DENIED, ["mcp__recon__note"])
res = [b for e in ev if type(e).__name__ == "UserMessage" for b in e.content][0]
check("the refusal is the tool's (error) result", (res.is_error, res.content[0]["text"]), (True, "Tool 'note' is disabled."))
check("...and is what the model reads", s.requests[1]["body"]["messages"][-1]["content"], "Tool 'note' is disabled.")
s = Script([call(("bash", '{"cmd": "id"}')), say("ok")])
ev = asyncio.run(run(engine_openai.OpenAISession(spec(), provider(), post=s)))
res = [b for e in ev if type(e).__name__ == "UserMessage" for b in e.content][0]
check("a tool the agent does not have is an error, nothing runs", (res.is_error, "no tool named 'bash'" in res.content[0]["text"]), (True, True))
s = Script([call(("run_scan", "{not json")), say("ok")])
RAN.clear()
ev = asyncio.run(run(engine_openai.OpenAISession(spec(), provider(), post=s)))
check("arguments that are not JSON: the tool does not run", RAN, [])

section("the operator: a message sent mid-run reaches the model after the tool")
DELIVER[:] = ["[Operator message] focus on port 22"]
s = Script([call(("run_scan", '{"command": "nmap 10.0.0.1"}')), say("ok")])
asyncio.run(run(engine_openai.OpenAISession(spec(), provider(), post=s)))
msgs = s.requests[1]["body"]["messages"]
check("after the tool result, as the next user turn", (msgs[-2]["role"], msgs[-1]),
      ("tool", {"role": "user", "content": "[Operator message] focus on port 22"}))

section("caps: turns and budget end the query as the Claude SDK does")
s = Script([call(("run_scan", '{"command": "a"}'))] * 5)
ev = asyncio.run(run(engine_openai.OpenAISession(spec(max_turns=2), provider(), post=s)))
check("max_turns: error_max_turns after 2 model calls", (ev[-1].subtype, ev[-1].num_turns, len(s.requests)), ("error_max_turns", 2, 2))
s = Script([call(("run_scan", '{"command": "a"}'), pin=600_000, pout=0)] * 5)
ev = asyncio.run(run(engine_openai.OpenAISession(spec(max_budget_usd=1.0), provider(), post=s)))
check("budget: error_max_budget_usd once spend reaches the cap", (ev[-1].subtype, len(s.requests)), ("error_max_budget_usd", 2))
try:
    engine_openai.OpenAISession(spec(model_prices={}), provider(), post=Script([]))
    check("a cloud model with no price is refused", False, True)
except EngineError as e:
    check("a cloud model with no price is refused, naming the fix", "--model-price openai:gpt-5.1" in str(e), True)
try:
    engine_openai.OpenAISession(spec(env={}), provider(), post=Script([]))
    check("no API key is refused", False, True)
except EngineError as e:
    check("no API key is refused, naming the key", "OPENAI_API_KEY" in str(e), True)
loc = spec(model="local:qwen3:32b", env={"LOCAL_LLM_BASE_URL": "http://10.9.9.9:11434/v1"}, model_prices={})
s = Script([say("hi")])
ev = asyncio.run(run(engine_openai.OpenAISession(loc, provider("local"), post=s)))
check("a self-hosted model needs no key and no price", (ev[-1].subtype, s.requests[0]["url"], s.requests[0]["headers"]),
      ("success", "http://10.9.9.9:11434/v1/chat/completions", {}))
try:
    engine_openai.OpenAISession(spec(model="local:x", env={}, model_prices={}), provider("local"), post=Script([]))
    check("self-hosted with no address is refused", False, True)
except EngineError as e:
    check("self-hosted with no address is refused, naming the setting", "LOCAL_LLM_BASE_URL" in str(e), True)

section("interrupt, model switch, resume")


async def interrupted():
    sess = engine_openai.OpenAISession(spec(), provider(), post=Script([call(("run_scan", '{"command": "a"}')), say("x")]))
    out = []
    async with sess:
        await sess.query("go")
        async for e in sess.receive_response():
            out.append(e)
            if type(e).__name__ == "AssistantMessage":
                await sess.interrupt()
    return out
ev = asyncio.run(interrupted())
check("an interrupt ends the query at the next step", (ev[-1].subtype, ev[-1].is_error), ("error_during_execution", True))


async def switch():
    sess = engine_openai.OpenAISession(spec(model_prices={"openai:gpt-5.1": [1, 2], "openai:gpt-5.1-mini": [0.2, 0.8]}),
                                       provider(), post=Script([]))
    await sess.set_model("openai:gpt-5.1-mini")
    try:
        await sess.set_model("sonnet")
        other = "allowed"
    except EngineError:
        other = "refused"
    return sess.model, other
check("set_model: same provider switches, another provider is refused", asyncio.run(switch()), ("gpt-5.1-mini", "refused"))

st = Path(tempfile.mkdtemp())
first = engine_openai.OpenAISession(spec(state_dir=st), provider(), post=Script([say("found 2 hosts")]))
ev = asyncio.run(run(first, "scan it"))
sid = ev[0].data["session_id"]
saved = json.loads((st / "conversation.json").read_text())
check("the conversation is kept in the run's state, private to the run", (saved["session_id"], oct((st / "conversation.json").stat().st_mode & 0o777)), (sid, "0o600"))
s = Script([say("continuing")])
again = engine_openai.OpenAISession(spec(state_dir=st, resume=sid), provider(), post=s)
asyncio.run(run(again, "resume"))
check("a resume continues the same conversation",
      [m["content"] for m in s.requests[0]["body"]["messages"][1:]], ["scan it", "found 2 hosts", "resume"])
s = Script([say("fresh")])
asyncio.run(run(engine_openai.OpenAISession(spec(state_dir=st, resume="another-id"), provider(), post=s)))
check("a resume id that is not this conversation starts afresh", len(s.requests[0]["body"]["messages"]), 2)


async def two_queries():
    sess = engine_openai.OpenAISession(spec(), provider(), post=Script([say("a"), say("b")]))
    out = []
    async with sess:
        for t in ("one", "two"):
            await sess.query(t)
            async for e in sess.receive_response():
                if type(e).__name__ == "ResultMessage":
                    out.append((e.total_cost_usd, e.session_cost_usd))
    return out
q = asyncio.run(two_queries())
one = round((100 * 1.0 + 50 * 2.0) / 1e6, 6)
check("each result: this query's cost, and the session's so far", q, [(one, one), (one, round(2 * one, 6))])

# ---------------------------------------------------------------------------
section("OpenAI's own wire: the Responses API (tools on reasoning models)")
check("OpenAI speaks Responses, a self-hosted server Chat Completions",
      (mr.PROVIDERS["openai"].wire, mr.PROVIDERS["local"].wire), ("responses", "chat"))


def r_call(name, args, *, cid="call_1", pin=100, pout=50):
    return {"status": "completed", "usage": {"input_tokens": pin, "output_tokens": pout}, "output": [
        {"type": "reasoning", "id": "rs_1", "encrypted_content": "ENC", "summary": []},
        {"type": "function_call", "id": "fc_1", "call_id": cid, "name": name, "arguments": args}]}


def r_say(text, pin=100, pout=50):
    return {"status": "completed", "usage": {"input_tokens": pin, "output_tokens": pout}, "output": [
        {"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": text}]}]}


RAN.clear()
s = Script([r_call("run_scan", '{"command": "nmap 10.0.0.1"}'), r_say("Found 1 host.")])
ev = asyncio.run(run(engine_openai.OpenAISession(spec(), mr.PROVIDERS["openai"], post=s)))
b0 = s.requests[0]["body"]
check("it posts to /responses with the system prompt as instructions",
      (s.requests[0]["url"], b0["instructions"], b0["input"]),
      ("https://api.openai.com/v1/responses", "You are a recon agent.", [{"role": "user", "content": "go"}]))
check("nothing is stored at OpenAI; reasoning comes back encrypted", (b0["store"], b0["include"]),
      (False, ["reasoning.encrypted_content"]))
check("tools in the Responses shape", b0["tools"][0],
      {"type": "function", "name": "run_scan", "description": "Run one scan.",
       "parameters": {"type": "object", "properties": {"command": {"type": "string"}}, "required": ["command"]}})
check("the tool ran", RAN, [{"command": "nmap 10.0.0.1"}])
nxt = s.requests[1]["body"]["input"]
check("the next request returns the reasoning, the call and its output",
      [i.get("type", i.get("role")) for i in nxt], ["user", "reasoning", "function_call", "function_call_output"])
check("...the output keyed by the call's id", (nxt[-1]["call_id"], nxt[-1]["output"]), ("call_1", "scanned: nmap 10.0.0.1"))
check("the answer and its cost", (ev[-1].subtype, ev[-1].result, ev[-1].total_cost_usd),
      ("success", "Found 1 host.", round(2 * (100 * 1.0 + 50 * 2.0) / 1e6, 6)))
DELIVER[:] = ["[Operator message] stop after this"]
s = Script([r_call("run_scan", '{"command": "a"}'), r_say("ok")])
asyncio.run(run(engine_openai.OpenAISession(spec(), mr.PROVIDERS["openai"], post=s)))
check("an operator message follows the tool output as a user turn", s.requests[1]["body"]["input"][-1],
      {"role": "user", "content": "[Operator message] stop after this"})
st2 = Path(tempfile.mkdtemp())
ev = asyncio.run(run(engine_openai.OpenAISession(spec(state_dir=st2), mr.PROVIDERS["openai"], post=Script([r_say("hi")]))))
s = Script([r_say("again")])
asyncio.run(run(engine_openai.OpenAISession(spec(state_dir=st2, resume=ev[0].data["session_id"]), mr.PROVIDERS["openai"], post=s)))
check("a resume on the Responses wire continues the conversation", len(s.requests[0]["body"]["input"]), 3)
s = Script([r_say("chat")])
asyncio.run(run(engine_openai.OpenAISession(spec(state_dir=st2, resume=ev[0].data["session_id"]), provider(), post=s)))
check("...but a conversation from another wire is not mixed in", len(s.requests[0]["body"]["messages"]), 2)

# ---------------------------------------------------------------------------
section("the wire: a real request through the actual egress relay")


class FakeAPI(BaseHTTPRequestHandler):
    seen = []

    def log_message(self, *a):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        FakeAPI.seen.append((self.path, self.headers.get("Authorization"), body["model"]))
        out = json.dumps(say("over the wire")).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)


api = ThreadingHTTPServer(("127.0.0.1", 0), FakeAPI)
threading.Thread(target=api.serve_forever, daemon=True).start()
api_port = api.server_address[1]
sock = socket.socket()
sock.bind(("127.0.0.1", 0))
relay_port = sock.getsockname()[1]
sock.close()
relay = subprocess.Popen([sys.executable, str(HERE / "egress_relay.py"), "--listen", f"127.0.0.1:{relay_port}",
                          "--allow", f"127.0.0.1:{api_port}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
try:
    for _ in range(50):
        try:
            socket.create_connection(("127.0.0.1", relay_port), timeout=0.2).close()
            break
        except OSError:
            time.sleep(0.1)
    wire = spec(model="local:tiny", env={"LOCAL_LLM_BASE_URL": f"http://127.0.0.1:{api_port}/v1",
                                         "LOCAL_LLM_API_KEY": "lk", "AGENTI_RELAY": f"http://127.0.0.1:{relay_port}"},
                model_prices={})
    ev = asyncio.run(run(engine_openai.OpenAISession(wire, provider("local"))))
    check("plain HTTP to a self-hosted model, tunnelled by the relay", (ev[-1].result, FakeAPI.seen[-1]),
          ("over the wire", ("/v1/chat/completions", "Bearer lk", "tiny")))
    blocked = spec(model="local:tiny", env={"LOCAL_LLM_BASE_URL": "http://127.0.0.1:9/v1",
                                            "AGENTI_RELAY": f"http://127.0.0.1:{relay_port}"}, model_prices={})
    try:
        asyncio.run(run(engine_openai.OpenAISession(blocked, provider("local"))))
        check("an address the relay does not allow is unreachable", False, True)
    except OSError as e:
        check("an address the relay does not allow is unreachable (the relay refuses the tunnel)", "403" in str(e), True)
finally:
    relay.terminate()
    api.shutdown()

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
