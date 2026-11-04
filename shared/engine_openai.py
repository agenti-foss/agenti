"""
engine_openai.py — Agenti's own run loop for any model behind the
OpenAI-compatible Chat Completions API: OpenAI's models, and self-hosted ones
(Ollama, vLLM, LM Studio, llama.cpp server, LiteLLM). docs/model-providers.md.

The model is offered ONLY the agent's own tools (agent_tools.ToolDef, the same
ones the Claude engine offers). Before any of them runs, the call goes through
the contract's allow-list guard — the very hook the Claude SDK calls — and
after it, the operator/team delivery hook, so a run hears its operator the same
way on every provider. There is no shell, no file access, no tool of the
engine's own: what the model can do is exactly the tool list.

Caps, per query() as the Claude SDK applies them (session_runner and
pump_channels add them up across the run): turns = model calls; budget = tokens
x the organisation's stated price (a cloud model with no price is refused,
model_registry.price_for); the wall clock is session_runner's.

The model is reached through agenti-relay (AGENTI_RELAY, an HTTP CONNECT
tunnel) when the run has one — the run's kernel fence allows nothing else —
and only this connection uses it, never the tools' own processes. The
conversation is kept in the run's state/ so a stopped run can be resumed.

Standard library only.
"""
from __future__ import annotations

import asyncio
import http.client
import json
import os
import secrets
import time
from pathlib import Path
from urllib.parse import urlsplit

import agent_tools
import model_registry
from model_session import (AssistantMessage, EngineError, ResultMessage, SessionSpec,
                           SystemMessage, TextBlock, ToolResultBlock, ToolUseBlock,
                           UserMessage)

TIMEOUT_S = 600              # one model call; the run's wall clock bounds the whole
MAX_REPLY_BYTES = 8_000_000
CONVERSATION = "conversation.json"


def _post_json(url: str, body: dict, headers: dict, relay: str, timeout: float) -> dict:
    """POST JSON, through the relay's CONNECT tunnel when there is one (http
    and https alike: the relay only tunnels, it never reads the traffic)."""
    u = urlsplit(url)
    https = u.scheme == "https"
    host, port = u.hostname or "", u.port or (443 if https else 80)
    if relay:
        r = urlsplit(relay if "://" in relay else f"http://{relay}")
        cls = http.client.HTTPSConnection if https else http.client.HTTPConnection
        conn = cls(r.hostname, r.port or 80, timeout=timeout)
        conn.set_tunnel(host, port)
    else:
        cls = http.client.HTTPSConnection if https else http.client.HTTPConnection
        conn = cls(host, port, timeout=timeout)
    path = (u.path or "/") + (f"?{u.query}" if u.query else "")
    try:
        conn.request("POST", path, body=json.dumps(body).encode(),
                     headers={"Content-Type": "application/json", "User-Agent": "agenti", **headers})
        resp = conn.getresponse()
        raw = resp.read(MAX_REPLY_BYTES + 1)
    finally:
        conn.close()
    if len(raw) > MAX_REPLY_BYTES:
        raise EngineError("the model's reply was unexpectedly large; refused")
    try:
        data = json.loads(raw or b"{}")
    except ValueError:
        data = {}
    if resp.status >= 400:
        msg = ((data.get("error") or {}).get("message") if isinstance(data.get("error"), dict)
               else data.get("error")) or raw[:300].decode("utf-8", "replace")
        if resp.status in (401, 403):
            raise EngineError(f"the provider refused the API key (HTTP {resp.status}): {msg}")
        raise EngineError(f"the provider answered HTTP {resp.status}: {msg}")
    return data


class OpenAISession:
    def __init__(self, spec: SessionSpec, provider: model_registry.Provider, *, post=_post_json):
        self.spec = spec
        self.provider = provider
        self._post = post
        env = {**os.environ, **(spec.env or {})}
        self.base_url = (provider.base_url or env.get(provider.base_url_env, "")).rstrip("/")
        if not self.base_url:
            raise EngineError(f"{provider.label}: no address is set ({provider.base_url_env}). Set it: "
                              f"sudo /usr/lib/agenti/set-secret.sh --provider {provider.name} "
                              f"--base-url http://<host>:<port>/v1")
        self.api_key = env.get(provider.key_env, "")
        if provider.key_required and not self.api_key:
            raise EngineError(f"no {provider.label} API key reached this run ({provider.key_env}). "
                              f"Set it: sudo /usr/lib/agenti/set-secret.sh --provider {provider.name}")
        self.relay = env.get("AGENTI_RELAY", "")
        self.model = model_registry.split(spec.model)[1]
        self.price = model_registry.price_for(spec.model, spec.model_prices)
        if self.price is None:
            raise EngineError(
                f"REFUSING: no price is set for {spec.model}, so this run's budget cap could not be "
                f"enforced. An admin states it, in US dollars per million input and output tokens: "
                f"sudo agenti engagement set --model-price {spec.model}=<input>,<output>")
        self.contract = spec.contract
        self.tools = {t.name: t for t in spec.contract.tools}
        self.tool_specs = [{"type": "function", "function": {
            "name": t.name, "description": t.description, "parameters": agent_tools.json_schema(t)}}
            for t in spec.contract.tools]
        self.messages: list[dict] = [{"role": "system", "content": spec.system_prompt}]
        self.session_id = ""
        self._queued: list[str] = []
        self._interrupted = False
        self._announced = False

    # -- the conversation on disk (resume) ---------------------------------
    def _path(self) -> Path:
        return Path(self.spec.state_dir) / CONVERSATION

    def _save(self) -> None:
        p = self._path()
        tmp = p.with_name(p.name + ".tmp")
        tmp.write_text(json.dumps({"session_id": self.session_id, "model": self.spec.model,
                                   "messages": self.messages[1:]}))
        os.chmod(tmp, 0o600)
        tmp.replace(p)

    async def __aenter__(self):
        if self.spec.resume:
            try:
                saved = json.loads(self._path().read_text())
            except (OSError, ValueError):
                saved = {}
            if saved.get("session_id") == self.spec.resume and isinstance(saved.get("messages"), list):
                self.session_id = self.spec.resume
                self.messages += saved["messages"]
        if not self.session_id:
            self.session_id = secrets.token_hex(16)
        return self

    async def __aexit__(self, *exc):
        return False

    # -- the four calls ----------------------------------------------------
    async def query(self, text: str) -> None:
        self._queued.append(text)

    async def interrupt(self) -> None:
        self._interrupted = True

    async def set_model(self, model: str) -> None:
        provider, bare = model_registry.split(model)
        if provider != self.provider.name:
            raise EngineError(f"this run uses {self.provider.label}; '{model}' is another provider's "
                              f"model. A run keeps its provider: start a new run to use it.")
        price = model_registry.price_for(model, self.spec.model_prices)
        if price is None:
            raise EngineError(f"no price is set for {model}: sudo agenti engagement set "
                              f"--model-price {model}=<input>,<output>")
        self.model, self.price = bare, price

    async def receive_response(self):
        started = time.monotonic()
        api_ms = 0
        turns, cost = 0, 0.0
        usage = {"input_tokens": 0, "output_tokens": 0}
        if not self._announced:
            self._announced = True
            yield SystemMessage("init", {"session_id": self.session_id, "model": self.spec.model,
                                         "provider": self.provider.name})
        for text in self._queued:
            self.messages.append({"role": "user", "content": text})
        self._queued.clear()
        self._save()

        def result(subtype, *, text=None, error=False, stop=None):
            return ResultMessage(subtype=subtype, is_error=error, num_turns=turns,
                                 session_id=self.session_id, total_cost_usd=round(cost, 6),
                                 result=text, stop_reason=stop, usage=dict(usage),
                                 duration_ms=int((time.monotonic() - started) * 1000),
                                 duration_api_ms=api_ms)

        last_text = ""
        while True:
            if self._interrupted:
                yield result("error_during_execution", text="interrupted by the operator", error=True)
                return
            if turns >= self.spec.max_turns:
                yield result("error_max_turns", text=last_text or None, error=True)
                return
            if cost >= self.spec.max_budget_usd:
                yield result("error_max_budget_usd", text=last_text or None, error=True)
                return
            body = {"model": self.model, "messages": self.messages}
            if self.tool_specs:
                body["tools"] = self.tool_specs
            headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
            t0 = time.monotonic()
            reply = await asyncio.to_thread(self._post, f"{self.base_url}/chat/completions",
                                            body, headers, self.relay, TIMEOUT_S)
            api_ms += int((time.monotonic() - t0) * 1000)
            turns += 1
            u = reply.get("usage") or {}
            pin, pout = int(u.get("prompt_tokens") or 0), int(u.get("completion_tokens") or 0)
            usage["input_tokens"] += pin
            usage["output_tokens"] += pout
            cost += model_registry.cost_usd(self.price, pin, pout)
            choice = (reply.get("choices") or [{}])[0]
            msg = choice.get("message") or {}
            text = msg.get("content") or ""
            calls = msg.get("tool_calls") or []
            blocks: list = [TextBlock(text)] if text else []
            for c in calls:
                fn = c.get("function") or {}
                try:
                    args = json.loads(fn.get("arguments") or "{}")
                except ValueError:
                    args = {"_unparsed": fn.get("arguments")}
                blocks.append(ToolUseBlock(id=str(c.get("id") or secrets.token_hex(6)),
                                           name=self._qualified(fn.get("name", "")), input=args))
            yield AssistantMessage(content=blocks, model=self.spec.model)
            kept = {"role": "assistant", "content": text or None}
            if calls:
                kept["tool_calls"] = calls
            self.messages.append(kept)
            if text:
                last_text = text
            if not calls:
                self._save()
                yield result("success", text=text, stop=choice.get("finish_reason") or "stop")
                return

            context = []
            for c, block in zip(calls, [b for b in blocks if isinstance(b, ToolUseBlock)]):
                out, is_error = await self._run_tool(block)
                self.messages.append({"role": "tool", "tool_call_id": str(c.get("id") or block.id),
                                      "content": out})
                yield UserMessage(content=[ToolResultBlock(tool_use_id=block.id,
                                                           content=[{"type": "text", "text": out}],
                                                           is_error=is_error)])
                extra = await self._after_tool(block)
                if extra:
                    context.append(extra)
            if context:
                self.messages.append({"role": "user", "content": "\n\n".join(context)})
            self._save()

    # -- tools ---------------------------------------------------------------
    def _qualified(self, name: str) -> str:
        """The name the guard and the ledger use (the Claude SDK's MCP form), so a
        rule or a record never depends on which engine ran."""
        return f"mcp__{self.contract.mcp_server_name}__{name}"

    async def _run_tool(self, block: ToolUseBlock) -> tuple[str, bool]:
        verdict = await self.spec.pre_tool_hook(
            {"tool_name": block.name, "tool_input": block.input}, block.id, None)
        out = (verdict or {}).get("hookSpecificOutput") or {}
        if out.get("permissionDecision") == "deny":
            return out.get("permissionDecisionReason") or "This tool call was refused.", True
        bare = block.name.rsplit("__", 1)[-1]
        td = self.tools.get(bare)
        if td is None:
            return f"There is no tool named '{bare}'.", True
        if "_unparsed" in block.input:
            return "The arguments were not valid JSON; send them again as a JSON object.", True
        try:
            return agent_tools.result_text(await td.handler(block.input))
        except Exception as e:  # noqa: BLE001 - a tool's failure is the model's to read, not a crash
            return f"The tool failed: {type(e).__name__}: {e}", True

    async def _after_tool(self, block: ToolUseBlock) -> str:
        try:
            r = await self.spec.post_tool_hook(
                {"tool_name": block.name, "tool_input": block.input}, block.id, None)
        except Exception as e:  # noqa: BLE001 - delivery must never break a run
            print(f"[warn] inbox check failed: {e}")
            return ""
        return ((r or {}).get("hookSpecificOutput") or {}).get("additionalContext") or ""


def open_session(spec: SessionSpec, provider: model_registry.Provider) -> OpenAISession:
    return OpenAISession(spec, provider)
