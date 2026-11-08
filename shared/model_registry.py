"""
model_registry.py — which AI providers Agenti can talk to, and what a model
name means (docs/model-providers.md).

A model is named `<provider>:<model>`: `openai:gpt-5.1`, `local:qwen3:32b`,
`anthropic:claude-sonnet-5-5`. Claude models keep their old spellings too:
the aliases `haiku` / `sonnet` / `opus` and a bare `claude-…` id are Claude's,
and a Claude model's canonical form stays the bare id the Claude SDK expects
(so every existing run-config, report and allowed list means what it meant).

This module checks the FORM of a name and which provider it belongs to; it
never decides a name is "unknown" (any model a provider serves is fine — the
provider answers). What is allowed is the organization's policy
(engagement_context.model_allowed), which may list exact names or
`<provider>:*`.

Standard library only: system python3 (preflight, engagement_store) imports it.
"""
from __future__ import annotations

import json
import hashlib
import http.client
import re
import urllib.request
from urllib.parse import urlsplit
from dataclasses import dataclass


@dataclass(frozen=True)
class Provider:
    name: str              # the prefix in a model name
    label: str             # what a person sees
    engine: str            # "claude" (the Claude Agent SDK) or "openai" (Agenti's own loop)
    key_env: str           # the secret holding its API key (the usual tiers)
    key_required: bool
    base_url: str          # "" = read from base_url_env
    base_url_env: str = ""
    relay_host: str = ""   # host:port the egress relay must allow by default
    wire: str = "chat"     # engine_openai's format: "responses" (OpenAI) or "chat" (Chat Completions)


PROVIDERS: dict[str, Provider] = {
    "anthropic": Provider("anthropic", "Claude (Anthropic)", "claude", "ANTHROPIC_API_KEY", True,
                          "https://api.anthropic.com/v1", relay_host="api.anthropic.com:443"),
    # The Responses API: OpenAI's reasoning models take tools only there.
    "openai": Provider("openai", "ChatGPT (OpenAI)", "openai", "OPENAI_API_KEY", True,
                       "https://api.openai.com/v1", relay_host="api.openai.com:443", wire="responses"),
    # Anything speaking the OpenAI-compatible Chat Completions API: Ollama,
    # vLLM, LM Studio, llama.cpp server, LiteLLM. Its address is the
    # organization's (LOCAL_LLM_BASE_URL); root adds it to the relay.
    "local": Provider("local", "Self-hosted (OpenAI-compatible)", "openai", "LOCAL_LLM_API_KEY", False,
                      "", base_url_env="LOCAL_LLM_BASE_URL"),
}

# The old curated names, still accepted everywhere. Moved here from
# engagement_context.MODEL_ALIASES (which now points at this).
CLAUDE_ALIASES: dict[str, str] = {
    "haiku": "claude-haiku-4-5-20251001",
    "sonnet": "claude-sonnet-5",
    "opus": "claude-opus-5",
}

# A model id after its provider prefix: what providers actually use (Ollama's
# "qwen3:32b", "meta-llama/Llama-3.3-70B", "gpt-5.1-mini", dates, "@" tags).
_MODEL_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,127}$")


class ModelNameError(ValueError):
    """A model name that cannot be one: the message says what form is expected."""


def split(name: str) -> tuple[str, str]:
    """(provider, model id) of any accepted spelling. Raises ModelNameError."""
    name = str(name or "").strip()
    if not name:
        raise ModelNameError("no model given")
    if name in CLAUDE_ALIASES:
        return "anthropic", CLAUDE_ALIASES[name]
    prefix, sep, rest = name.partition(":")
    if sep and prefix in PROVIDERS:
        if not _MODEL_ID.match(rest):
            raise ModelNameError(f"'{rest}' is not a model name (letters, digits and . _ : / @ -, up to 128)")
        if prefix == "anthropic" and rest in CLAUDE_ALIASES:
            return "anthropic", CLAUDE_ALIASES[rest]
        return prefix, rest
    if name.startswith("claude-") and _MODEL_ID.match(name):
        return "anthropic", name
    raise ModelNameError(
        f"'{name}' does not name a provider. Write <provider>:<model>, e.g. "
        f"openai:gpt-5.1 or local:qwen3:32b (providers: {', '.join(PROVIDERS)}), "
        f"or a Claude name: {', '.join(CLAUDE_ALIASES)} or claude-…")


def canonical(name: str) -> str:
    """One spelling per model: a Claude model as its bare id (what the Claude
    SDK and every existing record use), any other as <provider>:<id>."""
    provider, model = split(name)
    return model if provider == "anthropic" else f"{provider}:{model}"


def provider_of(name: str) -> Provider:
    return PROVIDERS[split(name)[0]]


def valid_policy_entry(entry: str) -> bool:
    """An allowed_models entry: any accepted model name, or <provider>:*."""
    prefix, sep, rest = str(entry).partition(":")
    if sep and rest == "*" and prefix in PROVIDERS:
        return True
    try:
        split(entry)
        return True
    except ModelNameError:
        return False


def allowed(name: str, entries: list[str]) -> bool:
    """Is model `name` covered by the allowed list (exact names or <provider>:*)?"""
    try:
        provider, model = split(name)
    except ModelNameError:
        return False
    want = canonical(name)
    for e in entries or []:
        prefix, sep, rest = str(e).partition(":")
        if sep and rest == "*" and prefix == provider:
            return True
        try:
            if canonical(e) == want:
                return True
        except ModelNameError:
            continue
    return False


# ---------------------------------------------------------------------------
# Prices: USD per million tokens (input, output). Claude's spend is the Claude
# SDK's own figure; for the OpenAI-compatible engine the organization states
# the price of each cloud model it allows (policy.model_prices), because a
# table here would go stale and an unbounded spend must never be the default.
# A self-hosted model costs nothing (turns and the wall clock still bound it).
# ---------------------------------------------------------------------------
def price_for(name: str, model_prices: dict | None) -> tuple[float, float] | None:
    """(input, output) USD per million tokens, or None when unknown."""
    provider, _ = split(name)
    if provider == "local":
        return (0.0, 0.0)
    want = canonical(name)
    for k, v in (model_prices or {}).items():
        try:
            if canonical(k) == want and isinstance(v, (list, tuple)) and len(v) == 2:
                return (float(v[0]), float(v[1]))
        except (ModelNameError, TypeError, ValueError):
            continue
    return None


def cost_usd(price: tuple[float, float], prompt_tokens: int, completion_tokens: int) -> float:
    return (prompt_tokens * price[0] + completion_tokens * price[1]) / 1_000_000


def secret_digest(provider: str, key: str, base_url: str = "") -> str:
    """Bind approval to the provider, address and key without exposing the key."""
    return hashlib.sha256(json.dumps([provider, base_url, key], separators=(",", ":")).encode()).hexdigest()


def validate_base_url(value: str) -> str:
    """The address shape supported by the CONNECT relay; never echo credentials."""
    try:
        url = urlsplit(value)
        valid = (url.scheme in ("http", "https") and url.hostname and
                 re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", url.hostname) and
                 not url.username and not url.password and not url.query and not url.fragment and
                 not any(c.isspace() or ord(c) < 32 for c in value) and
                 (url.port is None or 1 <= url.port <= 65535))
    except ValueError:
        valid = False
    if not valid:
        raise ValueError("Use an HTTP or HTTPS address with a DNS name or IPv4 address and port 1–65535, without credentials, a query or a fragment.")
    return value


# ---------------------------------------------------------------------------
# What a key can use, live from the provider (GET /models). Through the relay
# when a run or the CLI has one (HTTPS_PROXY); the caller supplies the key.
# ---------------------------------------------------------------------------
def list_models(provider: str, *, api_key: str = "", base_url: str = "",
                opener=urllib.request.urlopen, timeout: float = 15, relay: str = "") -> list[str]:
    """The model ids the provider says this key can use, as Agenti names them
    (sorted). Raises RuntimeError with a plain reason on any failure."""
    p = PROVIDERS.get(provider)
    if p is None:
        raise RuntimeError(f"unknown provider '{provider}' (one of {', '.join(PROVIDERS)})")
    url = (base_url or p.base_url).rstrip("/")
    if not url:
        raise RuntimeError(f"{p.label}: no address set ({p.base_url_env})")
    validate_base_url(url)
    headers = {"Accept": "application/json", "User-Agent": "agenti"}
    if p.name == "anthropic":
        headers.update({"x-api-key": api_key, "anthropic-version": "2023-06-01"})
    elif api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    req = urllib.request.Request(url + "/models", headers=headers)
    try:
        if relay:
            endpoint, proxy = urlsplit(url), urlsplit(relay)
            cls = http.client.HTTPSConnection if endpoint.scheme == "https" else http.client.HTTPConnection
            conn = cls(proxy.hostname, proxy.port or 80, timeout=timeout)
            conn.set_tunnel(endpoint.hostname, endpoint.port or (443 if endpoint.scheme == "https" else 80))
            try:
                conn.request("GET", endpoint.path.rstrip("/") + "/models", headers=headers)
                response = conn.getresponse()
                if response.status >= 400:
                    raise RuntimeError(f"{p.label} returned HTTP {response.status}; check the provider key and relay allow-list")
                data = json.loads(response.read(2_000_001))
            finally:
                conn.close()
        else:
            with opener(req, timeout=timeout) as r:
                data = json.loads(r.read(2_000_001))
    except Exception as e:  # noqa: BLE001 - one plain message for the person
        code = getattr(e, "code", None)
        if code in (401, 403):
            raise RuntimeError(f"{p.label} refused the API key (HTTP {code})") from e
        # URLs and transport exceptions can contain provider credentials.
        # Never send either back to the CLI or the web tier.
        raise RuntimeError(f"could not reach {p.label} ({type(e).__name__}); check the server address, API key and relay allow-list") from e
    ids = [str(m.get("id")) for m in (data.get("data") or []) if isinstance(m, dict) and m.get("id")]
    out = []
    for i in ids:
        try:
            out.append(canonical(i if p.name == "anthropic" else f"{p.name}:{i}"))
        except ModelNameError:
            continue
    return sorted(set(out))
