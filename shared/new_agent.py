#!/usr/bin/env python3
"""
new_agent.py — the scaffolding engine behind `agenti new <name>`.

Per CLAUDE.md §3f: "One creation path, three front-ends" — a hand-written
agent file, this CLI scaffold, and (eventually) the GUI's "Create Agent"
form are all supposed to produce the SAME shape: an AgentContract with a
non-empty tool list and a real scope boundary. This script is what makes
that shape concrete for the CLI front-end. It does not invent a second
creation path — it generates exactly the file a human would otherwise
write by copying enum-agent.py or research-agent.py and editing it by hand,
with the boilerplate already correct and clearly marked where it is NOT
(the one example tool, which is a stub by design — see its docstring).

WHY THIS IS A SEPARATE PYTHON SCRIPT, NOT BASH: the actual output is
templated Python source, and after writing it this script PY_COMPILES it
and constructs the AgentContract in a subprocess to confirm it doesn't
raise (see `_smoke_test`) — the same validation deploy.sh does at deploy
time, run here instead, at scaffold time, so a broken scaffold is caught
in the two seconds after `agenti new` runs, not the next time someone
tries to deploy it.

WHY THIS RUNS AGAINST SYSTEM PYTHON, NOT THE VAULT'S VENV: unlike every
other agent operation, this one happens BEFORE deployment — the vault may
be locked, or this may be the very first agent ever scaffolded in a fresh
checkout. It only needs the standard library.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import NoReturn

NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}$")   # matches deploy.sh's own check


class ScaffoldError(Exception):
    """Raised for any condition that should stop scaffolding with a clear,
    user-facing message — never let a raw traceback be the first thing
    someone sees from a tool meant to be a good first impression."""


def _fail(msg: str) -> NoReturn:
    raise ScaffoldError(msg)


# ---------------------------------------------------------------------------
# validation — every check that can refuse BEFORE anything is written
# ---------------------------------------------------------------------------
def validate_name(name: str) -> None:
    if not name:
        _fail("an agent name is required.\n  usage: agenti new <name> [options]\n"
              "  example: agenti new logtriage")
    if not NAME_RE.match(name):
        _fail(
            f"'{name}' is not a valid agent name.\n"
            f"  allowed: lowercase letters, digits, hyphens; must start with a "
            f"letter; 32 characters max.\n"
            f"  this matches deploy.sh's own requirement, since the name becomes "
            f"a directory name, part of a systemd instance name "
            f"(agenti-{name}-instance@<slot>), and a service-account-readable path — "
            f"those all reject the same things.\n"
            f"  examples of valid names: logtriage, dns-enum, research2"
        )
    # Every word the CLI or the API already uses in an agent's position —
    # mirrors api/cli_bridge.py's RESERVED_NAMES (this file is installed on
    # its own, so it can't import that one), plus the vault's own folders.
    reserved = {
        "shared", "lost+found", "list",
        "new", "admin", "vault", "gui", "help", "docs", "agents", "setup", "verify",
        "team", "outputs", "tool-requests",
        "engagement", "dashboard", "principals", "users", "bindings", "principal-history",
        "user-history", "rename",
    }
    if name in reserved:
        _fail(
            f"'{name}' is a reserved name — the CLI or the web API already uses it "
            f"(e.g. `agenti {name}`), so an agent called that could never be "
            f"addressed.\n  pick a different name, e.g. {name}-agent."
        )


def validate_scope(scope: str) -> None:
    if scope not in ("cidr", "domain"):
        _fail(
            f"--scope must be 'cidr' or 'domain', got '{scope}'.\n"
            f"  cidr   — the agent's authorization boundary is IP/CIDR ranges "
            f"(what enum and trafficmon use: shared/scope_cidr.py).\n"
            f"  domain — the agent's authorization boundary is domain names "
            f"(what research uses: shared/scope_domain.py).\n"
            f"  Building a genuinely different boundary (e.g. a set of log "
            f"sources)? Write a new ScopeBoundary implementation first (see "
            f"shared/scope_domain.py's docstring for the interface), then add "
            f"a third choice here — don't force it into cidr or domain."
        )


# `name` was always validated before being embedded into the
# generated agent source; `description` was not. It lands in TWO different
# textual contexts in _agent_py_template()'s output: plain docstring prose
# (name, ` — `, description) and a double-quoted Python string literal
# (argparse's own `description="..."`). A description containing `"""` can
# close the generated file's module docstring early; one containing `"` or
# `\` can break out of the argparse literal — either lets attacker-controlled
# text become executable statements in the scaffolded file, which `_smoke_test`'s
# `py_compile` check does not catch (it only proves the result still parses,
# not that it's the file the template intended). Low risk today (only the
# trusted operator runs `agenti new`), but CLAUDE.md's own plan for the GUI's
# "Create Agent" flow is to reuse this exact template — the day a web form
# collects this same free-text field, this becomes code execution as
# whoever deploys and runs the resulting agent. Found in the 2026-09-20
# security audit (CLAUDE.md §4 item 15); fixed by rejecting the characters
# that make either breakout possible, rather than trying to escape them
# correctly in two different contexts.
_DESCRIPTION_BAD_CHARS = re.compile(r'["\'\\`\r\n]')


def validate_description(value: str) -> None:
    if not value:
        return
    if len(value) > 200:
        _fail(f"--description is {len(value)} characters; keep it to 200 or fewer "
              f"(it's meant to be a one-line summary, not the task prompt).")
    if _DESCRIPTION_BAD_CHARS.search(value):
        _fail(
            f"--description contains a character that isn't allowed: quotes, "
            f"backslashes, and backticks.\n"
            f"  it gets embedded directly into the generated agent's source "
            f"file (both a docstring and a Python string literal), so those "
            f"characters could break out of one and inject code into the "
            f"scaffolded file.\n"
            f"  rephrase without quotes/backslashes/backticks, e.g.: "
            f"'triages application logs for anomalies'"
        )


# ---------------------------------------------------------------------------
# interactive prompting — used only when a required field is missing AND
# stdin is a real terminal (mirrors the harness's own `[[ -t 0 ]]` checks
# for the vault passphrase and the API key prompt)
# ---------------------------------------------------------------------------
def _prompt(label: str, default: str = "", validator=None) -> str:
    suffix = f" [{default}]" if default else ""
    while True:
        try:
            value = input(f"{label}{suffix}: ").strip() or default
        except EOFError:
            _fail(f"no value given for '{label}' and input ended — "
                  f"pass it as a flag instead (see: agenti new --help)")
        if validator:
            try:
                validator(value)
            except ScaffoldError as e:
                print(f"  ✗ {e}", file=sys.stderr)
                continue
        return value


def interactive_fill(args: argparse.Namespace) -> None:
    if not sys.stdin.isatty():
        return   # nothing to prompt into; missing fields will fail validation below
    print(f"Scaffolding a new agent pack. Answers become {args.name}-agent/ — "
          f"press Enter to accept a default in [brackets].\n")
    if not args.scope:
        args.scope = _prompt("scope type (cidr or domain)", "cidr",
                             lambda v: validate_scope(v))
    if not args.description:
        args.description = _prompt(
            "one-line description", f"{args.name} agent (describe its purpose)",
            lambda v: validate_description(v))


# ---------------------------------------------------------------------------
# templates
# ---------------------------------------------------------------------------
def _agent_py_template(name: str, scope: str, description: str) -> str:
    class_name = "CIDRScope" if scope == "cidr" else "DomainScope"
    scope_module = "scope_cidr" if scope == "cidr" else "scope_domain"
    target_example = "192.168.1.50" if scope == "cidr" else "example.com"

    return f'''#!/usr/bin/env python3
"""
{name}-agent.py — {description}

SCAFFOLDED by `agenti new {name}`. This is a STARTING POINT, not a finished
agent — everything marked TODO below needs your attention before this is
real. Three existing agents show what "finished" looks like for different
shapes: enum-agent.py (active scanner, CIDR scope, one central validator),
trafficmon-agent.py (passive collector, CIDR scope, per-tool inline checks),
research-agent.py (active web fetcher, domain scope, per-tool checks + rate
limits). Read whichever is closest to what you're building.

WHAT'S ALREADY WIRED (do not need to touch, and generally shouldn't):
  - The harness (shared/agent_runtime.py): secrets loading, audit logging,
    SIGTERM handling, run-config parsing, the report skeleton.
  - The scope boundary (shared/{scope_module}.py, via SCOPE below): the
    narrowing rule and per-call containment checks.
  - The contract (shared/agent_contract.py, via CONTRACT below): this is
    what makes it STRUCTURALLY IMPOSSIBLE to deploy this file with no tools
    or no scope — CONTRACT's own __post_init__ raises if you remove the one
    example tool below without adding a replacement.

WHAT YOU MUST EDIT (all marked TODO):
  1. ALLOWED_BINARIES / whatever your validator checks, if you shell out to
     external tools at all — this template's example tool does not.
  2. The example tool (record_note) — replace it with your real tool(s).
     Keep the shape: validate the target against SCOPE before doing
     anything, log REQUESTED/EXECUTING lines, save real output to disk if
     it's large, return a trimmed summary.
  3. TASK / _OPERATIONAL_NOTES — the prompt the agent actually sees.
  4. The organisation engagement — set once for every agent by an
     admin (sudo agenti engagement set ..., or the GUI). This is
     the ONE master scope every launch reads. Model and caps are set at
     launch time (agenti ... start --model ...), narrowed by the organisation's
     own policy (the SAME engagement record) — there is nothing left to
     hardcode here.
"""

import argparse
import asyncio
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from claude_agent_sdk import (
    ClaudeAgentOptions,
    ClaudeSDKClient,
    HookMatcher,
    ResultMessage,
    tool,
)

from engagement_context import (build_system_prompt, assert_in_window,
                                load_engagement, EngagementError)
import agent_runtime
import paths
import state
from agent_contract import AgentContract
from agent_runtime import Profile
from {scope_module} import {class_name}

# ---------------------------------------------------------------------------
# 0. RUN PROFILE
# ---------------------------------------------------------------------------
SCOPE = {class_name}(agent_name="{name}")

AGENTI_ROOT = paths.data_root()
# Everything lives under the one organisation directory.
ORG_DIR = AGENTI_ROOT / "org"
AGENT_NAME = "{name}"
AGENT_DIR = ORG_DIR / AGENT_NAME
SHARED_DIR = AGENTI_ROOT / "shared"


# Placeholder numbers — agent_runtime.load_run_config() ALWAYS overwrites
# every one of these before a run starts, resolved against the organisation's
# policy (CLAUDE.md "Current plan"). model=None is never actually used to
# run anything: --model is mandatory at launch, checked there. Still a
# one-entry dict (not a bare Profile) so AgentContract's own "profiles must
# be non-empty" invariant is structurally impossible to bypass by removing it.
PROFILES: dict[str, Profile] = {{
    "run": Profile(
        name="run",
        model=None,
        max_turns=0,
        max_budget_usd=0.0,
        timeout_s=0,
        data_root=AGENT_DIR,
    ),
}}


# ---------------------------------------------------------------------------
# 1. SCOPE + STATE
# ---------------------------------------------------------------------------
ALLOWED_TARGETS: list = []      # populated by configure() — empty means fail closed
ENGAGEMENT = None
PROFILE: Profile | None = None

DATA_DIR: Path | None = None    # set by configure(); reuses scans/ (existing CLI works unchanged)
EXECUTED_ACTIONS: list[dict] = []   # feeds the report's "Actions taken" section

LOG = logging.getLogger("{name}_agent")


# ---------------------------------------------------------------------------
# 2. TOOLS  (the agent's only access to anything — TODO: replace this stub)
# ---------------------------------------------------------------------------
@tool(
    "record_note",
    "STUB — replace this with your real tool(s). Validates `target` against "
    "scope, then records `note` about it. Demonstrates the required shape: "
    "scope check first, audit log, disk-backed output, trimmed response.",
    {{"target": str, "note": str}},
)
async def record_note(args):
    target = str(args.get("target", "")).strip()
    note = str(args.get("note", "")).strip()

    ok, reason = SCOPE.contains(target, ALLOWED_TARGETS)
    LOG.info("REQUESTED | record_note %s | verdict=%s", target, reason)
    if not ok:
        EXECUTED_ACTIONS.append({{"action": f"record_note {{target}}",
                                 "verdict": f"DENIED: {{reason}}"}})
        return {{"content": [{{"type": "text", "text": f"DENIED: {{reason}}"}}],
                "is_error": True}}

    path = DATA_DIR / "notes.jsonl"
    with path.open("a") as f:
        f.write(json.dumps({{"target": target, "note": note,
                            "ts": datetime.now(timezone.utc).isoformat()}}) + "\\n")
    EXECUTED_ACTIONS.append({{"action": f"record_note {{target}}", "verdict": "ok"}})
    return {{"content": [{{"type": "text", "text": f"recorded: {{target}} — {{note}}"}}]}}


# ---------------------------------------------------------------------------
# 3. SYSTEM PROMPT
# ---------------------------------------------------------------------------
# TODO: replace with real guidance for your tools.
_OPERATIONAL_NOTES = """\\
TODO: describe how to use your real tools here. This placeholder only knows
about record_note, the stub tool — replace this whole block once you have
real tools.

If a finding looks critical, stop and summarize it for human review.
"""

RUN_CTX: dict = {{}}       # this run's instruction files, loaded by configure()
SYSTEM_PROMPT = ""        # composed by configure()


# ---------------------------------------------------------------------------
# 4. CONFIGURE  (bind a profile -> engagement -> scope, paths, prompt)
# ---------------------------------------------------------------------------
def _load_run_target(ceiling: list) -> list:
    # required=True: matches enum/research (an active tool should always be
    # pointed at something explicit). Set required=False if this agent is a
    # passive collector where "the whole ceiling" is a legitimate default —
    # see trafficmon-agent.py's own _load_run_target for that shape.
    path = AGENT_DIR / "run-target"
    text = path.read_text() if path.exists() else ""
    return SCOPE.narrow(ceiling, text, required=True)


def configure(profile: Profile) -> Profile:
    global ENGAGEMENT, ALLOWED_TARGETS, DATA_DIR, SYSTEM_PROMPT, PROFILE, RUN_CTX

    PROFILE = profile

    # ONE master scope: the engagement record, viewed through
    # this agent's scope kind — editing/approving it from the GUI is what
    # makes it authoritative for every launch. Every failure names the fix.
    try:
        ENGAGEMENT = load_engagement(SCOPE.kind, org_dir=ORG_DIR,
                                     agent=AGENT_NAME, require_approved=True)
    except EngagementError as e:
        sys.exit(f"REFUSING: {{e}}")

    ALLOWED_TARGETS = SCOPE.ceiling_from_engagement(ENGAGEMENT)

    assert_in_window(ENGAGEMENT)

    if not profile.data_root.exists():
        sys.exit(f"REFUSING: {{profile.data_root}} does not exist. This agent's "
                 f"instance was not provisioned — run:\\n"
                 f"  sudo agenti {{AGENT_NAME}} provision")

    DATA_DIR = (profile.data_root / "scans").resolve()
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        (profile.data_root / "reports").mkdir(parents=True, exist_ok=True)
    except OSError as e:
        sys.exit(f"REFUSING: cannot create {{DATA_DIR}}: {{e}}")
    try:
        agent_runtime.configure_audit_log(LOG, profile.data_root / "audit.log")
    except OSError as e:
        sys.exit(f"REFUSING: cannot open the audit log under {{profile.data_root}}: {{e}}")

    ALLOWED_TARGETS = _load_run_target(ALLOWED_TARGETS)
    profile = agent_runtime.load_run_config(profile, AGENT_DIR, org_dir=ORG_DIR, logger=LOG)
    PROFILE = profile

    agent_runtime.load_secrets([profile.data_root / "secrets.env",
                                ORG_DIR / "secrets.env",
                                SHARED_DIR / "secrets.env"])
    agent_runtime.require_api_key(AGENT_NAME)

    _this_run = (
        "SCOPE FOR THIS RUN\\n"
        f"You may act ONLY on: {{SCOPE.describe(ALLOWED_TARGETS)}}\\n"
        "This is a subset of the engagement scope, selected for this run. Any "
        "action targeting anything else will be denied.\\n"
    )
    # Instruction files: this run's read-only snapshot (shared/context_store.py).
    try:
        RUN_CTX = agent_runtime.load_run_context(AGENT_DIR)
    except agent_runtime.RunContextError as e:
        sys.exit(f"REFUSING: {{e}}")
    SYSTEM_PROMPT = (build_system_prompt(ENGAGEMENT) + "\\n\\n"
                     + _this_run + "\\n" + agent_runtime.run_briefing(AGENT_DIR) + "\\n"
                     + agent_runtime.compose_instructions(RUN_CTX))

    LOG.info("PROFILE | %s | engagement=%s | scope=%s | model=%s | caps=%dt/$%s/%ds",
             profile.name, ENGAGEMENT.engagement_id,
             SCOPE.describe(ALLOWED_TARGETS), profile.model,
             profile.max_turns, profile.max_budget_usd, profile.timeout_s)
    return profile


# ---------------------------------------------------------------------------
# 5. THE DECLARATIVE MANIFEST (CLAUDE.md §3f)
# ---------------------------------------------------------------------------
TASK = "TODO: describe the task for the agent's first message here."

# This agent's own tools; the shared ones are added just below.
_TOOL_NAMES = ("record_note",)      # TODO: your real tool names go here
_TOOLS = (record_note,)             # TODO: your real tool functions go here
# The tools every agent shares (agent_runtime.run_tools); the holder lets
# ask_operator read the StateStore run() creates later.
_STATE_HOLDER = agent_runtime.StateHolder()
_names, _shared = agent_runtime.run_tools(AGENT_DIR, _STATE_HOLDER)
_TOOL_NAMES, _TOOLS = _TOOL_NAMES + _names, _TOOLS + _shared

CONTRACT = AgentContract(
    name=AGENT_NAME,
    tool_names=_TOOL_NAMES,
    tools=_TOOLS,
    mcp_server_name="{name}",
    scope=SCOPE,
    profiles=PROFILES,
    operational_notes=_OPERATIONAL_NOTES,
    task=TASK,
)
MCP_SERVER = CONTRACT.build_mcp_server()
TOOL_ALLOWLIST_HOOK = CONTRACT.make_tool_allowlist_hook(LOG)


# ---------------------------------------------------------------------------
# 6. REPORT
# ---------------------------------------------------------------------------
def write_report(profile: Profile, result, started: float, status: str,
                 findings: str | None = None, note: str | None = None,
                 resumed_from: str | None = None) -> Path | None:
    if ENGAGEMENT is None or PROFILE is None:
        return None
    now = datetime.now(timezone.utc)
    reports = profile.data_root / "reports"
    try:
        reports.mkdir(parents=True, exist_ok=True)
    except OSError:
        return None
    path = reports / f"{{ENGAGEMENT.engagement_id}}-{{now:%Y%m%d-%H%M%S}}.md"

    findings = findings or agent_runtime.findings_text(result)

    L = agent_runtime.report_header(
        title="{name} Report", engagement=ENGAGEMENT, status=status,
        agent_name=AGENT_NAME, profile=profile, scope_label="acted on",
        scope_desc=SCOPE.describe(ALLOWED_TARGETS), started=started, result=result,
        resumed_from=resumed_from,
    )
    if note:
        L += ["", f"> **Note:** {{note}}"]

    # Every note and steering message this run received (CLAUDE.md §3h).
    L += agent_runtime.report_inputs(AGENT_DIR, since=started)

    L += ["", "---", "", "## Findings", ""]
    L.append(findings.strip() if findings else
            "_No findings were produced — the run did not reach a summary._")

    L += ["", "---", "", "## Actions taken", ""]
    if EXECUTED_ACTIONS:
        for a in EXECUTED_ACTIONS:
            L.append(f"- `{{a['action']}}` — {{a['verdict']}}")
    else:
        L.append("_No actions were taken._")

    L += agent_runtime.context_versions_markdown(RUN_CTX)
    L += ["", "---", "", f"_Generated {{now:%Y-%m-%d %H:%M:%S}} UTC._", ""]

    try:
        path.write_text("\\n".join(L))
    except OSError as e:
        print(f"[warn] could not write report: {{e}}")
        return None
    return path


# ---------------------------------------------------------------------------
# 7. RUN
# ---------------------------------------------------------------------------
def _summarize_tool_content(content) -> str:
    """Same helper as enum-agent.py's — see there for the full rationale."""
    try:
        if isinstance(content, list):
            parts = [b.get("text", "") for b in content if isinstance(b, dict)]
            text = " ".join(p for p in parts if p)
        else:
            text = str(content)
    except Exception:
        text = "<unreadable tool result>"
    text = " ".join(text.split())
    return text[:200] + ("…" if len(text) > 200 else "")


# Sent instead of CONTRACT.task when continuing a stopped run. Deliberately
# terse: the conversation history the SDK reloads already contains the task,
# the scope and everything found so far.
RESUME_TASK = (
    "This run was interrupted and has been resumed. Review what you have "
    "already done in this conversation, then continue from where you stopped. "
    "Do not repeat work that is already complete. Note that a tool call which "
    "was in flight when the run stopped may be missing its result — if "
    "something looks unfinished, re-run just that step."
)


async def run(profile: Profile) -> int:
    print(f"[{{profile.name}}] {{ENGAGEMENT.engagement_id}} | "
          f"scope {{SCOPE.describe(ALLOWED_TARGETS)}} | "
          f"{{profile.model}} | <= {{profile.max_turns}} turns, "
          f"<= ${{profile.max_budget_usd}}, <= {{profile.timeout_s}}s\\n")

    # Durable live status + findings (CLAUDE.md §3d, shared/state.py). Every
    # STATE.* call is wrapped defensively; a state-tracking bug must never
    # abort the actual run. TODO: none — this works as-is once ENGAGEMENT
    # and SCOPE/ALLOWED_TARGETS exist, which they already do by this point.
    STATE = state.StateStore(profile.data_root / "state")
    _STATE_HOLDER.state = STATE   # ask_operator's tool closure reads this
    _used = {{"turns": 0, "cost": 0.0}}   # pump_channels' own cap accounting for this run
    launched_by = agent_runtime.read_launched_by(AGENT_DIR)
    launched_via = agent_runtime.read_launched_via(AGENT_DIR)
    # A resume continues the PREVIOUS conversation (CLAUDE.md §3d): the CLI
    # wrote the persisted SDK session id, and STATE.resume() appends to the
    # existing findings ledger instead of truncating it. If there is no prior
    # state, resume() returns False and this falls back to a normal start.
    # TODO: none — this works as-is.
    resume_session = agent_runtime.read_resume_session(AGENT_DIR)
    try:
        resumed = False
        if resume_session:
            resumed = STATE.resume(session_id=resume_session,
                                   launched_by=launched_by, launched_via=launched_via)
            if not resumed:
                print(f"[warn] asked to resume {{resume_session[:8]}}… but no prior "
                      f"state was found — starting a fresh run instead")
                resume_session = None
        if not resumed:
            STATE.start(engagement_id=ENGAGEMENT.engagement_id,
                    target=SCOPE.describe(ALLOWED_TARGETS),
                    profile_name=profile.name,
                    launched_by=launched_by, launched_via=launched_via)
        agent_runtime.log_run_attribution(LOG, agent_name=AGENT_NAME,
                                          launched_by=launched_by,
                                          launched_via=launched_via)
    except Exception as e:
        print(f"[warn] state tracking unavailable: {{e}}")

    # The message-stream tracker lives in the harness now (CLAUDE.md §3d):
    # narration, tool calls and their results into the one ledger, in order.
    _tracker = agent_runtime.StateTracker(STATE, _summarize_tool_content)
    _track_message_for_state = _tracker.track

    options = ClaudeAgentOptions(
        system_prompt=agent_runtime.system_prompt_file(SYSTEM_PROMPT),  # never on argv
        mcp_servers={{CONTRACT.mcp_server_name: MCP_SERVER}},
        allowed_tools=sorted(CONTRACT.allowed_tool_names),
        permission_mode="dontAsk",
        setting_sources=[],  # load no user/project settings: nothing outside our own files steers a run
        hooks=agent_runtime.build_hooks(TOOL_ALLOWLIST_HOOK, HookMatcher, agent_dir=AGENT_DIR,
                                        state=STATE, tracker=_tracker, logger=LOG),
        model=profile.model,
        max_turns=profile.max_turns,
        max_budget_usd=profile.max_budget_usd,
        # Attach to the previous conversation when resuming. Per-run caps are
        # deliberately NOT carried over: they are re-read from run-config.json
        # every time, so a resume can never inherit a looser budget than the
        # operator set for it (CLAUDE.md §1 invariant 7).
        resume=resume_session,
        env=agent_runtime.cli_env(),  # the relay, in an IP-scoped (kernel-fenced) run
    )

    started = time.time()
    result = None
    status = "failed"
    note = None
    reason = None            # why it ended, for history.jsonl — see state.finished()
    _unexpected_error = False
    # Outer try wraps the WHOLE `async with client` statement, not just its
    # body. Verified live in enum-agent.py (identical shape): a
    # KeyboardInterrupt raised mid-tool-call propagates once through the
    # inner receive_response() loop AND AGAIN separately when `async with
    # client:` tears itself down afterward (__aexit__ reaping the
    # still-unwinding tool-call task re-raises it). A try scoped only around
    # the inner loop catches the first copy and lets the second escape
    # uncaught from __aexit__ — write_report() below never runs despite the
    # first copy having been "handled". Wrapping the whole async-with closes
    # that gap.
    try:
        async with ClaudeSDKClient(options=options) as client:
            # `agenti ... interrupt` (SIGUSR1) — a faster stop that aborts the
            # in-flight tool call instead of waiting for it. Installed here,
            # once `client` is live, because client.interrupt() needs the
            # connection. See agent_runtime.install_interrupt_handler.
            agent_runtime.install_interrupt_handler(asyncio.get_running_loop(), client, LOG)
            # On a resume the model already has the task and its findings so
            # far in context; re-sending the original task would restart the
            # work from the top and pay for it twice.
            await client.query(RESUME_TASK if resume_session else agent_runtime.KICKOFF)
            try:
                # Nested (not merged into the outer except*) because
                # client.interrupt() below needs `client` still open, which
                # it no longer is once the outer async-with has unwound.
                async with asyncio.timeout(profile.timeout_s) as _deadline:
                    # A wait for the operator's answer pauses this clock.
                    agent_runtime.bind_run_deadline(_deadline)
                    # OUTER LOOP: one pass per turn cycle (CLAUDE.md §3h).
                    # The inbox is drained between cycles, never mid-tool-call.
                    while True:
                        async for message in client.receive_response():
                            print(message)
                            if isinstance(message, ResultMessage):
                                result = message
                                agent_runtime.note_result(message)
                            elif (type(message).__name__ == "SystemMessage"
                                    and getattr(message, "subtype", None) == "init"):
                                try:
                                    sid = (getattr(message, "data", None) or {{}}).get(
                                        "session_id", "")
                                    if sid:
                                        STATE.session_started(sid)
                                except Exception as e:
                                    print(f"[warn] state tracking: {{e}}")
                            _track_message_for_state(message)

                        # Operator interrupt landed during that turn (or during
                        # the linger below, on the previous pass): the tool
                        # call was already aborted by the signal handler; end
                        # the run here, at the turn boundary, before spending
                        # another turn. Cancels the handler's fallback timer —
                        # the SDK-level interrupt did its job.
                        if agent_runtime.interrupt_requested():
                            agent_runtime.clear_interrupt_fallback()
                            reason = "interrupted"
                            note = ("Run was interrupted by the operator: the step in "
                                    "flight was aborted and the run ended. Findings "
                                    "are incomplete.")
                            print("\\n[INTERRUPTED] ending the run at the turn boundary.")
                            break

                        followup = await agent_runtime.pump_channels(
                            agent_dir=AGENT_DIR, state=STATE, profile=profile,
                            result=result, turn=_tracker.turn, used=_used,
                            client=client, org_dir=ORG_DIR, logger=LOG)
                        if followup is None or agent_runtime.interrupt_requested():
                            if followup is None and agent_runtime.operator_wait_expired():
                                reason = "timeout"
                                note = agent_runtime.operator_wait_note(STATE)
                            break
                        await client.query(followup)
            except* asyncio.TimeoutError:
                reason = "timeout"
                note = f"Run hit the {{profile.timeout_s}}s wall-clock backstop and was interrupted."
                try:
                    await client.interrupt()
                except Exception:
                    pass
    # except* (not except): must catch both a bare KeyboardInterrupt
    # (interrupt during receive_response with no tool call in flight — the
    # original, already-working case) and one wrapped in a
    # BaseExceptionGroup (interrupt during a tool call, or during the
    # client's own teardown). A plain `except` does not match a group and
    # lets it propagate uncaught. except* matches a lone exception exactly
    # like a plain except would, so this is a strict widening.
    except* (KeyboardInterrupt, asyncio.CancelledError):
        # "interrupted" here means the SIGUSR1 handler's FALLBACK fired (the
        # SDK did not wind the turn down in time) — still the operator's
        # interrupt, and history.jsonl should say so, not "stopped".
        reason = "interrupted" if agent_runtime.interrupt_requested() else "stopped"
        note = "Run was stopped before completion. Findings may be incomplete."
    # A genuinely UNEXPECTED exception (a bug, an SDK/API error, anything
    # not already handled above) used to have no except* clause of its
    # own, so it propagated straight past write_report() below — the
    # process crashed with a raw traceback and NO REPORT was written,
    # contradicting the "a report is written on every outcome" invariant
    # (§1 invariant 6). Found in the 2026-09-21 error-message audit
    # (CLAUDE.md §4 item 17), missing from every scaffolded agent until now.
    except* Exception as eg:
        inner = eg.exceptions[0] if eg.exceptions else eg
        reason = "error"
        note = f"Run failed unexpectedly: {{type(inner).__name__}}: {{inner}}"
        print(f"\\n[ERROR] {{note}}")
        LOG.exception("run failed unexpectedly")
        _unexpected_error = True

    if result is not None:
        clean = (result.subtype == "success" and not result.is_error)
        # A resource cap (turns or budget) ending the run with no operator
        # interrupt or exception is the engagement's own configured ceiling
        # doing exactly its job (§1 invariant 7), not a crash.
        if reason is None:
            reason = agent_runtime.resource_cap_reason(result)
            if reason:
                note = note or (
                    f"Run ended: the {{'turn' if reason == 'max_turns' else 'budget'}} "
                    f"cap for this profile was reached before the task finished.")
        # _unexpected_error overrides: an exception AFTER a ResultMessage
        # already arrived must not be masked by a "clean"-looking result.
        if _unexpected_error:
            status = "failed"
        elif reason in ("interrupted", "max_turns", "max_budget"):
            # The SDK reports an interrupted turn OR a resource-cap cutoff as
            # an error result; neither is a bug in the run — one is the
            # operator's doing, the other is the engagement's own cap.
            status = "incomplete"
        else:
            status = "completed" if (clean and not note) else ("incomplete" if clean else "failed")
        rc = 0 if (clean and not _unexpected_error) else 1
    else:
        # Distinguishes "operator stopped it" (incomplete) from "it
        # genuinely broke" (failed) — both leave result as None.
        status = "failed" if _unexpected_error else "incomplete"
        note = note or "The run ended before the agent produced a summary."
        rc = 1

    report = write_report(profile, result, started, status, note=note,
                          resumed_from=resume_session)
    # The report first, then the terminal snapshot that names it, so a
    # history row can open ITS OWN report rather than "the latest one".
    try:
        STATE.finished(status=status, reason=reason,
                       report=report.name if report else None)
    except Exception as e:
        print(f"[warn] state tracking: {{e}}")
    # Tells a teammate this run is genuinely done (CLAUDE.md §4 item 47) —
    # a no-op for a solo run. Every failure/success path reaches here.
    agent_runtime.announce_team_member_ended(AGENT_DIR, status=status, reason=reason)
    if report:
        print(f"  report      : {{report}}")
    return rc


def main() -> int:
    agent_runtime.install_sigterm_handler()
    ap = argparse.ArgumentParser(
        description="{description} Model and caps are set at launch "
                    "(agenti ... start --model ...), not by a flag here.")
    ap.parse_args()

    profile = PROFILES["run"]
    profile = configure(profile)
    return agent_runtime.run_agent(run(profile))


if __name__ == "__main__":
    sys.exit(main())
'''


# ---------------------------------------------------------------------------
# writing + self-check
# ---------------------------------------------------------------------------
def _smoke_test(agent_py: Path) -> None:
    """py_compile the generated file. Catches a broken template immediately —
    the scaffold should never hand someone a syntax error as their first
    experience. (Constructing the actual AgentContract requires
    claude_agent_sdk, which may not be installed outside the vault's venv, so
    that deeper check happens at `agenti <name> verify` / deploy time instead —
    this is the check that's always possible, right here, right now.)"""
    result = subprocess.run([sys.executable, "-m", "py_compile", str(agent_py)],
                            capture_output=True, text=True)
    if result.returncode != 0:
        _fail(
            f"the generated {agent_py.name} does not even parse — this is a bug "
            f"in new_agent.py's template, not something you did:\n"
            f"{result.stderr}\n"
            f"Please report this rather than hand-fixing it silently."
        )


def scaffold(args: argparse.Namespace) -> Path:
    validate_name(args.name)
    interactive_fill(args)
    validate_scope(args.scope or "")
    # Re-validated here even though interactive_fill's prompt already ran a
    # validator: --description on the command line (the non-interactive path)
    # never goes through interactive_fill's validator at all.
    validate_description(args.description or "")

    out_dir = Path(args.dir) / f"{args.name}-agent"
    if out_dir.exists():
        _fail(
            f"{out_dir} already exists — refusing to overwrite it.\n"
            f"  remove it first if you really want to re-scaffold, or pick a "
            f"different name."
        )

    # Filesystem errors here (a read-only --dir, a missing parent, a
    # permission problem) are real and not rare — a typo'd --dir is the most
    # likely way to hit this. Wrapped so the operator sees WHAT failed and
    # WHERE, not a Python traceback through pathlib's internals. If we got
    # far enough to create the directory before failing, clean it up too, so
    # a retry doesn't immediately hit "already exists" from the dead attempt.
    created_dir = False
    try:
        out_dir.mkdir(parents=True)
        created_dir = True
        agent_py = out_dir / f"{args.name}-agent.py"
        agent_py.write_text(_agent_py_template(args.name, args.scope,
                                               args.description or f"{args.name} agent"))
        # The shipped default system prompt: what an admin edits in Settings →
        # Agents once the agent is deployed. Required — a run without one is refused.
        (out_dir / "context").mkdir()
        (out_dir / "context" / "system-prompt.md").write_text(
            "## Objective\n\n"
            f"{args.description or args.name + ' agent'}. TODO: describe what this agent "
            "should achieve and what its final summary should contain.\n\n"
            "## How you work\n\n"
            "TODO: describe how to use your real tools here. This placeholder only "
            "knows about record_note, the stub tool.\n\n"
            "If a finding looks critical, stop and summarize it for human review.\n")
    except OSError as e:
        if created_dir:
            import shutil
            shutil.rmtree(out_dir, ignore_errors=True)
        _fail(
            f"could not write {out_dir}: {e}\n"
            f"  check that {args.dir!r} exists and you have permission to "
            f"write into it — pass a different --dir if not."
        )

    _smoke_test(agent_py)

    return out_dir


# ---------------------------------------------------------------------------
class _JsonAwareArgumentParser(argparse.ArgumentParser):
    """Same fix, same reason, as iam.py's parser of the same name (CLAUDE.md
    §4 item 17): argparse's own error() prints usage to stderr and exit(2)s
    unconditionally, because a parse failure happens before there is a
    namespace to read .json from. That breaks the one-stream contract for
    every caller that asked for JSON — and `agenti new` acquired a real such
    caller when the GUI's create-agent flow started shelling to it through
    cli_bridge (which appends --json to EVERY call). Without this, a bad
    field came back to the browser as an empty stdout and a 500 rather than
    the message explaining what was wrong."""
    def error(self, message):
        if "--json" in sys.argv:
            print(json.dumps({"error": message}))
            self.exit(2)
        super().error(message)


def build_parser() -> argparse.ArgumentParser:
    ap = _JsonAwareArgumentParser(allow_abbrev=False, 
        prog="agenti new",
        description="Scaffold a new agent pack from the same contract every "
                    "agent is built from (CLAUDE.md §3f). Generates "
                    "<name>-agent/ with a working, runnable skeleton.",
        epilog="Fields not given as flags are prompted for interactively "
              "when run from a terminal. Example:\n"
              "  agenti new logtriage --scope domain \\\n"
              "      --description 'triages application logs for anomalies'",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("name", help="agent name — lowercase letters, digits, "
                    "hyphens; becomes <name>-agent/ and part of the systemd "
                    "unit name agenti-<name>-instance@<slot>")
    ap.add_argument("--scope", choices=("cidr", "domain"),
                    help="the agent's authorization boundary type: 'cidr' for "
                        "IP/network-based agents, 'domain' for web/OSINT-based "
                        "agents. See shared/scope_cidr.py / scope_domain.py.")
    ap.add_argument("--description", metavar="TEXT",
                    help="one-line description, used in the generated "
                        "docstring and --help text")
    ap.add_argument("--dir", default=".", metavar="PATH",
                    help="where to create <name>-agent/ (default: current "
                        "directory — run this from your source checkout)")
    ap.add_argument("--json", action="store_true",
                    help="emit one JSON object on stdout instead of the "
                        "human-readable next-steps text; errors become "
                        '{"error": "..."} with a non-zero exit, the same '
                        "one-stream contract every other agenti verb keeps")
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        out_dir = scaffold(args)
    except ScaffoldError as e:
        if args.json:
            print(json.dumps({"error": str(e)}))
        else:
            print(f"\nerror: {e}\n", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps({
            "name": args.name,
            "dir": str(out_dir),
            "files": sorted(p.name for p in out_dir.iterdir() if p.is_file()),
            "created": True,
            # Said in the payload, not just in the prose below, because the
            # GUI shows this to someone who cannot see a terminal: a scaffold
            # is a starting point, and nothing runs it until a human edits
            # its tools and an admin deploys it.
            "runnable": False,
            "next_steps": (f"edit {out_dir.name}/{args.name}-agent.py (its record_note "
                           f"stub is the only tool it has), then on the host: "
                           f"sudo ./shared/deploy.sh"),
        }))
        return 0

    print(f"""
scaffolded: {out_dir}/
  {args.name}-agent.py

This is a STARTING POINT — every TODO in {args.name}-agent.py needs your
attention before it does anything real.

  1. Review and edit {out_dir}/{args.name}-agent.py — especially the
     record_note stub tool (section 2).
  2. When it's ready for the hardened layout (from the source checkout):
       sudo ./shared/deploy.sh
  3. Set and approve the engagement, once for every agent in it —
     every launch reads this SAME record, and an admin's own policy on it
     (agenti engagement set --allowed-models ..., caps, whether
     approval is even required) governs what an operator may launch with:
       sudo agenti engagement set --engagement-id <id> --client <name> ...
       sudo agenti engagement approve
     (or Settings → Engagement in the GUI).
  4. Run it:
       sudo agenti {args.name} start -t <target> --model sonnet
     (--model is mandatory, from the organisation's allowed list set in step 3.)

There is no standalone "run it by hand, no deployment needed" shortcut any
more (CLAUDE.md "Current plan"): the model and caps are resolved from the
organisation's own engagement record at launch, so a real deployment is what
makes a run of ANY kind possible now, not an extra step for commercial use.
""")
    return 0


if __name__ == "__main__":
    sys.exit(main())
