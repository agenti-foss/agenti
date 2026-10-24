"""
recon_runner.py — the ONE runner every network-recon agent uses (enum, and
every agent an admin builds in Settings -> Agents).

A recon agent is DATA, not code: its own folder holds a manifest.json (its
name, title, description and the reviewed programs it may run) and a
three-line stub that calls main() here. Nothing typed into a form ever
becomes code, and there is no per-agent runner to review. The behaviour is
exactly what enum-agent.py always did — this file IS that code, with the
agent-specific values (name, program allow-list) read from the manifest:

  * Disk offload .... run_scan saves the FULL raw output to ./scans/ and
                      returns only a trimmed summary + an index.
  * On-demand fetch . read_scan pulls back exactly what the agent needs from
                      a saved scan, by grep pattern or line range.
  * Guardrails ...... a validated allow-list tool is the agent's only network
                      path, raw Bash is hard-denied by a hook, scope is a
                      hard boundary enforced by root-owned files, and every
                      run reads the organisation's engagement record.

>>> Only ever point this at networks you are explicitly authorized to test. <<<

WHAT A MANIFEST MAY CHOOSE, AND WHAT IT MAY NOT
  It may choose which programs the agent can run — but only names that are
  either in the baseline recon list or in the reviewed catalog
  (shared/tool-catalog.json, which refuses shells, interpreters, exploitation
  tooling and anything else on its block list). setup() re-checks every name
  at run time, so a hand-edited manifest cannot smuggle in a program the
  catalog would refuse. It may NOT choose the denied argument patterns, the
  scope rules, the tools (always run_scan + read_scan) or the model/caps —
  those are fixed in code or resolved from the engagement's own policy.

Install:  pip install claude-agent-sdk
Auth:     export ANTHROPIC_API_KEY=...   (or secrets.env)
Run:      sudo agenti <agent> start -t <target> --model sonnet
"""

import argparse
import json
import logging
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

# The engagement module itself is chosen by the run profile and imported in
# configure(); only the helpers that consume it are imported statically here.
from engagement_context import (build_system_prompt, assert_in_window,
                                load_engagement, EngagementError)
import agent_runtime
import paths
import session_runner
from agent_contract import AgentContract
from agent_runtime import Profile
from scope_cidr import CIDRScope

# ---------------------------------------------------------------------------
# RUN STATE — set once by setup() from the manifest. Everything below reads
# these module globals, exactly as enum-agent.py did with its own constants.
# ---------------------------------------------------------------------------
AGENTI_ROOT = paths.data_root()
# Everything lives under the one organisation directory.
ORG_DIR = AGENTI_ROOT / "org"
SHARED_DIR = AGENTI_ROOT / "shared"

SCOPE: CIDRScope | None = None
AGENT_NAME = ""
AGENT_TITLE = ""
AGENT_DESCRIPTION = ""
AGENT_DIR: Path = AGENTI_ROOT
PROFILES: dict[str, Profile] = {}

# Populated by configure() from the engagement; empty until then — fail-closed.
ALLOWED_NETWORKS: list = []
ENGAGEMENT = None
PROFILE: Profile | None = None

ALLOWED_BINARIES: set = set()
TOOL_PURPOSES: dict = {}


SCAN_DIR: Path | None = None                 # set by configure(); full raw outputs

# Every command the agent proposed this run, allowed or denied, in order.
# Feeds the "Commands executed" section of the report — the denials are the
# audit-valuable part, since they show the boundary actually holding.
EXECUTED_COMMANDS: list[dict] = []
TRIM_BYTES = 8000                            # summary size returned to the agent
MAX_RETURN_BYTES = 8000                      # cap on any read_scan response

LOG = logging.getLogger("recon_agent")

import tool_registry

# Denied even on an allow-listed binary. Fixed in tool_registry, never from the
# manifest.
DENIED_PATTERNS = list(tool_registry.RECON_DENIED_PATTERNS)

# Built once; filled IN PLACE by configure() (workdir, scope, scope_ceiling).
# actions=EXECUTED_COMMANDS is the SAME list write_report() reads, so appends
# from inside a registry-built tool land in it.
TOOL_CTX = tool_registry.ToolContext(
    log=LOG, actions=EXECUTED_COMMANDS, trim_bytes=TRIM_BYTES, max_return_bytes=MAX_RETURN_BYTES)

RUN_CTX: dict = {}       # this run's instruction files, loaded by configure()
SYSTEM_PROMPT = ""        # composed by configure()
_OFFERED: set = set()     # programs an admin offered for operators to approve
_STATE_HOLDER = agent_runtime.StateHolder()
CONTRACT = None
MCP_SERVER = None
TOOL_ALLOWLIST_HOOK = None

TASK = ("Assess the authorized host(s) for live services and exposure, "
        "then give me a findings summary.")
_OPERATIONAL_NOTES = """\
Interact with the network ONLY via run_scan. Enumeration only: discover hosts,
ports and services. Never exploit, brute force, or run DoS.

Output is trimmed by default and saved to disk. When the summary or index
suggests detail you need, call read_scan with a TARGETED grep pattern or a
specific line range — do not pull whole files unless you truly need them.

If a finding looks critical, stop and summarize it for human review.
"""


class ManifestError(Exception):
    """The manifest is unusable; the message says why and what to do."""


def _load_manifest(manifest_path: Path) -> dict:
    try:
        data = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise ManifestError(f"cannot read {manifest_path}: {e}")
    if not isinstance(data, dict):
        raise ManifestError(f"{manifest_path} is not a JSON object")
    name = data.get("name")
    if not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,31}", name):
        raise ManifestError(f"{manifest_path}: 'name' is missing or not a valid agent name")
    # A built agent's folder is named after it. A manifest copied under
    # another agent's folder would run as that agent (its state, its grants),
    # so the two names must agree.
    if Path(manifest_path).resolve().parent.name != name:
        raise ManifestError(f"{manifest_path}: the manifest names '{name}' but sits in the folder "
                            f"'{Path(manifest_path).resolve().parent.name}' — they must match")
    if data.get("scope_kind") != "cidr":
        raise ManifestError(f"{manifest_path}: this runner only runs network (cidr) agents, "
                            f"not scope_kind={data.get('scope_kind')!r}")
    progs = data.get("programs")
    if not isinstance(progs, list) or not progs or not all(
            isinstance(p, dict) and isinstance(p.get("name"), str) for p in progs):
        raise ManifestError(f"{manifest_path}: 'programs' must list at least one "
                            f"{{name, purpose}} entry")
    return data


def _vet_programs(progs: list, catalog: dict) -> tuple[set, dict, list]:
    """(allowed names, purposes, extra denied patterns) for the manifest's
    programs, after checking each is a baseline or catalog program and none
    is blocked. Fails closed — the runner never trusts that the manifest was
    written by the builder."""
    import tool_catalog as tc
    baseline = {p["name"] for p in tc.baseline_programs(catalog)}
    known = baseline | tc.catalog_names(catalog)
    names, purposes = set(), {}
    for p in progs:
        n = p["name"]
        if not tc.NAME_RE.match(n):
            raise ManifestError(f"program {n!r} is not a valid program name")
        if n in tc.BLOCKED_PROGRAMS or n in {x for x in catalog.get("never_in_this_catalog", [])}:
            raise ManifestError(f"program {n!r} is on the block list and can never be allowed")
        if n not in known:
            raise ManifestError(
                f"program {n!r} is not in the baseline recon list or the reviewed catalog — "
                f"an admin can add it in Settings -> Agents -> Program catalog, or remove it "
                f"from this agent")
        names.add(n)
        purposes[n] = str(p.get("purpose") or "")[:200]
    return names, purposes, tc.patterns_for_programs(names, catalog)


def setup(manifest_path: Path) -> None:
    """Bind this process to one manifest: identity, scope object, program
    allow-list, and the contract/tools/hook built from them. Called once, by
    main(), before configure()."""
    global SCOPE, AGENT_NAME, AGENT_TITLE, AGENT_DESCRIPTION, AGENT_DIR, PROFILES
    global ALLOWED_BINARIES, TOOL_PURPOSES, _OFFERED
    global CONTRACT, MCP_SERVER, TOOL_ALLOWLIST_HOOK
    import tool_catalog as tc
    import tool_settings_store as tss

    manifest = _load_manifest(manifest_path)
    AGENT_NAME = manifest["name"]
    AGENT_TITLE = str(manifest.get("title") or AGENT_NAME)
    AGENT_DESCRIPTION = str(manifest.get("description") or "")
    SCOPE = CIDRScope(agent_name=AGENT_NAME)

    # AGENTI_INSTANCE, when set, is the authoritative absolute path for this
    # run's own run-slot directory (CLAUDE.md §4 item 71: every run is some
    # user's, in <agent>/instances/<owner>[.<copy>]).
    AGENT_DIR = Path(os.environ["AGENTI_INSTANCE"]) if os.environ.get("AGENTI_INSTANCE") \
        else ORG_DIR / AGENT_NAME

    # Placeholder numbers — agent_runtime.load_run_config() ALWAYS overwrites
    # every one of these before a run starts, resolved against the organisation's
    # own policy. Still a one-entry dict so AgentContract's "profiles must be
    # non-empty" invariant (§3f) holds.
    PROFILES = {"run": Profile(name="run", model=None, max_turns=0, max_budget_usd=0.0,
                               timeout_s=0, data_root=AGENT_DIR)}

    try:
        catalog = tss.catalog_for(SHARED_DIR, strict=True)
    except tc.CatalogError as e:
        sys.exit(f"REFUSING: {e}")
    try:
        ALLOWED_BINARIES, TOOL_PURPOSES, catalog_denied = _vet_programs(manifest["programs"], catalog)
    except ManifestError as e:
        sys.exit(f"REFUSING: {e}")
    base_denied = DENIED_PATTERNS + catalog_denied

    # An admin may narrow ALLOWED_BINARIES or extend it from the reviewed
    # catalog. Settings that cannot be applied stop the run, never fall back
    # (agent_runtime.resolve_tool_allowlist).
    try:
        effective_binaries, effective_denied = agent_runtime.resolve_tool_allowlist(
            org_dir=ORG_DIR, shared_dir=SHARED_DIR, agent=AGENT_NAME,
            baseline=ALLOWED_BINARIES, denied_patterns=base_denied)
    except agent_runtime.ToolSettingsError as e:
        sys.exit(f"REFUSING: {e}")
    tool_names, tools = tool_registry.build_tools(
        ["run_scan", "read_scan"], TOOL_CTX,
        config={"run_scan": {"allowed_binaries": effective_binaries,
                             "denied_patterns": effective_denied,
                             # A program the operator approves for THIS run is
                             # added at call time — see make_run_grants_reader.
                             "dynamic_allow": agent_runtime.make_run_grants_reader(
                                 agent_dir=AGENT_DIR, org_dir=ORG_DIR,
                                 shared_dir=SHARED_DIR, agent=AGENT_NAME,
                                 baseline=ALLOWED_BINARIES)}})
    # The tools every agent shares (team, ask_operator, files, request_tool
    # when an admin offers a program) — agent_runtime.run_tools.
    _OFFERED = agent_runtime.offered_programs(
        org_dir=ORG_DIR, shared_dir=SHARED_DIR, agent=AGENT_NAME,
        baseline=ALLOWED_BINARIES)
    names, shared = agent_runtime.run_tools(AGENT_DIR, _STATE_HOLDER, _OFFERED)
    tool_names, tools = tool_names + names, tools + shared

    CONTRACT = AgentContract(
        name=AGENT_NAME, tool_names=tool_names, tools=tools,
        mcp_server_name="recon", mcp_server_version="2.0.0",
        scope=SCOPE, profiles=PROFILES,
        operational_notes=_OPERATIONAL_NOTES, task=TASK,
    )
    MCP_SERVER = CONTRACT.build_mcp_server()
    TOOL_ALLOWLIST_HOOK = CONTRACT.make_tool_allowlist_hook(LOG)



def _load_run_target(profile: Profile, ceiling: list) -> list:
    # AGENT_DIR, not data_root: the CLI writes one target per agent, and both
    # profiles read it. Keeping it root-owned is the whole protection.
    # required=True: an active scanner must always be pointed at something
    # explicit — unlike trafficmon, it never falls back to the whole ceiling.
    path = AGENT_DIR / "run-target"
    text = path.read_text() if path.exists() else ""
    return SCOPE.narrow(ceiling, text, required=True)


def configure(profile: Profile) -> Profile:
    global ENGAGEMENT, ALLOWED_NETWORKS, SCAN_DIR, SYSTEM_PROMPT, PROFILE, RUN_CTX

    PROFILE = profile

    # -- 1. load the engagement this profile is bound to ---------------------
    # CLAUDE.md "Current plan": ONE master scope, the organisation's
    # engagement record, viewed through this agent's scope kind — read by
    # BOTH profiles now, not a separate box-wide "lab" record only dev used
    # to read. Editing/approving it from the GUI is what makes it the
    # single source of truth for every launch, not just commercial ones.
    # Every failure the loader raises names the command that fixes it.
    try:
        ENGAGEMENT = load_engagement(SCOPE.kind, org_dir=ORG_DIR,
                                     agent=AGENT_NAME, require_approved=True)
    except EngagementError as e:
        sys.exit(f"REFUSING: {e}")

    # -- 2. derive scope from the config (single source of truth) -------------
    # (ceiling_from_engagement refuses if in_scope is empty or malformed)
    ALLOWED_NETWORKS = SCOPE.ceiling_from_engagement(ENGAGEMENT)

    # -- 3. time-bounded authorization ---------------------------------------
    assert_in_window(ENGAGEMENT)

    # -- paths: scans + audit log live under the profile's data root ----------
    if not profile.data_root.exists():
        sys.exit(f"REFUSING: {profile.data_root} does not exist. This agent's "
                 f"instance was not provisioned — run:\n"
                 f"  sudo agenti {AGENT_NAME} provision")

    SCAN_DIR = (profile.data_root / "scans").resolve()
    TOOL_CTX.workdir = SCAN_DIR
    try:
        SCAN_DIR.mkdir(parents=True, exist_ok=True)
        (profile.data_root / "reports").mkdir(parents=True, exist_ok=True)
    except OSError as e:
        sys.exit(f"REFUSING: cannot create {SCAN_DIR}: {e}")
    try:
        agent_runtime.configure_audit_log(LOG, profile.data_root / "audit.log")
    except OSError as e:
        sys.exit(f"REFUSING: cannot open the audit log under {profile.data_root}: {e}")

    # -- 4. per-run inputs: narrow the scope, apply run-config -----------------
    # ALLOWED_NETWORKS currently holds the engagement CEILING. The target file
    # narrows it for this run; anything outside the ceiling is refused.
    ALLOWED_NETWORKS = _load_run_target(profile, ALLOWED_NETWORKS)
    # TOOL_CTX is what the registry-built run_scan/read_scan actually read;
    # keeping ALLOWED_NETWORKS as a module global too is deliberate — it is
    # what write_report()'s prompt text and the rest of configure() already
    # use, so it stays exactly as it was rather than being routed through
    # TOOL_CTX and back.
    TOOL_CTX.scope = SCOPE
    TOOL_CTX.scope_ceiling = ALLOWED_NETWORKS
    # strict=True: a malformed run-config.json REFUSES rather than warns — this
    # agent spends real API budget per run, unlike trafficmon's lenient default.
    profile = agent_runtime.load_run_config(profile, AGENT_DIR, org_dir=ORG_DIR,
                                            logger=LOG, strict=True)
    PROFILE = profile

    # -- credentials ----------------------------------------------------------
    # Load secrets.env from the install prefix, then fail EARLY if there is no
    # key. Without this the run dies mid-flight on an auth error after the agent
    agent_runtime.load_secrets(
        agent_runtime.secrets_path_list(profile.data_root, AGENT_NAME, ORG_DIR, SHARED_DIR)
    )
    agent_runtime.require_api_key(AGENT_NAME)

    # -- the prompt the agent actually sees -----------------------------------
    # The authorization block comes from the engagement (the ceiling), but the
    # agent is told the scope for THIS run so it doesn't waste turns proposing
    # scans the validator would deny.
    _this_run = (
        "SCOPE FOR THIS RUN\n"
        f"You may scan ONLY: {SCOPE.describe(ALLOWED_NETWORKS)}\n"
        "This is a subset of the engagement scope, selected for this run. Any "
        "command targeting anything else will be denied.\n"
    )

    # -- instruction files: this run's read-only snapshot (context_store.py) --
    try:
        RUN_CTX = agent_runtime.load_run_context(AGENT_DIR)
    except agent_runtime.RunContextError as e:
        sys.exit(f"REFUSING: {e}")
    SYSTEM_PROMPT = (build_system_prompt(ENGAGEMENT) + "\n\n"
                     + _this_run + "\n" + agent_runtime.run_briefing(AGENT_DIR) + "\n"
                     + agent_runtime.compose_instructions(RUN_CTX))
    if _OFFERED:
        # Only said when an admin actually offered something: otherwise the
        # tool does not exist and there is nothing to mention.
        SYSTEM_PROMPT += (
            "\n\n===== ASKING FOR AN EXTRA PROGRAM =====\n"
            "If a command is refused because its program is not on your allow-list, and the "
            "program is one of: " + ", ".join(sorted(_OFFERED)) + " — and you genuinely need it — "
            "call the request_tool tool with the program and a short reason, instead of "
            "asking the operator in free text. The operator can allow it for this run only. "
            "Anything not in that list cannot be requested this way.\n")

    LOG.info("PROFILE | %s | engagement=%s | scope=%s | model=%s | caps=%dt/$%s/%ds",
             profile.name, ENGAGEMENT.engagement_id,
             SCOPE.describe(ALLOWED_NETWORKS), profile.model,
             profile.max_turns, profile.max_budget_usd, profile.timeout_s)
    return profile


# ---------------------------------------------------------------------------
# 7. WIRE IT UP
#
# CACHING — what the SDK does vs. what you control:
#   * The Agent SDK caches automatically (tools, system prompt, and growing
#     history), the same machinery as Claude Code. You do NOT hand-place
#     cache_control here.
#   * What you DO control: keep the cached prefix byte-stable. The SYSTEM_PROMPT
#     above and the ALLOWED_* config are stable; avoid injecting volatile values
#     (clock, random IDs) into the front of context, or you cause cache misses.
#   * The disk-offload design helps caching too: small, stable summaries enter
#     history (cheap to keep warm) instead of huge volatile dumps.
#   * Long scans can outlive the 5-min cache TTL while the agent waits. If you
#     run your own loop (section 8), put the 1-hour TTL on the stable prefix.
# ---------------------------------------------------------------------------
def write_report(profile: Profile, result, started: float, status: str,
                 findings: str | None = None, note: str | None = None,
                 resumed_from: str | None = None) -> Path | None:
    """Write a durable, client-readable report of this run.

    Written on EVERY outcome, including failure and early stop — a run that was
    interrupted still touched a client network, and the record of what it did
    matters at least as much as one that finished. The journal rotates; this
    does not, and it lives inside the encrypted vault.
    """
    if ENGAGEMENT is None or PROFILE is None:
        return None
    now = datetime.now(timezone.utc)
    reports = profile.data_root / "reports"
    try:
        reports.mkdir(parents=True, exist_ok=True)
    except OSError:
        return None
    path = reports / f"{ENGAGEMENT.engagement_id}-{now:%Y%m%d-%H%M%S}.md"

    findings = findings or agent_runtime.findings_text(result)

    L = agent_runtime.report_header(
        title="Assessment Report", engagement=ENGAGEMENT, status=status,
        agent_name=AGENT_NAME, profile=profile, scope_label="scanned",
        scope_desc=SCOPE.describe(ALLOWED_NETWORKS), started=started, result=result,
        resumed_from=resumed_from,
    )
    if note:
        L += ["", f"> **Note:** {note}"]

    # Every note and steering message this run received (CLAUDE.md §3h).
    # In EVERY report, not just ones that got input: "the operator steered this
    # run" is material context for whoever reads the findings.
    L += agent_runtime.report_inputs(AGENT_DIR, since=started)

    L += session_runner.findings_block(findings)
    L += session_runner.commands_block(
        EXECUTED_COMMANDS, denied_note="denied by the scope/allow-list validator — the boundary held.")
    L += session_runner.outputs_block("Raw scan files", "scans", SCAN_DIR, EXECUTED_COMMANDS)

    L += agent_runtime.context_versions_markdown(RUN_CTX)
    L += ["", "---", "",
          f"_Generated {now:%Y-%m-%d %H:%M:%S} UTC. Enumeration only — "
          f"no exploitation was attempted._", ""]

    try:
        path.write_text("\n".join(L))
    except OSError as e:
        print(f"[warn] could not write report: {e}")
        return None
    return path


async def run(profile: Profile) -> int:
    """The run loop is shared with the file-analysis kind (session_runner.py);
    what is specific to a recon agent is handed over here."""
    return await session_runner.run_session(session_runner.Session(
        profile=profile, contract=CONTRACT, mcp_server=MCP_SERVER,
        allowlist_hook=TOOL_ALLOWLIST_HOOK, system_prompt=SYSTEM_PROMPT,
        agent_dir=AGENT_DIR, org_dir=ORG_DIR, log=LOG, state_holder=_STATE_HOLDER,
        engagement_id=ENGAGEMENT.engagement_id,
        target_label=SCOPE.describe(ALLOWED_NETWORKS),
        write_report=write_report))


def main(manifest_path: Path | str) -> int:
    agent_runtime.install_sigterm_handler()
    ap = argparse.ArgumentParser(allow_abbrev=False, 
        description="Scope-limited, authorized network recon agent. "
                    "Model and caps are set at launch (agenti ... start --model ...), "
                    "not by a flag here.")
    ap.parse_args()
    setup(Path(manifest_path))
    profile = configure(PROFILES["run"])   # every refusal gate runs in here
    return agent_runtime.run_agent(run(profile))
