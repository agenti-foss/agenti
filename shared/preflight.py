#!/usr/bin/env python3
"""
preflight.py — security & operational gate for the assessment harness.

Run by systemd as ExecStartPre. Exits NON-ZERO (aborting harness startup) unless
every precondition for safely running an unattended drop box is met:

  1. Clock is sane and synchronized        (window checks & TLS depend on it;
                                             the Pi has no battery-backed RTC)
  2. Data partition is mounted AND LUKS     (scans/logs/keys encrypted at rest)
  3. Secrets file exists, owned by us, 0600
  4. scans/ directory is writable
  5. Outbound TLS to the Claude API works   (no egress -> brain-dead agent)
  6. The organisation's engagement — the ONE master scope, read by every run
     (CLAUDE.md "Current plan") — loads for this agent's scope kind, is
     in its authorized window and has a non-empty scope for that kind
     (one engagement for the whole organisation, not per agent)
  7. Admin approval, UNLESS the organisation's policy has it turned off: an
     admin has approved the engagement AS IT STANDS — the approval
     is bound to the record's content digest, so an edit after approval
     fails this check until it is re-approved (§3g). require_approval
     defaults to true; it may be turned off (agenti engagement
     set --no-require-approval) as part of its own operational policy.

All checks run, so the operator sees the full picture, then the script exits 1
if ANY failed. A clean exit (0) is the only thing that lets the harness launch.
"""

import json
import os
import secrets
import socket
import ssl
import shutil
import stat
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

# Which agent are we gating? The run-slot unit (agenti-instance@.service,
# rendered per agent) sets AGENT_NAME and AGENTI_INSTANCE explicitly; %i there
# is the run slot, not the agent. Both fall back sanely so a hand-run (no
# systemd env at all) still resolves to somewhere sensible: the agent name
# from AGENTI_INSTANCE's own directory name (this script no longer sits
# inside the agent's own tree at all — see MASTER_DIR).
import paths  # noqa: E402  (where Agenti's files live; beside this file)

AGENTI_ROOT = paths.data_root()
ORG_DIR = AGENTI_ROOT / "org"
_INSTANCE_HINT = os.environ.get("AGENTI_INSTANCE")
AGENT_NAME = os.environ.get("AGENT_NAME") or (
    Path(_INSTANCE_HINT).name if _INSTANCE_HINT else "default")
# DATA_ROOT is this run's own slot — runtime state only (scans/reports/
# state/run-target/…). MASTER_DIR is the agent's own CODE — one copy,
# shared by every user: <agent>-agent.py, manifest.json, capabilities.json.
# Immutability means "this uid cannot write MASTER_DIR".
# _INSTANCE_HINT, when set, is the authoritative absolute path for this
# run's own slot directory (…/org/<agent>/instances/<owner>[.<copy>]).
DATA_ROOT = Path(_INSTANCE_HINT) if _INSTANCE_HINT else ORG_DIR / AGENT_NAME
MASTER_DIR = paths.master_dir(AGENT_NAME, AGENTI_ROOT)
SCANS_DIR = DATA_ROOT / "scans"
SHARED_DIR = AGENTI_ROOT / "shared"
# The organisation's engagement record and its approval live in org/:
# one record every agent reads through its own scope kind. Both are
# root-owned 0640, readable by this service account, writable by nobody but
# root — the same shape as run-target.
ORG_DIR = ORG_DIR

# Key lookup mirrors the harness exactly: the agent's own key wins, else shared.
# Checking a different file than the agent uses would make this gate a lie.
SECRETS_CANDIDATES = [DATA_ROOT / "secrets.env", SHARED_DIR / "secrets.env"]
API_HOST = "api.anthropic.com"

results: list[tuple[bool, str, str]] = []


def add(ok: bool, label: str, detail: str = "") -> None:
    results.append((ok, label, detail))


def check_clock() -> None:
    now = datetime.now(timezone.utc)
    if now.year < 2026:
        add(False, "clock", f"system clock looks unset ({now.isoformat()})")
        return
    try:
        out = subprocess.run(
            ["timedatectl", "show", "-p", "NTPSynchronized", "--value"],
            capture_output=True, text=True, timeout=5,
        )
        synced = out.stdout.strip() == "yes"
        add(synced, "clock", "NTP synchronized" if synced else "NOT NTP-synced")
    except Exception:
        add(True, "clock", f"plausible ({now.date()}); NTP state unknown")


def check_encrypted() -> None:
    """Encryption at rest is reported, not required (operator decision 5,
    audit run 1): the vault is optional, and with neither it nor full-disk
    encryption the run still starts, with the standing warning in its log."""
    import disk_encryption
    st = disk_encryption.status(DATA_ROOT)
    if st["encrypted"]:
        add(True, "encrypted-disk", f"{DATA_ROOT} on {st['device']} ({st['how']} encryption)")
    elif st["encrypted"] is False:
        add(True, "encrypted-disk", f"WARNING: {disk_encryption.WARNING}")
    else:
        add(True, "encrypted-disk", f"WARNING: could not tell whether {DATA_ROOT} is encrypted "
                                    f"(device {st['device'] or 'unknown'})")


def check_secrets() -> None:
    """Two legitimately different secure shapes now (CLAUDE.md §3g), not one:

    - agent-specific / organisation-shared tiers: owned outright by this process's
      own account, strictly owner-only (0600) — unchanged from before
      multi-tenancy existed.
    - platform-shared tier: root-owned, group-readable by 'agenti-shared'
      (0640) — the service account is a member, so this ONE file can be a
      fallback for every agent without being world-readable. Bits alone
      don't prove readability here, so this also checks the process is
      actually a member of the owning group.
    """
    # systemd has already loaded every key tier (shared, org, agent, slot and
    # the owner's own, last wins) into this environment; that is the key the
    # run will use, so it is the one to require (audit run 1, N01).
    if not os.environ.get("ANTHROPIC_API_KEY"):
        add(False, "secrets",
            "no Anthropic API key reached this run (vault unlocked? set one with: "
            "sudo agenti setup, sudo agenti <agent> set-key or sudo agenti admin set-user-key <user>)")
        return
    found = next((p for p in SECRETS_CANDIDATES if p.exists()), None)
    if found is None:
        add(True, "secrets", "API key present (from the organisation, agent or user tier)")
        return
    SECRETS_FILE = found
    st = SECRETS_FILE.stat()
    mode = stat.S_IMODE(st.st_mode)

    if st.st_uid == os.getuid():
        tight = (mode & 0o077) == 0          # no group/other bits at all
        if tight:
            add(True, "secrets", f"{SECRETS_FILE} {oct(mode)} owner-only")
        else:
            add(False, "secrets",
                f"{SECRETS_FILE} mode {oct(mode)} uid {st.st_uid} — need owner-only 0600")
        return

    other_denied = (mode & 0o007) == 0
    group_read_only = (mode & 0o070) in (0o040, 0o000)
    root_owned = st.st_uid == 0
    in_group = st.st_gid in (*os.getgroups(), os.getgid())
    if root_owned and other_denied and group_read_only and in_group:
        add(True, "secrets", f"API key present; {SECRETS_FILE} {oct(mode)} root-owned, group-readable")
    else:
        add(False, "secrets",
            f"{SECRETS_FILE} mode {oct(mode)} uid {st.st_uid} gid {st.st_gid} — "
            f"expected root-owned 0640 and this process a member of the owning group")


def check_claude_code() -> None:
    """Anthropic's Claude Code program, which agenti-runtime fetches at install
    instead of redistributing it (packaging/runtime/fetch-claude-code)."""
    import importlib.util
    spec = importlib.util.find_spec("claude_agent_sdk")
    if spec is None or not spec.origin:
        add(False, "claude-code", "the Claude Agent SDK is not installed — reinstall: sudo apt install --reinstall agenti-runtime")
        return
    exe = os.path.join(os.path.dirname(spec.origin), "_bundled", "claude")
    if os.path.isfile(exe) and os.access(exe, os.X_OK):
        add(True, "claude-code", "present")
    else:
        add(False, "claude-code", f"{exe} is missing (agenti-runtime fetches it at install) — "
                                  "fetch it: sudo /usr/lib/agenti-runtime/fetch-claude-code")


def check_scans() -> None:
    # A file-analysis agent saves its program output under analysis/, not scans/.
    target = DATA_ROOT / "analysis" if agent_scope_kind() == "files" else SCANS_DIR
    try:
        target.mkdir(parents=True, exist_ok=True)
        # A fresh name, created exclusively and never through a link: a fixed
        # name in a folder the run writes could be a link it planted.
        probe = target / f".preflight_write_test.{os.getpid()}.{secrets.token_hex(4)}"
        fd = os.open(probe, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        os.write(fd, b"ok")
        os.close(fd)
        probe.unlink()
        add(True, "scans-writable", str(target))
    except Exception as e:
        add(False, "scans-writable", f"{target}: {e}")


def _connect_api(relay: str) -> socket.socket:
    """A TCP connection to API_HOST:443 — direct, or through the run's relay
    (an IP-scoped run can reach nothing else; audit run 1, fix 1b)."""
    if not relay:
        return socket.create_connection((API_HOST, 443), timeout=8)
    hostport = relay.split("://", 1)[-1].rstrip("/")
    host, port = hostport.rsplit(":", 1)
    sock = socket.create_connection((host, int(port)), timeout=8)
    sock.sendall(f"CONNECT {API_HOST}:443 HTTP/1.1\r\nHost: {API_HOST}:443\r\n\r\n".encode())
    reply = b""
    while b"\r\n\r\n" not in reply and len(reply) < 4096:
        chunk = sock.recv(1024)
        if not chunk:
            break
        reply += chunk
    if not reply.startswith((b"HTTP/1.1 200", b"HTTP/1.0 200")):
        sock.close()
        status = reply.split(b"\r\n", 1)[0].decode(errors="replace")
        raise OSError(f"the relay at {hostport} refused: {status}")
    return sock


def check_egress() -> None:
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    relay = os.environ.get("AGENTI_RELAY", "")
    via = f" via the relay ({relay})" if relay else ""
    try:
        with _connect_api(relay) as raw:
            with ctx.wrap_socket(raw, server_hostname=API_HOST) as tls:
                tls.getpeercert()        # also validates the cert -> catches bad clock
        add(True, "api-egress", f"TLS to {API_HOST}:443{via} ok")
    except Exception as e:
        hint = ("  [start the relay: sudo systemctl start agenti-relay]" if relay else "")
        add(False, "api-egress", f"cannot reach {API_HOST}:443{via} ({e}){hint}")


def check_code_immutable() -> None:
    """The agent must not be able to modify its own code, its engagement or
    its approval.

    deploy.sh sets this up; preflight re-verifies it on EVERY run, because a
    stray chown/chmod between deploys would silently turn the scope boundary
    into a suggestion. Tested by attempting access, not by reading mode bits,
    so ACLs and group changes are caught too.

    MASTER_DIR (CLAUDE.md "Current plan" phase 2) is the agent's own code —
    ONE copy, shared by every user, root:agenti-shared and unwritable by
    any of them. Checking it here means code immutability is now proven
    once per agent — the same MASTER_DIR
    that fails this check for the service account fails it
    for every user, because it is the same directory.
    """
    if not MASTER_DIR.is_dir():
        add(False, "code-immutable", f"{MASTER_DIR} missing (vault unlocked? reinstall: sudo apt install --reinstall agenti)")
        return
    if os.access(MASTER_DIR, os.W_OK):
        add(False, "code-immutable",
            f"{MASTER_DIR} is WRITABLE by uid {os.getuid()} — the agent could rewrite "
            f"its own scope. Reset the permissions: sudo dpkg-reconfigure agenti")
        return
    if agent_scope_kind() == "files":
        # A file-analysis agent has no engagement or approval to protect, and
        # runs without one; its code is what must stay unwritable.
        add(True, "code-immutable", f"{MASTER_DIR} read-only to uid {os.getuid()} (file analysis: no engagement)")
        return
    # The file that DEFINES scope is the engagement record, and it
    # must exist and be unwritable by this account, as must the approval
    # record when there is one — an agent that could edit approval.json
    # could approve its own engagement.
    to_check = [ORG_DIR / "engagement.json"]
    if (ORG_DIR / "approval.json").exists():
        to_check.append(ORG_DIR / "approval.json")
    for cfg in to_check:
        if not cfg.exists():
            add(False, "code-immutable",
                f"{cfg} missing — there is no engagement yet; an admin sets one with: "
                f"sudo agenti engagement set ...")
            return
        if os.access(cfg, os.W_OK):
            add(False, "code-immutable", f"{cfg} is WRITABLE — scope or approval could be altered at runtime")
            return
    add(True, "code-immutable",
        f"{MASTER_DIR} and {', '.join(p.name for p in to_check)} read-only to uid {os.getuid()}")


# Per-agent binary checklist — kept in lockstep with the AGENT case in
# deploy.sh's verify(). A fixed list applied to every agent would report on
# tools an agent will never call (e.g. requiring nmap before trafficmon can
# start, while never checking for tcpdump) — a check like that is worse than
# no check, because it looks like assurance while missing what matters.
AGENT_TOOLS: dict[str, tuple[str | None, list[str]]] = {
    "enum": ("nmap", ["nikto", "gobuster", "dig", "whatweb", "enum4linux-ng",
                       "rpcclient", "smbclient", "netexec", "ping"]),
    # zeek is deliberately NOT listed, though trafficmon still calls it when
    # present (run_zeek() checks shutil.which and degrades to tshark-derived
    # records). Kali Rolling lists zeek 5.1.1-0kali3 for arm64, but the package
    # pins libc6 (<< 2.38) against this box's libc6 2.43 and is therefore
    # UNINSTALLABLE — `apt-get -s install zeek` reaches conflicting
    # assignments. Warning on every run about a tool that cannot be installed
    # trains an operator to ignore preflight, which costs more than the missing
    # check is worth. Re-add it the day the package is installable again.
    "trafficmon": ("tcpdump", ["tshark", "dumpcap", "suricata"]),
    # None core, empty optional: genuinely zero external binaries (pure
    # Python http.client/html.parser), not "nobody's declared this agent
    # yet" — see the AGENT_TOOLS.get(...) is None branch below for that case.
    "research": (None, []),
}


def _manifest_tools() -> tuple[str | None, list[str]] | None:
    """A recon agent built in Settings -> Agents lists its programs in its
    manifest.json (beside its code in the master copy). None of them is
    required — run_scan answers a clean "not installed" for a missing one —
    so all are reported as optional."""
    try:
        data = json.loads((MASTER_DIR / "manifest.json").read_text(encoding="utf-8"))
        names = [p["name"] for p in data.get("programs", []) if isinstance(p, dict) and p.get("name")]
    except (OSError, ValueError, KeyError, TypeError):
        return None
    return (None, names) if names else None


def check_sandbox() -> None:
    """A file-analysis agent runs every program inside bubblewrap, with a
    syscall filter. If the sandbox cannot start here, the agent would be
    refused at its first analysis; say so before the run spends anything.
    Nothing else needs it.

    This runs the REAL sandbox (shared/sandbox.py), not a hand-built bubblewrap
    command: a probe that differs from what a run does can pass while a run
    fails, and the filter is part of what must start."""
    if agent_scope_kind() != "files":
        return
    import sandbox
    try:
        probe = sandbox.run(["/usr/bin/true"], "light")
    except sandbox.SandboxUnavailable as e:
        add(False, "sandbox", f"{e}")
        return
    if probe.ok:
        add(True, "sandbox", "bubblewrap can create the analysis sandbox, with its syscall filter")
    else:
        add(False, "sandbox", f"bubblewrap cannot start under this unit ({probe.stderr.strip()[:200] or probe.exit_code}) — "
            f"the unit needs CAP_SYS_ADMIN in its bounding set; re-render it: sudo dpkg-reconfigure agenti")


def check_tools() -> None:
    """Allow-listed binaries must exist, or the agent burns turns (and tokens)
    rediscovering that they don't."""
    entry = AGENT_TOOLS.get(AGENT_NAME) or _manifest_tools()
    if entry is None:
        add(True, "tools", f"no binary checklist defined for agent '{AGENT_NAME}' — unchecked")
        return
    core, optional = entry
    if core is None and not optional:
        add(True, "tools", "no external binaries required (pure Python)")
        return
    import tool_catalog       # finds a program under its distribution name too
    missing_req = [] if (core is None or tool_catalog.which_program(core)) else [core]
    missing_opt = [b for b in optional if tool_catalog.which_program(b) is None]
    if missing_req:
        add(False, "tools", f"missing required: {', '.join(missing_req)}")
    elif missing_opt:
        add(True, "tools", f"{core} present; optional missing: {', '.join(missing_opt)}")
    else:
        add(True, "tools", "all allow-listed binaries present")


def check_tool_settings() -> None:
    """An agent whose program list an admin may change must be able to apply
    those changes; anything unreadable stops the start (operator decision
    2026-10-21). The run reads them the same way (tool_settings_store.
    settings_for_run); checking here puts the reason on a FAIL line."""
    import tool_catalog as tc
    import tool_settings_store as tss
    if not tss.has_enforced_list(SHARED_DIR, AGENT_NAME):
        return
    try:
        base, _purposes = tss.baseline(SHARED_DIR, AGENT_NAME)
        _catalog, settings = tss.settings_for_run(ORG_DIR, SHARED_DIR, AGENT_NAME, base)
    except (tc.CatalogError, tss.StoreError) as e:
        add(False, "tool-settings", f"{e}\n       An admin can fix it: save {AGENT_NAME}'s program list "
            f"again (Settings → Agents → {AGENT_NAME} → Tool allow-list, or sudo agenti {AGENT_NAME} "
            f"tool-settings set ...); if the catalog is missing: sudo apt install --reinstall agenti")
        return
    words = {"enable": "added", "disable": "removed", "approvable": "offered for approval"}
    changed = [f"{len(settings[k])} {w}" for k, w in words.items() if settings.get(k)]
    add(True, "tool-settings", f"the admin's program changes apply ({', '.join(changed) or 'none made'})")


_SCOPE_KIND_LABELS = {"CIDRScope": "cidr", "DomainScope": "domain", "FilesScope": "files"}


def agent_scope_kind() -> str | None:
    """This agent's scope kind, from the root-owned capabilities.json
    deploy.sh writes beside its MASTER copy (§4 item 26; phase 2: 
    independent, like the code it describes) — the same descriptor the
    CLI's `tools` verb and `engagement-set` already read, never re-derived
    a second way. None when it cannot be determined; the engagement check
    then validates the whole record rather than one kind's view, and says
    so, instead of guessing."""
    try:
        data = json.loads((MASTER_DIR / "capabilities.json").read_text())
        return _SCOPE_KIND_LABELS.get(str(data.get("scope_kind") or ""))
    except (OSError, json.JSONDecodeError, AttributeError):
        return None


def _engagement_module():
    """engagement_context lives in the shared harness now (CLAUDE.md
    "Current plan" phase 2 — the code folder, installed ONCE), the same
    directory this very file is deployed into, so it is importable without
    any sys.path change: Python already puts a script's own directory at
    sys.path[0]. Imported lazily so a missing/broken copy is a reported
    check failure, not a crash before any check runs."""
    import engagement_context
    return engagement_context


def check_engagement() -> None:
    if agent_scope_kind() == "files":
        add(True, "engagement", "not applicable: a file-analysis agent touches no network or client asset")
        return
    try:
        ec = _engagement_module()
    except Exception as e:
        add(False, "engagement", f"cannot import engagement_context: {e}")
        return
    kind = agent_scope_kind()
    try:
        if kind:
            eng = ec.load_engagement(kind, org_dir=ORG_DIR, agent=AGENT_NAME)
            note = f"{len(eng.in_scope)} {kind} scope entries"
        else:
            # Scope kind unknown (no capabilities.json yet): validate the record
            # as a whole and check the window on whichever kind has entries.
            # The harness will still refuse if ITS kind turns out empty.
            path = ec.engagement_path(org_dir=ORG_DIR)
            record = ec.read_record(path)
            populated = [k for k in ec.SCOPE_KINDS if record["scope"][k]["in_scope"]]
            eng = ec.engagement_from_record(record, populated[0])
            note = (f"scope kind of this agent unknown (no capabilities.json) — record valid, "
                    f"entries for: {', '.join(populated)}")
        ec.assert_in_window(eng)
    except ec.EngagementError as e:
        add(False, "engagement", str(e))
        return
    except Exception as e:
        add(False, "engagement", str(e))
        return
    add(True, "engagement",
        f"{eng.engagement_id} in window {eng.valid_from}..{eng.valid_until}, {note}")


def check_approval() -> None:
    """Admin approval gate (CLAUDE.md §3g), bound to CONTENT since phase 1
    of the cybersecurity refocus: `org/approval.json` records the
    digest of the engagement an admin approved, and this check passes only
    while the engagement still has that digest. Editing a scope entry,
    a date or the notes after approval therefore fails the next start until
    an admin approves again — the property that makes approval mean
    something. Whether this gate applies AT ALL is itself a per-organisation
    policy field now (CLAUDE.md "Current plan": the retired --dev profile's
    exemption became `policy.require_approval`, read directly off the SAME
    record this check already has open — no separate profile hint to
    re-derive). Defaults to required; it may be turned off as its own
    operational choice. Root-enforced like every other check here:
    approval.json is written only by `agenti engagement approve`,
    a root-gated verb, so the agent cannot approve itself.

    Segregation of duties (the approver being a DIFFERENT person than the
    author) is enforced by the CLI's `require-separate-approver` policy at
    start time, not here — preflight runs as the service account
    and cannot read iam.db.
    """
    if agent_scope_kind() == "files":
        add(True, "approval", "not applicable: no engagement scope to approve")
        return
    try:
        ec = _engagement_module()
        record = ec.read_record(ORG_DIR / ec.ORG_ENGAGEMENT_FILENAME)
    except Exception:
        add(True, "approval", "engagement failed to load — reported by the engagement check instead")
        return
    policy = ec.resolve_policy(record)
    if not policy["require_approval"]:
        add(True, "approval", "not required — the organisation's policy has it off")
        return
    status = ec.approval_status(record, ec.read_approval(ORG_DIR / ec.APPROVAL_FILENAME))
    if status["current"]:
        add(True, "approval", f"'{record['engagement_id']}' {status['reason']}")
        return
    add(False, "approval",
        f"'{record['engagement_id']}' is not approved as it stands: {status['reason']}. "
        f"An admin must run:\n"
        f"       sudo agenti engagement approve")


def main() -> int:
    for fn in (check_clock, check_encrypted, check_code_immutable,
               check_secrets, check_claude_code, check_scans, check_sandbox, check_tools, check_tool_settings,
               check_egress, check_engagement, check_approval):
        try:
            fn()
        except Exception as e:                       # a check itself blowing up = fail
            add(False, fn.__name__, f"raised: {e}")

    print("preflight checks:")
    for ok, label, detail in results:
        print(f"  [{'PASS' if ok else 'FAIL'}] {label}: {detail}")

    failed = [r for r in results if not r[0]]
    if failed:
        print(f"\npreflight FAILED ({len(failed)} check(s)); "
              f"harness will NOT start.", file=sys.stderr)
        return 1
    print("\npreflight OK; starting harness.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
