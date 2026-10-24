#!/usr/bin/env python3
"""
trafficmon-agent.py — windowed passive traffic assessment.

SHAPE: capture for a bounded window, reduce locally, THEN reason. The model is
never in the packet path. By the time the agent loop starts, capture is already
finished and what exists on disk is a set of structured records — connection
logs, DNS/HTTP/TLS metadata, IDS alerts. The agent reads those.

That ordering is deliberate and load-bearing:
  * Cost. A quiet LAN is thousands of packets a second. Reduction happens in
    Zeek/Suricata/tshark, which cost nothing per run.
  * Termination. Capture is bounded by a wall clock before the model is
    consulted, so the expensive phase cannot run away.
  * Payload exposure. Packet bytes never enter context. The agent sees records
    ABOUT traffic, not traffic.

FOUR BOUNDARIES, each enforced somewhere the agent cannot reach:
  1. BPF filter      — compiled from the engagement scope, applied by the
                       kernel. Out-of-scope traffic is never written to disk.
  2. Snaplen         — when the engagement forbids payload capture, the capture
                       is truncated to headers. Not a policy, a byte limit.
  3. Tool allow-list — a PreToolUse hook; the agent's entire surface is the
                       three tools below.
  4. Backstops       — turns, spend, wall clock.

Auth:     ANTHROPIC_API_KEY, or secrets.env (agent's own key wins over shared).
Run:      sudo agenti trafficmon start -t <ip-or-cidr>
Dev:      python3 trafficmon-agent.py --dev

ON THE SHARED HARNESS: profile loading, secrets, run-target/run-config
parsing, the SIGTERM handler, audit setup and the report skeleton now live in
shared/agent_runtime.py; the CIDR narrowing rule lives in shared/scope_cidr.py.
This agent was the first migrated onto both (CLAUDE.md §3f) — enum-agent.py
still carries its own copy of the same logic until it migrates too.
"""

import argparse
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

from engagement_context import (build_system_prompt, assert_in_window,
                                load_engagement, EngagementError)
import agent_runtime
import paths
import session_runner
from agent_contract import AgentContract
from scope_cidr import CIDRScope

# ---------------------------------------------------------------------------
# 0. RUN PROFILE
# ---------------------------------------------------------------------------
# The profile's caps/model change WHERE capture may happen and HOW MUCH may
# be spent, resolved fresh per run against the organisation's policy. They
# never change WHAT is permitted: the BPF scope filter, the snaplen rule,
# the tool allow-list and the target validator are fixed in code.

SCOPE = CIDRScope(agent_name="trafficmon")

# The external programs this agent's capture pipeline invokes, for the
# operator-facing "Tools & permissions" panel (shared/gen_capabilities.py).
# trafficmon has no ALLOWED_BINARIES set — the model never composes a command;
# these fixed tools are driven by the agent's own code, on a BPF-scoped
# capture. Passive only: no injection, no ARP spoofing. zeek is listed as
# optional because it degrades to tshark-derived records when not installed
# (see run_zeek / trafficmon.deps).
EXTERNAL_TOOLS = [
    ("tcpdump", "captures a short, BPF-scoped window to a pcap on the mirror interface"),
    ("tshark", "decodes the captured pcap into per-protocol summaries"),
    ("suricata", "runs IDS signatures over the captured pcap"),
    ("zeek (optional)", "connection/protocol logging when installed; degrades to tshark otherwise"),
]


@dataclass(frozen=True)
class Profile(agent_runtime.Profile):
    window_s: int           # how long to capture before reasoning starts


AGENTI_ROOT = paths.data_root()
# Everything lives under the one organisation directory.
ORG_DIR = AGENTI_ROOT / "org"
AGENT_NAME = "trafficmon"
AGENT_TITLE = "Traffic monitor"              # shown in the GUI
AGENT_DESCRIPTION = "Passively captures and summarizes network traffic for in-scope hosts."
# AGENTI_INSTANCE, when set, is the authoritative absolute path for this
# run's own instance directory — for the default (single) instance it is
# always identical to ORG_DIR/AGENT_NAME (the unit sets it to
# exactly that), so reading it here changes nothing for existing runs. A
# NAMED instance's unit (CLAUDE.md "Current plan" — concurrent same-type
# instances) points it at a nested .../instances/<label>/ directory
# instead, which is what makes a second concurrent enum against a
# different target fully isolated from the first without this agent's
# own code needing to know instances exist at all.
AGENT_DIR = Path(os.environ["AGENTI_INSTANCE"]) if os.environ.get("AGENTI_INSTANCE") \
    else ORG_DIR / AGENT_NAME
SHARED_DIR = AGENTI_ROOT / "shared"


# Placeholder numbers for the ceiling-governed fields — agent_runtime.
# load_run_config() ALWAYS overwrites max_turns/max_budget_usd/timeout_s/
# model before a run starts, resolved against the organisation's policy
# (CLAUDE.md "Current plan"). window_s is NOT part of that ceiling system
# (it is a capture-length knob, not a cost cap — see
# agent_runtime._OTHER_NUMERIC_OVERRIDES) so it keeps a REAL default here,
# narrowable via --window same as before. model=None is never actually used
# to run anything: --model is mandatory at launch, checked there. Still a
# one-entry dict (not a bare Profile) so AgentContract's own "profiles must
# be non-empty" invariant is unchanged by retiring the second profile.
PROFILES: dict[str, Profile] = {
    "run": Profile(
        name="run",
        model=None,
        max_turns=0,
        max_budget_usd=0.0,
        timeout_s=0,
        window_s=300,                 # 5 minutes of capture by default
        data_root=AGENT_DIR,
    ),
}


# ---------------------------------------------------------------------------
# 1. SCOPE + STATE
# ---------------------------------------------------------------------------
ALLOWED_NETWORKS: list = []      # populated by configure() — empty means fail closed
ENGAGEMENT = None
PROFILE: Profile | None = None

# Evidence lands in scans/ so the existing tree and CLI work unchanged:
# `agenti trafficmon scans` lists it, export/purge cover it, and deploy.sh
# already creates it with the right ownership.
EVIDENCE_DIR: Path | None = None
CAPTURE_IFACE = os.environ.get("TRAFFICMON_IFACE", "")

MAX_RETURN_BYTES = 8000
TRIM_BYTES = 8000
MAX_FOLLOWUP_S = 120             # ceiling on any single capture_host call

# Everything the agent did this run, in order. The denials are the
# audit-valuable part: they show the boundary actually holding.
ACTIONS: list[dict] = []
MANIFEST: dict = {}              # what collection produced
FILTER_ERRORS: list[str] = []    # detectors that failed to RUN, vs found nothing

LOG = logging.getLogger("trafficmon")


# ---------------------------------------------------------------------------
# 2. THE BPF SCOPE FILTER
#
# This is the strongest boundary in the agent, and it is worth being precise
# about why: the enum agent validates a command in Python before running it,
# but here the filter is compiled into the kernel's packet filter. Traffic from
# an out-of-scope host is not "rejected after inspection" — it is never copied
# to userspace, never written, never seen. On a mirrored/SPAN port, where the
# Pi can physically observe an entire segment, this is what keeps a
# single-host engagement from becoming a whole-network capture.
# ---------------------------------------------------------------------------
def _bpf_from_scope(nets: list, exclude: str = "") -> str:
    """Compile an engagement scope into a tcpdump/libpcap filter expression."""
    if not nets:
        raise ValueError("refusing to build a filter from an empty scope")
    terms = []
    for n in nets:
        if n.num_addresses == 1:
            terms.append(f"host {n.network_address}")
        else:
            terms.append(f"net {n.with_prefixlen}")
    expr = "(" + " or ".join(terms) + ")"
    if exclude:
        expr += f" and not ({exclude})"
    return expr


def _default_iface() -> str:
    """The interface carrying the default route.

    Auto-detected rather than configured, because the common mistake is
    capturing on the wrong NIC and concluding the agent is broken when it
    simply saw nothing. Override with TRAFFICMON_IFACE when the capture
    interface is deliberately not the routed one (a tap or SPAN port).
    """
    if CAPTURE_IFACE:
        return CAPTURE_IFACE
    try:
        out = subprocess.run(["ip", "-o", "route", "get", "1.1.1.1"],
                             capture_output=True, text=True, timeout=5).stdout
        m = re.search(r"\bdev\s+(\S+)", out)
        if m:
            return m.group(1)
    except Exception:
        pass
    return "eth0"


def _iface_addr(iface: str) -> str | None:
    """This host's own IPv4 on the capture interface, for the SSH exclusion."""
    try:
        out = subprocess.run(["ip", "-4", "-o", "addr", "show", "dev", iface],
                             capture_output=True, text=True, timeout=5).stdout
        m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)", out)
        return m.group(1) if m else None
    except Exception:
        return None


def _management_exclusion(iface: str) -> str:
    """Keep the operator's own SSH session out of the capture.

    Not a security control — it is noise reduction plus basic hygiene. Your
    management session is not part of the engagement, and capturing it means
    your own keystrokes end up in a client evidence file. Returns "" when the
    address cannot be determined, which fails toward capturing more rather than
    silently building a filter that drops real traffic.
    """
    addr = _iface_addr(iface)
    return f"tcp port 22 and host {addr}" if addr else ""


def _snaplen() -> int:
    """Bytes captured per packet — the payload boundary, enforced in bytes.

    When the engagement forbids payload capture we truncate at 512 bytes. That
    keeps link/IP/TCP headers plus the early protocol fields Zeek needs (DNS
    names, HTTP Host, TLS SNI) while discarding message bodies.

    Honest limitation: 512 bytes is a large reduction, not a guarantee. Basic
    auth headers and plaintext protocol handshakes can sit inside it. The real
    protections are that raw pcap never enters model context and is deleted per
    the engagement's retention setting.
    """
    if ENGAGEMENT is not None and getattr(ENGAGEMENT, "capture_payloads", False):
        return 0            # 0 = full packet
    return 512


# ---------------------------------------------------------------------------
# 3. COLLECTION  (runs BEFORE the model — no agent involvement)
# ---------------------------------------------------------------------------
def _run_split(cmd: list[str], timeout: int) -> tuple[int, str, str]:
    """Run a command, keeping stdout and stderr SEPARATE.

    The separation is not cosmetic. Evidence files are built from stdout, and
    tshark writes diagnostics to stderr — Kali's build emits a harmless
    'Couldn't load plugin falco-events.so' warning on every single invocation.
    Folded together, that warning was appended to the bottom of every extracted
    log: noise inside the evidence, counted against the agent's truncation
    budget, and shipped in a client deliverable.
    """
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout or "", p.stderr or ""
    except subprocess.TimeoutExpired:
        return 124, "", "timed out"
    except FileNotFoundError:
        return 127, "", "not installed"


def _run(cmd: list[str], timeout: int) -> tuple[int, str]:
    """Combined output, for callers that only want a diagnostic string."""
    rc, out, err = _run_split(cmd, timeout)
    return rc, out + err


# An empty pcap still contains a 24-byte global header, so "zero packets" is a
# small file rather than a missing one. Anything at or under this is empty.
_EMPTY_PCAP_BYTES = 32


def capture_window(bpf: str, iface: str, seconds: int, out: Path) -> tuple[bool, str]:
    """Capture to a pcap for a bounded window. The scope filter is applied here.

    WHY `timeout --signal=INT` RATHER THAN tcpdump's OWN -G/-W ROTATION:
    tcpdump evaluates its rotation deadline only when a packet arrives. On a
    filter that matches nothing it blocks in the capture loop indefinitely and
    never notices the window has elapsed — so a quiet window hung until an outer
    SIGKILL, which also discarded whatever had been buffered. Both failure modes
    then looked identical to "no packets", which made a hang indistinguishable
    from a correct empty result.

    timeout(1) owns the clock instead, and SIGINT is the signal tcpdump handles
    cleanly: it flushes its buffer and writes a valid file on the way out. -U
    makes each packet hit the file as it is captured, so nothing depends on a
    graceful exit at all.
    """
    snap = _snaplen()
    cmd = ["timeout", "--signal=INT", str(seconds),
           "tcpdump", "-i", iface, "-n", "-U", "-w", str(out),
           "-s", str(snap), bpf]
    LOG.info("CAPTURE | iface=%s window=%ds snaplen=%s | %s", iface, seconds,
             snap or "full", bpf)
    rc, out_text = _run(cmd, timeout=seconds + 30)

    size = out.stat().st_size if out.exists() else 0
    detail = out_text.strip()[:200]

    # 124 is timeout(1) reporting that the window elapsed — the NORMAL path.
    # Anything else means tcpdump stopped early and the reason matters.
    if rc not in (0, 124):
        if rc == 127:
            return False, "tcpdump is not installed"
        return False, (f"tcpdump exited early (rc={rc}): {detail or 'no output'}. "
                       f"A permission error here usually means the run is not "
                       f"getting CAP_NET_RAW from its agenti-instance@ unit.")

    if size <= _EMPTY_PCAP_BYTES:
        # Distinguish this clearly from a failure: the capture worked, the
        # filter simply matched nothing. That is a real and common result.
        out.unlink(missing_ok=True)
        return False, (f"the {seconds}s window elapsed with zero packets matching "
                       f"the scope filter")
    return True, f"{size} bytes"


def run_zeek(pcap: Path, workdir: Path) -> list[Path]:
    """Zeek over the pcap — the primary evidence source.

    Produces conn/dns/http/ssl/notice logs: structured records describing
    traffic rather than the traffic itself. This is why payloads do not need to
    reach the model to produce useful findings.
    """
    if shutil.which("zeek") is None:
        return []
    workdir.mkdir(parents=True, exist_ok=True)
    rc, out = _run(["zeek", "-C", "-r", str(pcap), "LogAscii::use_json=F"], timeout=600)
    logs = sorted(workdir.glob("*.log"))
    LOG.info("ZEEK | rc=%s | %d log(s)", rc, len(logs))
    return logs


def run_suricata(pcap: Path, workdir: Path) -> list[Path]:
    """Suricata over the pcap — signature-based alerts, complementary to Zeek."""
    if shutil.which("suricata") is None:
        return []
    workdir.mkdir(parents=True, exist_ok=True)
    rc, out = _run(["suricata", "-r", str(pcap), "-l", str(workdir)], timeout=600)
    logs = [p for p in (workdir / "eve.json", workdir / "fast.log") if p.exists()]
    LOG.info("SURICATA | rc=%s | %d log(s)", rc, len(logs))
    return logs


def tshark_evidence(pcap: Path, base: Path) -> list[Path]:
    """Derive Zeek-shaped metadata logs using tshark.

    Zeek is the better tool, but its Kali package is currently pinned to an
    older libc and will not install on a current rolling image, so on this box
    tshark is the PRIMARY source rather than a fallback. These extractions
    reproduce the Zeek logs that actually carry the findings: connection
    records, DNS questions, HTTP request metadata, TLS server names.

    THE IMPORTANT DESIGN RULE IS WHAT IS *NOT* EXTRACTED. Every field list here
    is metadata — addresses, ports, names, protocol identifiers. None of them
    pull message bodies or credential arguments. The cleartext detector records
    that an unencrypted auth protocol was SEEN and where, never the username or
    password it carried. That matters because whatever lands in these files is
    what the model reads: excluding the value here is a stronger guarantee than
    asking the model not to repeat it.
    """
    if shutil.which("tshark") is None:
        return []
    base.mkdir(parents=True, exist_ok=True)
    produced: list[Path] = []

    def extract(name: str, args: list[str], header: str) -> None:
        """Run one extraction, distinguishing 'no matches' from 'filter broken'.

        These are completely different outcomes and used to be indistinguishable:
        both produced no file. So a display filter with a syntax error looked
        exactly like a clean window, and the absence of cleartext.log could mean
        either "no cleartext auth occurred" — a finding — or "the detector never
        ran" — a silent hole in the assessment. A detector that can fail
        invisibly is worse than no detector, because its silence gets trusted.
        """
        rc, out, err = _run_split(["tshark", "-r", str(pcap), "-n"] + args,
                                  timeout=300)
        body = out.strip()
        if rc not in (0, 2):
            LOG.error("TSHARK | %s FAILED (rc=%s) — this detector did NOT run: %s",
                      name, rc, err.strip()[:300] or "(no stderr)")
            FILTER_ERRORS.append(f"{name}: {err.strip()[:200] or f'rc={rc}'}")
            return
        if err.strip():
            # Non-fatal chatter (Kali's falco plugin warning, for one). Worth a
            # journal line so it is not invisible, but it stays OUT of the file.
            LOG.debug("TSHARK | %s stderr: %s", name, err.strip()[:200])
        if not body:
            LOG.info("TSHARK | %s — no matches (detector ran, found nothing)", name)
            return
        out = base / name
        out.write_text(header + "\n" + body + "\n")
        produced.append(out)

    F = ["-T", "fields", "-E", "separator=/t"]

    # Connection records. FLOW-SHAPED, not per-packet: the display filter keeps
    # only handshake and teardown frames (SYN / SYN-ACK / FIN / RST) plus UDP and
    # ICMP. A per-packet log of a single nmap scan came to 8.5 MB and truncated
    # on every read, which cost the agent turns and told it nothing extra — the
    # interesting facts are who talked to whom and whether the port answered,
    # and those live entirely in the handshake. This is also what makes the log
    # comparable to Zeek's conn.log rather than a packet dump.
    extract("conn.log",
            ["-Y", "tcp.flags.syn == 1 || tcp.flags.fin == 1 || "
                   "tcp.flags.reset == 1 || udp || icmp", *F,
             "-e", "frame.number", "-e", "frame.time_relative",
             "-e", "ip.src", "-e", "tcp.srcport", "-e", "udp.srcport",
             "-e", "ip.dst", "-e", "tcp.dstport", "-e", "udp.dstport",
             "-e", "_ws.col.Protocol", "-e", "frame.len"],
            "#frame\ttime\tsrc\tsport_tcp\tsport_udp\tdst\tdport_tcp\tdport_udp\tproto\tbytes")

    # DNS questions and answers — names, not payloads.
    extract("dns.log",
            ["-Y", "dns", *F,
             "-e", "frame.number", "-e", "ip.src", "-e", "ip.dst",
             "-e", "dns.qry.name", "-e", "dns.a", "-e", "dns.flags.rcode"],
            "#frame\tsrc\tdst\tquery\tanswer\trcode")

    # HTTP request metadata. Host/URI/User-Agent are how you identify a service;
    # bodies and Authorization values are deliberately absent.
    extract("http.log",
            ["-Y", "http.request", *F,
             "-e", "frame.number", "-e", "ip.src", "-e", "ip.dst",
             "-e", "http.host", "-e", "http.request.method",
             "-e", "http.request.uri", "-e", "http.user_agent"],
            "#frame\tsrc\tdst\thost\tmethod\turi\tuser_agent")

    # TLS ClientHello/ServerHello — SNI and negotiated version, which is what
    # weak-crypto findings are actually built from.
    # TLS handshakes. The `hs_type` column is the whole point: 1 = ClientHello,
    # 2 = ServerHello. Without it the two are indistinguishable in the log, and
    # a scanner probing with a deliberately ancient version looks identical to a
    # server agreeing to one. That distinction is the difference between "the
    # tool asked" and "the host said yes" — i.e. between no finding and a real
    # one. Only hs_type 2 is evidence about the server's configuration.
    extract("tls.log",
            ["-Y", "tls.handshake.type == 1 || tls.handshake.type == 2", *F,
             "-e", "frame.number", "-e", "tls.handshake.type",
             "-e", "ip.src", "-e", "ip.dst",
             "-e", "tls.handshake.extensions_server_name",
             "-e", "tls.handshake.version", "-e", "tls.handshake.ciphersuite"],
            "#frame\ths_type\tsrc\tdst\tserver_name\tversion\tciphersuite  "
            "(hs_type 1=ClientHello=OFFERED by client; 2=ServerHello=AGREED by server. "
            "Only hs_type 2 is evidence about the server.)")

    # Cleartext auth SIGHTINGS. Protocol and endpoints only — no argument
    # fields, so the credential itself never reaches disk or context. The agent
    # reports "cleartext FTP auth at frame N between A and B", which is the
    # finding; the value adds nothing and is a liability in a client report.
    # Filter by field PRESENCE, not by value. `in {USER PASS}` and a bare
    # `== AUTH` are both syntax whose acceptance varies across Wireshark
    # releases, and a rejected filter takes the whole detector down. Asking
    # "does this frame carry an FTP command at all" is stable everywhere, and
    # broader too: the finding is that an unencrypted session existed, not
    # merely that it contained a login.
    #
    # ftp.request.command is extracted as a FIELD (USER, PASS, LIST...) because
    # the command NAME is metadata. The credential lives in ftp.request.arg,
    # which is deliberately absent from this list and every other list here.
    extract("cleartext.log",
            ["-Y", "ftp.request.command || ftp.response.code || telnet || "
                   "http.authorization || pop.request.command || "
                   "imap.request || smtp.req.command", *F,
             "-e", "frame.number", "-e", "frame.time_relative",
             "-e", "ip.src", "-e", "tcp.srcport",
             "-e", "ip.dst", "-e", "tcp.dstport", "-e", "_ws.col.Protocol",
             "-e", "ftp.request.command", "-e", "pop.request.command",
             "-e", "smtp.req.command"],
            "#frame\ttime\tsrc\tsport\tdst\tdport\tproto\tftp_cmd\tpop_cmd\tsmtp_cmd  "
            "(SIGHTING ONLY — command NAMES only; argument values, i.e. the "
            "credentials themselves, are deliberately never extracted)")

    # Protocol hierarchy and conversation tables: cheap aggregates that let the
    # agent orient in one read instead of grepping conn.log repeatedly.
    # Protocol hierarchy + IP endpoints only. The per-conversation tables ran to
    # 9 MB on a scan window because every probed port is its own conversation;
    # the agent could never read one without truncating. Port-level detail is
    # already in conn.log, where it can be grepped.
    rc, sout, serr = _run_split(["tshark", "-r", str(pcap), "-n", "-q",
                                 "-z", "io,phs", "-z", "endpoints,ip"], timeout=300)
    if sout.strip():
        outp = base / "summary.txt"
        outp.write_text(sout)
        produced.append(outp)

    LOG.info("TSHARK | %d evidence file(s)", len(produced))
    return produced


def collect_evidence(profile: Profile, bpf: str, iface: str) -> dict:
    """Run the whole local pipeline and return a manifest.

    Everything here is deterministic and costs nothing per run. The agent has
    not started yet and cannot influence any of it.
    """
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    base = EVIDENCE_DIR / f"window-{stamp}"
    base.mkdir(parents=True, exist_ok=True)
    pcap = base / "capture.pcap"

    started = time.time()
    seconds = _seconds_left_in_engagement(profile.window_s)
    if seconds <= 0:
        return {"window_started": stamp, "window_seconds": 0, "interface": iface, "bpf": bpf,
                "capture_ok": False, "sources": {}, "files": [],
                "capture_detail": "the engagement's authorized window is over, so nothing was captured"}
    try:
        return _collect(profile, bpf, iface, stamp, base, pcap, started, seconds)
    finally:
        # Whatever ends the capture (a stop included), packet bytes are not
        # kept when the engagement does not permit payload capture.
        if pcap.exists() and (ENGAGEMENT is None or not getattr(ENGAGEMENT, "capture_payloads", False)):
            pcap.unlink(missing_ok=True)


def _seconds_left_in_engagement(window_s: int) -> int:
    """The capture window, cut to the end of the engagement's last day (UTC):
    a long window must not run past the authorization (audit run 2)."""
    if ENGAGEMENT is None:
        return window_s
    end = datetime.fromisoformat(ENGAGEMENT.valid_until).replace(tzinfo=timezone.utc) + timedelta(days=1)
    left = int((end - datetime.now(timezone.utc)).total_seconds())
    return max(0, min(window_s, left))


def _collect(profile, bpf, iface, stamp, base, pcap, started, seconds) -> dict:
    ok, detail = capture_window(bpf, iface, seconds, pcap)
    manifest = {
        "window_started": stamp,
        "window_seconds": seconds,
        "interface": iface,
        "bpf": bpf,
        "snaplen": _snaplen() or "full",
        "capture_ok": ok,
        "capture_detail": detail,
        "sources": {},
        "files": [],
    }
    if not ok:
        LOG.warning("CAPTURE | %s", detail)
        pcap.unlink(missing_ok=True)     # no stub files from failed windows
        return manifest

    for name, logs in (("zeek", run_zeek(pcap, base / "zeek")),
                       ("suricata", run_suricata(pcap, base / "suricata"))):
        if logs:
            manifest["sources"][name] = [str(p.relative_to(EVIDENCE_DIR)) for p in logs]

    tsl = tshark_evidence(pcap, base / "tshark")
    if tsl:
        manifest["sources"]["tshark"] = [str(p.relative_to(EVIDENCE_DIR)) for p in tsl]

    if FILTER_ERRORS:
        manifest["filter_errors"] = list(FILTER_ERRORS)
    if not manifest["sources"]:
        LOG.warning("COLLECT | capture succeeded but no analyser produced output")

    # Retention: the pcap is the only artifact holding packet bytes. When the
    # engagement forbids payload capture there is no reason to keep it once the
    # analysers have run, and the derived logs are what the agent reads anyway.
    if ENGAGEMENT is not None and not getattr(ENGAGEMENT, "capture_payloads", False):
        try:
            pcap.unlink()
            manifest["pcap"] = "deleted after analysis (payload capture not permitted)"
            LOG.info("RETENTION | pcap deleted — payload capture not permitted")
        except OSError as e:
            LOG.warning("RETENTION | could not delete pcap: %s", e)
    else:
        manifest["pcap"] = str(pcap.relative_to(EVIDENCE_DIR))

    for p in sorted(base.rglob("*")):
        if p.is_file():
            manifest["files"].append({
                "path": str(p.relative_to(EVIDENCE_DIR)),
                "bytes": p.stat().st_size,
                "lines": _count_lines(p),
            })
    manifest["collect_seconds"] = round(time.time() - started, 1)
    (base / "manifest.json").write_text(json.dumps(manifest, indent=2))
    return manifest


def _count_lines(p: Path) -> int | None:
    try:
        if p.suffix == ".pcap":
            return None
        with p.open("rb") as f:
            return sum(1 for _ in f)
    except OSError:
        return None


# ---------------------------------------------------------------------------
# 4. TOOLS — list_evidence / read_evidence / capture_host now live in
# shared/tool_registry.py (CLAUDE.md "Current plan", phase 2). Built below
# from TOOL_CTX plus the trafficmon-specific capture backends this file
# still owns (_default_iface, _bpf_from_scope, _management_exclusion,
# capture_window, tshark_evidence) — none of that is generic across agents.
# See shared/test_tool_registry.py for the behavior parity proof, including
# the real bug this extraction caught: capture_payloads is read from
# TOOL_CTX.extra at CALL time, not fixed when the tool is built (which
# happens before configure() has loaded ENGAGEMENT).
# ---------------------------------------------------------------------------
import tool_registry

TOOL_CTX = tool_registry.ToolContext(
    log=LOG, actions=ACTIONS, trim_bytes=TRIM_BYTES, max_return_bytes=MAX_RETURN_BYTES)


# ---------------------------------------------------------------------------
# 5. HARD TOOL ALLOW-LIST  (deny by default)
#
# The MCP server, the qualified allow-list and the PreToolUse hard-deny hook
# are all now DERIVED from CONTRACT (shared/agent_contract.py, built below
# once TASK exists) rather than hand-written here. This used to be a
# hand-written AGENT_TOOL_ALLOWLIST set + enforce_tool_allowlist hook —
# byte-for-byte identical in shape to enum's own copy, differing only in the
# tool names. See agent_contract.AgentContract.make_tool_allowlist_hook for
# the shared implementation: allowed_tools alone does not restrict
# availability (an unlisted tool falls through to the permission mode), so
# this hook is the hard block — hooks run first in the SDK's pipeline and a
# hook deny wins even under bypass. ToolSearch is permitted (via the
# contract's extra_allowed_tools default) because it is the runtime's tool
# LOADER; discovering a schema is not executing it, and any real call still
# passes through here.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# 6. SYSTEM PROMPT
# ---------------------------------------------------------------------------
_OPERATIONAL_NOTES = """\
This is a PASSIVE assessment. You observe traffic that already happened; you do
not scan, connect to, probe or interact with any host. capture_host only listens
for longer on one address — it sends nothing.

Start with list_evidence to see what the window produced. Then read_evidence
with a TARGETED grep or line range. Evidence files can be very large and every
byte you retrieve stays in context for the rest of the run, so pull slices, not
whole files. A pattern of "." matches every line and simply burns the response
cap — use line ranges to page through a file, and patterns to find something
specific.

What to look for, roughly in order of value:
  - Cleartext protocols carrying credentials (telnet, ftp, http basic auth,
    unencrypted smtp/pop/imap, plain LDAP).
  - Outdated or weak TLS. READ tls.log CAREFULLY: hs_type 1 is a ClientHello,
    which shows only what the CLIENT offered, and a scanner deliberately offers
    ancient versions to test what is accepted. hs_type 2 is a ServerHello — what
    the server AGREED to — and only that is evidence about the server's
    configuration. Never report a weak-crypto finding from a ClientHello alone.
  - Unexpected external destinations, or internal hosts talking to each other
    in ways the engagement notes do not explain.
  - Service and OS fingerprints visible in banners and headers.
  - IDS alerts, if Suricata ran — treat each as a lead to corroborate in the
    connection logs, not as a conclusion.

REPORTING RULE — this matters more here than in an active assessment. Describe
findings by LOCATION and TYPE, never by quoting the sensitive value. Write
"cleartext credentials observed in the FTP session at conn.log line 412", never
the username or password itself. The same applies to tokens, cookies, personal
data and any payload bytes. A report that leaks what it found is worse than no
report.

If the capture produced nothing, say so plainly and explain the likely reason
(a switched network shows this interface only broadcast traffic plus this host's
own conversations). Do not speculate about hosts you have no evidence for.

If a finding looks critical, stop and summarize it for human review.

Your final message IS the client deliverable and is written into the report
verbatim. Begin it directly with the report content — no "Perfect", no "Let me
now generate...", no announcing what you are about to do.
"""

RUN_CTX: dict = {}       # this run's instruction files, loaded by configure()
SYSTEM_PROMPT = ""


# ---------------------------------------------------------------------------
# 7. PER-RUN INPUTS  (root-owned: the agent reads, never writes)
#
# Parsing and the narrowing rule now live in shared/scope_cidr.py (used via
# SCOPE above); run-config overrides and the profile hint live in
# shared/agent_runtime.py. What's left here is just wiring AGENT_DIR in.
# ---------------------------------------------------------------------------
def _load_run_target(ceiling: list) -> list:
    # required=False: a passive collector can legitimately capture the whole
    # engagement scope by default — unlike enum, an explicit -t is optional.
    path = AGENT_DIR / "run-target"
    text = path.read_text() if path.exists() else ""
    return SCOPE.narrow(ceiling, text, required=False)


# ---------------------------------------------------------------------------
# 8. CONFIGURE  — every gate that can refuse the run, before any packet moves
# ---------------------------------------------------------------------------
def configure(profile: Profile) -> Profile:
    global ALLOWED_NETWORKS, ENGAGEMENT, PROFILE, SYSTEM_PROMPT, EVIDENCE_DIR, RUN_CTX

    EVIDENCE_DIR = profile.data_root / "scans"
    TOOL_CTX.workdir = EVIDENCE_DIR
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    (profile.data_root / "reports").mkdir(parents=True, exist_ok=True)
    agent_runtime.configure_audit_log(LOG, profile.data_root / "audit.log",
                                      also_stdout=True)

    # 1. the engagement must load. CLAUDE.md "Current plan": ONE master
    #    scope, the engagement record, viewed through this
    #    agent's scope kind. Editing/approving it from the GUI is what
    #    makes it the single source of truth for every launch. Every
    #    failure the loader raises names the fix.
    try:
        ENGAGEMENT = load_engagement(SCOPE.kind, org_dir=ORG_DIR,
                                     agent=AGENT_NAME, require_approved=True)
    except EngagementError as e:
        sys.exit(f"REFUSING: {e}")
    # capture_host was already built (at import time, before ENGAGEMENT
    # existed) — this is what it reads at call time; see the comment above
    # tool_registry._build_capture_host for why it cannot be a fixed kwarg.
    TOOL_CTX.extra["capture_payloads"] = getattr(ENGAGEMENT, "capture_payloads", False)

    # 2. it must declare a scope (ceiling_from_engagement refuses if empty)
    ceiling = SCOPE.ceiling_from_engagement(ENGAGEMENT)

    # 3. today must be inside the authorized window
    assert_in_window(ENGAGEMENT)

    ALLOWED_NETWORKS = _load_run_target(ceiling)
    TOOL_CTX.scope = SCOPE
    TOOL_CTX.scope_ceiling = ALLOWED_NETWORKS
    profile = agent_runtime.load_run_config(profile, AGENT_DIR, org_dir=ORG_DIR, logger=LOG)
    PROFILE = profile

    agent_runtime.load_secrets(
        agent_runtime.secrets_path_list(profile.data_root, AGENT_NAME, ORG_DIR, SHARED_DIR)
    )
    agent_runtime.require_api_key(AGENT_NAME)

    _this_run = (
        "SCOPE FOR THIS RUN\n"
        f"Traffic was captured ONLY for: {SCOPE.describe(ALLOWED_NETWORKS)}\n"
        "The kernel packet filter enforced this during capture, so nothing "
        "outside it exists in the evidence. capture_host is limited to the same "
        "set.\n"
    )

    # -- instruction files: this run's read-only snapshot (context_store.py) --
    try:
        RUN_CTX = agent_runtime.load_run_context(AGENT_DIR)
    except agent_runtime.RunContextError as e:
        sys.exit(f"REFUSING: {e}")
    SYSTEM_PROMPT = (build_system_prompt(ENGAGEMENT) + "\n\n"
                     + _this_run + "\n" + agent_runtime.run_briefing(AGENT_DIR) + "\n"
                     + agent_runtime.compose_instructions(RUN_CTX))

    LOG.info("PROFILE | %s | engagement=%s | scope=%s | model=%s | "
             "window=%ds caps=%dt/$%s/%ds",
             profile.name, ENGAGEMENT.engagement_id,
             SCOPE.describe(ALLOWED_NETWORKS), profile.model,
             profile.window_s, profile.max_turns, profile.max_budget_usd,
             profile.timeout_s)
    return profile


# ---------------------------------------------------------------------------
# 9. REPORT
# ---------------------------------------------------------------------------
def _clean_findings(text: str) -> str:
    """Drop the model's conversational lead-in from a client deliverable.

    Models often open with "Perfect. I have enough evidence — let me generate
    the report now." Harmless in a chat transcript, out of place as the first
    line of something handed to a client. If a markdown heading appears early,
    everything before it is preamble. Conservative on purpose: no heading in the
    first stretch means the text is returned untouched rather than risking the
    loss of real content.
    """
    body = (text or "").strip()
    if not body:
        return body
    head = body[:800]
    m = re.search(r"^#{1,3} \S", head, re.MULTILINE)
    if m and m.start() > 0:
        return body[m.start():].strip()
    return body


def write_report(profile: Profile, result, started: float, status: str,
                 findings: str | None = None, note: str | None = None,
                 resumed_from: str | None = None) -> Path | None:
    """Written on EVERY outcome, including failure and early stop.

    A run that was interrupted still captured traffic on a client network, and
    the record of what it collected matters at least as much as one that
    finished. The journal rotates; this does not, and it sits in the vault.
    """
    reports = profile.data_root / "reports"
    try:
        reports.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        LOG.error("cannot create reports dir: %s", e)
        return None

    # Filename uses "now" (when the report was written); the header's
    # **Started** field uses `started` (when the run actually began) via
    # report_header() below — those are two different moments for a run that
    # took any real time, and conflating them (as this used to) mislabels the
    # header on anything but an instant run.
    path = reports / f"trafficmon-{datetime.now(timezone.utc):%Y%m%d-%H%M%S}.md"

    lines = agent_runtime.report_header(
        title="Traffic Assessment", engagement=ENGAGEMENT, status=status,
        agent_name=AGENT_NAME, profile=profile, scope_label="captured",
        scope_desc=SCOPE.describe(ALLOWED_NETWORKS), started=started, result=result,
        resumed_from=resumed_from,
    ) + agent_runtime.report_inputs(AGENT_DIR, since=started) + [
        "",
        "## Collection",
        "",
        f"- Interface: `{MANIFEST.get('interface', 'n/a')}`",
        f"- Window: {MANIFEST.get('window_seconds', 'n/a')}s",
        f"- Packet filter: `{MANIFEST.get('bpf', 'n/a')}`",
        f"- Snaplen: {MANIFEST.get('snaplen', 'n/a')} "
        f"({'payloads permitted' if getattr(ENGAGEMENT, 'capture_payloads', False) else 'headers/metadata only'})",
        f"- Retention: {MANIFEST.get('pcap', 'n/a')}",
        f"- Analysers: {', '.join(MANIFEST.get('sources', {})) or '(none produced output)'}",
        "",
    ]
    # A detector that could not RUN is a gap in coverage, not a clean result.
    # Saying so on the face of the report stops its silence being read as
    # "nothing to find here".
    if MANIFEST.get("filter_errors"):
        lines += ["> **Detector failures — coverage gap.** These extractions did "
                  "not run, so their absence is NOT evidence of absence:", ""]
        lines += [f">   - `{e}`" for e in MANIFEST["filter_errors"]]
        lines += [""]
    if note:
        lines += [f"> **Note:** {note}", ""]
    lines += ["---", "", "## Findings", ""]
    lines.append(_clean_findings(findings) if findings
                 else "_No findings were produced — the run did not reach a summary._")

    lines += ["", "---", "", "## Actions taken", ""]
    if ACTIONS:
        for a in ACTIONS:
            action = agent_runtime.one_line(a["action"]).replace("`", "'")
            lines.append(f"- `{action}` — {agent_runtime.one_line(a['verdict'])}")
    else:
        lines.append("_None recorded._")

    lines += agent_runtime.context_versions_markdown(RUN_CTX)
    lines += ["", "---", "",
              "_Generated by trafficmon-agent. Passive collection only — no host "
              "was scanned, probed or connected to. Findings reference evidence "
              "by location; sensitive values are deliberately not reproduced._"]

    try:
        path.write_text("\n".join(lines))
    except OSError as e:
        LOG.error("cannot write report: %s", e)
        return None
    LOG.info("REPORT | %s", path)
    return path


# ---------------------------------------------------------------------------
# 10. RUN
# ---------------------------------------------------------------------------
TASK = """\
A {window}s passive capture has already completed for the in-scope address(es).
Review the collected evidence and produce a findings summary for the client:
what services and protocols were observed, any cleartext or weakly protected
traffic, any unexpected destinations, and anything warranting human attention.

Begin with list_evidence.
"""

# The declarative manifest (CLAUDE.md §3f). Built here, not at the top of the
# file, because it needs every piece — the tool functions, PROFILES, the
# scope boundary, the prompt notes and the task — to already exist.

_TOOL_NAMES, _TOOLS = tool_registry.build_tools(
    ["list_evidence", "read_evidence", "capture_host"], TOOL_CTX,
    config={"capture_host": {"default_iface": _default_iface, "bpf_from_scope": _bpf_from_scope,
                             "management_exclusion": _management_exclusion,
                             "capture_window": capture_window, "tshark_evidence": tshark_evidence,
                             "max_followup_s": MAX_FOLLOWUP_S}})
# The tools every agent shares (agent_runtime.run_tools); the holder lets
# ask_operator read the StateStore run() creates later.
_STATE_HOLDER = agent_runtime.StateHolder()
_names, _shared = agent_runtime.run_tools(AGENT_DIR, _STATE_HOLDER)
_TOOL_NAMES, _TOOLS = _TOOL_NAMES + _names, _TOOLS + _shared

CONTRACT = AgentContract(
    name=AGENT_NAME,
    tool_names=_TOOL_NAMES,
    tools=_TOOLS,
    mcp_server_name="trafficmon",
    scope=SCOPE,
    profiles=PROFILES,
    operational_notes=_OPERATIONAL_NOTES,
    task=TASK,
)
MCP_SERVER = CONTRACT.build_mcp_server()
TOOL_ALLOWLIST_HOOK = CONTRACT.make_tool_allowlist_hook(LOG)


async def run(profile: Profile) -> int:
    """The run loop is shared with every other agent (session_runner.py).
    What is specific to trafficmon is the capture, which happens BEFORE the
    model is started so it cannot influence what was captured."""

    def collect() -> str | None:
        global MANIFEST
        iface = _default_iface()
        bpf = _bpf_from_scope(ALLOWED_NETWORKS, exclude=_management_exclusion(iface))
        MANIFEST = collect_evidence(profile, bpf, iface)
        # list_evidence (registry-built, tool_registry.py) reads this at call
        # time via ctx.extra — the tool is built before capture happens, so
        # there is nothing to hand it earlier than this.
        TOOL_CTX.extra["manifest"] = MANIFEST
        if MANIFEST.get("capture_ok"):
            return None
        note = (
            f"Capture produced no packets in {profile.window_s}s on {iface} "
            f"({MANIFEST.get('capture_detail', 'no detail')}).\n"
            f"> This is expected on a switched network: this interface sees "
            f"broadcast traffic plus THIS host's own conversations, and nothing "
            f"else. Traffic between two other machines never reaches it.\n"
            f"> To observe another host's sessions you need a SPAN/mirror port or "
            f"an inline tap. To test the pipeline without one, generate the "
            f"traffic FROM this host so it crosses {iface}.")
        LOG.warning("%s", note)
        return note

    def report(profile, result, started, status, note=None, resumed_from=None):
        findings = agent_runtime.FINDINGS.text() or getattr(result, "result", None)
        return write_report(profile, result, started, status, findings, note,
                            resumed_from=resumed_from)

    return await session_runner.run_session(session_runner.Session(
        profile=profile, contract=CONTRACT, mcp_server=MCP_SERVER,
        allowlist_hook=TOOL_ALLOWLIST_HOOK, system_prompt=SYSTEM_PROMPT,
        agent_dir=AGENT_DIR, org_dir=ORG_DIR, log=LOG, state_holder=_STATE_HOLDER,
        engagement_id=ENGAGEMENT.engagement_id,
        target_label=SCOPE.describe(ALLOWED_NETWORKS),
        write_report=report, prepare=collect,
        kickoff=(f"A {profile.window_s}s passive capture has already completed "
                 f"for this run's scope. " + agent_runtime.KICKOFF)))


def main() -> int:
    agent_runtime.install_sigterm_handler()
    ap = argparse.ArgumentParser(allow_abbrev=False, 
        description="Windowed passive traffic assessment agent. Model and caps "
                    "are set at launch (agenti ... start --model ...), not by a "
                    "flag here.")
    ap.add_argument("--window", type=int, default=None,
                    help="override the capture window, in seconds")
    args = ap.parse_args()

    profile = PROFILES["run"]
    profile = configure(profile)
    if args.window:
        profile = replace(profile, window_s=max(5, args.window))

    return agent_runtime.run_agent(run(profile))


if __name__ == "__main__":
    sys.exit(main())
