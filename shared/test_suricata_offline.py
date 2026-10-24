#!/usr/bin/env python3
"""test_suricata_offline.py — running Suricata over an attached capture
(shared/suricata_offline.py and shared/suricata-offline.yaml).

    python3 shared/test_suricata_offline.py

No root, no vault, no SDK. The pure parts (rule-set choice, bind list, log
harvesting, the summary) always run. The live part runs Suricata for real in
the sandbox over a capture built here (one DNS query), and skips LOUDLY when
Suricata or bubblewrap is absent — as on GitHub's runners — rather than pass
without having tested anything.

What matters:
  * the rule set is the one suricata-update wrote if it exists, else the
    package's event rules, else none — and the summary says plainly when the
    rules cannot have flagged a threat, because "no alerts" from those rules is
    not "clean";
  * the sandbox is handed the shipped config and the shared config files,
    read-only, at fixed paths — nothing from the model;
  * logs are moved out of the private directory and it is removed;
  * the summary survives a damaged eve.json and never raises;
  * a real run over a real capture produces a DNS event and a flow, with no
    Suricata warning (so the shipped config and rules were found and loaded).
"""
import json
import struct
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import sandbox  # noqa: E402
import suricata_offline as so  # noqa: E402

PASS = FAIL = SKIP = 0


def check(label, got, want):
    global PASS, FAIL
    if got == want:
        PASS += 1; print(f"  [ OK ] {label}")
    else:
        FAIL += 1; print(f"  [FAIL] {label}\n         got  {got!r}\n         want {want!r}")


def skip(label, why):
    global SKIP
    SKIP += 1; print(f"  [SKIP] {label} — {why}")


def section(t): print(f"\n=== {t} ===")


tmp = Path(tempfile.mkdtemp(prefix="agenti-test-suricata-"))

# ---------------------------------------------------------------------------
section("the shipped config")
text = so.CONFIG_PATH.read_text()
check("it exists beside the module", so.CONFIG_PATH.is_file(), True)
check("it reads rules from the sandbox path and logs to the sandbox path",
      ("default-rule-path: /rules" in text, "default-log-dir: /out" in text), (True, True))
check("it never stores the files it finds in traffic", "enabled: no" in text.split("file-store:")[1], True)
check("it validates no checksums (a capture from an offloading NIC has bad ones)",
      "checksum-checks: no" in text, True)
check("it names no host path outside the sandbox mapping",
      [ln for ln in text.splitlines()
       if ("/etc/" in ln or "/var/" in ln or "/opt/" in ln or "/home/" in ln) and not ln.lstrip().startswith("#")], [])
# Every protocol the package's own event rules mention must be parsed, or
# Suricata refuses to load that rule file at all.
for proto in ("modbus", "dnp3", "enip", "smb", "dns", "http", "tls"):
    check(f"the {proto} parser is on", f"    {proto}:\n      enabled: yes" in text, True)

# ---------------------------------------------------------------------------
section("which rules are used")
real = (so._UPDATED_RULES, so._PACKAGE_RULES)
upd, pkg = tmp / "updated", tmp / "package"
so._UPDATED_RULES, so._PACKAGE_RULES = upd, pkg
try:
    d, note = so.rules_source()
    check("with no rules anywhere there is no rule dir, and the note says there is no detection",
          (d, "no detection" in note), (None, True))
    pkg.mkdir(); (pkg / "dns-events.rules").write_text("alert dns any any -> any any (sid:1;)\n")
    d, note = so.rules_source()
    check("the package's event rules are used when nothing else is there", d, pkg)
    check("...and the note says they are NOT threat signatures and names the fix",
          ("NOT threat signatures" in note, "suricata-update" in note), (True, True))
    upd.mkdir(); (upd / "suricata.rules").write_text("")
    d, _ = so.rules_source()
    check("an EMPTY suricata.rules does not displace the package rules", d, pkg)
    (upd / "suricata.rules").write_text("alert tcp any any -> any any (msg:\"x\"; sid:2;)\n")
    d, note = so.rules_source()
    check("suricata-update's output wins when it exists", d, upd)
    check("...and is described as threat signatures", "threat signatures" in note and "NOT" not in note, True)

    section("what is bound into the sandbox")
    b = dict((dest, src) for src, dest in so.binds())
    check("the shipped config is mapped to /cfg/suricata.yaml", b["/cfg/suricata.yaml"], str(so.CONFIG_PATH))
    check("the rules directory is mapped to /rules", b["/rules"], str(upd))
    check("the shared config files are mapped under /cfg",
          sorted(k for k in b if k.startswith("/cfg/") and not k.endswith("suricata.yaml")),
          ["/cfg/classification.config", "/cfg/reference.config", "/cfg/threshold.config"])
    check("every source is an absolute path", all(Path(s).is_absolute() for s in b.values()), True)
    so._UPDATED_RULES, so._PACKAGE_RULES = tmp / "none-a", tmp / "none-b"
    empty = tmp / "empty"; empty.mkdir()
    b = dict((dest, src) for src, dest in so.binds(empty))
    check("with no rules at all, an empty directory is bound so Suricata still starts", b["/rules"], str(empty))
    try:
        so.binds()
        check("...but not by accident: no empty directory given is an error", False, True)
    except FileNotFoundError:
        check("...but not by accident: no empty directory given is an error", True, True)
finally:
    so._UPDATED_RULES, so._PACKAGE_RULES = real

# ---------------------------------------------------------------------------
section("harvesting a run's logs")
logdir = tmp / "log"; logdir.mkdir()
dest = tmp / "saved"; dest.mkdir()
(logdir / "eve.json").write_text('{"event_type":"flow"}\n')
(logdir / "fast.log").write_text("x\n")
(logdir / "stats.log").write_text("y\n")
(logdir / "suricata.log").write_text("z\n")
(logdir / "stray.bin").write_bytes(b"\x00")
(logdir / "link.log").symlink_to("/etc/passwd")
got = so.harvest(logdir, dest, "suricata_1")
check("the four known logs are moved out under the run's stem",
      sorted(p.name for p in dest.iterdir()),
      ["suricata_1_eve.json", "suricata_1_fast.log", "suricata_1_stats.log", "suricata_1_suricata.log"])
check("...keyed by their original names", sorted(got), ["eve.json", "fast.log", "stats.log", "suricata.log"])
check("the private log directory is removed, with anything unexpected in it", logdir.exists(), False)
# a log that is a symlink must not be followed out
logdir.mkdir(); (logdir / "eve.json").symlink_to("/etc/passwd")
got = so.harvest(logdir, dest, "suricata_2")
check("a symlink posing as a log is not moved", (got, (dest / "suricata_2_eve.json").exists()), ({}, False))

# ---------------------------------------------------------------------------
section("the summary")
eve = tmp / "eve.json"
rows = [
    {"event_type": "flow", "src_ip": "1.1.1.1"},
    {"event_type": "flow", "src_ip": "1.1.1.2"},
    {"event_type": "dns", "dns": {"rrname": "example.com"}},
    {"timestamp": "2026-01-02T03:04:05.000000+0000", "event_type": "alert", "src_ip": "10.0.0.5", "src_port": 4444,
     "dest_ip": "10.0.0.9", "dest_port": 445, "alert": {"signature": "ET EXPLOIT MS17-010", "severity": 1, "signature_id": 2024218}},
    {"timestamp": "2026-01-02T03:04:06.000000+0000", "event_type": "alert", "src_ip": "10.0.0.5", "src_port": 4445,
     "dest_ip": "10.0.0.9", "dest_port": 445, "alert": {"signature": "ET EXPLOIT MS17-010", "severity": 1, "signature_id": 2024218}},
    {"event_type": "alert", "alert": {"signature": "SURICATA SMB malformed", "severity": 3, "signature_id": 2225002}},
    {"event_type": "anomaly", "anomaly": {"event": "malformed_data"}},
]
eve.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
out = so.summarise(eve, console="i: pcap: read 1 file, 10171 packets, 962530 bytes\n", rules_note="rules from suricata-update")
check("it says how much was read", out.splitlines()[0], "Suricata read 10,171 packets (962,530 bytes).")
check("it states which rules were used", "Rules: rules from suricata-update." in out, True)
check("alerts are counted and grouped by signature, most frequent first",
      out.index("ET EXPLOIT MS17-010") < out.index("SURICATA SMB malformed"), True)
check("...with the count, the id and where it first appeared",
      "2 x  sev 1  [2024218] ET EXPLOIT MS17-010   first: 10.0.0.5:4444 -> 10.0.0.9:445" in out, True)
check("the total is stated", "Alerts: 3 (2 distinct)" in out, True)
check("anomalies and event counts are listed", ("malformed_data x1" in out, "flow 2" in out, "dns 1" in out), (True, True, True))

eve.write_text('{"event_type":"flow"}\nthis is not json\n[1,2]\n"str"\n')
out = so.summarise(eve, console="", rules_note="")
check("a damaged eve.json is summarised, not fatal", ("flow 1" in out, "1 unreadable line" in out), (True, True))
check("with no alerts it says so", "Alerts: none." in out, True)
check("a missing eve.json is summarised, not fatal", so.summarise(tmp / "nope.json").startswith("Suricata ran."), True)
check("a missing eve.json yields no event list", "Events by type" in so.summarise(None), False)

check("only warnings and errors are passed on from the console",
      so.warnings_only("i: noise\nW: threshold-config: Error opening file\nE: bad\nNotice: x\nC: fatal\n"),
      "W: threshold-config: Error opening file\nE: bad\nC: fatal")

# ---------------------------------------------------------------------------
section("a real run in the sandbox over a real capture")


def dns_query_pcap(path: Path) -> None:
    """A classic pcap holding ONE Ethernet/IPv4/UDP DNS query for example.com."""
    qname = b"\x07example\x03com\x00"
    dns = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", 1, 1)
    udp = struct.pack("!HHHH", 53124, 53, 8 + len(dns), 0) + dns
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                     bytes([10, 0, 0, 5]), bytes([10, 0, 0, 1])) + udp
    eth = bytes.fromhex("020000000001" "020000000002" "0800") + ip
    glob_hdr = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    rec = struct.pack("<IIII", 1700000000, 0, len(eth), len(eth))
    path.write_bytes(glob_hdr + rec + eth)


suricata = "/usr/bin/suricata" if Path("/usr/bin/suricata").exists() else None
if not sandbox.available() or suricata is None or not so.available():
    skip("running Suricata for real", "bubblewrap, suricata or the package config files are missing. "
         "THIS SUITE PROVED NOTHING ABOUT A REAL RUN — install them.")
else:
    probe = sandbox.run(["/bin/true"], "light")
    if not probe.ok:
        skip("running Suricata for real", "the sandbox cannot start here (unprivileged user namespaces refused?)")
    else:
        inp, outp = tmp / "in", tmp / "out"
        inp.mkdir(); outp.mkdir()
        dns_query_pcap(inp / "q.pcap")
        spare = tmp / "spare"; spare.mkdir()
        r = sandbox.run([suricata, "-c", "/cfg/suricata.yaml", "-l", "/out", "-r", "/in/q.pcap"],
                        "suricata", input_dir=inp, output_dir=outp, binds=so.binds(spare))
        check("it completes", (r.ok, r.limit_hit), (True, None))
        console = r.stdout + r.stderr
        check("it read the one packet", "read 1 file, 1 packets" in console, True)
        check("it printed no warning or error: the shipped config and the rules were found",
              so.warnings_only(console), "")
        events = [json.loads(ln) for ln in (outp / "eve.json").read_text().splitlines() if ln.strip()]
        kinds = sorted({e["event_type"] for e in events})
        # Suricata 8 logs DNS as version 3: the names are in a "queries" list.
        check("eve.json holds a DNS request event naming the query", any(
            e["event_type"] == "dns" and e["dns"].get("type") == "request"
            and any(q.get("rrname") == "example.com" for q in e["dns"].get("queries", []))
            for e in events), True)
        check("...and a flow record", "flow" in kinds, True)
        summary = so.summarise(outp / "eve.json", console=console, rules_note="test")
        check("the summary reads it back", ("1 packets" in summary, "dns 1" in summary, "flow 1" in summary),
              (True, True, True))

print(f"\n{PASS} passed, {FAIL} failed, {SKIP} skipped")
sys.exit(1 if FAIL else 0)
