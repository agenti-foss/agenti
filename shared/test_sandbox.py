#!/usr/bin/env python3
"""test_sandbox.py — the untrusted-file sandbox (shared/sandbox.py).

    python3 shared/test_sandbox.py

WHAT IT PINS DOWN. This is the one module whose failure mode is silent and
catastrophic: a sandbox that quietly isn't one looks exactly like a working
sandbox until a malicious capture gets out of it. So nothing here is asserted
from configuration — every containment property is checked by ATTEMPTING the
thing and confirming it fails, and the network test carries a control
(the identical call from outside the sandbox) so that "it failed" cannot be
mistaken for "the box has no network anyway".

Two halves:
  * the argv builder, which needs nothing installed — the bubblewrap flags
    ARE the boundary, so they are asserted directly;
  * live containment, which needs bubblewrap. Unlike the project's other
    suites this one therefore can skip: it says so loudly rather than
    passing vacuously, because a green run that tested nothing would be the
    worst possible outcome here. (On CI, GitHub's runners restrict
    unprivileged user namespaces, so the live half cannot run there; it runs
    on the box, via shared/deploy.sh --verify and by hand.)
"""
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import sandbox  # noqa: E402

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


tmp = Path(tempfile.mkdtemp(prefix="agenti-sandbox-test-"))
IN, OUT = tmp / "in", tmp / "out"
for d in (IN, OUT):
    d.mkdir()
(IN / "input.txt").write_text("the input file\n")

# ---------------------------------------------------------------------------
section("the argv builder — the flags ARE the boundary")
argv, files = sandbox.build_argv(["/bin/true"], sandbox.PROFILES["light"],
                                 input_dir=IN, output_dir=OUT)
joined = " ".join(argv)
check("every namespace unshared", "--unshare-all" in argv, True)
check("network NOT shared by default", "--share-net" in argv, False)
check("environment cleared (the agent holds API keys)", "--clearenv" in argv, True)
check("dies with its parent", "--die-with-parent" in argv, True)
check("detached from the controlling terminal", "--new-session" in argv, True)
check("root is a throwaway tmpfs", argv[1:3], ["--tmpfs", "/"])
check("input bound READ-ONLY", f"--ro-bind {IN.resolve()} /in" in joined, True)
check("output bound WRITABLE", f"--bind {OUT.resolve()} /out" in joined, True)
check("the host's /etc is never bound in", " --ro-bind /etc /etc" in joined, False)
check("no Agenti data, state or code folder is bound in",
      [d for d in ("/var/lib/agenti", "/usr/lib/agenti", "/etc/agenti", "/opt/agenti") if d in joined], [])
check("a synthetic passwd and group are injected instead", len(files), 2)
check("...and the passwd names no real account",
      b"root:x:0:0" in files[0][1] and b"agent:x:" in files[0][1], True)
check("the program is separated from bwrap's own flags by --", "--" in argv, True)
check("PATH is set explicitly, not inherited", "--setenv" in argv and "PATH" in argv, True)

# Host files at fixed sandbox paths (Suricata's config and rules): read-only,
# chosen by code, and a missing source is an error rather than a silent omission.
_cfg = IN / "cfg.yaml"
_cfg.write_text("%YAML 1.1\n---\n")
b_argv, _ = sandbox.build_argv(["/bin/true"], sandbox.PROFILES["light"], binds=[(str(_cfg), "/cfg/suricata.yaml")])
check("a mapped host file is bound READ-ONLY at its fixed path",
      " ".join(b_argv).count(f"--ro-bind {_cfg.resolve()} /cfg/suricata.yaml"), 1)
check("...and never writable", f"--bind {_cfg.resolve()}" in " ".join(b_argv), False)
for bad, why in (([("relative.yaml", "/cfg/x")], "a relative source"),
                 ([(str(_cfg), "cfg/x")], "a relative destination"),
                 ([(str(IN / "missing.yaml"), "/cfg/x")], "a source that does not exist")):
    try:
        sandbox.build_argv(["/bin/true"], sandbox.PROFILES["light"], binds=bad)
        check(f"{why} is refused", False, True)
    except (ValueError, FileNotFoundError):
        check(f"{why} is refused", True, True)

# A bind inside another bind (the cracker's /wordlists/hashcat-rules inside
# /wordlists). bwrap cannot make a mount point inside a read-only bind, which
# failed every john/hashcat run (2026-10-16); the parent becomes a tmpfs of
# its entries, the inner bind mounts on it, then the parent goes read-only.
_wl, _rules = tmp / "wl", tmp / "rules"
_wl.mkdir(); _rules.mkdir()
(_wl / "list.txt").write_text("pw\n")
(_wl / "hashcat-rules").mkdir()                      # shadowed by the inner bind
os.symlink("/usr/share/dict/words", _wl / "words")
(_rules / "best66.rule").write_text(":\n")
n_argv = sandbox._bind_args([(str(_rules), "/wordlists/hashcat-rules"), (str(_wl), "/wordlists")])
check("the outer directory becomes a tmpfs, before anything mounts inside it",
      n_argv[:2], ["--tmpfs", "/wordlists"])
check("its plain entries are bound read-only one by one",
      f"--ro-bind {(_wl / 'list.txt').resolve()} /wordlists/list.txt" in " ".join(n_argv), True)
check("its symlinks stay symlinks (resolved inside the sandbox, never on the host)",
      "--symlink /usr/share/dict/words /wordlists/words" in " ".join(n_argv), True)
check("an entry with the inner bind's name is left to the inner bind",
      f"{_wl.resolve()}/hashcat-rules" in " ".join(n_argv), False)
check("the inner bind follows, read-only",
      f"--ro-bind {_rules.resolve()} /wordlists/hashcat-rules" in " ".join(n_argv), True)
check("...and the outer tmpfs is remounted read-only last", n_argv[-2:], ["--remount-ro", "/wordlists"])
check("a bind with nothing inside it stays a single read-only bind",
      sandbox._bind_args([(str(_rules), "/r")]), ["--ro-bind", str(_rules.resolve()), "/r"])
check("the cracker profile takes only john's config, the OpenCL driver list and the CPU topology",
      sandbox.PROFILES["cracker"].extra_ro, ("/etc/john", "/etc/OpenCL", "/sys/devices/system/cpu"))

net_argv, _ = sandbox.build_argv(["/bin/true"], sandbox.SandboxProfile("n", network=True))
check("network only when the profile asks", "--share-net" in net_argv, True)

check("the profiles are light, analysis, suricata and cracker",
      sorted(sandbox.PROFILES), ["analysis", "cracker", "light", "suricata"])
check("every profile is network-off by default",
      all(not p.network for p in sandbox.PROFILES.values()), True)
check("every profile bounds wall-clock, cpu, memory and output",
      all(p.wall_clock_s > 0 and p.cpu_seconds > 0 and p.memory_bytes > 0
          and p.output_bytes > 0 for p in sandbox.PROFILES.values()), True)
try:
    sandbox.build_argv([], sandbox.PROFILES["light"])
    check("an empty command is refused", False, True)
except ValueError:
    check("an empty command is refused", True, True)

# ---------------------------------------------------------------------------
if not sandbox.available():
    section("live containment")
    skip("all live containment checks", f"{sandbox.BWRAP} is not installed. "
         "THIS SUITE PROVED NOTHING ABOUT CONTAINMENT — install bubblewrap.")
else:
    # Unprivileged user namespaces can be switched off by the host (GitHub's
    # Ubuntu runners do, via AppArmor). That is "cannot test here", not "the
    # sandbox is broken", but it must never read as a pass.
    probe = sandbox.run(["/bin/true"], "light")
    if not probe.ok and ("Operation not permitted" in probe.stderr
                         or "Permission denied" in probe.stderr
                         or "Can't mkdir" in probe.stderr or "setting up uid map" in probe.stderr):
        section("live containment")
        skip("all live containment checks",
             f"bubblewrap is installed but this host refuses it ({probe.stderr.strip()[:120]}). "
             "THIS SUITE PROVED NOTHING ABOUT CONTAINMENT HERE.")
        print(f"\n{PASS} passed, {FAIL} failed, {SKIP} skipped")
        sys.exit(1 if FAIL else 0)

    section("live containment: the filesystem")
    r = sandbox.run(["/bin/sh", "-c", "ls /opt 2>&1; cat /etc/shadow 2>&1"],
                    "light", input_dir=IN, output_dir=OUT)
    check("the vault (/opt) does not exist inside", "No such file" in r.stdout, True)
    check("/etc/shadow does not exist inside", "No such file" in r.stdout.split("\n")[-2] or
          "No such file" in r.stdout, True)

    r = sandbox.run(["/bin/cat", "/in/input.txt"], "light", input_dir=IN, output_dir=OUT)
    check("the run's input is readable", r.stdout.strip(), "the input file")

    r = sandbox.run(["/bin/sh", "-c", "echo tampered > /in/input.txt"], "light",
                    input_dir=IN, output_dir=OUT)
    check("writing to the input is refused", r.ok, False)
    check("...and the host's input file is untouched",
          (IN / "input.txt").read_text().strip(), "the input file")

    r = sandbox.run(["/bin/sh", "-c", "echo produced > /out/result.txt"], "light",
                    input_dir=IN, output_dir=OUT)
    check("writing to the output directory works", r.ok, True)
    check("...and the file reaches the host", (OUT / "result.txt").read_text().strip(), "produced")

    r = sandbox.run(["/bin/sh", "-c", "echo x > /escaped.txt && cat /escaped.txt"],
                    "light", input_dir=IN, output_dir=OUT)
    check("a write to the sandbox root is discarded with the sandbox",
          (r.ok, Path("/escaped.txt").exists()), (True, False))

    section("live containment: the network")
    r = sandbox.run(["/usr/bin/python3", "-c",
                     "import socket\n"
                     "try:\n"
                     "    socket.create_connection(('1.1.1.1', 53), timeout=4); print('CONNECTED')\n"
                     "except OSError as e: print('refused', e.errno)"], "light")
    check("outbound network is unreachable inside", "CONNECTED" not in r.stdout, True)
    # The control: without it, "it failed" could just mean the box is offline.
    host_online = False
    try:
        socket.create_connection(("1.1.1.1", 53), timeout=4).close()
        host_online = True
    except OSError:
        pass
    if host_online:
        check("...while the identical call succeeds OUTSIDE (the control)", host_online, True)
    else:
        skip("the outbound control", "this box has no outbound network right now, "
             "so the refusal inside proves less than usual")

    r = sandbox.run(["/bin/sh", "-c", "ls /sys/class/net 2>/dev/null; cat /proc/net/dev"], "light")
    check("only loopback exists inside", "eth0" not in r.stdout and "wlan" not in r.stdout, True)

    section("live containment: identity and environment")
    os.environ["AGENTI_TEST_FAKE_SECRET"] = "this-must-not-leak"
    r = sandbox.run(["/usr/bin/env"], "light")
    check("the parent's environment does not leak in",
          "this-must-not-leak" not in r.stdout, True)
    check("...and PATH is the one we set", "PATH=/usr/bin:/bin" in r.stdout, True)
    os.environ.pop("AGENTI_TEST_FAKE_SECRET", None)

    # The synthetic passwd was mounted BEFORE the tmpfs root until 2026-10-16,
    # so the root hid it and there was no /etc/passwd at all; hashcat's
    # OpenCL runtime looks its user up and died with a bare SIGSEGV.
    r = sandbox.run(["/usr/bin/cat", "/etc/passwd", "/etc/group"], "light")
    check("the synthetic passwd and group are actually visible inside",
          r.ok and "agent:x:" in r.stdout and "root:x:0:" in r.stdout, True)
    check("...and they are the synthetic ones, not the host's",
          len(r.stdout.splitlines()), 4)

    r = sandbox.run(["/bin/sh", "-c", "cat /w/list.txt /w/hashcat-rules/best66.rule && "
                     "! touch /w/new 2>/dev/null && ! touch /w/hashcat-rules/new 2>/dev/null && echo ro"],
                    "light", binds=[(str(_wl), "/w"), (str(_rules), "/w/hashcat-rules")])
    check("a bind inside a bind: both readable, neither writable",
          (r.ok, r.stdout.split()), (True, ["pw", ":", "ro"]))

    r = sandbox.run(["/bin/sh", "-c", "grep -E 'NoNewPrivs|CapEff' /proc/self/status"], "light")
    check("NoNewPrivs is set", "NoNewPrivs:\t1" in r.stdout, True)
    check("no capabilities at all", "CapEff:\t0000000000000000" in r.stdout, True)

    r = sandbox.run(["/bin/sh", "-c", "ls /proc | grep -c '^[0-9]*$'"], "light")
    check("a private PID namespace (only its own processes visible)",
          int(r.stdout.strip() or 99) <= 4, True)

    section("live containment: the ceilings")
    t0 = time.monotonic()
    r = sandbox.run(["/bin/sh", "-c", "sleep 60"],
                    sandbox.SandboxProfile("t", wall_clock_s=3, cpu_seconds=30))
    check("the wall-clock deadline stops a hung program", r.limit_hit, "wall_clock")
    check("...promptly", time.monotonic() - t0 < 10, True)
    check("...and it is reported as not-ok", r.ok, False)
    check("...with an operator-readable summary", "time limit" in r.summary(), True)

    r = sandbox.run(["/usr/bin/python3", "-c", "x=0\nwhile True: x+=1"],
                    sandbox.SandboxProfile("c", wall_clock_s=60, cpu_seconds=2))
    check("the CPU ceiling stops a spinner", r.ok, False)
    check("...well before the wall clock", r.duration_s < 30, True)

    r = sandbox.run(["/usr/bin/python3", "-c",
                     "try:\n bytearray(512*1024*1024); print('ALLOCATED')\n"
                     "except MemoryError: print('refused')"],
                    sandbox.SandboxProfile("m", memory_bytes=256 * sandbox.MB))
    check("the memory ceiling refuses a large allocation",
          "ALLOCATED" not in r.stdout, True)

    r = sandbox.run(["/usr/bin/python3", "-c",
                     "open('/out/big','wb').write(b'x'*(8*1024*1024))"],
                    sandbox.SandboxProfile("f", output_bytes=1 * sandbox.MB),
                    output_dir=OUT)
    check("the output-size ceiling refuses a large write", r.ok, False)
    check("...and the truncated file is why a failed run's output is discardable",
          (OUT / "big").exists() and (OUT / "big").stat().st_size <= 1 * sandbox.MB, True)

    section("live containment: output streamed to files")
    with open(tmp / "so.txt", "wb") as so:
        r = sandbox.run(["/bin/sh", "-c", "echo to-stdout; echo to-stderr 1>&2"], "light",
                        stdout_to=so)
    check("a program's stdout goes straight into the given file",
          ((tmp / "so.txt").read_text().strip(), r.stdout), ("to-stdout", ""))
    check("...and its stderr comes back in the result", r.stderr.strip(), "to-stderr")
    r = sandbox.run(["/bin/sh", "-c", "echo to-stdout; echo to-stderr 1>&2"], "light")
    check("without a file, stdout is returned in the result too",
          (r.stdout.strip(), r.stderr.strip()), ("to-stdout", "to-stderr"))

    r = sandbox.run(["/usr/bin/python3", "-c",
                     "import sys\nwhile True: sys.stderr.write('e' * 65536)"],
                    sandbox.SandboxProfile("eflood", wall_clock_s=60, cpu_seconds=30,
                                           output_bytes=1 * sandbox.MB))
    check("a program that floods stderr is stopped too, and only the last 64 KB come back",
          (r.ok, r.limit_hit, len(r.stderr) <= 64 * 1024), (False, "output_size", True))
    r = sandbox.run(["/usr/bin/python3", "-c",
                     "import sys\nwhile True: sys.stdout.write('x' * 65536)"],
                    sandbox.SandboxProfile("oflood", wall_clock_s=60, cpu_seconds=30,
                                           output_bytes=1 * sandbox.MB))
    check("...and so is a flood of stdout when no file was given (never unbounded in memory)",
          (r.ok, r.limit_hit, len(r.stdout) <= 1 * sandbox.MB), (False, "output_size", True))

    with open(tmp / "flood.txt", "wb") as so:
        r = sandbox.run(["/usr/bin/python3", "-c",
                         "import sys\nwhile True: sys.stdout.write('x' * 65536)"],
                        sandbox.SandboxProfile("flood", wall_clock_s=60, cpu_seconds=30,
                                               output_bytes=1 * sandbox.MB),
                        stdout_to=so)
    check("a program that prints without end is stopped by the size ceiling",
          (r.ok, r.limit_hit), (False, "output_size"))
    check("...and what it wrote is capped at the ceiling",
          (tmp / "flood.txt").stat().st_size <= 1 * sandbox.MB + 65536, True)

    section("live containment: a runaway process tree")
    proc = subprocess.Popen(
        sandbox.build_argv(["/bin/sh", "-c", "sleep 120.731 & sleep 120.731 & sleep 120.731; wait"],
                           sandbox.PROFILES["light"])[0],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    time.sleep(1.5)
    # Only THIS test's processes (a unique duration): counting every 'sleep' of
    # the user also counted unrelated shells waiting in a loop (a flaky FAIL).
    running = subprocess.run(["pgrep", "-c", "-u", str(os.getuid()), "-f", "^sleep 120.731$"],
                             capture_output=True, text=True).stdout.strip() or "0"
    proc.kill()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass
    time.sleep(1.0)
    left = subprocess.run(["pgrep", "-c", "-u", str(os.getuid()), "-f", "^sleep 120.731$"],
                          capture_output=True, text=True).stdout.strip() or "0"
    check("children were running inside", int(running) >= 3, True)
    check("killing the sandbox reaps EVERY process in it", left, "0")

    section("live containment: a real parser on a hostile file")
    tshark = "/usr/bin/tshark" if Path("/usr/bin/tshark").exists() else None
    if tshark is None:
        skip("tshark containment", "tshark is not installed")
    else:
        # A valid classic-pcap header (little-endian, Ethernet) followed by one
        # record whose length claims far more than the file holds, then noise.
        # The point is NOT that tshark rejects it — it is that whatever
        # tshark does with it, it stays contained.
        bad = IN / "malformed.pcap"
        bad.write_bytes(
            bytes.fromhex("d4c3b2a1" "0200" "0400" "00000000" "00000000" "ffff0000" "01000000")
            + bytes.fromhex("01000000" "02000000" "ffffff7f" "ffffff7f") + os.urandom(512))
        r = sandbox.run([tshark, "-r", "/in/malformed.pcap", "-q", "-z", "io,phs"],
                        "analysis", input_dir=IN, output_dir=OUT)
        check("a malformed capture is handled without escaping the sandbox",
              isinstance(r.exit_code, int) and r.limit_hit is None, True)
        check("...the input file is still unmodified on the host",
              bad.read_bytes()[:4], bytes.fromhex("d4c3b2a1"))
        check("...and nothing was written outside the output directory",
              sorted(p.name for p in OUT.iterdir() if p.name not in ("result.txt", "big")), [])

        good = IN / "ok.pcap"
        good.write_bytes(
            bytes.fromhex("d4c3b2a1" "0200" "0400" "00000000" "00000000" "ffff0000" "01000000")
            + bytes.fromhex("01000000" "02000000" "3c000000" "3c000000") + b"\x00" * 60)
        r = sandbox.run([tshark, "-r", "/in/ok.pcap", "-T", "fields", "-e", "frame.len"],
                        "analysis", input_dir=IN, output_dir=OUT)
        check("a valid capture is read normally (the sandbox does not break real work)",
              r.ok and r.stdout.strip() == "60", True)

    section("live containment: Suricata with its config and rules bound in")
    import suricata_offline as so
    suricata = "/usr/bin/suricata" if Path("/usr/bin/suricata").exists() else None
    if suricata is None or not so.available():
        skip("suricata containment", "suricata (or its package config files) is not installed")
    else:
        spare = OUT / "norules"
        spare.mkdir()
        logdir = OUT / "sur"
        logdir.mkdir()
        _hdr = bytes.fromhex("d4c3b2a1" "0200" "0400" "00000000" "00000000" "ffff0000" "01000000")
        (IN / "sur-ok.pcap").write_bytes(_hdr + bytes.fromhex("01000000" "02000000" "3c000000" "3c000000") + b"\x00" * 60)
        (IN / "sur-bad.pcap").write_bytes(_hdr + bytes.fromhex("01000000" "02000000" "ffffff7f" "ffffff7f") + os.urandom(512))
        r = sandbox.run([suricata, "-c", "/cfg/suricata.yaml", "-l", "/out", "-r", "/in/sur-ok.pcap"],
                        "suricata", input_dir=IN, output_dir=logdir, binds=so.binds(spare))
        check("Suricata runs to completion over a valid capture", (r.ok, r.limit_hit), (True, None))
        check("...writes its logs only into the output directory", (logdir / "eve.json").is_file(), True)
        check("...and printed no warning or error (config and rules were found)",
              so.warnings_only(r.stdout + r.stderr), "")
        r = sandbox.run([suricata, "-c", "/cfg/suricata.yaml", "-l", "/out", "-r", "/in/sur-bad.pcap"],
                        "suricata", input_dir=IN, output_dir=logdir, binds=so.binds(spare))
        check("a malformed capture is handled without escaping the sandbox",
              isinstance(r.exit_code, int) and r.limit_hit is None, True)
        # The config is bound read-only: a program cannot change it.
        r = sandbox.run(["/bin/sh", "-c", "echo x >> /cfg/suricata.yaml"], "light",
                        input_dir=IN, output_dir=logdir, binds=so.binds(spare))
        check("the bound config cannot be written to from inside", r.ok, False)
        check("...and is unchanged on the host", "x" == so.CONFIG_PATH.read_text().splitlines()[-1], False)

    # The cracker's two programs, started the way the agent starts them. Run
    # 183c7543fd9d (2026-10-16) failed every call before either program ran;
    # behind the mount error sat a missing /etc/john, a missing passwd, the
    # OpenCL driver list and CPU topology, and a too-small address space.
    section("live containment: john and hashcat start in the cracker profile")
    import analysis_programs as ap
    john, hashcat = ap.binary_path("john"), ap.binary_path("hashcat")
    if not (john and hashcat):
        skip("cracker programs", "john and/or hashcat are not installed")
    else:
        crack_out = tmp / "crack-out"
        crack_out.mkdir()
        binds = ap.wordlist_binds()
        r = sandbox.run([john, "--pot=/out/john.pot", "--no-log", "--list=formats"], "cracker",
                        input_dir=IN, output_dir=crack_out, binds=binds)
        check("john reads its config and lists its formats", (r.ok, "NT" in r.stdout), (True, True))
        r = sandbox.run([hashcat, "-I"], "cracker", input_dir=IN, output_dir=crack_out, binds=binds)
        check("hashcat finds its CPU OpenCL device (no SIGSEGV)",
              (r.exit_code, "Backend Device ID" in r.stdout), (0, True))
        if binds:
            r = sandbox.run(["/usr/bin/ls", "/wordlists", "/wordlists/hashcat-rules"], "cracker",
                            input_dir=IN, output_dir=crack_out, binds=binds)
            check("the wordlists and the rules inside them are both mounted", r.ok, True)
        # CPU seconds count every thread. A 4-thread john hit a 1800 s CPU
        # ceiling after ~8 wall minutes and was reported as "exit 137"
        # (run 78473136). The ceiling now scales with cores, and a CPU kill is
        # recognised from the CPU used, not the wall time.
        import dataclasses
        check("the cracker's CPU ceiling is one wall clock per core",
              sandbox.PROFILES["cracker"].cpu_seconds,
              sandbox.PROFILES["cracker"].wall_clock_s * (os.cpu_count() or 1))
        if (os.cpu_count() or 1) > 1:
            # xz -T4 is multithreaded and does not catch SIGXCPU (john does:
            # it saves its potfile and exits 1, which tool_registry reads).
            tight = dataclasses.replace(sandbox.PROFILES["light"], cpu_seconds=4, wall_clock_s=60)
            r = sandbox.run(["/bin/sh", "-c", "xz -T4 -1 -c /dev/zero > /dev/null"], tight)
            check("a multithreaded program killed at its CPU ceiling is reported as that, not a bare exit code",
                  (r.limit_hit, r.duration_s < 4), ("cpu", True))

print(f"\n{PASS} passed, {FAIL} failed, {SKIP} skipped")
if SKIP and not sandbox.available():
    print("  WARNING: containment was NOT verified on this machine.")
sys.exit(1 if FAIL else 0)
