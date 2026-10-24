#!/usr/bin/env python3
"""test_egress_backstop.py — the kernel fence for IP-scoped runs and the relay
that is their only non-target way out (audit run 1, fix 1b).

    python3 shared/test_egress_backstop.py

No root, no systemd, no network beyond loopback. What each section pins down:
  * the relay forwards CONNECT to an allowed host:port and refuses anything
    else (other hosts, other ports, plain HTTP requests) with 403/400;
  * the networks the fence allows are exactly the runner's own narrowed scope,
    exclusions removed, and a target outside it refuses the start;
  * the rendered drop-in denies everything, allows localhost plus those
    networks, points the run at the relay and refuses bpf();
  * only the Claude CLI is handed the proxy; nothing is set without a relay.
"""
import asyncio
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import agent_runtime  # noqa: E402
import egress_relay  # noqa: E402
import scope_cidr  # noqa: E402

PASS = FAIL = 0


def check(label, got, want):
    global PASS, FAIL
    if got == want:
        PASS += 1; print(f"  [ OK ] {label}")
    else:
        FAIL += 1; print(f"  [FAIL] {label}\n         got  {got!r}\n         want {want!r}")


def section(t): print(f"\n=== {t} ===")


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


section("the relay: CONNECT to the allowed endpoint only")
echo_port, relay_port = free_port(), free_port()


def echo_server():
    srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", echo_port)); srv.listen()
    while True:
        c, _ = srv.accept()
        data = c.recv(100)
        c.sendall(b"echo:" + data); c.close()


threading.Thread(target=echo_server, daemon=True).start()
loop = asyncio.new_event_loop()
threading.Thread(target=lambda: loop.run_until_complete(
    egress_relay.serve(f"127.0.0.1:{relay_port}", {f"localhost:{echo_port}"})), daemon=True).start()


def ask(request: bytes, then: bytes = b"") -> bytes:
    for _ in range(50):
        try:
            s = socket.create_connection(("127.0.0.1", relay_port), timeout=3)
            break
        except OSError:
            import time; time.sleep(0.05)
    s.sendall(request)
    reply = s.recv(200)
    if then and reply.startswith(b"HTTP/1.1 200"):
        s.sendall(then)
        reply += b"|" + s.recv(100)
    s.close()
    return reply


r = ask(f"CONNECT localhost:{echo_port} HTTP/1.1\r\nHost: x\r\n\r\n".encode(), b"hello")
check("the allowed host:port is connected and bytes flow both ways",
      r.startswith(b"HTTP/1.1 200") and r.endswith(b"echo:hello"), True)
check("another host is refused with 403",
      ask(b"CONNECT example.com:443 HTTP/1.1\r\n\r\n").startswith(b"HTTP/1.1 403"), True)
check("the allowed host on another port is refused with 403",
      ask(f"CONNECT localhost:{echo_port + 1} HTTP/1.1\r\n\r\n".encode()).startswith(b"HTTP/1.1 403"), True)
check("a plain HTTP request (not CONNECT) is refused with 400",
      ask(b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n").startswith(b"HTTP/1.1 400"), True)
check("the default allow-list is the Anthropic API alone", egress_relay.DEFAULT_ALLOW, ("api.anthropic.com:443",))

# audit run 2: systemd's agenti-relay.socket holds the port and hands it over as an fd
_held = socket.socket(); _held.bind(("127.0.0.1", 0)); _held.listen()
_held_port = _held.getsockname()[1]
_loop2 = asyncio.new_event_loop()
threading.Thread(target=lambda: _loop2.run_until_complete(
    egress_relay.serve("ignored:0", {f"localhost:{echo_port}"}, fd=_held.fileno())), daemon=True).start()
relay_port, _saved_port = _held_port, relay_port
r = ask(f"CONNECT localhost:{echo_port} HTTP/1.1\r\nHost: x\r\n\r\n".encode(), b"fd")
check("served on an inherited socket (--fd), the relay works the same",
      r.startswith(b"HTTP/1.1 200") and r.endswith(b"echo:fd"), True)
relay_port = _saved_port

section("the networks the fence allows = the runner's narrowed scope")
org = Path(tempfile.mkdtemp()) / "org"
org.mkdir()
record = json.loads((HERE / "engagement.example.json").read_text())
record["valid_from"], record["valid_until"] = "2000-01-01", "2999-01-01"
record["scope"] = {"cidr": {"in_scope": ["10.0.0.0/24 (lab)"], "out_of_scope": ["10.0.0.9 (printer)"]},
                   "domain": {"in_scope": [], "out_of_scope": []}}
(org / "engagement.json").write_text(json.dumps(record))
check("a /32 target inside the scope is the whole fence",
      [str(n) for n in scope_cidr.backstop_networks(org, "enum", "10.0.0.5", required=False)], ["10.0.0.5/32"])
nets = [str(n) for n in scope_cidr.backstop_networks(org, "trafficmon", "", required=False)]
check("no target (a passive collector) fences to the ceiling, the excluded host cut out",
      ("10.0.0.9/32" not in nets, "10.0.0.8/32" in nets, "10.0.0.10/31" in nets), (True, True, True))
for bad in ("10.0.0.9", "10.0.0.0/24", "192.0.2.1"):
    try:
        scope_cidr.backstop_networks(org, "enum", bad, required=False)
        check(f"target {bad} refuses the start", "allowed", "refused")
    except SystemExit as e:
        check(f"target {bad} refuses the start", "REFUSING" in str(e), True)
out = subprocess.run([sys.executable, str(HERE / "scope_cidr.py"), "backstop", "--org-dir", str(org),
                      "--agent", "enum", "--target-file", "/nonexistent", "--optional"],
                     capture_output=True, text=True)
check("the CLI form prints one network per line", (out.returncode, "10.0.0.8/32" in out.stdout.split()), (0, True))

section("the rendered drop-in")
lib = HERE / "capability-dropin.sh"
txt = subprocess.run(["bash", "-c", f'source "{lib}"; scope_dropin 10.0.0.5/32 10.0.1.0/24'],
                     capture_output=True, text=True, env={**os.environ, "AGENTI_RELAY_ADDR": "127.0.0.1:8429"}).stdout
lines = txt.splitlines()
check("everything is denied first", "IPAddressDeny=any" in lines, True)
check("localhost and exactly the run's networks are allowed",
      "IPAddressAllow=localhost 10.0.0.5/32 10.0.1.0/24" in lines, True)
check("the run is pointed at the relay", "Environment=AGENTI_RELAY=http://127.0.0.1:8429" in lines, True)
check("the run REQUIRES the relay's held socket (no fall-through to another listener)",
      ("Requires=agenti-relay.socket" in lines, "After=agenti-relay.socket" in lines), (True, True))
check("bpf() is refused inside the run", "SystemCallFilter=~bpf" in lines, True)

section("only the Claude CLI gets the proxy")
saved = os.environ.pop("AGENTI_RELAY", None)
check("no relay: the CLI's environment is untouched", agent_runtime.cli_env(), {})
os.environ["AGENTI_RELAY"] = "http://127.0.0.1:8429"
env = agent_runtime.cli_env()
check("with a relay the CLI is told to use it", env.get("HTTPS_PROXY"), "http://127.0.0.1:8429")
check("...and the process's own environment (what scanners inherit) has no proxy",
      ("HTTPS_PROXY" in os.environ, "https_proxy" in os.environ), (False, False))
os.environ.pop("AGENTI_RELAY")
if saved is not None:
    os.environ["AGENTI_RELAY"] = saved

print(f"\n{PASS} passed, {FAIL} failed")
sys.stdout.flush()
os._exit(1 if FAIL else 0)
