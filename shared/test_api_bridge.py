#!/usr/bin/env python3
"""test_api_bridge.py — the web tier's only way to root (shared/api_bridge.py)
and the API side that talks to it (shared/api/cli_bridge.py).

    python3 shared/test_api_bridge.py

No root, no sudo. What each section pins down:
  * every verb shared/api/main.py calls is on the bridge's list, read from
    main.py itself, so the API and the bridge cannot drift apart;
  * everything else is refused: verbs the web tier never uses (export,
    set-key, vault, set-limit, bind ...), --help anywhere, control characters,
    journalctl options on `logs`, a role on create-user (audit run 1, fix 2);
  * every secret (passwords, codes, link tokens, grants) leaves the argument
    list for the environment, and iam.py puts it back (N05);
  * the request line is read without consuming the body that follows it, and
    cli_bridge sends the command on stdin, never as sudo arguments.
"""
import ast
import io
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE / "api"))
import api_bridge as ab  # noqa: E402
import iam  # noqa: E402

PASS = FAIL = 0


def check(label, got, want):
    global PASS, FAIL
    if got == want:
        PASS += 1; print(f"  [ OK ] {label}")
    else:
        FAIL += 1; print(f"  [FAIL] {label}\n         got  {got!r}\n         want {want!r}")


def section(t): print(f"\n=== {t} ===")


_agents = Path(tempfile.mkdtemp(prefix="agenti-bridge-agents-"))
for _a in ("enum", "research"):
    (_agents / _a).mkdir()
    (_agents / _a / f"{_a}-agent.py").write_text("")
(_agents / "half-removed").mkdir()
ab.SHIPPED_AGENTS = _agents
ab.BUILT_AGENTS = _agents / "none"


def allowed(argv):
    try:
        ab.check(argv)
        return True
    except ab.Refused:
        return False


section("every verb the API calls is on the bridge's list (read from main.py)")
tree = ast.parse((HERE / "api" / "main.py").read_text())
CALLS = {"_call", "_call_text", "_call_bytes", "run_agenti", "run_agenti_text", "run_agenti_bytes"}
seen = set()


def shape(args) -> list[str]:
    """The literal verb words of one call, with stand-ins for the names."""
    words = []
    for a in args[:3]:
        if isinstance(a, ast.Constant) and isinstance(a.value, str):
            words.append(a.value)
        elif isinstance(a, ast.Name) and a.id in ("agent", "scope_agent"):
            words.append("enum")
        elif isinstance(a, ast.Name) and a.id in ("team", "name"):
            words.append("myteam")
        elif isinstance(a, ast.JoinedStr):
            words.append("action-approve")                     # f"action-{body.decision}"
        else:
            break
    return words


for node in ast.walk(tree):
    if isinstance(node, ast.List) and node.elts and isinstance(node.elts[0], (ast.Constant, ast.Name)):
        words = shape(node.elts)
    elif isinstance(node, ast.Call) and getattr(node.func, "id", getattr(node.func, "attr", None)) in CALLS | {"_call_stdin", "_attach"}:
        words = shape(node.args[1:] if getattr(node.func, "id", "") in ("_call_stdin", "_attach") else node.args)
    else:
        continue
    if not words or words[0] not in ("admin", "team", "engagement", "docs", "dashboard", "agents", "enum"):
        continue
    if words[0] == "enum" and len(words) < 2:
        continue
    seen.add(tuple(words[:3] if words[0] == "team" else words[:2]))
missing = sorted(w for w in seen if not allowed(list(w) + ["--json"]))
check(f"all {len(seen)} verb shapes the API uses pass the bridge", missing, [])

section("everything else is refused")
for argv in (["enum", "export"], ["enum", "set-key"], ["enum", "purge"], ["vault", "lock"],
             ["vault", "lock", "--help"], ["enum", "status", "--help"], ["admin", "set-limit", "runs", "1"],
             ["admin", "bind", "user", "x", "--role", "admin"], ["admin", "issue-key"], ["admin", "user", "add", "x"],
             ["admin", "set-policy", "require-2fa", "off"], ["setup"], ["verify"], ["gui", "configure"],
             ["new", "x"], ["enum", "logs", "--vacuum-time=1s"], ["enum", "logs", "-n", "5", "+", "_COMM=sudo"],
             ["enum", "logs", "-f"], ["admin", "create-user", "x", "--kind", "user", "--role", "admin"],
             ["admin", "create-user", "x", "--role=admin"], ["../x", "status"], ["Enum", "status"],
             ["enum", "say", "line\nsecond"], ["engagement", "import"], ["team", "x", "purge"], [],):
    check(f"refused: {argv}", allowed(argv) if argv else False, False)
check("create-user with a role passes only together with its approval grant",
      (allowed(["admin", "create-user", "x", "--kind", "user", "--role", "admin", "--grant=G"]),
       allowed(["admin", "create-user", "x", "--kind", "user", "--role", "admin"])), (True, False))
check("decision 6: only 'vault enable' with its grant reaches root; every other vault verb is refused",
      (allowed(["vault", "enable", "--size=8G", "--grant=G", "--json"]),
       allowed(["vault", "enable", "--size=8G"]),
       allowed(["vault", "unlock"]), allowed(["vault", "disable", "--grant=G"]),
       allowed(["vault", "enable", "--size=8G", "--grant=G", "--passphrase-stdin"])),
      (True, False, False, False, False))
check("logs with -n N and the run options passes", allowed(["enum", "logs", "-n", "50", "--owner", "op1", "--copy", "run-ab12cd34", "--json"]), True)

section("audit run 2: only an installed agent's name opens the agent verbs")
for argv in (["new", "start", "--dir=/etc/x"], ["new", "status"], ["gui", "status"], ["setup", "show"],
             ["verify", "status"], ["help", "show"], ["outputs", "status"], ["tool-requests", "status"],
             ["half-removed", "status"], ["nosuchagent", "status"]):
    check(f"refused: {argv}", allowed(argv), False)
check("an installed agent still passes", allowed(["research", "status", "--json"]), True)

section("secrets leave the command line (N05)")
argv, env = ab.hide_secrets(["admin", "enrol-consume", "TOKEN123", "--new", "pw1", "--totp-secret", "S", "--totp-code", "123456", "--json"])
flat = " ".join(argv)
check("no password, code, secret or token is left in the arguments",
      any(x in flat for x in ("TOKEN123", "pw1", " S ", "123456")), False)
check("they are in the environment instead", sorted(env.values()), sorted(["TOKEN123", "pw1", "S", "123456"]))
argv2, env2 = ab.hide_secrets(["admin", "reset-user-password", "bob", "--new=pw2", "--grant=G1", "--json"])
check("--opt=value secrets are moved too", (any("pw2" in a or "G1" in a for a in argv2), sorted(env2.values())),
      (False, ["G1", "pw2"]))
check("non-secret values are untouched", ab.hide_secrets(["enum", "say", "--new", "x"])[0][:2], ["enum", "say"])
os.environ.update(env)
check("iam.py puts every value back", iam.resolve_env_args(argv),
      ["admin", "enrol-consume", "TOKEN123", "--new", "pw1", "--totp-secret", "S", "--totp-code", "123456", "--json"])
check("iam.py reads only AGENTI_ARG_<n>, never another variable", iam.resolve_env_args(["--new=@env:HOME"]), ["--new=@env:HOME"])

section("the request line is read without touching the body")
r, w = os.pipe()
os.write(w, b'{"argv": ["enum", "attach", "-"]}\nBODY-BYTES')
os.close(w)
check("the argv comes from the first line", ab._read_request(r), ["enum", "attach", "-"])
check("the body is still there for agenti", os.read(r, 100), b"BODY-BYTES")
for bad in (b"not json\n", b'{"argv": "enum"}\n', b'{"argv": []}\n', b'["enum"]\n'):
    r, w = os.pipe(); os.write(w, bad); os.close(w)
    try:
        ab._read_request(r)
        check(f"a malformed request is refused: {bad!r}", "accepted", "refused")
    except ab.Refused:
        check(f"a malformed request is refused: {bad!r}", True, True)

section("cli_bridge sends the command on stdin, never as sudo arguments")
import cli_bridge  # noqa: E402
fake = Path(tempfile.mkdtemp()) / "fake_bridge.py"
fake.write_text("import sys,json\nline=sys.stdin.buffer.readline()\nbody=sys.stdin.buffer.read()\n"
                "print(json.dumps({'argv_given': sys.argv[1:], 'request': json.loads(line), 'body': body.decode()}))\n")
seen_cmd = []
_real = subprocess.Popen


def fake_popen(cmd, **kw):
    seen_cmd.append(cmd)
    return _real([sys.executable, str(fake)], **kw)


cli_bridge.subprocess.Popen = fake_popen
try:
    out = cli_bridge.run_agenti("admin", "enrol-consume", "TOK", "--new", "pw")
    check("sudo is given the bridge and nothing else", seen_cmd[-1], ["sudo", "-n", cli_bridge.API_BRIDGE])
    check("the bridge itself got no arguments", out["argv_given"], [])
    check("the command arrived as one JSON line", out["request"], {"argv": ["admin", "enrol-consume", "TOK", "--new", "pw", "--json"]})
    out = cli_bridge.run_agenti("enum", "attach", "-", stdin_file=io.BytesIO(b"file-bytes"))
    check("a body follows the line", out["body"], "file-bytes")
finally:
    cli_bridge.subprocess.Popen = _real

section("the API and the CLI hash an engagement change the same way (F13)")
import hashlib  # noqa: E402
import re  # noqa: E402
_cli = (HERE / "agenti").read_text()
_m = re.search(r"_engagement_change_sha\(\) \{.*?python3 -c '([^']*)' \"\$@\"", _cli, re.S)
check("the CLI's hashing helper is found", bool(_m), True)
_change = ["--engagement-id", "E-1", "--client", "Ünïcode Ltd", "--cidr-in", "192.0.2.0/24 (lab)", "--notes", ""]
_cli_sha = subprocess.run([sys.executable, "-c", _m.group(1), *_change], capture_output=True, text=True).stdout.strip()
check("same arguments, same SHA-256 (non-ASCII and empty values included)",
      _cli_sha, hashlib.sha256(json.dumps(_change).encode()).hexdigest())

section("the bridge refuses to run except through sudo")
proc = subprocess.run([sys.executable, str(HERE / "api_bridge.py")], input=b'{"argv":["agents"]}\n',
                      capture_output=True)
check("run as a normal user it refuses", (proc.returncode, b"REFUSING" in proc.stdout),
      (2 if os.geteuid() != 0 else proc.returncode, os.geteuid() != 0))

section("audit run 2: root's raw output never reaches the browser")
_secret = "root:$y$planted-shadow-line"
for _rc, _out in ((1, _secret), (1, '{"not_error": "' + _secret + '"}'), (1, "")):
    try:
        cli_bridge._fail_text(_rc, _out, _secret)
        check("a failure raises", False, True)
    except cli_bridge.AgentiError as e:
        check(f"failure output {_out[:12]!r}...: the message names a reference, not the bytes",
              (_secret in str(e), "ref " in str(e)), (False, True))
try:
    cli_bridge._fail_text(1, '{"error": "REFUSING: plain reason"}', "")
except cli_bridge.AgentiError as e:
    check("the CLI's own JSON error still reaches the user as written", str(e), "REFUSING: plain reason")
_real_run = cli_bridge._run
cli_bridge._run = lambda *a, **k: subprocess.CompletedProcess(a, 0, _secret + "\n", "")
try:
    cli_bridge._run_agenti_uncached("enum", "status")
    check("non-JSON success output raises", False, True)
except cli_bridge.AgentiError as e:
    check("non-JSON success output: a reference, not the bytes", (_secret in str(e), e.status_code), (False, 502))
finally:
    cli_bridge._run = _real_run

section("audit run 2: link tokens never reach the access log")
import logging as _lg
_src = (HERE / "api" / "main.py").read_text()
_snip = _src[_src.index("_LINK_PATH = re.compile"):_src.index('logging.getLogger("uvicorn.access").addFilter')]
_ns = {"re": __import__("re"), "logging": _lg}
exec(_snip, _ns)
_f = _ns["_RedactLinkTokens"]()
for path, want in (("/enrol/AbC-123_xyz", "/enrol/<token>"), ("/password-reset/T0k3n?x=1", "/password-reset/<token>?x=1"),
                   ("/agents/enum/status", "/agents/enum/status")):
    _rec = _lg.LogRecord("uvicorn.access", _lg.INFO, "", 0, '%s - "%s %s HTTP/%s" %d',
                         ("10.0.0.1:5", "GET", path, "1.1", 200), None)
    _f.filter(_rec)
    check(f"access log line for {path}", _rec.getMessage(), f'10.0.0.1:5 - "GET {want} HTTP/1.1" 200')
check("the filter is installed on uvicorn's access logger", 'logging.getLogger("uvicorn.access").addFilter(_RedactLinkTokens())' in _src, True)

section("first-run setup: the setup page answers only the machine itself")
_snip = _src[_src.index("_FORWARDING_HEADERS = ("):_src.index("class SetupAdminRequest")]


class _Hdrs(dict):
    def get(self, k, d=None):
        return super().get(k.lower(), d)


class _Req:
    def __init__(self, peer, headers):
        self.client = type("C", (), {"host": peer})()
        self.headers = _Hdrs({k.lower(): v for k, v in headers.items()})


for header_cfg in ("", "CF-Connecting-IP"):
    _ns = {"CLIENT_IP_HEADER": header_cfg, "Request": object}
    exec(_snip, _ns)
    local = _ns["_setup_is_local"]
    for label, peer, hdrs, want in (
            ("the box's own browser", "127.0.0.1", {"host": "127.0.0.1:8420"}, True),
            ("...as localhost, with its own Origin", "127.0.0.1",
             {"host": "localhost:8420", "origin": "http://localhost:8420"}, True),
            ("...over IPv6", "::1", {"host": "[::1]:8420"}, True),
            ("an ssh -L tunnel (loopback, no proxy header)", "127.0.0.1", {"host": "127.0.0.1:18420"}, True),
            ("another computer", "198.51.100.20", {"host": "198.51.100.5:8420"}, False),
            ("a tunnel or proxy on the box (says so in a header)", "127.0.0.1",
             {"host": "127.0.0.1:8420", "x-forwarded-for": "203.0.113.9"}, False),
            ("Cloudflare Tunnel", "127.0.0.1", {"host": "agenti.example.com", "cf-connecting-ip": "203.0.113.9"}, False),
            ("loopback peer but a public Host (DNS rebinding)", "127.0.0.1", {"host": "evil.example:8420"}, False),
            ("loopback peer, page posted from another site", "127.0.0.1",
             {"host": "127.0.0.1:8420", "origin": "https://evil.example"}, False),
            ("a Forwarded header", "127.0.0.1", {"host": "127.0.0.1", "forwarded": "for=203.0.113.9"}, False)):
        check(f"[{header_cfg or 'direct'}] {label}", local(_Req(peer, hdrs)), want)

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
