#!/usr/bin/env python3
"""test_tool_registry.py — the vetted tool library (shared/tool_registry.py).

    python3 shared/test_tool_registry.py

No root, no vault, no venv, no real network — every tool factory is built
against a FAKE `claude_agent_sdk` (installed into sys.modules before import,
same "the dev sandbox has no SDK" situation test_team_channel.py already
documents) whose `tool(name, desc, schema)` decorator does structurally what
the real one does for every call site in this codebase: it returns the
`async def foo(args)` callable itself, awaitable with a plain dict, with the
name/description/schema attached as attributes. Nothing about the SDK's
actual MCP wire protocol is exercised or asserted — only that a registry
entry, once built, behaves exactly like its original agent-embedded
predecessor when called the way the SDK calls it.

WHAT THIS PINS DOWN: phase 2 of the generic-launcher arc moved eight tools
(enum's run_scan/read_scan, research's fetch_page/read_page/web_search,
trafficmon's list_evidence/read_evidence/capture_host) out of three agent
files and into one shared registry, unifying the three read/retrieve tools
and the path-traversal guard that were duplicated near-verbatim. The whole
point of that move was "prove no behavior change" — so every case below
reproduces a documented behavior from the ORIGINAL agent code (scope
denial, path-traversal refusal, truncation, the caps, the exact ledger
shapes) and checks the registry-built tool still does it.
"""
import asyncio
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

# ---------------------------------------------------------------------------
# A structurally-faithful fake of claude_agent_sdk, installed BEFORE
# tool_registry is imported. Every factory in that module imports `tool`
# lazily inside its own build() function specifically so this works.
# ---------------------------------------------------------------------------
_fake_sdk = types.ModuleType("claude_agent_sdk")


def _fake_tool(name, description, schema):
    def decorator(fn):
        fn.tool_name = name
        fn.description = description
        fn.input_schema = schema
        return fn
    return decorator


_fake_sdk.tool = _fake_tool
sys.modules.setdefault("claude_agent_sdk", _fake_sdk)

import tool_registry as tr  # noqa: E402

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


def run(coro):
    return asyncio.run(coro)


class FakeLog:
    def __init__(self):
        self.lines = []
    def info(self, fmt, *a):
        self.lines.append(fmt % a if a else fmt)
    def warning(self, fmt, *a):
        self.lines.append(fmt % a if a else fmt)


class FakeCIDRScope:
    """Mirrors shared/scope_cidr.py's contains() shape closely enough to
    drive the tools: (ok, reason), checked against a list of ipaddress
    networks passed as `scope_ceiling`."""
    def contains(self, target, ceiling):
        import ipaddress
        try:
            t = ipaddress.ip_network(target, strict=False)
        except ValueError:
            return False, f"'{target}' is not a valid IP/CIDR"
        for net in ceiling:
            if t.subnet_of(net) or t == net:
                return True, "in scope"
        return False, f"{target} is outside the authorized scope"


class FakeDomainScope:
    def contains(self, target, ceiling):
        from urllib.parse import urlsplit
        host = (urlsplit(target).hostname or target).lower()
        for d in ceiling:
            if host == d or host.endswith("." + d):
                return True, "in scope"
        return False, f"'{host}' is not in the authorized domain(s)"


tmp = Path(tempfile.mkdtemp(prefix="agenti-tool-registry-test-"))


def fresh_ctx(**kw):
    d = tmp / f"wd-{len(list(tmp.iterdir()))}"
    d.mkdir()
    defaults = dict(log=FakeLog(), workdir=d, trim_bytes=200, max_return_bytes=200)
    defaults.update(kw)
    return tr.ToolContext(**defaults)


# ===========================================================================
section("registry contents and metadata")
# ===========================================================================
check("twelve tools registered (enum, research, trafficmon and file-analysis families)",
      sorted(tr.REGISTRY), sorted([
    "run_scan", "read_scan", "fetch_page", "fetch_external", "read_page", "web_search",
    "list_evidence", "read_evidence", "capture_host", "analyze_file", "read_output",
    "extract_hashes"]))
check("every spec has real metadata", all(
    spec.category and spec.scope_kind in ("cidr", "domain", "files")
    for spec in tr.REGISTRY.values()), True)
check("registering a duplicate name is refused", True, True)
try:
    tr._register(tr.ToolSpec(name="run_scan", category="x", purpose="x", schema={},
                             scope_kind="none", network=False, build=lambda ctx: None))
    check("...proven", False, True)
except ValueError:
    check("...proven", True, True)
try:
    tr.ToolSpec(name="x", category="x", purpose="x", schema={}, scope_kind="none",
               network=False)
    check("a ToolSpec with no build() is refused", False, True)
except ValueError:
    check("a ToolSpec with no build() is refused", True, True)

try:
    tr.build_tools(["no-such-tool"], fresh_ctx())
    check("build_tools on an unknown name raises", False, True)
except KeyError as e:
    check("build_tools on an unknown name raises", "Known:" in str(e), True)


# ===========================================================================
section("safe_path — the unified traversal guard")
# ===========================================================================
base = tmp / "safe-base"; (base / "sub").mkdir(parents=True)
(base / "sub" / "f.txt").write_text("x")
check("a nested valid path resolves", tr.safe_path(base, "sub/f.txt"),
      (base / "sub" / "f.txt").resolve())
check("empty input refused", tr.safe_path(base, ""), None)
check("a sibling directory with a shared prefix is NOT wrongly allowed",
      tr.safe_path(base, "../safe-base-evil/x.txt"), None)
check("classic .. traversal refused", tr.safe_path(base, "../../etc/passwd"), None)
check("None base refused (no crash)", tr.safe_path(None, "x"), None)
(tmp / "safe-base-evil").mkdir(exist_ok=True)


# ===========================================================================
section("retrieve — grep / line-range, shared by all three read tools")
# ===========================================================================
f = tmp / "retrieve-test.txt"
f.write_text("\n".join(f"line {i}" for i in range(1, 21)))
body, label = tr.retrieve(f, pattern=None, start_line=None, end_line=None, max_return_bytes=10_000)
check("default range starts at 1, spans 80 lines (all 20 shown)", body.count("\n") + 1, 20)
check("...label uses the UNCLAMPED end (faithful to the original: the label "
      "was never clamped to the file length there either)", label, "lines 1-81")
body, label = tr.retrieve(f, pattern=None, start_line=5, end_line=7, max_return_bytes=10_000)
check("explicit range", body, "L5: line 5\nL6: line 6\nL7: line 7")
body, label = tr.retrieve(f, pattern="line 1[0-9]", start_line=None, end_line=None, max_return_bytes=10_000)
check("grep matches lines 10-19", body.count("\n") + 1, 10)
check("grep label", label, "grep 'line 1[0-9]'")
body, label = tr.retrieve(f, pattern="nomatch", start_line=None, end_line=None, max_return_bytes=10_000)
check("grep no-match text", body, "(no matches)")
body, _ = tr.retrieve(f, pattern=None, start_line=1, end_line=100, max_return_bytes=5)
check("max_return_bytes truncation is the CALLER's job (retrieve returns full body)",
      len(body) > 5, True)


# ===========================================================================
section("run_scan / read_scan (enum family)")
# ===========================================================================
ctx = fresh_ctx(scope=FakeCIDRScope())
import ipaddress
import recon_programs
# A harmless stand-in program with a reviewed (empty) option list: plain
# arguments are IP targets. Real programs have their lists in recon_programs.
recon_programs.PROGRAMS["echo"] = recon_programs.Program("echo", {}, positional="targets", min_positional=0)
ctx.scope_ceiling = [ipaddress.ip_network("10.0.0.0/24")]
run_scan = tr.REGISTRY["run_scan"].build(
    ctx, allowed_binaries={"echo"}, denied_patterns=[r"[;&|]", r"`|\$\(", r">|>>"])

r = run(run_scan({"command": "echo hi"}))
check("no IP target: denied (matches enum's original rule)", r["is_error"], True)
check("...reason", r["content"][0]["text"].startswith("DENIED: target 'hi' is not a literal IP or CIDR"), True)

r = run(run_scan({"command": "nmap 10.0.0.5"}))
check("binary not on the allow-list: denied", "not in the allow-list" in r["content"][0]["text"], True)

r = run(run_scan({"command": "echo 10.0.0.5; rm -rf /"}))
check("shell metacharacters denied even though 'echo' is allowed",
      "denied pattern" in r["content"][0]["text"], True)

r = run(run_scan({"command": "echo 172.16.0.5"}))
check("out-of-scope target denied", "outside the authorized scope" in r["content"][0]["text"], True)

r = run(run_scan({"command": "echo 10.0.0.5"}))
check("an allowed, in-scope, harmless command succeeds", r.get("is_error"), None)
check("...and is recorded ok in ctx.actions with the ORIGINAL shape ({'command':...})",
      ctx.actions[-1], {"command": "echo 10.0.0.5", "verdict": "ok",
                        "output": ctx.actions[-1]["output"]})
saved = ctx.workdir / ctx.actions[-1]["output"]
check("...and the full output is saved to workdir", saved.exists() and "10.0.0.5" in saved.read_text(), True)
check("...summary names the saved file for read_scan", ctx.actions[-1]["output"] in r["content"][0]["text"], True)

read_scan = tr.REGISTRY["read_scan"].build(ctx)
r = run(read_scan({"file": ctx.actions[-1]["output"]}))
check("read_scan retrieves the saved output", "10.0.0.5" in r["content"][0]["text"], True)
_n_before_missing_read = len(ctx.actions)
r = run(read_scan({"file": "../../etc/passwd"}))
check("read_scan refuses traversal", r["is_error"], True)
check("...enum's original 'No such saved scan.' message", r["content"][0]["text"], "No such saved scan.")
check("read_scan does NOT add a denied ledger entry on missing file (matches enum original)",
      len(ctx.actions), _n_before_missing_read)


section("run_scan: a program approved mid-run (phase 7) and one that is not installed")
for _name in ("printf", "definitely-not-installed-xyz"):
    recon_programs.PROGRAMS[_name] = recon_programs.Program(_name, {}, positional="targets", min_positional=0)
granted = {"progs": set(), "pats": []}
ctx_g = fresh_ctx(scope=FakeCIDRScope())
ctx_g.scope_ceiling = [ipaddress.ip_network("10.0.0.0/24")]
rs_g = tr.REGISTRY["run_scan"].build(
    ctx_g, allowed_binaries={"echo"}, denied_patterns=[r"[;&|]"],
    dynamic_allow=lambda: (set(granted["progs"]), list(granted["pats"])))
r = run(rs_g({"command": "printf 10.0.0.5"}))
check("a program not yet approved is refused", "not in the allow-list" in r["content"][0]["text"], True)
granted["progs"] = {"printf"}
r = run(rs_g({"command": "printf 10.0.0.5"}))
check("the SAME tool object allows it once approved (checked at call time, not frozen at build)",
      r.get("is_error"), None)
granted["pats"] = [r"--forbidden"]
r = run(rs_g({"command": "printf --forbidden 10.0.0.5"}))
check("a granted program's own argument rules still apply", "denied pattern" in r["content"][0]["text"], True)
r = run(rs_g({"command": "printf 172.16.0.5"}))
check("a granted program is still scope-checked", "outside the authorized scope" in r["content"][0]["text"], True)
granted["progs"] = set()
check("withdrawing the grant refuses it again immediately",
      "not in the allow-list" in run(rs_g({"command": "printf 10.0.0.5"}))["content"][0]["text"], True)
rs_n = tr.REGISTRY["run_scan"].build(ctx_g, allowed_binaries={"definitely-not-installed-xyz"}, denied_patterns=[])
r = run(rs_n({"command": "definitely-not-installed-xyz 10.0.0.5"}))
check("an allowed but uninstalled program is a clean message, not a crash",
      (r["is_error"], "not installed" in r["content"][0]["text"]), (True, True))

section("run_scan runs each program in an empty folder of its own (audit run 2)")
recon_programs.PROGRAMS["pwd"] = recon_programs.Program("pwd", {}, positional="targets", min_positional=0,
                                                         needs_target=False)
rs_p = tr.REGISTRY["run_scan"].build(ctx_g, allowed_binaries={"pwd"}, denied_patterns=[])
r = run(rs_p({"command": "pwd"}))
_cwd = (ctx_g.workdir / ctx_g.actions[-1]["output"]).read_text().strip()
check("the program's working folder is not the run's slot", _cwd not in (str(ctx_g.workdir), os.getcwd()), True)
check("...and it is removed afterwards", Path(_cwd).exists(), False)
for _name in ("env", "ls"):
    recon_programs.PROGRAMS[_name] = recon_programs.Program(_name, {}, positional="targets",
                                                             min_positional=0, needs_target=False)
r = run(tr.REGISTRY["run_scan"].build(ctx_g, allowed_binaries={"env"}, denied_patterns=[])({"command": "env"}))
_home = [ln for ln in (ctx_g.workdir / ctx_g.actions[-1]["output"]).read_text().splitlines()
         if ln.startswith("HOME=")]
check("...and is its home too (a program's settings folder must be writable)",
      bool(_home) and _home[0] != f"HOME={ctx_g.workdir}" and "run_scan-" in _home[0], True)
r = run(tr.REGISTRY["run_scan"].build(ctx_g, allowed_binaries={"ls"}, denied_patterns=[])(
    {"command": "ls 10.0.0.5"}))
_out = (ctx_g.workdir / ctx_g.actions[-1]["output"]).read_text()
check("a program's error output is kept in the saved result, with its exit code",
      "--- error output (exit 2) ---" in _out and "10.0.0.5" in _out, True)

section("cracker output: never through a link the sandbox left (audit run 2)")
_cv = tmp / "crack-victim.txt"; _cv.write_text("KEEP")
_cw = tmp / "crack-wd"; _cw.mkdir()
(_cw / "out.txt").symlink_to(_cv)
with tr._fresh_output(_cw / "out.txt") as _fo:
    _fo.write(b"line1\nline2\n")
    check("the output file is created fresh, not through the planted link",
          (_cv.read_text(), (_cw / "out.txt").is_symlink()), ("KEEP", False))
    check("...and is read back through the same descriptor", tr._count_lines_and_head_fd(_fo, 5), (2, "line1"))
(_cw / "john.pot").symlink_to(_cv)
check("a potfile that is a link reports no size (its target is never read)", tr._plain_size(_cw / "john.pot"), None)
(_cw / "cracked.txt").write_text("abc")
check("a plain cracked.txt reports its size", tr._plain_size(_cw / "cracked.txt"), 3)

section("run_scan never blocks the run's clock, and stops at the run's limit (audit run 2)")
import agent_runtime as _art
recon_programs.PROGRAMS["sleep"] = recon_programs.Program("sleep", {}, positional="ldapfilter",
                                                           min_positional=1, needs_target=False)
rs_s = tr.REGISTRY["run_scan"].build(ctx_g, allowed_binaries={"sleep"}, denied_patterns=[])


async def _scan_under_deadline():
    ticks = [0]

    async def ticker():
        while True:
            await asyncio.sleep(0.1); ticks[0] += 1
    t = asyncio.create_task(ticker())
    t0 = time.monotonic()
    async with asyncio.timeout(5) as d:
        _art.bind_run_deadline(d)
        d.reschedule(asyncio.get_running_loop().time() + 2)
        r = await rs_s({"command": "sleep 30"})
    t.cancel()
    return r, time.monotonic() - t0, ticks[0]
_r, _took, _ticks = asyncio.run(_scan_under_deadline())
_art.bind_run_deadline(None)
check("a 30 s program under a run with 2 s left is cut at the run's limit",
      (_r.get("is_error"), "run's own time limit" in _r["content"][0]["text"], _took < 4), (True, True, True))
check("...and the event loop kept running meanwhile (the clock can fire)", _ticks >= 5, True)

section("a model's regex cannot hold the run (audit run 2)")
_slow = tmp / "slow.txt"; _slow.write_text("a" * 40 + "b\nplain line\n")
_t0 = time.monotonic()
tr.GREP_TIMEOUT_S, _keep = 1, tr.GREP_TIMEOUT_S
_body, _ = tr.retrieve(_slow, pattern="(a+)+$", start_line=None, end_line=None, max_return_bytes=4000)
tr.GREP_TIMEOUT_S = _keep
check("a catastrophic pattern is stopped and explained", ("took longer than" in _body, time.monotonic() - _t0 < 5),
      (True, True))
check("an ordinary pattern still matches", tr.retrieve(_slow, pattern="PLAIN", start_line=None, end_line=None,
                                                       max_return_bytes=4000)[0], "L2: plain line")
try:
    tr.retrieve(_slow, pattern="(", start_line=None, end_line=None, max_return_bytes=4000)
    check("a bad pattern still raises re.error for the caller", "no error", "re.error")
except re.error:
    check("a bad pattern still raises re.error for the caller", "re.error", "re.error")

section("read_scan: the OSError guard extended from trafficmon to all three")
odir = ctx.workdir / "a-directory.txt"
odir.mkdir()   # exists() is True, but read_text() raises IsADirectoryError (an OSError)
r = run(read_scan({"file": "a-directory.txt"}))
check("an unreadable (not merely missing) path is reported gracefully, not raised", r["is_error"], True)
check("...with the OSError text", "Unreadable:" in r["content"][0]["text"], True)


# ===========================================================================
section("fetch_page / read_page / web_search (research family)")
# ===========================================================================
def fake_http_get(url):
    if "fail" in url:
        return None, "connection refused"
    return {"status": 200, "content_type": "text/html", "text":
            f"<html><title>T</title><body>hello <a href='https://sub.example.com/x'>l</a> "
            f"<a href='https://evil.example/y'>l2</a></body></html>", "truncated": False}, None


def fake_extract(html, base_url):
    from urllib.parse import urljoin
    return "T", "hello", [urljoin(base_url, "https://sub.example.com/x"),
                          urljoin(base_url, "https://evil.example/y")]


def fake_page_filename(url):
    from urllib.parse import urlsplit
    host = urlsplit(url).hostname or "unknown"
    return f"{host}.html"


ctx = fresh_ctx(scope=FakeDomainScope(), scope_ceiling=["example.com"])
fetch_page = tr.REGISTRY["fetch_page"].build(
    ctx, http_get=fake_http_get, extract_html=fake_extract,
    page_filename=fake_page_filename, max_fetches_per_run=3)

r = run(fetch_page({"url": "https://evil.example/"}))
check("out-of-domain URL denied", r["is_error"], True)

r = run(fetch_page({"url": "https://sub.example.com/ok"}))
check("in-domain fetch succeeds", r.get("is_error"), None)
check("saved with the ORIGINAL filename function's output (host-based, port-safe)",
      (ctx.workdir / "sub.example.com.html").exists(), True)
check("in-scope link is offered, out-of-scope link is not, but mentioned",
      ("sub.example.com/x" in r["content"][0]["text"],
       "evil.example/y" in r["content"][0]["text"],
       "out-of-scope link" in r["content"][0]["text"]),
      (True, False, True))
check("action ledger uses research's original shape ({'action':...})",
      ctx.actions[-1]["action"], "fetch_page https://sub.example.com/ok")

for i in range(5):
    run(fetch_page({"url": f"https://sub.example.com/{i}"}))
r = run(fetch_page({"url": "https://sub.example.com/last"}))
check("fetch cap enforced (max_fetches_per_run=3)", "already fetched 3 pages" in r["content"][0]["text"], True)

r = run(fetch_page({"url": "https://fail.example.com/"}))
# capped already, so this also hits the cap first — use a fresh ctx to test the error path cleanly
ctx2 = fresh_ctx(scope=FakeDomainScope(), scope_ceiling=["example.com"])
fetch_page2 = tr.REGISTRY["fetch_page"].build(
    ctx2, http_get=fake_http_get, extract_html=fake_extract,
    page_filename=fake_page_filename, max_fetches_per_run=3)
r = run(fetch_page2({"url": "https://fail.example.com/"}))
check("a fetch failure is reported, not raised", r["is_error"], True)
check("...with the underlying error", "connection refused" in r["content"][0]["text"], True)

read_page = tr.REGISTRY["read_page"].build(ctx)
r = run(read_page({"file": "sub.example.com.html"}))
check("read_page retrieves the saved page", "hello" in r["content"][0]["text"], True)


def fake_search_backend(query, key):
    return [{"title": "In", "url": "https://sub.example.com/found", "description": "d"},
            {"title": "Out", "url": "https://evil.example/found", "description": "d"}], None


def domain_join(domains):
    return " OR ".join(f"site:{d}" for d in domains)


import os
ctx3 = fresh_ctx(scope=FakeDomainScope(), scope_ceiling=["example.com"])
web_search_nokey = tr.REGISTRY["web_search"].build(
    ctx3, search_backend=fake_search_backend, api_key_env="AGENTI_TEST_NO_SUCH_KEY_XYZ",
    max_searches_per_run=2, domain_join=domain_join)
r = run(web_search_nokey({"query": "x"}))
check("no API key configured: denied with the setup instructions", r["is_error"], True)
check("...names the env var", "AGENTI_TEST_NO_SUCH_KEY_XYZ" in r["content"][0]["text"], True)

os.environ["AGENTI_TEST_SEARCH_KEY"] = "fake-key"
ctx4 = fresh_ctx(scope=FakeDomainScope(), scope_ceiling=["example.com"])
web_search = tr.REGISTRY["web_search"].build(
    ctx4, search_backend=fake_search_backend, api_key_env="AGENTI_TEST_SEARCH_KEY",
    max_searches_per_run=5, domain_join=domain_join)
r = run(web_search({"query": "widgets", "target_only": True}))
check("target_only: results filtered to in-scope only (belt-and-suspenders, layer 2)",
      ("sub.example.com/found" in r["content"][0]["text"],
       "evil.example/found" in r["content"][0]["text"]), (True, False))
r = run(web_search({"query": "widgets"}))
t = r["content"][0]["text"]
check("default: the whole public web comes back (background research)",
      ("sub.example.com/found" in t, "evil.example/found" in t), (True, True))
check("...each result says whether it is inside the target scope",
      ("[in scope]" in t, "outside" in t), (True, True))
check("...and snippets are labelled untrusted", "untrusted" in t, True)
import scope_domain
ctx4.extra["engagement_ceiling"] = scope_domain.DomainCeiling(["example.com", "evil.example"])
t = run(web_search({"query": "tagged"}))["content"][0]["text"]
check("a result inside the engagement but outside this run's target is tagged do-not-read",
      "[excluded or outside this run's target" in t, True)
ctx4.extra.pop("engagement_ceiling")
for _i in range(2):
    run(web_search({"query": "again"}))
r = run(web_search({"query": "third"}))
check("search cap enforced", "already made 5 searches" in r["content"][0]["text"], True)
del os.environ["AGENTI_TEST_SEARCH_KEY"]

r = run(web_search({"query": ""}))
check("empty query denied without spending a call", "empty query" in r["content"][0]["text"], True)


section("fetch_external (read-only background reading of other public sites)")
ctxe = fresh_ctx(scope=FakeDomainScope(), scope_ceiling=["example.com"])
fetch_external = tr.REGISTRY["fetch_external"].build(
    ctxe, http_get=fake_http_get, extract_html=fake_extract,
    page_filename=fake_page_filename, max_external_per_run=2)
r = run(fetch_external({"url": "https://news.example.org/story"}))
check("an outside public page is read", r.get("is_error", False), False)
check("...labelled as untrusted outside content", "EXTERNAL SITE" in r["content"][0]["text"] and "Untrusted" in r["content"][0]["text"], True)
check("...recorded as an external action naming the host",
      (ctxe.actions[-1].get("external"), ctxe.actions[-1].get("host")), (True, "news.example.org"))
check("...saved so read_page can grep it", (ctxe.workdir / "news.example.org.html").exists(), True)
r = run(fetch_external({"url": "https://sub.example.com/x"}))
check("the TARGET's own pages are refused here (probing stays fetch_page's job)",
      (r["is_error"], "fetch_page" in r["content"][0]["text"]), (True, True))
for bad, why in (("ftp://x.example.org/f", "scheme"), ("https://user:pw@news.example.org/", "credentials"),
                 ("not a url", "relative")):
    check(f"refused: {why}", run(fetch_external({"url": bad}))["is_error"], True)
_fake_scope, ctxe.scope = ctxe.scope, scope_domain.DomainScope("research")
ctxe.scope_ceiling = scope_domain.DomainCeiling(["example.com"], ["payroll.example.com"])
r = run(fetch_external({"url": "https://payroll.example.com/"}))
check("audit run 2: an EXCLUDED host of the engagement is refused, not read as 'outside'",
      (r["is_error"], "belongs to the engagement" in r["content"][0]["text"]), (True, True))
ctxe.extra["engagement_ceiling"] = scope_domain.DomainCeiling(["example.com", "example.org"], [])
ctxe.scope_ceiling = scope_domain.DomainCeiling(["example.com"], [])
r = run(fetch_external({"url": "https://www.example.org/"}))
check("...and so is an engagement host outside this run's -t target",
      (r["is_error"], "belongs to the engagement" in r["content"][0]["text"]), (True, True))
ctxe.extra.pop("engagement_ceiling")
ctxe.scope, ctxe.scope_ceiling = _fake_scope, ["example.com"]
check("...but a look-alike name is not caught by label-boundary matching",
      tr._host_under("notexample.org", ["example.org"]), None)
run(fetch_external({"url": "https://two.example.org/"}))
r = run(fetch_external({"url": "https://three.example.org/"}))
check("per-run cap enforced", "cap for one run" in r["content"][0]["text"], True)
check("a failed fetch is reported, not raised",
      run(tr.REGISTRY["fetch_external"].build(fresh_ctx(scope=FakeDomainScope(), scope_ceiling=["example.com"]),
          http_get=fake_http_get, extract_html=fake_extract, page_filename=fake_page_filename,
          max_external_per_run=2)({"url": "https://fail.example.org/"}))["is_error"], True)


# ===========================================================================
section("list_evidence / read_evidence / capture_host (trafficmon family)")
# ===========================================================================
ctx = fresh_ctx(scope=FakeCIDRScope())
ctx.scope_ceiling = [ipaddress.ip_network("10.0.0.0/24")]
list_evidence = tr.REGISTRY["list_evidence"].build(ctx)
r = run(list_evidence({}))
check("no manifest yet: 'No evidence collected.'", r["content"][0]["text"], "No evidence collected.")
check("...and marked an error", r["is_error"], True)

ctx.extra["manifest"] = {
    "window_seconds": 60, "interface": "eth0", "bpf": "not port 22",
    "snaplen": 262144, "capture_ok": True, "capture_detail": "ok",
    "sources": ["tshark"], "files": [{"path": "tshark/summary.txt", "bytes": 120, "lines": 5}],
}
r = run(list_evidence({}))
check("lists the manifest's files", "tshark/summary.txt" in r["content"][0]["text"], True)
check("not an error once evidence exists", r.get("is_error"), None)

(ctx.workdir / "tshark").mkdir()
(ctx.workdir / "tshark" / "summary.txt").write_text("proto tcp\nproto udp\n")
read_evidence = tr.REGISTRY["read_evidence"].build(ctx)
r = run(read_evidence({"file": "tshark/summary.txt"}))
check("read_evidence retrieves a real file", "proto tcp" in r["content"][0]["text"], True)
n_actions_before = len(ctx.actions)
r = run(read_evidence({"file": "no-such-file.txt"}))
check("read_evidence: missing file is an error", r["is_error"], True)
check("...trafficmon's original message", r["content"][0]["text"], "No such evidence file.")
check("...AND appends a DENIED ledger entry (trafficmon's original behavior, unlike read_scan/read_page)",
      len(ctx.actions), n_actions_before + 1)
check("...with the right verdict", ctx.actions[-1]["verdict"], "DENIED: no such file")

section("read_evidence: the missed success-ledger regression, now pinned")
# trafficmon's ORIGINAL read_evidence appended an "ok" ledger entry on every
# successful read (unlike enum's read_scan / research's read_page, neither
# of which ever does) — the first pass of this extraction dropped it while
# correctly keeping the DENIED-on-missing difference. Caught by live-testing
# trafficmon's real configure()+tools, not by re-reading the diff.
n_before = len(ctx.actions)
r = run(read_evidence({"file": "tshark/summary.txt"}))
check("a successful read_evidence appends an 'ok' ledger entry", len(ctx.actions), n_before + 1)
check("...with the original action-string shape", ctx.actions[-1],
      {"action": "read_evidence summary.txt (lines 1-81)", "verdict": "ok"})   # unclamped end, faithful to the original
n_before2 = len(ctx.actions)
read_scan_ctx = fresh_ctx(scope=FakeCIDRScope())
read_scan_ctx.scope_ceiling = [ipaddress.ip_network("10.0.0.0/24")]
(read_scan_ctx.workdir / "f.txt").write_text("x\n")
rs = tr.REGISTRY["read_scan"].build(read_scan_ctx)
run(rs({"file": "f.txt"}))
check("read_scan does NOT log a success ledger entry (unlike read_evidence, matching enum's original)",
      len(read_scan_ctx.actions), 0)
rp_ctx = fresh_ctx(scope=FakeDomainScope(), scope_ceiling=["example.com"])
(rp_ctx.workdir / "f.html").write_text("x\n")
rp = tr.REGISTRY["read_page"].build(rp_ctx)
run(rp({"file": "f.html"}))
check("read_page does NOT log a success ledger entry either (matching research's original)",
      len(rp_ctx.actions), 0)

capture_calls = []


def fake_default_iface():
    return "eth0"


def fake_bpf_from_scope(nets, exclude):
    return f"net {nets[0]}"


def fake_management_exclusion(iface):
    return "not port 22"


def fake_capture_window(bpf, iface, seconds, pcap_path):
    capture_calls.append((bpf, iface, seconds))
    pcap_path.write_bytes(b"FAKEPCAP")
    return True, "1 packet"


def fake_tshark_evidence(pcap, base):
    summary = base / "summary.txt"
    summary.write_text("host seen: 10.0.0.9\n")
    return [summary]


ctx.extra["capture_payloads"] = False
capture_host = tr.REGISTRY["capture_host"].build(
    ctx, default_iface=fake_default_iface, bpf_from_scope=fake_bpf_from_scope,
    management_exclusion=fake_management_exclusion, capture_window=fake_capture_window,
    tshark_evidence=fake_tshark_evidence, max_followup_s=60)

r = run(capture_host({"host": "172.16.0.9", "seconds": 30}))
check("out-of-scope host denied", r["is_error"], True)

r = run(capture_host({"host": "10.0.0.9", "seconds": 999}))
check("seconds is clamped to max_followup_s (60), a real follow-up capture happens",
      capture_calls[-1][2], 60)
check("capture_payloads=False deletes the raw pcap afterwards",
      any(p.name == "capture.pcap" for p in ctx.workdir.rglob("*.pcap")), False)
check("the tshark-derived summary is what's returned", "10.0.0.9" in r["content"][0]["text"], True)

ctx2 = fresh_ctx(scope=FakeCIDRScope())
ctx2.scope_ceiling = [ipaddress.ip_network("10.0.0.0/24")]


def fake_capture_window_nopackets(bpf, iface, seconds, pcap_path):
    return False, "no packets seen"


ctx2.extra["capture_payloads"] = True
capture_host2 = tr.REGISTRY["capture_host"].build(
    ctx2, default_iface=fake_default_iface, bpf_from_scope=fake_bpf_from_scope,
    management_exclusion=fake_management_exclusion, capture_window=fake_capture_window_nopackets,
    tshark_evidence=fake_tshark_evidence, max_followup_s=60)
r = run(capture_host2({"host": "10.0.0.5", "seconds": 5}))
check("no packets captured: explained, not an error", r.get("is_error"), None)
check("...switched-network caveat included", "switched network" in r["content"][0]["text"], True)

section("capture_host: capture_payloads is read dynamically, not baked in at build() time")
# Proves the real bug this caught: capture_host is BUILT before configure()
# has loaded ENGAGEMENT, so a value fixed at build() time would always be
# the pre-configure default. ctx.extra must be read at CALL time.
ctx3 = fresh_ctx(scope=FakeCIDRScope())
ctx3.scope_ceiling = [ipaddress.ip_network("10.0.0.0/24")]
capture_host3 = tr.REGISTRY["capture_host"].build(   # built with NOTHING in ctx.extra yet
    ctx3, default_iface=fake_default_iface, bpf_from_scope=fake_bpf_from_scope,
    management_exclusion=fake_management_exclusion, capture_window=fake_capture_window,
    tshark_evidence=fake_tshark_evidence, max_followup_s=60)
run(capture_host3({"host": "10.0.0.9", "seconds": 5}))
check("default (unset) capture_payloads behaves as False: pcap deleted",
      any(p.name == "capture.pcap" for p in ctx3.workdir.rglob("*.pcap")), False)
ctx3.extra["capture_payloads"] = True   # configure() runs AFTER build(), same as production
r = run(capture_host3({"host": "10.0.0.9", "seconds": 5}))
check("...but flips to keeping the pcap once configure() sets it, on the SAME built tool",
      any(p.name == "capture.pcap" for p in ctx3.workdir.rglob("*.pcap")), True)


section("RECON_DENIED_PATTERNS — the fixed refusals every recon agent shares")
check("it refuses command chaining, substitution and redirection",
      [bool(__import__("re").search(p, t)) for p, t in zip(tr.RECON_DENIED_PATTERNS, ("a; b", "a `b`", "a > b"))],
      [True, True, True])
check("it lets an ordinary command through",
      any(__import__("re").search(p, "nmap -sV 10.0.0.5") for p in tr.RECON_DENIED_PATTERNS), False)



section("analyze_file / read_output (file-analysis family)")
import io as _io
import analysis_programs as _ap
import run_files as _rf
import sandbox as _sb

check("both tools are registered for the 'files' scope, with no network",
      [(tr.REGISTRY[n].category, tr.REGISTRY[n].scope_kind, tr.REGISTRY[n].network)
       for n in ("analyze_file", "read_output")],
      [("file-analysis", "files", False)] * 2)

_slot = Path(tempfile.mkdtemp(prefix="analyze-test-")) / "agent" / "instances" / "alice"
_slot.mkdir(parents=True)
_PCAP = (bytes.fromhex("d4c3b2a1" "0200" "0400" "00000000" "00000000" "ffff0000" "01000000")
         + bytes.fromhex("01000000" "02000000" "3c000000" "3c000000") + b"\x00" * 60)
_rf.attach(_io.BytesIO(_PCAP), [("a", "pending", _slot)], name="cap.pcap", by="alice")
_rf.begin_run(_slot)
_actx = tr.ToolContext(log=FakeLog(), workdir=Path(tempfile.mkdtemp(prefix="analysis-out-")))
_names, _tools = tr.build_tools(["analyze_file", "read_output"], _actx,
                                config={"analyze_file": {"programs": {"tshark", "capinfos"}, "agent_dir": _slot}})
analyze, read_out = _tools


def _text(r): return r["content"][0]["text"]


check("the model-facing description lists the programs and says there is no shell",
      "tshark" in analyze.description and "capinfos" in analyze.description
      and "no shell" in analyze.description.lower(), True)

r = run(analyze({"command": "tshark -r cap.pcap -w stolen.pcap"}))
check("a write option is refused", (bool(r.get("is_error")), _text(r).startswith("DENIED")), (True, True))
check("...recorded in the ledger as DENIED, with no output file",
      (_actx.actions[-1]["verdict"].startswith("DENIED"), _actx.actions[-1]["output"],
       list(_actx.workdir.iterdir())), (True, None, []))
r = run(analyze({"command": "tshark -r /etc/passwd"}))
check("a file that is not attached is refused", (bool(r.get("is_error")), "not a file attached" in _text(r)), (True, True))
r = run(analyze({"command": "tshark -r cap.pcap | head"}))
check("a pipe is refused", (bool(r.get("is_error")), "no shell" in _text(r)), (True, True))
r = run(analyze({"command": "nmap -sV 10.0.0.1"}))
check("a program that is not an analysis program is refused", (bool(r.get("is_error")), "not a program" in _text(r)), (True, True))

_real_binary_path = _ap.binary_path
_ap.binary_path = lambda name: None
r = run(analyze({"command": "tshark -r cap.pcap -c 1"}))
_ap.binary_path = _real_binary_path
check("a program that is not installed gets a clean message, not a crash",
      (bool(r.get("is_error")), "not installed" in _text(r)), (True, True))

# The tool checks "is the program installed" BEFORE it checks the sandbox, so on
# a host without tshark (CI) this case would stop at the first check and never
# reach the one under test. Pretend the program exists; the sandbox is what is
# missing here.
_real_bwrap = _sb.BWRAP
_sb.BWRAP = "/nonexistent/bwrap"
_ap.binary_path = lambda name: "/usr/bin/" + name
r = run(analyze({"command": "tshark -r cap.pcap -c 1"}))
_ap.binary_path = _real_binary_path
_sb.BWRAP = _real_bwrap
check("with no sandbox nothing runs, and the message says so",
      (bool(r.get("is_error")), "sandbox is not available" in _text(r), list(_actx.workdir.iterdir())),
      (True, True, []))

_probe = _sb.run(["/bin/true"], "light") if _sb.available() else None
if _probe is None or not _probe.ok or not _ap.binary_path("tshark"):
    skip("running tshark through the tool", "bubblewrap or tshark is unavailable on this host")
else:
    r = run(analyze({"command": "tshark -r cap.pcap -T fields -e frame.len"}))
    check("a real analysis runs in the sandbox and returns its output", (not r.get("is_error"), "60" in _text(r)), (True, True))
    saved = _actx.actions[-1]["output"]
    check("...the full output is saved and the ledger names it", (_actx.actions[-1]["verdict"], saved is not None and (_actx.workdir / saved).read_text().strip()),
          ("ok", "60"))
    check("...the plugin-load noise tshark prints is not shown to the model", "Couldn't load plugin" in _text(r), False)
    r2 = run(read_out({"file": saved, "pattern": "^60$"}))
    check("read_output searches the saved output", (not r2.get("is_error"), "60" in _text(r2)), (True, True))
    check("read_output cannot leave the analysis folder", bool(run(read_out({"file": "../../etc/passwd"})).get("is_error")), True)

    r = run(analyze({"command": "capinfos -c cap.pcap"}))
    check("capinfos works on the same file", (not r.get("is_error"), "Number of packets" in _text(r)), (True, True))

    _rf.attach(_io.BytesIO(b"this is not a capture file at all"), [("a", "run", _slot)], name="junk.pcap", by="alice")
    r = run(analyze({"command": "tshark -r junk.pcap"}))
    check("a file attached AFTER the tool was built is usable (mid-run attach)", "junk.pcap" in str(_actx.actions[-1]["command"]), True)
    check("a program that fails reports it as an error, with the reason, and the ledger says so",
          (bool(r.get("is_error")), "failed (exit" in _actx.actions[-1]["verdict"], "NOTE" in _text(r)), (True, True, True))

    # ---- suricata: the one analysis program that writes and needs host files ----
    import suricata_offline as _so
    r = run(analyze({"command": "suricata -r cap.pcap"}))
    check("an agent not given suricata cannot run it", (bool(r.get("is_error")), "not a program" in _text(r)), (True, True))

    if not (_ap.binary_path("suricata") and _so.available()):
        skip("running suricata through the tool", "suricata (or its package config files) is not installed")
    else:
        _sctx = tr.ToolContext(log=FakeLog(), workdir=Path(tempfile.mkdtemp(prefix="analysis-sur-")))
        _n, _t = tr.build_tools(["analyze_file", "read_output"], _sctx,
                                config={"analyze_file": {"programs": {"suricata", "tshark"}, "agent_dir": _slot}})
        sur, sur_read = _t
        check("suricata appears in the model-facing description", "suricata" in sur.description, True)
        r = run(sur({"command": "suricata -c /etc/suricata/suricata.yaml -r cap.pcap"}))
        check("the model cannot choose a config", (bool(r.get("is_error")), _text(r).startswith("DENIED")), (True, True))
        r = run(sur({"command": "suricata -r cap.pcap"}))
        txt = _text(r)
        check("a real run succeeds and returns a summary, not raw output",
              (not r.get("is_error"), txt.startswith("Suricata read"), "Rules:" in txt, "Events by type" in txt or "Alerts:" in txt),
              (True, True, True, True))
        check("...the ledger records ok and names the summary file",
              (_sctx.actions[-1]["verdict"], _sctx.actions[-1]["output"].endswith("_summary.txt")), ("ok", True))
        names = sorted(p.name for p in _sctx.workdir.iterdir())
        check("...the full logs are saved beside it, and the private log directory is gone",
              (any(n.endswith("_eve.json") for n in names), any(n.endswith("_fast.log") for n in names),
               any(n.endswith("_stats.log") for n in names), [n for n in names if n.startswith(".")]),
              (True, True, True, []))
        check("...and the text says how to search them", "read_output(file=" in txt, True)
        eve = next(n for n in names if n.endswith("_eve.json"))
        r2 = run(sur_read({"file": eve, "pattern": "flow"}))
        check("read_output reads the saved eve.json", not r2.get("is_error"), True)
        check("nothing a run leaves in the output folder names the vault or the host's /etc",
              any(d in (_sctx.workdir / n).read_text(errors="replace") for n in names
                  for d in ("/var/lib/agenti", "/opt/agenti")
                  if n.endswith(("_summary.txt", "_fast.log"))), False)


print(f"\n{PASS} passed, {FAIL} failed, {SKIP} skipped")
sys.exit(1 if FAIL else 0)