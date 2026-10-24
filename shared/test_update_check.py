#!/usr/bin/env python3
"""test_update_check.py — shared/update_check.py. No network, no root.

    python3 shared/test_update_check.py

The properties that matter: it is OFF by default and then makes NO request
(proved with a fetcher that fails the test if called), it never claims an
update it cannot justify, and a hostile or broken GitHub reply degrades to a
plain message instead of an exception or a poisoned link.
"""
import io
import json
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import update_check as uc  # noqa: E402

PASS = FAIL = 0


def check(name, got, want):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print(f"  [ OK ] {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name}\n         got  {got!r}\n         want {want!r}")


def boom():
    raise AssertionError("network was used while the check is switched off")


# --- versions
check("newer patch", uc.is_newer("1.0.1", "1.0.0"), True)
check("newer minor beats patch", uc.is_newer("1.1.0", "1.0.9"), True)
check("numeric not lexical (1.10 > 1.9)", uc.is_newer("1.10.0", "1.9.0"), True)
check("same is not newer", uc.is_newer("1.0.0", "1.0.0"), False)
check("older is not newer", uc.is_newer("0.9.0", "1.0.0"), False)
check("release is newer than its own pre-release", uc.is_newer("0.1.0", "0.1.0-dev"), True)
check("pre-release is not newer than the release", uc.is_newer("0.1.0-dev", "0.1.0"), False)
check("v prefix accepted", uc.is_newer("v1.2.0", "1.1.0"), True)
check("garbage latest -> no claim", uc.is_newer("latest", "1.0.0"), False)
check("garbage installed -> no claim", uc.is_newer("1.0.0", "weird"), False)

# --- off by default: no request at all
r = uc.check(False, "0.1.0", fetch=boom)
check("off: no network, says how to enable", (r["enabled"], r["checked"], r["enable_command"]),
      (False, False, uc.ENABLE_COMMAND))
check("off: render explains and shows the command", "makes no request" in uc.render(r) and uc.ENABLE_COMMAND in uc.render(r), True)

# --- on
r = uc.check(True, "0.1.0", fetch=lambda: ("0.2.0", "https://github.com/agenti-foss/agenti/releases/tag/v0.2.0"), now=lambda: 1000)
check("update available", (r["checked"], r["update_available"], r["latest"], r["install_command"]),
      (True, True, "0.2.0", uc.INSTALL_COMMAND))
check("render names the command and says nothing was installed",
      "Nothing has been installed" in uc.render(r) and uc.INSTALL_COMMAND in uc.render(r), True)
r = uc.check(True, "0.2.0", fetch=lambda: ("0.2.0", ""))
check("up to date", (r["update_available"], r["install_command"], "up to date" in uc.render(r)), (False, None, True))
r = uc.check(True, None, fetch=lambda: ("0.2.0", ""))
check("unknown installed version is reported, not guessed", (r["update_available"], bool(r["error"])), (False, True))


def fail_fetch():
    raise RuntimeError("no release has been published yet")


r = uc.check(True, "0.1.0", fetch=fail_fetch)
check("fetch failure -> plain error", (r["checked"], r["error"], "Could not check" in uc.render(r)),
      (False, "no release has been published yet", True))


# --- fetch_latest against fake responses
class Resp(io.BytesIO):
    def __enter__(self): return self
    def __exit__(self, *a): return False


def opener_for(body):
    return lambda req, timeout: Resp(body if isinstance(body, bytes) else json.dumps(body).encode())


ok = uc.fetch_latest(opener_for({"tag_name": "v1.2.3", "html_url": "https://github.com/agenti-foss/agenti/releases/tag/v1.2.3"}))
check("fetch parses tag and link", ok, ("1.2.3", "https://github.com/agenti-foss/agenti/releases/tag/v1.2.3"))
evil = uc.fetch_latest(opener_for({"tag_name": "1.2.3", "html_url": "https://evil.example/x"}))
check("a link off the project's repo is replaced", evil[1], "https://github.com/agenti-foss/agenti/releases")


def raises(fn):
    try:
        fn()
    except RuntimeError as e:
        return str(e)
    return None


check("not JSON", bool(raises(lambda: uc.fetch_latest(opener_for(b"<html>")))), True)
check("no tag", bool(raises(lambda: uc.fetch_latest(opener_for({"name": "x"})))), True)
check("odd tag refused", "unrecognised" in (raises(lambda: uc.fetch_latest(opener_for({"tag_name": "rm -rf /"}))) or ""), True)
check("oversize refused", "large" in (raises(lambda: uc.fetch_latest(opener_for(b"x" * (uc.MAX_BYTES + 5)))) or ""), True)


class Http404(Exception):
    code = 404


def opener404(req, timeout):
    raise Http404("nf")


check("404 means no release yet", raises(lambda: uc.fetch_latest(opener404)), "no release has been published yet")


def opener_down(req, timeout):
    raise OSError("unreachable")


check("network down is explained", "internet access" in (raises(lambda: uc.fetch_latest(opener_down)) or ""), True)

# --- installed version lookup
def run_deb(cmd, **kw): return subprocess.CompletedProcess(cmd, 0, stdout="0.3.1-1\n", stderr="")
def run_none(cmd, **kw): return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="")
def run_missing(cmd, **kw): raise FileNotFoundError("dpkg-query")


check("dpkg version wins, packaging suffix dropped", uc.installed_version(run_deb), "0.3.1")
with tempfile.TemporaryDirectory() as d:
    vf = Path(d) / "VERSION"
    vf.write_text("0.1.0-dev\n")
    check("VERSION file when not a .deb", uc.installed_version(run_none, vf), "0.1.0-dev")
    check("no dpkg at all falls back too", uc.installed_version(run_missing, vf), "0.1.0-dev")
    check("nothing known -> None", uc.installed_version(run_none, Path(d) / "absent"), None)

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
