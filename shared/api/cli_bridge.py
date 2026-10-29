"""
cli_bridge.py — the "one implementation, not two divergent ones" mechanism
(CLAUDE.md §3a/§4 step 5).

Every route in main.py shells out to the installed `agenti` CLI binary via
`sudo -n` and parses its output. This module contains NO knowledge of the
vault layout, systemd, root-owned run-config files, or any other runtime
detail — that would be reaching past the CLI/runtime into files or systemd
directly, exactly what CLAUDE.md warns against. If a future change tightens
a CLI safety check, every API caller inherits it automatically, because
there is only one place the check lives.

WHY sudo -n (never-prompt) rather than running this whole process as root:
the API's OWN authentication (sessions and per-user keys, checked by
agenti-authd) decides whether a request may act at all; the API process
itself stays an unprivileged service account (agenti-api) with a narrow,
auditable sudoers grant for exactly this one binary (shared/agenti-api.sudoers;
configure.sh creates the account and installs the grant). `-n` is essential: if the sudoers
grant is ever missing or misconfigured, this must fail immediately with a
clear error, never hang waiting on a password prompt nobody can answer.

WHY EVERY CALL PASSES --json, EVEN FOR VERBS WHOSE SUCCESSFUL OUTPUT ISN'T
JSON (pause, resume, reports, scans, report, logs): a PRECONDITION failure
(unknown agent, no active run, vault locked, ...) always goes through
shared/agenti's die(), which is --json-aware for every verb regardless of
whether that verb's own successful output is. Passing --json unconditionally
means a failure always comes back as clean, parseable {"error": "..."} —
found by testing pause/resume for real and getting a raw, unparsed CLI error
string back instead of a clean HTTP error, not by reading the CLI source and
assuming both cases behave the same way.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import threading
import time

# shared/paths.py's agenti_bin(), restated: this process imports nothing from
# the code folder but iam.py (test_paths.py keeps the two equal).
AGENTI_BIN = os.environ.get("AGENTI_BIN", "/usr/bin/agenti")
# The only program this account may run as root (audit run 1, fix 2). Its sudo
# rule allows it with NO arguments: the command travels as one JSON line on
# stdin, so nothing of it (passwords, link tokens, grants) reaches sudo's log
# or the process list. See shared/api_bridge.py.
API_BRIDGE = os.environ.get("AGENTI_API_BRIDGE", "/usr/lib/agenti/api_bridge.py")
DEFAULT_TIMEOUT_S = 30.0

# ---------------------------------------------------------------------------
# Input validation for anything that becomes an argv element.
#
# There is no shell here (subprocess gets a list, never a string), so shell
# metacharacters are inert — `agent="enum; id"` is just a nonexistent agent
# name, confirmed by probing the live service. The real hazard is different
# and was found the same way: `agenti`'s grammar is positional, so a path
# param in the AGENT slot can escape into the CLI's TOP-LEVEL verb table.
# `GET /vault/unlock/status` became `agenti vault unlock status --json` and
# actually reached the vault verb — an operation this API deliberately has
# no route for, and `vault lock` would have been a live denial of service
# through a URL that reads like a 404.
#
# Two rules, both enforced here rather than in main.py, because this is the
# one place argv is built: a route that forgets to validate cannot exist if
# the check lives next to the thing it protects.
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")

# Names an agent may never have, because they are words the CLI already
# dispatches on at the top level (`agenti agents`, `agenti team ...`,
# `agenti engagement ...`, `agenti dashboard`, ...): an agent with one of
# these names could never be addressed. Keep in sync with the CLI's own
# top-level dispatch in shared/agenti.
RESERVED_NAMES = frozenset({
    "new", "admin", "vault", "gui", "help", "docs", "agents", "setup", "setup-code", "verify",
    "team", "engagement", "dashboard", "outputs", "tool-requests",
})
# Report/scan filenames, which also reach argv. Uppercase is allowed here
# (engagement IDs are uppercase); a leading '-' is not, so a filename can
# never be read as a flag.
FILENAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def validate_name(value: str, kind: str = "name") -> str:
    """Raises ValueError so FastAPI renders a 422 with this message — the
    correct status for malformed input, and it never reaches a subprocess."""
    if not NAME_RE.match(value or ""):
        raise ValueError(
            f"invalid {kind} {value!r}: must be lowercase letters, digits, "
            f"'-' or '_', starting with a letter or digit, max 64 characters")
    if value in RESERVED_NAMES:
        raise ValueError(
            f"invalid {kind} {value!r}: that name is reserved — it is one of "
            f"the agenti CLI's own top-level commands ({', '.join(sorted(RESERVED_NAMES))}) "
            f"and cannot be used in the {kind} position")
    return value


def validate_filename(value: str) -> str:
    if not FILENAME_RE.match(value or ""):
        raise ValueError(
            f"invalid filename {value!r}: must be a plain filename — letters, "
            f"digits, '.', '-' or '_', starting with a letter or digit, and no "
            f"path separators")
    return value


class AgentiError(Exception):
    """Raised for every way a shelled-out `agenti` call can fail. `status_code`
    is chosen to be a reasonable HTTP status for main.py to return directly —
    this module doesn't import FastAPI, so it can't raise an HTTPException
    itself, but it hands back enough to construct one without guessing."""

    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


def _bridge(args: tuple, *, timeout: float, text: bool, stdin_text: str | None = None,
            stdin_file=None) -> subprocess.CompletedProcess:
    """Run `agenti <args> --json` as root through the bridge: one JSON line on
    stdin, then the body (an instruction text, or an attached file's bytes) if
    the verb takes one. Root never opens a path this account chose."""
    cmd = ["sudo", "-n", API_BRIDGE]
    header = (json.dumps({"argv": [*args, "--json"]}) + "\n").encode("utf-8")
    try:
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
    except FileNotFoundError:
        raise AgentiError("sudo is not available on this host — is agenti installed?", 500)
    pipe, proc.stdin = proc.stdin, None         # fed by the thread below, not by communicate()

    def feed() -> None:
        try:
            pipe.write(header)
            if stdin_text is not None:
                pipe.write(stdin_text.encode("utf-8"))
            elif stdin_file is not None:
                shutil.copyfileobj(stdin_file, pipe, 1 << 16)
        except (BrokenPipeError, OSError):
            pass
        finally:
            try:
                pipe.close()
            except OSError:
                pass

    writer = threading.Thread(target=feed, daemon=True)
    writer.start()
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        raise AgentiError(f"agenti {' '.join(args[:2])} did not finish within {timeout}s", 504)
    finally:
        writer.join(timeout=5)
    if text:
        out, err = out.decode("utf-8"), err.decode("utf-8", errors="replace")
    return subprocess.CompletedProcess(cmd, proc.returncode, out, err)


def _run(*args: str, timeout: float, stdin_text: str | None = None,
         stdin_file=None) -> subprocess.CompletedProcess:
    return _bridge(args, timeout=timeout, text=True, stdin_text=stdin_text, stdin_file=stdin_file)


def _run_bytes(*args: str, timeout: float) -> subprocess.CompletedProcess:
    """Same call as _run(), but stdout/stderr come back as raw bytes, not
    decoded. For verbs whose SUCCESS output is an arbitrary binary file
    (phase 7's output download) — decoding it would corrupt it or crash on
    invalid UTF-8."""
    return _bridge(args, timeout=timeout, text=False)


def _unexpected(what: str, raw: str, status: int) -> "AgentiError":
    """Root's raw output never goes back to the browser: it can carry bytes a
    run planted (a link to a root-only file once came back in a 502, audit
    run 2). Nor does it go to the journal, where an enrolment link or a run's
    data would outlive the request (CodeQL, 2026-10-24): only its size and
    SHA-256 are logged, under a reference; the admin re-runs the verb at the
    console to see the output itself."""
    ref = secrets.token_hex(4)
    digest = hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:16]
    print(f"[agenti-api] {what} ref={ref}: {len(raw)} chars, sha256 {digest}", file=sys.stderr)
    return AgentiError(f"{what} (ref {ref}) — an admin can see it in: journalctl -u agenti-api", status)


def _fail_text(returncode: int, stdout: str, stderr: str) -> None:
    """Shared failure path for every runner below. A precondition failure
    (the common case) went through die(), which prints clean JSON even for
    verbs whose SUCCESS output isn't JSON — try that first. Fall back to raw
    stdout/stderr only if even that isn't parseable, so nothing is silently
    swallowed."""
    stdout = stdout.strip()
    if not stdout:
        raise _unexpected(f"agenti produced no output (rc={returncode}); check that the agenti-api "
                          f"sudoers grant is installed", stderr.strip(), 500)
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        raise _unexpected(f"agenti failed with an unexpected reply (rc={returncode})", stdout, 400)
    if isinstance(data, dict) and isinstance(data.get("error"), str):
        raise AgentiError(data["error"], 400)
    raise _unexpected(f"agenti failed with an unexpected reply (rc={returncode})", stdout, 400)


def _fail(proc: subprocess.CompletedProcess) -> None:
    _fail_text(proc.returncode, proc.stdout, proc.stderr)


def _fail_bytes(proc: subprocess.CompletedProcess) -> None:
    """Same as _fail(), for a _run_bytes() result: only the FAILURE path is
    ever decoded — a verb's success bytes are returned untouched by the
    caller, so decoding is never attempted on real binary content, only on
    the die()-produced JSON error text every failure path already is."""
    _fail_text(proc.returncode,
              proc.stdout.decode("utf-8", errors="replace"),
              proc.stderr.decode("utf-8", errors="replace"))


# A very short cache for the few read verbs whose answer does NOT depend on who
# is asking (the catalogue — each caller's view is
# filtered afterwards in main.py). Every call costs a sudo + bash + python
# round trip (300-900 ms on the Pi), and a Settings load makes several of
# these. 3 seconds is long enough to share one page load and short enough that
# nothing visibly lags; any `admin ...` call (every create/rename/delete/build
# goes through it) empties the cache at once. Never used for per-run verbs.
_CACHEABLE_FIRST_ARGS = {"agents"}
_CACHE_TTL_S = 3.0
_read_cache: dict[tuple, tuple[float, object]] = {}


def run_agenti(*args: str, timeout: float = DEFAULT_TIMEOUT_S,
               stdin_text: str | None = None, stdin_file=None) -> dict | list:
    if args and args[0] == "admin":
        _read_cache.clear()
    if stdin_file is not None:
        return _run_agenti_uncached(*args, timeout=timeout, stdin_file=stdin_file)
    if stdin_text is None and args and args[0] in _CACHEABLE_FIRST_ARGS:
        now = time.monotonic()
        hit = _read_cache.get(args)
        if hit and now - hit[0] < _CACHE_TTL_S:
            return copy.deepcopy(hit[1])
        out = _run_agenti_uncached(*args, timeout=timeout, stdin_text=stdin_text)
        _read_cache[args] = (now, copy.deepcopy(out))
        return out
    return _run_agenti_uncached(*args, timeout=timeout, stdin_text=stdin_text)


def _run_agenti_uncached(*args: str, timeout: float = DEFAULT_TIMEOUT_S,
                         stdin_text: str | None = None, stdin_file=None) -> dict | list:
    """For verbs whose SUCCESSFUL output is JSON (the majority). Almost all
    emit an object; `findings` is the one exception (a bare JSON array) —
    found by actually hitting the /findings route and getting a FastAPI
    ResponseValidationError, not by reading the CLI source and assuming.
    Typed as dict | list here rather than dict so that surprise is visible
    at the type level, not just in a runtime crash."""
    proc = _run(*args, timeout=timeout, stdin_text=stdin_text, stdin_file=stdin_file)
    if proc.returncode != 0:
        _fail(proc)
    stdout = proc.stdout.strip()
    try:
        return json.loads(stdout)
    except json.JSONDecodeError:
        raise _unexpected("agenti produced an unexpected reply", stdout, 502)


def run_agenti_text(*args: str, timeout: float = DEFAULT_TIMEOUT_S) -> str:
    """For verbs whose SUCCESSFUL output is plain text, not JSON: pause,
    resume (a colored 'ok' line), reports/scans/report (a listing or a
    report's raw Markdown body), logs (raw journalctl text). --json is
    still passed (see module docstring) so a PRECONDITION failure still
    comes back as a clean, parseable error — only the SUCCESS path is
    returned verbatim, uninterpreted."""
    proc = _run(*args, timeout=timeout)
    if proc.returncode != 0:
        _fail(proc)
    return proc.stdout


def run_agenti_bytes(*args: str, timeout: float = DEFAULT_TIMEOUT_S) -> bytes:
    """For verbs whose SUCCESSFUL output is an arbitrary binary file — today
    just `admin outputs-cat` (phase 7 of the generic-launcher arc: a
    promoted output can be an image, PDF, video, anything). Same --json-on-
    failure/raw-payload-on-success duality run_agenti_text() already uses
    for report/logs, not a new contract — only the SUCCESS path is ever
    binary; a failure is always plain JSON text, decoded the normal way."""
    proc = _run_bytes(*args, timeout=timeout)
    if proc.returncode != 0:
        _fail_bytes(proc)
    return proc.stdout
