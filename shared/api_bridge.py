#!/usr/bin/python3 -IS
"""
api_bridge.py — the ONLY thing the web tier (agenti-api) may run as root.

Until audit run 1 agenti-api's sudo rule allowed /usr/bin/agenti with any
arguments, and every verb had to remember to refuse it. Several did not
(`<agent> logs` passing options to journalctl, `export` to any folder, a
trailing --help reaching `vault`, set-key, account creation with the admin
role ...), and every password a user typed into an enrolment or reset link
was written by sudo into the system journal, because it was on the command
line (F10-F17, N05).

Now the sudo rule is `agenti-api ALL=(root) NOPASSWD: <this file> ""`: no
arguments at all, so sudo logs nothing but this file's name. The API writes
ONE line of JSON on standard input — {"argv": [...]} — followed, for the few
verbs that take one, by the request body (an attached file, an instruction
text). This program:

  * refuses anything that is not a verb the web tier actually uses
    (default-deny: an allow-list built from every call in shared/api/main.py,
    test_api_bridge.py keeps them in step), and enforces the argument rules
    the risky verbs need (`logs` takes -n N only; no --help anywhere; no
    control characters; create-user cannot set a role);
  * moves every secret value (passwords, codes, link tokens, grants) out of
    the argument list into environment variables of the root process, which
    only root can read; iam.py, the only program that consumes them, reads
    them back (`@env:AGENTI_ARG_<n>`). No secret appears in sudo's log or in
    /proc/<pid>/cmdline;
  * runs /usr/bin/agenti from / with a minimal environment, so nothing of
    the caller's (PATH, PYTHONPATH, its working directory) reaches root.

The CLI keeps its own refusals (refuse_iam_writes_from_api, console_only,
grant checks): this is a second, independent gate in front of them.
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

AGENTI_BIN = "/usr/bin/agenti"
# Where an installed agent lives (the CLI's list_agents): a folder holding its
# own <name>-agent.py, shipped with the package or built in Settings. The
# bridge runs with sudo's clean environment, so these are the defaults.
SHIPPED_AGENTS = Path("/usr/lib/agenti/agents")
BUILT_AGENTS = Path("/var/lib/agenti/data/shared/agents")
MAX_INPUT_LINE = 1 << 20        # the argv line; a body follows on stdin
MAX_ARGS = 400

NAME = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")

# Every verb the web tier uses (shared/api/main.py). Anything else is refused.
ADMIN_VERBS = frozenset("""
agent-build bindings catalog context-memory context-read context-web create-user delete-user
disable-user enable-user enrol-check enrol-consume list-keys list-users mint-enrolment-link
outputs-cat outputs-delete outputs-list outputs-usage passkey-commit passkey-list
password-reset-check password-reset-consume policy rename-user reset-user-mfa reset-user-password
revoke-key self set-webauthn tool-approvals tool-request-file tool-request-list update-check
user-history web-bind web-unbind
""".split())
AGENT_VERBS = frozenset("""
acknowledge action-approve action-reject action-pending agent-scope approval attach controls
engagement files findings history inbox interrupt logs note pause promote-output rename report
reports resume say scans send send-list set-model show start status stop tools tool-settings
""".split())
TEAM_VERBS = frozenset("""
acknowledge add-agent attach consensus delete files inbox note pause remove-agent report resume
say show start status stop
""".split())
ENGAGEMENT_VERBS = frozenset({"show", "set", "approve"})
DOCS_VERBS = frozenset({"list", "show", "search"})

# Options whose value is a secret: moved to the environment. Positional link
# tokens of these admin verbs are secrets too.
SECRET_OPTIONS = frozenset({"--new", "--current", "--totp", "--reauth", "--secret", "--code",
                            "--totp-secret", "--totp-code", "--grant"})
TOKEN_VERBS = frozenset({"enrol-check", "enrol-consume", "password-reset-check", "password-reset-consume"})


class Refused(Exception):
    pass


def _read_request(fd: int = 0) -> list[str]:
    """The first line of stdin, read one byte at a time so the rest of stdin
    (a body some verbs take) is left untouched for agenti."""
    buf = bytearray()
    while len(buf) <= MAX_INPUT_LINE:
        b = os.read(fd, 1)
        if not b or b == b"\n":
            break
        buf += b
    else:
        raise Refused("the request line is too long")
    try:
        req = json.loads(buf.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise Refused("the request is not one line of JSON")
    argv = req.get("argv") if isinstance(req, dict) else None
    if not isinstance(argv, list) or not argv or not all(isinstance(a, str) for a in argv):
        raise Refused('the request must be {"argv": ["verb", ...]}')
    if len(argv) > MAX_ARGS:
        raise Refused("too many arguments")
    return argv


def check(argv: list[str]) -> None:
    """Raise Refused unless `argv` is a call the web tier makes."""
    for a in argv:
        if any(ord(c) < 32 or ord(c) == 127 for c in a):
            raise Refused("an argument contains a control character")
        if a in ("--help", "-h"):
            raise Refused("--help is not available to the web tier")
    words = [a for a in argv if not a.startswith("-")]
    first = argv[0]
    if first in ("agents",):
        return
    if first == "dashboard":
        return
    if first == "vault":
        # Only turning it on, with its grant (decision 6); the passphrase is the
        # request body on stdin. Everything else about the vault is terminal-only.
        rest = argv[2:]
        _need(len(argv) > 1 and argv[1] == "enable"
              and all(a.startswith(("--size=", "--grant=")) or a == "--json" for a in rest)
              and any(a.startswith("--grant=") for a in rest), f"vault {argv[1:2]}")
        return
    if first == "docs":
        _need(len(words) > 1 and words[1] in DOCS_VERBS, f"docs {words[1:2]}")
        return
    if first == "engagement":
        _need(len(words) > 1 and words[1] in ENGAGEMENT_VERBS, f"engagement {words[1:2]}")
        return
    if first == "team":
        _need(len(argv) > 1, "team")
        if argv[1] in ("list", "create"):
            return
        _need(NAME.match(argv[1]) and len(argv) > 2 and argv[2] in TEAM_VERBS, f"team {argv[1:3]}")
        return
    if first == "admin":
        _need(len(argv) > 1 and argv[1] in ADMIN_VERBS, f"admin {argv[1:2]}")
        if argv[1] == "create-user":
            # A role on creation only together with the re-authenticated grant
            # that names it (F15; operator decision 2026-10-22). iam.py checks
            # the grant covers exactly this name, kind and role.
            has_role = any(a == "--role" or a.startswith("--role=") for a in argv)
            has_grant = any(a == "--grant" or a.startswith("--grant=") for a in argv)
            _need(has_grant or not has_role, "create-user --role without an approval grant")
        return
    # Default-deny: the first word must NAME AN INSTALLED AGENT. Matching the
    # name's shape was not enough: the CLI's own top-level words ('new' ...)
    # have that shape too and reached root before any gate (audit run 2).
    _need(_is_agent(first) and len(argv) > 1 and argv[1] in AGENT_VERBS, f"{first} {argv[1:2]}")
    if argv[1] == "logs":
        _check_logs(argv[2:])


def _check_logs(rest: list[str]) -> None:
    """`<agent> logs` reaches a root journalctl: only -n N and the global
    --owner/--copy/--json options (F12)."""
    i = 0
    while i < len(rest):
        a = rest[i]
        if a == "-n" and i + 1 < len(rest) and rest[i + 1].isdigit():
            i += 2
        elif a in ("--owner", "--copy") and i + 1 < len(rest) and NAME.match(rest[i + 1].replace(".", "-")):
            i += 2
        elif a.startswith(("--owner=", "--copy=")) or a == "--json":
            i += 1
        else:
            raise Refused(f"logs does not take {a!r} from the web tier")


def _is_agent(name: str) -> bool:
    return bool(NAME.match(name)) and any(
        (base / name / f"{name}-agent.py").is_file() for base in (SHIPPED_AGENTS, BUILT_AGENTS))


def _need(ok, what) -> None:
    if not ok:
        raise Refused(f"'{what}' is not something the web tier may run")


def hide_secrets(argv: list[str]) -> tuple[list[str], dict[str, str]]:
    """Replace every secret value with @env:AGENTI_ARG_<n>; return the new
    argv and the variables to set."""
    out, env, n = [], {}, 0

    def stash(value: str) -> str:
        nonlocal n
        n += 1
        env[f"AGENTI_ARG_{n}"] = value
        return f"@env:AGENTI_ARG_{n}"

    token_slot = None
    if len(argv) > 2 and argv[0] == "admin" and argv[1] in TOKEN_VERBS:
        token_slot = 2
    i = 0
    while i < len(argv):
        a = argv[i]
        name, eq, val = a.partition("=")
        if i == token_slot and not a.startswith("-"):
            out.append(stash(a))
        elif a.startswith("--") and eq and name in SECRET_OPTIONS:
            out.append(f"{name}={stash(val)}")
        elif a in SECRET_OPTIONS and i + 1 < len(argv):
            out += [a, stash(argv[i + 1])]
            i += 1
        else:
            out.append(a)
        i += 1
    return out, env


def _refuse(message: str) -> int:
    print(json.dumps({"error": f"REFUSING: {message}."}))
    return 2


def main() -> int:
    if os.geteuid() != 0:
        return _refuse("this runs only through sudo")
    try:
        argv = _read_request()
        check(argv)
    except Refused as e:
        return _refuse(str(e))
    argv, secret_env = hide_secrets(argv)
    env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"}
    # Who is asking, exactly as sudo set it: the CLI's invoking_user() and
    # every refusal for the web tier key on SUDO_USER.
    for k in ("SUDO_USER", "SUDO_UID", "SUDO_GID", "SUDO_COMMAND"):
        if k in os.environ:
            env[k] = os.environ[k]
    env.update(secret_env)
    os.chdir("/")
    os.execve(AGENTI_BIN, [AGENTI_BIN, *argv], env)
    return 0                                       # not reached


if __name__ == "__main__":
    sys.exit(main())
