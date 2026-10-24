#!/usr/bin/env python3
"""update_check.py — "is a newer Agenti released?", report-only.

    agenti admin update-check              (the CLI verb runs this)

WHAT IT IS. One outbound HTTPS request to GitHub's public releases API,
compared against the installed version. It NEVER downloads or installs
anything: the answer names the version and the exact command an admin runs
themselves (`sudo apt update && sudo apt install --only-upgrade agenti`).

OFF BY DEFAULT. A self-hosted security tool should not phone home unasked.
The platform policy `update-check` must be switched on by root at a terminal
(`sudo agenti admin set-policy update-check on`); until then this module
makes no network request at all and says how to enable it. The API can read
the policy but never set it (policy changes are refused to the API).

WHAT IS SENT. A plain GET to api.github.com with a User-Agent of "agenti".
No installation id, no hostname, no version, no account name. GitHub sees
this machine's IP address, like any visit to a web page.

The installed version comes from the package manager when Agenti was
installed as a .deb, otherwise from the VERSION file shipped beside this
module. Both fetching and version lookup are injectable so tests need no
network.
"""
import json
import re
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

REPO = "agenti-foss/agenti"
API_URL = f"https://api.github.com/repos/{REPO}/releases/latest"
INSTALL_COMMAND = "sudo apt update && sudo apt install --only-upgrade agenti"
ENABLE_COMMAND = "sudo agenti admin set-policy update-check on"
MAX_BYTES = 1_000_000
TIMEOUT_S = 10

_VER = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)(?:[-~+]([0-9A-Za-z.\-~+]+))?$")


def parse_version(text):
    """'v1.2.3', '1.2.3-dev', '1.2.3~rc1' -> ((1,2,3), prerelease-or-''). None if not a version."""
    m = _VER.match(str(text).strip())
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3))), (m.group(4) or "")


def is_newer(latest, installed):
    """True if `latest` is a strictly newer release than `installed`.
    A pre-release sorts BEFORE its own release (1.0.0-dev < 1.0.0). Unparseable
    on either side -> False: never claim an update we cannot justify."""
    a, b = parse_version(latest), parse_version(installed)
    if a is None or b is None:
        return False
    if a[0] != b[0]:
        return a[0] > b[0]
    if a[1] == b[1]:
        return False
    if a[1] == "":          # latest is final, installed is a pre-release of the same number
        return True
    if b[1] == "":
        return False
    return a[1] > b[1]


def installed_version(run=subprocess.run, version_file=None):
    """The .deb's version if dpkg knows Agenti, else the VERSION file, else None."""
    try:
        r = run(["dpkg-query", "-W", "-f=${Version}", "agenti"], capture_output=True, text=True, timeout=5)
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip().split("-")[0] if parse_version(r.stdout.strip().split("-")[0]) else r.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        pass
    path = Path(version_file) if version_file else Path(__file__).resolve().parent / "VERSION"
    try:
        return path.read_text().strip() or None
    except OSError:
        return None


def fetch_latest(opener=urllib.request.urlopen):
    """(tag, page_url) of the latest published release, or raises RuntimeError with a plain reason."""
    req = urllib.request.Request(API_URL, headers={"User-Agent": "agenti", "Accept": "application/vnd.github+json"})
    try:
        with opener(req, timeout=TIMEOUT_S) as r:
            raw = r.read(MAX_BYTES + 1)
    except Exception as e:  # noqa: BLE001 - any failure becomes a plain message
        code = getattr(e, "code", None)
        if code == 404:
            raise RuntimeError("no release has been published yet") from e
        raise RuntimeError(f"could not reach GitHub ({e.__class__.__name__}: {e}); check this machine's internet access") from e
    if len(raw) > MAX_BYTES:
        raise RuntimeError("GitHub's reply was unexpectedly large; ignoring it")
    try:
        data = json.loads(raw)
        tag, url = str(data["tag_name"]), str(data.get("html_url", ""))
    except (ValueError, KeyError, TypeError) as e:
        raise RuntimeError("GitHub's reply was not a release description") from e
    if parse_version(tag) is None:
        raise RuntimeError(f"the latest release has an unrecognised version tag {tag!r}")
    if url and not url.startswith(f"https://github.com/{REPO}/"):
        url = f"https://github.com/{REPO}/releases"
    return tag.lstrip("v"), url


def check(enabled, installed=None, fetch=fetch_latest, now=time.time):
    """The whole answer as a dict (always has 'enabled', 'installed', 'checked').
    Makes NO network request unless `enabled` is true."""
    out = {"enabled": bool(enabled), "installed": installed, "checked": False,
           "latest": None, "update_available": False, "release_url": None,
           "install_command": None, "error": None, "enable_command": None,
           "checked_at": None}
    if not enabled:
        out["enable_command"] = ENABLE_COMMAND
        return out
    try:
        latest, url = fetch()
    except RuntimeError as e:
        out["error"] = str(e)
        return out
    out.update(checked=True, latest=latest, release_url=url or None, checked_at=int(now()))
    if installed is None:
        out["error"] = "could not tell which version is installed"
        return out
    out["update_available"] = is_newer(latest, installed)
    if out["update_available"]:
        out["install_command"] = INSTALL_COMMAND
    return out


def render(res):
    """Human text for the terminal."""
    if not res["enabled"]:
        return ("Update checking is off (the default): this machine makes no request to GitHub.\n"
                f"  Installed version: {res['installed'] or 'unknown'}\n"
                f"  To allow it:       {res['enable_command']}")
    if res["error"] and not res["checked"]:
        return f"Could not check for updates: {res['error']}."
    lines = [f"Installed version: {res['installed'] or 'unknown'}", f"Latest release:    {res['latest']}"]
    if res["error"]:
        lines.append(f"Note: {res['error']}.")
    elif res["update_available"]:
        lines += ["", "A newer version is available. Nothing has been installed. To update:",
                  f"  {res['install_command']}"]
        if res["release_url"]:
            lines.append(f"Release notes: {res['release_url']}")
    else:
        lines.append("You are up to date.")
    return "\n".join(lines)


def main(argv):
    enabled = "--enabled" in argv
    res = check(enabled, installed_version())
    if "--json" in argv:
        print(json.dumps(res))
    else:
        print(render(res))
    # In --json mode the answer (error included) is the body; a non-zero exit would make
    # the API treat "no release yet" as a server failure.
    return 0 if ("--json" in argv or not res["error"]) else 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main(sys.argv[1:]))
