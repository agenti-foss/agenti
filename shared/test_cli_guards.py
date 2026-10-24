#!/usr/bin/env python3
"""test_cli_guards.py — the CLI's own refusals behind the web bridge
(audit run 1, fix 2d). No root, no systemd: the real bash functions are
loaded from shared/agenti and run with journalctl/exec stubbed.

    python3 shared/test_cli_guards.py

  * `<agent> logs` passes only -n N and -f to journalctl (F12);
  * `<agent> export` refuses Agenti's own folders and system folders (F11);
  * `vault ... --help` is console-only like every other vault call (F17);
  * `set-key` is console-only;
  * every Python the CLI starts ignores the caller's working directory (F14).
"""
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
CLI = (HERE / "agenti").read_text()
PASS = FAIL = 0


def check(label, got, want):
    global PASS, FAIL
    if got == want:
        PASS += 1; print(f"  [ OK ] {label}")
    else:
        FAIL += 1; print(f"  [FAIL] {label}\n         got  {got!r}\n         want {want!r}")


def func(name: str) -> str:
    m = re.search(rf"^{re.escape(name)}\(\) \{{.*?^\}}", CLI, re.M | re.S)
    assert m, name
    return m.group(0)


PRELUDE = r'''
set -u
die() { printf 'DIE: %s\n' "$*"; exit 3; }
journalctl() { printf 'JOURNALCTL'; printf ' [%s]' "$@"; printf '\n'; }
unit() { printf 'agenti-%s-instance@x.service' "$1"; }
'''


def bash(body: str, *args: str) -> str:
    return subprocess.run(["bash", "-c", PRELUDE + body, "t", *args], capture_output=True, text=True).stdout


print("\n=== F12: logs passes only -n N and -f ===")
logs = func("require_int") + "\n" + func("cmd_logs").replace("exec journalctl", "journalctl") + '\ncmd_logs enum "$@"'
check("no options: the last 100 lines", bash(logs).strip(),
      "JOURNALCTL [-u] [agenti-enum-instance@x.service] [-n] [100] [--no-pager]")
check("-n 20 -f", bash(logs, "-n", "20", "-f").strip(),
      "JOURNALCTL [-u] [agenti-enum-instance@x.service] [-n] [20] [--no-pager] [-f]")
for bad in (["--vacuum-time=1s"], ["+", "_COMM=sudo"], ["--rotate"], ["-n", "5;rm"], ["-u", "ssh.service"]):
    out = bash(logs, *bad)
    check(f"refused, journalctl never runs: {bad}", ("DIE:" in out, "JOURNALCTL" in out), (True, False))

print("\n=== F11: export stays out of Agenti's own and the system's folders ===")
tmp = Path(tempfile.mkdtemp())
export = (f'LIBDIR=/usr/lib/agenti; AGENTI_STATE=/var/lib/agenti; AGENTI_ROOT=/var/lib/agenti/data; '
          f'AGENTI_ETC=/etc/agenti; DRY_RUN=1; run() {{ printf "RUN %s\\n" "$*"; }}; '
          f'agent_dir() {{ printf {tmp}; }}; ok() {{ :; }}; warn() {{ :; }}\n'
          + func("cmd_export") + '\ncmd_export enum "$@"')
for dest in ("/usr/lib/agenti/agents", "/var/lib/agenti/data/x", "/etc", "/usr/local/bin",
             "/var/lib/agenti/data/../../agenti/data", "/proc/self"):
    out = bash(export, dest)
    check(f"refused: {dest}", ("DIE:" in out and "REFUSING" in out, "RUN mkdir" in out), (True, False))
check("a folder of your own is fine", "RUN mkdir" in bash(export, str(tmp / "delivery")), True)

print("\n=== F17, set-key: console-only, help included ===")
vault_pre = re.search(r'if \[\[ "\$\{1:-\}" == "vault" \]\]; then\n(.*?)\nfi\n', CLI, re.S).group(1)
check("the vault --help path calls console_only before reaching vault.sh",
      vault_pre.index("console_only") < vault_pre.index("cmd_vault"), True)
check("cmd_setkey starts with console_only", func("cmd_setkey").splitlines()[1].strip().startswith("console_only"), True)
cons = 'invoking_user() { printf "%s" "${SUDO_USER:-root}"; }\n' + func("console_only") + '\nconsole_only "vault lock"; echo PASSED'
check("console_only refuses the web account", "REFUSING" in subprocess.run(
    ["bash", "-c", PRELUDE + cons], capture_output=True, text=True, env={**os.environ, "SUDO_USER": "agenti-api"}).stdout, True)
check("...and lets a console user through", "PASSED" in subprocess.run(
    ["bash", "-c", PRELUDE + cons], capture_output=True, text=True, env={**os.environ, "SUDO_USER": "alice"}).stdout, True)

print("\n=== F14: no Python the CLI starts imports from the caller's folder ===")
check("the CLI exports PYTHONSAFEPATH=1 right after set -euo pipefail",
      "set -euo pipefail\n" in CLI and CLI.index("export PYTHONSAFEPATH=1") < CLI.index("set -euo pipefail") + 400, True)
check("...and PYTHONPATH names the code folder, so the helpers still import each other",
      "PYTHONPATH=\"$(dirname \"$(readlink -f \"$_paths_sh\")\")\"" in CLI and "export PYTHONPATH" in CLI, True)
for helper in ("iam.py", "tool_approvals.py", "tool_settings_store.py", "preflight.py", "scope_cidr.py"):
    r = subprocess.run([sys.executable, str(HERE / helper), "--help"], cwd=tempfile.gettempdir(),
                       capture_output=True, text=True,
                       env={**os.environ, "PYTHONSAFEPATH": "1", "PYTHONPATH": str(HERE)})
    check(f"{helper} imports its siblings under PYTHONSAFEPATH + PYTHONPATH",
          "ModuleNotFoundError" in r.stderr, False)
plant = Path(tempfile.mkdtemp())
(plant / "json.py").write_text("raise SystemExit('PLANTED')\n")
r = subprocess.run(["bash", "-c", "export PYTHONSAFEPATH=1; python3 -c 'import json; print(\"stdlib\")'"],
                   cwd=plant, capture_output=True, text=True)
check("with it, a planted json.py in the current folder is ignored", r.stdout.strip(), "stdlib")

print("\n=== audit run 2, decision 3: the web tier cannot choose who or how ===")
import ast as _ast
_unguarded = []
for _p in sorted(list(HERE.glob("*.py")) + list(HERE.parent.glob("*-agent/*.py"))):
    if _p.name.startswith("test_"):
        continue
    for _n in _ast.walk(_ast.parse(_p.read_text())):
        if isinstance(_n, _ast.Call):
            _f = _n.func.attr if isinstance(_n.func, _ast.Attribute) else getattr(_n.func, "id", "")
            if (_f == "add_parser" or _f.endswith("ArgumentParser")) and not any(
                    k.arg == "allow_abbrev" and getattr(k.value, "value", None) is False for k in _n.keywords):
                _unguarded.append(f"{_p.name}:{_n.lineno}")
check("every argparse parser and subparser refuses abbreviated options", _unguarded, [])
ident = 'invoking_user() { printf "%s" "${SUDO_USER:-root}"; }\n' + func("_via") + "\n" + \
        func("_refuse_identity_from_api") + '\nfor a in "$@"; do _refuse_identity_from_api set "$a"; done; echo PASSED'
for bad in ("--by=mallory", "--by", "--via=cli", "--via"):
    out = subprocess.run(["bash", "-c", PRELUDE + ident, "t", bad], capture_output=True, text=True,
                         env={**os.environ, "SUDO_USER": "agenti-api"}).stdout
    check(f"engagement set/approve from the web refuses {bad}", "DIE:" in out and "PASSED" not in out, True)
check("...a console admin may still name --by",
      "PASSED" in subprocess.run(["bash", "-c", PRELUDE + ident, "t", "--by=alice"], capture_output=True,
                                 text=True, env={**os.environ, "SUDO_USER": "alice"}).stdout, True)
for fn in ("cmd_org_engagement_set", "cmd_org_engagement_approve"):
    body = func(fn)
    check(f"{fn} checks every argument for a caller identity", "_refuse_identity_from_api" in body, True)
    check(f"{fn} passes the CLI's own --by/--via LAST", bool(re.search(r'"\$\{args\[@\]\}" --by "\$by" --via "\$via"', body)), True)
for fn in ("cmd_team_say", "cmd_team_note", "cmd_say", "cmd_note", "cmd_set_model", "cmd_acknowledge",
           "cmd_action_approve", "cmd_action_reject", "cmd_tool_settings"):
    body = func(fn)
    check(f"{fn}: --via comes from sudo, never the caller",
          ("via=$(_via)" in body, bool(re.search(r'via="\$2"', body))), (True, False))
new_block = re.search(r'if \[\[ "\$\{1:-\}" == "new" \]\]; then\n(.*?)\nfi\n', CLI, re.S).group(1)
check("'new' is console-only, before cmd_new", new_block.index("console_only new") < new_block.index("cmd_new"), True)

print("\n=== audit run 2: scans lists a run's names without handing them to a program ===")
slot = Path(tempfile.mkdtemp())
(slot / "scans" / "window-1").mkdir(parents=True)
(slot / "scans" / "window-1" / "t.log").write_text("x" * 2048)
weird = slot / "scans" / "a\n--files0-from=secret"
weird.mkdir()
(weird / "f.txt").write_text("y")
(slot / "scans" / "link.txt").symlink_to("/etc/hostname")
scans = (f'lib_dir() {{ printf %s "{HERE}"; }}; agent_dir() {{ printf %s "{slot}"; }}\n'
         + func("_slot_list_recursive") + "\n" + func("cmd_scans") + "\ncmd_scans enum")
out = bash(scans)
check("nested evidence is listed with its size", "window-1/t.log" in out and "2.0K" in out, True)
check("a name with a newline is ONE escaped line, not an option on its own line",
      ("a\\n--files0-from=secret/f.txt" in out, any(ln.startswith("--") for ln in out.splitlines())), (True, False))
check("a planted link is not listed (never followed)", "link.txt" in out, False)
check("du is gone from cmd_scans", "du " in func("cmd_scans"), False)

print("\n=== audit run 2: --bind takes a literal address, and IPv6 is written in brackets ===")
CONF = (HERE / "configure.sh").read_text()
def cfunc(name):
    m = re.search(rf"^{re.escape(name)}\(\) \{{.*?^\}}|^{re.escape(name)}\(\) \{{[^\n]*\}}$", CONF, re.M | re.S)
    assert m, name
    return m.group(0)
_vb = cfunc("valid_bind") + "\n" + cfunc("listen_addr") + "\n" + cfunc("is_loopback") + \
      '\nfor a in "$@"; do if valid_bind "$a"; then printf "%s=%s\\n" "$a" "$(listen_addr "$a" 8420)"; else printf "%s=REFUSED\\n" "$a"; fi; done'
_out = subprocess.run(["bash", "-c", _vb, "t", "127.0.0.1", "::1", "192.168.1.20", "localhost", "beef",
                       "999.1.1.1", "0.0.0.0", "fe80::1"], capture_output=True, text=True).stdout.split()
check("addresses render as systemd reads them; names and bad addresses are refused", _out,
      ["127.0.0.1=127.0.0.1:8420", "::1=[::1]:8420", "192.168.1.20=192.168.1.20:8420", "localhost=REFUSED",
       "beef=REFUSED", "999.1.1.1=REFUSED", "0.0.0.0=0.0.0.0:8420", "fe80::1=[fe80::1]:8420"])
check("the socket unit is rendered through listen_addr", 'ListenStream=$(listen_addr "$BIND_HOST" "$BIND_PORT")' in CONF, True)

print("\n=== audit run 2: every root entry-point script keeps Python off the caller's folder ===")
for _sc in ("verify.sh", "configure.sh", "deploy.sh", "../packaging/install-tree.sh"):
    _t = (HERE / _sc).read_text()
    _first_py = min((i for i in (_t.find("python3 -"), _t.find("python3 \""), _t.find("PY=")) if i >= 0), default=len(_t))
    check(f"{_sc} exports PYTHONSAFEPATH=1 and PYTHONPATH before any Python",
          ("export PYTHONSAFEPATH=1" in _t and "export PYTHONPATH=" in _t
           and _t.index("export PYTHONSAFEPATH=1") < _first_py), True)

print("\n=== audit run 2: a resume is held to the same start checks ===")
_org = Path(tempfile.mkdtemp())
(_org / "approval.json").write_text('{"approved_by": "alice"}')
(_org / "iam.py").write_text('import json; print(json.dumps({"require-separate-approver": "on"}))')
_asa = (f'invoking_user() {{ printf "%s" "${{SUDO_USER:-root}}"; }}; org_dir() {{ printf %s "{_org}"; }}\n'
        f'IAM_PY="{_org}/iam.py"; _iam_can() {{ [[ "$1" != nostart ]]; }}\n'
        + func("_assert_start_authority") + '\n_assert_start_authority "$1" enum resuming; echo PASSED')
for who, user, want in (("alice", "root", "DIE"), ("bob", "root", "PASSED"), ("nostart", "agenti-api", "DIE"),
                        ("bob", "agenti-api", "PASSED")):
    out = subprocess.run(["bash", "-c", PRELUDE + _asa, "t", who], capture_output=True, text=True,
                         env={**os.environ, "SUDO_USER": user}).stdout
    check(f"resume by {who} (via {user}): {want}", "DIE:" in out if want == "DIE" else "PASSED" in out, True)
_res = func("cmd_resume")
check("cmd_resume checks authority before it thaws or starts anything",
      _res.index("_assert_start_authority") < min(_res.index("systemctl thaw"), _res.index("systemctl start")), True)
check("cmd_start uses the same helper", "_assert_start_authority \"$launched_by\"" in func("cmd_start"), True)

print("\n=== audit run 2: logs shows only this slot's own lifetime ===")
_ls = Path(tempfile.mkdtemp()); (_ls / "run-created").write_text("1792800000\n")
_lg = (f'agent_dir() {{ printf %s "{_ls}"; }}\n' + func("require_int") + "\n"
       + func("cmd_logs").replace("exec journalctl", "journalctl") + '\ncmd_logs enum "$@"')
check("journalctl starts at the slot's creation", bash(_lg).strip(),
      "JOURNALCTL [-u] [agenti-enum-instance@x.service] [--since] [@1792800000] [-n] [100] [--no-pager]")
check("logs needs the slot to exist now (a renamed user's slots moved away)",
      'logs)           require_slot "$AGENT"; cmd_logs' in CLI, True)

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
