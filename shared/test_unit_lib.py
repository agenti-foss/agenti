#!/usr/bin/env python3
"""Tests for shared/capability-dropin.sh — the systemd-unit helpers that the
agenti CLI, deploy.sh and vault.sh all source.

No root, no systemd, no vault: each case runs the real library in bash against
a throwaway SYSTEMD_DIR, with `chown`, `systemctl` and install's -o/-g owner
flags stubbed out (ownership is the only thing a non-root user cannot do).

What a regression here would silently break:
  - team_dropin binding something for a solo run, or more than one team's chat;
  - a capability drop-in widening past the template's ceiling.

Run: python3 shared/test_unit_lib.py   (exits non-zero on failure)
"""
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path

LIB = Path(__file__).resolve().parent / "capability-dropin.sh"
TEMPLATE = Path(__file__).resolve().parent / "agenti-instance@.service"

STUBS = r'''
ok()   { printf 'OK %s\n' "$*"; }
warn() { printf 'WARN %s\n' "$*"; }
die()  { printf 'DIE %s\n' "$*"; exit 1; }
chown() { :; }
systemctl() { :; }
install() {
    local a=()
    while [[ $# -gt 0 ]]; do
        case "$1" in -o|-g) shift 2 ;; *) a+=("$1"); shift ;; esac
    done
    command install "${a[@]}"
}
'''

passed = failed = 0


def check(label, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print(f"  [ OK ] {label}")
    else:
        failed += 1
        print(f"  [FAIL] {label}" + (f"\n         {detail}" if detail else ""))


def sh(sysdir: Path, script: str, root: str | None = None) -> subprocess.CompletedProcess:
    # The path table (paths.sh) pinned to the test's own folders.
    top = sysdir.parent
    paths = (f"export AGENTI_ROOT={shlex.quote(str(root or top / 'data'))} AGENTI_LIBDIR={top / 'lib'} "
             f"AGENTI_RUNTIME={top / 'rt'} AGENTI_ETC={top / 'etc'}\n")
    body = f"set -euo pipefail\n{STUBS}\n{paths}SYSTEMD_DIR={sysdir}\nsource {LIB}\n{script}\n"
    return subprocess.run(["bash", "-c", body], capture_output=True, text=True)


def lines(out: str) -> list[str]:
    return [l for l in out.splitlines() if l.strip()]


with tempfile.TemporaryDirectory() as td:
    sd = Path(td) / "systemd"
    sd.mkdir()
    (Path(td) / "lib" / "agents" / "enum").mkdir(parents=True)
    (Path(td) / "etc").mkdir()

    print("render_slot_template")
    r = sh(sd, f'render_slot_template enum agenti-run {TEMPLATE}')
    unit = sd / "agenti-enum-instance@.service"
    check("writes the slot template and prints its path", r.returncode == 0 and r.stdout.strip() == str(unit), r.stderr)
    text = unit.read_text() if unit.exists() else ""
    check("substitutes account and agent",
          "User=agenti-run" in text and "Environment=AGENT_NAME=enum" in text and "__" not in text)
    check("binds no part of teams/ (team chat only via a team slot's drop-in)",
          not any(l.startswith(("BindPaths", "ReadWritePaths")) and "teams" in l for l in text.splitlines()))
    r = sh(sd, f'render_slot_template enum agenti-run {TEMPLATE}')
    check("unchanged on a second render (prints nothing)", r.returncode == 0 and r.stdout.strip() == "")
    r = sh(sd, 'render_slot_template enum agenti-run /nonexistent')
    check("returns 1 when the template is missing", r.returncode == 1)
    r = sh(sd, f'slot_template_agent {unit}')
    check("slot_template_agent reads the agent back from the file", r.stdout.strip() == "enum")
    check("a shipped agent runs from the code folder, on the bundled agent Python",
          f"ExecStart={td}/rt/agent/bin/python3 {td}/lib/agents/enum/enum-agent.py" in text
          and f"ExecStartPre={td}/rt/agent/bin/python3 {td}/lib/preflight.py" in text, text[:0])
    check("the harness is imported from the code folder", f"Environment=PYTHONPATH={td}/lib" in text)
    check("the run sees the data root's org/ as an empty read-only folder",
          f"TemporaryFileSystem={td}/data/org:ro" in text)
    check("vault off: no mount assertion (the data root is a plain folder)",
          "AssertPathIsMountPoint" not in text)
    _fam = [l for l in text.splitlines() if l.startswith("RestrictAddressFamilies=")]
    check("audit run 2: enum gets no raw packet sockets (AF_PACKET skips the IP fence)",
          len(_fam) == 1 and "AF_PACKET" not in _fam[0] and "AF_INET" in _fam[0], _fam)
    (Path(td) / "lib" / "agents" / "trafficmon").mkdir(parents=True, exist_ok=True)
    _sd2 = Path(td) / "systemd-tm"; _sd2.mkdir()
    sh(_sd2, f'render_slot_template trafficmon agenti-run {TEMPLATE}')
    _tm = (_sd2 / "agenti-trafficmon-instance@.service").read_text()
    check("...trafficmon alone keeps them, for its capture",
          [l for l in _tm.splitlines() if l.startswith("RestrictAddressFamilies=")],
          ["RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK AF_PACKET"])
    r = sh(sd, f'render_slot_template mine agenti-run {TEMPLATE}')
    built = (sd / "agenti-mine-instance@.service").read_text()
    check("an agent built in Settings runs from the data root's shared/agents/",
          f"ExecStart={td}/rt/agent/bin/python3 {td}/data/shared/agents/mine/mine-agent.py" in built)
    (Path(td) / "etc" / "vault.conf").write_text("IMAGE=/x\n")
    r = sh(sd, f'render_slot_template enum agenti-run {TEMPLATE}')
    text = unit.read_text()
    check("vault on: re-rendered with the data root asserted as a mount point",
          r.stdout.strip() == str(unit) and f"AssertPathIsMountPoint={td}/data" in text)
    (Path(td) / "etc" / "vault.conf").unlink()
    sh(sd, f'render_slot_template enum agenti-run {TEMPLATE}')
    r = sh(sd, f'render_slot_template enum agenti-run {TEMPLATE}', root="/srv/my data")
    check("a data root with a space is refused, nothing written", r.returncode == 1 and "refusing" in r.stdout
          and "/srv/my data" not in unit.read_text())

    print("all_unit_paths")
    sh(sd, f'render_slot_template research agenti-run {TEMPLATE}')
    for d in ("agenti-enum-instance@.service.d", "agenti-enum-instance@bob.team-proj.service.d"):
        (sd / d).mkdir()
    r = sh(sd, 'all_unit_paths')
    got = sorted(Path(l).name for l in lines(r.stdout))
    want = sorted(["agenti-enum-instance@.service", "agenti-enum-instance@.service.d",
                   "agenti-enum-instance@bob.team-proj.service.d",
                   "agenti-mine-instance@.service", "agenti-research-instance@.service"])
    check("lists every template with its template and slot drop-ins", got == want, f"got {got}")

    print("team_dropin")
    r = sh(sd, 'team_dropin enum bob')
    check("a solo slot gets no drop-in", r.returncode == 0 and r.stdout.strip() == "")
    r = sh(sd, 'team_dropin enum bob.lab2')
    check("a second copy (not a team) gets no drop-in", r.stdout.strip() == "")
    r = sh(sd, 'team_dropin enum bob.team-proj')
    binds = [l for l in r.stdout.splitlines() if l.startswith(("BindReadOnlyPaths=", "BindPaths=", "ReadWritePaths="))]
    check("a team slot sees its team's channel folder read-only and may write only its OWN file (N02)",
          binds == [f"BindReadOnlyPaths={td}/data/org/teams/proj.d",
                    f"BindPaths={td}/data/org/teams/proj.d/member-enum.jsonl",
                    f"ReadWritePaths={td}/data/org/teams/proj.d/member-enum.jsonl"], f"got {binds}")

    print("userkey_dropin")
    r = sh(sd, 'userkey_dropin bob')
    check("the owner's own key file is loaded last, optional (N01)",
          [l for l in r.stdout.splitlines() if l.startswith("EnvironmentFile")]
          == [f"EnvironmentFile=-{td}/data/org/users/bob/secrets.env"], r.stdout)

    print("write_dropin / remove_dropin")
    u = "agenti-enum-instance@carol.team-q.service"
    r = sh(sd, f'write_dropin {u} team "$(team_dropin enum carol.team-q)"')
    f = sd / f"{u}.d" / "team.conf"
    check("writes <unit>.d/<name>.conf", r.returncode == 0 and f.is_file() and "q.d/member-enum.jsonl" in f.read_text(), r.stderr)
    mtime = f.stat().st_mtime_ns
    sh(sd, f'write_dropin {u} team "$(team_dropin enum carol.team-q)"')
    check("same content is not rewritten", f.stat().st_mtime_ns == mtime)
    sh(sd, f'remove_dropin {u} team')
    check("remove deletes the file and the now-empty folder", not f.exists() and not f.parent.exists())
    r = sh(sd, f'remove_dropin {u} team')
    check("removing again is a harmless no-op", r.returncode == 0)

    print("render_capability_dropin")
    cap = Path(td) / "research.capabilities"
    cap.write_text("# none needed\n")
    r = sh(sd, f'render_capability_dropin research {cap}')
    conf = sd / "agenti-research-instance@.service.d" / "capabilities.conf"
    check("narrows on the slot TEMPLATE", r.returncode == 0 and conf.is_file(), r.stdout + r.stderr)
    cap.write_text("CAP_SYS_ADMIN\nCAP_SETUID\n")
    r = sh(sd, f'render_capability_dropin research {cap}')
    check("refuses to widen past the template ceiling", r.returncode != 0 and "DIE" in r.stdout)
    r = sh(sd, 'render_capability_dropin research')
    check("no capabilities file removes the drop-in", not conf.exists())

    print("render_capability_dropin: the analysis sandbox")
    pconf = sd / "agenti-pcap-instance@.service.d" / "capabilities.conf"
    cap = Path(td) / "pcap.capabilities"
    cap.write_text("# bubblewrap needs this in the BOUNDING set only\nCAP_SYS_ADMIN\n")
    r = sh(sd, f'render_capability_dropin pcap {cap}')
    text = pconf.read_text() if pconf.is_file() else ""
    unit_lines = [ln for ln in text.splitlines() if ln and not ln.startswith("#")]
    check("CAP_SYS_ADMIN alone is accepted", r.returncode == 0 and pconf.is_file(), r.stdout + r.stderr)
    check("...it goes in the BOUNDING set", "CapabilityBoundingSet=CAP_SYS_ADMIN" in unit_lines, text)
    check("...and is NEVER ambient (it would be live on the agent process itself)",
          not any(ln.startswith("AmbientCapabilities=") and ln != "AmbientCapabilities=" for ln in unit_lines), text)
    check("...the template's raw-socket capabilities are dropped (it touches no network)",
          "CAP_NET_RAW" not in text.replace("# ", "").replace("(CAP_NET_RAW CAP_NET_ADMIN)", ""), text)
    check("...with exactly the two settings the sandbox needs relaxed",
          "RestrictSUIDSGID=no" in unit_lines and "ProtectKernelTunables=no" in unit_lines, text)
    check("...and no other hardening setting touched",
          sorted(ln.split("=")[0] for ln in unit_lines if "=" in ln and ln.endswith("=no"))
          == ["ProtectKernelTunables", "RestrictSUIDSGID"], text)
    cap.write_text("CAP_NET_RAW\nCAP_SYS_ADMIN\n")
    sh(sd, f'render_capability_dropin pcap {cap}')
    text = pconf.read_text()
    check("with a network capability too, only THAT one is ambient",
          "AmbientCapabilities=CAP_NET_RAW" in text and "AmbientCapabilities=CAP_NET_RAW CAP_SYS_ADMIN" not in text, text)
    cap.write_text("CAP_NET_RAW\n")
    sh(sd, f'render_capability_dropin pcap {cap}')
    text = pconf.read_text()
    check("without CAP_SYS_ADMIN nothing is relaxed", "RestrictSUIDSGID" not in text and "ProtectKernelTunables" not in text, text)
    cap.write_text("CAP_SYS_ADMIN\nCAP_SYS_PTRACE\n")
    r = sh(sd, f'render_capability_dropin pcap {cap}')
    check("any other capability is still refused", r.returncode != 0 and "DIE" in r.stdout)

    print("render_capability_dropin: every real file-analysis agent's capfile actually asks for the sandbox cap")
    # Found live 2026-10-08: cracker-agent/cracker.capabilities was ALL COMMENTS
    # ("capability-dropin.sh adds CAP_SYS_ADMIN for every file-analysis agent
    # regardless of this file") describing behaviour render_capability_dropin
    # does not and never did implement — it only grants what a capfile lists
    # literally. The rendered drop-in came out with an empty
    # CapabilityBoundingSet=, bubblewrap couldn't create its sandbox, and
    # preflight.py's check_sandbox() then failed ExecStartPre — which fails
    # `systemctl start` itself, synchronously, before any journal entry
    # exists. Guards every scope_kind=="files" agent shipped in the repo,
    # not just cracker, so a future one can't ship the same silent gap.
    REPO = LIB.parent.parent
    for manifest in sorted(REPO.glob("*-agent/manifest.json")):
        import json as _json
        kind = _json.loads(manifest.read_text()).get("scope_kind", "")
        if kind != "files":
            continue
        agent_dir = manifest.parent
        name = agent_dir.name.removesuffix("-agent")
        capfile = agent_dir / f"{name}.capabilities"
        check(f"{name}.capabilities exists", capfile.is_file())
        conf = sd / f"agenti-{name}-instance@.service.d" / "capabilities.conf"
        r = sh(sd, f'render_capability_dropin {name} {capfile}')
        text = conf.read_text() if conf.is_file() else ""
        check(f"{name}: a file-analysis agent's capfile actually grants CAP_SYS_ADMIN (bounding set)",
              r.returncode == 0 and "CapabilityBoundingSet=CAP_SYS_ADMIN" in text, r.stdout + r.stderr + text)

print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
