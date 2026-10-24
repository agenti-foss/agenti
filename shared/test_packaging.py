#!/usr/bin/env python3
"""test_packaging.py — the .deb and what goes into it (docs/packaging.md).

What a regression here would silently break: a closed file shipped in the open
package, a developer script shipped to users, an old /usr/local or /opt path
left in a shipped file, a maintainer script that dpkg cannot run, a sudoers
grant that breaks sudo for the whole machine, an agent name that shadows a
CLI verb, or an agent's run unit enabled to start on boot.

Builds into a temporary folder; no root, no network. Needs dpkg-deb (skips
loudly without it).

    python3 shared/test_packaging.py
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
PKG = REPO / "packaging"
PASS = FAIL = SKIP = 0


def check(name, got, want):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print(f"  [ OK ] {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name}\n         got  {got!r}\n         want {want!r}")


def skip(name, why):
    global SKIP
    SKIP += 1
    print(f"  [SKIP] {name} — {why}")


def run(*cmd, **kw):
    return subprocess.run([str(c) for c in cmd], capture_output=True, text=True, **kw)


def bash_array(script: Path, name: str) -> list:
    m = re.search(rf"^{name}=\((.*?)\)", script.read_text(), re.S | re.M)
    return re.sub(r"#.*", "", m.group(1)).split() if m else []


tree_sh = PKG / "install-tree.sh"
CORE, DEV, DOCS = (bash_array(tree_sh, n) for n in ("CORE_FILES", "DEV_FILES", "DOC_FILES"))
# Each closed agent's files, from its own conf (present only where its private
# repo is overlaid on this checkout).
PLUGIN = [f for c in sorted((PKG / "plugins").glob("*.conf")) for f in bash_array(c, "PLUGIN_FILES")]
tmp = Path(tempfile.mkdtemp(prefix="agenti-test-pkg-"))
env = {**os.environ, "TMPDIR": str(tmp)}

print("what ships: every file in shared/ is classified exactly once")
listed = CORE + PLUGIN + DEV + DOCS
check("no file is in two lists", sorted({f for f in listed if listed.count(f) > 1}), [])
on_disk = sorted(p.name for p in HERE.iterdir()
                 if p.is_file() and not p.name.startswith("test_") and p.name != "__pycache__")
check("every file in shared/ is in a list (install-tree.sh refuses otherwise)",
      sorted(set(on_disk) - set(listed)), [])
check("no list names a file that does not exist", sorted(set(listed) - set(on_disk)), [])

print("\nthe open core, staged")
open_root = tmp / "open"
r = run(tree_sh, REPO, open_root, env=env)
check("install-tree.sh (open) succeeds", (r.returncode, r.stderr.strip()[-200:]), (0, ""))
lib = open_root / "usr/lib/agenti"
shipped = {p.relative_to(open_root).as_posix() for p in open_root.rglob("*") if p.is_file()}
check("every CORE file is installed", sorted(f for f in CORE if f"usr/lib/agenti/{f}" not in shipped), [])
check("no plugin (closed) file is in the open core",
      sorted(s for s in shipped if any(s.endswith("/" + f) for f in PLUGIN)), [])
check("no developer file or test ships",
      sorted(s for s in shipped if s.rsplit("/", 1)[-1] in DEV and s != "usr/bin/agenti" or "/test_" in s), [])
check("the CLI is /usr/bin/agenti", "usr/bin/agenti" in shipped, True)
check("nothing is installed under /usr/local or /opt",
      sorted(s for s in shipped if s.startswith(("usr/local", "opt"))), [])
check("only the open agents ship", sorted(p.name for p in (lib / "agents").iterdir()), ["enum", "research", "trafficmon"])
check("each agent ships its tools descriptor and system prompt",
      sorted(a.name for a in (lib / "agents").iterdir()
             if not ((a / "capabilities.json").is_file() and (a / "context/system-prompt.md").is_file())), [])
help_pages = sorted(p.stem for p in (lib / "help").glob("*.md"))
check("the exploit help page stays with the closed edition", "exploiting-a-target" in help_pages, False)
check("...and index.json does not list it",
      "exploiting-a-target" in json.loads((lib / "help/index.json").read_text())["pages"], False)
bad_modes = []
for p in open_root.rglob("*"):
    if p.is_file():
        want = 0o755 if p.read_bytes()[:2] == b"#!" else 0o644
        if p.stat().st_mode & 0o7777 != want:
            bad_modes.append(f"{p.relative_to(open_root)} {oct(p.stat().st_mode & 0o7777)}")
check("modes: 0755 for scripts (#!), 0644 for everything else", bad_modes[:5], [])
check("no __pycache__ in the staged tree", list(open_root.rglob("__pycache__")), [])
old_paths = []
for p in open_root.rglob("*"):
    if p.is_file() and p.suffix in (".py", ".sh", ".service", ".js", ".html", "") and "gui/fonts" not in str(p):
        t = p.read_text(errors="replace")
        for needle in ("/opt/agenti", "/usr/local/lib/agenti", "/usr/local/bin/agenti", "deploy-api.sh"):
            if needle in t:
                old_paths.append(f"{p.relative_to(open_root)}: {needle}")
check("no shipped file names an old path or a removed script", old_paths[:8], [])
check("the GUI's scripts carry a version stamp",
      bool(re.search(r'src="js/api\.js\?v=[0-9a-f]{10}"', (lib / "api/gui/login.html").read_text())), True)

print("\nthe closed agents, one package each, staged")
def pro_item(path):
    rel = path.removeprefix("usr/lib/agenti/")
    return rel.split("/")[1] if rel.startswith("agents/") else rel.split("/")[-1]


PLUGIN_WANT = {"exploit": {"exploit_runner.py", "msf_client.py", "msf_module_catalog.py", "exploit",
                           "exploiting-a-target.md", "exploiting-a-target.json"},
               "cracker": {"hash_extract.py", "cracker"}}
present = sorted(p.stem for p in (PKG / "plugins").glob("*.conf"))
for name in present:
    pro_root = tmp / f"plugin-{name}"
    r = run(tree_sh, REPO, pro_root, "--edition", name, env=env)
    check(f"install-tree.sh --edition {name} succeeds", r.returncode, 0)
    got = {pro_item(p.relative_to(pro_root).as_posix()) for p in pro_root.rglob("*") if p.is_file()}
    check(f"agenti-{name} holds its own harness files, agent and help, nothing else",
          sorted(got), sorted(PLUGIN_WANT.get(name, got)))
r = run(tree_sh, REPO, tmp / "nope", "--edition", "pro", env=env)
check("an edition with no plugin conf is refused, naming the plugins there are",
      (r.returncode != 0, "plugin present" in r.stderr), (True, True))

print("\nthe API's sudoers grant")
sudoers = (HERE / "agenti-api.sudoers").read_text()
grants = [ln for ln in sudoers.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
bridge_default = run("bash", "-c", f'source "{HERE}/paths.sh"; printf %s "$API_BRIDGE"',
                     env={k: v for k, v in os.environ.items() if not k.startswith("AGENTI_")}).stdout
check("exactly one rule: agenti-api may run the bridge with no arguments, and nothing else", grants,
      [f'agenti-api ALL=(root) NOPASSWD: {bridge_default} ""'])
if shutil.which("visudo"):
    check("it parses (a broken file under sudoers.d breaks sudo for everyone)",
          run("visudo", "-c", "-q", "-f", HERE / "agenti-api.sudoers").returncode, 0)
else:
    skip("the sudoers file parses", "visudo is not installed")
cli = (HERE / "agenti").read_text()
_defined = set(re.findall(r"\b(c_[a-z0-9])=", cli))
_used = set(re.findall(r"\$\{?(c_[a-z0-9])\b", cli))
check("every colour the CLI prints with is defined (an undefined one killed `agenti setup`)",
      sorted(_used - _defined), [])
cfg = (HERE / "configure.sh").read_text()
check("configure.sh checks it with visudo BEFORE it reaches sudoers.d",
      cfg.index('visudo -c -q -f "$SUDOERS_SRC"') < cfg.index('mv "$SUDOERS_DST.agenti-new" "$SUDOERS_DST"'), True)
check("...through a temporary name sudo ignores (it contains a dot)", '"$SUDOERS_DST.agenti-new"' in cfg, True)

print("\nunits")
tpl = (HERE / "agenti-instance@.service").read_text()
check("the run-unit template hard-codes no path (placeholders only)",
      [ln for ln in tpl.splitlines() if not ln.startswith("#") and re.search(r"/(opt|usr|var|etc)/", ln)], [])
check("an agent's run unit has no [Install] section (never starts on boot)",
      any(ln.strip() == "[Install]" for ln in tpl.splitlines()), False)
enables = [ln for ln in cfg.splitlines() if "systemctl enable" in ln]
check("configure.sh enables only the GUI and the retention timer, never a run",
      [ln for ln in enables if "instance" in ln], [])

print("\nevery top-level verb is a reserved agent name")
cli = (HERE / "agenti").read_text()
block = cli[cli.rindex('case "${1:-}" in\n    admin)'):]
verbs = sorted(set(re.findall(r"^    ([a-z][a-z-]*)\)", block[:block.index("\nesac")], re.M)))
bridge = re.search(r"RESERVED_NAMES = frozenset\(\{(.*?)\}\)", (HERE / "api/cli_bridge.py").read_text(), re.S).group(1)
builder = re.search(r"RESERVED = frozenset\(\{(.*?)\}\)", (HERE / "agent_builder.py").read_text(), re.S).group(1)
scaffold = re.search(r"reserved = \{(.*?)\}", (HERE / "new_agent.py").read_text(), re.S).group(1)
for where, text in (("api/cli_bridge.py", bridge), ("agent_builder.py", builder), ("new_agent.py", scaffold)):
    check(f"{where} reserves {', '.join(verbs)}", [v for v in verbs if f'"{v}"' not in text], [])

print("\nthe bundled Python (agenti-runtime)")
pin = (PKG / "runtime/python.pin").read_text()
arches = dict((m[0], m[2]) for m in re.findall(r"^(amd64|arm64) (\S+) ([0-9a-f]{64})$", pin, re.M))
check("python.pin pins both CPU types with a SHA-256", sorted(arches), ["amd64", "arm64"])
check("runtime/VERSION is X.Y.Z", bool(re.fullmatch(r"\d+\.\d+\.\d+", (PKG / "runtime/VERSION").read_text().strip())), True)
for env_name in ("agent", "api", "authd"):
    lock = (PKG / f"runtime/{env_name}.lock").read_text()
    pkgs = re.findall(r"^([a-z0-9][a-z0-9._-]*)==", lock, re.M)
    blocks = re.split(r"\n(?=[a-z0-9])", lock)
    unhashed = [b.split("==")[0] for b in blocks if "==" in b and "--hash=sha256:" not in b]
    check(f"{env_name}.lock: {len(pkgs)} packages, every one pinned by hash", (len(pkgs) > 0, unhashed), (True, []))
authd_pkgs = re.findall(r"^([a-z0-9][a-z0-9._-]*)==", (PKG / "runtime/authd.lock").read_text(), re.M)
check("authd's environment holds cryptography and its own two dependencies only", sorted(authd_pkgs),
      ["cffi", "cryptography", "pycparser"])

print("\nthe packages")
if not shutil.which("dpkg-deb"):
    skip("build both packages", "dpkg-deb is not installed")
else:
    dist = tmp / "dist"
    for edition in ("open", *present):
        r = run(PKG / "build-deb.sh", "dev", dist, "--edition", edition, env=env)
        check(f"build-deb.sh dev --edition {edition}", (r.returncode, r.stderr.strip()[-300:]), (0, ""))
    debs = {p.name.split("_")[0]: p for p in dist.glob("*.deb")}
    check("one package per edition, architecture all",
          sorted((n, p.name.endswith("_all.deb")) for n, p in debs.items()),
          sorted([("agenti", True)] + [(f"agenti-{n}", True) for n in present]))
    api_n = (HERE / "PLUGIN_API_VERSION").read_text().strip()
    rt_v = (PKG / "runtime/VERSION").read_text().strip()

    def field(deb, name):
        return run("dpkg-deb", "-f", deb, name).stdout.strip()
    check("agenti Provides the plugin API version", field(debs["agenti"], "Provides"), f"agenti-plugin-api-{api_n}")
    for n in present:
        check(f"agenti-{n} Depends on that same version",
              field(debs[f"agenti-{n}"], "Depends").startswith(f"agenti-plugin-api-{api_n}"), True)
    dep = field(debs["agenti"], "Depends")
    check("agenti needs a compatible runtime (a range, so a major change cannot sneak in)",
          (f"agenti-runtime (>= {rt_v})" in dep, f"agenti-runtime (<< {int(rt_v.split('.')[0]) + 1})" in dep), (True, True))
    check("agent tools are Recommends, never Depends (some exist only on Kali)",
          ("nmap" in dep, "netexec" in field(debs["agenti"], "Recommends")), (False, True))
    ctl = tmp / "ctl"
    run("dpkg-deb", "-e", debs["agenti"], ctl)
    scripts = sorted(p.name for p in ctl.iterdir())
    check("maintainer scripts and the debconf question are in the package", scripts,
          ["config", "control", "md5sums", "postinst", "postrm", "prerm", "templates"])
    for s in ("postinst", "prerm", "postrm", "config"):
        text = (ctl / s).read_text()
        check(f"{s}: /bin/sh, set -e, parses, executable",
              (text.startswith("#!/bin/sh\n"), "\nset -e\n" in text, run("sh", "-n", ctl / s).returncode,
               (ctl / s).stat().st_mode & 0o111 != 0), (True, True, 0, True))
    tpl_text = (ctl / "templates").read_text()
    check("the purge question defaults to No (keep the data)",
          bool(re.search(r"Template: agenti/purge-data\nType: boolean\nDefault: false\n", tpl_text)), True)
    post = (ctl / "postinst").read_text()
    check("postinst runs configure.sh, with --first only on a first install",
          ("configure.sh install --first" in post, 'if [ -z "$2" ]' in post), (True, True))
    check("prerm stops everything on remove, nothing on upgrade",
          bool(re.search(r"remove\|deconfigure\)\n\s+/usr/lib/agenti/configure.sh remove", (ctl / "prerm").read_text())), True)
    content = run("dpkg-deb", "-c", debs["agenti"]).stdout
    check("every file in the package is owned by root:root", sorted({ln.split()[1] for ln in content.splitlines()}), ["root/root"])
    check("Debian's copyright and changelog are there",
          ("usr/share/doc/agenti/copyright" in content, "usr/share/doc/agenti/changelog.gz" in content), (True, True))

print("\n=== audit run 2: the release signs only what its build jobs made ===")
import re as _re
_wf = Path(__file__).resolve().parent.parent / ".github" / "workflows"
_rel, _pkg = (_wf / "release.yml").read_text(), (_wf / "package.yml").read_text()
_attest = _rel[_rel.index("  attest:"):_rel.index("  publish:")]
check("the signing job downloads artifacts by name only (no merge of every artifact)",
      ("merge-multiple" in _attest, _attest.count("name: agenti-deb") + _attest.count("name: runtime-amd64")
       + _attest.count("name: runtime-arm64")), (False, 3))
check("...signs the digests the build jobs reported (subject-checksums), not a file glob",
      ("subject-checksums: dist/SHA256SUMS" in _attest, "subject-path" in _attest), (True, False))
check("...and refuses any file no build job made", "files no build job made" in _attest, True)
_imgs = _re.findall(r"(?:container:|image:)\s*\"?([^\s\",}]+)", _pkg)
check("every container image in package.yml is pinned by digest",
      [i for i in _imgs if "${{" not in i and "@sha256:" not in i], [])

shutil.rmtree(tmp, ignore_errors=True)
print(f"\n{PASS} passed, {FAIL} failed, {SKIP} skipped")
sys.exit(1 if FAIL else 0)
