#!/usr/bin/env python3
"""test_paths.py — shared/paths.sh and shared/paths.py are one table.

Every bash script sources paths.sh and every Python module imports paths.py;
if the two disagreed, the CLI and the harness would look for the same file in
two places. No root, no network.

    python3 shared/test_paths.py
"""
import os
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import paths  # noqa: E402

PASS = FAIL = 0
NAMES = ("AGENTI_LIBDIR", "AGENTI_RUNTIME", "AGENTI_STATE", "AGENTI_ROOT", "AGENTI_ETC",
         "AGENTI_BIN", "AGENTI_IAM_DB", "AGENTI_RUNTIME_DB", "AGENTI_SHIPPED_AGENTS", "AGENTI_BUILT_AGENTS")


def check(name, got, want):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print(f"  [ OK ] {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name}\n         got  {got!r}\n         want {want!r}")


def clean_env(**over):
    env = {k: v for k, v in os.environ.items() if not k.startswith("AGENTI_")}
    env.update(over)
    return env


def from_bash(env, extra=""):
    script = f'source "{HERE}/paths.sh"; ' + "; ".join(f'printf "%s=%s\\n" {n} "${n}"' for n in NAMES) + extra
    out = subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env, check=True).stdout
    return dict(line.split("=", 1) for line in out.splitlines() if "=" in line)


def from_python(env):
    saved = dict(os.environ)
    os.environ.clear()
    os.environ.update(env)
    try:
        return {"AGENTI_LIBDIR": str(paths.libdir()), "AGENTI_RUNTIME": str(paths.runtime()),
                "AGENTI_STATE": str(paths.state()), "AGENTI_ROOT": str(paths.data_root()),
                "AGENTI_ETC": str(paths.etc()), "AGENTI_BIN": str(paths.agenti_bin()),
                "AGENTI_IAM_DB": str(paths.iam_db()), "AGENTI_RUNTIME_DB": str(paths.runtime_db()),
                "AGENTI_SHIPPED_AGENTS": str(paths.shipped_agents()),
                "AGENTI_BUILT_AGENTS": str(paths.built_agents())}
    finally:
        os.environ.clear()
        os.environ.update(saved)


print("the defaults")
b, p = from_bash(clean_env()), from_python(clean_env())
for n in NAMES:
    check(f"{n} is the same in bash and Python ({b.get(n)})", b.get(n), p[n])
check("nothing lives under /usr/local", [n for n in NAMES if b.get(n, "").startswith("/usr/local")], [])
check("the data root is inside the state folder by default", b["AGENTI_ROOT"], "/var/lib/agenti/data")

print("\noverrides")
over = clean_env(AGENTI_STATE="/tmp/st", AGENTI_LIBDIR="/tmp/lib")
b, p = from_bash(over), from_python(over)
for n in NAMES:
    check(f"with AGENTI_STATE and AGENTI_LIBDIR moved, {n} still agrees", b.get(n), p[n])
check("the data root follows AGENTI_STATE", p["AGENTI_ROOT"], "/tmp/st/data")
check("an explicit AGENTI_ROOT wins", from_python(clean_env(AGENTI_ROOT="/elsewhere"))["AGENTI_ROOT"], "/elsewhere")

print("\nan agent's code folder: shipped first, then built")
with tempfile.TemporaryDirectory() as d:
    lib, root = Path(d, "lib"), Path(d, "data")
    (lib / "agents" / "enum").mkdir(parents=True)
    (root / "shared" / "agents" / "mine").mkdir(parents=True)
    env = clean_env(AGENTI_LIBDIR=str(lib), AGENTI_ROOT=str(root))
    for agent, want in (("enum", lib / "agents" / "enum"), ("mine", root / "shared" / "agents" / "mine")):
        out = subprocess.run(["bash", "-c", f'source "{HERE}/paths.sh"; agenti_master_dir {agent}'],
                             capture_output=True, text=True, env=env, check=True).stdout
        saved = dict(os.environ)
        os.environ.update(env)
        try:
            py = paths.master_dir(agent)
        finally:
            os.environ.clear()
            os.environ.update(saved)
        check(f"{agent}: bash and Python agree ({want.relative_to(d)})", (out, str(py)), (str(want), str(want)))

print("\nthe vault switch")
with tempfile.TemporaryDirectory() as d:
    env = clean_env(AGENTI_ETC=d, AGENTI_ROOT=d)
    rc = subprocess.run(["bash", "-c", f'source "{HERE}/paths.sh"; agenti_vault_enabled'], env=env).returncode
    check("no vault.conf: the vault is off", rc, 1)
    rc = subprocess.run(["bash", "-c", f'source "{HERE}/paths.sh"; agenti_data_ready'], env=env).returncode
    check("vault off and the data root exists: data is ready", rc, 0)
    Path(d, "vault.conf").write_text("IMAGE=/x\n")
    rc = subprocess.run(["bash", "-c", f'source "{HERE}/paths.sh"; agenti_data_ready'], env=env).returncode
    check("vault on and not mounted: data is NOT ready (fail closed)", rc, 1)

print("\nmodules that restate a default (they cannot import paths.py)")
src = (HERE / "api" / "cli_bridge.py").read_text()
check("the API calls the CLI where paths.sh installs it",
      'os.environ.get("AGENTI_BIN", "/usr/bin/agenti")' in src and from_bash(clean_env())["AGENTI_BIN"] == "/usr/bin/agenti", True)
src = (HERE / "help_docs.py").read_text()
check("help_docs reads the help pages from the code folder",
      'Path(os.environ.get("AGENTI_LIBDIR", "/usr/lib/agenti")) / "help"' in src, True)

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
