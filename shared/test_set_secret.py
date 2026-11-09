#!/usr/bin/env python3
"""test_set_secret.py — set-secret.sh writes keys only through keystore.py.

Runs the real script as "root" inside a user namespace (unshare -r), against
a temporary data root, state folder and in-memory folder, with dummy keys:
nothing touches a real key store. Skips loudly where user namespaces are not
allowed.

    python3 shared/test_set_secret.py
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
PASS = FAIL = SKIP = 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  [ OK ] {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name} {detail}")


def done():
    print(f"\n{PASS} passed, {FAIL} failed, {SKIP} skipped")
    sys.exit(1 if FAIL else 0)


if not shutil.which("unshare") or subprocess.run(["unshare", "-r", "true"], capture_output=True).returncode:
    SKIP += 1
    print("  [SKIP] set-secret.sh — user namespaces are not allowed here (unshare -r)")
    done()

base = Path(tempfile.mkdtemp(prefix="setsecret-"))
root, state, run, etc = base / "data", base / "state", base / "run", base / "etc"
for d in (root / "shared", root / "org", state, etc):
    d.mkdir(parents=True)
env = {**os.environ, "AGENTI_ROOT": str(root), "AGENTI_STATE": str(state), "AGENTI_KEYS_RUN": str(run),
       "AGENTI_ETC": str(etc), "AGENTI_KEYS_TPM": "0", "PYTHONPATH": str(HERE)}
PP = "a throwaway key passphrase"


def sh(*args, stdin=""):
    r = subprocess.run(["unshare", "-r", "bash", str(HERE / "set-secret.sh"), *args],
                       input=stdin, capture_output=True, text=True, env=env, timeout=120)
    return r.returncode, r.stdout + r.stderr


def keystore(*args):
    r = subprocess.run(["unshare", "-r", sys.executable, str(HERE / "keystore.py"), *args],
                       capture_output=True, text=True, env=env, timeout=120)
    return r.stdout


print("== a fresh box with no TPM and no vault")
rc, out = sh("--stdin", stdin="sk-ant-dummy-0001\n")
check("the first key without a passphrase is refused", rc != 0 and "key passphrase" in out, out)
check("…and nothing was written", not any(root.rglob("secrets.*")))
rc, out = sh("--stdin", "--passphrase-first", stdin=f"{PP}\nsk-ant-dummy-0001\n")
check("with a passphrase it is stored encrypted", rc == 0 and "encrypted (passphrase seal)" in out, out)
enc = root / "shared" / "secrets.enc"
check("the encrypted file holds no key text", enc.is_file() and b"dummy" not in enc.read_bytes())
check("no plain file", not (root / "shared" / "secrets.env").exists())

print("== one provider at a time; the other lines stay")
rc, out = sh("--stdin", "--provider", "openai", stdin="sk-openai-dummy-0002\n")
check("a second provider is saved", rc == 0, out)
held = json.loads(keystore("has", "--tier", "shared", "ANTHROPIC_API_KEY", "OPENAI_API_KEY") or "{}")
check("both keys are held", held == {"ANTHROPIC_API_KEY": True, "OPENAI_API_KEY": True}, held)
rc, out = sh("--stdin", "--provider", "anthropic", stdin="not-a-claude-key\n")
check("a mis-pasted key is refused by its prefix", rc != 0 and "sk-ant-" in out, out)
rc, out = sh("--stdin", "--provider", "local", stdin="\n")
check("a self-hosted model without an address is refused", rc != 0 and "--base-url" in out, out)
rc, out = sh("--stdin", "--provider", "local", "--base-url", "http://model.example.com:11434/v1", stdin="\n")
check("with an address it is saved, with no key", rc == 0, out)
held = json.loads(keystore("has", "--tier", "shared", "ANTHROPIC_API_KEY", "OPENAI_API_KEY",
                           "LOCAL_LLM_API_KEY", "LOCAL_LLM_BASE_URL") or "{}")
check("the address is held and the earlier keys kept",
      held == {"ANTHROPIC_API_KEY": True, "OPENAI_API_KEY": True, "LOCAL_LLM_API_KEY": False,
               "LOCAL_LLM_BASE_URL": True}, held)
rc, out = sh("--stdin", "--provider", "local", stdin="\n")
check("the saved address counts for the next self-hosted save", rc == 0, out)

print("== show, remove")
rc, out = sh("--show")
check("show gives fingerprints, never a key", rc == 0 and "ANTHROPIC_API_KEY set: sk-ant-" in out
      and "dummy-0001" not in out, out)
rc, out = sh("--remove")
check("remove drops the tier", rc == 0 and not enc.exists(), out)

shutil.rmtree(base, ignore_errors=True)
done()
