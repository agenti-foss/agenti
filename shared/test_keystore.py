#!/usr/bin/env python3
"""test_keystore.py — the API keys are encrypted on disk at all times.

No root, no TPM, no network: a temporary data root, state folder and
in-memory folder stand in for the real ones; AGENTI_KEYS_TPM=0/1 stands in for
the chip (the TPM calls themselves are replaced).

    python3 shared/test_keystore.py
"""
import json
import os
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

PASS = FAIL = 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  [ OK ] {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name} {detail}")


def raises(fn, needle=""):
    import keystore
    try:
        fn()
    except keystore.KeystoreError as e:
        return needle in str(e)
    return False


def fresh(tpm="0", vault=False):
    """A clean box: returns (root, state, run)."""
    base = Path(tempfile.mkdtemp(prefix="ks-"))
    root, state, run, etc = base / "data", base / "state", base / "run", base / "etc"
    for d in (root / "shared", root / "org" / "enum", root / "org" / "users" / "alice", state, etc):
        d.mkdir(parents=True)
    os.environ.update(AGENTI_ROOT=str(root), AGENTI_STATE=str(state), AGENTI_KEYS_RUN=str(run),
                      AGENTI_ETC=str(etc), AGENTI_KEYS_TPM=tpm)
    if vault:
        (etc / "vault.conf").write_text("IMAGE=x\nMAPPER=y\n")
    return root, state, run


import keystore  # noqa: E402

# Faster scrypt for the test run; the real cost is checked separately below.
REAL_SCRYPT = dict(keystore.SCRYPT)
keystore.SCRYPT = {"n": 2 ** 12, "r": 8, "p": 1}
KEY = "ANTHROPIC_API_KEY=sk-ant-test-0123456789\n"

print("== crypto")
kmk = os.urandom(32)
blob = keystore.encrypt_tier(kmk, "org", KEY)
check("a tier round-trips", keystore.decrypt_tier(kmk, "org", blob) == KEY)
check("the key is not in the file", b"sk-ant" not in blob)
check("a file copied into another tier does not decrypt",
      raises(lambda: keystore.decrypt_tier(kmk, "shared", blob), "does not decrypt"))
d = json.loads(blob)
d["c"] = d["c"][:-4] + ("AAAA" if d["c"][-4:] != "AAAA" else "BBBB")
check("a changed file does not decrypt",
      raises(lambda: keystore.decrypt_tier(kmk, "org", json.dumps(d).encode()), "does not decrypt"))
w = keystore.wrap_passphrase(kmk, "correct horse battery")
check("the passphrase unwraps the master key", keystore.unwrap_passphrase(w, "correct horse battery") == kmk)
check("a wrong passphrase is refused", raises(lambda: keystore.unwrap_passphrase(w, "wrong horse battery"),
                                             "not the key passphrase"))
check("the shipped scrypt cost is 2^17", REAL_SCRYPT == {"n": 2 ** 17, "r": 8, "p": 1})
check("tier names are checked", raises(lambda: keystore.check_tier("../etc"), "not a key tier")
      and raises(lambda: keystore.check_tier("org/users"), "not a key tier"))

print("== fresh box, no TPM, no vault: the first key needs a passphrase")
root, state, run = fresh()
st = keystore.status()
check("state is none, a passphrase is needed", st["state"] == "none" and st["needs_passphrase"], st)
check("the first key without a passphrase is refused, nothing written",
      raises(lambda: keystore.put("shared", KEY), "key passphrase")
      and not (root / "shared" / "secrets.env").exists() and not (root / "shared" / "secrets.enc").exists())
check("a short passphrase is refused", raises(lambda: keystore.put("shared", KEY, passphrase="short"),
                                              "at least 12"))
r = keystore.put("shared", KEY, passphrase="a long key passphrase")
check("with a passphrase it is stored encrypted", r["stored"] == "encrypted" and r["seal"] == "passphrase", r)
check("no plain file on disk", not (root / "shared" / "secrets.env").exists())
enc = root / "shared" / "secrets.enc"
check("the encrypted file is 0600 and holds no key",
      oct(enc.stat().st_mode & 0o777) == "0o600" and b"sk-ant" not in enc.read_bytes())
check("the unlocked copy is in the in-memory folder", (run / "shared" / "secrets.env").read_text() == KEY)
check("the in-memory folder is 0700", oct(run.stat().st_mode & 0o777) == "0o700")
check("tier_paths reads the unlocked copy first",
      keystore.tier_paths(root)[-2] == run / "shared" / "secrets.env")
check("get returns the tier", keystore.get("shared") == KEY)
keystore.put("org/users/alice", "OPENAI_API_KEY=sk-alice\n")
check("status: unlocked, two encrypted tiers",
      keystore.status()["state"] == "unlocked" and keystore.status()["encrypted_tiers"] == ["org/users/alice", "shared"])

print("== has and set: one line replaced, the others kept, under one lock")
r = keystore.set_vars("org", {"OPENAI_API_KEY": "sk-one"})
keystore.set_vars("org", {"ANTHROPIC_API_KEY": "sk-ant-two"})
check("set keeps the other provider's line",
      "OPENAI_API_KEY=sk-one" in keystore.get("org") and "ANTHROPIC_API_KEY=sk-ant-two" in keystore.get("org"))
keystore.set_vars("org", {"OPENAI_API_KEY": "sk-three"})
check("set replaces its own line once", keystore.get("org").count("OPENAI_API_KEY=") == 1
      and "sk-three" in keystore.get("org"))
check("has says yes/no, never a value",
      keystore.has("org", ["OPENAI_API_KEY", "LOCAL_LLM_BASE_URL"]) == {"OPENAI_API_KEY": True, "LOCAL_LLM_BASE_URL": False})
keystore.set_vars("org", {"OPENAI_API_KEY": ""})
check("an empty value removes the line", "OPENAI_API_KEY" not in keystore.get("org"))
check("a bad variable name is refused", raises(lambda: keystore.set_vars("org", {"x=y": "1"}), "variable name"))
check("whitespace in a value is refused", raises(lambda: keystore.set_vars("org", {"OPENAI_API_KEY": "a b"}), "whitespace"))
keystore.forget("org")

print("== lock and unlock")
keystore.lock()
check("locked: the in-memory copies are gone", not (run / "shared" / "secrets.env").exists())
check("status says locked", keystore.status()["state"] == "locked")
check("get while locked names how to unlock", raises(lambda: keystore.get("shared"), "Settings → Platform"))
check("put while locked is refused", raises(lambda: keystore.put("org", KEY), "locked"))
check("auto unlock does nothing for a passphrase seal", keystore.unlock(auto=True)["state"] == "locked")
check("a wrong passphrase does not unlock", raises(lambda: keystore.unlock("not the passphrase"), "not the key passphrase"))
r = keystore.unlock("a long key passphrase")
check("the right passphrase unlocks both tiers", r["unlocked"] == 2, r)
check("…and the keys are back", (run / "org" / "users" / "alice" / "secrets.env").read_text() == "OPENAI_API_KEY=sk-alice\n")
keystore.change_passphrase("another long passphrase")
keystore.lock()
check("after a change, the old passphrase fails", raises(lambda: keystore.unlock("a long key passphrase"), "not the key"))
check("…and the new one works", keystore.unlock("another long passphrase")["unlocked"] == 2)

print("== forget and reset")
keystore.forget("org/users/alice")
check("forget removes the encrypted file and its copy",
      not (root / "org/users/alice/secrets.enc").exists() and not (run / "org/users/alice/secrets.env").exists())
keystore.reset()
check("reset drops every key and the seal",
      keystore.status()["state"] == "none" and not enc.exists() and not (state / "keys" / "kmk.pass").exists())

print("== upgraded box with plain files, no TPM, no vault: keeps working")
root, state, run = fresh()
(root / "org" / "secrets.env").write_text(KEY)
os.chmod(root / "org" / "secrets.env", 0o600)
st = keystore.status()
check("state is plain, a passphrase is needed", st["state"] == "plain" and st["needs_passphrase"]
      and st["plain_tiers"] == ["org"], st)
r = keystore.put("shared", "OPENAI_API_KEY=sk-x\n")
check("a new key is still written plain until a passphrase is set", r["stored"] == "plain"
      and (root / "shared" / "secrets.env").exists())
check("tier_paths still finds the plain file", root / "org" / "secrets.env" in keystore.tier_paths(root))
r = keystore.seal("a long key passphrase")
check("setting the passphrase encrypts both", r["encrypted"] == 2 and r["seal"] == "passphrase", r)
check("…and removes the plain files",
      not (root / "org" / "secrets.env").exists() and not (root / "shared" / "secrets.env").exists())
check("…keeping their content", keystore.get("org") == KEY)
check("sealing twice is refused", raises(lambda: keystore.seal("a long key passphrase"), "already"))

print("== TPM: seals by itself, unlocks by itself")
root, state, run = fresh(tpm="1")
keystore._tpm_seal = lambda k: b"TPM:" + keystore._b64(k).encode()
keystore._tpm_unseal = lambda b: keystore._unb64(b[4:].decode())
st = keystore.status()
check("no passphrase needed with a TPM", st["state"] == "none" and not st["needs_passphrase"], st)
r = keystore.put("shared", KEY)
check("the first key seals with the TPM", r["stored"] == "encrypted" and r["seal"] == "tpm2", r)
check("no passphrase file", not (state / "keys" / "kmk.pass").exists() and (state / "keys" / "kmk.tpm2").exists())
keystore.lock()
r = keystore.unlock(auto=True)
check("boot: auto unlock opens it", r["state"] == "unlocked" and r["unlocked"] == 1, r)

print("== vault: one unlock for both")
root, state, run = fresh(vault=True)
keystore._vault_open = lambda: True
st = keystore.status()
check("vault open: no passphrase needed", not st["needs_passphrase"], st)
r = keystore.put("org", KEY)
check("the first key seals inside the vault", r["seal"] == "vault" and (root / ".keystore" / "kmk").exists(), r)
keystore.lock()
check("vault unlock (auto) unlocks the keys", keystore.unlock(auto=True)["unlocked"] == 1)
keystore._vault_open = lambda: False
keystore.lock()
check("vault locked: auto unlock waits", keystore.unlock(auto=True)["state"] == "locked")
check("…and says to unlock the vault", raises(lambda: keystore.unlock("x" * 20), "vault unlock"))
keystore._vault_open = lambda: True
keystore.unlock(auto=True)
check("turning the vault off without a passphrase is refused",
      raises(lambda: keystore.vault_disabling_hook(None), "key passphrase"))
r = keystore.vault_disabling_hook("a long key passphrase")
check("…with one, the seal moves out of the vault", r["seal"] == "passphrase"
      and not (root / ".keystore" / "kmk").exists() and (state / "keys" / "kmk.pass").exists(), r)
r = keystore.vault_enabled_hook()
check("turning it on again moves a passphrase seal into the vault", r["seal"] == "vault"
      and not (state / "keys" / "kmk.pass").exists())

print("== vault turned on over plain files")
root, state, run = fresh(vault=True)
(root / "shared" / "secrets.env").write_text(KEY)
keystore._vault_open = lambda: True
r = keystore.vault_enabled_hook()
check("plain files are encrypted under a vault seal", r["seal"] == "vault" and r["encrypted"] == 1
      and not (root / "shared" / "secrets.env").exists(), r)

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
