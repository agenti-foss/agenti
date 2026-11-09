#!/usr/bin/env python3
"""keystore.py — the AI provider keys, encrypted on disk at all times.

Operator decision 2026-11-08: "the API key must be stored encrypted at all
times regardless of the vault state. Should anyone ever steal or break into
the box, they should not be able to access the api key."

HOW
  Each key tier's file (shared/, org/, org/<agent>/, org/users/<user>/) is
  stored as `secrets.enc`: AES-256-GCM under one random 32-byte key, the keys
  master key (KMK), with the tier's own path as associated data, so a file
  copied into another tier does not decrypt. Root-only, 0600.

  The KMK is sealed one of three ways (state/keys/seal.json says which):
    tpm2        systemd-creds, sealed to this machine's TPM chip. Unlocks by
                itself at boot (agenti-keys.service). Nobody has to do anything.
    vault       a file inside the vault. Unlocking the vault unlocks the keys:
                one passphrase, one step.
    passphrase  scrypt + AES-GCM, from a key passphrase an admin chose. An
                admin unlocks after each start-up: Settings → Platform, or
                sudo agenti keys unlock.
  A TPM is preferred when present, then the vault, then a passphrase.

  Unlocked, the KMK and every tier's plain `secrets.env` exist only under
  /run/agenti-keys: a tmpfs of its own, mounted noswap so its pages never
  reach the swap file, root-only 0700 (systemd, as root, reads it for the run
  units' EnvironmentFile=; no service account can). Power off and it is gone.

  A box upgraded from before 0.1.4 with neither a TPM nor the vault keeps its
  plain `secrets.env` files until an admin sets a key passphrase (operator
  decision 2026-11-08: keep working, with a warning). A fresh install never
  writes a plain key file: its first key needs a seal.

WHAT IT DOES NOT DO (be honest): while the keys are unlocked, root on the
running machine can read them; no software that uses a key unattended can stop
that. A TPM seal does not stop a thief who boots the whole machine. Plain key
files written before the upgrade may survive in the disk's free space: rotate
those keys at the provider.

    keystore.py status                       one JSON object
    keystore.py unlock [--auto] [--passphrase-stdin]
    keystore.py lock
    keystore.py seal [--passphrase-stdin]    first seal; encrypts any plain files
    keystore.py passphrase --passphrase-stdin   change it (passphrase seal, unlocked)
    keystore.py get  --tier REL              the tier's plain text, to stdout
    keystore.py put  --tier REL              the tier's new plain text, from stdin
    keystore.py has --tier REL NAME...       which variables the tier sets (yes/no, no values)
    keystore.py set --tier REL NAME...       replace those lines; values on stdin, one per line
    keystore.py forget --tier REL            remove one tier's keys
    keystore.py reset --yes                  drop the seal and every encrypted key
    keystore.py vault-enabled | vault-disabling [--passphrase-stdin]

The crypto verbs need the `cryptography` package (the bundled authd runtime
has it); status, tier paths and forget do not.
"""
from __future__ import annotations

import base64
import contextlib
import fcntl
import grp
import hashlib
import json
import os
import pwd
import re
import secrets as _secrets
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import paths  # noqa: E402

ENC = "secrets.enc"
PLAIN = "secrets.env"
SVC_USER = "agenti-run"
SHARED_GROUP = os.environ.get("AGENTI_SHARED_GROUP", "agenti-shared")
MIN_PASSPHRASE = 12
# scrypt at 2^17 x 8: about 128 MiB and a fraction of a second per try on a
# Pi 5, so a stolen seal file is expensive to guess against.
SCRYPT = {"n": 2 ** 17, "r": 8, "p": 1}
CRED_NAME = "agenti-keys"
TIER_RE = re.compile(r"^(shared|org|org/(?!users$)[a-z0-9][a-z0-9_-]{0,63}|org/users/[a-z0-9][a-z0-9_-]{0,63})$")


class KeystoreError(Exception):
    """A refusal to show the operator as is: it names the fix."""


# --------------------------------------------------------------------------
# Where things are
# --------------------------------------------------------------------------
def run_dir() -> Path:
    return paths.keys_run()


def seal_dir() -> Path:
    return paths.state() / "keys"


def vault_kmk() -> Path:
    return paths.data_root() / ".keystore" / "kmk"


def check_tier(rel: str) -> str:
    if not TIER_RE.match(rel or ""):
        raise KeystoreError(f"not a key tier: {rel!r} (shared, org, org/<agent> or org/users/<user>)")
    return rel


def tier_rel(owner: str | None = None, agent: str | None = None) -> list[str]:
    """The tiers a run looks in, narrowest first: its owner's, its agent's,
    the organization's, the platform's."""
    out = []
    if owner:
        out.append(f"org/users/{owner}")
    if agent:
        out.append(f"org/{agent}")
    return out + ["org", "shared"]


def tier_paths(root, owner: str | None = None, agent: str | None = None, org_dir=None) -> list[Path]:
    """Plain files to read, in order, for agent_runtime.read_secrets: each
    tier's unlocked copy, then its pre-0.1.4 plain file (an upgraded box
    that has no seal yet). Neither existing is fine: that tier has no key.
    `org_dir` names the organization folder when it is not <root>/org."""
    root = Path(root)
    org = Path(org_dir) if org_dir is not None else root / "org"
    out = []
    for rel in tier_rel(owner, agent):
        plain = (org / rel[4:] if rel.startswith("org/") else org if rel == "org" else root / rel) / PLAIN
        out += [run_dir() / rel / PLAIN, plain]
    return out


def all_tiers(root=None) -> list[str]:
    """Every tier that holds a key file of either kind, as relative paths."""
    root = Path(root or paths.data_root())
    found = set()
    for name in (ENC, PLAIN):
        for p in [root / "shared" / name, root / "org" / name,
                  *root.glob(f"org/*/{name}"), *root.glob(f"org/users/*/{name}")]:
            if p.is_file():
                rel = str(p.parent.relative_to(root))
                if TIER_RE.match(rel):
                    found.add(rel)
    return sorted(found)


# --------------------------------------------------------------------------
# State
# --------------------------------------------------------------------------
def _seal_info() -> dict:
    try:
        info = json.loads((seal_dir() / "seal.json").read_text())
        return info if info.get("kind") in ("tpm2", "vault", "passphrase") else {}
    except (OSError, ValueError):
        return {}


def _vault_on() -> bool:
    return paths.vault_enabled()


def _vault_open() -> bool:
    return _vault_on() and os.path.ismount(paths.data_root())


def tpm_available() -> bool:
    forced = os.environ.get("AGENTI_KEYS_TPM")
    if forced in ("0", "1"):
        return forced == "1"
    if not shutil.which("systemd-creds") or not any(Path("/dev").glob("tpmrm*")):
        return False
    # A real seal probe takes up to a second or so, and status() runs on every
    # dashboard poll: probe once per boot (the answer describes the hardware,
    # not a secret; /run is emptied at every start-up).
    memo = run_dir().with_name("agenti-keys-tpm")
    with contextlib.suppress(OSError):
        return memo.read_text().strip() == "1"
    r = subprocess.run(["systemd-creds", "encrypt", "--with-key=tpm2", "--tpm2-pcrs=",
                        f"--name={CRED_NAME}-probe", "-", "-"],
                       input=b"probe", capture_output=True, timeout=60, check=False)
    if os.geteuid() == 0:
        with contextlib.suppress(OSError):
            _write(memo, b"1" if r.returncode == 0 else b"0", mode=0o600)
    return r.returncode == 0


def unlocked() -> bool:
    return (run_dir() / ".kmk").is_file()


def locked_reason() -> str:
    """Empty when the keys can be read; else why not and how to fix it.
    Cheap: no TPM probe, no decryption (launch prechecks call it)."""
    return _locked_message() if _seal_info() and not unlocked() else ""


def _tiers_with(root: Path, name: str) -> list[str]:
    return [t for t in (all_tiers(root) if root.is_dir() else []) if (root / t / name).is_file()]


def status(root=None) -> dict:
    root = Path(root or paths.data_root())
    info = _seal_info()
    kind = info.get("kind")
    plain, enc = _tiers_with(root, PLAIN), _tiers_with(root, ENC)
    if kind:
        state = "unlocked" if unlocked() else "locked"
    elif plain:
        state = "plain"
    else:
        state = "none"
    tpm = tpm_available() if not kind else kind == "tpm2"
    # A fresh box with no seal: the first key seals by itself with a TPM or
    # the vault, and needs a passphrase otherwise.
    needs_passphrase = state in ("plain", "none") and not tpm and not _vault_open()
    return {"state": state, "seal": kind, "tpm": tpm, "vault": _vault_on(),
            "encrypted_tiers": enc, "plain_tiers": plain,
            "needs_passphrase": needs_passphrase}


# --------------------------------------------------------------------------
# Crypto
# --------------------------------------------------------------------------
def _aes():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as e:
        raise KeystoreError("the cryptography package is missing; run this with the bundled "
                            f"runtime's Python ({paths.runtime()}/authd/bin/python3)") from e
    return AESGCM


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _unb64(s: str) -> bytes:
    return base64.b64decode(s.encode(), validate=True)


def _aad(rel: str) -> bytes:
    """Binds each encrypted file to its tier: a copy in another tier fails."""
    return f"agenti-keys-v1:{rel}".encode()


def encrypt_tier(kmk: bytes, rel: str, text: str) -> bytes:
    nonce = os.urandom(12)
    ct = _aes()(kmk).encrypt(nonce, text.encode(), _aad(rel))
    return json.dumps({"v": 1, "n": _b64(nonce), "c": _b64(ct)}).encode()


def decrypt_tier(kmk: bytes, rel: str, blob: bytes) -> str:
    try:
        d = json.loads(blob)
        return _aes()(kmk).decrypt(_unb64(d["n"]), _unb64(d["c"]), _aad(rel)).decode()
    except KeystoreError:
        raise
    except Exception as e:
        raise KeystoreError(f"{rel}/{ENC} does not decrypt: it was changed, copied from another "
                            "tier, or sealed under another key. Set that key again.") from e


def _derive(passphrase: str, salt: bytes, kdf: dict) -> bytes:
    return hashlib.scrypt(passphrase.encode(), salt=salt, n=kdf["n"], r=kdf["r"], p=kdf["p"],
                          maxmem=256 * 1024 * 1024, dklen=32)


def wrap_passphrase(kmk: bytes, passphrase: str) -> bytes:
    salt, nonce = os.urandom(16), os.urandom(12)
    ct = _aes()(_derive(passphrase, salt, SCRYPT)).encrypt(nonce, kmk, b"agenti-kmk-v1")
    return json.dumps({"v": 1, "kdf": "scrypt", **SCRYPT, "salt": _b64(salt),
                       "n_": _b64(nonce), "c": _b64(ct)}).encode()


def unwrap_passphrase(blob: bytes, passphrase: str) -> bytes:
    d = json.loads(blob)
    kdf = {"n": int(d["n"]), "r": int(d["r"]), "p": int(d["p"])}
    try:
        return _aes()(_derive(passphrase, _unb64(d["salt"]), kdf)).decrypt(
            _unb64(d["n_"]), _unb64(d["c"]), b"agenti-kmk-v1")
    except KeystoreError:
        raise
    except Exception as e:
        raise KeystoreError("that is not the key passphrase") from e


def _tpm_seal(kmk: bytes) -> bytes:
    r = subprocess.run(["systemd-creds", "encrypt", "--with-key=tpm2", "--tpm2-pcrs=",
                        f"--name={CRED_NAME}", "-", "-"],
                       input=_b64(kmk).encode(), capture_output=True, timeout=60, check=False)
    if r.returncode != 0:
        raise KeystoreError(f"the TPM did not seal the key: {r.stderr.decode(errors='replace').strip()}")
    return r.stdout


def _tpm_unseal(blob: bytes) -> bytes:
    r = subprocess.run(["systemd-creds", "decrypt", f"--name={CRED_NAME}", "-", "-"],
                       input=blob, capture_output=True, timeout=60, check=False)
    if r.returncode != 0:
        raise KeystoreError("this machine's TPM no longer unseals the API keys (a new motherboard, "
                            "or a cleared TPM). Start over and enter the keys again: "
                            "sudo agenti keys reset, then Settings → AI providers")
    return _unb64(r.stdout.decode().strip())


# --------------------------------------------------------------------------
# Files
# --------------------------------------------------------------------------
@contextlib.contextmanager
def _lock():
    d = seal_dir()
    d.mkdir(mode=0o700, parents=True, exist_ok=True)
    with open(d / ".lock", "a") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX)
        yield


def _write(path: Path, data: bytes, mode: int = 0o600, owner=None) -> None:
    """Atomic, never briefly readable at a looser mode."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    if owner and os.geteuid() == 0:
        os.chown(tmp, *owner)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def _shred(path: Path) -> None:
    """Best effort: overwrite, then remove. A journaling filesystem or an SSD
    may keep old blocks; that is why the docs say to rotate the key."""
    try:
        size = path.stat().st_size
        with open(path, "r+b", buffering=0) as fh:
            fh.write(b"\0" * size)
            os.fsync(fh.fileno())
    except OSError:
        pass
    with contextlib.suppress(FileNotFoundError):
        path.unlink()


def _plain_owner(rel: str):
    """Owner and mode of a pre-0.1.4 plain file: the shared tier is
    root:agenti-shared 0640, the others agenti-run 0600 (set-secret.sh)."""
    try:
        if rel == "shared":
            return (0, grp.getgrnam(SHARED_GROUP).gr_gid), 0o640
        pw = pwd.getpwnam(SVC_USER)
        return (pw.pw_uid, pw.pw_gid), 0o600
    except KeyError:
        return None, 0o600


def _mount_run() -> None:
    d = run_dir()
    if os.environ.get("AGENTI_KEYS_RUN") or os.geteuid() != 0:
        d.mkdir(mode=0o700, parents=True, exist_ok=True)     # tests: a plain folder
        os.chmod(d, 0o700)
        return
    if os.path.ismount(d):
        return
    d.mkdir(mode=0o700, parents=True, exist_ok=True)
    base = "size=4m,mode=0700,uid=0,gid=0,nosuid,nodev,noexec"
    r = subprocess.run(["mount", "-t", "tmpfs", "-o", base + ",noswap", "agenti-keys", str(d)],
                       capture_output=True, check=False)
    if r.returncode != 0:      # a kernel older than 6.4 has no noswap
        r = subprocess.run(["mount", "-t", "tmpfs", "-o", base, "agenti-keys", str(d)],
                           capture_output=True, check=False)
        if r.returncode != 0:
            raise KeystoreError(f"could not create the in-memory key folder {d}: "
                                f"{r.stderr.decode(errors='replace').strip()}")
        print(f"  [WARN] {d}: this kernel cannot keep it out of swap (noswap needs Linux 6.4+)",
              file=sys.stderr)


def _umount_run() -> None:
    d = run_dir()
    if os.path.ismount(d):
        subprocess.run(["umount", str(d)], check=False)
    elif d.is_dir():
        for p in sorted(d.rglob("*"), reverse=True):
            if p.is_file():
                _shred(p)
            elif p.is_dir():
                p.rmdir()


def _install_kmk(kmk: bytes) -> None:
    """The unlocked master key, in the in-memory folder only."""
    _mount_run()
    _write(run_dir() / ".kmk", _b64(kmk).encode())


def _store_tier(kmk: bytes, root: Path, rel: str, text: str) -> None:
    """One tier: encrypted on disk, unlocked copy in memory, no plain file."""
    _write(root / rel / ENC, encrypt_tier(kmk, rel, text))
    _write(run_dir() / rel / PLAIN, text.encode())
    _shred(root / rel / PLAIN)


def _kmk_now() -> bytes:
    try:
        return _unb64((run_dir() / ".kmk").read_text().strip())
    except FileNotFoundError:
        raise KeystoreError(_locked_message()) from None


def _locked_message() -> str:
    kind = _seal_info().get("kind")
    if kind == "vault":
        return "the API keys are locked with the vault: sudo agenti vault unlock"
    return ("the API keys are locked: unlock them in Settings → Platform → API key encryption, "
            "or at the server: sudo agenti keys unlock")


def _mirror(kmk: bytes, root: Path) -> int:
    """Decrypt every tier into the in-memory folder. Returns how many."""
    n = 0
    for rel in all_tiers(root):
        enc = root / rel / ENC
        if enc.is_file():
            _write(run_dir() / rel / PLAIN, decrypt_tier(kmk, rel, enc.read_bytes()).encode())
            n += 1
    return n


# --------------------------------------------------------------------------
# Verbs
# --------------------------------------------------------------------------
def _kmk_from_seal(info: dict, passphrase: str | None, auto: bool) -> bytes | None:
    kind = info["kind"]
    if kind == "tpm2":
        return _tpm_unseal((seal_dir() / "kmk.tpm2").read_bytes())
    if kind == "vault":
        if not _vault_open():
            if auto:
                return None
            raise KeystoreError("the API keys open with the vault: sudo agenti vault unlock")
        return _unb64(vault_kmk().read_text().strip())
    if auto:
        return None
    if passphrase is None:
        raise KeystoreError("the API keys need the key passphrase to unlock")
    return unwrap_passphrase((seal_dir() / "kmk.pass").read_bytes(), passphrase)


def unlock(passphrase: str | None = None, auto: bool = False, root=None) -> dict:
    root = Path(root or paths.data_root())
    with _lock():
        info = _seal_info()
        if not info:
            return {"ok": True, "state": status(root)["state"], "unlocked": 0}
        if unlocked():
            # Again after the vault opens: a TPM-sealed box unlocked at boot,
            # when the vault's tiers were not there to read yet.
            return {"ok": True, "state": "unlocked", "unlocked": _mirror(_kmk_now(), root),
                    "seal": info["kind"]}
        kmk = _kmk_from_seal(info, passphrase, auto)
        if kmk is None:
            return {"ok": True, "state": "locked", "unlocked": 0}
        _install_kmk(kmk)
        n = _mirror(kmk, root)
    return {"ok": True, "state": "unlocked", "unlocked": n, "seal": info["kind"]}


def lock() -> dict:
    with _lock():
        _umount_run()
    return {"ok": True, "state": "locked" if _seal_info() else status()["state"]}


def _choose_kind(passphrase: str | None) -> str:
    if tpm_available():
        return "tpm2"
    if _vault_open():
        return "vault"
    if passphrase is None:
        raise KeystoreError("this machine has no TPM chip and the vault is off, so the API keys need "
                            "a key passphrase: Settings → Platform → API key encryption, or "
                            "sudo agenti keys seal")
    return "passphrase"


def _check_passphrase(p: str) -> str:
    if len(p) < MIN_PASSPHRASE:
        raise KeystoreError(f"the key passphrase must be at least {MIN_PASSPHRASE} characters")
    if any(ord(c) < 32 for c in p):
        raise KeystoreError("the key passphrase may not contain line breaks or control characters")
    return p


def _seal_files() -> dict[str, Path]:
    return {"tpm2": seal_dir() / "kmk.tpm2", "passphrase": seal_dir() / "kmk.pass",
            "vault": vault_kmk()}


def _store_seal(kind: str, kmk: bytes, passphrase: str | None) -> None:
    d = seal_dir()
    if kind == "tpm2":
        _write(d / "kmk.tpm2", _tpm_seal(kmk))
    elif kind == "vault":
        _write(vault_kmk(), _b64(kmk).encode())
    else:
        _write(d / "kmk.pass", wrap_passphrase(kmk, _check_passphrase(passphrase or "")))
    _write(d / "seal.json", json.dumps({"v": 1, "kind": kind}).encode())
    for other, path in _seal_files().items():
        if other != kind:
            _shred(path)


def seal(passphrase: str | None = None, root=None, kind: str | None = None) -> dict:
    """The first seal: a new KMK, sealed the best way this box allows, then
    every plain key file encrypted and shredded, and the keys left unlocked."""
    with _lock():
        return _seal(passphrase, Path(root or paths.data_root()), kind)


def _seal(passphrase: str | None, root: Path, kind: str | None) -> dict:   # holds _lock()
    if _seal_info():
        raise KeystoreError("the API keys are already encrypted (sudo agenti keys status)")
    kind = kind or _choose_kind(passphrase)
    kmk = os.urandom(32)
    _store_seal(kind, kmk, passphrase)
    _install_kmk(kmk)
    plain = _tiers_with(root, PLAIN)
    for rel in plain:
        _store_tier(kmk, root, rel, (root / rel / PLAIN).read_text())
    return {"ok": True, "state": "unlocked", "seal": kind, "encrypted": len(plain)}


def change_passphrase(passphrase: str) -> dict:
    with _lock():
        if _seal_info().get("kind") != "passphrase":
            raise KeystoreError("the API keys are not sealed with a passphrase "
                                f"(they use: {_seal_info().get('kind') or 'nothing yet'})")
        _store_seal("passphrase", _kmk_now(), passphrase)
    return {"ok": True, "seal": "passphrase"}


def get(rel: str, root=None) -> str:
    root = Path(root or paths.data_root())
    check_tier(rel)
    if _seal_info():
        if (root / rel / ENC).is_file():
            return decrypt_tier(_kmk_now(), rel, (root / rel / ENC).read_bytes())
        return ""
    p = root / rel / PLAIN
    return p.read_text() if p.is_file() else ""


def put(rel: str, text: str, root=None, passphrase: str | None = None) -> dict:
    """Store one tier's whole plain text. Encrypted when there is a seal; on a
    fresh box the first put seals first (TPM, vault, or the passphrase given);
    an upgraded box without a seal keeps a plain file, as before 0.1.4."""
    check_tier(rel)
    with _lock():
        return _put(rel, text, Path(root or paths.data_root()), passphrase)


def _put(rel: str, text: str, root: Path, passphrase: str | None) -> dict:   # holds _lock()
    if len(text.encode()) > 65536:
        raise KeystoreError("a key file is limited to 64 KiB")
    if not _seal_info() and (passphrase is not None or not _tiers_with(root, PLAIN)):
        _seal(passphrase, root, None)
    info = _seal_info()
    if info:
        _store_tier(_kmk_now(), root, rel, text)
        return {"ok": True, "stored": "encrypted", "seal": info["kind"]}
    owner, mode = _plain_owner(rel)
    _write(root / rel / PLAIN, text.encode(), mode=mode, owner=owner)
    return {"ok": True, "stored": "plain", "seal": None}


VAR_RE = re.compile(r"[A-Z][A-Z0-9_]{0,63}")


def _check_vars(names: list[str]) -> list[str]:
    bad = [n for n in names if not VAR_RE.fullmatch(n)]
    if bad or not names:
        raise KeystoreError(f"not a key variable name: {', '.join(bad) or '(none given)'}")
    return names


def has(rel: str, names: list[str], root=None) -> dict:
    """Which of these variables the tier sets to something: yes/no, never a value."""
    check_tier(rel)
    held = {line.split("=", 1)[0] for line in get(rel, root).splitlines()
            if "=" in line and line.split("=", 1)[1]}
    return {n: n in held for n in _check_vars(names)}


def set_vars(rel: str, values: dict[str, str], root=None, passphrase: str | None = None) -> dict:
    """Replace these variables' lines in one tier, keeping every other line;
    an empty value removes the line. Read, change and write under one lock."""
    check_tier(rel)
    _check_vars(list(values))
    for v in values.values():
        if any(c.isspace() for c in v):
            raise KeystoreError("a key value may not contain whitespace (likely a bad paste)")
    root = Path(root or paths.data_root())
    with _lock():
        kept = [line for line in get(rel, root).splitlines()
                if VAR_RE.match(line) and "=" in line and line.split("=", 1)[0] not in values]
        new = [f"{k}={v}" for k, v in values.items() if v]
        text = "\n".join([f"# {rel} keys. Never commit or copy this anywhere.", *kept, *new]) + "\n"
        return _put(rel, text, root, passphrase)


def forget(rel: str, root=None) -> dict:
    root = Path(root or paths.data_root())
    check_tier(rel)
    with _lock():
        for p in (root / rel / ENC, root / rel / PLAIN, run_dir() / rel / PLAIN):
            _shred(p)
    return {"ok": True}


def reset(root=None) -> dict:
    """Forgotten passphrase or a TPM that no longer unseals: drop the seal and
    every encrypted key. The keys must be entered again."""
    root = Path(root or paths.data_root())
    with _lock():
        for rel in all_tiers(root):
            _shred(root / rel / ENC)
        _umount_run()
        for p in (*_seal_files().values(), seal_dir() / "seal.json"):
            _shred(p)
    return {"ok": True, "state": status(root)["state"]}


def vault_enabled_hook(root=None) -> dict:
    """After `vault enable` (the data now in the vault, mounted): a passphrase
    seal moves into the vault, so one unlock opens both; a box with plain
    files or none gets a vault seal. A TPM seal stays as it is."""
    root = Path(root or paths.data_root())
    info = _seal_info()
    if not info:
        return seal(None, root, kind="tpm2" if tpm_available() else "vault")
    if info["kind"] == "passphrase":
        with _lock():
            _store_seal("vault", _kmk_now(), None)
        return {"ok": True, "seal": "vault"}
    return {"ok": True, "seal": info["kind"]}


def vault_disabling_hook(passphrase: str | None) -> dict:
    """Before `vault disable` moves the data out: a vault seal needs a new home
    first, or the KMK would land on the bare disk next to the keys."""
    info = _seal_info()
    if info.get("kind") != "vault":
        return {"ok": True, "seal": info.get("kind")}
    with _lock():
        kmk = _kmk_now()
        kind = "tpm2" if tpm_available() else "passphrase"
        if kind == "passphrase" and passphrase is None:
            raise KeystoreError("turning the vault off needs a key passphrase for the API keys")
        _store_seal(kind, kmk, passphrase)
        with contextlib.suppress(OSError):
            vault_kmk().parent.rmdir()
    return {"ok": True, "seal": kind}


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def _read_passphrase(flag: bool) -> str | None:
    if not flag:
        return None
    line = sys.stdin.readline()
    return line[:-1] if line.endswith("\n") else line


def main(argv: list[str]) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="keystore.py", description=__doc__.split("\n\n")[0], allow_abbrev=False)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status", allow_abbrev=False)
    p = sub.add_parser("unlock", allow_abbrev=False)
    p.add_argument("--auto", action="store_true")
    p.add_argument("--passphrase-stdin", action="store_true")
    sub.add_parser("lock", allow_abbrev=False)
    p = sub.add_parser("seal", allow_abbrev=False)
    p.add_argument("--passphrase-stdin", action="store_true")
    p = sub.add_parser("passphrase", allow_abbrev=False)
    p.add_argument("--passphrase-stdin", action="store_true", required=True)
    for name in ("get", "forget"):
        sub.add_parser(name, allow_abbrev=False).add_argument("--tier", required=True)
    p = sub.add_parser("put", allow_abbrev=False)
    p.add_argument("--tier", required=True)
    p.add_argument("--passphrase-first", action="store_true",
                   help="stdin's first line is a key passphrase to seal with first")
    p = sub.add_parser("has", allow_abbrev=False, help="which variables a tier sets (yes/no)")
    p.add_argument("--tier", required=True)
    p.add_argument("names", nargs="+")
    p = sub.add_parser("set", allow_abbrev=False,
                       help="replace these variables' lines; values on stdin, one per line")
    p.add_argument("--tier", required=True)
    p.add_argument("--passphrase-first", action="store_true",
                   help="stdin's first line is a key passphrase to seal with first")
    p.add_argument("names", nargs="+")
    p = sub.add_parser("reset", allow_abbrev=False)
    p.add_argument("--yes", action="store_true", required=True)
    sub.add_parser("vault-enabled", allow_abbrev=False)
    p = sub.add_parser("vault-disabling", allow_abbrev=False)
    p.add_argument("--passphrase-stdin", action="store_true")
    a = ap.parse_args(argv)
    try:
        if a.cmd == "status":
            out = status()
        elif a.cmd == "unlock":
            out = unlock(_read_passphrase(a.passphrase_stdin), auto=a.auto)
        elif a.cmd == "lock":
            out = lock()
        elif a.cmd == "seal":
            out = seal(_read_passphrase(a.passphrase_stdin))
        elif a.cmd == "passphrase":
            out = change_passphrase(_check_passphrase(_read_passphrase(True) or ""))
        elif a.cmd == "get":
            sys.stdout.write(get(a.tier))
            return 0
        elif a.cmd == "put":
            pp = _read_passphrase(True) if a.passphrase_first else None
            out = put(a.tier, sys.stdin.read(), passphrase=pp)
        elif a.cmd == "has":
            out = has(a.tier, a.names)
        elif a.cmd == "set":
            pp = _read_passphrase(True) if a.passphrase_first else None
            out = set_vars(a.tier, {n: _read_passphrase(True) or "" for n in a.names}, passphrase=pp)
        elif a.cmd == "forget":
            out = forget(a.tier)
        elif a.cmd == "reset":
            out = reset()
        elif a.cmd == "vault-enabled":
            out = vault_enabled_hook()
        else:
            out = vault_disabling_hook(_read_passphrase(a.passphrase_stdin))
    except KeystoreError as e:
        print(json.dumps({"ok": False, "error": str(e)}))
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    print(json.dumps(out))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
