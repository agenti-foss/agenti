"""
iam.py — identity, credentials and authorization for Agenti (CLAUDE.md §3g).

THE ONE IMPLEMENTATION. Both the root-gated CLI (`agenti admin ...`) and the
unprivileged API (`shared/api/`) import this module. Neither carries its own
copy of the schema, the permission catalog, or the resolution rules — the same
discipline `cli_bridge.py` applies to CLI operations, applied here to identity.

TWO STORES, SPLIT ALONG A PRIVILEGE BOUNDARY
--------------------------------------------
  iam.db      principals, roles, bindings, keys, password hashes, TOTP secrets
              0640 root:agenti-api  —  the API opens it READ-ONLY
  runtime.db  sessions, lockout counters, key last-used, the authz audit log
              0600 agenti-api       —  the API opens it read-write

The split protects one specific property: a compromised API process can forge a
session for an EXISTING principal, but cannot create a principal, alter a role
binding, mint a key, or un-revoke one. All of that is root-only, through the
CLI. That is not nothing and it is not everything, and it is described that way
rather than overclaimed — see CLAUDE.md §3g.

Both live OUTSIDE the vault, for the same reason vault.sh and set-secret.sh do:
the API must be able to start, authenticate a caller, and correctly answer "the
vault is locked" WHILE the vault is actually locked. An identity store inside
the vault would be unreadable in exactly the state it most needs to work.

WHERE THIS IS ENFORCED, AND WHERE IT IS NOT
-------------------------------------------
The API enforces. The CLI deliberately does not. Every CLI verb already requires
root, and root can rewrite iam.db directly — an IAM check there would be theatre,
not a boundary. The CLI is the AUDITED root break-glass path: it records who
acted (`$SUDO_USER`) and that the action came via the CLI, and every IAM mutation
is written to the audit log. Stated plainly here because "the CLI ignores RBAC"
is not something a reader should have to discover.

One layer up, the same honesty applies: this is an APPLICATION-layer boundary,
meaningfully weaker than the OS-level isolation beneath it. Shell as
agenti-api bypasses it entirely by calling `sudo agenti` directly.
"""

from __future__ import annotations

import base64
import contextlib
import functools
import hashlib
import json     # module-level: _main() has its own `import json as _json`, which
                # the module-level functions above _main cannot see
import shutil
import hmac
import os
import re
import secrets
import sqlite3
import stat
import struct
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

import paths  # noqa: E402  (where Agenti's files live; beside this file)

# ---------------------------------------------------------------------------
# Locations (paths.py). Overridable by env for testing; the defaults are what
# configure.sh provisions and what the systemd units point at.
# ---------------------------------------------------------------------------
IAM_DB_PATH = paths.iam_db()
# runtime.db (sessions, lockout counters, TOTP replay records, enrolment
# tokens, key last-used, the authz audit log) sits in its OWN directory, owned
# by agenti-authd — the privileged authentication service (shared/authd.py,
# §4 item 23). The API account has NO access to it: a session store the web
# tier could write would be a session store a compromised web tier could
# forge. SQLite in WAL mode creates -wal/-shm sidecars NEXT TO the database,
# so the writing account needs the directory, not just the file. Root (the
# CLI) also writes here — self-service credential changes, enrolment tokens,
# session revocation — which is why authd holds one connection open for its
# whole life: so the sidecars are created by its account, not root's.
RUNTIME_DB_PATH = paths.runtime_db()

SCHEMA_VERSION = 2


class IAMError(Exception):
    """Every way an IAM operation can legitimately fail. Carries a message
    written to the same bar as the rest of this project: what went wrong, and
    what to do about it."""


# ---------------------------------------------------------------------------
# The permission catalog — the complete set of things a role can grant.
#
# Adding a verb to the CLI or a route to the API does NOT automatically create a
# permission: the mapping is explicit in shared/api/rbac.py, and an unmapped
# route fails closed. That is deliberate — a new endpoint should require a
# decision about who may call it, not inherit one.
# ---------------------------------------------------------------------------
PERMISSIONS: tuple[str, ...] = (
    "agent:read",           # status, show, engagement, reports, scans, report, findings, approval, logs
    "agent:start",
    "agent:stop",
    "agent:pause",
    "agent:resume",
    "agent:chat",           # send a STEERING message into a live run
    "agent:note",           # annotate a run; never reaches the model
    "output:promote",       # keep one of YOUR OWN run's reports in the permanent
                            # Outputs store. Quota-gated by outputs_check(); the
                            # file is always the caller's own — an admin viewing
                            # a dashboard cannot promote.
    "output:delete",        # remove a promoted output you own (an admin, any).
                            # Ownership is enforced inside delete_output() /
                            # resolve_output_path(), not by holding this
                            # permission alone.
    "engagement:approve",
    "engagement:manage",    # AUTHOR the organisation's engagement — client,
                            # scope, validity window, policy. Deliberately NOT
                            # held by `operator`: it defines the boundary every
                            # other enforcement layer checks against, so it is
                            # admin-only by default.
    "iam:read",
    "iam:manage",
    "team:manage",          # create/delete a team, add/remove members (§3i)
)

# Built-in roles. Seeded at bootstrap, and editable afterwards like any other
# role — "built-in" marks their origin, it does not freeze them. Kept as a
# starting bundle rather than a hard-coded special case so that custom roles
# and built-in roles go through exactly the same resolution path.
#
# There are two roles. An operator launches and runs agents; their runs are
# private to them. An admin does that and also manages users, the engagement,
# agents and the platform. There is no read-only role: runs are private to the
# user who launched them, so a role whose whole purpose was watching other
# people's agents has nothing left to show.
BUILTIN_ROLES: dict[str, tuple[str, ...]] = {
    "operator": (
        "agent:read", "agent:note",
        "agent:start", "agent:stop", "agent:pause", "agent:resume", "agent:chat",
        "team:manage",
        "output:promote", "output:delete",
    ),
    "admin": PERMISSIONS,
}

NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")


def validate_name(value: str, kind: str = "name") -> str:
    if not NAME_RE.match(value or ""):
        raise IAMError(
            f"invalid {kind} {value!r}: lowercase letters, digits, '-' or '_', "
            f"starting with a letter or digit, max 64 characters")
    return value


# ---------------------------------------------------------------------------
# The one resource
# ---------------------------------------------------------------------------
ORG_RESOURCE = "org"

# Where the organisation's data lives.
ORG_ROOT = paths.data_root()


def org_dir() -> Path:
    return ORG_ROOT / "org"


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------
_IAM_SCHEMA = """
CREATE TABLE IF NOT EXISTS principals (
    name            TEXT PRIMARY KEY,
    kind            TEXT NOT NULL CHECK(kind IN ('user','service')),
    active          INTEGER NOT NULL DEFAULT 1,
    role            TEXT NOT NULL DEFAULT 'operator',
    password_hash   TEXT,
    password_set_at REAL,
    must_change     INTEGER NOT NULL DEFAULT 0,
    totp_secret     TEXT,
    totp_enrolled_at REAL,
    created_at      REAL NOT NULL,
    created_by      TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS api_keys (
    prefix     TEXT PRIMARY KEY,
    principal  TEXT NOT NULL,
    key_hash   TEXT NOT NULL,
    created_at REAL NOT NULL,
    created_by TEXT NOT NULL,
    expires_at REAL,
    revoked_at REAL
);
CREATE TABLE IF NOT EXISTS recovery_codes (
    principal TEXT NOT NULL,
    code_hash TEXT NOT NULL,
    used_at   REAL,
    PRIMARY KEY (principal, code_hash)
);
CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
-- WebAuthn/passkey credentials. One row per registered device, not one
-- column on principals (like api_keys, not like totp_secret): a real person
-- has a phone AND a laptop. Only the STABLE registration record lives here
-- (written once, by root, after agenti-authd has cryptographically verified
-- the attestation — see passkey_commit()/webauthn_register_action() below).
-- x/y are the raw P-256 coordinates, base64url TEXT — iam.py never decodes
-- them to bytes itself; only webauthn_lite.py (imported by authd, not by
-- this module) does that. The MUTABLE per-login state (the replay-defeating
-- signature counter) deliberately does NOT live here — see passkey_state in
-- _RUNTIME_SCHEMA for why.
CREATE TABLE IF NOT EXISTS passkeys (
    credential_id TEXT PRIMARY KEY,
    principal     TEXT NOT NULL,
    alg           TEXT NOT NULL,
    pubkey_x      TEXT NOT NULL,
    pubkey_y      TEXT NOT NULL,
    name          TEXT,
    created_at    REAL NOT NULL,
    created_by    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS schema_meta (version INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS idx_keys_principal   ON api_keys(principal);
CREATE INDEX IF NOT EXISTS idx_passkeys_principal ON passkeys(principal);
"""

_RUNTIME_SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id           TEXT PRIMARY KEY,
    principal    TEXT NOT NULL,
    csrf         TEXT NOT NULL,
    created_at   REAL NOT NULL,
    expires_at   REAL NOT NULL,
    last_seen    REAL NOT NULL,
    revoked_at   REAL,
    pending_totp INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS login_attempts (
    principal    TEXT PRIMARY KEY,
    failures     INTEGER NOT NULL DEFAULT 0,
    locked_until REAL,
    last_failure REAL
);
CREATE TABLE IF NOT EXISTS login_attempts_addr (
    addr         TEXT PRIMARY KEY,
    failures     INTEGER NOT NULL DEFAULT 0,
    locked_until REAL,
    last_failure REAL
);
CREATE TABLE IF NOT EXISTS recovery_used (
    principal TEXT NOT NULL,
    code_id   INTEGER NOT NULL,
    used_at   REAL NOT NULL,
    PRIMARY KEY (principal, code_id)
);
CREATE TABLE IF NOT EXISTS totp_used (
    principal TEXT NOT NULL,
    counter   INTEGER NOT NULL,
    used_at   REAL NOT NULL,
    PRIMARY KEY (principal, counter)
);
CREATE TABLE IF NOT EXISTS enrolment_tokens (
    token_hash TEXT PRIMARY KEY,
    principal  TEXT NOT NULL,
    created_at REAL NOT NULL,
    created_by TEXT,
    expires_at REAL NOT NULL,
    used_at    REAL
);
-- Same shape as enrolment_tokens, for the opposite case: an ALREADY-enrolled
-- account whose admin has chosen the "send a one-time link" mode of
-- reset_principal_password rather than typing a value directly (see
-- mint_password_reset_link's own docstring for why minting this is safe
-- here but _refuse_if_enrolled forbids the identical shape for an
-- enrolment token). Resets ONLY the password when consumed — 2FA/passkeys
-- are a deliberately separate action, reset_principal_mfa.
CREATE TABLE IF NOT EXISTS password_reset_tokens (
    token_hash TEXT PRIMARY KEY,
    principal  TEXT NOT NULL,
    created_at REAL NOT NULL,
    created_by TEXT,
    expires_at REAL NOT NULL,
    used_at    REAL
);
CREATE TABLE IF NOT EXISTS action_grants (
    id          TEXT PRIMARY KEY,
    principal   TEXT NOT NULL,
    action_hash TEXT NOT NULL,
    created_at  REAL NOT NULL,
    expires_at  REAL NOT NULL,
    used_at     REAL
);
-- WebAuthn ceremony challenges. Same single-use/short-TTL shape as
-- enrolment_tokens/action_grants above: only the HASH of the challenge is
-- stored, never the challenge itself. `principal` is set for a registration
-- challenge (bound to the account that's mid-ceremony) and NULL for a login
-- challenge (unknown until the assertion names a credential_id).
CREATE TABLE IF NOT EXISTS webauthn_challenges (
    challenge_hash TEXT PRIMARY KEY,
    principal      TEXT,
    purpose        TEXT NOT NULL,
    created_at     REAL NOT NULL,
    expires_at     REAL NOT NULL,
    used_at        REAL
);
-- The MUTABLE half of a passkey: the signature counter and last-used time.
-- Lives here, not in iam.db's passkeys table, specifically so agenti-authd
-- can update it on every successful login WITHOUT iam.db write access,
-- which it must never have. Exactly the same split as totp_used below —
-- the stable secret/credential is root-owned; the per-login replay state
-- is authd-owned.
CREATE TABLE IF NOT EXISTS passkey_state (
    credential_id TEXT PRIMARY KEY,
    sign_count    INTEGER NOT NULL DEFAULT 0,
    last_used_at  REAL
);
CREATE TABLE IF NOT EXISTS key_usage (
    prefix    TEXT PRIMARY KEY,
    last_used REAL NOT NULL,
    uses      INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS authz_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         REAL NOT NULL,
    principal  TEXT,
    permission TEXT,
    resource   TEXT,
    decision   TEXT NOT NULL,
    reason     TEXT,
    via        TEXT
);
CREATE INDEX IF NOT EXISTS idx_sessions_principal ON sessions(principal);
CREATE INDEX IF NOT EXISTS idx_authz_ts           ON authz_log(ts);
"""


def _connect(path: Path, *, readonly: bool, wal: bool) -> sqlite3.Connection:
    if readonly:
        # mode=ro, and deliberately NOT immutable=1. immutable would let SQLite
        # assume the file never changes and cache accordingly — which means a
        # key revoked by the CLI would keep working in an already-open API
        # process. Revocation that does not take effect is worse than a little
        # extra I/O. Callers open read-only connections per request for the
        # same reason (see rbac.py).
        try:
            return sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        except sqlite3.OperationalError as e:
            raise IAMError(
                f"cannot open the identity store at {path} ({e}).\n"
                f"If this is a fresh install, initialise it:\n"
                f"  sudo agenti admin bootstrap --user <your-name>")
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    # WAL only where the SAME account both reads and writes (runtime.db).
    # iam.db is written by root and read by agenti-api, and a WAL reader must
    # be able to read -wal/-shm next to the database — files root would own.
    # Rollback journaling keeps iam.db a single self-contained file that any
    # reader with read access to it can open, with no sidecar permissions to
    # get wrong.
    if wal:
        conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def _check_schema(conn: sqlite3.Connection, *, writable: bool) -> None:
    """Fresh installs only (operator decision 4, audit run 1): an identity
    store from before the two-role model (schema v1: custom roles, groups and
    bindings) is refused, never migrated. The old migration turned unbound
    and deny-bound accounts into operators and kept deny-overridden admins
    as admins (F34)."""
    cols = {r[1] for r in conn.execute("PRAGMA table_info(principals)")}
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if (cols and "role" not in cols) or "bindings" in tables:
        raise IAMError(
            "this identity store is from an older Agenti (schema v1: custom roles and "
            "bindings) and is not migrated: Agenti supports fresh installs only. Move it "
            "aside and start a new one:\n"
            f"  sudo mv {IAM_DB_PATH} {IAM_DB_PATH}.v1\n"
            "  sudo agenti setup")
    if writable and conn.execute("SELECT 1 FROM schema_meta").fetchone() is None:
        conn.execute("INSERT INTO schema_meta(version) VALUES (?)", (SCHEMA_VERSION,))
        conn.commit()


def open_iam(*, readonly: bool = True, path: Path | None = None) -> sqlite3.Connection:
    """Read-only by default: agenti-authd is the common caller (the API
    itself no longer opens this file at all — §4 item 23) and must never be
    able to widen anyone's authority. The CLI passes readonly=False
    explicitly, which is the whole point of it being a separate, root-gated
    path."""
    conn = _connect(path or IAM_DB_PATH, readonly=readonly, wal=False)
    conn.row_factory = sqlite3.Row
    try:
        _check_schema(conn, writable=False)     # before any CREATE touches an old store
    except IAMError:
        conn.close()
        raise
    if not readonly:
        conn.executescript(_IAM_SCHEMA)
        _check_schema(conn, writable=True)      # stamps a fresh store's version
    return conn


def _runtime_files_check(path: Path) -> os.stat_result:
    """The folder holding runtime.db belongs to agenti-authd. Root opening it
    must not follow a link authd planted there (runtime.db -> /etc/shadow,
    audit run 1, F18): the folder and every SQLite file in it must be the real
    thing. Returns the folder's stat (its owner is whom root opens it as)."""
    try:
        dst = os.lstat(path.parent)
    except FileNotFoundError:
        raise IAMError(f"the runtime store's folder {path.parent} does not exist. It is "
                       f"created at install; recreate it with: sudo dpkg-reconfigure agenti")
    if not stat.S_ISDIR(dst.st_mode):
        raise IAMError(f"refusing to open the runtime store: {path.parent} is not a plain "
                       f"folder (a link?). Move it aside first")
    for suffix in ("", "-wal", "-shm", "-journal"):
        f = Path(f"{path}{suffix}")
        try:
            st = os.lstat(f)
        except FileNotFoundError:
            continue
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            raise IAMError(f"refusing to open the runtime store: {f} is not a plain file "
                           f"(a link?), so root will not touch it. Move it aside first")
    return dst


@contextlib.contextmanager
def _as_owner_of(dst: os.stat_result):
    """Root works on runtime.db as the folder's owner, so even a link swapped
    in after the check above opens nothing that account could not already."""
    if os.geteuid() != 0 or dst.st_uid == 0:
        yield
        return
    groups = os.getgroups()
    os.setgroups([dst.st_gid])
    os.setegid(dst.st_gid)
    os.seteuid(dst.st_uid)
    try:
        yield
    finally:
        os.seteuid(0)
        os.setegid(0)
        os.setgroups(groups)


def open_runtime(path: Path | None = None) -> sqlite3.Connection:
    path = path or RUNTIME_DB_PATH
    dst = _runtime_files_check(path) if path.parent.exists() else None
    # SQLite opens the database, -wal and -shm during the first transaction
    # and keeps them open for the connection's life, so this window covers
    # every file it touches.
    with _as_owner_of(dst) if dst else contextlib.nullcontext():
        conn = _connect(path, readonly=False, wal=True)
        conn.row_factory = sqlite3.Row
        conn.executescript(_RUNTIME_SCHEMA)
        conn.commit()
    return conn


def iam_initialised(path: Path | None = None) -> bool:
    p = path or IAM_DB_PATH
    if not p.exists():
        return False
    try:
        conn = _connect(p, readonly=True, wal=False)
        row = conn.execute(
            "SELECT count(*) AS n FROM sqlite_master "
            "WHERE type='table' AND name='principals'").fetchone()
        conn.close()
        return bool(row and row[0])
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Credentials
#
# Two different hashes on purpose, because the two secrets are different kinds
# of thing:
#   - API keys are 256 bits of CSPRNG output. There is no dictionary to slow
#     down, so a KDF buys nothing; plain SHA-256 is correct and fast.
#   - Passwords are human-chosen and low-entropy. They get scrypt (stdlib —
#     no third-party dependency for the most security-sensitive primitive here)
#     with per-user salt and deliberately expensive parameters.
# ---------------------------------------------------------------------------
KEY_PREFIX_LEN = 8
_SCRYPT_N, _SCRYPT_R, _SCRYPT_P = 2 ** 15, 8, 1
# scrypt needs 128 * N * r bytes = exactly 32 MiB at these parameters, and
# OpenSSL's DEFAULT maxmem is also 32 MiB — so the call fails with an opaque
# "[digital envelope routines] memory limit exceeded" unless maxmem is raised
# explicitly. Found by running it, not by reading the docs: every password set
# and every login would have failed on this box. Headroom is deliberate so a
# future parameter bump doesn't silently hit the same wall.
_SCRYPT_MAXMEM = 96 * 1024 * 1024


def hash_key(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


def generate_key() -> tuple[str, str, str]:
    """Returns (full_key, prefix, key_hash). The full key is shown to the
    operator exactly once and never stored; only the hash and the prefix
    persist, so a key is identifiable in `list-keys` without being recoverable."""
    prefix = secrets.token_hex(KEY_PREFIX_LEN // 2)
    secret = secrets.token_urlsafe(32)
    return f"agk_{prefix}_{secret}", prefix, hash_key(secret)


def split_key(presented: str) -> tuple[str, str] | None:
    """agk_<prefix>_<secret> → (prefix, secret). None if malformed — callers
    must treat that as an authentication failure, never as an error to report
    in detail (it would confirm key-format details to an unauthenticated
    caller)."""
    parts = (presented or "").split("_", 2)
    if len(parts) != 3 or parts[0] != "agk" or not parts[1] or not parts[2]:
        return None
    return parts[1], parts[2]


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R,
                        p=_SCRYPT_P, dklen=32, maxmem=_SCRYPT_MAXMEM)
    return f"scrypt${_SCRYPT_N}${_SCRYPT_R}${_SCRYPT_P}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


@functools.lru_cache(maxsize=1)
def _dummy_password_hash() -> str:
    """A fixed scrypt hash, computed once per process on first use, spent by
    verify_login()'s missing-principal branch so it costs exactly the same
    ONE scrypt call as the real-principal-wrong-password branch.

    The bug this replaces: calling hash_password() fresh on every request
    (as this used to) does TWO scrypt hashes (hash_password's own, then
    verify_password's), not one — a ~100ms-scale gap, in the direction that
    makes a NONEXISTENT principal answer measurably SLOWER than a real one
    with a wrong password. That is the exact enumeration oracle this
    function's caller exists to close, reopened by a well-intentioned line
    that looked equivalent but wasn't. Found in the 2026-09-20 security
    audit (CLAUDE.md §4 item 15)."""
    return hash_password("timing-equalizer")


def verify_password(password: str, stored: str | None) -> bool:
    if not stored:
        return False
    try:
        algo, n, r, p, salt_b64, dk_b64 = stored.split("$")
        if algo != "scrypt":
            return False
        dk = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt_b64),
                            n=int(n), r=int(r), p=int(p),
                            dklen=len(base64.b64decode(dk_b64)), maxmem=_SCRYPT_MAXMEM)
        return secrets.compare_digest(dk, base64.b64decode(dk_b64))
    except (ValueError, TypeError):
        return False


# ---------------------------------------------------------------------------
# TOTP (RFC 6238) and recovery codes
#
# Implemented against the standard library rather than a dependency, for one
# decisive reason: RFC 6238 publishes official test vectors, so this can be
# PROVEN correct (see shared/test_iam.py) instead of trusted. "Don't roll your
# own crypto" is about designing primitives; HOTP is a documented truncation of
# an HMAC the stdlib already provides, and a wrong implementation fails the
# vectors loudly rather than silently weakening anything.
# ---------------------------------------------------------------------------
TOTP_STEP_S = 30
TOTP_DIGITS = 6
# One step of drift tolerated either way. Larger windows are a real weakening:
# each extra step is another 30 seconds in which a shoulder-surfed or phished
# code still works.
TOTP_WINDOW = 1
RECOVERY_CODE_COUNT = 10


def _hotp(key: bytes, counter: int, digits: int = TOTP_DIGITS,
          algo: str = "sha1") -> str:
    """RFC 4226 HOTP. sha1 is not a weakness here: HMAC-SHA1 is unbroken, and it
    is what every authenticator app implements."""
    mac = hmac.new(key, struct.pack(">Q", counter), algo).digest()
    offset = mac[-1] & 0x0F
    code = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10 ** digits)).zfill(digits)


def totp_generate_secret() -> str:
    """160 bits, the RFC 4226 recommended length, base32 for authenticator apps."""
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def totp_uri(secret: str, principal: str, issuer: str = "Agenti") -> str:
    """The otpauth:// URI an authenticator app consumes. Returned as text so the
    GUI renders the QR code CLIENT-side — no server-side QR dependency, and the
    secret never has to be turned into an image on disk."""
    from urllib.parse import quote
    label = quote(f"{issuer}:{principal}")
    return (f"otpauth://totp/{label}?secret={secret}&issuer={quote(issuer)}"
            f"&algorithm=SHA1&digits={TOTP_DIGITS}&period={TOTP_STEP_S}")


def totp_code(secret: str, at: float | None = None,
              digits: int = TOTP_DIGITS, step: int = TOTP_STEP_S,
              algo: str = "sha1") -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    return _hotp(key, int((time.time() if at is None else at) // step), digits, algo)


def totp_verify(secret: str, code: str, at: float | None = None) -> int | None:
    """Returns the matched time-step counter, or None.

    Returning the COUNTER rather than a bool is what makes replay protection
    possible: the caller records it and refuses that counter again, so a code
    observed in transit cannot be reused inside its remaining validity window.
    A bool would quietly make that impossible."""
    code = (code or "").strip().replace(" ", "")
    if not code.isdigit() or len(code) != TOTP_DIGITS:
        return None
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    now = int((time.time() if at is None else at) // TOTP_STEP_S)
    for drift in range(-TOTP_WINDOW, TOTP_WINDOW + 1):
        if secrets.compare_digest(_hotp(key, now + drift), code):
            return now + drift
    return None


def generate_recovery_codes(n: int = RECOVERY_CODE_COUNT) -> list[str]:
    """Shown once at enrolment. Grouped with a dash purely so a human can read
    one off a printout without losing their place."""
    out = []
    for _ in range(n):
        raw = secrets.token_hex(5)
        out.append(f"{raw[:5]}-{raw[5:]}")
    return out


# ---------------------------------------------------------------------------
# Authorization
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Decision:
    """The result of one permission check, with enough detail to EXPLAIN it.

    `agenti admin whoami-can` prints this verbatim. An authorization system
    nobody can debug is one people work around, so "why" is part of the
    return value, not something to reconstruct from logs afterwards."""
    allowed: bool
    principal: str
    permission: str
    resource: str
    reason: str
    matched: tuple[str, ...] = ()

    def as_dict(self) -> dict:
        return {
            "allowed": self.allowed, "principal": self.principal,
            "permission": self.permission, "resource": self.resource,
            "reason": self.reason, "matched": list(self.matched),
        }


def effective_permissions(conn: sqlite3.Connection, principal: str,
                          resource: str) -> tuple[set[str], list[str]]:
    """Permissions this principal holds, plus a human-readable explanation.

    Derived from the principal's role column rather than a bindings table.
    The ``resource`` parameter is accepted for API compatibility but the only
    resource is ``ORG_RESOURCE``; it has no effect on the result.
    """
    row = conn.execute("SELECT active, role FROM principals WHERE name=?",
                       (principal,)).fetchone()
    if row is None or not row["active"]:
        return set(), []
    role = row["role"]
    perms = set(BUILTIN_ROLES.get(role, ()))
    trace = [f"role={role!r} on {ORG_RESOURCE}"]
    return perms, trace


def check(conn: sqlite3.Connection, principal: str, permission: str,
          resource: str) -> Decision:
    """The single authorization entry point. Fails closed at every step."""
    if permission not in PERMISSIONS:
        return Decision(False, principal, permission, resource,
                        f"unknown permission {permission!r} — not in the catalog "
                        f"(this is a bug in the caller, not a policy decision)")
    row = conn.execute("SELECT active, role FROM principals WHERE name=?",
                       (principal,)).fetchone()
    if row is None:
        return Decision(False, principal, permission, resource,
                        f"no user named {principal!r}")
    if not row["active"]:
        return Decision(False, principal, permission, resource,
                        f"user {principal!r} is disabled")
    role = row["role"]
    if permission in BUILTIN_ROLES.get(role, ()):
        return Decision(True, principal, permission, resource,
                        f"granted by role {role!r}", (f"role={role!r}",))
    return Decision(False, principal, permission, resource,
                    f"role {role!r} does not include {permission!r}",
                    (f"role={role!r}",))


def context_text_sha256(text: str) -> str:
    """The hash an 'edit-context' grant is bound to: SHA-256 of the text
    exactly as context_store will store it (CRLF folded to LF). The API
    computes the same value before asking for approval; the root CLI computes
    it again from the file it was handed — they must agree or nothing is
    saved. Pinned against context_store in test_context_store.py."""
    import hashlib
    return hashlib.sha256(text.replace("\r\n", "\n").encode("utf-8")).hexdigest()


# The web tier's own account. Every call it makes reaches iam.py with this as
# --actor (the CLI passes $SUDO_USER, set by sudo itself, not by the caller).
API_ACCOUNT = os.environ.get("AGENTI_API_USER", "agenti-api")


def web_approve_create_user(conn, runtime, action: dict, grant_id: str) -> str:
    """Consumes a 'create-user' grant for exactly `action` (name, kind and
    role, rebuilt by the CLI from its own arguments) and re-checks, fresh,
    that the approver holds iam:manage. Returns the approver, who is recorded
    as the account's creator (operator decision 2026-10-22: creating an
    account from the web needs a fresh re-authentication every time)."""
    if action.get("op") != "create-user":
        raise IAMError("not a create-user action")
    approver = consume_action_grant(runtime, grant_id, action)
    if not check(conn, approver, "iam:manage", action["resource"]).allowed:
        raise IAMError(f"{approver!r} approved this but is not an admin — refusing. "
                       f"No account was created.")
    return approver


def web_approve_engagement(conn, runtime, action: dict, grant_id: str) -> str:
    """Consumes an 'engagement-set' or 'engagement-approve' grant for exactly
    `action` (the CLI rebuilds it: the SHA-256 of the change it received, or
    the digest the approver reviewed) and re-checks, fresh, that the approver
    holds engagement:manage or engagement:approve. Returns the approver, who
    is recorded as the author or approver (audit run 1, F13)."""
    perm = {"engagement-set": "engagement:manage", "engagement-approve": "engagement:approve"}.get(action.get("op"))
    if perm is None:
        raise IAMError("not an engagement-set/engagement-approve action")
    approver = consume_action_grant(runtime, grant_id, action)
    if not check(conn, approver, perm, action["resource"]).allowed:
        raise IAMError(f"{approver!r} approved this but does not hold {perm} — refusing. "
                       f"The engagement was not changed.")
    return approver


def web_approve_context_edit(conn, runtime, action: dict, grant_id: str) -> str:
    """Consumes an 'edit-context' grant for exactly `action` (the CLI rebuilds
    it from its own arguments) and re-checks, fresh, that the approver holds
    iam:manage on the action's resource. Returns the approver; writing the
    file is context_store's job."""
    if action.get("op") != "edit-context":
        raise IAMError("not an edit-context action")
    approver = consume_action_grant(runtime, grant_id, action)
    if not check(conn, approver, "iam:manage", action["resource"]).allowed:
        raise IAMError(f"{approver!r} approved this but does not hold iam:manage on "
                       f"{action['resource']} — refusing. Nothing was changed.")
    return approver


def web_approve_agent_build(conn, runtime, action: dict, grant_id: str) -> str:
    """Consumes a 'build-agent' or 'remove-agent' grant for exactly `action`
    (the CLI rebuilds it — for a build, from the SHA-256 of the spec it was
    handed) and re-checks, fresh, that the approver holds iam:manage. Returns
    the approver; agent_builder.py does the work."""
    if action.get("op") not in ("build-agent", "remove-agent", "update-agent", "edit-catalog"):
        raise IAMError("not an agent build/update/remove or catalog-edit action")
    if action.get("resource") != ORG_RESOURCE:
        raise IAMError("building or removing an agent is an organisation-wide action")
    approver = consume_action_grant(runtime, grant_id, action)
    if not check(conn, approver, "iam:manage", action["resource"]).allowed:
        raise IAMError(f"{approver!r} approved this but is not an admin — refusing. "
                       f"Nothing was changed.")
    return approver


def web_approve_vault_enable(conn, runtime, size: str, grant_id: str) -> str:
    """Consumes a 'vault-enable' grant for exactly this container size and
    re-checks, fresh, that the approver is an admin (decision 6, audit run 1).
    Returns the approver; vault.sh does the work."""
    action = {"op": "vault-enable", "size": size, "resource": ORG_RESOURCE}
    approver = consume_action_grant(runtime, grant_id, action)
    if not check(conn, approver, "iam:manage", ORG_RESOURCE).allowed:
        raise IAMError(f"{approver!r} approved this but is not an admin — refusing. "
                       f"Nothing was changed.")
    return approver


def web_approve_exploit_action(conn, runtime, action: dict, grant_id: str) -> str:
    """Consumes an 'action-approve' or 'action-reject' grant (or their legacy
    'exploit-approve'/'exploit-reject' names) for exactly `action`. Deliberately
    NOT iam:manage — approving a live module is an operator deciding on their
    own run; the fresh re-authentication is what raises the bar.
    Returns the approver; shared/agenti writes the approval record."""
    if action.get("op") not in ("action-approve", "action-reject",
                                 "exploit-approve", "exploit-reject"):
        raise IAMError("not an action-approve/action-reject action")
    if action.get("resource") != ORG_RESOURCE:
        raise IAMError("an exploit approval is bound to the organisation's engagement")
    approver = consume_action_grant(runtime, grant_id, action)
    if not check(conn, approver, "agent:chat", action["resource"]).allowed:
        raise IAMError(f"{approver!r} approved this but does not hold agent:chat — "
                       f"refusing. Nothing was changed.")
    if approver != action.get("owner"):
        raise IAMError(f"{approver!r} approved this, but the run belongs to "
                       f"{action.get('owner')!r}: only the operator whose run proposed an "
                       f"action may decide it. Nothing was changed.")
    return approver


def effective_role_name(conn: sqlite3.Connection, principal: str,
                        resource: str = ORG_RESOURCE) -> str | None:
    """The role this principal holds, or None if they have no account."""
    row = conn.execute("SELECT role FROM principals WHERE name=? AND active=1",
                       (principal,)).fetchone()
    return row["role"] if row else None


def _is_admin(conn: sqlite3.Connection, name: str) -> bool:
    row = conn.execute("SELECT role FROM principals WHERE name=? AND active=1",
                       (name,)).fetchone()
    return bool(row and row["role"] == "admin")


def dashboard_access(conn: sqlite3.Connection, viewer: str, target: str) -> dict:
    """May `viewer` see `target`'s dashboard (their runs, history and kept
    files), and stop / mark-complete / delete there? Runs are private to the
    user who launched them, so the answer is no except:

      - yourself, always;
      - an admin -> any operator;
      - nobody -> an admin's dashboard (it is private to them).

    Returns {"allowed", "reason"}."""
    out = {"allowed": False, "reason": ""}
    if viewer == target:
        return {**out, "allowed": True, "reason": "your own dashboard"}
    if conn.execute("SELECT 1 FROM principals WHERE name=? AND active=1",
                    (viewer,)).fetchone() is None:
        return {**out, "reason": f"{viewer!r} is not an active user"}
    if conn.execute("SELECT 1 FROM principals WHERE name=?", (target,)).fetchone() is None:
        return {**out, "reason": f"no user named {target!r}"}
    if _is_admin(conn, target):
        return {**out, "reason": "an admin's dashboard is private to them"}
    if _is_admin(conn, viewer):
        return {**out, "allowed": True, "reason": "admin"}
    return {**out, "reason": "runs are private to the user who launched them — only an "
                             "admin may open someone else's dashboard"}


def log_decision(runtime: sqlite3.Connection, d: Decision, via: str) -> None:
    """Append one row per authorization decision. Deliberately records DENIES
    as well as allows: a burst of denials is the signal that someone is probing
    or that a binding is wrong, and it is invisible if only successes are kept."""
    try:
        runtime.execute(
            "INSERT INTO authz_log(ts, principal, permission, resource, decision, reason, via)"
            " VALUES (?,?,?,?,?,?,?)",
            (time.time(), d.principal, d.permission, d.resource,
             "allow" if d.allowed else "deny", d.reason, via))
        runtime.commit()
    except sqlite3.Error:
        # Audit logging must never be able to fail a request open OR closed.
        # The decision itself already happened; losing one log row is strictly
        # better than 500-ing an authorized call. Same reasoning as state.py's
        # try/except around every StateStore call.
        pass


# ---------------------------------------------------------------------------
# Key authentication
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class AuthResult:
    principal: str | None
    reason: str = ""
    prefix: str | None = None

    @property
    def ok(self) -> bool:
        return self.principal is not None


def authenticate_key(conn: sqlite3.Connection, presented: str) -> AuthResult:
    """Constant-time comparison, and a DELIBERATELY UNIFORM failure reason for
    every rejection path (unknown prefix, wrong secret, revoked, expired,
    disabled principal). The caller turns this into one 401 with one message —
    distinguishing "no such key" from "wrong secret" would let an
    unauthenticated caller enumerate valid prefixes."""
    generic = "invalid or expired credentials"
    parts = split_key(presented)
    if parts is None:
        return AuthResult(None, generic)
    prefix, secret = parts
    row = conn.execute("SELECT * FROM api_keys WHERE prefix = ?", (prefix,)).fetchone()
    if row is None:
        # Still hash, so a missing prefix costs the same time as a wrong secret.
        hash_key(secret)
        return AuthResult(None, generic)
    if not secrets.compare_digest(hash_key(secret), row["key_hash"]):
        return AuthResult(None, generic)
    if row["revoked_at"]:
        return AuthResult(None, generic, prefix)
    if row["expires_at"] and row["expires_at"] < time.time():
        return AuthResult(None, generic, prefix)
    p = conn.execute("SELECT active FROM principals WHERE name = ?",
                     (row["principal"],)).fetchone()
    if p is None or not p["active"]:
        return AuthResult(None, generic, prefix)
    return AuthResult(row["principal"], "ok", prefix)


def record_key_use(runtime: sqlite3.Connection, prefix: str) -> None:
    """Written to runtime.db, not iam.db — the API cannot write the identity
    store, which is the point of the split. Stale last-used data is a far
    smaller problem than an API process that can edit its own permissions."""
    try:
        runtime.execute(
            "INSERT INTO key_usage(prefix, last_used, uses) VALUES (?,?,1) "
            "ON CONFLICT(prefix) DO UPDATE SET last_used=excluded.last_used, uses=uses+1",
            (prefix, time.time()))
        runtime.commit()
    except sqlite3.Error:
        pass


# ---------------------------------------------------------------------------
# Password / TOTP verification and lockout.
#
# These read iam.db (credentials) and write runtime.db (attempt counters, TOTP
# replay records) — the split from this module's docstring, in practice: the
# API can CHECK a credential and can record that someone tried, and it cannot
# change what the credential is.
# ---------------------------------------------------------------------------
LOCKOUT_THRESHOLD = 5
LOCKOUT_SECONDS = 15 * 60

# Per-SOURCE-ADDRESS throttling, separate from the per-principal lockout above
# and deliberately looser.
#
# The two answer different attacks. The per-principal lockout stops someone
# guessing one account's password. It does nothing about an attacker spreading
# attempts ACROSS accounts from one machine, and — worse on a network — it is
# itself a weapon: anyone who can reach the login page can lock out a principal
# they know the name of, indefinitely, at a few requests an hour.
#
# On loopback that barely mattered, because reaching the page meant already
# being on the box. The moment the GUI is LAN-reachable over HTTPS it matters,
# which is why this lands in the same phase as the exposure rather than later.
#
# Threshold is higher than the per-principal one because several people can
# legitimately share an address (NAT, a shared machine) and a household typo
# should not lock a street out.
ADDR_LOCKOUT_THRESHOLD = 20
ADDR_LOCKOUT_SECONDS = 10 * 60


def _addr_state(runtime, addr: str) -> tuple[int, float]:
    row = runtime.execute(
        "SELECT failures, locked_until FROM login_attempts_addr WHERE addr=?",
        (addr,)).fetchone()
    if row is None:
        return 0, 0.0
    return row["failures"], (row["locked_until"] or 0.0)


def address_locked(runtime, addr: str) -> float:
    """Seconds remaining before this address may try again, or 0."""
    if not addr:
        return 0.0
    _, locked_until = _addr_state(runtime, addr)
    remaining = (locked_until or 0.0) - time.time()
    return remaining if remaining > 0 else 0.0


@contextlib.contextmanager
def _write_txn(runtime):
    """One write transaction taken BEFORE the read it depends on (BEGIN
    IMMEDIATE), so two requests cannot both read the same old value."""
    if runtime.in_transaction:
        runtime.commit()
    runtime.execute("BEGIN IMMEDIATE")
    try:
        yield
        runtime.commit()
    except BaseException:
        runtime.rollback()
        raise


def _reserve_attempt(runtime, table: str, col: str, key: str,
                     threshold: int, seconds: float) -> float:
    """Count this attempt BEFORE it is checked, and return how long the key is
    still locked (0 = go ahead). Counting after the check let thirty parallel
    guesses all be checked before the fifth one's lock landed (audit run 2).
    The window resets after `seconds` with no attempt: a counter that only
    ever grows turns into a permanent lock after a long-forgotten streak
    (2026-09-20 audit), so five fresh attempts per window, never one."""
    if not key:
        return 0.0
    now = time.time()
    with _write_txn(runtime):
        row = runtime.execute(f"SELECT failures, locked_until, last_failure FROM {table} WHERE {col}=?",
                              (key,)).fetchone()
        if row is not None and (row["locked_until"] or 0.0) > now:
            return row["locked_until"] - now
        stale = row is None or not row["last_failure"] or (now - row["last_failure"]) > seconds
        failures = 1 if stale else (row["failures"] or 0) + 1
        runtime.execute(
            f"INSERT INTO {table}({col}, failures, locked_until, last_failure) VALUES (?,?,?,?)"
            f" ON CONFLICT({col}) DO UPDATE SET failures=excluded.failures,"
            f" locked_until=excluded.locked_until, last_failure=excluded.last_failure",
            (key, failures, now + seconds if failures >= threshold else None, now))
    # A lockout is worth an admin seeing (`agenti admin authz-log`), once,
    # on the attempt that reaches it.
    if table == "login_attempts" and failures == threshold:
        try:
            runtime.execute(
                "INSERT INTO authz_log(ts, principal, permission, resource, decision, reason, via)"
                " VALUES (?,?,?,?,?,?,?)",
                (now, key, "auth:login", "-", "deny",
                 f"account locked for {LOCKOUT_SECONDS}s after {failures} failed attempts", "login"))
            runtime.commit()
        except sqlite3.Error:
            pass
    return 0.0


def _release_attempt(runtime, table: str, col: str, key: str, threshold: int) -> None:
    """Give back the count a CORRECT password took while its second factor is
    still to come: otherwise four typos and then the right password would lock
    the account before the code could be entered. Only clearing the counters
    on a full sign-in stays the rule (audit run 1, F20)."""
    if not key:
        return
    with _write_txn(runtime):
        runtime.execute(
            f"UPDATE {table} SET failures=MAX(failures-1, 0),"
            f" locked_until=CASE WHEN failures-1 >= ? THEN locked_until ELSE NULL END WHERE {col}=?",
            (threshold, key))


def _reserve_principal(runtime, principal: str) -> float:
    return _reserve_attempt(runtime, "login_attempts", "principal", principal,
                            LOCKOUT_THRESHOLD, LOCKOUT_SECONDS)


def _reserve_address(runtime, addr: str) -> float:
    return _reserve_attempt(runtime, "login_attempts_addr", "addr", addr,
                            ADDR_LOCKOUT_THRESHOLD, ADDR_LOCKOUT_SECONDS)


def _release_both(runtime, principal: str, addr: str) -> None:
    _release_attempt(runtime, "login_attempts", "principal", principal, LOCKOUT_THRESHOLD)
    _release_attempt(runtime, "login_attempts_addr", "addr", addr, ADDR_LOCKOUT_THRESHOLD)


def record_address_failure(runtime, addr: str) -> None:
    """Count one failed attempt from this address (the passkey login, which
    has no secret to guess, feeds only this counter)."""
    _reserve_address(runtime, addr)


def clear_address_failures(runtime, addr: str) -> None:
    """A successful login clears the address counter — otherwise a busy shared
    address accumulates unrelated typos until it locks itself out."""
    if not addr:
        return
    runtime.execute("DELETE FROM login_attempts_addr WHERE addr=?", (addr,))
    runtime.commit()


@dataclass(frozen=True)
class LoginResult:
    principal: str | None
    totp_required: bool = False
    must_change_password: bool = False
    reason: str = ""
    retry_after: float = 0.0

    @property
    def ok(self) -> bool:
        return self.principal is not None


def _lockout_state(runtime, principal: str) -> tuple[int, float]:
    row = runtime.execute(
        "SELECT failures, locked_until FROM login_attempts WHERE principal=?",
        (principal,)).fetchone()
    if row is None:
        return 0, 0.0
    return row["failures"], (row["locked_until"] or 0.0)


def clear_failures(runtime, principal: str) -> None:
    runtime.execute("DELETE FROM login_attempts WHERE principal=?", (principal,))
    runtime.commit()


def verify_login(conn, runtime, principal: str, password: str,
                 addr: str = "") -> LoginResult:
    """Step one of login. Returns totp_required when the principal is enrolled;
    the caller must NOT consider them authenticated until totp is verified too.

    Every failure path returns the SAME message. Saying "no such user" would let
    anyone enumerate valid principal names, and this service's principal names
    are client and staff names.

    `addr` is the caller's source address, throttled separately from the
    per-principal lockout (see ADDR_LOCKOUT_THRESHOLD). Empty means "not
    known", which disables the address check rather than inventing a bucket
    every caller shares — a single shared bucket would let one attacker lock
    out every login on the box."""
    generic = "invalid credentials"
    # Address throttle first: it is the one check that must apply even to a
    # principal name that does not exist, since spraying across invented names
    # is exactly the pattern the per-principal counter cannot see.
    # Every attempt is COUNTED before it is checked (see _reserve_attempt);
    # a failure needs nothing more, a success gives the count back.
    addr_wait = _reserve_address(runtime, addr)
    if addr_wait > 0:
        return LoginResult(None, reason="too many failed attempts from this "
                                        "address — try again later",
                           retry_after=addr_wait)
    # Lockout is checked and recorded even for a principal that does not exist,
    # so the timing and the response of a real account under attack are
    # indistinguishable from a fabricated one.
    wait = _reserve_principal(runtime, principal)
    if wait > 0:
        return LoginResult(None, reason="account temporarily locked after repeated "
                                        "failed attempts — try again later",
                           retry_after=wait)

    row = conn.execute(
        "SELECT name, active, password_hash, must_change, totp_secret"
        " FROM principals WHERE name=?", (principal,)).fetchone()
    if row is None or not row["active"] or not row["password_hash"]:
        # Spend the same ONE scrypt call a real verification below does, so a
        # missing principal is not distinguishable by response time. Must be
        # a FIXED precomputed hash, not hash_password() called fresh here —
        # that was two scrypt calls (this file's own past mistake; see
        # _dummy_password_hash()'s docstring).
        verify_password(password, _dummy_password_hash())
        return LoginResult(None, reason=generic)

    if not verify_password(password, row["password_hash"]):
        return LoginResult(None, reason=generic)

    # A correct password is only the whole sign-in when the account has no
    # second factor. Otherwise the failure counters stay as they are until the
    # second step passes too: clearing them here let someone holding the
    # password guess codes four at a time forever (audit run 1, F20).
    if row["totp_secret"]:
        _release_both(runtime, principal, addr)
        return LoginResult(principal, totp_required=True,
                           must_change_password=bool(row["must_change"]), reason="ok")
    if has_passkey(conn, principal):
        # A passkey is this account's second factor, so the password alone
        # is not a sign-in (audit run 1, F07): the passkey door is the way in.
        _release_both(runtime, principal, addr)
        return LoginResult(None, reason=PASSKEY_ACCOUNT_REASON)
    clear_failures(runtime, principal)
    clear_address_failures(runtime, addr)
    return LoginResult(principal, must_change_password=bool(row["must_change"]), reason="ok")


PASSKEY_ACCOUNT_REASON = ("this account's second factor is a passkey, so the password "
                          "alone is not enough — use your passkey instead (Sign in with a "
                          "passkey, or the passkey button in this dialog). Lost it? An admin "
                          "can reset your 2FA: Settings → Users.")


def verify_second_factor(conn, runtime, principal: str, code: str,
                         addr: str = "") -> LoginResult:
    """Step two: a TOTP code, or a single-use recovery code. A wrong code
    counts against the account and the caller's address, like a wrong
    password; only a right one clears them (F20).

    Replay protection is the reason totp_verify returns a counter: a code seen
    in transit is otherwise valid for the rest of its 30-second step, and
    re-using it would be indistinguishable from the real login."""
    generic = "invalid code"
    addr_wait = _reserve_address(runtime, addr)
    if addr_wait > 0:
        return LoginResult(None, reason="too many failed attempts from this "
                                        "address — try again later", retry_after=addr_wait)
    wait = _reserve_principal(runtime, principal)
    if wait > 0:
        return LoginResult(None, reason="account temporarily locked — try again later",
                           retry_after=wait)

    row = conn.execute("SELECT totp_secret FROM principals WHERE name=?",
                       (principal,)).fetchone()
    if row is None or not row["totp_secret"]:
        return LoginResult(None, reason=generic)

    counter = totp_verify(row["totp_secret"], code)
    if counter is not None:
        # The insert decides "already used": of two requests with one code,
        # only one row can be written (audit run 2).
        try:
            runtime.execute("INSERT INTO totp_used(principal, counter, used_at) VALUES (?,?,?)",
                            (principal, counter, time.time()))
        except sqlite3.IntegrityError:
            runtime.rollback()
            return LoginResult(None, reason="that code has already been used")
        # Old counters can never match again (the window has moved on), so
        # pruning keeps the table from growing without bound.
        runtime.execute("DELETE FROM totp_used WHERE used_at < ?", (time.time() - 3600,))
        runtime.commit()
        clear_failures(runtime, principal)
        clear_address_failures(runtime, addr)
        return LoginResult(principal, reason="ok")

    # Fall back to a recovery code. Single use.
    #
    # The "already used" marker lives in runtime.db, NOT in iam.db, specifically
    # so that burning a code does not require the API to write the identity
    # store — that read-only property is the headline guarantee of the two-store
    # split and is worth more than keeping all recovery state in one file. The
    # residual: wiping runtime.db would make already-used codes valid again, but
    # that also destroys every session, is a root-only act, and is visible.
    used_ids = {r["code_id"] for r in runtime.execute(
        "SELECT code_id FROM recovery_used WHERE principal=?", (principal,))}
    for r in conn.execute(
            "SELECT rowid AS rid, code_hash FROM recovery_codes WHERE principal=?",
            (principal,)):
        if r["rid"] in used_ids:
            continue
        if verify_password(code.strip().lower(), r["code_hash"]):
            try:
                runtime.execute("INSERT INTO recovery_used(principal, code_id, used_at) VALUES (?,?,?)",
                                (principal, r["rid"], time.time()))
            except sqlite3.IntegrityError:
                runtime.rollback()
                return LoginResult(None, reason=generic)      # spent a moment ago by another request
            runtime.commit()
            clear_failures(runtime, principal)
            clear_address_failures(runtime, addr)
            return LoginResult(principal, reason="ok (recovery code consumed)")

    return LoginResult(None, reason=generic)


def reauthenticate_self(conn, runtime, name: str, current_password: str,
                        totp_code: str | None, addr: str = "",
                        require_password: bool = True) -> None:
    """Re-prove a principal's OWN current credential before a self-service
    identity change (`self password` / `self mfa-start` / `self mfa-confirm`
    in shared/agenti) or a web-tier action gated behind fresh proof of
    presence (the bounded web grant, §4 item 24). Raises IAMError on any
    failure; returns normally on success.

    THIS is what makes it safe for the API to invoke these verbs at all,
    despite iam.db being nominally read-only to it. A compromised API
    process, or a hijacked session cookie, holds neither the password nor a
    live TOTP code — the session store is exactly the thing the API DOES
    own — so this check defeats precisely that attack, even though the
    request that reaches here is already root, already past
    refuse_iam_writes_from_api's allow-list, and already carrying a
    principal name the API claims to trust. It is the actual authorization
    mechanism for the whole 'self' verb family, not a formality on top of
    one.

    `require_password=False` (used only by the lower-stakes tier of the web
    grant ceremony — see WEB_GRANT_PASSWORD_ROLES) skips the password check
    entirely and relies on the 2FA code alone. The attack this whole
    function defends against — a compromised API or a hijacked session
    cookie, neither of which holds a live code — is defeated by the code
    check on its own; what dropping the password check gives up is only
    that someone holding the account's TOTP generator but not its password
    can pass this check. A code-only caller MUST have 2FA enrolled: there
    is no weaker fallback, since skipping the one check that was asked for
    without still requiring the other would leave nothing proven at all.

    Unlike the network-facing /auth/login endpoint, error messages here are
    specific rather than deliberately vague: by the time this runs, the
    caller is already an authenticated session asking about ITS OWN account,
    so there is no principal name to enumerate — they already know it."""
    row = conn.execute("SELECT totp_secret FROM principals WHERE name=?",
                       (name,)).fetchone()
    if row is None:
        raise IAMError(f"no user named {name!r}")
    if require_password:
        result = verify_login(conn, runtime, name, current_password, addr=addr)
        if not result.ok:
            raise IAMError("current password is incorrect" if result.reason == "invalid credentials"
                           else result.reason)
    if not row["totp_secret"]:
        if require_password:
            return
        raise IAMError("this account has no 2FA enrolled, so there is nothing "
                       "a code-only check can verify — enroll 2FA first")
    if not totp_code:
        raise IAMError("this account has 2FA enrolled — a current code "
                       "(or a recovery code) is required too")
    code_result = verify_second_factor(conn, runtime, name, totp_code, addr=addr)
    if not code_result.ok:
        raise IAMError(code_result.reason or "invalid code")


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------
def get_setting(conn: sqlite3.Connection, key: str, default: str = "") -> str:
    row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else default


def set_setting(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute("INSERT INTO settings(key, value) VALUES (?,?) "
                 "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))
    conn.commit()


# ---------------------------------------------------------------------------
# Two-factor policy: is a second factor REQUIRED for this account?
#
# Default ON, platform-wide, with one narrower override — "2FA should be
# enforced at sign up, no exception unless stated otherwise in a security
# policy for the user." Resolution, most specific first:
#
#   1. a service principal never needs one (it authenticates with an API key
#      — there is no password to protect, and no human to hold a device);
#   2. `require-2fa:<principal>`  — an explicit per-account setting wins;
#   3. the platform policy `require-2fa`, which is ON unless set off.
#
# It is enforced in two places, and they answer different questions.
# consume_enrolment_token() refuses to finish a sign-up without a verified
# second factor — the "at sign up" half. agenti-authd then marks every
# password-only session `mfa_setup_required` (authd.op_authenticate), and
# the API refuses that session everything except the self-service MFA
# routes — the half that catches an account enrolled before the policy
# existed, or by the root CLI's `set-password`, which deliberately stays
# a one-step break-glass path. Setting the policy OFF for someone is a
# `set-policy` call: an authorization decision, refused to the API.
# ---------------------------------------------------------------------------
TWO_FACTOR_POLICY_KEY = "require-2fa"


def two_factor_required(conn: sqlite3.Connection, principal: str) -> tuple[bool, str]:
    """(required, why) — the `why` names the policy row that decided it, so a
    refusal can say exactly which setting to change."""
    row = conn.execute("SELECT kind FROM principals WHERE name=?", (principal,)).fetchone()
    if row is None:
        raise IAMError(f"no user named {principal!r}")
    if row["kind"] == "service":
        return False, "service accounts authenticate with an API key, not a password"
    own = get_setting(conn, f"{TWO_FACTOR_POLICY_KEY}:{principal}", "")
    if own in ("on", "off"):
        return own == "on", f"policy {TWO_FACTOR_POLICY_KEY}:{principal} = {own}"
    platform = get_setting(conn, TWO_FACTOR_POLICY_KEY, "")
    if platform in ("on", "off"):
        return platform == "on", f"platform policy {TWO_FACTOR_POLICY_KEY} = {platform}"
    return True, f"platform policy {TWO_FACTOR_POLICY_KEY} = on (the default)"


def mfa_setup_required(conn: sqlite3.Connection, principal: str) -> bool:
    """Password-holder with no second factor, under a policy that requires
    one. What authd attaches to every session so the API can confine it.

    A registered passkey satisfies this on its own, same as TOTP — a
    platform/synced authenticator already performs a biometric or PIN check
    before releasing a signature, so it proves both 'something you have' and
    'something you are' without a separate TOTP enrolment on top of it."""
    row = conn.execute("SELECT totp_secret FROM principals WHERE name=?",
                       (principal,)).fetchone()
    if row is None or row["totp_secret"]:
        return False
    if has_passkey(conn, principal):
        return False
    return two_factor_required(conn, principal)[0]


def _qr_svg(text: str) -> str | None:
    """The otpauth URI as an SVG, or None if the encoder is not installed
    beside this file (the package installs it; the enrolment still works
    from the secret alone, so this must never be the reason a call fails)."""
    try:
        import qr
        return qr.to_svg(qr.encode(text, "M"))
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Mutations — root/CLI only. Every one takes `actor` so the store records who
# made the change, not just what changed.
# ---------------------------------------------------------------------------

# Outside the vault, like TOOL_REQUESTS_PATH — so a rename or a
# hard delete's permanent record survives even a vault re-create, and so the
# API (which never opens iam.db) can still be handed a read-only accessor to
# it later without gaining any new reach into identity data.
PRINCIPAL_HISTORY_PATH = Path(os.environ.get(
    "AGENTI_PRINCIPAL_HISTORY_PATH", "/var/lib/agenti/principal-history.jsonl"))


def _append_principal_history(row: dict) -> None:
    """The permanent record of a principal rename or hard delete — modelled
    directly on _append_outputs_history: best-effort on the chmod, and a
    logging failure must never turn an already-committed rename/delete into
    a reported failure, since by the time this is called the real mutation
    has already succeeded. This is also what _is_tombstoned() below reads to
    refuse reissuing a deleted name, and what a future display-side reader
    uses to annotate a now-absent name as "(deleted)"/"(now <new>)"."""
    try:
        existed = PRINCIPAL_HISTORY_PATH.is_file()
        PRINCIPAL_HISTORY_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(PRINCIPAL_HISTORY_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
        if not existed:
            os.chmod(PRINCIPAL_HISTORY_PATH, 0o640)
    except OSError:
        pass


def _is_tombstoned(name: str) -> bool:
    """True if `name` was permanently hard-deleted before (delete_principal).
    Reused, it would let a new, unrelated account silently inherit every
    historical record — audit rows, run history, team chat, reports — that
    still names it, exactly the reactivation hazard delete_role's own
    docstring already argues against for a role name. A RENAMED-away name is
    deliberately NOT tombstoned this way: nothing was destroyed there, only
    relabeled, so the old name is free to reissue."""
    if not PRINCIPAL_HISTORY_PATH.is_file():
        return False
    try:
        with open(PRINCIPAL_HISTORY_PATH, encoding="utf-8") as f:
            for line in f:
                try:
                    row = json.loads(line)
                except (json.JSONDecodeError, ValueError):
                    continue
                if row.get("event") == "deleted" and row.get("name") == name:
                    return True
    except OSError:
        pass
    return False


def add_principal(conn, name: str, kind: str, actor: str,
                  role: str = "operator") -> None:
    validate_name(name, "user")
    if kind not in ("user", "service"):
        raise IAMError(f"kind must be 'user' or 'service', not {kind!r}")
    if role not in BUILTIN_ROLES:
        raise IAMError(f"role must be one of {', '.join(BUILTIN_ROLES)}, not {role!r}")
    if _is_tombstoned(name):
        raise IAMError(
            f"{name!r} was a real account here before and was permanently deleted — "
            f"reusing it would let this new account silently inherit old audit/run "
            f"history that still names it. Pick a name that was never used before "
            f"(see: sudo agenti admin user-history).")
    try:
        conn.execute(
            "INSERT INTO principals(name, kind, active, role, created_at, created_by)"
            " VALUES (?,?,1,?,?,?)", (name, kind, role, time.time(), actor))
        conn.commit()
    except sqlite3.IntegrityError:
        raise IAMError(f"principal {name!r} already exists. See: sudo agenti admin user list")


def set_principal_role(conn, name: str, role: str, actor: str) -> None:
    """Change a user's role to operator or admin."""
    if role not in BUILTIN_ROLES:
        raise IAMError(f"role must be one of {', '.join(BUILTIN_ROLES)}, not {role!r}. "
                       f"See: sudo agenti admin bind user <name> --role <operator|admin>")
    validate_name(name, "user")
    if conn.execute("SELECT 1 FROM principals WHERE name=?", (name,)).fetchone() is None:
        raise IAMError(f"no user named {name!r}")
    if role != "admin" and _is_last_admin(conn, name):
        raise IAMError(
            f"{name!r} is the only active admin — demoting them would leave no admin. "
            f"Promote another account first: "
            f"sudo agenti admin bind user <name> --role admin")
    conn.execute("UPDATE principals SET role=? WHERE name=?", (role, name))
    conn.commit()
    _append_principal_history({
        "ts": time.time(), "event": "role", "name": name,
        "role": role, "by": actor,
    })


def set_principal_active(conn, name: str, active: bool, actor: str | None = None) -> None:
    """Disabling refuses two lockouts, the same two delete_principal refuses
    (§4 item 78): the account you are acting as, and the last active global
    admin. Neither is bypassable by root: add a second admin first."""
    if not active:
        if actor and actor == name:
            raise IAMError("you cannot disable the account you are currently using — "
                           "ask another admin to do it.")
        if _is_last_admin(conn, name):
            raise IAMError(
                f"{name!r} is the only active admin — disabling them would lock everyone "
                f"out of the admin screens. Give another account admin first: "
                f"sudo agenti admin bind user <name> --role admin")
    if conn.execute("UPDATE principals SET active=? WHERE name=?",
                    (1 if active else 0, name)).rowcount == 0:
        raise IAMError(f"no user named {name!r}")
    conn.commit()


def _active_admins(conn) -> list[str]:
    return [r["name"] for r in conn.execute(
        "SELECT name FROM principals WHERE active=1 AND role='admin'"
    )]


def _is_last_admin(conn, name: str) -> bool:
    admins = _active_admins(conn)
    return name in admins and len(admins) == 1


def _owner_slots(owner: str) -> list[Path]:
    """Every run slot this user owns, in every agent: <agent>/
    instances/<owner> and <owner>.<copy> (§4 item 71 — a run lives in its
    launcher's own slot)."""
    out = []
    try:
        for inst in org_dir().glob("*/instances"):
            out += [d for d in inst.iterdir() if d.is_dir()
                    and (d.name == owner or d.name.startswith(owner + "."))]
    except OSError:
        pass
    return out


def _slot_unit(slot: Path) -> str:
    agent = slot.parent.parent.name
    return f"agenti-{agent}-instance@{slot.name}.service"


def _mangle(path: Path) -> str:
    """The SDK keys a session transcript directory by its working directory
    with every non-alphanumeric replaced by '-'."""
    return re.sub(r"[^A-Za-z0-9]", "-", str(path))


def _rename_user_files(old: str, new: str) -> None:
    """Move what is keyed by the user's name outside iam.db: their memory for
    each agent (with its edit history and suggestion decisions) and their own
    API key folder. Left behind, a new account given the old name would
    inherit both (audit run 1, F36). Best-effort per item, like the other
    moves; never overwrites anything already under the new name."""
    def move(src: Path, dst: Path) -> None:
        if src.exists() and not dst.exists():
            try:
                dst.parent.mkdir(parents=True, exist_ok=True)
                src.rename(dst)
            except OSError:
                pass
    ctx = org_dir() / "context"
    mem = ctx / "memory"
    if mem.is_dir():
        for agent_dir in mem.iterdir():
            if agent_dir.is_dir() and not agent_dir.is_symlink():
                move(agent_dir / f"{old}.md", agent_dir / f"{new}.md")
                move(agent_dir / ".versions" / old, agent_dir / ".versions" / new)
    dec = ctx / "memory-decisions"
    if dec.is_dir():
        for agent_dir in dec.iterdir():
            if agent_dir.is_dir() and not agent_dir.is_symlink():
                move(agent_dir / f"{old}.json", agent_dir / f"{new}.json")
    move(org_dir() / "users" / old, org_dir() / "users" / new)


def _rename_runs(old: str, new: str) -> int:
    """Move a renamed user's run slots, their SDK transcripts (so a stopped
    run stays resumable) and the owner field of their teams. Best-effort per
    item, like the outputs-directory move: the identity rename has already
    committed by the time this runs. Returns how many slots moved."""
    moved = 0
    for slot in _owner_slots(old):
        dest = slot.parent / (new + slot.name[len(old):])
        if dest.exists():
            continue
        try:
            slot.rename(dest)
            moved += 1
        except OSError:
            continue
        projects = dest / ".claude" / "projects"
        stale = projects / _mangle(slot)
        if stale.is_dir():
            try:
                stale.rename(projects / _mangle(dest))
            except OSError:
                pass
    for tf in (org_dir() / "teams").glob("*.json"):
        try:
            doc = json.loads(tf.read_text())
            if doc.get("owner") == old:
                doc["owner"] = new
                tf.write_text(json.dumps(doc))
        except (OSError, ValueError):
            continue
    return moved


def rename_principal(conn, runtime, old: str, new: str, actor: str) -> dict:
    """Renames a principal's real login name — the identifier itself, not a
    cosmetic label — everywhere it IS the identity: every binding,
    membership, API key, recovery code and passkey record, plus the three
    per-principal settings rows (require-2fa:<n>,
    limit:outputs-bytes-per-operator:<n>),
    all in one iam.db transaction. `created_by`/`authz_log` actor columns
    are left alone — they are historical records of who did something, not
    live references to who someone currently is.

    Every existing session for the OLD name is revoked (the same "a
    credential just changed, so re-login" posture set_principal_password
    already established), while runtime-side lockout/replay state
    (login_attempts, totp_used, recovery_used, enrolment_tokens,
    webauthn_challenges) moves WITH the name — best-effort, same posture as
    _revoke_sessions — so a rename cannot be used to quietly dodge a lockout
    or reopen a TOTP replay window. Outstanding action_grants are left to
    expire naturally (120s): a grant's hash is bound to the OLD name, so it
    could never be spent under the new one anyway.

    Refuses to rename yourself (a session is keyed by principal name, so
    renaming the account making this request would invalidate it
    mid-operation) and refuses a destination name that is already in use or
    that the tombstone remembers as a deleted account (see _is_tombstoned)."""
    validate_name(new, "user")
    if old == new:
        raise IAMError("that is already this user's name")
    if conn.execute("SELECT 1 FROM principals WHERE name=?", (old,)).fetchone() is None:
        raise IAMError(f"no user named {old!r}")
    if old == actor:
        raise IAMError("you cannot rename the account you are currently using — "
                       "have another admin do it, or sign in as someone else first")
    if conn.execute("SELECT 1 FROM principals WHERE name=?", (new,)).fetchone() is not None:
        raise IAMError(f"principal {new!r} already exists")
    if _is_tombstoned(new):
        raise IAMError(
            f"{new!r} was a real account here before and was permanently deleted — "
            f"renaming into it would let this account silently inherit old audit/run "
            f"history that still names it. Pick a name that was never used before.")
    busy = [_slot_unit(sl) for sl in _owner_slots(old)
            if subprocess.run(["systemctl", "is-active", "--quiet", _slot_unit(sl)],
                              check=False).returncode == 0]
    if busy:
        raise IAMError(f"{old!r} has a run in progress ({', '.join(busy)}) — their runs move "
                       f"with the rename, so stop them first, then try again.")
    conn.execute("UPDATE principals SET name=? WHERE name=?", (new, old))
    conn.execute("UPDATE api_keys SET principal=? WHERE principal=?", (new, old))
    conn.execute("UPDATE recovery_codes SET principal=? WHERE principal=?", (new, old))
    conn.execute("UPDATE passkeys SET principal=? WHERE principal=?", (new, old))
    for prefix in ("require-2fa", "limit:outputs-bytes-per-operator"):
        old_key, new_key = f"{prefix}:{old}", f"{prefix}:{new}"
        row = conn.execute("SELECT value FROM settings WHERE key=?", (old_key,)).fetchone()
        if row is not None:
            conn.execute("DELETE FROM settings WHERE key=?", (new_key,))
            conn.execute("UPDATE settings SET key=? WHERE key=?", (new_key, old_key))
    conn.commit()
    if runtime is not None:
        try:
            for table in ("login_attempts", "recovery_used", "totp_used",
                          "enrolment_tokens", "webauthn_challenges"):
                runtime.execute(f"UPDATE {table} SET principal=? WHERE principal=?", (new, old))
            runtime.commit()
        except sqlite3.Error:
            pass
    _drop_reset_links(runtime, old)
    _revoke_sessions(runtime, old)
    # The kept-outputs directory is named after the principal.
    old_dir = org_dir() / "outputs" / old
    new_dir = old_dir.parent / new
    if old_dir.is_dir() and not new_dir.exists():
        try:
            old_dir.rename(new_dir)
        except OSError:
            pass
    runs_moved = _rename_runs(old, new)
    _rename_user_files(old, new)
    _append_principal_history({"ts": time.time(), "event": "renamed",
                               "name": old, "new_name": new, "by": actor})
    return {"old": old, "new": new, "renamed": True, "run_slots_moved": runs_moved}


def delete_principal(conn, runtime, name: str, actor: str) -> dict:
    """Permanently removes a principal — every credential, binding,
    membership and per-principal settings override, genuinely gone — per
    the operator's own explicit choice (a disable-only convention was
    offered and declined in favor of "a genuine hard delete"). Deliberately
    NOT touched: audit logs, run history, team chat, reports and outputs —
    the record of what this person actually did stays exactly as it was
    recorded (§1 invariant 6). `_append_principal_history` leaves a
    tombstone so a display site can annotate a now-absent name as
    "(deleted)" instead of silently going quiet, and so the name itself
    cannot be reissued to someone else (see _is_tombstoned).

    Refuses to delete yourself, and refuses to delete the last active
    holder of admin — the one footgun that would leave nobody able
    to administer the platform at all."""
    if conn.execute("SELECT 1 FROM principals WHERE name=?", (name,)).fetchone() is None:
        raise IAMError(f"no user named {name!r}")
    if name == actor:
        raise IAMError("you cannot delete the account you are currently using — "
                       "have another admin do it, or sign in as someone else first")
    if _is_last_admin(conn, name):
        raise IAMError(
            f"{name!r} is the only active admin — deleting them would leave nobody able "
            f"to administer the platform. Give someone else admin first: "
            f"sudo agenti admin bind user <name> --role admin --resource {ORG_RESOURCE}")
    cred_ids = [r["credential_id"] for r in conn.execute(
        "SELECT credential_id FROM passkeys WHERE principal=?", (name,))]
    conn.execute("DELETE FROM api_keys WHERE principal=?", (name,))
    conn.execute("DELETE FROM recovery_codes WHERE principal=?", (name,))
    conn.execute("DELETE FROM passkeys WHERE principal=?", (name,))
    for prefix in ("require-2fa", "limit:outputs-bytes-per-operator"):
        conn.execute("DELETE FROM settings WHERE key=?", (f"{prefix}:{name}",))
    conn.execute("DELETE FROM principals WHERE name=?", (name,))
    conn.commit()
    if runtime is not None:
        try:
            for table in ("login_attempts", "recovery_used", "totp_used",
                          "enrolment_tokens", "webauthn_challenges", "action_grants",
                          "password_reset_tokens"):
                runtime.execute(f"DELETE FROM {table} WHERE principal=?", (name,))
            for cid in cred_ids:
                runtime.execute("DELETE FROM passkey_state WHERE credential_id=?", (cid,))
            runtime.commit()
        except sqlite3.Error:
            pass
    _revoke_sessions(runtime, name)
    # Their own API key is a credential: it goes with the account. (Memory is
    # kept, like reports: the name is tombstoned, so nobody inherits it.)
    try:
        (org_dir() / "users" / name / "secrets.env").unlink()
    except OSError:
        pass
    _append_principal_history({"ts": time.time(), "event": "deleted",
                               "name": name, "by": actor})
    return {"name": name, "deleted": True}


# ---------------------------------------------------------------------------
# Enrolment tokens — onboarding a new person without ever handing the API a
# password to set on their behalf (CLAUDE.md §4 step 6 phase 2).
#
# A freshly `add_principal()`-created account has no password and holds no
# permissions until an admin later runs `agenti admin bind` — see the plan's
# "authority rule". The token is what lets that NEW person, who by
# definition cannot prove any existing credential, set their own first
# password (and, optionally, enrol their own first 2FA factor) themselves,
# rather than an admin typing a temporary password and relaying it by some
# out-of-band channel this project has no opinion on.
#
# Hashed with hash_key() (plain SHA-256), not hash_password() (scrypt): a
# token is 256 random bits, never typed or memorised by a human trying to
# guess it — the same reasoning API keys already use. Single-use and
# short-lived (ENROLMENT_TOKEN_TTL_S) because unlike a password it grants
# access to an account outright, not merely a guess at one.
ENROLMENT_TOKEN_TTL_S = 48 * 3600  # two days: long enough to actually reach
                                   # someone, short enough that a forgotten
                                   # link is not a standing door


def _link_token() -> str:
    """A one-time link token (enrolment, password reset). Never starts with
    '-': it travels to the root CLI as a positional argument, and a token
    that looked like an option was refused, so about one link in 64 never
    worked (found during audit run 1)."""
    while True:
        t = secrets.token_urlsafe(32)
        if not t.startswith("-"):
            return t


def mint_enrolment_token(runtime, conn, principal: str, actor: str) -> str:
    """Returns the plaintext token (shown once, never stored). Only a hash of
    it is kept, in runtime.db — not iam.db — so minting one is something the
    API can do on an admin's behalf without ever writing the identity store,
    the same split that already lets it read permissions safely."""
    _refuse_if_enrolled(conn, principal)
    _refuse_web_link_for_admin(conn, principal, actor)
    token = _link_token()
    now = time.time()
    runtime.execute(
        "INSERT INTO enrolment_tokens(token_hash, principal, created_at, created_by, expires_at)"
        " VALUES (?,?,?,?,?)",
        (hash_key(token), principal, now, actor, now + ENROLMENT_TOKEN_TTL_S))
    runtime.commit()
    return token


def _refuse_web_link_for_admin(conn, principal: str, minted_by: str) -> None:
    """A link the web account minted on its own (no approval grant) never
    opens an admin account: whoever holds the link sets the first password,
    so the web tier alone would be choosing an admin's credentials (audit
    run 2, F08/F15 variant). Checked when minting and again when the link is
    used, in case the account became an admin in between. A new admin made
    from the web gets its link under the approving admin's name (create-user
    takes a grant), so that path is unaffected."""
    if minted_by != API_ACCOUNT:
        return
    row = conn.execute("SELECT role FROM principals WHERE name=?", (principal,)).fetchone()
    if row is not None and row["role"] == "admin":
        raise IAMError(f"REFUSING: {principal!r} is an admin, and a link for an admin cannot come from "
                       f"the web tier on its own. Issue it at the host's terminal: "
                       f"sudo agenti admin mint-enrolment-link {principal}")


def _refuse_if_enrolled(conn, principal: str) -> None:
    """An enrolment link is ONLY for an account that has never set a
    credential. Minting one for a principal that already has a password
    or a 2FA factor — and consuming it — would be a credential RESET, and
    `mint-enrolment-link` + `enrol-consume` are both reachable by the API
    service account (they have to be: the admin Users view mints links and
    the enrolment page consumes them). Without this check a compromised
    API could reset ANY principal's password and 2FA in two sudo calls,
    including the admin's — precisely the "grant or restore authority"
    the authority rule (CLAUDE.md §4 item 21) forbids the web tier. Found
    while designing the privileged-auth split (§4 item 23), not by the
    audit that shipped the feature. Resetting an enrolled account's
    credentials stays a root-only act: `user set-password` and
    `user reset-2fa`, both refused to the API."""
    row = conn.execute("SELECT password_hash, totp_secret, kind FROM principals WHERE name=?",
                       (principal,)).fetchone()
    if row is None:
        raise IAMError(f"no user named {principal!r}")
    if row["kind"] == "service":
        # A service account signs in with an API key, never a password; a link
        # for one would hand whoever holds it the account (and any role it
        # has) as a password login (audit run 1, F08).
        raise IAMError(f"{principal!r} is a service account: it uses an API key and never "
                       f"signs in with a password, so no enrolment link can be issued for it. "
                       f"Issue it a key on the host: sudo agenti admin issue-key --user {principal}")
    has_passkey = conn.execute("SELECT 1 FROM passkeys WHERE principal=? LIMIT 1",
                               (principal,)).fetchone()
    # An account that holds a live API key is in use: a link would add a
    # password login to authority it already exercises (audit run 2).
    has_key = conn.execute("SELECT 1 FROM api_keys WHERE principal=? AND revoked_at IS NULL"
                           " AND (expires_at IS NULL OR expires_at > ?) LIMIT 1",
                           (principal, time.time())).fetchone()
    if has_key and not (row["password_hash"] or row["totp_secret"] or has_passkey):
        raise IAMError(f"{principal!r} already signs in with an API key, so no enrolment link can be "
                       f"issued for it. Revoke the key first if a person should sign in instead: "
                       f"sudo agenti admin revoke-key <prefix>")
    if row["password_hash"] or row["totp_secret"] or has_passkey:
        raise IAMError(
            f"{principal!r} is already enrolled (it has a password and/or 2FA). An "
            f"enrolment link only sets up an account that has never had a credential. "
            f"To reset an existing account's credentials, an admin runs at a terminal: "
            f"sudo agenti admin user set-password {principal}  (and, for 2FA, "
            f"sudo agenti admin user reset-2fa {principal})")


def enrolment_token_principal(runtime, token: str) -> str | None:
    """Read-only: is this token valid right now, and for whom? The enrolment
    PAGE calls this before showing a password form, so a stale link says
    "this link has expired" instead of failing opaquely on submit."""
    row = runtime.execute(
        "SELECT principal, expires_at, used_at FROM enrolment_tokens WHERE token_hash=?",
        (hash_key(token),)).fetchone()
    if row is None or row["used_at"] is not None or row["expires_at"] < time.time():
        return None
    return row["principal"]


def consume_enrolment_token(conn, runtime, token: str, new_password: str,
                            totp_secret: str | None = None,
                            totp_code: str | None = None) -> tuple[str, list[str]]:
    """Set the initial password (and, optionally, the first 2FA factor) named
    by an enrolment token, then burn it. Returns (principal, recovery codes)
    — the codes are empty when no second factor was enrolled, and are the
    ONE-TIME display of them: until 2026-09-22 this function generated them
    and threw them away, so nobody who enrolled 2FA at sign-up ever saw
    theirs.

    The token is burned BEFORE the password write, not after: if the write
    somehow fails partway, a still-valid token silently retrying is worse
    than an enrolment that has to be reissued by an admin — the same
    fail-closed instinct as everything else that touches iam.db here."""
    row = runtime.execute(
        "SELECT principal, expires_at, used_at, created_by FROM enrolment_tokens WHERE token_hash=?",
        (hash_key(token),)).fetchone()
    if row is None or row["used_at"] is not None or row["expires_at"] < time.time():
        raise IAMError("this enrolment link is invalid or has expired. "
                       "Ask an admin to send a new one.")
    principal = row["principal"]
    _refuse_web_link_for_admin(conn, principal, row["created_by"])
    # Re-checked at CONSUME time too: a token minted while the account was
    # still blank must die the moment the account is enrolled by any other
    # path, or an outstanding link would be a reset waiting to happen.
    _refuse_if_enrolled(conn, principal)
    required, why = two_factor_required(conn, principal)
    if required and not (totp_secret and totp_code):
        raise IAMError(
            f"two-factor authentication is required for this account ({why}) — "
            f"set up an authenticator app in the same step. An admin can exempt "
            f"this one account at a terminal with: sudo agenti admin set-policy "
            f"{TWO_FACTOR_POLICY_KEY}:{principal} off")
    if totp_secret and totp_code and totp_verify(totp_secret, totp_code) is None:
        raise IAMError("that 2FA code is not valid for the secret you were given — "
                       "check your device's clock and try again")
    cur = runtime.execute("UPDATE enrolment_tokens SET used_at=? WHERE token_hash=? AND used_at IS NULL",
                          (time.time(), hash_key(token)))
    runtime.commit()
    if cur.rowcount != 1:            # another request used it a moment ago (audit run 2)
        raise IAMError("this enrolment link is invalid or has expired. "
                       "Ask an admin to send a new one.")
    set_principal_password(conn, principal, new_password, runtime=runtime)
    codes: list[str] = []
    if totp_secret and totp_code:
        codes = confirm_totp_enrolment(conn, principal, totp_secret, runtime)
    return principal, codes


MIN_PASSWORD_LENGTH = 8


def check_password_length(password: str) -> None:
    """Length only, no composition rules (§4 item 78). Every path that sets a
    password goes through set_principal_password, so the pages' own
    minlength is a convenience, not the check."""
    if len(password) < MIN_PASSWORD_LENGTH:
        raise IAMError(f"password must be at least {MIN_PASSWORD_LENGTH} characters. "
                       f"Nothing was changed.")


def set_principal_password(conn, name: str, password: str, *, must_change: bool = False,
                            runtime=None) -> int:
    """Returns the number of sessions revoked (0 if `runtime` is not given).

    A password change is exactly the remediation step after a suspected
    credential compromise — it must not leave an already-issued session (up
    to the 8h sliding TTL) usable by whoever had it. `revoke_all_for` existed
    in api/sessions.py and was correctly implemented but never called from
    here; found dead in the 2026-09-20 security audit (CLAUDE.md §4 item
    15). Deleting the rows directly rather than importing sessions.py: iam.py
    already owns the `sessions` table's schema (_RUNTIME_SCHEMA) and already
    reaches into other runtime.db tables it doesn't "own" the higher-level
    API for (totp_used, recovery_used, login_attempts) — sessions.py is a
    thin API-layer convenience wrapper over the same table, not a different
    authority."""
    check_password_length(password)
    if conn.execute(
            "UPDATE principals SET password_hash=?, password_set_at=?, must_change=? WHERE name=?",
            (hash_password(password), time.time(), 1 if must_change else 0, name)).rowcount == 0:
        raise IAMError(f"no user named {name!r}")
    conn.commit()
    _drop_reset_links(runtime, name)
    return _revoke_sessions(runtime, name)


def revoke_all_sessions(runtime) -> int:
    """Sign everyone out. Run by `agenti gui stop`: while the GUI's port is
    free a local process can take it and collect cookies, so no session may
    outlive the stop (audit run 2)."""
    n = runtime.execute("DELETE FROM sessions").rowcount
    runtime.commit()
    return n


def _revoke_sessions(runtime, name: str) -> int:
    if runtime is None:
        return 0
    try:
        n = runtime.execute("DELETE FROM sessions WHERE principal=?", (name,)).rowcount
        runtime.commit()
        return n
    except sqlite3.Error:
        return 0


def enroll_totp(conn, name: str, runtime=None) -> tuple[str, list[str]]:
    """Root break-glass / interactive path: generate a fresh TOTP secret and
    commit it IMMEDIATELY (no confirmation step — the operator running this
    at a terminal is expected to test it themselves). Returns (secret,
    plaintext recovery codes) for a ONE-TIME display; only hashes are stored.

    The self-service web path (shared/agenti's `self mfa-start`/`mfa-confirm`)
    deliberately does NOT use this function directly — see
    confirm_totp_enrolment()'s docstring for why an unconfirmed commit is a
    real footgun for someone with no CLI fallback."""
    if conn.execute("SELECT 1 FROM principals WHERE name=?", (name,)).fetchone() is None:
        raise IAMError(f"no user named {name!r}")
    secret = totp_generate_secret()
    codes = confirm_totp_enrolment(conn, name, secret, runtime)
    return secret, codes


def confirm_totp_enrolment(conn, name: str, secret: str, runtime=None) -> list[str]:
    """Commit an ALREADY-VERIFIED secret. Same replace-not-append semantics
    and runtime cleanup as enroll_totp() (they share this code), but the
    secret is supplied by the caller rather than generated here.

    Why this split exists: root's `enroll-2fa` commits in one round trip
    because a terminal operator can immediately test the result and re-run
    it if it's wrong. The web self-service path cannot assume that — a
    browser user who mistypes the secret or has clock drift would be left
    with a totp_secret in the database that they cannot actually produce a
    code for, which is a self-inflicted lockout with no CLI to fall back to.
    So the web path is two calls: `self mfa-start` generates a candidate
    secret and writes NOTHING, the browser's authenticator app produces a
    code from it, and only `self mfa-confirm` — after checking that code is
    actually valid for that secret — calls this function to make it real.
    Nothing about the secret needs to be remembered server-side between the
    two calls: proving the CURRENT password (and current 2FA code, if one is
    already enrolled) is required again at confirm time, so skipping straight
    to a self-chosen secret at confirm time would need exactly the same proof
    anyway — there is nothing to gain by attacking the gap between them."""
    if conn.execute("SELECT 1 FROM principals WHERE name=?", (name,)).fetchone() is None:
        raise IAMError(f"no user named {name!r}")
    codes = generate_recovery_codes()
    conn.execute("UPDATE principals SET totp_secret=?, totp_enrolled_at=? WHERE name=?",
                 (secret, time.time(), name))
    conn.execute("DELETE FROM recovery_codes WHERE principal=?", (name,))
    conn.executemany("INSERT INTO recovery_codes(principal, code_hash) VALUES (?,?)",
                     [(name, hash_password(c)) for c in codes])
    conn.commit()
    _clear_second_factor_runtime_state(runtime, name)
    return codes


def _clear_second_factor_runtime_state(runtime, name: str) -> None:
    """Drop the replay records and burned-recovery-code markers for a principal.

    Called whenever the second factor is REPLACED or CLEARED. Those records are
    keyed by time-step counter and recovery-code rowid, both of which belong to
    the secret and the code set that just ceased to exist — keeping them causes
    a real false rejection: re-enrol, and your very first code is refused as
    "already used" if you happened to authenticate inside the same 30-second
    window with the old device. Found by the test suite, not in production."""
    if runtime is None:
        return
    try:
        runtime.execute("DELETE FROM totp_used WHERE principal=?", (name,))
        runtime.execute("DELETE FROM recovery_used WHERE principal=?", (name,))
        runtime.commit()
    except sqlite3.Error:
        pass
    # Same reasoning as set_principal_password's _revoke_sessions call: the
    # second factor just changed, so a session established under the old one
    # (or established before 2FA existed at all) should not survive it.
    _revoke_sessions(runtime, name)


def reset_totp(conn, name: str, runtime=None) -> None:
    """Root break-glass: the operator lost their device and every recovery code.
    Clears 2FA entirely, so the next login is password-only until re-enrolment."""
    if conn.execute("UPDATE principals SET totp_secret=NULL, totp_enrolled_at=NULL"
                    " WHERE name=?", (name,)).rowcount == 0:
        raise IAMError(f"no user named {name!r}")
    conn.execute("DELETE FROM recovery_codes WHERE principal=?", (name,))
    conn.commit()
    _clear_second_factor_runtime_state(runtime, name)


# ---------------------------------------------------------------------------
# Resetting a DIFFERENT principal's password or MFA from the GUI (the
# operator's own explicit request, made after the authority rule (§4 item
# 21) had held this CLI-only for years — see reset_principal_password's own
# docstring for why revisiting it now is safe). Two genuinely separate jobs,
# on purpose ("I want the resetting password job and resetting MFA job to be
# separate tasks"): resetting one never touches the other, and each is its
# own grant-gated action (see web_reset_principal_password /
# web_reset_principal_mfa) so approving one never silently approves both.
# Both are admin only, through the GUI: resetting someone else's credentials
# is restoring authority, so each needs the admin's own fresh re-authentication.
# ---------------------------------------------------------------------------
PASSWORD_RESET_TOKEN_TTL_S = 24 * 3600  # a day: long enough to actually reach
                                        # someone, short enough that a
                                        # forgotten link isn't a standing door
                                        # into an already-active account


def reset_principal_password(conn, runtime, name: str, new_password: str, actor: str) -> dict:
    """Administratively sets a DIFFERENT principal's password directly.
    Unlike every other web-reachable action this genuinely RESTORES
    authority over the target account — the admin performing it (or anyone
    they tell) can now sign in as that person — which is exactly why it is
    reachable ONLY through the grant-gated path (see
    web_reset_principal_password): getting here already required the
    requesting admin to prove their own password and a fresh 2FA code (or a
    passkey), with the grant bound to this EXACT new password value, so a
    compromised web tier cannot substitute a different one than what the
    admin approved.

    Revokes every existing session for the account — the same "a credential
    just changed, log back in" posture set_principal_password already has —
    and records the reset in user-history so it is visible who did it
    and when, never silently."""
    if conn.execute("SELECT 1 FROM principals WHERE name=?", (name,)).fetchone() is None:
        raise IAMError(f"no user named {name!r}")
    n = set_principal_password(conn, name, new_password, must_change=True, runtime=runtime)
    _append_principal_history({"ts": time.time(), "event": "password-reset",
                               "name": name, "by": actor})
    return {"principal": name, "password_reset": True, "sessions_revoked": n}


def mint_password_reset_link(runtime, conn, principal: str, actor: str) -> str:
    """The admin-initiated counterpart to mint_enrolment_token(), which
    REFUSES this exact case (_refuse_if_enrolled) specifically because it is
    reachable by the API with no re-authentication beyond an ordinary
    session. This path is different on the one point that matters: it is
    only ever mintable through the grant-gated reset-password action, so
    reaching here already required the requesting admin to prove their own
    password and a fresh 2FA code (or a passkey) — exactly the human-
    presence proof _refuse_if_enrolled's own comment says an unauthenticated
    mint lacks. Resets ONLY the password when consumed, deliberately never
    2FA — see reset_principal_mfa for that — and the admin never learns the
    value the target ends up choosing."""
    if conn.execute("SELECT 1 FROM principals WHERE name=?", (principal,)).fetchone() is None:
        raise IAMError(f"no user named {principal!r}")
    token = _link_token()
    now = time.time()
    _drop_reset_links(runtime, principal)       # a new link replaces any older one
    runtime.execute(
        "INSERT INTO password_reset_tokens(token_hash, principal, created_at, created_by, expires_at)"
        " VALUES (?,?,?,?,?)",
        (hash_key(token), principal, now, actor, now + PASSWORD_RESET_TOKEN_TTL_S))
    runtime.commit()
    _append_principal_history({"ts": time.time(), "event": "password-reset-link",
                               "name": principal, "by": actor})
    return token


def _drop_reset_links(runtime, principal: str) -> None:
    """Every unused reset link for this name stops working: on a new link, a
    password change, a rename and a delete (audit run 1, F19: a link keyed by
    name alone outlived a rename and reset whoever took the name next)."""
    if runtime is None:
        return
    try:
        runtime.execute("DELETE FROM password_reset_tokens WHERE principal=? AND used_at IS NULL",
                        (principal,))
        runtime.commit()
    except sqlite3.Error:
        pass


def _reset_link_row(conn, runtime, token: str):
    """The token's row if it is unused, unexpired and still belongs to the
    account it was made for: one created before the link and whose password
    has not changed since. Else None."""
    row = runtime.execute(
        "SELECT principal, created_at, expires_at, used_at FROM password_reset_tokens"
        " WHERE token_hash=?", (hash_key(token),)).fetchone()
    if row is None or row["used_at"] is not None or row["expires_at"] < time.time():
        return None
    acct = conn.execute("SELECT created_at, password_set_at FROM principals WHERE name=?",
                        (row["principal"],)).fetchone()
    if acct is None or acct["created_at"] > row["created_at"] \
            or (acct["password_set_at"] or 0) > row["created_at"]:
        return None
    return row


def password_reset_token_principal(conn, runtime, token: str) -> str | None:
    """Read-only: is this token valid right now, and for whom? The reset
    page calls this before showing a password form, mirroring
    enrolment_token_principal exactly."""
    row = _reset_link_row(conn, runtime, token)
    return row["principal"] if row else None


def consume_password_reset_token(conn, runtime, token: str, new_password: str) -> str:
    """Set a new password using a one-time reset token, then burn it — the
    target account's OWN action, no existing credential required, the same
    "burn before write" fail-closed order consume_enrolment_token already
    uses. Never touches 2FA/passkeys, on purpose — a password reset link is
    exactly that, nothing more."""
    row = _reset_link_row(conn, runtime, token)
    if row is None:
        raise IAMError("this password reset link is invalid, has expired, or was replaced "
                       "(a newer link, a password change or a rename ends it). "
                       "Ask an admin to send a new one.")
    principal = row["principal"]
    cur = runtime.execute("UPDATE password_reset_tokens SET used_at=? WHERE token_hash=? AND used_at IS NULL",
                          (time.time(), hash_key(token)))
    runtime.commit()
    if cur.rowcount != 1:            # another request used it a moment ago (audit run 2)
        raise IAMError("this password reset link has already been used. Ask an admin to send a new one.")
    set_principal_password(conn, principal, new_password, runtime=runtime)
    return principal


def reset_principal_mfa(conn, runtime, name: str, actor: str) -> dict:
    """Administratively clears EVERY second factor — TOTP and every passkey
    — for a DIFFERENT principal, as one combined action deliberately kept
    separate from reset_principal_password above (the operator's own
    explicit ask: two independent admin jobs, never bundled). If the
    require-2fa policy applies to this account, its very next login is
    confined to re-registering a factor (rbac.py's mfa_setup_required gate)
    — the same mechanism a fresh sign-up already goes through, applied here
    to an account whose factor was lost or compromised rather than one that
    never had one."""
    if conn.execute("SELECT 1 FROM principals WHERE name=?", (name,)).fetchone() is None:
        raise IAMError(f"no user named {name!r}")
    reset_totp(conn, name, runtime=runtime)
    n_keys = reset_passkeys(conn, runtime, name)
    _append_principal_history({"ts": time.time(), "event": "mfa-reset",
                               "name": name, "by": actor})
    return {"principal": name, "mfa_reset": True, "passkeys_removed": n_keys}


def web_reset_principal_password(conn, runtime, name: str, resource: str, grant_id: str,
                                 new_password: str) -> dict:
    """The web-reachable form of reset_principal_password() — same grant-
    and-re-check shape as web_rename_principal(). The grant is bound to the
    exact new_password value (see op_approve_action's action dict), so a
    compromised web tier cannot show the admin one password and set a
    different one."""
    action = {"op": "reset-password", "principal": name, "resource": resource,
              "mode": "direct", "new_password": new_password}
    approver = consume_action_grant(runtime, grant_id, action)
    if not check(conn, approver, "iam:manage", resource).allowed:
        raise IAMError(f"{approver!r} approved this but does not hold iam:manage on "
                       f"{resource} — refusing. Nothing was changed.")
    return {**reset_principal_password(conn, runtime, name, new_password, approver),
            "approved_by": approver}


def web_mint_password_reset_link(conn, runtime, name: str, resource: str, grant_id: str) -> dict:
    """The web-reachable "send a link instead" mode — same grant-and-
    re-check shape as web_reset_principal_password() above, but the grant
    carries no password value at all (mode='link'): nobody but the target
    ever learns what they set it to."""
    action = {"op": "reset-password", "principal": name, "resource": resource, "mode": "link"}
    approver = consume_action_grant(runtime, grant_id, action)
    if not check(conn, approver, "iam:manage", resource).allowed:
        raise IAMError(f"{approver!r} approved this but does not hold iam:manage on "
                       f"{resource} — refusing. Nothing was changed.")
    token = mint_password_reset_link(runtime, conn, name, approver)
    return {"principal": name, "reset_token": token, "approved_by": approver}


def web_reset_principal_mfa(conn, runtime, name: str, resource: str, grant_id: str) -> dict:
    """The web-reachable form of reset_principal_mfa() — same grant-and-
    re-check shape as the two functions above."""
    action = {"op": "reset-mfa", "principal": name, "resource": resource}
    approver = consume_action_grant(runtime, grant_id, action)
    if not check(conn, approver, "iam:manage", resource).allowed:
        raise IAMError(f"{approver!r} approved this but does not hold iam:manage on "
                       f"{resource} — refusing. Nothing was changed.")
    return {**reset_principal_mfa(conn, runtime, name, approver), "approved_by": approver}


# Kept outputs have a two-level quota: one for the whole organisation's store
# and one per operator. It reuses the set-limit/LIMIT_KEYS mechanism — a
# limit, never a permission — which is the one identity-store write the API
# may make.
OUTPUTS_DEFAULT_TOTAL_BYTES = 5 * 1024 ** 3       # 5GB
OUTPUTS_DEFAULT_OPERATOR_BYTES = 1 * 1024 ** 3    # 1GB
OUTPUTS_WARN_FRACTION = 0.9

LIMIT_KEYS = ("outputs-bytes-total", "outputs-bytes-per-operator")

# What a ":<principal>" suffix on each key names (None: the key takes no
# suffix), the built-in fallback, and the sane upper bound on a stored value.
_LIMIT_SCOPE = {
    "outputs-bytes-total": None,
    "outputs-bytes-per-operator": "principal",
}
_LIMIT_DEFAULT = {
    "outputs-bytes-total": OUTPUTS_DEFAULT_TOTAL_BYTES,
    "outputs-bytes-per-operator": OUTPUTS_DEFAULT_OPERATOR_BYTES,
}
_LIMIT_MAX = {
    "outputs-bytes-total": 10 * 1024 ** 4,     # 10TB: a sanity ceiling, not a design target
    "outputs-bytes-per-operator": 10 * 1024 ** 4,
}


def _limit_lookup(conn, base: str, who: str | None) -> int:
    """Per-principal override, else the platform default, else the built-in
    default. A malformed stored value falls back rather than crashing every
    check — a limit is housekeeping, not a security boundary."""
    keys = ([f"limit:{base}:{who}"] if who else []) + [f"limit:{base}"]
    for key in keys:
        raw = get_setting(conn, key, "")
        if raw:
            try:
                return max(0, int(raw))
            except ValueError:
                continue
    return _LIMIT_DEFAULT[base]


def outputs_limit_total(conn) -> int:
    return _limit_lookup(conn, "outputs-bytes-total", None)


def outputs_limit_operator(conn, principal: str) -> int:
    return _limit_lookup(conn, "outputs-bytes-per-operator", principal)


def _dir_size(path: Path) -> int:
    """Total bytes of every regular file under `path`. Missing/unreadable
    entries are skipped rather than raising — usage accounting must never
    itself be the reason a promotion or a status check fails."""
    total = 0
    try:
        entries = path.rglob("*")
    except OSError:
        return 0
    for p in entries:
        try:
            if p.is_file():
                total += p.stat().st_size
        except OSError:
            continue
    return total


def _outputs_root() -> Path:
    return org_dir() / "outputs"


def outputs_usage_total() -> int:
    """Every byte in the permanent Outputs store, across every operator — the
    number the TOTAL quota is checked against."""
    return _dir_size(_outputs_root())


def outputs_usage_operator(principal: str) -> int:
    """One operator's own share of the store — the number the OPERATOR quota
    is checked against. Always <= outputs_usage_total()."""
    return _dir_size(_outputs_root() / principal)


def outputs_check(conn, principal: str, *, incoming_bytes: int = 0) -> dict:
    """The whole may-this-promotion-happen gate, in one place, so the API and
    the CLI answer it identically. Two INDEPENDENT quotas; a promotion is
    refused if EITHER is full, and the reason names WHICH one. `incoming_bytes`
    lets a caller ask "would promoting N more bytes still fit" before
    actually copying anything, rather than after."""
    total_limit = outputs_limit_total(conn)
    operator_limit = outputs_limit_operator(conn, principal)
    total_used = outputs_usage_total()
    operator_used = outputs_usage_operator(principal)
    allowed, reason = True, "ok"
    if total_used + incoming_bytes > total_limit:
        allowed, reason = False, (
            f"the organisation's kept-outputs store is full "
            f"({total_used:,}/{total_limit:,} bytes). An admin can raise it: "
            f"sudo agenti admin set-limit outputs-bytes-total N")
    elif operator_used + incoming_bytes > operator_limit:
        allowed, reason = False, (
            f"the OPERATOR outputs quota for {principal!r} is full "
            f"({operator_used:,}/{operator_limit:,} bytes). Delete an old output, or "
            f"ask an admin to raise it: sudo agenti admin set-limit "
            f"outputs-bytes-per-operator:{principal} N")
    warnings = []
    if total_used >= total_limit * OUTPUTS_WARN_FRACTION:
        warnings.append({"scope": "total", "message":
                         f"the kept-outputs store is nearing its limit "
                         f"({total_used:,}/{total_limit:,} bytes) — an admin should be warned"})
    if operator_used >= operator_limit * OUTPUTS_WARN_FRACTION:
        warnings.append({"scope": "operator", "message":
                         f"the operator outputs quota for {principal!r} is nearing its limit "
                         f"({operator_used:,}/{operator_limit:,} bytes)"})
    return {"principal": principal, "allowed": allowed, "reason": reason,
            "total_used": total_used, "total_limit": total_limit,
            "operator_used": operator_used, "operator_limit": operator_limit,
            "warnings": warnings}


def list_outputs(principal: str | None = None) -> list[dict]:
    """Every kept output in the permanent store, newest first. `principal=None`
    (an admin's view) lists every operator's; otherwise only that operator's
    own."""
    root = _outputs_root()
    out: list[dict] = []
    try:
        owners = [d for d in root.iterdir() if d.is_dir()]
    except OSError:
        return out
    for owner_dir in owners:
        if principal is not None and owner_dir.name != principal:
            continue
        for f in owner_dir.iterdir():
            if not f.is_file():
                continue
            try:
                st = f.stat()
            except OSError:
                continue
            out.append({"principal": owner_dir.name, "name": f.name,
                       "bytes": st.st_size, "promoted_at": st.st_mtime})
    out.sort(key=lambda r: r["promoted_at"], reverse=True)
    return out


def resolve_output_path(principal: str, name: str, by: str, conn=None) -> Path:
    """Validate and resolve ONE kept output's path, WITHOUT touching it — the
    read half of what delete_output() needs before it unlinks, split out so a
    download route reuses the exact same checks a delete already enforces: the
    name is validated, the resolved path must be a DIRECT child of
    `outputs/<principal>/` (no traversal, no symlink games), and only the
    operator whose own output this is, or an admin allowed to open their
    dashboard, may even learn its real path. `conn`, if given, is used for the
    dashboard-access check — a bare filesystem lookup like this otherwise has
    no reason to open the identity store at all."""
    validate_name(principal, "user")
    owner_dir = (_outputs_root() / principal).resolve()
    target = _outputs_root() / principal / name
    if not target.is_file():
        raise IAMError(f"no output named {name!r} for {principal!r}")
    if target.resolve().parent != owner_dir:
        raise IAMError(f"refusing: {target} does not resolve to a direct child of {owner_dir}")
    if by != principal and not (conn is not None and dashboard_access(conn, by, principal)["allowed"]):
        raise IAMError(f"{name!r} belongs to {principal!r}; only they, or an admin allowed to "
                       f"open their dashboard, may access it")
    return target.resolve()


def _append_outputs_history(row: dict) -> None:
    """org/outputs-history.jsonl: who deleted what, when — the output file
    itself is gone (deleting it IS the point), so this is the only record of
    the act, not of the content. Root-owned like every other audit trail here;
    nothing but an admin CLI reads it. Best-effort on the chmod: a failure to
    tighten permissions on a freshly created file must never turn a real
    deletion (already committed by the time this runs) into a reported
    failure."""
    path = org_dir() / "outputs-history.jsonl"
    try:
        existed = path.exists()
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
        if not existed:
            os.chmod(path, 0o640)
    except OSError:
        pass


def delete_output(principal: str, name: str, by: str, conn=None) -> dict:
    """Remove ONE kept output. Deliberately narrow: see resolve_output_path()
    for the validation this shares with the (read-only) outputs-path lookup.
    The file itself is the user's own permanent artifact and deleting it is
    the whole point, so it is genuinely gone afterward —
    _append_outputs_history keeps only the record of WHO deleted WHAT and
    WHEN, not the content."""
    target = resolve_output_path(principal, name, by, conn=conn)
    size = target.stat().st_size
    target.unlink()
    _append_outputs_history({"ts": time.time(), "name": name,
                             "principal": principal, "bytes": size, "deleted_by": by})
    return {"principal": principal, "name": name, "deleted": True, "by": by}


def delete_outputs(principal: str, names: list[str], by: str, conn=None) -> list[dict]:
    """Bulk form of delete_output() (the Outputs page's multi-select). Each
    name is resolved and deleted INDEPENDENTLY — one bad name (already gone,
    wrong owner, a traversal attempt) is reported and skipped rather than
    aborting the whole batch."""
    out = []
    for name in names:
        try:
            out.append(delete_output(principal, name, by, conn=conn))
        except IAMError as e:
            out.append({"principal": principal, "name": name, "deleted": False, "error": str(e)})
    return out


# ---------------------------------------------------------------------------
# Tool requests: "a tool the library lacks is a request, not a button: the GUI
# files it, a human reviews and adds it, then deploys." There is no
# notifications channel yet, so this is deliberately just a durable,
# admin-readable queue — filing needs only agent:read, listing is admin-only
# (iam:read), and there is no "approve" verb: acting on a request means a
# developer writing and reviewing real code, or an admin running an install
# at the server, which stays outside this system on purpose.
#
# Stored outside the vault — readable even with the vault locked, and no more
# sensitive than a request's own free-text description.
# ---------------------------------------------------------------------------
TOOL_REQUESTS_PATH = Path(os.environ.get("AGENTI_TOOL_REQUESTS_PATH",
                                         "/var/lib/agenti/tool-requests.jsonl"))
TOOL_REQUEST_MAX_CHARS = 2000


def _validate_tool_request_text(value: str) -> str:
    value = (value or "").strip()
    if not value:
        raise IAMError("a tool request needs some text describing what's missing")
    if len(value) > TOOL_REQUEST_MAX_CHARS:
        raise IAMError(f"tool request text is {len(value)} characters; keep it to "
                       f"{TOOL_REQUEST_MAX_CHARS} or fewer")
    if "\x00" in value:
        raise IAMError("tool request text may not contain a NUL byte")
    return value


def file_tool_request(principal: str, category: str, text: str) -> dict:
    """Append one request. `category` is free text too (the operator may be
    asking for something that doesn't exist at all) — it is NEVER checked
    against the tool registry, because the entire point is to name something
    that isn't there yet."""
    text = _validate_tool_request_text(text)
    category = (category or "").strip()[:64]
    row = {"id": uuid.uuid4().hex, "by": principal,
          "category": category, "text": text, "created_at": time.time()}
    TOOL_REQUESTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(TOOL_REQUESTS_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(row) + "\n")
    try:
        TOOL_REQUESTS_PATH.chmod(0o640)
    except OSError:
        pass
    return row


def list_tool_requests() -> list[dict]:
    """Every filed request, newest first — an admin's queue to triage. A
    malformed line is skipped rather than failing the whole listing, the same
    tolerance shared/state.py's own JSONL readers already apply."""
    if not TOOL_REQUESTS_PATH.is_file():
        return []
    out: list[dict] = []
    with open(TOOL_REQUESTS_PATH, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except ValueError:
                continue
    out.sort(key=lambda r: r.get("created_at", 0), reverse=True)
    return out


def set_limit(conn, key: str, value: int | None) -> str:
    """`key` is one of LIMIT_KEYS, optionally suffixed `:<principal>` where the
    key allows one (see _LIMIT_SCOPE) for a per-person override. Returns the
    stored settings key. This is the one settings write the API may invoke
    (see shared/agenti's IAM_WRITE_VERBS comment): a LIMIT, never a
    permission.

    `value=None` means "back to the default": an override row is DELETED so
    that person follows the platform value again, and the platform row is
    deleted so it falls back to the built-in default. Without this, an
    override could only ever be overwritten, never removed — a stale row that
    silently stopped tracking the platform default the moment an admin changed
    it."""
    base, _, who = key.partition(":")
    if base not in LIMIT_KEYS:
        raise IAMError(f"unknown limit {key!r}. Known: {', '.join(LIMIT_KEYS)} "
                       f"(outputs-bytes-per-operator takes a :<user> suffix for one person)")
    if who:
        scope = _LIMIT_SCOPE[base]
        if scope is None:
            raise IAMError(f"{base!r} is organisation-wide and takes no :<name> suffix")
        validate_name(who, scope)
        if conn.execute("SELECT 1 FROM principals WHERE name=?", (who,)).fetchone() is None:
            raise IAMError(f"no user named {who!r}")
    stored = f"limit:{base}" + (f":{who}" if who else "")
    if value is None:
        conn.execute("DELETE FROM settings WHERE key = ?", (stored,))
        conn.commit()
        return stored
    ceiling = _LIMIT_MAX[base]
    if not 0 <= value <= ceiling:
        raise IAMError(f"a value for {base!r} must be between 0 and {ceiling}")
    set_setting(conn, stored, str(value))
    return stored


def limit_value(text: str) -> int | None:
    """argparse type for set-limit: an integer, or the word 'default' to
    remove the row (see set_limit)."""
    import argparse
    if text == "default":
        return None
    try:
        return int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"{text!r} is not a whole number or the word 'default'")




# ---------------------------------------------------------------------------
# Bounded role grants from the web
#
# The "authority rule" (§4 item 21) says the web tier may never GRANT
# authority; this is the one bounded exception. Each grant is gated by a
# fresh re-authentication of the APPROVING admin, performed by agenti-authd,
# which mints a single-use, short-lived grant bound by hash to the exact
# action; the root CLI's `web-bind` consumes it from runtime.db (which the API
# cannot write) and takes the approver from the grant row, never from the API.
#
# Why each role is safe to grant this way:
#   operator — a compromised API already holds operator-level authority
#     through its sudo grant, so this hands it nothing new.
#   admin — web_bind() re-checks, fresh, that the approver holds iam:manage:
#     delegation within authority already held, never an escalation past it.
#     Only an existing admin can mint another; that widening was put to the
#     operator explicitly before it was allowed.
# What re-auth cannot defeat is request substitution (the API is the request
# path, so it could show one action and send another); the per-role bounds
# above are what limit the damage of that.
# ---------------------------------------------------------------------------
WEB_GRANTABLE_ROLES = ("operator", "admin")
ACTION_GRANT_TTL_S = 120

# There is no grace window: every admin action is its own re-authentication
# (operator decision 2026-10-23, audit run 2). The earlier 60 s ticket let a
# hijacked session ride a recent check without any credential.

# Web-grant re-authentication: every grant needs the approver's password AND
# a fresh 2FA code (or a passkey, which proves both on its own). The operator
# asked for one universal popup with both fields everywhere (2026-10-04), so
# a field the popup shows is a field the server checks — the earlier
# code-only rule for viewer/operator/kit grants (§4 items 56/65) is retired.
def web_grant_requires_password(role: str) -> bool:
    """Every role assignment requires password + 2FA (or a passkey)."""
    return role in WEB_GRANTABLE_ROLES


def web_grant_resource(role: str, resource: str) -> str:
    """Validate a web grant's role and resource."""
    if role not in WEB_GRANTABLE_ROLES:
        raise IAMError(f"the web tier may set only {' or '.join(WEB_GRANTABLE_ROLES)}, not "
                       f"{role!r}. Use the CLI: sudo agenti admin bind user <name> --role {role}")
    if resource != ORG_RESOURCE:
        raise IAMError(f"resource must be {ORG_RESOURCE!r}, not {resource!r}")
    return resource


def action_hash(action: dict) -> str:
    """What a grant is bound to. A password inside the action (an admin
    setting someone's password directly) goes in only as a slow scrypt
    derivation, never under the fast SHA-256 of the whole action: the grant row
    sits in runtime.db, and a fast hash of a chosen password is cheap to crack
    (CodeQL py/weak-sensitive-data-hashing, triaged in audit run 1)."""
    material = dict(action)
    if material.get("new_password"):
        material["new_password"] = hashlib.scrypt(
            material["new_password"].encode(), salt=f"agenti-grant:{material.get('principal', '')}".encode(),
            n=2 ** 14, r=8, p=1, maxmem=_SCRYPT_MAXMEM, dklen=32).hex()
    return hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def mint_action_grant(runtime, principal: str, action: dict) -> str:
    """Called by agenti-authd AFTER it has re-verified `principal`'s password
    and second factor. Returns the grant id (random, shown to the API once).
    The grant is bound to the action's hash, so the API can carry it but
    cannot spend it on anything else."""
    gid = secrets.token_urlsafe(24)
    now = time.time()
    runtime.execute(
        "INSERT INTO action_grants(id, principal, action_hash, created_at, expires_at)"
        " VALUES (?,?,?,?,?)", (gid, principal, action_hash(action), now, now + ACTION_GRANT_TTL_S))
    runtime.execute("DELETE FROM action_grants WHERE expires_at < ?", (now - 3600,))
    runtime.commit()
    return gid


# A passkey standing in for password + 2FA in ANY re-authentication popup.
# agenti-authd verifies the passkey assertion against the session's own
# principal, then mints this single-use, short-lived token in runtime.db (the
# API cannot write it). Whatever action the popup then performs presents the
# token instead of a password and code; the consumer passes the principal it
# is acting for, so a token for one account can never approve another's.
def _reauth_action(principal: str) -> dict:
    return {"op": "reauth", "principal": principal}


def _self_reauth(conn, runtime, a) -> None:
    """The `self` verbs' proof of presence: a passkey token if one was given,
    otherwise the current password (and 2FA code, once enrolled)."""
    if getattr(a, "reauth", ""):
        consume_reauth_token(runtime, a.reauth, a.name)
    else:
        reauthenticate_self(conn, runtime, a.name, a.current, a.totp, addr=a.addr)


def mint_reauth_token(runtime, principal: str) -> str:
    return mint_action_grant(runtime, principal, _reauth_action(principal))


def consume_reauth_token(runtime, token: str, principal: str) -> None:
    """Raises IAMError unless `token` is an unspent, unexpired passkey
    re-authentication for exactly `principal`."""
    if not isinstance(token, str) or not token:
        raise IAMError("no passkey confirmation was given")
    consume_action_grant(runtime, token, _reauth_action(principal))


def consume_action_grant(runtime, grant_id: str, action: dict) -> str:
    """Burn a grant and return the principal who approved it. Single use,
    time-limited, and refused outright if the action being performed is not
    the action that was approved — which is the check that turns a captured
    grant into nothing."""
    row = runtime.execute("SELECT principal, action_hash, expires_at, used_at FROM action_grants"
                          " WHERE id=?", (grant_id,)).fetchone()
    if row is None:
        raise IAMError("no such approval grant — the re-authentication step did not complete, "
                       "or the grant was already used. Re-enter your password and 2FA code "
                       "and try the action again.")
    if row["used_at"] is not None:
        raise IAMError("this approval grant was already used. Each re-authentication approves "
                       "exactly one action; re-enter your password and 2FA code to do another.")
    if row["expires_at"] < time.time():
        raise IAMError(f"this approval grant has expired (they last {ACTION_GRANT_TTL_S}s). "
                       f"Re-enter your password and 2FA code and try again.")
    if not secrets.compare_digest(row["action_hash"], action_hash(action)):
        raise IAMError("the approved action does not match the action requested — REFUSING, "
                       "and nothing was changed. What was shown for approval and what was "
                       "sent to the server differ; if you did not change anything between "
                       "the two, treat the web tier as compromised and use the CLI.")
    # Spent: the binding is no longer needed, so it is not kept. The WRITE
    # decides the burn: of two requests spending one grant at once, only the
    # one whose update changes the row goes on (audit run 2).
    cur = runtime.execute("UPDATE action_grants SET used_at=?, action_hash='' WHERE id=?"
                          " AND used_at IS NULL AND action_hash=?",
                          (time.time(), grant_id, row["action_hash"]))
    runtime.commit()
    if cur.rowcount != 1:
        raise IAMError("this approval grant was already used. Each re-authentication approves "
                       "exactly one action; re-enter your password and 2FA code to do another.")
    return row["principal"]


def web_bind(conn, runtime, principal: str, role: str, resource: str, grant_id: str) -> dict:
    """Set a user's role via a re-authenticated, single-use action grant.

    Every check runs as root in the CLI against stores the API cannot write,
    so the API's own claims are irrelevant to the outcome: the role must be
    one of WEB_GRANTABLE_ROLES, the resource the organisation, the grant
    genuine and unspent and for THIS exact action, and the approver it names
    must actually hold iam:manage — checked fresh, not trusted from the grant.
    """
    if role not in WEB_GRANTABLE_ROLES:
        raise IAMError(f"the web tier may set only {' or '.join(WEB_GRANTABLE_ROLES)}, not "
                       f"{role!r}. Use the CLI: sudo agenti admin bind user {principal} "
                       f"--role {role}")
    if resource != ORG_RESOURCE:
        raise IAMError(f"resource must be {ORG_RESOURCE!r}, not {resource!r}")
    validate_name(principal, "user")
    if conn.execute("SELECT 1 FROM principals WHERE name=?", (principal,)).fetchone() is None:
        raise IAMError(f"no user named {principal!r}")
    action = {"op": "bind", "principal": principal, "role": role, "resource": resource}
    approver = consume_action_grant(runtime, grant_id, action)
    if not check(conn, approver, "iam:manage", resource).allowed:
        raise IAMError(f"{approver!r} approved this but does not hold iam:manage on {resource} — "
                       f"refusing. Nothing was changed.")
    set_principal_role(conn, principal, role, approver)
    return {"principal": principal, "role": role, "resource": resource,
            "effect": "allow", "approved_by": approver}


def web_unbind(conn, principal: str, role: str, resource: str) -> dict:
    """Demote a user to operator. Removing authority is fail-safe so no
    re-auth grant is needed — but the same bounds apply."""
    if role not in WEB_GRANTABLE_ROLES:
        raise IAMError(f"the web tier may change only {' or '.join(WEB_GRANTABLE_ROLES)}, not "
                       f"{role!r}. Use the CLI: sudo agenti admin bind user {principal} "
                       f"--role operator")
    if resource != ORG_RESOURCE:
        raise IAMError(f"resource must be {ORG_RESOURCE!r}, not {resource!r}")
    validate_name(principal, "user")
    if conn.execute("SELECT 1 FROM principals WHERE name=?", (principal,)).fetchone() is None:
        raise IAMError(f"no user named {principal!r}")
    cur_role = conn.execute("SELECT role FROM principals WHERE name=?",
                            (principal,)).fetchone()["role"]
    if cur_role == "operator":
        return {"principal": principal, "role": role, "resource": resource,
                "effect": "allow", "removed": False}
    set_principal_role(conn, principal, "operator", "web")
    return {"principal": principal, "role": role, "resource": resource,
            "effect": "allow", "removed": True}


def web_rename_principal(conn, runtime, old: str, new: str, resource: str, grant_id: str) -> dict:
    """The web-reachable form of rename_principal(): consumes a single-use
    action grant (minted by agenti-authd only after the approver
    re-entered their password and a fresh 2FA code) and re-checks, fresh,
    that the approver holds iam:manage on `resource`. The approver, not
    anything the API claims, becomes the recorded actor."""
    action = {"op": "rename-principal", "principal": old, "new_name": new, "resource": resource}
    approver = consume_action_grant(runtime, grant_id, action)
    if not check(conn, approver, "iam:manage", resource).allowed:
        raise IAMError(f"{approver!r} approved this but does not hold iam:manage on "
                       f"{resource} — refusing. Nothing was changed.")
    return {**rename_principal(conn, runtime, old, new, approver), "approved_by": approver}


def web_delete_principal(conn, runtime, name: str, resource: str, grant_id: str) -> dict:
    """The web-reachable form of delete_principal() — same grant-and-
    re-check shape as web_rename_principal() above."""
    action = {"op": "delete-principal", "principal": name, "resource": resource}
    approver = consume_action_grant(runtime, grant_id, action)
    if not check(conn, approver, "iam:manage", resource).allowed:
        raise IAMError(f"{approver!r} approved this but does not hold iam:manage on "
                       f"{resource} — refusing. Nothing was changed.")
    return {**delete_principal(conn, runtime, name, approver), "approved_by": approver}


def web_enable_principal(conn, runtime, name: str, resource: str, grant_id: str) -> dict:
    """Re-enable a disabled account, grant-gated like rename/delete (§4 item
    78). Enabling RESTORES authority — whatever bindings the account kept — so
    it is never a plain web action: a single-use grant from a fresh password
    + 2FA/passkey check, and the approver must hold iam:manage on `resource`."""
    action = {"op": "enable-principal", "principal": name, "resource": resource}
    approver = consume_action_grant(runtime, grant_id, action)
    if not check(conn, approver, "iam:manage", resource).allowed:
        raise IAMError(f"{approver!r} approved this but does not hold iam:manage on "
                       f"{resource} — refusing. Nothing was changed.")
    set_principal_active(conn, name, True)
    return {"principal": name, "active": True, "approved_by": approver}


# ---------------------------------------------------------------------------
# WebAuthn / passkeys — credential storage, challenges, and the grant-bound
# registration commit. The actual cryptographic verification (CBOR/COSE
# parsing, ECDSA signature checks) lives entirely in webauthn_lite.py and
# runs inside agenti-authd, which is the only process with both the identity
# data AND the `cryptography` dependency needed to check it. This module
# never imports webauthn_lite and never touches raw key bytes — everything
# here works with opaque base64url TEXT, the same way it never decodes an
# API key's secret bytes either.
# ---------------------------------------------------------------------------
WEBAUTHN_CHALLENGE_TTL_S = 120  # same reasoning as ACTION_GRANT_TTL_S: long
                                # enough for a real biometric ceremony, short
                                # enough that an abandoned one isn't a door
WEBAUTHN_ENABLED_KEY = "webauthn-enabled"
WEBAUTHN_REGISTER_OP = "webauthn_register"


def webauthn_enabled(conn) -> bool:
    """Default OFF, unlike require-2fa's default ON — passkeys need a real
    domain and certificate an admin must deliberately configure first (see
    `agenti gui configure --hostname`), so 'available at all' is an opt-in, not an
    opt-out. Checked by agenti-authd on every WebAuthn op, alongside the
    structural AGENTI_HOSTNAME gate — two independent, honestly-worded
    reasons a caller can be refused."""
    return get_setting(conn, WEBAUTHN_ENABLED_KEY, "") == "on"


def set_webauthn_enabled(conn, enabled: bool) -> None:
    """The one settings-table write for this feature the API may invoke
    (`set-webauthn`, excluded from IAM_WRITE_VERBS the same deliberate way
    set-limit already is) — a feature flag, not a grant of authority to any
    specific principal, so it fits the existing set-limit carve-out rather
    than set-policy's blanket refusal."""
    set_setting(conn, WEBAUTHN_ENABLED_KEY, "on" if enabled else "off")


def _webauthn_challenge_hash(challenge_b64: str) -> str:
    return hashlib.sha256(challenge_b64.encode("ascii")).hexdigest()


def mint_webauthn_challenge(runtime, *, purpose: str, principal: str | None = None) -> str:
    """`purpose` is 'register', 'login', or 'reauth'. Returns the base64url
    challenge to hand to the browser; only its HASH is stored, single-use,
    short TTL — the exact shape mint_enrolment_token/mint_action_grant
    already use. Called by agenti-authd (op_webauthn_register_begin/
    op_webauthn_login_begin/op_approve_action_webauthn_begin), which owns
    runtime.db outright.

    'reauth' (added at the operator's request, alongside the stakes-based
    web-grant re-auth) is a passkey standing in for the password+TOTP
    re-authentication a web grant already requires — a platform
    authenticator's own possession + user-verification check is exactly
    what already lets a passkey replace password+TOTP at LOGIN (§4 item
    37); using it here is the same argument applied to proving presence
    for a SENSITIVE ACTION rather than a session. Scoped to a known
    principal ahead of time, like 'register', not discoverable like
    'login' — the caller already knows who is re-authenticating."""
    assert purpose in ("register", "login", "reauth")
    challenge_b64 = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode("ascii")
    now = time.time()
    runtime.execute(
        "INSERT INTO webauthn_challenges(challenge_hash, principal, purpose, created_at, expires_at)"
        " VALUES (?,?,?,?,?)",
        (_webauthn_challenge_hash(challenge_b64), principal, purpose, now, now + WEBAUTHN_CHALLENGE_TTL_S))
    runtime.execute("DELETE FROM webauthn_challenges WHERE expires_at < ?", (now - 3600,))
    runtime.commit()
    return challenge_b64


def consume_webauthn_challenge(runtime, challenge_b64: str, *, purpose: str,
                                principal: str | None = None) -> None:
    """Raises IAMError if the challenge is unknown, expired, already used, of
    the wrong purpose, or (for a registration challenge) issued for a
    different principal. Marked used BEFORE any of those checks run — a
    WebAuthn ceremony gets exactly one attempt per challenge regardless of
    why it fails, the same single-use discipline every other short-lived
    token in this file follows."""
    h = _webauthn_challenge_hash(challenge_b64)
    row = runtime.execute(
        "SELECT principal, purpose, expires_at, used_at FROM webauthn_challenges"
        " WHERE challenge_hash=?", (h,)).fetchone()
    if row is None:
        raise IAMError("unknown WebAuthn challenge — start the ceremony again")
    cur = runtime.execute("UPDATE webauthn_challenges SET used_at=? WHERE challenge_hash=?"
                          " AND used_at IS NULL", (time.time(), h))
    runtime.commit()
    if row["used_at"] is not None or cur.rowcount != 1:
        raise IAMError("this WebAuthn challenge was already used — start the ceremony again")
    if row["expires_at"] < time.time():
        raise IAMError("this WebAuthn challenge has expired — start the ceremony again")
    if row["purpose"] != purpose:
        raise IAMError("WebAuthn challenge purpose mismatch — start the ceremony again")
    if purpose in ("register", "reauth") and row["principal"] != principal:
        raise IAMError("this WebAuthn challenge was not issued for this account")


def has_passkey(conn, principal: str) -> bool:
    return conn.execute("SELECT 1 FROM passkeys WHERE principal=? LIMIT 1",
                        (principal,)).fetchone() is not None


def list_passkeys(conn, principal: str, runtime=None) -> list[dict]:
    """Self-service device list. `runtime`, if given, fills in last_used_at
    from passkey_state — optional because a caller that only has `conn`
    (read-only iam.db) can still list names/dates without it."""
    rows = conn.execute(
        "SELECT credential_id, alg, name, created_at, created_by FROM passkeys"
        " WHERE principal=? ORDER BY created_at", (principal,)).fetchall()
    out = []
    for r in rows:
        last_used = None
        if runtime is not None:
            st = runtime.execute("SELECT last_used_at FROM passkey_state WHERE credential_id=?",
                                 (r["credential_id"],)).fetchone()
            last_used = st["last_used_at"] if st else None
        out.append({"credential_id": r["credential_id"], "alg": r["alg"],
                    "name": r["name"] or "", "created_at": r["created_at"],
                    "created_by": r["created_by"], "last_used_at": last_used})
    return out


def webauthn_register_action(principal: str, credential_id: str, alg: str, x: str, y: str,
                              sign_count: int) -> dict:
    """The exact shape agenti-authd hashes when it mints a registration grant
    (after running the REAL cryptographic verification in webauthn_lite.py),
    and that passkey_commit() below re-derives from its own CLI arguments
    before spending the grant. A mismatch — the API altering any field in
    between — means consume_action_grant refuses outright, the same
    protection web_bind() already gets from this exact mechanism."""
    return {"op": WEBAUTHN_REGISTER_OP, "principal": principal, "credential_id": credential_id,
            "alg": alg, "x": x, "y": y, "sign_count": sign_count}


def passkey_commit(conn, runtime, principal: str, credential_id: str, alg: str, x: str, y: str,
                    sign_count: int, name: str, grant_id: str) -> dict:
    """Write a newly-registered passkey. Trusts nothing about the caller's
    claim that these fields are genuine — only that a valid, unspent action
    grant exists for EXACTLY this action, which only agenti-authd could have
    minted, and only after it verified a real attestation. Mirrors web_bind's
    shape precisely: the grant is what makes an API-reachable identity write
    safe, not anything the API itself asserts."""
    if conn.execute("SELECT 1 FROM principals WHERE name=?", (principal,)).fetchone() is None:
        raise IAMError(f"no user named {principal!r}")
    action = webauthn_register_action(principal, credential_id, alg, x, y, sign_count)
    approver = consume_action_grant(runtime, grant_id, action)
    if approver != principal:
        # Should be structurally impossible (the grant is minted for the same
        # principal that just re-authenticated as themselves) — checked
        # anyway, the same "don't trust the relay" posture as everywhere else
        # in this function.
        raise IAMError("this approval grant was not issued for this account — refusing")
    try:
        conn.execute(
            "INSERT INTO passkeys(credential_id, principal, alg, pubkey_x, pubkey_y,"
            " name, created_at, created_by) VALUES (?,?,?,?,?,?,?,?)",
            (credential_id, principal, alg, x, y, name or "", time.time(), principal))
        conn.commit()
    except sqlite3.IntegrityError:
        raise IAMError("this device is already registered as a passkey. If it's meant "
                       "to be for a different account, remove the existing registration "
                       "first.")
    runtime.execute(
        "INSERT INTO passkey_state(credential_id, sign_count, last_used_at) VALUES (?,?,NULL)"
        " ON CONFLICT(credential_id) DO UPDATE SET sign_count=excluded.sign_count",
        (credential_id, sign_count))
    runtime.commit()
    return {"credential_id": credential_id, "principal": principal, "alg": alg, "name": name or ""}


def remove_own_passkey(conn, runtime, principal: str, credential_id: str) -> bool:
    """Self-service removal (`self passkey-remove`) — `principal` must
    already be the reauthenticated caller. Returns False if no such passkey
    exists FOR THIS principal; a credential id belonging to someone else
    looks identical to a nonexistent one, on purpose."""
    row = conn.execute("SELECT 1 FROM passkeys WHERE credential_id=? AND principal=?",
                       (credential_id, principal)).fetchone()
    if row is None:
        return False
    conn.execute("DELETE FROM passkeys WHERE credential_id=?", (credential_id,))
    conn.commit()
    if runtime is not None:
        try:
            runtime.execute("DELETE FROM passkey_state WHERE credential_id=?", (credential_id,))
            runtime.commit()
        except sqlite3.Error:
            pass
    # Removing a passkey is what you do when it is lost or stolen: a session
    # someone opened with it must not outlive it (audit run 1).
    _revoke_sessions(runtime, principal)
    return True


def reset_passkeys(conn, runtime, principal: str) -> int:
    """Root break-glass (mirrors reset_totp): remove EVERY passkey for this
    principal — 'lost every device, need a clean slate.' CLI-only, never
    reachable by the API — it lives under `principal`, which IAM_WRITE_VERBS
    refuses outright, the same place reset-2fa already lives."""
    if conn.execute("SELECT 1 FROM principals WHERE name=?", (principal,)).fetchone() is None:
        raise IAMError(f"no user named {principal!r}")
    ids = [r["credential_id"] for r in
           conn.execute("SELECT credential_id FROM passkeys WHERE principal=?", (principal,))]
    conn.execute("DELETE FROM passkeys WHERE principal=?", (principal,))
    conn.commit()
    if runtime is not None and ids:
        try:
            runtime.executemany("DELETE FROM passkey_state WHERE credential_id=?",
                               [(i,) for i in ids])
            runtime.commit()
        except sqlite3.Error:
            pass
    if ids:
        _revoke_sessions(runtime, principal)
    return len(ids)




def issue_key(conn, principal: str, actor: str, *, expires_days: int | None = None) -> str:
    row = conn.execute("SELECT active FROM principals WHERE name=?", (principal,)).fetchone()
    if row is None:
        raise IAMError(f"no user named {principal!r}. "
                       f"Create it: sudo agenti admin user add {principal}")
    if not row["active"]:
        raise IAMError(f"principal {principal!r} is disabled — enable it first: "
                       f"sudo agenti admin user enable {principal}")
    full, prefix, key_hash = generate_key()
    expires = time.time() + expires_days * 86400 if expires_days else None
    conn.execute("INSERT INTO api_keys(prefix, principal, key_hash, created_at, created_by,"
                 " expires_at) VALUES (?,?,?,?,?,?)",
                 (prefix, principal, key_hash, time.time(), actor, expires))
    conn.commit()
    return full


def revoke_key(conn, prefix: str) -> None:
    if conn.execute("UPDATE api_keys SET revoked_at=? WHERE prefix=? AND revoked_at IS NULL",
                    (time.time(), prefix)).rowcount == 0:
        raise IAMError(f"no active key with prefix {prefix!r}. "
                       f"See: sudo agenti admin list-keys")
    conn.commit()


def bootstrap(conn, principal: str, actor: str) -> str:
    """First-run setup: an admin user and its first API key.

    Idempotent: refuses to re-mint if the principal already has an active key,
    so an accidental second run cannot silently hand out a second admin
    credential.
    """
    validate_name(principal, "user")
    if conn.execute("SELECT 1 FROM principals WHERE name=?", (principal,)).fetchone() is None:
        add_principal(conn, principal, "user", actor, role="admin")
    else:
        set_principal_role(conn, principal, "admin", actor)
    existing = conn.execute(
        "SELECT count(*) AS n FROM api_keys WHERE principal=? AND revoked_at IS NULL"
        " AND (expires_at IS NULL OR expires_at > ?)", (principal, time.time())).fetchone()
    if existing["n"]:
        raise IAMError(
            f"principal {principal!r} already has {existing['n']} active key(s) — refusing to\n"
            f"mint another silently. To rotate:\n"
            f"  sudo agenti admin list-keys --user {principal}\n"
            f"  sudo agenti admin revoke-key <prefix>\n"
            f"  sudo agenti admin issue-key --user {principal}")
    return issue_key(conn, principal, actor)


# ---------------------------------------------------------------------------
# CLI entry point — `agenti admin ...` dispatches here.
#
# Argument parsing lives in Python rather than bash for the same reason
# new_agent.py's does: this is a dozen subcommands with typed options and real
# validation, and reimplementing that in a case statement is how you get the
# class of bug the 2026-09-20 CLI audit found. shared/agenti stays a thin
# forwarder.
#
# Every subcommand supports --json, so the API's own `agenti admin ...` calls
# and a human at a terminal get the same data in the shape each needs.
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# The public vocabulary is "user" (operator decision, 2026-10-19).
#
# Everything an operator can type or read says "user": CLI verbs and flags,
# --json keys, error text. Inside, the store keeps "principal" (the iam.db
# tables and columns, the Python names, the `subject_kind` value stored in
# `bindings`, and the op names and keys of the grant actions that agenti-authd binds a grant
# to) -- renaming those buys nothing and a mistake in a hash-bound action would
# break approvals. Two small functions are the whole boundary:
#
#   canonical_argv()  the OLD spellings still work for one release: the old verb
#                     names and --principal are rewritten before argparse sees
#                     them, so --help only ever shows the new names;
#   public_json()     every --json document goes out with "user" keys.
# ---------------------------------------------------------------------------
OLD_VERBS = {
    "principal": "user", "list-principals": "list-users",
    "create-principal": "create-user", "disable-principal": "disable-user",
    "enable-principal": "enable-user", "rename-principal": "rename-user",
    "delete-principal": "delete-user", "principal-history": "user-history",
    "principal-exists": "user-exists",
    "reset-principal-password": "reset-user-password",
    "reset-principal-mfa": "reset-user-mfa",
}


_ENV_ARG = re.compile(r"@env:(AGENTI_ARG_[0-9]{1,3})")


def resolve_env_args(argv: list[str]) -> list[str]:
    """The web tier's bridge (api_bridge.py) moves every secret out of the
    command line into the root process's environment, so no password, code,
    link token or grant reaches sudo's log or /proc/<pid>/cmdline (audit run 1,
    N05). It leaves `@env:AGENTI_ARG_<n>` in its place, alone or after
    `--option=`; this puts the value back. Only that exact name pattern is
    read, never an arbitrary variable."""
    def one(arg: str) -> str:
        name, eq, val = arg.partition("=") if arg.startswith("--") else ("", "", arg)
        m = _ENV_ARG.fullmatch(val)
        if not m:
            return arg
        value = os.environ.get(m.group(1))
        if value is None:
            raise SystemExit(f"error: {m.group(1)} was not passed — this call must come through the bridge")
        return f"{name}={value}" if eq else value
    return [one(a) for a in argv]


def canonical_argv(argv: list) -> list:
    """Rewrite the old spellings (verb names, --principal) to the current ones.

    Only the verb (the first word that is not a global flag) and tokens that are
    exactly `--principal` / `--principal=...` are touched, and nothing after a
    bare `--`: a user who happens to be NAMED "principal" is left alone."""
    out, verb_seen, i = [], False, 0
    while i < len(argv):
        tok = argv[i]
        if tok == "--":
            out.extend(argv[i:])
            break
        if not verb_seen:
            if tok == "--actor" and i + 1 < len(argv):
                out.extend(argv[i:i + 2]); i += 2; continue
            if not tok.startswith("-"):
                tok = OLD_VERBS.get(tok, tok)
                verb_seen = True
        elif tok == "--principal":
            tok = "--user"
        elif tok.startswith("--principal="):
            tok = "--user=" + tok[len("--principal="):]
        out.append(tok)
        i += 1
    return out


def public_json(obj):
    """The document a --json call prints: "principal" keys become "user", and a
    binding's stored subject_kind 'principal' reads 'user'. A dict that already
    has a "user" key keeps both rather than lose one."""
    if isinstance(obj, list):
        return [public_json(x) for x in obj]
    if not isinstance(obj, dict):
        return obj
    out = {}
    for k, v in obj.items():
        if k == "principal" and "user" not in obj:
            k = "user"
        if k == "subject_kind" and v == "principal":
            v = "user"
        out[k] = public_json(v)
    return out




def _main() -> int:  # pragma: no cover - exercised via the CLI
    import argparse
    import getpass
    import json as _json

    class _JsonAwareArgumentParser(argparse.ArgumentParser):
        """argparse's own default error() prints usage + message to STDERR
        and exit(2)s, unconditionally — it has no idea --json was asked
        for, because a parse error by definition happens before parsing
        succeeds, so there is no namespace with a trustworthy .json
        attribute yet to check. That breaks the one-stream contract every
        OTHER failure path here honors (IAMError below is caught and
        re-emitted as JSON when asked): a caller parsing stdout as JSON —
        such as `agenti admin issue-key --expires-days abc --json` — got
        nothing useful. Found live (2026-09-20); the same class of gap
        CLAUDE.md §4 step 10 already found and fixed once in the bash
        CLI's own argument parsing, missed here because that audit
        predates this file. Checking raw sys.argv rather than the
        (nonexistent) parsed namespace is the same trick the bash CLI
        uses: strip/inspect global flags before real parsing can fail.

        Propagates automatically to every subparser: argparse's own
        add_subparsers() defaults parser_class to type(self)."""
        def error(self, message):
            if "--json" in sys.argv:
                print(_json.dumps({"error": message}))
                self.exit(2)
            super().error(message)

    ap = _JsonAwareArgumentParser(allow_abbrev=False, 
        prog="agenti admin",
        description="Identity and access management for Agenti (CLAUDE.md §3g).\n\n"
                    "Users are WHO acts. Roles are WHAT may be done. Bindings\n"
                    "attach a role (operator or admin) to a user or group on the\n"
                    "organisation (resource 'org'). Explicit deny always beats allow.",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--actor", default=os.environ.get("SUDO_USER", "root"),
                    help="who is making this change (recorded in the store)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def add(name, help_):
        return sub.add_parser(name, allow_abbrev=False, help=help_)

    p = add("user", "create and manage identities")
    ps = p.add_subparsers(dest="sub", required=True)
    q = ps.add_parser("add", allow_abbrev=False); q.add_argument("name")
    q.add_argument("--kind", choices=("user", "service"), default="user")
    ps.add_parser("list", allow_abbrev=False)
    for verb in ("disable", "enable", "set-password", "enroll-2fa", "reset-2fa",
                 "reset-passkeys"):
        q = ps.add_parser(verb, allow_abbrev=False); q.add_argument("name")
        if verb == "set-password":
            # setup checks the password first, then hands it over here: on
            # stdin, never in argv (sudo logs argv; /proc shows it).
            q.add_argument("--password-stdin", action="store_true",
                           help="read the password (one line) from standard input")

    q = add("bind", "set a user's role (operator or admin)")
    q.add_argument("subject_kind", choices=("user", "principal"),
                   metavar="{user}", help="always 'user'")
    q.add_argument("subject", metavar="user")
    q.add_argument("--role", required=True, choices=WEB_GRANTABLE_ROLES)

    q = add("bindings", "list users and their roles")
    q.add_argument("--user", dest="principal", metavar="USER")

    # ---- the bounded web grant (§4 item 24) ------------------------------
    q = add("web-bind", "set operator or admin on a user via an approval grant "
            "that agenti-authd minted after the approving admin re-entered their "
            "password and 2FA code.")
    q.add_argument("principal", metavar="user")
    q.add_argument("--role", required=True, choices=WEB_GRANTABLE_ROLES)
    q.add_argument("--grant", required=True, help="the approval grant id from agenti-authd")
    q = add("web-unbind", "demote a user back to operator. No grant needed — "
            "removing authority is fail-safe.")
    q.add_argument("principal", metavar="user")
    q.add_argument("--role", required=True, choices=WEB_GRANTABLE_ROLES)

    # ---- WebAuthn / passkeys — same "authd verifies, root commits" shape
    # as the bounded web grant right above, and deliberately positioned next
    # to it: passkey-commit's grant comes from agenti-authd's
    # op_webauthn_register_finish (after REAL cryptographic verification),
    # not from op_approve_action, but the mechanism — a grant bound to the
    # exact action, unspendable on anything else — is the same one.
    q = add("passkey-commit", "record a newly-verified passkey credential. Only "
            "callable with a valid, unspent registration grant from agenti-authd "
            "— the API's own claims about the credential are never trusted.")
    q.add_argument("principal", metavar="user")
    q.add_argument("--credential-id", required=True)
    q.add_argument("--alg", required=True)
    q.add_argument("--x", required=True, help="base64url public key x-coordinate")
    q.add_argument("--y", required=True, help="base64url public key y-coordinate")
    q.add_argument("--sign-count", type=int, required=True)
    q.add_argument("--name", default="", help="a friendly label ('iPhone', "
                   "'MacBook Pro') — not cryptographically verified, purely cosmetic")
    q.add_argument("--grant", required=True, help="the registration grant id from agenti-authd")

    q = add("passkey-list", "list a user's registered passkeys (read-only "
            "twin of the self-service list — see list-users' comment for "
            "why this is its own top-level verb)")
    q.add_argument("principal", metavar="user")

    q = add("issue-key", "mint an API key (printed once, never recoverable)")
    q.add_argument("--user", dest="principal", metavar="USER", required=True)
    q.add_argument("--expires-days", type=int)
    q = add("revoke-key", "revoke a key by prefix"); q.add_argument("prefix")
    q = add("list-keys", "list keys and when they were last used")
    q.add_argument("--user", dest="principal", metavar="USER")

    # Read-only, standalone, same shape and same reason as list-keys right
    # above: "principal" (the multi-purpose verb, add/disable/set-password/
    # ...) is fully refused to the API regardless of sub-verb, because
    # refuse_iam_writes_from_api matches on the top-level verb name, not the
    # sub-verb — so even `user list` was refused, which is exactly what
    # broke the admin Users view's first live test (found by running it, not
    # by reading the refusal logic). Fixed the same way list-keys already
    # solves it for API keys: a dedicated top-level verb for the one
    # read-only action, never added to IAM_WRITE_VERBS.
    q = add("list-users", "list users (read-only twin of "
        "`user list`, callable by the API — see the comment above)")

    # ---- self-service (CLAUDE.md §4 step 6 phase 2) --------------------
    #
    # Deliberately its OWN verb, not folded into `principal`: `principal` is
    # listed in shared/agenti's IAM_WRITE_VERBS and refused outright when the
    # caller is the API service account. `self` is NOT in that list — see
    # its comment there — which is the entire mechanism that lets the web
    # GUI offer self-service password/2FA changes at all. Every subcommand
    # here re-proves the CURRENT credential (reauthenticate_self()) before
    # touching anything, which is what makes that safe: the API can invoke
    # this, but it cannot forge what only the real human can supply.
    p = add("self", "change your OWN password or 2FA — requires proving the "
            "current credential first; used by the web GUI's self-service "
            "account page")
    ss = p.add_subparsers(dest="sub", required=True)

    q = ss.add_parser("password", allow_abbrev=False, help="change your own password")
    q.add_argument("name")
    q.add_argument("--current", default="", help="your CURRENT password (or --reauth)")
    q.add_argument("--reauth", default="", help="a passkey re-authentication token (instead of --current/--totp)")
    q.add_argument("--new", required=True)
    q.add_argument("--totp", help="a current 2FA code (or recovery code) — "
                   "required if 2FA is enrolled")
    q.add_argument("--addr", default="", help="caller's source address, for "
                   "the same throttling a real login gets")

    q = ss.add_parser("mfa-start", allow_abbrev=False, help="begin enrolling/re-enrolling 2FA. "
                      "Writes NOTHING — returns a candidate secret; call "
                      "mfa-confirm with a code generated from it to actually "
                      "turn it on")
    q.add_argument("name")
    q.add_argument("--current", default="")
    q.add_argument("--reauth", default="", help="a passkey re-authentication token (instead of --current/--totp)")
    q.add_argument("--totp", help="a current 2FA code (or recovery code) — "
                   "required if 2FA is ALREADY enrolled, so re-enrolling "
                   "needs proof of the OLD factor, not just the password")
    q.add_argument("--addr", default="")

    q = ss.add_parser("mfa-confirm", allow_abbrev=False, help="finish 2FA enrolment: consumes the "
                      "single-use grant mfa-start minted (proof the "
                      "re-authentication already happened there) and proves "
                      "the secret from mfa-start was actually captured "
                      "correctly before it takes effect")
    q.add_argument("name")
    q.add_argument("--grant", required=True, help="the grant id mfa-start returned")
    q.add_argument("--secret", required=True, help="the secret mfa-start returned")
    q.add_argument("--code", required=True, help="a CURRENT code generated "
                   "from that secret")

    q = ss.add_parser("passkey-remove", allow_abbrev=False, help="remove one of your own registered "
                      "passkeys. Registering a NEW one is not here — that goes "
                      "through agenti-authd (a real cryptographic ceremony, not "
                      "a password-gated write) and lands via `passkey-commit`.")
    q.add_argument("name")
    q.add_argument("--current", default="")
    q.add_argument("--reauth", default="", help="a passkey re-authentication token (instead of --current/--totp)")
    q.add_argument("--totp", help="a current 2FA code (or recovery code) — "
                   "required if 2FA is enrolled")
    q.add_argument("--credential-id", required=True)
    q.add_argument("--addr", default="")

    # ---- narrow admin actions the web GUI may take directly ------------
    #
    # Each of these is its OWN top-level verb, deliberately not a subcommand
    # of `principal`/`group` (both fully refused to the API — see
    # IAM_WRITE_VERBS), and each does exactly ONE thing chosen because it can
    # only REMOVE or grant-nothing authority, never grant or restore it —
    # disable-user is fail-safe (worst case: someone gets locked out).
    # create-user is the exception that proves the rule: from the web it runs
    # only on a fresh, single-use 'create-user' grant naming the account, its
    # kind and its role (operator decision 2026-10-22, audit run 1).
    q = add("approve-engagement", "consume a web grant to set or approve the engagement "
            "(called by the CLI, never directly)")
    q.add_argument("change", choices=("set", "approve"))
    q.add_argument("bound", help="the change's SHA-256 (set) or the reviewed digest (approve)")
    q.add_argument("--grant", required=True)

    q = add("create-user", "create a new user account")
    q.add_argument("name")
    q.add_argument("--role", choices=WEB_GRANTABLE_ROLES, default="operator",
                   help="initial role (default: operator)")
    q.add_argument("--kind", choices=("user", "service"), default="user")
    q.add_argument("--no-link", action="store_true",
                   help="skip minting an enrolment link (e.g. for a service "
                        "user, which authenticates with a key, not a "
                        "password)")
    q.add_argument("--grant", help="from the web: the re-authenticated approval "
                                   "(op create-user) for exactly this name, kind and role")

    q = add("disable-user", "disable one user (fail-safe: only "
            "removes authority)")
    q.add_argument("name")
    q.add_argument("--by", help="the account performing this (refuses disabling yourself)")

    q = add("mint-enrolment-link", "issue a fresh one-time enrolment link "
            "for an existing user with no password yet (e.g. a link "
            "that expired before they used it)")
    q.add_argument("name")

    # ---- rename/delete a principal — grant-gated ONLY, unlike everything
    # else on this page. Unlike disable-user/create-user (fail-safe:
    # they can only remove authority or grant none at all), a rename
    # re-points an identity every audit/run-history record refers to, and a
    # delete is irreversible — both judged to warrant the SAME re-
    # authenticated, single-use approval grant the bounded web grant
    # (web-bind) already uses, rather than the API's bare sudo reach alone.
    # There is deliberately no plain, grant-less root form: even a terminal
    # admin goes through agenti-authd's re-auth ceremony for these two.
    q = add("rename-user", "rename a user's real login name — "
            "every binding, key, passkey and per-user setting moves "
            "with it — on the strength of an approval grant agenti-authd "
            "minted after the approving admin re-entered their password "
            "and 2FA code")
    q.add_argument("old_name"); q.add_argument("new_name")
    q.add_argument("--grant", required=True, help="the approval grant id from agenti-authd")

    q = add("delete-user", "PERMANENTLY delete a user — every "
            "credential, binding and membership, genuinely gone. Audit "
            "logs, run history, team chat and reports keep the name they "
            "recorded; a tombstone is left so it can never be reissued. "
            "Same grant requirement as rename-user above.")
    q.add_argument("name")
    q.add_argument("--grant", required=True, help="the approval grant id from agenti-authd")

    q = add("enable-user", "re-enable a disabled user — grant-gated "
            "ONLY (enabling restores whatever access the account kept). Same "
            "grant requirement as delete-user above. From a terminal "
            "as root, `user enable <name>` still works directly.")
    q.add_argument("name")
    q.add_argument("--grant", required=True, help="the approval grant id from agenti-authd")

    q = add("user-history", "read-only: every user rename/hard-"
            "delete ever recorded, for the (deleted)/(now <new>) annotation")

    # ---- reset a DIFFERENT principal's password or MFA — grant-gated ONLY,
    # global-admin only, and deliberately two separate verbs (the operator's
    # own explicit ask): resetting one never touches the other. Same "no
    # plain root form" posture as rename/delete-user above — even a
    # terminal admin goes through agenti-authd's re-auth ceremony.
    q = add("reset-user-password", "reset a DIFFERENT user's "
            "password — either set an exact new value directly (--new), or "
            "mint a one-time link for them to set their own (--link, valid "
            f"{PASSWORD_RESET_TOKEN_TTL_S // 3600}h) — on the strength of an "
            "approval grant agenti-authd minted after the approving admin "
            "re-entered their own password and 2FA code. Admin only. "
            "See reset-user-mfa "
            "for the separate 2FA/passkey reset.")
    q.add_argument("name")
    q.add_argument("--new", help="set this exact password directly")
    q.add_argument("--link", action="store_true", help="mint a one-time "
                   "reset link instead — pass exactly one of --new/--link")
    q.add_argument("--grant", required=True, help="the approval grant id from agenti-authd")

    q = add("reset-user-mfa", "clear a DIFFERENT user's 2FA "
            "entirely — every TOTP secret and passkey — forcing them to "
            "re-register at their next login if the require-2fa policy "
            "applies to them. Deliberately separate from "
            "reset-user-password above; same grant requirement, "
            "global-admin only.")
    q.add_argument("name")
    q.add_argument("--grant", required=True, help="the approval grant id from agenti-authd")

    q = add("password-reset-check", "is this password reset token still "
            "valid, and for whom? Mirrors enrol-check.")
    q.add_argument("token")

    q = add("password-reset-consume", "set a new password using a one-time "
            "reset token, then burn it — the target account's OWN action, "
            "no existing credential required. Mirrors enrol-consume, but "
            "for an already-enrolled account and password only.")
    q.add_argument("token")
    q.add_argument("--new", required=True, help="the new password")

    q = add("user-exists", "read-only: does this user exist? (what the CLI checks "
            "before acting on a user's runs)")
    q.add_argument("name")

    q = add("dashboard-access", "read-only: may VIEWER open TARGET's dashboard "
            "(see their runs, stop / mark complete, manage their kept files)?")
    q.add_argument("viewer"); q.add_argument("target")

    q = add("approve-context-edit", "consume an edit-context approval grant for "
            "exactly this change and return who approved it — does not write the "
            "file itself (agenti admin context-web does, after this succeeds)")
    q.add_argument("change", choices=("set", "reset", "revert"))
    q.add_argument("kind", choices=("system-prompt", "skills", "platform-skills", "org"))
    q.add_argument("--agent", default=None)
    q.add_argument("--text-file", default=None, help="the new text (set only); its hash must match the grant")
    q.add_argument("--version", default=None, help="the version id (revert only)")
    q.add_argument("--grant", required=True)

    q = add("approve-agent-build", "consume a build/update/remove-agent or edit-catalog approval "
            "grant for exactly this agent or program (and this spec's SHA-256) and return "
            "who approved it — agenti admin agent-build / catalog do the work")
    q.add_argument("change", choices=("build", "update", "remove", "catalog-add", "catalog-update", "catalog-remove"))
    q.add_argument("name")
    q.add_argument("--sha256", default=None)
    q.add_argument("--grant", required=True)

    q = add("approve-vault-enable", "consume a vault-enable approval grant for exactly this "
            "container size and return who approved it — agenti vault enable does the work")
    q.add_argument("--size", required=True)
    q.add_argument("--grant", required=True)

    q = add("approve-exploit-action", "consume an action-approve/action-reject (or legacy "
            "exploit-approve/reject) approval grant for exactly this pending request "
            "and return who approved it — agenti <agent> action-approve / action-reject do the work")
    q.add_argument("decision", choices=("approve", "reject"))
    q.add_argument("agent")
    q.add_argument("request_id")
    q.add_argument("options_hash")
    q.add_argument("--owner", required=True, help="the user whose run holds the request")
    q.add_argument("--grant", required=True)

    # ---- enrolment link consumption — NO existing credential to prove ---
    #
    # Reachable by someone who has proven nothing yet but the link itself,
    # which is exactly why it is single-use, short-lived, high-entropy, and
    # why failures here are deliberately as generic as /auth/login's.
    q = add("enrol-check", "is this enrolment token still valid, and for whom?")
    q.add_argument("token")

    q = add("enrol-consume", "set the initial password (and, optionally, "
            "first 2FA factor) an enrolment token names, then burn it")
    q.add_argument("token")
    q.add_argument("--new", required=True, help="the new account's first password")
    q.add_argument("--totp-secret", help="enrol 2FA in the same step — the "
                   "secret shown to the user (see 'self mfa-start')")
    q.add_argument("--totp-code", help="a current code generated from --totp-secret")

    # ---- numeric limits ---------------------------------------------------
    # set-limit is not in shared/agenti's IAM_WRITE_VERBS: it changes a
    # numeric quota, never a permission.
    q = add("set-limit", "set a numeric limit: "
            "outputs-bytes-total or outputs-bytes-per-operator (each a "
            "platform default), optionally suffixed :<name> for one person's "
            "override. The value 'default' removes the row — that person "
            "follows the platform value again, or the platform falls back to the "
            "built-in default")
    q.add_argument("key"); q.add_argument("value", type=limit_value,
                                          help="a whole number, or 'default'")
    q = add("set-webauthn", "turn WebAuthn/passkey sign-in on or off, platform-wide. "
            "A feature flag, not a permission grant — same carve-out reasoning as "
            "set-limit, which is why this is API-reachable while set-policy is not. "
            "Passkeys also need a real domain "
            "(sudo agenti gui configure --hostname <domain>); this toggle does nothing without one.")
    q.add_argument("value", choices=("on", "off"))
    q = add("outputs-usage", "the permanent Outputs store's two-level quota: "
            "the organisation's total usage, and optionally one "
            "operator's own share of it")
    q.add_argument("--user", dest="principal", metavar="USER", help="also show this operator's own usage/limit")
    q = add("outputs-list", "promoted outputs in the permanent store")
    q.add_argument("--user", dest="principal", metavar="USER", help="only this operator's own (default: everyone's)")
    q = add("outputs-delete", "delete one or more promoted outputs — the owner's, "
            "or anyone's with iam:manage (CLAUDE.md decision 5: the Outputs page's "
            "multi-select is one call, not N)")
    q.add_argument("--user", dest="principal", metavar="USER", required=True)
    q.add_argument("name", nargs="+", help="one or more output names")
    q.add_argument("--by", required=True, help="the user asking")
    q = add("outputs-path", "resolve ONE promoted output's real path, without "
            "touching it — same ownership check as outputs-delete, read-only "
            "(phase 7 of the generic-launcher arc: what a download route resolves "
            "before shared/agenti cats the file)")
    q.add_argument("--user", dest="principal", metavar="USER", required=True)
    q.add_argument("name"); q.add_argument("--by", required=True,
                                           help="the user asking")

    # ---- tool requests (CLAUDE.md "Current plan", decision 4) -------------
    q = add("tool-request-file", "file a request for a tool the library "
            "lacks — reviewed by a human, never auto-actioned")
    q.add_argument("--by", required=True)
    q.add_argument("--category", default="", help="what it's roughly for, free text")
    q.add_argument("text")
    q = add("tool-request-list", "every filed tool request, newest first "
            "(admin-only at the API layer)")

    q = add("can", "explain an authorization decision")
    q.add_argument("principal", metavar="user"); q.add_argument("permission")
    q = add("bootstrap", "first-run setup: roles, an admin user, its first key")
    q.add_argument("--user", dest="principal", metavar="USER", required=True)
    q = add("set-policy", "change a platform policy")
    q.add_argument("key"); q.add_argument("value", choices=("on", "off"))
    add("permissions", "list the permission catalog")
    add("policy", "show current platform policies")
    q = add("authz-log", "recent authorization decisions, allows AND denies")
    q.add_argument("-n", type=int, default=50)
    q.add_argument("--user", dest="principal", metavar="USER")
    q.add_argument("--denied-only", action="store_true",
                   help="only refusals — the signal that a binding is wrong or "
                        "someone is probing")

    a = ap.parse_args(canonical_argv(resolve_env_args(sys.argv[1:])))

    def emit(obj, lines: Iterable[str] = ()) -> int:
        if a.json:
            print(_json.dumps(public_json(obj)))
        else:
            for line in lines:
                print(line)
        return 0

    try:
        # Read-only verbs must not create the store as a side effect of being
        # asked a question, so they open read-only and fail with the bootstrap
        # hint if it isn't there yet.
        readonly = a.cmd in ("bindings", "list-keys", "list-users", "can",
                             "permissions", "policy", "authz-log", "enrol-check",
                             "outputs-usage", "outputs-list", "outputs-delete",
                             "outputs-path", "tool-request-file", "tool-request-list",
                             "passkey-list", "user-history",
                             "password-reset-check",
                             "dashboard-access", "user-exists") or (
                                 a.cmd in ("user", "role", "group")
                                 and getattr(a, "sub", "") in ("list", "show"))
        if a.cmd == "permissions":
            return emit({"permissions": list(PERMISSIONS),
                         "builtin_roles": {k: list(v) for k, v in BUILTIN_ROLES.items()}},
                        ["permissions:"] + [f"  {p}" for p in PERMISSIONS])

        conn = open_iam(readonly=readonly)

        if a.cmd == "user":
            if a.sub == "add":
                add_principal(conn, a.name, a.kind, a.actor)
                return emit({"principal": a.name, "kind": a.kind, "created": True},
                            [f"  ✓ created {a.kind} user '{a.name}'",
                             f"    next: sudo agenti admin bind user {a.name} "
                             f"--role operator"])
            if a.sub in ("disable", "enable"):
                set_principal_active(conn, a.name, a.sub == "enable", getattr(a, "by", None))
                return emit({"principal": a.name, "active": a.sub == "enable"},
                            [f"  ✓ {a.sub}d user '{a.name}'"])
            if a.sub == "enroll-2fa":
                try:
                    _rt = open_runtime()
                except Exception:
                    _rt = None
                secret, codes = enroll_totp(conn, a.name, _rt)
                if _rt is not None:
                    _rt.close()
                uri = totp_uri(secret, a.name)
                if a.json:
                    print(_json.dumps(public_json({"principal": a.name, "secret": secret,
                                                  "otpauth_uri": uri, "recovery_codes": codes})))
                else:
                    print()
                    print("  ============================================================")
                    print(f"   2FA ENROLMENT for '{a.name}' — shown once, save it now")
                    print()
                    print("   Scan this in an authenticator app, or type the secret:")
                    try:
                        import qr as _qr
                        for _line in _qr.to_text(_qr.encode(uri, "M")).split("\n"):
                            print(f"     {_line}")
                        print()
                    except Exception:
                        pass  # the URI and secret below are enough on their own
                    print(f"     {uri}")
                    print()
                    print(f"     secret: {secret}")
                    print()
                    print("   RECOVERY CODES — each works once, if the device is lost:")
                    for c in codes:
                        print(f"     {c}")
                    print()
                    print("   Any previous 2FA device and recovery codes for this")
                    print("   user have just been invalidated.")
                    print("  ============================================================")
                return 0
            if a.sub == "reset-2fa":
                try:
                    _rt = open_runtime()
                except Exception:
                    _rt = None
                reset_totp(conn, a.name, _rt)
                if _rt is not None:
                    _rt.close()
                return emit({"principal": a.name, "totp": False},
                            [f"  ✓ 2FA cleared for '{a.name}' — next sign-in is password-only",
                             f"    re-enrol: sudo agenti admin user enroll-2fa {a.name}"])
            if a.sub == "reset-passkeys":
                try:
                    _rt = open_runtime()
                except Exception:
                    _rt = None
                n = reset_passkeys(conn, _rt, a.name)
                if _rt is not None:
                    _rt.close()
                return emit({"principal": a.name, "passkeys_removed": n},
                            [f"  ✓ {n} passkey(s) removed for '{a.name}'"
                             + (" — signed out everywhere" if n else "")])
            if a.sub == "set-password":
                # Checked BEFORE prompting, not after: set_principal_password()
                # already refused a nonexistent principal, but only after the
                # operator had typed (or pasted) a password and its
                # confirmation into two getpass prompts for nothing. Found in
                # the 2026-09-21 error-message audit (CLAUDE.md §4 item 17)
                # — same class of "cause discovered too late" gap as the
                # earlier --json/--help ones, just at the interaction level
                # rather than the output level.
                if conn.execute("SELECT 1 FROM principals WHERE name=?",
                                (a.name,)).fetchone() is None:
                    raise IAMError(f"no user named {a.name!r}. "
                                   f"Create it first: sudo agenti admin user add {a.name}")
                if a.password_stdin:
                    pw = sys.stdin.readline().rstrip("\n")
                    if not pw:
                        raise IAMError("empty password on standard input — nothing changed")
                else:
                    pw = getpass.getpass(f"password for '{a.name}': ")
                    if not pw:
                        raise IAMError("empty password — nothing changed")
                    if pw != getpass.getpass("confirm: "):
                        raise IAMError("passwords did not match — nothing changed")
                try:
                    _rt = open_runtime()
                except Exception:
                    _rt = None
                revoked = set_principal_password(conn, a.name, pw, runtime=_rt)
                if _rt is not None:
                    _rt.close()
                lines = [f"  ✓ password set for '{a.name}'"]
                if revoked:
                    lines.append(f"    {revoked} existing session(s) revoked — "
                                  f"they'll need to sign in again")
                return emit({"principal": a.name, "password_set": True,
                            "sessions_revoked": revoked}, lines)
            rows = list(conn.execute(
                "SELECT name, kind, active, created_at, created_by,"
                " password_hash IS NOT NULL AS has_password,"
                " totp_secret IS NOT NULL AS has_totp, role,"
                " EXISTS (SELECT 1 FROM passkeys k WHERE k.principal = principals.name) AS has_passkey"
                " FROM principals ORDER BY name"))
            return emit([dict(r) for r in rows],
                        ["users:"] + [
                            f"  {r['name']:<20} {r['kind']:<8} "
                            f"{'active' if r['active'] else 'DISABLED':<9}"
                            f"{' +password' if r['has_password'] else ''}"
                            f"{' +2fa' if r['has_totp'] else ''}" for r in rows])

        if a.cmd == "self":
            # runtime.db is needed by every subcommand here (reauthenticate_self
            # checks lockout state and TOTP replay even for mfa-start, which
            # writes nothing to iam.db itself) — opened once, up front.
            try:
                rt = open_runtime()
            except Exception as e:
                raise IAMError(f"cannot open the runtime store ({e}). It is "
                               f"created at install; recreate it with: "
                               f"sudo dpkg-reconfigure agenti")
            try:
                if a.sub == "password":
                    _self_reauth(conn, rt, a)
                    if a.current and a.current == a.new:
                        raise IAMError("the new password must be different from the current one")
                    revoked = set_principal_password(conn, a.name, a.new, runtime=rt)
                    return emit({"principal": a.name, "password_set": True,
                                "sessions_revoked": revoked},
                               [f"  ✓ password changed for '{a.name}'",
                                f"    {revoked} session(s) revoked, including this one — "
                                f"sign in again with the new password"])

                if a.sub == "mfa-start":
                    _self_reauth(conn, rt, a)
                    secret = totp_generate_secret()
                    _uri = totp_uri(secret, a.name)
                    # Bind a single-use grant to THIS candidate secret, the
                    # same action_grants primitive the bounded web grant (§4
                    # item 24) and WebAuthn registration already use — so
                    # mfa-confirm can prove this re-authentication happened
                    # without asking for the password/code a second time.
                    # That second ask is what used to break re-enrolment:
                    # both calls hit the SAME OLD totp_secret's replay table,
                    # so resending the same code (the obvious thing to do,
                    # since nothing prompted for a fresh one) failed with
                    # "already been used" — the identical bug class already
                    # found and fixed once for WebAuthn register/finish.
                    gid = mint_action_grant(rt, a.name, {"op": "mfa-confirm",
                                                         "principal": a.name, "secret": secret})
                    return emit({"principal": a.name, "secret": secret,
                                "otpauth_uri": _uri, "qr_svg": _qr_svg(_uri),
                                "grant": gid, "expires_in": ACTION_GRANT_TTL_S},
                               [f"  secret: {secret}",
                                f"  scan or enter this in your authenticator app, then "
                                f"confirm with a code it generates (within {ACTION_GRANT_TTL_S}s)"])

                if a.sub == "mfa-confirm":
                    action = {"op": "mfa-confirm", "principal": a.name, "secret": a.secret}
                    approver = consume_action_grant(rt, a.grant, action)
                    if approver != a.name:
                        raise IAMError("this grant was not issued for this account")
                    if totp_verify(a.secret, a.code) is None:
                        raise IAMError("that code is not valid for the secret you were "
                                       "given — check your device's clock and try again "
                                       "(start over with mfa-start if the secret expired "
                                       "from your authenticator app's list)")
                    codes = confirm_totp_enrolment(conn, a.name, a.secret, rt)
                    lines = [f"  ✓ 2FA enabled for '{a.name}'", "",
                            "  RECOVERY CODES — each works once, if the device is lost:"]
                    lines += [f"    {c}" for c in codes]
                    lines.append("")
                    lines.append("  Save these now — they will not be shown again. Any "
                                 "previous 2FA device and codes were just invalidated.")
                    return emit({"principal": a.name, "totp": True, "recovery_codes": codes},
                               lines)

                if a.sub == "passkey-remove":
                    _self_reauth(conn, rt, a)
                    removed = remove_own_passkey(conn, rt, a.name, a.credential_id)
                    if not removed:
                        raise IAMError(f"no passkey {a.credential_id!r} registered to "
                                       f"'{a.name}' — nothing removed")
                    return emit({"principal": a.name, "credential_id": a.credential_id,
                                "removed": True, "signed_out": True},
                               [f"  ✓ passkey removed for '{a.name}' — signed out everywhere; "
                                f"sign in again"])

                raise IAMError(f"unhandled self subcommand {a.sub!r}")
            finally:
                rt.close()

        if a.cmd == "passkey-commit":
            rt = open_runtime()
            try:
                out = passkey_commit(conn, rt, a.principal, a.credential_id, a.alg, a.x, a.y,
                                     a.sign_count, a.name, a.grant)
            finally:
                rt.close()
            return emit(out, [f"  ✓ passkey '{out['name'] or out['credential_id'][:12]}' "
                              f"registered for '{out['principal']}'"])

        if a.cmd == "passkey-list":
            try:
                rt = open_runtime()
            except Exception:
                rt = None
            try:
                rows = list_passkeys(conn, a.principal, rt)
            finally:
                if rt is not None:
                    rt.close()
            lines = [f"passkeys for '{a.principal}':"] + (
                [f"  {r['name'] or '(unnamed)'}  {r['credential_id'][:16]}…  "
                 f"registered {time.strftime('%Y-%m-%d', time.localtime(r['created_at']))}"
                 for r in rows] or ["  (none)"])
            return emit(rows, lines)

        if a.cmd == "list-users":
            rows = list(conn.execute(
                "SELECT name, kind, active, created_at, created_by,"
                " password_hash IS NOT NULL AS has_password,"
                " totp_secret IS NOT NULL AS has_totp FROM principals ORDER BY name"))
            data = []
            for r in rows:
                d = dict(r)
                d["totp_required"] = two_factor_required(conn, r["name"])[0]
                data.append(d)
            return emit(data,
                        ["users:"] + [
                            f"  {r['name']:<20} {r['kind']:<8} "
                            f"{'active' if r['active'] else 'DISABLED':<9}"
                            f"{' +password' if r['has_password'] else ''}"
                            f"{' +2fa' if r['has_totp'] else (' 2FA-REQUIRED' if r['totp_required'] and r['has_password'] else '')}"
                            for r in data])

        if a.cmd == "approve-engagement":
            key = "sha256" if a.change == "set" else "digest"
            try:
                rt = open_runtime()
            except Exception as e:
                raise IAMError(f"cannot open the runtime store ({e}).")
            try:
                approver = web_approve_engagement(
                    conn, rt, {"op": f"engagement-{a.change}", key: a.bound, "resource": ORG_RESOURCE},
                    a.grant)
            finally:
                rt.close()
            return emit({"approved_by": approver}, [f"  ✓ approved by {approver}"])

        if a.cmd == "create-user":
            role = getattr(a, "role", "operator") or "operator"
            creator = a.actor
            if a.actor == API_ACCOUNT:
                # From the web, an account is created only on a fresh,
                # single-use approval for exactly this name, kind and role.
                if not a.grant:
                    raise IAMError("REFUSING: creating an account from the web needs a fresh "
                                   "re-authentication (an approval grant). Nothing was created.")
                try:
                    rt = open_runtime()
                except Exception as e:
                    raise IAMError(f"cannot open the runtime store ({e}).")
                try:
                    creator = web_approve_create_user(
                        conn, rt, {"op": "create-user", "principal": a.name, "kind": a.kind,
                                   "role": role, "resource": ORG_RESOURCE}, a.grant)
                finally:
                    rt.close()
            add_principal(conn, a.name, a.kind, creator, role=role)
            link = None
            if not a.no_link:
                try:
                    rt = open_runtime()
                except Exception:
                    rt = None
                if rt is not None:
                    link = mint_enrolment_token(rt, conn, a.name, creator)
                    rt.close()
            lines = [f"  ✓ created {a.kind} user '{a.name}' (role: {role})"]
            if link:
                lines += ["", f"  ONE-TIME ENROLMENT LINK (shown once, valid "
                          f"{ENROLMENT_TOKEN_TTL_S // 3600}h): {link}"]
            return emit({"principal": a.name, "kind": a.kind, "role": role,
                         "created": True, "enrolment_token": link}, lines)

        if a.cmd == "disable-user":
            set_principal_active(conn, a.name, False, getattr(a, "by", None))
            return emit({"principal": a.name, "active": False},
                        [f"  ✓ disabled '{a.name}'"])

        if a.cmd == "rename-user":
            try:
                rt = open_runtime()
            except Exception as e:
                raise IAMError(f"cannot open the runtime store ({e}).")
            try:
                out = web_rename_principal(conn, rt, a.old_name, a.new_name, ORG_RESOURCE, a.grant)
            finally:
                rt.close()
            return emit(out, [f"  ✓ renamed '{out['old']}' to '{out['new']}' "
                              f"(approved by {out['approved_by']})"])

        if a.cmd == "delete-user":
            try:
                rt = open_runtime()
            except Exception as e:
                raise IAMError(f"cannot open the runtime store ({e}).")
            try:
                out = web_delete_principal(conn, rt, a.name, ORG_RESOURCE, a.grant)
            finally:
                rt.close()
            return emit(out, [f"  ✓ permanently deleted '{out['name']}' "
                              f"(approved by {out['approved_by']})"])

        if a.cmd == "enable-user":
            try:
                rt = open_runtime()
            except Exception as e:
                raise IAMError(f"cannot open the runtime store ({e}).")
            try:
                out = web_enable_principal(conn, rt, a.name, ORG_RESOURCE, a.grant)
            finally:
                rt.close()
            return emit(out, [f"  ✓ re-enabled '{out['principal']}' "
                              f"(approved by {out['approved_by']})"])

        if a.cmd == "user-history":
            rows = []
            if PRINCIPAL_HISTORY_PATH.is_file():
                with open(PRINCIPAL_HISTORY_PATH, encoding="utf-8") as f:
                    for line in f:
                        try:
                            row = json.loads(line)
                        except (json.JSONDecodeError, ValueError):
                            continue
                        rows.append(row)
            # Rows written before every event shared one shape used
            # "op"/"actor"; read either rather than fail the whole list.
            for r in rows:
                r.setdefault("event", r.get("op", "?"))
                r.setdefault("by", r.get("actor") or "?")
            lines = [f"  {r.get('ts', 0):.0f}  {r['event']:8s}  {r.get('name', '?')}"
                    + (f" -> {r['new_name']}" if r.get("new_name") else "")
                    + (f" = {r['role']}" if r.get("role") else "")
                    + f"  (by {r['by']})" for r in rows] or ["  (none)"]
            return emit(rows, lines)

        if a.cmd == "reset-user-password":
            if bool(a.new) == bool(a.link):
                raise IAMError("pass exactly one of --new <password> or --link")
            try:
                rt = open_runtime()
            except Exception as e:
                raise IAMError(f"cannot open the runtime store ({e}).")
            try:
                if a.link:
                    out = web_mint_password_reset_link(conn, rt, a.name, ORG_RESOURCE, a.grant)
                    return emit(out, [f"  ✓ one-time reset link minted for '{out['principal']}' "
                                      f"(approved by {out['approved_by']}), valid "
                                      f"{PASSWORD_RESET_TOKEN_TTL_S // 3600}h:",
                                      f"    {out['reset_token']}"])
                out = web_reset_principal_password(conn, rt, a.name, ORG_RESOURCE, a.grant, a.new)
                return emit(out, [f"  ✓ password reset for '{out['principal']}' "
                                  f"(approved by {out['approved_by']}); "
                                  f"{out['sessions_revoked']} session(s) revoked"])
            finally:
                rt.close()

        if a.cmd == "reset-user-mfa":
            try:
                rt = open_runtime()
            except Exception as e:
                raise IAMError(f"cannot open the runtime store ({e}).")
            try:
                out = web_reset_principal_mfa(conn, rt, a.name, ORG_RESOURCE, a.grant)
            finally:
                rt.close()
            return emit(out, [f"  ✓ MFA reset for '{out['principal']}' "
                              f"(approved by {out['approved_by']}); "
                              f"{out['passkeys_removed']} passkey(s) removed"])

        if a.cmd == "password-reset-check":
            try:
                rt = open_runtime()
            except Exception as e:
                raise IAMError(f"cannot open the runtime store ({e}).")
            try:
                principal = password_reset_token_principal(conn, rt, a.token)
            finally:
                rt.close()
            if principal is None:
                # Raises, matching enrol-check's exact shape, rather than a
                # "soft" {"valid": false} 200 — the GUI page's own error
                # handling (reset-password.html, mirroring enrol.html) relies
                # on this route FAILING for an invalid/expired token, the
                # same contract every other check-a-token route in this file
                # already has.
                raise IAMError("this password reset link is invalid or has expired")
            return emit({"principal": principal, "valid": True}, [f"  valid, for '{principal}'"])

        if a.cmd == "password-reset-consume":
            try:
                rt = open_runtime()
            except Exception as e:
                raise IAMError(f"cannot open the runtime store ({e}).")
            try:
                principal = consume_password_reset_token(conn, rt, a.token, a.new)
            finally:
                rt.close()
            return emit({"principal": principal, "password_reset": True},
                       [f"  ✓ password set for '{principal}'"])

        if a.cmd == "user-exists":
            exists = conn.execute("SELECT 1 FROM principals WHERE name=?",
                                  (a.name,)).fetchone() is not None
            return emit({"principal": a.name, "exists": exists},
                        [f"  {a.name}: {'exists' if exists else 'no such user'}"])

        if a.cmd == "dashboard-access":
            out = dashboard_access(conn, a.viewer, a.target)
            return emit(out, [f"  {'allowed' if out['allowed'] else 'refused'}: {out['reason']}"])

        if a.cmd == "approve-agent-build":
            if a.change.startswith("catalog-"):
                action = {"op": "edit-catalog", "name": a.name, "change": a.change.split("-", 1)[1],
                          "resource": ORG_RESOURCE}
            else:
                action = {"op": f"{a.change}-agent", "name": a.name, "resource": ORG_RESOURCE}
            if a.change in ("build", "update", "catalog-add", "catalog-update"):
                if not a.sha256 or not re.fullmatch(r"[0-9a-f]{64}", a.sha256):
                    raise IAMError("--sha256 (the spec's SHA-256) is required for a build")
                action["sha256"] = a.sha256
            try:
                rt = open_runtime()
            except Exception as e:
                raise IAMError(f"cannot open the runtime store ({e}).")
            try:
                approver = web_approve_agent_build(conn, rt, action, a.grant)
            finally:
                rt.close()
            return emit({"approved_by": approver}, [f"  ✓ approved by {approver}"])

        if a.cmd == "approve-vault-enable":
            try:
                rt = open_runtime()
            except Exception as e:
                raise IAMError(f"cannot open the runtime store ({e}).")
            try:
                approver = web_approve_vault_enable(conn, rt, a.size, a.grant)
            finally:
                rt.close()
            return emit({"approved_by": approver}, [f"  ✓ approved by {approver}"])

        if a.cmd == "approve-exploit-action":
            action = {"op": f"action-{a.decision}", "agent": a.agent, "request_id": a.request_id,
                      "options_hash": a.options_hash, "owner": a.owner, "resource": ORG_RESOURCE}
            try:
                rt = open_runtime()
            except Exception as e:
                raise IAMError(f"cannot open the runtime store ({e}).")
            try:
                approver = web_approve_exploit_action(conn, rt, action, a.grant)
            finally:
                rt.close()
            return emit({"approved_by": approver}, [f"  ✓ approved by {approver}"])

        if a.cmd == "approve-context-edit":
            action = {"op": "edit-context", "kind": a.kind, "change": a.change, "resource": ORG_RESOURCE}
            if a.kind not in ("platform-skills", "org"):
                action["agent"] = a.agent or ""
            if a.change == "set":
                try:
                    with open(a.text_file or "", encoding="utf-8") as fh:
                        action["sha256"] = context_text_sha256(fh.read())
                except OSError as e:
                    raise IAMError(f"cannot read the new text: {e}")
            elif a.change == "revert":
                action["version"] = a.version or ""
            try:
                rt = open_runtime()
            except Exception as e:
                raise IAMError(f"cannot open the runtime store ({e}).")
            try:
                approver = web_approve_context_edit(conn, rt, action, a.grant)
            finally:
                rt.close()
            return emit({"approved_by": approver}, [f"  ✓ approved by {approver}"])

        if a.cmd == "mint-enrolment-link":
            try:
                rt = open_runtime()
            except Exception as e:
                raise IAMError(f"cannot open the runtime store ({e}).")
            link = mint_enrolment_token(rt, conn, a.name, a.actor)
            rt.close()
            return emit({"principal": a.name, "enrolment_token": link},
                        [f"  ONE-TIME ENROLMENT LINK (shown once, valid "
                         f"{ENROLMENT_TOKEN_TTL_S // 3600}h): {link}"])

        if a.cmd == "enrol-check":
            try:
                rt = open_runtime()
            except Exception as e:
                raise IAMError(f"cannot open the runtime store ({e}).")
            principal = enrolment_token_principal(rt, a.token)
            rt.close()
            if principal is None:
                raise IAMError("this enrolment link is invalid or has expired")
            # A candidate secret for the page to show — NOTHING is written;
            # enrol-consume proves a code from it before it becomes real,
            # the same two-step shape as `self mfa-start` / `mfa-confirm`.
            required, why = two_factor_required(conn, principal)
            secret = totp_generate_secret()
            uri = totp_uri(secret, principal)
            return emit({"principal": principal, "valid": True,
                         "totp_required": required, "totp_reason": why,
                         "totp_secret": secret, "otpauth_uri": uri,
                         "qr_svg": _qr_svg(uri)},
                        [f"  valid — for '{principal}'",
                         f"  2FA {'required' if required else 'optional'}: {why}"])

        if a.cmd == "enrol-consume":
            try:
                rt = open_runtime()
            except Exception as e:
                raise IAMError(f"cannot open the runtime store ({e}).")
            try:
                principal, codes = consume_enrolment_token(conn, rt, a.token, a.new,
                                                           a.totp_secret, a.totp_code)
            finally:
                rt.close()
            return emit({"principal": principal, "enrolled": True,
                         "totp_enrolled": bool(codes), "recovery_codes": codes},
                        [f"  ✓ account '{principal}' is ready — sign in with "
                         f"the new password"] +
                        (["  RECOVERY CODES (shown once):"] + [f"    {c}" for c in codes]
                         if codes else []))

        if a.cmd == "set-limit":
            stored = set_limit(conn, a.key, a.value)
            shown = "default" if a.value is None else a.value
            return emit({"key": a.key, "value": a.value, "stored_as": stored},
                        [f"  ✓ {a.key} = {shown}"])

        if a.cmd == "set-webauthn":
            set_webauthn_enabled(conn, a.value == "on")
            return emit({"webauthn_enabled": a.value == "on"},
                        [f"  ✓ WebAuthn/passkey sign-in is now {a.value}"])

        if a.cmd == "outputs-usage":
            data = {"total_used": outputs_usage_total(),
                    "total_limit": outputs_limit_total(conn)}
            lines = [f"  organisation: {data['total_used']:,} / "
                    f"{data['total_limit']:,} bytes"]
            if a.principal:
                data["principal"] = a.principal
                data["operator_used"] = outputs_usage_operator(a.principal)
                data["operator_limit"] = outputs_limit_operator(conn, a.principal)
                lines.append(f"  operator {a.principal!r}: {data['operator_used']:,} / "
                            f"{data['operator_limit']:,} bytes")
            return emit(data, lines)

        if a.cmd == "outputs-list":
            rows = list_outputs(principal=a.principal)
            body = [f"  {r['principal']:<16} {r['name']:<32} {r['bytes']:>12,} bytes" for r in rows]
            return emit(rows, ["promoted outputs:"] + (body or ["  (none)"]))

        if a.cmd == "outputs-delete":
            rows = delete_outputs(a.principal, a.name, a.by, conn=conn)
            lines = []
            for r in rows:
                if r.get("deleted"):
                    lines.append(f"  ✓ deleted output '{r['name']}' ({a.principal})")
                else:
                    lines.append(f"  ✗ {r['name']}: {r.get('error', 'unknown error')}")
            return emit(rows, lines)

        if a.cmd == "outputs-path":
            p = resolve_output_path(a.principal, a.name, a.by, conn=conn)
            return emit({"path": str(p)}, [f"  {p}"])

        if a.cmd == "tool-request-file":
            r = file_tool_request(a.by, a.category, a.text)
            return emit(r, [f"  ✓ filed tool request '{r['id']}'"])

        if a.cmd == "tool-request-list":
            rows = list_tool_requests()
            body = [f"  {r['created_at']!r:<18} {r['by']:<16} "
                    f"{r['category'] or '?':<14} {r['text'][:50]}" for r in rows]
            return emit(rows, ["tool requests:"] + (body or ["  (none)"]))

        if a.cmd == "bind":
            set_principal_role(conn, a.subject, a.role, a.actor)
            return emit({"subject_kind": "user", "subject": a.subject,
                         "role": a.role, "resource": ORG_RESOURCE, "effect": "allow"},
                        [f"  ✓ user '{a.subject}' is now {a.role} on {ORG_RESOURCE}",
                         f"    check it: sudo agenti admin can {a.subject} "
                         f"agent:start {ORG_RESOURCE}"])

        if a.cmd == "web-bind":
            rt = open_runtime()
            try:
                out = web_bind(conn, rt, a.principal, a.role, ORG_RESOURCE, a.grant)
            finally:
                rt.close()
            return emit(out, [f"  ✓ user '{out['principal']}' is now {out['role']} "
                              f"(approved by {out['approved_by']})"])

        if a.cmd == "web-unbind":
            out = web_unbind(conn, a.principal, a.role, ORG_RESOURCE)
            return emit(out, [f"  ✓ '{a.principal}' demoted to operator"
                              if out["removed"] else
                              f"  '{a.principal}' was already operator — nothing changed"])

        if a.cmd == "bindings":
            if a.principal:
                rows = list(conn.execute(
                    "SELECT name, role FROM principals WHERE name=? AND active=1",
                    (a.principal,)))
            else:
                rows = list(conn.execute(
                    "SELECT name, role FROM principals WHERE active=1 ORDER BY name"))
            data = [{"subject_kind": "user", "subject": r["name"],
                     "role": r["role"], "resource": ORG_RESOURCE,
                     "effect": "allow"} for r in rows]
            return emit(data, ["users and roles:"] + [
                f"  {d['subject']:<28} role={d['role']}" for d in data])

        if a.cmd == "issue-key":
            full = issue_key(conn, a.principal, a.actor, expires_days=a.expires_days)
            exp = f"expires in {a.expires_days} day(s)" if a.expires_days else "no expiry"
            if a.json:
                print(_json.dumps(public_json({"principal": a.principal, "key": full,
                                               "prefix": full.split("_")[1],
                                               "expires_days": a.expires_days})))
            else:
                print()
                print("  ============================================================")
                print(f"   API KEY for '{a.principal}' — shown once, save it now ({exp}):")
                print()
                print(f"   {full}")
                print()
                print("   Use it as:  Authorization: Bearer <key>")
                print("  ============================================================")
            return 0

        if a.cmd == "revoke-key":
            revoke_key(conn, a.prefix)
            return emit({"prefix": a.prefix, "revoked": True},
                        [f"  ✓ revoked key {a.prefix} — it stops working on the next request"])

        if a.cmd == "list-keys":
            sql = "SELECT * FROM api_keys"
            args_: tuple = ()
            if a.principal:
                sql += " WHERE principal = ?"; args_ = (a.principal,)
            rows = list(conn.execute(sql + " ORDER BY created_at DESC", args_))
            usage: dict[str, float] = {}
            try:
                rt = open_runtime()
                usage = {r["prefix"]: r["last_used"] for r in rt.execute(
                    "SELECT prefix, last_used FROM key_usage")}
                rt.close()
            except Exception:
                pass  # last-used is a nicety; never fail a listing over it

            def state(r) -> str:
                if r["revoked_at"]:
                    return "REVOKED"
                if r["expires_at"] and r["expires_at"] < time.time():
                    return "EXPIRED"
                return "active"
            data = [{"prefix": r["prefix"], "principal": r["principal"],
                     "state": state(r), "created_at": r["created_at"],
                     "expires_at": r["expires_at"],
                     "last_used": usage.get(r["prefix"])} for r in rows]
            def when(v): return time.strftime("%Y-%m-%d", time.localtime(v)) if v else "never"
            return emit(data, ["keys:"] + [
                f"  {d['prefix']}  {d['principal']:<18} {d['state']:<8} "
                f"last used {when(d['last_used'])}" for d in data])

        if a.cmd == "can":
            # check() itself doesn't validate the resource SHAPE — it just
            # compares whatever string it is given; the only resource is the
            # organisation, so there is nothing for the caller to type.
            d = check(conn, a.principal, a.permission, ORG_RESOURCE)
            lines = [f"  {'ALLOW' if d.allowed else 'DENY '}  {a.principal} "
                     f"{a.permission} on {ORG_RESOURCE}", f"  reason: {d.reason}"]
            if d.matched:
                lines.append("  bindings considered:")
                lines += [f"    {m}" for m in d.matched]
            return emit(d.as_dict(), lines)

        if a.cmd == "bootstrap":
            full = bootstrap(conn, a.principal, a.actor)
            if a.json:
                print(_json.dumps(public_json({"principal": a.principal, "key": full,
                                               "prefix": full.split("_")[1], "bootstrapped": True})))
            else:
                print(f"  ✓ user '{a.principal}' created with role 'admin'")
                print()
                print("  ============================================================")
                print(f"   FIRST API KEY for '{a.principal}' — shown once, save it now:")
                print()
                print(f"   {full}")
                print()
                print("   Use it as:  Authorization: Bearer <key>")
                print("  ============================================================")
                print()
                print("  next:")
                print(f"    sudo agenti admin user set-password {a.principal}   (for GUI login)")
                print(f"    sudo agenti admin can {a.principal} agent:start")
            return 0

        if a.cmd == "set-policy":
            known = ("require-separate-approver", "update-check")
            # require-2fa, in its two shapes (see two_factor_required()):
            # organisation-wide, or per account. Per account names a
            # principal that must exist, so a typo cannot create a dangling
            # exemption that springs to life when that name is created later.
            _m2 = None
            _m3 = re.match(rf"^{TWO_FACTOR_POLICY_KEY}:([a-z0-9][a-z0-9_-]{{0,63}})$", a.key)
            if _m3 and conn.execute("SELECT 1 FROM principals WHERE name=?",
                                    (_m3.group(1),)).fetchone() is None:
                raise IAMError(f"no user named {_m3.group(1)!r} — the per-account "
                               f"policy names an existing account")
            if a.key not in known and a.key != TWO_FACTOR_POLICY_KEY and not (_m2 or _m3):
                raise IAMError(f"unknown policy {a.key!r}. Known: {', '.join(known)}, "
                               f"{TWO_FACTOR_POLICY_KEY}, {TWO_FACTOR_POLICY_KEY}:<user>")
            set_setting(conn, a.key, a.value)
            extra = []
            if (a.key == TWO_FACTOR_POLICY_KEY or _m2 or _m3) and a.value == "off":
                extra = ["    accounts this covers may now sign up and sign in with a",
                         "    password alone — an explicit weakening, recorded here"]
            if a.key == "update-check" and a.value == "on":
                extra = ["    an admin can now ask GitHub whether a newer release exists",
                         "    (sudo agenti admin update-check, or the Platform tab). It only",
                         "    reports: nothing is downloaded or installed, and no request is",
                         "    made until someone asks"]
            if a.key == "require-separate-approver" and a.value == "on":
                extra = ["    a commercial run is now refused when the approving user",
                         "    is the same one starting it — real segregation of duties"]
            return emit({"policy": a.key, "value": a.value},
                        [f"  ✓ policy {a.key} = {a.value}"] + extra)

        if a.cmd == "authz-log":
            # runtime.db is 0700 agenti-api so the API can write it, which also
            # means it is unreadable without root — an authorization audit
            # trail nobody can read is not an audit trail. This is the root-side
            # reader, the same gap `agenti <agent> audit` closes for
            # the in-vault agent audit log.
            try:
                rt = open_runtime()
            except Exception as e:
                raise IAMError(f"cannot open the runtime store ({e}). It is created "
                               f"at install; recreate it with: sudo dpkg-reconfigure agenti")
            sql = "SELECT * FROM authz_log"
            where, args_ = [], []
            if a.principal:
                where.append("principal = ?"); args_.append(a.principal)
            if a.denied_only:
                where.append("decision = 'deny'")
            if where:
                sql += " WHERE " + " AND ".join(where)
            rows = list(rt.execute(sql + " ORDER BY id DESC LIMIT ?", (*args_, a.n)))
            rt.close()
            data = [{"ts": r["ts"], "principal": r["principal"],
                     "permission": r["permission"], "resource": r["resource"],
                     "decision": r["decision"], "reason": r["reason"],
                     "via": r["via"]} for r in rows]
            return emit(data, ["authorization decisions (newest first):"] + [
                f"  {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(d['ts']))} "
                f"{d['decision']:<5} {str(d['principal']):<16} "
                f"{str(d['permission']):<18} {d['resource']}" for d in data])

        if a.cmd == "policy":
            data = {k: get_setting(conn, k, "off") for k in
                    ("require-separate-approver", WEBAUTHN_ENABLED_KEY, "update-check")}
            # require-2fa defaults ON — the one policy whose absence means the
            # strict answer — then every account override ever set.
            data[TWO_FACTOR_POLICY_KEY] = get_setting(conn, TWO_FACTOR_POLICY_KEY, "on")
            for r in conn.execute("SELECT key, value FROM settings WHERE key LIKE "
                                  "'require-2fa:%' ORDER BY key"):
                data[r["key"]] = r["value"]
            return emit(data, ["policies:"] + [f"  {k:<40} {v}" for k, v in data.items()])

        raise IAMError(f"unhandled command {a.cmd!r}")

    except IAMError as e:
        if a.json:
            print(_json.dumps({"error": str(e)}))
        else:
            print(f"\nerror: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(_main())
