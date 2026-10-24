#!/usr/bin/env python3
"""
authd.py — the privileged login, session and authorization service
(CLAUDE.md §4 item 23).

WHY THIS PROCESS EXISTS
-----------------------
Until it did, the web API (shared/api/) authenticated people itself: it read
password hashes and TOTP secrets out of iam.db, and it owned runtime.db, the
file that holds sessions. That meant a compromised API process could forge a
session for ANY existing principal, read every TOTP secret and compute codes,
extend or revive sessions, clear lockout counters, and rewrite the authz
audit log — the record of its own decisions. CLAUDE.md §4 item 21 named this
as the residual risk the "authority rule" could not close and said the real
fix was a separate privileged process. This is that process.

Now the API holds NO identity data and NO session store. It speaks to this
daemon over a Unix socket, and this daemon is the only thing that can:

    - verify a password or a second factor (it alone reads iam.db),
    - create, rotate, look up or revoke a session (it alone writes runtime.db),
    - answer "may <principal> do <permission> on <resource>?" and log it.

What a compromised API can STILL do, stated so nobody mistakes this for
more than it is: it terminates TLS, so it sees a password and a TOTP code in
flight at login and could use them once, right then; it can ride any session
whose cookie it is handed, because it is the request path; and it can call
the narrow set of `sudo agenti ...` verbs its sudoers grant allows. It cannot
mint a session for someone who is not logging in, cannot read a hash or a
secret, and cannot alter the audit trail. The next arc — a per-request
authorization grant the root CLI itself verifies — is what would shrink the
sudo path too; the `authorize` op here is shaped so that can be added
without a redesign.

WHO MAY CONNECT
---------------
Two layers, both enforced here, neither relying on the other:
  1. the socket is 0660, group agenti-sock, a group whose only members are
     the API account and this daemon's account — so no other local account
     can even connect; and
  2. every accepted connection's peer uid is read from the kernel
     (SO_PEERCRED) and must be one of --allow-user. Root included is NOT an
     exception: root has no business here (the root CLI writes runtime.db
     directly through iam.py), and refusing it is what lets
     `agenti verify` prove the check exists by connecting as root.

PROTOCOL
--------
One request per connection: a single JSON object terminated by a newline,
answered by a single JSON object terminated by a newline, then the
connection closes. Every response carries "ok". A refusal carries "status"
(the HTTP status the API should relay) and "error" (the message, written to
the same bar as every other error in this project). Requests are capped at
MAX_REQUEST_BYTES and every read has a timeout, so a stuck client cannot
hold a handler thread forever.

This module is importable without starting anything: `Service.handle()` is
a pure request→response function over two SQLite paths, which is what
shared/test_authd.py drives. Only main() touches a socket.
"""

from __future__ import annotations

import argparse
import grp
import json
import re
import os
import pwd
import secrets
import signal
import socket
import socketserver
import sqlite3
import struct
import sys
import threading
import time
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import iam  # noqa: E402
import webauthn_lite  # noqa: E402

SERVICE_NAME = "agenti-authd"
PROTOCOL_VERSION = 1
DEFAULT_SOCKET = "/run/agenti/authd.sock"
DEFAULT_ALLOW_USER = "agenti-api"
DEFAULT_SOCKET_GROUP = "agenti-sock"

MAX_REQUEST_BYTES = 64 * 1024
IO_TIMEOUT_S = 10.0

# Session lifetimes. Sliding for a real session: an active one renews, an
# idle one expires. A half-finished login (password accepted, TOTP not yet
# supplied) is a credential in its own right and gets a deliberately tiny
# lifetime — and it does NOT slide, so polling cannot keep it alive.
SESSION_TTL_S = 8 * 60 * 60
PENDING_TTL_S = 5 * 60

# Bounds on every string field a caller may send. Generous for real use,
# tight enough that a hostile API process cannot make this daemon chew on
# megabytes of "principal".
MAX_NAME = 64
MAX_SECRET = 1024
MAX_TOKEN = 256
MAX_RESOURCE = 512
MAX_CANDIDATES = 1000
# WebAuthn payloads are real binary data (a public key, a CBOR attestation
# object) base64url-encoded — meaningfully bigger than a password or a TOTP
# code, but still bounded: a real attestationObject is a few hundred bytes,
# not megabytes.
MAX_WEBAUTHN_FIELD = 8 * 1024

# Same module-level-constant-from-env-var pattern iam.py already uses for
# IAM_DB_PATH/RUNTIME_DB_PATH. Read once at import time, set by configure.sh
# on THIS unit only (agenti gui configure --hostname) — the API/GUI never hold their own copy,
# they only ever ask this process for it (op_webauthn_config below).
WEBAUTHN_RP_ID = os.environ.get("AGENTI_HOSTNAME", "")
WEBAUTHN_ORIGIN = os.environ.get("AGENTI_ORIGIN", "")


class AuthError(Exception):
    """A refusal the API should relay as-is: `status` is the HTTP status,
    `message` the text, `extra` any structured detail (retry_after)."""

    def __init__(self, status: int, message: str, **extra):
        super().__init__(message)
        self.status = status
        self.message = message
        self.extra = extra


# ---------------------------------------------------------------------------
# Session store — moved here, verbatim in behaviour, from api/sessions.py.
# Server-side rows, never JWTs: this platform launches network tools against
# client networks, so "disable that account NOW" has to mean now, and a row
# can be deleted while a signed token cannot be un-signed.
# ---------------------------------------------------------------------------
def create_session(runtime: sqlite3.Connection, principal: str, *,
                   pending_totp: bool = False) -> dict:
    sid = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(24)
    now = time.time()
    ttl = PENDING_TTL_S if pending_totp else SESSION_TTL_S
    runtime.execute(
        "INSERT INTO sessions(id, principal, csrf, created_at, expires_at,"
        " last_seen, pending_totp) VALUES (?,?,?,?,?,?,?)",
        (sid, principal, csrf, now, now + ttl, now, 1 if pending_totp else 0))
    runtime.commit()
    return {"session_id": sid, "principal": principal, "csrf": csrf,
            "pending": pending_totp}


def rotate_session(runtime: sqlite3.Connection, old_sid: str) -> dict:
    """Second factor accepted: the pending session is REPLACED by a real one
    with a fresh id, not flipped in place. Rotating the id on privilege
    change is the standard session-fixation defence."""
    row = runtime.execute("SELECT principal FROM sessions WHERE id=?", (old_sid,)).fetchone()
    if row is None:
        raise AuthError(401, "session expired — start again")
    new = create_session(runtime, row["principal"], pending_totp=False)
    runtime.execute("DELETE FROM sessions WHERE id=?", (old_sid,))
    runtime.commit()
    return new


def lookup_session(runtime: sqlite3.Connection, sid: str) -> dict | None:
    row = runtime.execute("SELECT * FROM sessions WHERE id=?", (sid,)).fetchone()
    if row is None:
        return None
    if row["revoked_at"] or row["expires_at"] < time.time():
        runtime.execute("DELETE FROM sessions WHERE id=?", (sid,))
        runtime.commit()
        return None
    if not row["pending_totp"]:
        runtime.execute("UPDATE sessions SET last_seen=?, expires_at=? WHERE id=?",
                        (time.time(), time.time() + SESSION_TTL_S, sid))
        runtime.commit()
    return {"session_id": row["id"], "principal": row["principal"],
            "csrf": row["csrf"], "pending": bool(row["pending_totp"])}


def revoke_session(runtime: sqlite3.Connection, sid: str) -> None:
    runtime.execute("DELETE FROM sessions WHERE id=?", (sid,))
    runtime.commit()


def revoke_all_for(runtime: sqlite3.Connection, principal: str) -> int:
    n = runtime.execute("DELETE FROM sessions WHERE principal=?", (principal,)).rowcount
    runtime.commit()
    return n


def purge_expired(runtime: sqlite3.Connection) -> None:
    runtime.execute("DELETE FROM sessions WHERE expires_at < ?", (time.time(),))
    runtime.commit()


# ---------------------------------------------------------------------------
# Request validation. Every field is type- and length-checked before it
# reaches SQLite or scrypt. A wrong type is a 400 naming the field — the
# API is the only legitimate caller and a malformed request from it is a
# bug worth a clear message, not a traceback.
# ---------------------------------------------------------------------------
def _str(req: dict, field: str, max_len: int, *, required: bool = True) -> str:
    v = req.get(field)
    if v is None:
        if required:
            raise AuthError(400, f"request is missing the field {field!r}")
        return ""
    if not isinstance(v, str):
        raise AuthError(400, f"field {field!r} must be a string")
    if len(v) > max_len:
        raise AuthError(400, f"field {field!r} is longer than {max_len} characters")
    return v


def _credential_bytes(req: dict, *keys: str) -> bytes:
    """Walk a nested path (e.g. "credential", "response", "clientDataJSON")
    into the request, expecting a base64url string at the end, and return
    the decoded bytes. Mirrors the shape navigator.credentials.create()/
    .get() actually produce once every ArrayBuffer is base64url-encoded for
    JSON transport (PublicKeyCredential.toJSON()) — the GUI's JS does that
    encoding, never this process."""
    node = req
    path = "request"
    for k in keys:
        path = f"{path}.{k}"
        if not isinstance(node, dict) or k not in node:
            raise AuthError(400, f"request is missing {path!r}")
        node = node[k]
    if not isinstance(node, str):
        raise AuthError(400, f"field {path!r} must be a base64url string")
    if len(node) > MAX_WEBAUTHN_FIELD:
        raise AuthError(400, f"field {path!r} is longer than {MAX_WEBAUTHN_FIELD} characters")
    try:
        return webauthn_lite.b64url_decode(node)
    except webauthn_lite.WebAuthnError as e:
        raise AuthError(400, f"field {path!r} is not valid base64url: {e}")


def _credential_id_str(req: dict) -> str:
    """The credential id travels as opaque base64url TEXT everywhere in
    storage (iam.db, action grants) — never decoded to raw bytes outside
    webauthn_lite's own parsing — so this validates it without decoding."""
    node = req.get("credential")
    if not isinstance(node, dict) or not isinstance(node.get("id"), str):
        raise AuthError(400, "request is missing 'credential.id'")
    cid = node["id"]
    if not cid or len(cid) > MAX_WEBAUTHN_FIELD:
        raise AuthError(400, "field 'credential.id' is empty or too long")
    return cid


def _require_webauthn_configured(conn) -> None:
    if not WEBAUTHN_RP_ID or not WEBAUTHN_ORIGIN:
        raise AuthError(503, "WebAuthn/passkeys are not configured on this deployment "
                             "— it needs a real domain: sudo agenti gui configure --hostname <domain>")
    if not iam.webauthn_enabled(conn):
        raise AuthError(503, "WebAuthn/passkey sign-in is turned off on this deployment. "
                             "An admin can enable it: sudo agenti admin set-webauthn on")


class Service:
    """The request→response core. One instance per process; every call opens
    its own SQLite connections (fresh, per request — a long-lived read
    connection would keep serving a key the CLI has since revoked, exactly
    the reason rbac.py opened per request when it did this job)."""

    def __init__(self, iam_path: Path | None = None, runtime_path: Path | None = None):
        self.iam_path = iam_path
        self.runtime_path = runtime_path

    # -- plumbing ----------------------------------------------------------
    def _iam(self) -> sqlite3.Connection:
        return iam.open_iam(readonly=True, path=self.iam_path)

    def _runtime(self) -> sqlite3.Connection:
        return iam.open_runtime(self.runtime_path)

    def handle(self, request) -> dict:
        try:
            if not isinstance(request, dict):
                raise AuthError(400, "request must be a JSON object")
            op = request.get("op")
            if not isinstance(op, str) or not op.isidentifier() or op.startswith("_"):
                raise AuthError(400, "request has no valid 'op'")
            fn = getattr(self, f"op_{op}", None)
            if fn is None:
                raise AuthError(400, f"unknown op {op!r}")
            out = fn(request)
            out.setdefault("ok", True)
            return out
        except AuthError as e:
            return {"ok": False, "status": e.status, "error": e.message, **e.extra}
        except iam.IAMError as e:
            # The identity store is missing or unreadable: the service is up,
            # its data is not. 503 with iam.py's own message, which names
            # the bootstrap command.
            return {"ok": False, "status": 503, "error": str(e)}
        except Exception:
            ref = secrets.token_hex(4)
            print(f"[{SERVICE_NAME}] internal error ref={ref}", file=sys.stderr)
            traceback.print_exc()
            return {"ok": False, "status": 500,
                    "error": f"internal error in {SERVICE_NAME} (ref {ref}) — "
                             f"see: journalctl -u {SERVICE_NAME}"}

    # -- ops ---------------------------------------------------------------
    def op_ping(self, req: dict) -> dict:
        return {"service": SERVICE_NAME, "protocol": PROTOCOL_VERSION}

    def op_login(self, req: dict) -> dict:
        """Step one: password. On success a session exists — PENDING if the
        principal has 2FA enrolled, in which case the csrf is withheld and
        every real route refuses it until op_totp promotes it."""
        principal = _str(req, "principal", MAX_NAME)
        password = _str(req, "password", MAX_SECRET)
        addr = _str(req, "addr", MAX_NAME, required=False)
        conn, rt = self._iam(), self._runtime()
        try:
            purge_expired(rt)
            result = iam.verify_login(conn, rt, principal, password, addr=addr)
            if not result.ok:
                # 429 when throttled so a client can tell "wrong password"
                # from "stop trying"; the MESSAGE stays generic either way.
                status = 429 if result.retry_after else 401
                raise AuthError(status, result.reason, retry_after=result.retry_after)
            sess = create_session(rt, result.principal, pending_totp=result.totp_required)
            return {"principal": result.principal,
                    "totp_required": result.totp_required,
                    # No second factor enrolled, under a policy that requires
                    # one: the session is real but the API confines it to the
                    # self-service MFA routes (rbac.py) until enrolment is done.
                    "mfa_setup_required": (not result.totp_required
                                           and iam.mfa_setup_required(conn, result.principal)),
                    "must_change_password": result.must_change_password,
                    "session_id": sess["session_id"],
                    "pending": sess["pending"],
                    "csrf": None if sess["pending"] else sess["csrf"]}
        finally:
            conn.close(); rt.close()

    def op_totp(self, req: dict) -> dict:
        sid = _str(req, "session_id", MAX_TOKEN)
        code = _str(req, "code", MAX_NAME)
        addr = _str(req, "addr", MAX_NAME, required=False)
        conn, rt = self._iam(), self._runtime()
        try:
            sess = lookup_session(rt, sid)
            if sess is None or not sess["pending"]:
                raise AuthError(401, "no pending login — POST /auth/login first")
            result = iam.verify_second_factor(conn, rt, sess["principal"], code, addr=addr)
            if not result.ok:
                status = 429 if result.retry_after else 401
                raise AuthError(status, result.reason, retry_after=result.retry_after)
            new = rotate_session(rt, sid)
            return {"principal": new["principal"], "session_id": new["session_id"],
                    "csrf": new["csrf"], "note": result.reason}
        finally:
            conn.close(); rt.close()

    def op_logout(self, req: dict) -> dict:
        sid = _str(req, "session_id", MAX_TOKEN)
        rt = self._runtime()
        try:
            revoke_session(rt, sid)
        finally:
            rt.close()
        return {"logged_out": True}

    def op_authenticate(self, req: dict) -> dict:
        """Resolve a session cookie to a principal, sliding its expiry. The
        messages are the ones rbac.py used to raise itself, unchanged, so
        the GUI's handling of them did not have to move."""
        sid = _str(req, "session_id", MAX_TOKEN)
        conn, rt = self._iam(), self._runtime()
        try:
            sess = lookup_session(rt, sid)
            if sess is None:
                raise AuthError(401, "session expired or revoked — sign in again")
            if sess["pending"]:
                raise AuthError(401, "second factor required — POST the code to /auth/totp")
            # A disabled principal must lose access immediately, not at
            # session expiry: re-read, never trusted from the session row.
            row = conn.execute("SELECT active, totp_secret FROM principals WHERE name=?",
                               (sess["principal"],)).fetchone()
            if row is None or not row["active"]:
                revoke_session(rt, sid)
                raise AuthError(401, "account is disabled — session ended")
            # Re-read per request, like `active`: the moment the person
            # enrols, the confinement lifts without a new login; the moment
            # an admin turns the policy on, every password-only session is
            # confined on its very next call.
            return {"principal": sess["principal"], "csrf": sess["csrf"],
                    "totp_enrolled": bool(row["totp_secret"]),
                    "mfa_setup_required": (not row["totp_secret"]
                                           and iam.mfa_setup_required(conn, sess["principal"]))}
        finally:
            conn.close(); rt.close()

    def op_authenticate_key(self, req: dict) -> dict:
        presented = _str(req, "key", MAX_TOKEN)
        conn, rt = self._iam(), self._runtime()
        try:
            result = iam.authenticate_key(conn, presented)
            if not result.ok:
                # Logged with the PREFIX, never the presented secret; one
                # uniform message for every rejection path so a caller
                # cannot enumerate valid prefixes. '-' = no particular
                # resource (a failed sign-in isn't scoped to one); older rows
                # say '*', from before that spelling was retired.
                iam.log_decision(rt, iam.Decision(False, result.prefix or "?",
                                                  "authenticate", "-", result.reason), "api")
                raise AuthError(401, result.reason)
            if result.prefix:
                iam.record_key_use(rt, result.prefix)
            return {"principal": result.principal, "prefix": result.prefix}
        finally:
            conn.close(); rt.close()

    def op_authorize(self, req: dict) -> dict:
        """THE decision, and its audit row — written by this process, which
        the API cannot reach, so the record of what the web tier was allowed
        to do is no longer kept by the web tier."""
        principal = _str(req, "principal", MAX_NAME)
        permission = _str(req, "permission", MAX_NAME)
        resource = iam.ORG_RESOURCE   # the organisation is the only resource
        via = _str(req, "via", MAX_NAME, required=False) or "api"
        conn, rt = self._iam(), self._runtime()
        try:
            decision = iam.check(conn, principal, permission, resource)
            iam.log_decision(rt, decision, via)
            return {"allowed": decision.allowed, "reason": decision.reason}
        finally:
            conn.close(); rt.close()

    def op_can(self, req: dict) -> dict:
        """A bare yes/no for result FILTERING — no audit row, or a listing
        would write one per candidate and drown the log."""
        principal = _str(req, "principal", MAX_NAME)
        permission = _str(req, "permission", MAX_NAME)
        resource = iam.ORG_RESOURCE   # the organisation is the only resource
        conn = self._iam()
        try:
            return {"allowed": iam.check(conn, principal, permission, resource).allowed}
        finally:
            conn.close()

    def op_permissions(self, req: dict) -> dict:
        principal = _str(req, "principal", MAX_NAME)
        resource = iam.ORG_RESOURCE   # the organisation is the only resource
        conn = self._iam()
        try:
            perms, _ = iam.effective_permissions(conn, principal, resource)
            role = iam.effective_role_name(conn, principal, resource)
            return {"permissions": sorted(perms), "role": role}
        finally:
            conn.close()

    # Every op a web-tier approval grant may be minted for. "bind" is the
    # original bounded grant (§4 item 24); the four lifecycle ops were added
    # when rename/delete of a user became reachable from the GUI;
    # reset-password/reset-mfa were added when the operator asked for a
    # global admin to be able to reset another user's password or MFA from
    # the GUI (previously CLI-only, per the authority rule — see iam.py's
    # reset_principal_password for why revisiting that is safe now).
    # action-approve/action-reject (and their legacy exploit-* aliases) were
    # added so plugin agents' per-action approvals can be answered from the GUI.
    # Unlike the other ops here, the bar re-checked is agent:chat (the run's
    # own owner), not iam:manage, because approving a live module is an operator
    # deciding on their OWN run, not an admin-wide action.
    # A grant is hashed to its whole action dict, so an op not in this table
    # cannot be approved at all, and a grant minted for one action can never
    # be spent on another.
    GRANT_OPS = ("create-user", "engagement-set", "engagement-approve", "bind", "rename-principal", "delete-principal", "enable-principal",
                 "reset-password", "reset-mfa",
                 "edit-context", "build-agent", "remove-agent", "update-agent", "edit-catalog",
                 "action-approve", "action-reject", "vault-enable",
                 "exploit-approve", "exploit-reject")  # kept as aliases

    @staticmethod
    def _grant_field(action: dict, key: str, *, kind: str = "name", max_len: int = MAX_RESOURCE) -> str:
        v = action.get(key)
        if not isinstance(v, str) or not v or len(v) > max_len:
            raise AuthError(400, f"action.{key} must be a non-empty string")
        if kind == "name":
            try:
                iam.validate_name(v, key)
            except iam.IAMError as e:
                raise AuthError(400, str(e))
        return v

    @classmethod
    def _validate_action(cls, req: dict) -> dict:
        """Shared by every path that mints a web-grant approval (password/
        TOTP and, since the passkey option, WebAuthn too): the bound is
        checked before any credential is spent at all, so a request for
        something the CLI would refuse anyway costs neither a TOTP code nor
        a passkey ceremony. Returns the clean action dict to mint the grant
        from — the SAME dict the root CLI re-derives from its own arguments
        and compares by hash, so nothing the API relays can re-target it.

        Validating the SHAPE here is not the authorization decision: every
        consuming verb re-checks, fresh, that the approver actually holds
        the permission on `resource`, taking the approver's identity from
        the grant row rather than from anything the API claims."""
        action = req.get("action")
        if not isinstance(action, dict) or action.get("op") not in cls.GRANT_OPS:
            raise AuthError(400, "field 'action' must be an object whose op is one of "
                                 + ", ".join(cls.GRANT_OPS))
        op = action["op"]
        # Every op carries the one resource there is — the organisation — so
        # a grant is bound to it; the CLI re-checks the approver holds the
        # permission on it.
        resource = action.get("resource", iam.ORG_RESOURCE)
        if resource != iam.ORG_RESOURCE:
            raise AuthError(400, f"action.resource must be {iam.ORG_RESOURCE!r}, not {resource!r}")
        if op == "bind":
            principal = cls._grant_field(action, "principal")
            role = cls._grant_field(action, "role", kind="raw")
            if role not in iam.WEB_GRANTABLE_ROLES:
                raise AuthError(400, f"the web tier may grant only "
                                     f"{' or '.join(iam.WEB_GRANTABLE_ROLES)}, not {role!r}")
            try:
                iam.web_grant_resource(role, resource)
            except iam.IAMError as e:
                raise AuthError(400, str(e))
            return {"op": op, "principal": principal, "role": role, "resource": resource}

        if op in ("engagement-set", "engagement-approve"):
            # Writing or approving the engagement from the web (audit run 1,
            # F13): a set is bound to the SHA-256 of the exact change the CLI
            # receives, an approval to the digest of the version the admin
            # reviewed. Neither can be spent on anything else.
            key = "sha256" if op == "engagement-set" else "digest"
            bound = cls._grant_field(action, key, kind="raw", max_len=64)
            if not re.fullmatch(r"[0-9a-f]{64}", bound):
                raise AuthError(400, f"action.{key} must be a SHA-256 hex digest")
            return {"op": op, key: bound, "resource": resource}

        if op == "create-user":
            # Creating an account from the web (operator decision 2026-10-22,
            # audit run 1): one re-authenticated grant at the end of the
            # New-user wizard, bound to the name, the kind and the role it is
            # created with. Without it the web tier cannot create an account.
            principal = cls._grant_field(action, "principal")
            kind = cls._grant_field(action, "kind", kind="raw", max_len=16)
            if kind not in ("user", "service"):
                raise AuthError(400, "action.kind must be user or service")
            role = cls._grant_field(action, "role", kind="raw", max_len=16)
            if role not in iam.WEB_GRANTABLE_ROLES:
                raise AuthError(400, f"the web tier may create only "
                                     f"{' or '.join(iam.WEB_GRANTABLE_ROLES)} accounts, not {role!r}")
            return {"op": op, "principal": principal, "kind": kind, "role": role, "resource": resource}

        if op in ("reset-password", "reset-mfa"):
            principal = cls._grant_field(action, "principal")
            clean = {"op": op, "principal": principal, "resource": resource}
            if op == "reset-password":
                mode = action.get("mode")
                if mode not in ("direct", "link"):
                    raise AuthError(400, "action.mode for reset-password must be "
                                         "'direct' or 'link'")
                clean["mode"] = mode
                if mode == "direct":
                    clean["new_password"] = cls._grant_field(
                        action, "new_password", kind="raw", max_len=MAX_SECRET)
            return clean

        if op == "edit-catalog":
            # Adding/changing/removing a command-line program in the catalog
            # admins pick from. Add/update are bound to the SHA-256 of the
            # exact normalized entry.
            change = cls._grant_field(action, "change", kind="raw", max_len=16)
            if change not in ("add", "update", "remove"):
                raise AuthError(400, "action.change must be add, update or remove")
            clean = {"op": op, "name": cls._grant_field(action, "name", kind="raw", max_len=64),
                     "change": change, "resource": resource}
            if change != "remove":
                sha = cls._grant_field(action, "sha256", kind="raw", max_len=64)
                if not re.fullmatch(r"[0-9a-f]{64}", sha):
                    raise AuthError(400, "action.sha256 must be a SHA-256 hex digest")
                clean["sha256"] = sha
            return clean

        if op == "vault-enable":
            # Turning the vault on from Settings → Platform (decision 6). Bound
            # to the container size; the passphrase never comes here at all.
            size = cls._grant_field(action, "size", kind="raw", max_len=8)
            if not re.fullmatch(r"[1-9][0-9]{0,3}G", size):
                raise AuthError(400, "action.size must be whole gigabytes, like 8G")
            return {"op": op, "size": size, "resource": resource}

        if op in ("build-agent", "remove-agent", "update-agent"):
            # Building or removing a whole agent (Settings -> Agents). A build
            # is bound to the SHA-256 of the exact normalized spec
            # (agent_builder.spec_sha256), so an approval for one set of
            # programs or instructions can never be spent on another.
            clean = {"op": op, "name": cls._grant_field(action, "name"), "resource": resource}
            if op in ("build-agent", "update-agent"):
                sha = cls._grant_field(action, "sha256", kind="raw", max_len=64)
                if not re.fullmatch(r"[0-9a-f]{64}", sha):
                    raise AuthError(400, "action.sha256 must be a SHA-256 hex digest")
                clean["sha256"] = sha
            return clean

        if op == "edit-context":
            # An edit to one of the instruction files (shared/context_store.py).
            # The grant names the file, what is being done and, for a save,
            # the SHA-256 of the EXACT text — so a grant approved for one text
            # can never be spent on another.
            kind = cls._grant_field(action, "kind", kind="raw", max_len=32)
            change = cls._grant_field(action, "change", kind="raw", max_len=16)
            if kind not in ("system-prompt", "skills", "platform-skills", "org"):
                raise AuthError(400, f"action.kind {kind!r} cannot be edited through the web")
            if change not in ("set", "reset", "revert"):
                raise AuthError(400, "action.change must be set, reset or revert")
            clean = {"op": op, "kind": kind, "change": change, "resource": resource}
            if kind not in ("platform-skills", "org"):
                clean["agent"] = cls._grant_field(action, "agent")
            if change == "set":
                sha = cls._grant_field(action, "sha256", kind="raw", max_len=64)
                if not re.fullmatch(r"[0-9a-f]{64}", sha):
                    raise AuthError(400, "action.sha256 must be a SHA-256 hex digest")
                clean["sha256"] = sha
            elif change == "revert":
                ver = cls._grant_field(action, "version", kind="raw", max_len=40)
                if not re.fullmatch(r"\d+-[0-9a-f]{12}", ver):
                    raise AuthError(400, "action.version is not a saved version id")
                clean["version"] = ver
            return clean

        if op in ("action-approve", "action-reject",
                  "exploit-approve", "exploit-reject"):  # exploit-* kept as aliases
            # Bound to the exact pending request (its id) AND the exact
            # options it was proposed with (options_hash, from the pending
            # record) — so a grant approved for what the operator actually
            # saw can never be replayed against a request that was edited
            # or superseded in between.
            agent = cls._grant_field(action, "agent")
            request_id = cls._grant_field(action, "request_id", kind="raw", max_len=32)
            options_hash = cls._grant_field(action, "options_hash", kind="raw", max_len=64)
            if not re.fullmatch(r"[0-9a-f]{8,32}", request_id):
                raise AuthError(400, "action.request_id is not a request id")
            if not re.fullmatch(r"[0-9a-f]{16,64}", options_hash):
                raise AuthError(400, "action.options_hash is not an options hash")
            # ...and to the run's OWNER (audit run 1, F26): only the operator
            # whose run proposed it may decide it, so a grant one operator
            # approves can never be spent on another operator's request. The
            # legacy exploit-* names are the same grant.
            return {"op": op.replace("exploit-", "action-"), "agent": agent,
                    "request_id": request_id, "options_hash": options_hash,
                    "owner": cls._grant_field(action, "owner"), "resource": resource}

        clean = {"op": op, "principal": cls._grant_field(action, "principal"),
                 "resource": resource}
        if op == "rename-principal":
            clean["new_name"] = cls._grant_field(action, "new_name")
        return clean

    @classmethod
    def _grant_requires_password(cls, clean: dict) -> bool:
        """A bind never requires the password any more (iam.
        WEB_GRANT_PASSWORD_ROLES is empty — a fresh 2FA code alone already
        defeats the attack this exists for, see that tuple's own comment);
        every other op still requires it unconditionally, because each one
        either destroys an account, re-points an identity every audit
        record refers to, or hands someone else's password/2FA to whoever
        performs the reset — a materially bigger stake than a permission
        grant."""
        if clean["op"] == "bind":
            return iam.web_grant_requires_password(clean["role"])
        return True

    def op_approve_action(self, req: dict) -> dict:
        """Re-verify the session's current 2FA code — and, for the four
        lifecycle ops (rename/delete principal), the session's
        password too (see _grant_requires_password) — then mint a
        single-use approval grant bound to exactly `action`. This is the
        privileged half of the bounded web grant (§4 item 24): the API
        relays the credentials and gets back an opaque id it can carry to
        the root CLI but cannot alter, forge, or spend on a different
        action — the grant lives in runtime.db, which the API cannot open.

        Every call checks the credential: there is no grace window (operator
        decision 2026-10-23, audit run 2)."""
        sid = _str(req, "session_id", MAX_TOKEN)
        password = _str(req, "password", MAX_SECRET, required=False)
        totp = _str(req, "totp", MAX_NAME, required=False)
        reauth = _str(req, "reauth", MAX_TOKEN, required=False)
        addr = _str(req, "addr", MAX_NAME, required=False)
        clean = self._validate_action(req)
        conn, rt = self._iam(), self._runtime()
        try:
            sess = lookup_session(rt, sid)
            if sess is None or sess["pending"]:
                raise AuthError(401, "session expired or revoked — sign in again")
            try:
                if reauth:
                    iam.consume_reauth_token(rt, reauth, sess["principal"])
                else:
                    iam.reauthenticate_self(conn, rt, sess["principal"], password, totp or None,
                                            addr=addr,
                                            require_password=self._grant_requires_password(clean))
            except iam.IAMError as e:
                # Specific messages are fine: this is an authenticated caller
                # re-proving their OWN credential (see reauthenticate_self).
                raise AuthError(403, str(e))
            gid = iam.mint_action_grant(rt, sess["principal"], clean)
            return {"grant": gid, "approved_by": sess["principal"],
                    "expires_in": iam.ACTION_GRANT_TTL_S}
        finally:
            conn.close(); rt.close()

    def op_reauth_webauthn_begin(self, req: dict) -> dict:
        """A passkey standing in for password + 2FA in ANY re-authentication
        popup (granting, renaming, deleting, your own password/2FA/passkeys,
        instruction edits, building agents) — the operator asked for it to be
        an option everywhere. Scoped to the CURRENT
        session's own principal and their OWN registered credentials —
        unlike login's discoverable flow, the caller is already known, so
        `allowCredentials` is filled in rather than left empty, which is
        what lets the OS skip straight to "touch your key" instead of
        showing an account picker. Requires a passkey to already be
        enrolled: there is no weaker fallback here, the same posture
        reauthenticate_self(require_password=False) already takes for a
        code-only grant with no 2FA enrolled — asking for a credential
        that doesn't exist would prove nothing."""
        sid = _str(req, "session_id", MAX_TOKEN)
        conn, rt = self._iam(), self._runtime()
        try:
            _require_webauthn_configured(conn)
            sess = lookup_session(rt, sid)
            if sess is None or sess["pending"]:
                raise AuthError(401, "session expired or revoked — sign in again")
            principal = sess["principal"]
            creds = iam.list_passkeys(conn, principal)
            if not creds:
                raise AuthError(403, "you have no passkey yet — add one under Settings → "
                                     "Security, or use your password and 2FA code")
            challenge = iam.mint_webauthn_challenge(rt, purpose="reauth", principal=principal)
            return {
                "challenge": challenge, "rpId": WEBAUTHN_RP_ID, "origin": WEBAUTHN_ORIGIN,
                "timeout": iam.WEBAUTHN_CHALLENGE_TTL_S * 1000,
                "allowCredentials": [{"type": "public-key", "id": c["credential_id"]}
                                     for c in creds],
                "userVerification": "required",
            }
        finally:
            conn.close(); rt.close()

    def op_reauth_webauthn_finish(self, req: dict) -> dict:
        """Verify the assertion against one of THIS principal's own stored
        passkeys, then mint a single-use re-authentication token
        (iam.mint_reauth_token) the popup's action presents in place of a
        password and code. Every consumer re-checks it is for the same
        principal, and each still checks its own authority fresh. Every failure is the same posture login_finish already
        uses (a bad ceremony and an unknown credential look the same) —
        except the address throttle does not apply here, since the caller
        is already an authenticated session, not an anonymous one."""
        sid = _str(req, "session_id", MAX_TOKEN)
        credential_id = _credential_id_str(req)
        client_data_json = _credential_bytes(req, "credential", "response", "clientDataJSON")
        authenticator_data = _credential_bytes(req, "credential", "response", "authenticatorData")
        signature = _credential_bytes(req, "credential", "response", "signature")
        conn, rt = self._iam(), self._runtime()
        try:
            _require_webauthn_configured(conn)
            sess = lookup_session(rt, sid)
            if sess is None or sess["pending"]:
                raise AuthError(401, "session expired or revoked — sign in again")
            principal = sess["principal"]
            fail_msg = "could not verify this passkey — try again, or use your password and 2FA code"
            row = conn.execute(
                "SELECT principal, pubkey_x, pubkey_y FROM passkeys WHERE credential_id=?",
                (credential_id,)).fetchone()
            # Scoped to THIS session's own principal, not just any valid
            # credential — an assertion for someone else's passkey must
            # never approve an action taken under this session, even if
            # somehow submitted.
            if row is None or row["principal"] != principal:
                raise AuthError(403, fail_msg)
            try:
                client_data = json.loads(client_data_json.decode("utf-8"))
                challenge_b64 = client_data.get("challenge")
                if not isinstance(challenge_b64, str):
                    raise ValueError("missing challenge")
            except (ValueError, UnicodeDecodeError):
                raise AuthError(400, fail_msg)
            try:
                iam.consume_webauthn_challenge(rt, challenge_b64, purpose="reauth",
                                               principal=principal)
            except iam.IAMError as e:
                raise AuthError(403, str(e))
            state = rt.execute("SELECT sign_count FROM passkey_state WHERE credential_id=?",
                               (credential_id,)).fetchone()
            stored_count = state["sign_count"] if state else 0
            try:
                new_count = webauthn_lite.verify_assertion(
                    rp_id=WEBAUTHN_RP_ID, origin=WEBAUTHN_ORIGIN,
                    expected_challenge_b64=challenge_b64,
                    client_data_json=client_data_json, authenticator_data=authenticator_data,
                    signature=signature,
                    stored_x=webauthn_lite.b64url_decode(row["pubkey_x"]),
                    stored_y=webauthn_lite.b64url_decode(row["pubkey_y"]),
                    stored_sign_count=stored_count)
            except webauthn_lite.WebAuthnError:
                raise AuthError(403, fail_msg)
            now = time.time()
            rt.execute(
                "INSERT INTO passkey_state(credential_id, sign_count, last_used_at) VALUES (?,?,?)"
                " ON CONFLICT(credential_id) DO UPDATE SET sign_count=excluded.sign_count,"
                " last_used_at=excluded.last_used_at", (credential_id, new_count, now))
            rt.commit()
            return {"reauth": iam.mint_reauth_token(rt, principal), "expires_in": iam.ACTION_GRANT_TTL_S}
        finally:
            conn.close(); rt.close()

    def op_dashboard_access(self, req: dict) -> dict:
        """May `viewer` act on `target`'s runs (private per user — §4 item
        71)? A bare read like op_can: no audit row."""
        viewer = _str(req, "viewer", MAX_NAME)
        target = _str(req, "target", MAX_NAME)
        conn = self._iam()
        try:
            return iam.dashboard_access(conn, viewer, target)
        finally:
            conn.close()

    # -- WebAuthn / passkeys ------------------------------------------------
    # The actual cryptographic verification (CBOR/COSE parsing, ECDSA
    # signature checks — webauthn_lite.verify_registration/verify_assertion)
    # happens HERE, inside agenti-authd, and nowhere else. That is the whole
    # point of this daemon existing: a decision this consequential — "mint a
    # real, non-pending session for this principal" — cannot be delegated to
    # the API's own claim that a signature checked out, or a compromised API
    # could simply always say yes. See CLAUDE.md's WebAuthn item for the
    # full reasoning on why the crypto dependency lives in THIS process's
    # own dedicated venv rather than anywhere else.

    def op_setup_status(self, req: dict) -> dict:
        """Unauthenticated: can anyone sign in yet? Before `agenti setup` makes
        the first admin, the login page says how to start instead of refusing
        every attempt with no explanation. Once any person's account exists
        this answers false and reveals nothing more."""
        conn = self._iam()
        try:
            n = conn.execute("SELECT count(*) FROM principals WHERE kind='user'").fetchone()[0]
            return {"setup_needed": n == 0}
        finally:
            conn.close()

    def op_webauthn_config(self, req: dict) -> dict:
        """Unauthenticated: the login page needs to know whether to even
        show a passkey button, and which RP id to build the ceremony
        against. Neither value is sensitive — the RP id is this
        deployment's own public domain name.

        Also the Settings setup wizard's status check — which needs to tell
        apart "no domain configured at all" from "domain configured but the
        platform toggle is off", two different steps in that walkthrough.
        `configured` answers the first question on its own; `enabled` stays
        the strict AND (domain present AND toggle on) that gates the login
        page's own button, unchanged, so existing callers keep working."""
        conn = self._iam()
        try:
            configured = bool(WEBAUTHN_RP_ID and WEBAUTHN_ORIGIN)
            enabled = configured and iam.webauthn_enabled(conn)
            return {"enabled": enabled, "configured": configured,
                    "rpId": WEBAUTHN_RP_ID if configured else None,
                    "origin": WEBAUTHN_ORIGIN if configured else None}
        finally:
            conn.close()

    def op_webauthn_register_begin(self, req: dict) -> dict:
        """Step one of adding a passkey to an ALREADY-authenticated account.
        Re-proves the current credential first, exactly like `self
        mfa-start` — a hijacked session cookie holds neither the password
        nor a live second factor, which is what makes it safe for the API
        to reach this op at all."""
        sid = _str(req, "session_id", MAX_TOKEN)
        password = _str(req, "password", MAX_SECRET, required=False)
        reauth = _str(req, "reauth", MAX_TOKEN, required=False)
        totp = _str(req, "totp", MAX_NAME, required=False)
        addr = _str(req, "addr", MAX_NAME, required=False)
        conn, rt = self._iam(), self._runtime()
        try:
            _require_webauthn_configured(conn)
            sess = lookup_session(rt, sid)
            if sess is None or sess["pending"]:
                raise AuthError(401, "session expired or revoked — sign in again")
            try:
                if reauth:
                    iam.consume_reauth_token(rt, reauth, sess["principal"])
                else:
                    iam.reauthenticate_self(conn, rt, sess["principal"], password, totp or None,
                                            addr=addr)
            except iam.IAMError as e:
                raise AuthError(403, str(e))
            challenge = iam.mint_webauthn_challenge(rt, purpose="register",
                                                    principal=sess["principal"])
            user_id = webauthn_lite.b64url_encode(sess["principal"].encode("utf-8"))
            return {
                "challenge": challenge,
                "rp": {"id": WEBAUTHN_RP_ID, "name": "Agenti"},
                "user": {"id": user_id, "name": sess["principal"], "displayName": sess["principal"]},
                "pubKeyCredParams": [{"type": "public-key", "alg": -7}],  # ES256 only — see
                                                                          # webauthn_lite's docstring
                "timeout": iam.WEBAUTHN_CHALLENGE_TTL_S * 1000,
                "attestation": "none",
                "authenticatorSelection": {
                    # "platform" biases the OS toward its built-in biometric
                    # UI rather than prompting for a USB key — matches the
                    # operator's stated focus on synced/platform
                    # authenticators. Loosening this later to also welcome
                    # roaming keys is a one-line change here; nothing about
                    # verification cares which kind was used.
                    "authenticatorAttachment": "platform",
                    "residentKey": "required",
                    "requireResidentKey": True,
                    "userVerification": "required",
                },
            }
        finally:
            conn.close(); rt.close()

    def op_webauthn_register_finish(self, req: dict) -> dict:
        """Step two: verify the attestation for real, then mint a grant
        bound to the exact verified fields. The API commits them via the
        root CLI's `passkey-commit`, which trusts the GRANT — never the
        API's own relay of these fields, which could have tampered with any
        of them in transit.

        Does NOT re-authenticate with password/TOTP again — deliberately,
        after this cost a real live registration attempt on 2026-09-24.
        This used to mirror `self mfa-start`/`mfa-confirm`'s "prove the
        credential at every step" convention exactly, calling
        reauthenticate_self() here too. That is provably redundant, not
        merely unnecessary: the only way to reach this call with a VALID,
        unexpired, unconsumed challenge for this principal is to have
        already passed register_begin's own reauthenticate_self() — the
        challenge is minted there, single-use, principal-scoped, and short-
        TTL'd (iam.WEBAUTHN_CHALLENGE_TTL_S), so consuming it below is
        already proof a recent reauth happened. A hijacked session cookie
        alone, without ever passing begin's reauth, still cannot get a
        valid challenge here — so this change gives up nothing begin's
        check didn't already cover. What it DOES fix: verify_second_factor
        marks a TOTP code used the instant it succeeds (replay defense), so
        a client sending the SAME code to both begin and finish — the
        obvious, and previously the ONLY, way to fill in a form with one
        current-password/current-code pair — made finish's re-check fail
        every time with 'that code has already been used'. Every account
        with 2FA enrolled (the platform default since require-2fa) could
        therefore NEVER successfully register a passkey. See CLAUDE.md's
        WebAuthn item for the live incident this was found from."""
        sid = _str(req, "session_id", MAX_TOKEN)
        name = _str(req, "name", MAX_NAME, required=False)
        client_data_json = _credential_bytes(req, "credential", "response", "clientDataJSON")
        attestation_object = _credential_bytes(req, "credential", "response", "attestationObject")
        conn, rt = self._iam(), self._runtime()
        try:
            _require_webauthn_configured(conn)
            sess = lookup_session(rt, sid)
            if sess is None or sess["pending"]:
                raise AuthError(401, "session expired or revoked — sign in again")
            try:
                client_data = json.loads(client_data_json.decode("utf-8"))
                challenge_b64 = client_data.get("challenge")
                if not isinstance(challenge_b64, str):
                    raise ValueError("clientDataJSON has no 'challenge' string")
            except (ValueError, UnicodeDecodeError) as e:
                raise AuthError(400, f"credential.response.clientDataJSON is malformed: {e}")
            try:
                iam.consume_webauthn_challenge(rt, challenge_b64, purpose="register",
                                               principal=sess["principal"])
            except iam.IAMError as e:
                raise AuthError(400, str(e))
            try:
                result = webauthn_lite.verify_registration(
                    rp_id=WEBAUTHN_RP_ID, origin=WEBAUTHN_ORIGIN,
                    expected_challenge_b64=challenge_b64,
                    client_data_json=client_data_json, attestation_object=attestation_object)
            except webauthn_lite.WebAuthnError as e:
                raise AuthError(400, f"could not verify this passkey: {e}")
            stored_id = webauthn_lite.b64url_encode(result["credential_id"])
            stored_x = webauthn_lite.b64url_encode(result["x"])
            stored_y = webauthn_lite.b64url_encode(result["y"])
            action = iam.webauthn_register_action(sess["principal"], stored_id, result["alg"],
                                                  stored_x, stored_y, result["sign_count"])
            gid = iam.mint_action_grant(rt, sess["principal"], action)
            return {"credential_id": stored_id, "alg": result["alg"], "x": stored_x, "y": stored_y,
                    "sign_count": result["sign_count"], "name": name, "grant": gid}
        finally:
            conn.close(); rt.close()

    def op_webauthn_login_begin(self, req: dict) -> dict:
        """Passwordless first factor: no session, no principal known yet — a
        discoverable-credential request (empty allowCredentials), so the OS
        shows its own 'sign in as...' picker among whatever platform
        passkeys already exist for this RP id."""
        addr = _str(req, "addr", MAX_NAME, required=False)
        conn, rt = self._iam(), self._runtime()
        try:
            _require_webauthn_configured(conn)
            addr_wait = iam.address_locked(rt, addr)
            if addr_wait > 0:
                raise AuthError(429, "too many failed attempts from this address — "
                                     "try again later", retry_after=addr_wait)
            challenge = iam.mint_webauthn_challenge(rt, purpose="login")
            # "rpId" (camelCase) — this shape is spread directly into
            # navigator.credentials.get()'s `publicKey` option, which the
            # WebAuthn spec defines with THIS exact key name (unlike the
            # registration side's nested `rp: {id, name}`, the request
            # options carry a flat `rpId` string with no `name`). Getting
            # this wrong doesn't 400 — the browser just silently ignores an
            # unrecognized key and fails to scope the ceremony correctly.
            return {"challenge": challenge, "rpId": WEBAUTHN_RP_ID, "origin": WEBAUTHN_ORIGIN,
                    "timeout": iam.WEBAUTHN_CHALLENGE_TTL_S * 1000, "allowCredentials": [],
                    "userVerification": "required"}
        finally:
            conn.close(); rt.close()

    def op_webauthn_login_finish(self, req: dict) -> dict:
        """The passwordless login itself. Verifies the assertion against the
        STORED public key — never trusts anything the caller claims about
        it — updates the replay-defeating signature counter directly (authd
        owns runtime.db, where that mutable state lives; see passkey_state's
        comment in iam.py's _RUNTIME_SCHEMA for why it is NOT in iam.db),
        and mints a real, non-pending session: a platform passkey already
        proves possession plus a biometric/PIN check, so it satisfies this
        platform's 2FA policy on its own, the same as a TOTP code does.

        Every failure path is the SAME generic message and feeds the same
        per-address throttle a password login gets (an unknown credential
        id, a malformed ceremony, and a genuinely bad signature all look
        identical to the caller) — deliberately NOT the per-PRINCIPAL
        lockout counter, which exists to slow down guessing a secret. A
        forged WebAuthn signature isn't a guessable secret; locking an
        account because one device sent a malformed assertion would be a
        real availability cost with no matching security benefit."""
        addr = _str(req, "addr", MAX_NAME, required=False)
        credential_id = _credential_id_str(req)
        client_data_json = _credential_bytes(req, "credential", "response", "clientDataJSON")
        authenticator_data = _credential_bytes(req, "credential", "response", "authenticatorData")
        signature = _credential_bytes(req, "credential", "response", "signature")
        conn, rt = self._iam(), self._runtime()
        try:
            _require_webauthn_configured(conn)
            addr_wait = iam.address_locked(rt, addr)
            if addr_wait > 0:
                raise AuthError(429, "too many failed attempts from this address — "
                                     "try again later", retry_after=addr_wait)
            fail_msg = "invalid credentials"
            try:
                client_data = json.loads(client_data_json.decode("utf-8"))
                challenge_b64 = client_data.get("challenge")
                if not isinstance(challenge_b64, str):
                    raise ValueError("missing challenge")
            except (ValueError, UnicodeDecodeError):
                iam.record_address_failure(rt, addr)
                raise AuthError(401, fail_msg)
            try:
                iam.consume_webauthn_challenge(rt, challenge_b64, purpose="login")
            except iam.IAMError:
                iam.record_address_failure(rt, addr)
                raise AuthError(401, fail_msg)
            row = conn.execute(
                "SELECT principal, alg, pubkey_x, pubkey_y FROM passkeys WHERE credential_id=?",
                (credential_id,)).fetchone()
            if row is None:
                iam.record_address_failure(rt, addr)
                raise AuthError(401, fail_msg)
            principal = row["principal"]
            prow = conn.execute("SELECT active FROM principals WHERE name=?",
                                (principal,)).fetchone()
            if prow is None or not prow["active"]:
                iam.record_address_failure(rt, addr)
                raise AuthError(401, fail_msg)
            state = rt.execute("SELECT sign_count FROM passkey_state WHERE credential_id=?",
                               (credential_id,)).fetchone()
            stored_count = state["sign_count"] if state else 0
            try:
                new_count = webauthn_lite.verify_assertion(
                    rp_id=WEBAUTHN_RP_ID, origin=WEBAUTHN_ORIGIN,
                    expected_challenge_b64=challenge_b64,
                    client_data_json=client_data_json, authenticator_data=authenticator_data,
                    signature=signature,
                    stored_x=webauthn_lite.b64url_decode(row["pubkey_x"]),
                    stored_y=webauthn_lite.b64url_decode(row["pubkey_y"]),
                    stored_sign_count=stored_count)
            except webauthn_lite.WebAuthnError:
                iam.record_address_failure(rt, addr)
                raise AuthError(401, fail_msg)
            now = time.time()
            rt.execute(
                "INSERT INTO passkey_state(credential_id, sign_count, last_used_at) VALUES (?,?,?)"
                " ON CONFLICT(credential_id) DO UPDATE SET sign_count=excluded.sign_count,"
                " last_used_at=excluded.last_used_at", (credential_id, new_count, now))
            rt.commit()
            iam.clear_address_failures(rt, addr)
            sess = create_session(rt, principal, pending_totp=False)
            return {"principal": principal, "session_id": sess["session_id"],
                    "csrf": sess["csrf"], "mfa_setup_required": iam.mfa_setup_required(conn, principal)}
        finally:
            conn.close(); rt.close()


# ---------------------------------------------------------------------------
# The socket server
# ---------------------------------------------------------------------------
def peer_credentials(sock: socket.socket) -> tuple[int, int, int]:
    """(pid, uid, gid) of the process on the other end, from the kernel —
    not from anything the client sent."""
    data = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    return struct.unpack("3i", data)


class _Handler(socketserver.StreamRequestHandler):
    timeout = IO_TIMEOUT_S

    def _reply(self, obj: dict) -> None:
        try:
            self.wfile.write(json.dumps(obj).encode() + b"\n")
        except OSError:
            pass

    def handle(self) -> None:
        try:
            pid, uid, gid = peer_credentials(self.request)
        except OSError as e:
            self._reply({"ok": False, "status": 403,
                         "error": f"refused: could not read peer credentials ({e})"})
            return
        if uid not in self.server.allowed_uids:
            print(f"[{SERVICE_NAME}] refused a connection from uid {uid} (pid {pid}); "
                  f"allowed uids: {sorted(self.server.allowed_uids)}", file=sys.stderr)
            self._reply({"ok": False, "status": 403,
                         "error": f"refused: peer uid {uid} is not an allowed caller of "
                                  f"{SERVICE_NAME} (allowed: {sorted(self.server.allowed_uids)})"})
            return
        try:
            line = self.rfile.readline(MAX_REQUEST_BYTES + 1)
        except (OSError, socket.timeout):
            return
        if not line:
            return
        if len(line) > MAX_REQUEST_BYTES:
            self._reply({"ok": False, "status": 413,
                         "error": f"request exceeds {MAX_REQUEST_BYTES} bytes"})
            return
        try:
            request = json.loads(line)
        except ValueError:
            self._reply({"ok": False, "status": 400, "error": "request is not valid JSON"})
            return
        self._reply(self.server.service.handle(request))


class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    allow_reuse_address = False
    # socketserver's default backlog is 5: a burst of sign-ins overflowed it
    # and the API's connect failed with EAGAIN (HTTP 500, audit run 2).
    request_queue_size = 128

    def __init__(self, path: str, service: Service, allowed_uids: set[int],
                 socket_group: str | None = None):
        self.service = service
        self.allowed_uids = set(allowed_uids)
        self.path = path
        # A stale socket file from an unclean stop must be removed or bind()
        # fails with EADDRINUSE and the service never comes up again.
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        # 0660: the group is the gate on the filesystem side (peer uid is the
        # gate on the kernel side). Set via umask so there is no window in
        # which the socket exists with a wider mode.
        old = os.umask(0o117)
        try:
            super().__init__(path, _Handler)
        finally:
            os.umask(old)
        if socket_group:
            gid = grp.getgrnam(socket_group).gr_gid
            os.chown(path, -1, gid)
            os.chmod(path, 0o660)


def serve(path: str, service: Service, allowed_uids: set[int],
          socket_group: str | None = None) -> Server:
    """Start serving in a background thread and return the server (the
    caller stops it with .shutdown(); .server_close()). Used by tests and
    by main()."""
    srv = Server(path, service, allowed_uids, socket_group)
    threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.5},
                     daemon=True, name="authd-accept").start()
    return srv


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(allow_abbrev=False, 
        prog="authd.py",
        description="Agenti's privileged login/session/authorization service. "
                    "Listens on a Unix socket; only the accounts named by "
                    "--allow-user may talk to it, checked by kernel peer credentials.")
    ap.add_argument("--socket", default=DEFAULT_SOCKET)
    ap.add_argument("--allow-user", action="append", default=[],
                    help=f"an account permitted to connect (repeatable; default {DEFAULT_ALLOW_USER})")
    ap.add_argument("--socket-group", default=DEFAULT_SOCKET_GROUP,
                    help="group to own the socket, 0660 ('' for none)")
    a = ap.parse_args(argv)

    allowed: set[int] = set()
    for name in a.allow_user or [DEFAULT_ALLOW_USER]:
        try:
            allowed.add(pwd.getpwnam(name).pw_uid)
        except KeyError:
            print(f"{SERVICE_NAME}: no such account {name!r} for --allow-user. "
                  f"The package creates it; recreate it with: sudo dpkg-reconfigure agenti", file=sys.stderr)
            return 2
    if a.socket_group:
        try:
            grp.getgrnam(a.socket_group)
        except KeyError:
            print(f"{SERVICE_NAME}: no such group {a.socket_group!r} for --socket-group. "
                  f"The package creates it; recreate it with: sudo dpkg-reconfigure agenti", file=sys.stderr)
            return 2

    service = Service()
    # Fail fast, with iam.py's own message, if the identity store cannot be
    # read — better than a service that is "active" and answers 503 forever.
    try:
        service._iam().close()
    except iam.IAMError as e:
        print(f"{SERVICE_NAME}: {e}", file=sys.stderr)
        return 1
    # One connection held open for the life of the process, never used for a
    # query: it makes THIS account the creator of runtime.db's -wal/-shm
    # sidecars. The root CLI also writes runtime.db (self-service password
    # changes, enrolment tokens, session revocation); if root's connection
    # were the one to create those sidecars they would be root-owned and this
    # unprivileged process could no longer open the database at all.
    keeper = service._runtime()

    try:
        srv = serve(a.socket, service, allowed, a.socket_group or None)
    except OSError as e:
        print(f"{SERVICE_NAME}: cannot listen on {a.socket}: {e}. The directory must "
              f"exist and be writable by this account (systemd's RuntimeDirectory= "
              f"does that when run as a unit).", file=sys.stderr)
        return 1
    print(f"{SERVICE_NAME}: listening on {a.socket} (protocol {PROTOCOL_VERSION}); "
          f"allowed uids {sorted(allowed)}; identity store {service.iam_path or iam.IAM_DB_PATH}; "
          f"session store {service.runtime_path or iam.RUNTIME_DB_PATH}", flush=True)

    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    while not stop.wait(1.0):
        pass
    srv.shutdown(); srv.server_close()
    keeper.close()
    try:
        os.unlink(a.socket)
    except FileNotFoundError:
        pass
    print(f"{SERVICE_NAME}: stopped", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
