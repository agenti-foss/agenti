"""
main.py — thin API layer over the `agenti` CLI (CLAUDE.md §3a/§3g/§4 step 5).

Every route below does exactly two things: check a permission, then build the
equivalent `agenti` argv and call cli_bridge.run_agenti()/run_agenti_text(). No
route touches the vault, systemd, or any harness file directly — see
cli_bridge.py's own docstring for why that matters. If you're adding a route and
find yourself reaching for a file path or a systemctl call instead of an `agenti`
sub-command, stop: either the CLI needs that verb added first, or this route
doesn't belong here.

EVERY ROUTE NAMES ITS PERMISSION. `caller: Caller = Depends(require("..."))` is
not decoration — it IS the authentication and the authorization check, and the
`Caller` it returns is the authenticated principal, threaded into mutating CLI
calls so attribution records a person rather than the service account. A route
that omits it gets neither check, which is why every one has it and why that is
auditable by grepping this file for `Depends(require(`.

Deliberately NOT exposed (see CLAUDE.md §4 step 5 for the full reasoning):
  - purge                       — CLI-only interactive typed-name confirmation
  - export                      — writes outside the vault to a caller path
  - set-key                     — needs a silent-prompt secret, not a body
  - evidence                    — raw multi-file dump, lower priority
  - logs -f (follow)            — needs streaming; logs (bounded, -n) is here instead
  - admin user/role/group/key management — root-gated CLI only, on purpose:
    the API reads iam.db and cannot write it, so a compromised API process
    cannot grant itself anything (shared/iam.py's module docstring).
  - vault unlock/lock/passphrase — NEVER exposed. The vault passphrase must
    never pass through any programmatic channel. Not deferred — refused.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import sys
import time
import traceback
import uuid
from pathlib import Path
from typing import Annotated, AsyncIterator, Literal, Optional

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse, Response as RawResponse, StreamingResponse
from pydantic import AfterValidator, AliasChoices, BaseModel, Field, model_validator

# iam.py is installed one level up (/usr/lib/agenti/iam.py) so that the
# root CLI and this service share exactly one copy. This must run BEFORE the
# local imports below: rbac.py does the same insert, but `import iam` here is
# evaluated first and failed with ModuleNotFoundError at startup until this
# was hoisted. Found by the service refusing to boot, not by review.
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cli_bridge import (AgentiError, run_agenti, run_agenti_bytes, run_agenti_text,
                        validate_filename, validate_name)
import docx as report_docx
import iam  # for constants (the permission catalog, resource grammar) ONLY — never opened here
import proxytrust
import sessions
from authd_client import AuthdError, call as authd_call
from rbac import (Caller, authenticated, can, require,
                  resolved_permissions, resolved_role)

# Every {agent} path param and every caller-supplied filename is
# validated BEFORE it can become an argv element — see cli_bridge's own
# comment for the escape this closes (an agent called "vault" reaching the CLI's
# top-level vault verb). Declared as annotated types rather than a per-route
# dependency so the constraint is part of each signature, visible in the
# generated OpenAPI schema, and hard to omit silently.
AgentName = Annotated[str, AfterValidator(lambda v: validate_name(v, "agent"))]
TeamName = Annotated[str, AfterValidator(lambda v: validate_name(v, "team"))]
# Same regex iam.py's own validate_name() enforces for a principal — a name
# that would be refused at the CLI is refused here before it is ever built
# into an argv, same reasoning as the three names above.
PrincipalName = Annotated[str, AfterValidator(lambda v: validate_name(v, "user"))]
# Which of the user's runs of an agent ("--copy" in the CLI). Every start is
# its own isolated run in a fresh slot; this is the label that names it. Same
# name rule as every other segment: it becomes part of a path and of a systemd
# unit name. None on a start means "generate one" (the reply says which); None
# on any other route means the one run going, else the latest.
CopyLabel = Annotated[str, AfterValidator(lambda v: validate_name(v, "copy"))]


def _slot(owner: str, copy: "str | None" = None) -> list:
    """`--owner <user> [--copy <label>]` — WHICH run a per-run CLI verb acts on.
    The CLI refuses an API call without --owner, so a route can only ever name
    the run of the user it resolved here."""
    return ["--owner", owner, *(["--copy", copy] if copy else [])]


# Any free-text field that becomes a CLI argument — a password, a search
# secret, a target, a model name — has one real hazard: a leading '-' would
# be consumed as a FLAG by the CLI's own argparse/getopts, not as data (`-t
# --budget` would silently set the target to the literal string "--budget").
# subprocess is always called with a list, so this is the only injection
# shape that survives that; rejecting it up front turns it into a clear 422
# instead of a confusing failure three layers down.
def _no_leading_dash(v: str) -> str:
    if v.startswith("-"):
        raise ValueError(f"{v!r} may not start with '-' — it would be read as a flag")
    return v


ArgValue = Annotated[str, AfterValidator(_no_leading_dash)]
# A run's display name (the CLI's valid_run_name re-checks it: trimmed, no
# control characters). Never an address — only what people read.
RunName = Annotated[str, Field(min_length=1, max_length=60), AfterValidator(_no_leading_dash)]
# A passkey re-authentication token (authd's reauth_webauthn_finish): what
# any approval popup sends instead of a password and 2FA code.
ReauthToken = Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{16,64}$")]
# An enrolment or password-reset link token (iam._link_token): base64url, never
# a leading '-'. Bounded, so a junk path never reaches the root CLI (N13).
LinkToken = Annotated[str, Field(pattern=r"^[A-Za-z0-9_][A-Za-z0-9_-]{15,127}$")]


ReportFile = Annotated[str, AfterValidator(validate_filename)]


# A WebAuthn credential id, as a URL path segment. base64url by construction
# (that's the whole reason base64URL, not plain base64, is used for anything
# that travels in a URL — no '/' to break path segmentation), constrained to
# that exact alphabet here so garbage in the path is a clean 422 rather than
# an opaque "no such passkey" from three layers down.
def _b64url_id_ok(v: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,512}", v):
        raise ValueError("must be a base64url credential id")
    return v


Base64UrlId = Annotated[str, AfterValidator(_b64url_id_ok)]

# uvicorn's access log goes to the journal, and an unused enrolment or reset
# link in it is a working credential (audit run 2, confirmed live): the token
# part of those paths is blanked before the line is written.
_LINK_PATH = re.compile(r"^(/(?:enrol|password-reset)/)[^/?#\s]+")


class _RedactLinkTokens(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        args = record.args
        if isinstance(args, tuple) and len(args) >= 3 and isinstance(args[2], str):
            record.args = (*args[:2], _LINK_PATH.sub(r"\1<token>", args[2]), *args[3:])
        return True


logging.getLogger("uvicorn.access").addFilter(_RedactLinkTokens())

app = FastAPI(
    title="Agenti API",
    description="Thin read/control layer over the agenti CLI, with per-principal "
                "RBAC. See CLAUDE.md §3a/§3g/§4 step 5.",
    version="0.2.0",
    # FastAPI's own explorer would publish a map of every route to anyone,
    # signed in or not, and load its page from a third-party CDN.
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

# Behind a reverse proxy or tunnel (agenti gui configure --behind-proxy). The unit
# sets these; absent, nothing here changes. See api/proxytrust.py.
BEHIND_PROXY = os.environ.get("AGENTI_BEHIND_PROXY", "") == "1"
CLIENT_IP_HEADER = (os.environ.get("AGENTI_CLIENT_IP_HEADER", "")
                    or proxytrust.DEFAULT_CLIENT_IP_HEADER).lower()
if BEHIND_PROXY:
    # Answer only to this deploy's own public name (plus loopback for health
    # checks). A loopback service that answers to ANY Host can be reached by
    # DNS rebinding or a misrouted proxy vhost.
    from starlette.middleware.trustedhost import TrustedHostMiddleware
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=proxytrust.allowed_hosts(os.environ.get("AGENTI_HOSTNAME", "")))

# Pages, scripts and stylesheets must never be served stale: a browser or the
# Cloudflare edge holding an old settings.js against a new settings.html broke
# whole Settings tabs (2026-10-05). "no-cache" means "check with the server
# before using a stored copy" — the ETag makes that check cheap. Deploys also
# stamp ?v=<hash> on every script and stylesheet link (packaging/install-tree.sh).
_REVALIDATE_SUFFIXES = (".html", ".js", ".css", "/")


@app.middleware("http")
async def _gui_cache_policy(request: Request, call_next):
    response = await call_next(request)
    path = request.url.path
    if path.endswith(_REVALIDATE_SUFFIXES) and "cache-control" not in response.headers:
        response.headers["Cache-Control"] = "no-cache"
    # Framed only by this same origin (the admin's dashboard pop-up frames a
    # page of its own): another origin on the same site could otherwise frame
    # a signed-in page and steer one-click approvals (audit run 2, confirmed
    # live). The referrer stays on this origin, so a link token in the address
    # bar is never sent elsewhere.
    response.headers.setdefault("Content-Security-Policy", "frame-ancestors 'self'")
    response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    return response


@app.exception_handler(Exception)
async def _unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """FastAPI's own default for a truly UNCAUGHT exception (a real bug —
    anything that isn't an HTTPException/AgentiError, both of which already
    have their own clean handling) is a PLAIN TEXT 500 body, not JSON —
    silently breaking the one-JSON-stream contract every other error path
    in this API keeps. Found in the 2026-09-21 error-message audit
    (CLAUDE.md §4 item 17).

    Registering a handler for the base Exception class does NOT shadow
    HTTPException's own more specific handler — FastAPI/Starlette resolve
    by walking the exception's MRO and picking the most specific match, so
    this only ever fires for what nothing else already handled.

    Logs via plain print(..., file=sys.stderr), not the `logging` module —
    tried that first and the message never reached the journal, because
    uvicorn configures its OWN named loggers and this one had no handler
    in its ancestry to actually emit anywhere. print() to stderr is what
    uvicorn's own default traceback dump already reliably uses (confirmed
    by triggering a real exception and watching it land in `journalctl -u
    agenti-api` before this handler existed), so it needs no logging
    configuration to trust.

    The full traceback is logged server-side with a correlation ref; the
    CLIENT gets only that ref and a generic message, not the raw exception
    text or a traceback. This route is reachable by any authenticated
    caller, not just a trusted operator, and a stack trace can hand an
    attacker internal paths and logic for free — the same reasoning
    behind every deliberately-generic message in sessions.py/iam.py."""
    ref = uuid.uuid4().hex[:12]
    print(f"[agenti-api] unhandled exception [ref={ref}] on "
          f"{request.method} {request.url.path}", file=sys.stderr)
    traceback.print_exc(file=sys.stderr)
    return JSONResponse(
        status_code=500,
        content={"error": f"an unexpected error occurred (ref={ref}) — "
                          f"see journalctl -u agenti-api for the real cause"})


def _call(*args: str) -> dict | list:
    try:
        return run_agenti(*args)
    except AgentiError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


def _call_text(*args: str) -> str:
    try:
        return run_agenti_text(*args)
    except AgentiError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


def _call_bytes(*args: str) -> bytes:
    try:
        return run_agenti_bytes(*args)
    except AgentiError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


def _authd(op: str, **fields) -> dict:
    """Ask agenti-authd (shared/authd.py) and relay a refusal with its own
    status and message. The login routes below are the only callers here;
    rbac.py has its own identical helper for the per-route dependency."""
    try:
        return authd_call(op, **fields)
    except AuthdError as e:
        raise HTTPException(status_code=e.status, detail=e.message)


def _owner(caller: "Caller", user: "str | None") -> str:
    """Whose run a request is about. Runs are private to the user who launched
    them (CLAUDE.md §4 item 71): with no `user` it is the caller's own, and
    naming someone else is allowed only down the dashboard ladder
    (iam.dashboard_access — an admin may open an operator's). Only the routes
    where an admin may act for someone — view, stop, mark complete, kept
    files — take `user` at all; launching, messaging and the rest never do."""
    if user is None or user == caller.principal:
        return caller.principal
    r = _authd("dashboard_access", viewer=caller.principal, target=user)
    if not r["allowed"]:
        raise HTTPException(status_code=403,
                            detail=f"you may not open {user}'s dashboard — {r['reason']}")
    return user


# ---------------------------------------------------------------------------
# Login — password, then TOTP when enrolled
#
# Two steps, two endpoints, and a SHORT-LIVED pending session between them. The
# pending session is what remembers "this browser proved the password" without
# granting anything: rbac refuses it for every real route, and it expires in
# minutes rather than hours.
#
# Since §4 item 23 none of this happens in this process. The password goes
# to agenti-authd over its socket, which alone can read the hash and alone
# can create the session row; what comes back is a session id to put in a
# cookie. This process never sees iam.db or the session store. (It does
# still see the password in flight — it terminates TLS — and that residual
# is stated in authd.py's docstring rather than hidden.)
# ---------------------------------------------------------------------------
class LoginRequest(BaseModel):
    # "user" is the name (2026-10-19); the old "principal" key is still accepted.
    user: str = Field(validation_alias=AliasChoices("user", "principal"))
    password: str


def _client_addr(request: Request) -> str:
    """The source address for login throttling.

    Direct deploys use the TCP peer and never read a forwarding header: with
    nothing in front, a header is purely attacker-controlled, and honouring it
    would let one client claim a fresh address per attempt. Behind a proxy
    (--behind-proxy) every peer is 127.0.0.1, so the real address comes from
    the proxy's header, trusted only from a loopback peer. Rules and tests:
    api/proxytrust.py, shared/test_proxytrust.py."""
    peer = request.client.host if request.client else ""
    # Every line of a repeated header, joined: a proxy that appends its own
    # line (rather than one merged value) must still be the right-most entry,
    # never a copy the client sent first (audit run 1, N14).
    return proxytrust.client_addr(peer, lambda h: ",".join(request.headers.getlist(h)) or None,
                                  behind_proxy=BEHIND_PROXY, header=CLIENT_IP_HEADER)


# The link pages need no sign-in (the token is the credential), so they get
# their own brake: per address, a few dozen tries in five minutes, and at most
# four at once overall, each of which costs a root CLI process (audit run 1,
# N13). Over either limit: 429, and nothing reaches root.
import threading as _threading  # noqa: E402
from collections import deque as _deque  # noqa: E402

LINK_WINDOW_S, LINK_MAX_PER_ADDR, LINK_MAX_INFLIGHT = 300, 30, 4
_link_hits: dict[str, _deque] = {}
_link_lock = _threading.Lock()
_link_inflight = _threading.BoundedSemaphore(LINK_MAX_INFLIGHT)


class _LinkGate:
    def __init__(self, request: Request):
        self.addr = _client_addr(request) or (request.client.host if request.client else "?")

    def __enter__(self):
        now = time.monotonic()
        with _link_lock:
            q = _link_hits.setdefault(self.addr, _deque())
            while q and now - q[0] > LINK_WINDOW_S:
                q.popleft()
            if len(q) >= LINK_MAX_PER_ADDR:
                raise HTTPException(status_code=429, detail="too many link attempts from this "
                                    "address — wait a few minutes and try again")
            q.append(now)
            if len(_link_hits) > 10000:          # never grows without bound
                _link_hits.clear()
        if not _link_inflight.acquire(blocking=False):
            raise HTTPException(status_code=429, detail="the server is busy — try again in a moment")
        return self

    def __exit__(self, *exc):
        _link_inflight.release()
        return False


@app.post("/auth/login")
def login(body: LoginRequest, request: Request, response: Response) -> dict:
    r = _authd("login", principal=body.user, password=body.password,
               addr=_client_addr(request))
    sess = sessions.Session(r["session_id"], r["principal"], r.get("csrf") or "",
                            bool(r["pending"]))
    sessions.set_cookie(response, sess)
    return {
        "user": r["principal"],
        "totp_required": r["totp_required"],
        "mfa_setup_required": bool(r.get("mfa_setup_required")),
        "must_change_password": r["must_change_password"],
        # The CSRF value is returned in the BODY, not a cookie: a value the
        # browser stores and replays automatically would defeat the point.
        "csrf": None if sess.pending_totp else sess.csrf,
    }


class TotpRequest(BaseModel):
    code: str


@app.post("/auth/totp")
def totp(body: TotpRequest, request: Request, response: Response) -> dict:
    sid = request.cookies.get(sessions.COOKIE_NAME)
    if not sid:
        raise HTTPException(status_code=401, detail="no pending login — POST /auth/login first")
    # authd verifies the code AND rotates the session id on success — the
    # standard session-fixation defence, done where the rows live.
    r = _authd("totp", session_id=sid, code=body.code, addr=_client_addr(request))
    new = sessions.Session(r["session_id"], r["principal"], r["csrf"], False)
    sessions.set_cookie(response, new)
    return {"user": new.principal, "authenticated": True,
            "csrf": new.csrf, "note": r.get("note", "")}


@app.post("/auth/logout")
def logout(request: Request, response: Response) -> dict:
    sid = request.cookies.get(sessions.COOKIE_NAME)
    if sid:
        try:
            authd_call("logout", session_id=sid)
        except AuthdError:
            # The cookie is cleared regardless: a client calling logout wants
            # to end up logged out. If authd was unreachable the row outlives
            # the cookie until its TTL, which is the same as closing the tab.
            pass
    sessions.clear_cookie(response)
    # Always 200: whether a session existed is not information worth leaking,
    # and a client calling logout wants to end up logged out either way.
    return {"logged_out": True}


# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------
@app.get("/auth/me")
def me(caller: Caller = Depends(authenticated())) -> dict:
    """Who am I and what may I do — the GUI's first call, so it can render the
    right controls rather than discovering its permissions by collecting 403s.

    Deliberately requires NO permission beyond a valid credential: any signed-in
    user must be able to ask who they are."""
    return {
        "user": caller.principal,
        "authenticated_via": caller.via,
        "role": resolved_role(caller.principal),
        "permissions": resolved_permissions(caller.principal),
        # Session callers only (a key has no second factor): whether 2FA is
        # enrolled, and whether the require-2fa policy is holding this session
        # to the enrolment routes until it is (rbac.MFA_SETUP_ALLOWED_PATHS).
        "totp_enrolled": caller.totp_enrolled,
        "mfa_setup_required": caller.mfa_setup_required,
    }


# ---------------------------------------------------------------------------
# Self-service account management (CLAUDE.md's "authority rule", GUI phase 2).
#
# The API still cannot write iam.db directly — that has not changed. What
# changed is that `agenti admin self ...` (shared/iam.py) is a narrow,
# root-gated CLI verb the API IS allowed to invoke (it is deliberately absent
# from shared/agenti's IAM_WRITE_VERBS refusal list), and every subcommand
# re-proves the caller's CURRENT password — and current 2FA code, if
# enrolled — before touching anything. That re-proof is what makes it safe:
# a forged session or a compromised API process holds neither, so this
# still defeats exactly the attack the read-only iam.db property exists to
# stop. See shared/agenti's IAM_WRITE_VERBS comment and
# iam.reauthenticate_self()'s docstring for the full reasoning.
# ---------------------------------------------------------------------------
def _self_proof(body) -> list[str]:
    """How a self-service change proves it's really you: a passkey token, or
    your current password (and 2FA code, once you have one)."""
    if getattr(body, "reauth", None):
        return [f"--reauth={body.reauth}"]
    out = [f"--current={body.current or ''}"]
    if body.totp:
        out.append(f"--totp={body.totp}")
    return out


class ChangePasswordRequest(BaseModel):
    current: Optional[ArgValue] = None
    new: ArgValue
    totp: Optional[ArgValue] = None
    reauth: Optional[ReauthToken] = None


@app.post("/auth/password")
def change_password(body: ChangePasswordRequest, request: Request,
                    caller: Caller = Depends(authenticated())) -> dict:
    args = ["admin", "self", "password", caller.principal, *_self_proof(body),
            "--new", body.new, "--addr", _client_addr(request)]
    return _call(*args)


class MfaStartRequest(BaseModel):
    current: Optional[ArgValue] = None
    totp: Optional[ArgValue] = None
    reauth: Optional[ReauthToken] = None


@app.post("/auth/mfa/enrol/start")
def mfa_enrol_start(body: MfaStartRequest, request: Request,
                    caller: Caller = Depends(authenticated())) -> dict:
    """Returns a candidate secret, its otpauth:// URI, and a single-use
    `grant` /confirm consumes instead of asking for the password/2FA code a
    second time — see confirm_totp_enrolment()'s docstring for why the
    two-step shape exists, and iam.py's mint_action_grant call in the
    mfa-start dispatch for why re-authenticating only once here is safe.
    Writes NOTHING itself. The GUI renders the URI as a QR code client-side."""
    args = ["admin", "self", "mfa-start", caller.principal, *_self_proof(body),
            "--addr", _client_addr(request)]
    return _call(*args)


class MfaConfirmRequest(BaseModel):
    # Deliberately NO current/totp fields — see mfa_enrol_start's docstring
    # and iam.py's mfa-confirm dispatch: /start already re-authenticated and
    # minted a single-use grant bound to this exact secret, so asking again
    # here would be both redundant and actively broken (the same OLD 2FA
    # code sent twice trips its own replay defense) — the identical class of
    # bug already found and fixed once for WebAuthn register/finish, below.
    grant: ArgValue
    secret: ArgValue
    code: ArgValue


@app.post("/auth/mfa/enrol/confirm")
def mfa_enrol_confirm(body: MfaConfirmRequest, request: Request,
                      caller: Caller = Depends(authenticated())) -> dict:
    """Commits the secret from /start — but only after proving a CURRENT
    code was actually generated from it, so a mistyped secret or a clock
    problem cannot leave the account enrolled in something it cannot
    authenticate with later. The re-authentication itself already happened
    at /start; `grant` is what proves that here without asking again.
    Returns fresh recovery codes, shown once."""
    return _call("admin", "self", "mfa-confirm", caller.principal,
               "--grant", body.grant, "--secret", body.secret, "--code", body.code)


# ---------------------------------------------------------------------------
# WebAuthn / passkeys.
#
# Registration mirrors the mfa-start/mfa-confirm shape above: two round
# trips, current password (+ current 2FA if enrolled) proven only at the
# FIRST one (because a hijacked session cookie holds neither), with the
# second trusting a single-use grant instead of asking again — the same
# reasoning, applied to a real WebAuthn ceremony rather than a TOTP secret.
# What's different is where the actual verification happens — a real attestation
# needs real elliptic-curve signature math, which only agenti-authd's own
# dedicated venv can do (see CLAUDE.md's WebAuthn item), so /finish asks
# authd to verify for real and hands back a single-use GRANT bound to the
# exact verified fields. This route then asks the root CLI to commit them —
# `admin passkey-commit` trusts the grant, never this process's own relay
# of the fields, so a compromised API cannot register an attacker-chosen
# key against someone else's account.
#
# Login is the passwordless path: no session exists yet, so both routes
# here are deliberately UNAUTHENTICATED, the same posture as /auth/login.
#
# One CLI-argument-building subtlety worth being explicit about: several
# fields below (credential_id, x, y, grant) are base64url strings authd
# generated from real cryptographic data — NOT text a person typed — so
# they cannot be rejected for "starts with a dash" the way ArgValue rejects
# ordinary form fields (base64url's alphabet includes '-', so a value
# legitimately starting with one is a matter of when, not if). Passed with
# `--flag=value` (one token) rather than `--flag`, `value` (two), which is
# the standard fix for argparse's "expected one argument" failure on a
# value that merely LOOKS like another option — verified directly against
# argparse before relying on it.
# ---------------------------------------------------------------------------
class WebauthnCredentialResponse(BaseModel):
    clientDataJSON: str
    attestationObject: Optional[str] = None
    authenticatorData: Optional[str] = None
    signature: Optional[str] = None


class WebauthnCredential(BaseModel):
    id: Base64UrlId
    response: WebauthnCredentialResponse


# ---- re-authenticating with a passkey, for ANY approval popup ---------------
# Two calls, like every WebAuthn ceremony: begin asks for the caller's OWN
# passkeys; finish has agenti-authd verify the assertion and return a
# single-use, two-minute token. The popup then performs its action with that
# token in place of a password and 2FA code; every consumer re-checks the
# token is for the same account (iam.consume_reauth_token).
def _session_id(request: Request, caller: Caller) -> str:
    sid = request.cookies.get(sessions.COOKIE_NAME)
    if caller.via != "session" or not sid:
        raise HTTPException(status_code=400, detail="confirming with a passkey needs a "
                            "signed-in browser session")
    return sid


@app.post("/auth/reauth/webauthn/begin")
def reauth_webauthn_begin(request: Request, caller: Caller = Depends(authenticated())) -> dict:
    return _authd("reauth_webauthn_begin", session_id=_session_id(request, caller))


class ReauthFinishRequest(BaseModel):
    credential: WebauthnCredential


@app.post("/auth/reauth/webauthn/finish")
def reauth_webauthn_finish(body: ReauthFinishRequest, request: Request,
                           caller: Caller = Depends(authenticated())) -> dict:
    return _authd("reauth_webauthn_finish", session_id=_session_id(request, caller),
                  credential=body.credential.model_dump())


@app.get("/auth/setup-status")
def setup_status(request: Request) -> dict:
    """Unauthenticated: true until an admin can sign in, so the login page
    sends people to the setup page instead of refusing silently. `local`
    says whether this browser may use the setup page (it works only on the
    Agenti machine itself)."""
    r = _authd("setup_status")
    return {"setup_needed": bool(r.get("setup_needed")), "local": _setup_is_local(request)}


# ---------------------------------------------------------------------------
# First-run setup from the browser (operator decision 2026-10-26). Like the
# link routes below, no sign-in: nobody can sign in yet. What stands in for
# it is the setup code, which only someone at the host's terminal can read
# (sudo agenti setup-code), checked by agenti-authd; a right code buys a
# single-use grant for exactly one admin name, spent by the root CLI. On top
# of that the page works only from the machine itself: a loopback peer with
# no proxy in between, addressed by a loopback name. A tunnel or proxy on the
# box (--behind-proxy) connects from loopback too, but always says so in a
# forwarding header, and is refused.
# ---------------------------------------------------------------------------
_FORWARDING_HEADERS = ("forwarded", "x-forwarded-for", "x-forwarded-host", "x-real-ip",
                       "cf-connecting-ip", "true-client-ip")
_LOOPBACK_NAMES = ("127.0.0.1", "localhost", "::1")


def _loopback_host(value: str) -> bool:
    host = value.strip().lower()
    if host.startswith("["):
        host = host[1:host.find("]")] if "]" in host else host
    elif host.count(":") == 1:
        host = host.split(":", 1)[0]
    return host in _LOOPBACK_NAMES or host.startswith("127.")


def _setup_is_local(request: Request) -> bool:
    peer = request.client.host if request.client else ""
    if not (peer == "::1" or peer.startswith("127.")):
        return False
    if any(request.headers.get(h) for h in (*_FORWARDING_HEADERS, CLIENT_IP_HEADER or "")):
        return False
    if not _loopback_host(request.headers.get("host", "")):
        return False
    origin = request.headers.get("origin")
    if origin:
        rest = origin.split("://", 1)[-1]
        if not _loopback_host(rest.split("/", 1)[0]):
            return False
    return True


class SetupAdminRequest(BaseModel):
    code: Annotated[str, Field(min_length=1, max_length=64)]
    name: PrincipalName


@app.post("/setup/admin")
def setup_first_admin(body: SetupAdminRequest, request: Request) -> dict:
    """Step 1 of the setup page: the setup code and the first admin's name.
    Returns the admin's one-time enrolment token; the page goes on to the
    enrolment page with it for the password and 2FA."""
    if not _setup_is_local(request):
        raise HTTPException(status_code=403, detail=(
            "setup works only in a browser on the Agenti machine itself: open "
            "http://127.0.0.1:8420 there (from another computer, first: "
            "ssh -L 8420:127.0.0.1:8420 <the machine>). Or, at its terminal: sudo agenti setup"))
    with _LinkGate(request):
        g = _authd("setup_begin", code=body.code, principal=body.name)
        r = _call("admin", "setup-first-admin", body.name, f"--grant={g['grant']}")
    return {"user": body.name, "enrolment_token": r.get("enrolment_token")}


@app.get("/auth/webauthn/config")
def webauthn_config() -> dict:
    """Unauthenticated: the login page needs to know whether to even show a
    'sign in with a passkey' button before anyone has signed in."""
    return _authd("webauthn_config")


class WebauthnRegisterStartRequest(BaseModel):
    password: Optional[ArgValue] = None
    totp: Optional[ArgValue] = None
    reauth: Optional[ReauthToken] = None


@app.post("/auth/webauthn/register/start")
def webauthn_register_start(body: WebauthnRegisterStartRequest, request: Request,
                            caller: Caller = Depends(authenticated())) -> dict:
    sid = request.cookies.get(sessions.COOKIE_NAME)
    if caller.via != "session" or not sid:
        raise HTTPException(status_code=400,
                            detail="registering a passkey needs a signed-in browser session "
                                   "— an API key has no browser to run the ceremony in")
    return _authd("webauthn_register_begin", session_id=sid, password=body.password or "",
                  totp=body.totp or "", reauth=body.reauth or "", addr=_client_addr(request))


class WebauthnRegisterFinishRequest(BaseModel):
    # Deliberately NO password/totp fields — see op_webauthn_register_finish's
    # docstring in authd.py for why re-proving the credential here would be
    # both redundant (the challenge consumed below already proves begin's
    # reauth happened) and actively broken (the same TOTP code sent twice
    # trips its own replay defense — found live on 2026-09-24).
    name: str = Field(default="", max_length=64)
    credential: WebauthnCredential


@app.post("/auth/webauthn/register/finish")
def webauthn_register_finish(body: WebauthnRegisterFinishRequest, request: Request,
                             caller: Caller = Depends(authenticated())) -> dict:
    sid = request.cookies.get(sessions.COOKIE_NAME)
    if caller.via != "session" or not sid:
        raise HTTPException(status_code=400,
                            detail="registering a passkey needs a signed-in browser session")
    r = _authd("webauthn_register_finish", session_id=sid,
              addr=_client_addr(request), name=body.name,
              credential=body.credential.model_dump())
    out = _call("admin", "passkey-commit", caller.principal,
               f"--credential-id={r['credential_id']}", f"--alg={r['alg']}",
               f"--x={r['x']}", f"--y={r['y']}", "--sign-count", str(r["sign_count"]),
               f"--name={r['name']}", f"--grant={r['grant']}")
    return out


@app.post("/auth/webauthn/login/start")
def webauthn_login_start(request: Request) -> dict:
    return _authd("webauthn_login_begin", addr=_client_addr(request))


class WebauthnLoginFinishRequest(BaseModel):
    credential: WebauthnCredential


@app.post("/auth/webauthn/login/finish")
def webauthn_login_finish(body: WebauthnLoginFinishRequest, request: Request,
                          response: Response) -> dict:
    r = _authd("webauthn_login_finish", addr=_client_addr(request),
              credential=body.credential.model_dump())
    sess = sessions.Session(r["session_id"], r["principal"], r["csrf"], False)
    sessions.set_cookie(response, sess)
    return {"user": r["principal"], "authenticated": True, "csrf": r["csrf"],
            "mfa_setup_required": bool(r.get("mfa_setup_required"))}


@app.get("/auth/webauthn/passkeys")
def webauthn_list_passkeys(caller: Caller = Depends(authenticated())) -> list:
    """Self only — the caller's own devices, never someone else's; see
    `admin passkey-list`'s comment for why this reads via a dedicated
    top-level verb rather than as a sub-verb of `principal` (fully refused
    to the API regardless of sub-verb)."""
    return _call("admin", "passkey-list", caller.principal)


class WebauthnRemovePasskeyRequest(BaseModel):
    current: Optional[ArgValue] = None
    totp: Optional[ArgValue] = None
    reauth: Optional[ReauthToken] = None


@app.post("/auth/webauthn/passkeys/{credential_id}/remove")
def webauthn_remove_passkey(credential_id: Base64UrlId, body: WebauthnRemovePasskeyRequest,
                            request: Request,
                            caller: Caller = Depends(authenticated())) -> dict:
    return _call("admin", "self", "passkey-remove", caller.principal, *_self_proof(body),
                 f"--credential-id={credential_id}", "--addr", _client_addr(request))


class SetWebauthnRequest(BaseModel):
    enabled: bool


@app.post("/admin/webauthn")
def set_webauthn(body: SetWebauthnRequest,
                 caller: Caller = Depends(require("iam:manage"))) -> dict:
    """A feature flag, not a permission grant — see set-webauthn's own
    comment in shared/iam.py for why this is API-reachable while
    set-policy is not."""
    return _call("admin", "set-webauthn", "on" if body.enabled else "off")


# What each kind of dashboard view may do. Your own: everything. Someone
# else's (an admin, down the ladder): look, stop a run, mark it complete, and
# manage their kept files — never launch, message, note, pause or switch
# models on their behalf (the operator's decision, §4 item 71).
DASHBOARD_ACTIONS = {
    "own": ["launch", "chat", "note", "stop", "pause", "resume", "acknowledge", "hide",
            "set_model", "outputs_delete"],
    "admin": ["stop", "acknowledge", "outputs_delete"],
}


@app.get("/dashboard")
def dashboard(user: Optional[PrincipalName] = None,
              caller: Caller = Depends(authenticated())) -> dict:
    """One user's whole dashboard in one call: every run they own (live
    status, recent activity, finished history) and their teams. Runs are
    private to the user who launched them (§4 item 71): without `user` this
    is the caller's own; with it, the dashboard ladder decides
    (iam.dashboard_access). Works the same with a session or an API key,
    which is the shape a future MCP tool layer reads."""
    target = user or caller.principal
    access = _authd("dashboard_access", viewer=caller.principal, target=target)
    if not access["allowed"]:
        raise HTTPException(status_code=403,
                            detail=f"you may not open {target}'s dashboard — {access['reason']}")
    mode = "own" if target == caller.principal else "admin"
    base = {"owner": target, "viewer": caller.principal, "mode": mode,
            "actions": DASHBOARD_ACTIONS[mode]}
    return {**_call("dashboard", "--owner", target), **base}


@app.get("/agents")
def list_agent_types(caller: Caller = Depends(authenticated())) -> dict:
    """The agent catalogue: which agents are installed on this box, with their
    title, description, scope kind and programs. Not sensitive, so any
    authenticated caller may read it."""
    return _call("agents")


@app.get("/admin/policy")
def get_policy(caller: Caller = Depends(require("iam:read"))) -> dict:
    """Read-only. Changing a policy is an authorization decision and stays
    behind `set-policy`, which is refused to the API; the GUI shows the exact
    command."""
    return _call("admin", "policy")


# The help pages. Every signed-in user may read them; `agenti docs` does the
# work, so the GUI shows exactly what the host's CLI prints.
DocPage = Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")]


@app.get("/docs")
def docs_list(caller: Caller = Depends(authenticated())) -> dict:
    return _call("docs", "list")


@app.get("/docs/search")
def docs_search(q: Annotated[str, Query(min_length=1, max_length=200)],
                caller: Caller = Depends(authenticated())) -> dict:
    return _call("docs", "search", f"--query={q}")


@app.get("/docs/{page}")
def docs_show(page: DocPage, caller: Caller = Depends(authenticated())) -> dict:
    return _call("docs", "show", page)


# Opt-in, report-only update check. The CLI verb does the work (and makes NO
# network request unless root switched the `update-check` policy on); this just
# relays it, with a short cache so a double-click cannot hammer GitHub's
# unauthenticated rate limit. It never installs anything.
_UPDATE_CACHE: dict = {"at": 0.0, "value": None}


@app.get("/admin/update-check")
def get_update_check(caller: Caller = Depends(require("iam:read"))) -> dict:
    now = time.monotonic()
    cached = _UPDATE_CACHE["value"]
    if cached is not None and now - _UPDATE_CACHE["at"] < 60:
        return cached
    result = _call("admin", "update-check")
    _UPDATE_CACHE.update(at=now, value=result)
    return result


# ---------------------------------------------------------------------------
# The admin Users view (CLAUDE.md's "authority rule", GUI phase 2).
#
# Every route below shells to one of the narrow verbs deliberately absent
# from shared/agenti's IAM_WRITE_VERBS refusal list (see that file's own
# comment) — never to "principal"/"group"/"revoke-key" in general, which
# stay fully refused to the API. Each one was picked because it can only
# REMOVE authority or grant NONE at all: creating a principal that holds no
# permissions, disabling one, revoking a key, shrinking a group. Restoring
# authority — enabling a disabled principal, any `bind`, resetting someone
# ELSE's password or 2FA — has no route here and stays a root CLI action,
# on purpose; the GUI shows the exact command instead of a button for those.
# ---------------------------------------------------------------------------
@app.get("/admin/users")
@app.get("/admin/principals", include_in_schema=False)
def list_principals(caller: Caller = Depends(require("iam:read"))) -> list:
    # NOT "admin user list" — "user" is fully refused to the API
    # regardless of sub-verb (refuse_iam_writes_from_api matches the
    # top-level verb name only). list-users is the dedicated read-only
    # twin, same shape as list-keys just above it in shared/iam.py.
    return _call("admin", "list-users")


class CreatePrincipalRequest(BaseModel):
    name: PrincipalName
    kind: Literal["user", "service"] = "user"
    role: Literal["operator", "admin"] = "operator"
    # A service principal authenticates with an API key, never a password —
    # minting it an enrolment link would be dead weight nobody consumes.
    no_link: bool = False
    # The creating admin re-authenticates for EVERY new account (operator
    # decision 2026-10-22): password + 2FA, or a passkey token.
    password: Optional[ArgValue] = None
    totp: Optional[ArgValue] = None
    reauth: Optional[ReauthToken] = None


@app.post("/admin/users")
@app.post("/admin/principals", include_in_schema=False)
def create_principal(body: CreatePrincipalRequest, request: Request,
                     caller: Caller = Depends(require("iam:manage"))) -> dict:
    sid = request.cookies.get(sessions.COOKIE_NAME)
    if caller.via != "session" or not sid:
        raise HTTPException(
            status_code=400,
            detail="creating a user needs a signed-in browser session: the creating admin "
                   "re-enters their password and a fresh 2FA code (or uses a passkey). An API "
                   f"key cannot do this — use the CLI: sudo agenti admin create-user {body.name}")
    action = {"op": "create-user", "principal": body.name, "kind": body.kind, "role": body.role,
              "resource": iam.ORG_RESOURCE}
    g = _authd("approve_action", session_id=sid, password=body.password or "", reauth=body.reauth or "",
               totp=body.totp or "", action=action, addr=_client_addr(request))
    args = ["admin", "create-user", body.name, "--kind", body.kind, "--role", body.role,
            f"--grant={g['grant']}"]
    if body.no_link:
        args.append("--no-link")
    result = _call(*args)
    if isinstance(result, dict):
        result["by"] = caller.principal
    return result


@app.post("/admin/users/{name}/disable")
@app.post("/admin/principals/{name}/disable", include_in_schema=False)
def disable_principal(name: PrincipalName,
                      caller: Caller = Depends(require("iam:manage"))) -> dict:
    return _call("admin", "disable-user", name, "--by", caller.principal)


@app.post("/admin/users/{name}/enrolment-link")
@app.post("/admin/principals/{name}/enrolment-link", include_in_schema=False)
def reissue_enrolment_link(name: PrincipalName,
                           caller: Caller = Depends(require("iam:manage"))) -> dict:
    """For a principal whose original link expired before they used it."""
    return _call("admin", "mint-enrolment-link", name)


@app.post("/admin/keys/{prefix}/revoke")
def revoke_key(prefix: ArgValue,
               caller: Caller = Depends(require("iam:manage"))) -> dict:
    _call_text("admin", "revoke-key", prefix)
    return {"prefix": prefix, "revoked": True}


@app.get("/admin/keys")
def list_keys(user: Optional[PrincipalName] = None, principal: Optional[PrincipalName] = None,
             caller: Caller = Depends(require("iam:read"))) -> list:
    args = ["admin", "list-keys"]
    if user or principal:
        args += ["--user", user or principal]
    return _call(*args)


# ---------------------------------------------------------------------------
# Bounded access grants from the browser (§4 item 24) — see iam.py's
# WEB_GRANTABLE_ROLES comment for the whole argument, including why admin is
# safe to add here: it is bounded by web_bind()'s own approver check, not by
# "the API already has this anyway". Two routes:
#
#   POST /admin/principals/{name}/access          grant operator or admin. Needs
#                                                  the caller's fresh
#                                                  re-authentication (authd mints
#                                                  a single-use grant bound to
#                                                  this exact action; the root
#                                                  CLI consumes it).
#   POST /admin/principals/{name}/access/remove   remove such a binding. No
#                                                  re-auth: removing authority is
#                                                  fail-safe. Same bound.
# ---------------------------------------------------------------------------
WebRole = Literal["operator", "admin"]


class GrantAccessRequest(BaseModel):
    role: WebRole
    # What the approver proves: password + a fresh 2FA code, or a passkey
    # re-authentication token. authd re-derives which are required from the
    # action's own `op`/`role`, never from what this request claims.
    password: Optional[ArgValue] = None
    totp: Optional[ArgValue] = None
    reauth: Optional[ReauthToken] = None


@app.post("/admin/users/{name}/access")
@app.post("/admin/principals/{name}/access", include_in_schema=False)
def grant_access(name: PrincipalName, body: GrantAccessRequest, request: Request,
                 caller: Caller = Depends(require("iam:manage"))) -> dict:
    sid = request.cookies.get(sessions.COOKIE_NAME)
    if caller.via != "session" or not sid:
        raise HTTPException(status_code=400,
                            detail="granting access needs a signed-in browser session: the "
                                   "approving admin re-enters their password and a fresh 2FA "
                                   "code. An API key cannot do this — use the CLI: "
                                   f"sudo agenti admin bind user {name} --role "
                                   f"{body.role}")
    action = {"op": "bind", "principal": name, "role": body.role, "resource": iam.ORG_RESOURCE}
    g = _authd("approve_action", session_id=sid, password=body.password or "", reauth=body.reauth or "",
               totp=body.totp or "", action=action, addr=_client_addr(request))
    return _call("admin", "web-bind", name, "--role", body.role, f"--grant={g['grant']}")


class RemoveAccessRequest(BaseModel):
    role: WebRole


@app.post("/admin/users/{name}/access/remove")
@app.post("/admin/principals/{name}/access/remove", include_in_schema=False)
def remove_access(name: PrincipalName, body: RemoveAccessRequest,
                  caller: Caller = Depends(require("iam:manage"))) -> dict:
    return _call("admin", "web-unbind", name, "--role", body.role)


@app.get("/admin/bindings")
def list_bindings(user: Optional[PrincipalName] = None, principal: Optional[PrincipalName] = None,
                  caller: Caller = Depends(require("iam:read"))) -> list:
    # ?user= is the name; ?principal= is the old spelling, still accepted. The
    # typed parameter makes a bad name a 422 instead of an unhandled 500.
    args = ["admin", "bindings"]
    if user or principal:
        args += ["--user", user or principal]
    return _call(*args)


# ---------------------------------------------------------------------------
# Renaming/hard-deleting a user (the operator's own explicit choice — "a
# genuine hard delete", "a real rename" — over the softer disable/display-
# name conventions everything above this comment uses). Unlike the bounded
# grants above, there is no ROLE the caller picks: the resource being
# approved is always the organisation, so it is never taken from the request
# body. Same re-authenticated, single-use action-grant mechanism as
# grant_access(), because a rename re-points every audit/run-history record
# that names the account, and a delete is irreversible: both are judged to
# need a human re-proving their OWN credential fresh, not merely a route
# whose permission check the caller's session already satisfies.
# ---------------------------------------------------------------------------
class RenamePrincipalRequest(BaseModel):
    new_name: PrincipalName
    password: Optional[ArgValue] = None
    totp: Optional[ArgValue] = None
    reauth: Optional[ReauthToken] = None


class ReauthRequest(BaseModel):
    password: Optional[ArgValue] = None
    totp: Optional[ArgValue] = None
    reauth: Optional[ReauthToken] = None


@app.post("/admin/users/{name}/rename")
@app.post("/admin/principals/{name}/rename", include_in_schema=False)
def rename_principal_route(name: PrincipalName, body: RenamePrincipalRequest, request: Request,
                           caller: Caller = Depends(require("iam:manage"))) -> dict:
    sid = request.cookies.get(sessions.COOKIE_NAME)
    if caller.via != "session" or not sid:
        raise HTTPException(
            status_code=400,
            detail="renaming a user needs a signed-in browser session: the approving admin "
                   "re-enters their password and a fresh 2FA code. An API key cannot do "
                   f"this — use the CLI: sudo agenti admin rename-user {name} "
                   f"{body.new_name} --grant <id>")
    action = {"op": "rename-principal", "principal": name, "new_name": body.new_name,
             "resource": iam.ORG_RESOURCE}
    g = _authd("approve_action", session_id=sid, password=body.password or "", reauth=body.reauth or "",
              totp=body.totp or "", action=action, addr=_client_addr(request))
    return _call("admin", "rename-user", name, body.new_name,
                f"--grant={g['grant']}")


@app.post("/admin/users/{name}/delete")
@app.post("/admin/principals/{name}/delete", include_in_schema=False)
def delete_principal_route(name: PrincipalName, body: ReauthRequest, request: Request,
                           caller: Caller = Depends(require("iam:manage"))) -> dict:
    sid = request.cookies.get(sessions.COOKIE_NAME)
    if caller.via != "session" or not sid:
        raise HTTPException(
            status_code=400,
            detail="deleting a user needs a signed-in browser session: the approving admin "
                   "re-enters their password and a fresh 2FA code. An API key cannot do "
                   f"this — use the CLI: sudo agenti admin delete-user {name} "
                   f"--grant <id>")
    action = {"op": "delete-principal", "principal": name, "resource": iam.ORG_RESOURCE}
    g = _authd("approve_action", session_id=sid, password=body.password or "", reauth=body.reauth or "",
              totp=body.totp or "", action=action, addr=_client_addr(request))
    return _call("admin", "delete-user", name, f"--grant={g['grant']}")


@app.post("/admin/users/{name}/enable")
@app.post("/admin/principals/{name}/enable", include_in_schema=False)
def enable_principal_route(name: PrincipalName, body: ReauthRequest, request: Request,
                           caller: Caller = Depends(require("iam:manage"))) -> dict:
    """Re-enable a disabled user. Enabling restores whatever access the account
    kept, so it needs the same re-authenticated single-use grant as rename and
    delete (§4 item 78)."""
    sid = request.cookies.get(sessions.COOKIE_NAME)
    if caller.via != "session" or not sid:
        raise HTTPException(
            status_code=400,
            detail="re-enabling a user needs a signed-in browser session: the approving admin "
                   "re-enters their password and a fresh 2FA code. An API key cannot do "
                   f"this — use the CLI: sudo agenti admin user enable {name}")
    action = {"op": "enable-principal", "principal": name, "resource": iam.ORG_RESOURCE}
    g = _authd("approve_action", session_id=sid, password=body.password or "", reauth=body.reauth or "",
              totp=body.totp or "", action=action, addr=_client_addr(request))
    return _call("admin", "enable-user", name, f"--grant={g['grant']}")


# ---------------------------------------------------------------------------
# Resetting a DIFFERENT user's password or MFA — the operator's own explicit
# request, after the authority rule (§4 item 21/56) had kept this CLI-only:
# "resetting someone else's credentials is restoring authority", so it needs
# the same re-authenticated, single-use action grant as rename/delete above,
# not a bare permission check. Admin only, from the GUI.
#
# Two independent actions, per the operator's own explicit ask ("I want the
# resetting password job and resetting MFA job to be separate tasks"):
# resetting one never touches the other, and each mints its own grant, so
# approving one can never be silently spent on the other.
# ---------------------------------------------------------------------------
class ResetPasswordRequest(BaseModel):
    mode: Literal["direct", "link"]
    new_password: Optional[ArgValue] = None
    password: Optional[ArgValue] = None
    totp: Optional[ArgValue] = None
    reauth: Optional[ReauthToken] = None

    @model_validator(mode="after")
    def _mode_shape(self):
        if self.mode == "direct" and not self.new_password:
            raise ValueError("mode 'direct' requires new_password")
        if self.mode == "link" and self.new_password:
            raise ValueError("mode 'link' must not include new_password")
        return self


@app.post("/admin/users/{name}/reset-password")
@app.post("/admin/principals/{name}/reset-password", include_in_schema=False)
def reset_principal_password_route(name: PrincipalName, body: ResetPasswordRequest, request: Request,
                                   caller: Caller = Depends(require("iam:manage"))) -> dict:
    sid = request.cookies.get(sessions.COOKIE_NAME)
    if caller.via != "session" or not sid:
        raise HTTPException(
            status_code=400,
            detail="resetting a user's password needs a signed-in browser session: the "
                   "approving admin re-enters their password and a fresh 2FA code. An API "
                   f"key cannot do this — use the CLI: sudo agenti admin "
                   f"reset-user-password {name} "
                   f"--grant <id> [--new <password>|--link]")
    action = {"op": "reset-password", "principal": name, "resource": iam.ORG_RESOURCE,
             "mode": body.mode}
    if body.mode == "direct":
        action["new_password"] = body.new_password
    g = _authd("approve_action", session_id=sid, password=body.password or "", reauth=body.reauth or "",
              totp=body.totp or "", action=action, addr=_client_addr(request))
    if body.mode == "direct":
        return _call("admin", "reset-user-password", name, 
                     f"--new={body.new_password}", f"--grant={g['grant']}")
    return _call("admin", "reset-user-password", name, 
                "--link", f"--grant={g['grant']}")


@app.post("/admin/users/{name}/reset-mfa")
@app.post("/admin/principals/{name}/reset-mfa", include_in_schema=False)
def reset_principal_mfa_route(name: PrincipalName, body: ReauthRequest, request: Request,
                              caller: Caller = Depends(require("iam:manage"))) -> dict:
    sid = request.cookies.get(sessions.COOKIE_NAME)
    if caller.via != "session" or not sid:
        raise HTTPException(
            status_code=400,
            detail="resetting a user's 2FA needs a signed-in browser session: the approving "
                   "admin re-enters their password and a fresh 2FA code. An API key cannot "
                   f"do this — use the CLI: sudo agenti admin reset-user-mfa {name} "
                   f"--grant <id>")
    action = {"op": "reset-mfa", "principal": name, "resource": iam.ORG_RESOURCE}
    g = _authd("approve_action", session_id=sid, password=body.password or "", reauth=body.reauth or "",
              totp=body.totp or "", action=action, addr=_client_addr(request))
    return _call("admin", "reset-user-mfa", name, f"--grant={g['grant']}")


@app.get("/admin/user-history")
@app.get("/admin/principal-history", include_in_schema=False)
def principal_history(caller: Caller = Depends(require("iam:read"))) -> list:
    return _call("admin", "user-history")


# ---------------------------------------------------------------------------
# Enrolment link consumption — the ONE pair of routes in this file with no
# `Depends(authenticated())` / `Depends(require(...))` at all, and that is
# deliberate, not an oversight: the entire point is letting someone who does
# not have an account yet set their first password. What stands in for
# authentication here is the token itself — high-entropy, single-use,
# short-lived (iam.ENROLMENT_TOKEN_TTL_S) — checked by
# iam.consume_enrolment_token(), the same shape a password-reset email link
# uses in any ordinary web app. A link can carry real authority (an account
# can be created with a role), so iam.py refuses the web account's own link
# for an admin, at minting and again here, and refuses any account already
# holding a credential or an API key. A new admin made from the web gets its
# link under the approving admin's name, through create-user's grant.
# ---------------------------------------------------------------------------
@app.get("/enrol/{token}")
def check_enrolment(token: LinkToken, request: Request) -> dict:
    with _LinkGate(request):
        return _call("admin", "enrol-check", token)


class ConsumeEnrolmentRequest(BaseModel):
    new: ArgValue
    totp_secret: Optional[ArgValue] = None
    totp_code: Optional[ArgValue] = None


@app.post("/enrol/{token}")
def consume_enrolment(token: LinkToken, body: ConsumeEnrolmentRequest, request: Request) -> dict:
    args = ["admin", "enrol-consume", token, "--new", body.new]
    if body.totp_secret and body.totp_code:
        args += ["--totp-secret", body.totp_secret, "--totp-code", body.totp_code]
    with _LinkGate(request):
        return _call(*args)


# ---------------------------------------------------------------------------
# Password reset link consumption — the SAME "no auth on this route at all,
# on purpose" shape as /enrol/{token} above, for the opposite case: an
# already-enrolled account whose admin chose "send a one-time link" (see
# iam.mint_password_reset_link). The token itself is the credential, same
# entropy/single-use/short-TTL (iam.PASSWORD_RESET_TOKEN_TTL_S) reasoning.
# Resets ONLY the password — never 2FA/passkeys, which stay a separate,
# always-authenticated admin action (reset-mfa above).
# ---------------------------------------------------------------------------
@app.get("/password-reset/{token}")
def check_password_reset(token: LinkToken, request: Request) -> dict:
    with _LinkGate(request):
        return _call("admin", "password-reset-check", token)


class ConsumePasswordResetRequest(BaseModel):
    new_password: ArgValue


@app.post("/password-reset/{token}")
def consume_password_reset(token: LinkToken, body: ConsumePasswordResetRequest,
                           request: Request) -> dict:
    with _LinkGate(request):
        return _call("admin", "password-reset-consume", token, f"--new={body.new_password}")


# ---------------------------------------------------------------------------
# The Outputs store and the tool-request queue. Same discipline as every
# route above — one permission check, one `agenti` call — plus a binary
# download (bytes OUT), documented where it happens below.
# ---------------------------------------------------------------------------


@app.get("/outputs")
def list_outputs(user: Optional[PrincipalName] = None,
                 caller: Caller = Depends(require("agent:read"))) -> dict:
    """One user's kept files plus the two-level quota (decision 8): the
    caller's own, or — down the dashboard ladder — the user named by `user`.
    Kept files are private like runs (§4 item 71); there is no organisation-wide
    listing."""
    owner = _owner(caller, user)
    rows = _call("admin", "outputs-list", "--user", owner)
    usage = _call("admin", "outputs-usage", "--user", owner)
    return {"owner": owner,
            "outputs": rows if isinstance(rows, list) else [], **usage}


@app.get("/outputs/{principal}/{name}")
def download_output(principal: PrincipalName, name: ReportFile,
                    caller: Caller = Depends(require("agent:read"))) -> RawResponse:
    """Binary-safe by construction: run_agenti_bytes() never decodes a
    success payload as text, unlike every other route here. Ownership
    (own output, or an admin's) is enforced inside iam.py's
    resolve_output_path(), not re-checked here — the same "the CLI enforces
    it, the route just calls it" shape."""
    _owner(caller, principal)   # yours, or allowed down the ladder
    body = _call_bytes("admin", "outputs-cat", "--user", principal,
                       "--by", caller.principal, name)
    return RawResponse(
        content=body, media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{name}"',
                 "Cache-Control": "no-store"})


class PromoteOutputBody(BaseModel):
    file: ReportFile
    copy: Optional[CopyLabel] = None


@app.post("/agents/{agent}/promote-output")
def promote_output_route(agent: AgentName, body: PromoteOutputBody,
                         caller: Caller = Depends(require("output:promote"))) -> dict:
    """Keep one of YOUR OWN run's reports in the permanent Outputs store.
    Never takes ?user=: promotion consumes the owner's quota, so an admin
    viewing someone's dashboard cannot do it for them (§4 item 78). The CLI
    re-checks the quota and that the file belongs to this run's owner."""
    return _call(agent, "promote-output", body.file,
                 *_slot(caller.principal, body.copy), "--by", caller.principal)


@app.delete("/outputs/{principal}/{name}")
def delete_output_route(principal: PrincipalName, name: ReportFile,
                        caller: Caller = Depends(require("output:delete"))) -> dict:
    _owner(caller, principal)
    return _call("admin", "outputs-delete", name, 
                "--user", principal, "--by", caller.principal)


class DeleteOutputsBody(BaseModel):
    names: list[ReportFile]


@app.post("/outputs/{principal}/delete")
def delete_outputs_route(principal: PrincipalName, body: DeleteOutputsBody,
                         caller: Caller = Depends(require("output:delete"))) -> dict:
    """Bulk form of delete_output_route (CLAUDE.md "Current plan" decision 5:
    the Outputs page's multi-select is one call, not N — the same shape as
    /{agent}/history/hide below). POST-with-a-body rather than
    DELETE-with-a-body, which fetch() and most HTTP clients handle awkwardly.
    iam.py's own delete_outputs() already resolves and deletes each name
    independently, so one bad name in the batch never aborts the rest —
    this route just relays that per-item result list back."""
    if not body.names:
        raise HTTPException(400, "no output names given")
    _owner(caller, principal)
    rows = _call("admin", "outputs-delete", *body.names, 
                "--user", principal, "--by", caller.principal)
    return {"user": principal,
            "results": rows if isinstance(rows, list) else []}


class ToolRequestBody(BaseModel):
    text: ArgValue
    category: ArgValue = ""


@app.post("/tool-requests")
def file_tool_request(body: ToolRequestBody,
                      caller: Caller = Depends(require("agent:read"))) -> dict:
    """Decision 4: "a tool the library lacks is a request, not a button."
    Needs only agent:read — anyone who can see an agent may ask for
    something it lacks; there is deliberately no way to act on one from
    here (see GET /admin/tool-requests's own docstring)."""
    return _call("admin", "tool-request-file", "--by", caller.principal,
                "--category", body.category or "", body.text)


@app.get("/admin/tool-requests")
def list_tool_requests(caller: Caller = Depends(require("iam:read"))) -> list:
    """Admin-only and read-only, on purpose: acting on a request means a
    human writing and reviewing real code, which stays outside this system
    — see the module-wide "Deliberately NOT exposed" note at the top of
    this file for the same reasoning applied to `purge`/`export`/etc."""
    return _call("admin", "tool-request-list")


# ---------------------------------------------------------------------------
# Read endpoints
# ---------------------------------------------------------------------------
@app.get("/agents/{agent}/status")
def status(agent: AgentName, copy: Optional[CopyLabel] = None,
           user: Optional[PrincipalName] = None,
           caller: Caller = Depends(require("agent:read"))) -> dict:
    return _call(agent, "status", *_slot(_owner(caller, user), copy))


@app.get("/agents/{agent}/show")
def show(agent: AgentName, copy: Optional[CopyLabel] = None,
         caller: Caller = Depends(require("agent:read"))) -> dict:
    return _call(agent, "show", *_slot(caller.principal, copy))


# ---------------------------------------------------------------------------
# Engagement: a property of the organisation, shared by every agent. The
# primary routes (GET/POST /engagement, POST /engagement/approve) are below;
# this per-agent GET is that agent's own VIEW, filtered to its scope kind.
# ---------------------------------------------------------------------------
@app.get("/agents/{agent}/engagement")
def engagement(agent: AgentName,
               caller: Caller = Depends(require("agent:read"))) -> dict:
    """This agent's own VIEW of the engagement — its own scope kind's entries
    only (a CIDR agent never sees a domain agent's scope, or vice versa).
    Read-only; GET /engagement returns the full record with both kinds, for
    the admin editor."""
    return _call(agent, "engagement")


# ---- per-agent scope: a NARROWING of the engagement ------------------------
# Admin only (iam:read / iam:manage). The CLI/store re-check that every entry
# lies inside the engagement's own scope.
class AgentScopeRequest(BaseModel):
    in_scope: list[ArgValue] = []      # empty = no narrowing (inherit the engagement's)
    out_of_scope: list[ArgValue] = []


@app.get("/admin/agent-scope/{scope_agent}")
def get_agent_scope(scope_agent: AgentName,
                    caller: Caller = Depends(require("iam:read"))) -> dict:
    """The engagement's scope, this agent's own narrowing of it, and the overlap
    a run is actually held to."""
    return _call(scope_agent, "agent-scope", "show")


@app.post("/admin/agent-scope/{scope_agent}")
def set_agent_scope(scope_agent: AgentName, body: AgentScopeRequest,
                    caller: Caller = Depends(require("iam:manage"))) -> dict:
    args = [scope_agent, "agent-scope", "set"]
    for entry in body.in_scope:
        args += ["--in", entry]
    for entry in body.out_of_scope:
        args += ["--out", entry]
    args += ["--by", caller.principal, "--via", "api"]
    return _call(*args)


# ---- the tool allow-list override (CLAUDE.md "Current plan" phase 6) -------
# Global admin only, same gate as agent-scope above: iam:read to see it,
# iam:manage to change it. No extra re-authentication, unlike the instruction
# files — what keeps this safe is not a password prompt but the CLOSED
# catalog an admin can only pick FROM (shared/tool-catalog.json, reviewed
# ahead of time), never type into. An "add" naming anything outside it is
# refused by shared/tool_catalog.py before a byte is written.
class ToolSettingsRequest(BaseModel):
    enable: list[ArgValue] = []
    disable: list[ArgValue] = []
    approvable: list[ArgValue] = []     # catalog programs an operator may approve for one run


@app.get("/admin/tool-settings/{scope_agent}")
def get_tool_settings(scope_agent: AgentName,
                      caller: Caller = Depends(require("iam:read"))) -> dict:
    """This agent's own baseline allow-list, the admin's override, the
    effective result, and the reviewed catalog of programs that may be
    added — everything Settings → Agents needs to draw the checklist."""
    return _call(scope_agent, "tool-settings", "show")


@app.post("/admin/tool-settings/{scope_agent}")
def set_tool_settings(scope_agent: AgentName, body: ToolSettingsRequest,
                      caller: Caller = Depends(require("iam:manage"))) -> dict:
    args = [scope_agent, "tool-settings", "set"]
    for entry in body.enable:
        args += ["--enable", entry]
    for entry in body.disable:
        args += ["--disable", entry]
    for entry in body.approvable:
        args += ["--approvable", entry]
    args += ["--by", caller.principal, "--via", "api"]
    return _call(*args)



@app.get("/admin/agent-controls/{scope_agent}")
def get_agent_controls(scope_agent: AgentName,
                       caller: Caller = Depends(require("iam:read"))) -> dict:
    """Everything that controls or restricts one agent, plus the live-vs-declared
    drift check. Admin only."""
    return _call(scope_agent, "controls")



# ---- instruction files (shared/context_store.py) ----------------------------
# system-prompt / skills / platform-skills / the organisation policy file:
# admin only. Every save, reset or revert needs a
# fresh re-authentication (an 'edit-context' approval grant bound to the file,
# the change and the SHA-256 of the exact text); the root verb re-checks the
# approver's authority. memory.md (one user's preferences) is the exception:
# the owner edits their own with just their session, an admin on the dashboard
# ladder may read it but never change it.
_CONTEXT_KINDS = ("system-prompt", "skills", "platform-skills")
_VERSION_RE = r"^\d+-[0-9a-f]{12}$"


class ContextEditRequest(BaseModel):
    change: Literal["set", "reset", "revert"] = "set"
    text: Optional[str] = Field(default=None, max_length=30000)
    version: Optional[str] = Field(default=None, pattern=_VERSION_RE)
    agent: Optional[AgentName] = None            # system-prompt and skills only
    password: Optional[ArgValue] = None
    totp: Optional[ArgValue] = None
    reauth: Optional[ReauthToken] = None


def _context_view(kind: str, who: list[str], version: Optional[str] = None) -> dict:
    if version is not None:
        if not re.fullmatch(_VERSION_RE, version):
            raise HTTPException(status_code=422, detail="not a saved version id")
        out = _call("admin", "context-read", "version", kind, *who, f"--version={version}")
        return {"version": version, "version_text": out.get("text", "")}
    cur = _call("admin", "context-read", "show", kind, *who)
    hist = _call("admin", "context-read", "history", kind, *who, "-n", "30")
    return {**cur, "history": hist.get("history", [])}


def _context_edit(request: Request, caller: "Caller", body: ContextEditRequest, *,
                  kind: str, who: list[str]) -> dict:
    sid = request.cookies.get(sessions.COOKIE_NAME)
    if caller.via != "session" or not sid:
        raise HTTPException(status_code=400, detail="editing instructions needs a signed-in "
                            "browser session: the approving admin re-authenticates. Use the CLI "
                            "(sudo agenti admin context ...) with an API key.")
    action = {"op": "edit-context", "kind": kind, "change": body.change,
              "resource": iam.ORG_RESOURCE}
    for flag in who:
        if flag.startswith("--agent="):
            action["agent"] = flag.split("=", 1)[1]
    text = None
    if body.change == "set":
        if body.text is None:
            raise HTTPException(status_code=422, detail="'text' is required to save")
        text = body.text.replace("\r\n", "\n")
        action["sha256"] = iam.context_text_sha256(text)
    elif body.change == "revert":
        if not body.version:
            raise HTTPException(status_code=422, detail="'version' is required to revert")
        action["version"] = body.version
    g = _authd("approve_action", session_id=sid, password=body.password or "", reauth=body.reauth or "",
               totp=body.totp or "", action=action, addr=_client_addr(request))
    args = ["admin", "context-web", body.change, kind, *who, f"--grant={g['grant']}"]
    if body.change == "revert":
        args.append(f"--version={body.version}")
    try:
        out = run_agenti(*args, stdin_text=text)
    except AgentiError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)
    return {**out, "approved_by": g["approved_by"]}


@app.get("/admin/context/{ctx_kind}")
def get_context(ctx_kind: Literal["system-prompt", "skills", "platform-skills"],
                agent: Optional[AgentName] = None, version: Optional[str] = None,
                caller: Caller = Depends(require("iam:read"))) -> dict:
    if ctx_kind != "platform-skills" and not agent:
        raise HTTPException(status_code=422, detail="'agent' is required for this file")
    return _context_view(ctx_kind, [] if ctx_kind == "platform-skills" else [f"--agent={agent}"], version)


@app.post("/admin/context/{ctx_kind}")
def edit_context(ctx_kind: Literal["system-prompt", "skills", "platform-skills"],
                 body: ContextEditRequest, request: Request,
                 caller: Caller = Depends(require("iam:manage"))) -> dict:
    if ctx_kind != "platform-skills" and not body.agent:
        raise HTTPException(status_code=422, detail="'agent' is required for this file")
    who = [] if ctx_kind == "platform-skills" else [f"--agent={body.agent}"]
    return _context_edit(request, caller, body, kind=ctx_kind, who=who)


@app.get("/context/org")
def get_org_context(version: Optional[str] = None,
                    caller: Caller = Depends(require("iam:read"))) -> dict:
    return _context_view("org", [], version)


@app.post("/context/org")
def edit_org_context(body: ContextEditRequest, request: Request,
                     caller: Caller = Depends(require("iam:manage"))) -> dict:
    return _context_edit(request, caller, body, kind="org", who=[])


# ---- building an agent from the GUI (shared/agent_builder.py) ----------------
# Global admins only. A built agent is data: a fixed stub that runs
# shared/recon_runner.py, a manifest naming reviewed recon programs, and its
# system prompt. Creating and removing one needs a fresh
# re-authentication; the create approval is bound to the SHA-256 of the exact
# normalized spec, which the root CLI recomputes before it builds anything.
# The kind is checked by the builder against its own KINDS (the one list); this
# only keeps the value tidy on the way in. Left out, it means "recon", as it
# always did. Without the field here the model would silently DROP it, and a
# file-analysis spec would be built as a recon agent.
AgentKind = Annotated[str, Field(pattern=r"^[a-z]{3,20}$")]


class AgentSpec(BaseModel):
    kind: AgentKind = "recon"
    name: AgentName
    title: str = Field(max_length=200)
    description: str = Field(max_length=1000)
    programs: list[str] = Field(min_length=1, max_length=60)
    system_prompt: str = Field(max_length=30000)


class AgentBuildRequest(BaseModel):
    spec: AgentSpec
    password: Optional[ArgValue] = None
    totp: Optional[ArgValue] = None
    reauth: Optional[ReauthToken] = None


class AgentRemoveRequest(BaseModel):
    password: Optional[ArgValue] = None
    totp: Optional[ArgValue] = None
    reauth: Optional[ReauthToken] = None


def _spec_json(spec: AgentSpec) -> str:
    return json.dumps(spec.model_dump(), ensure_ascii=False)


def _session_for_approval(request: Request, caller: "Caller", what: str) -> str:
    sid = request.cookies.get(sessions.COOKIE_NAME)
    if caller.via != "session" or not sid:
        raise HTTPException(status_code=400, detail=f"{what} needs a signed-in browser session: "
                            "the approving admin re-authenticates. From a terminal use "
                            "sudo agenti admin agent-build ... instead.")
    return sid


class ApiKeyRequest(BaseModel):
    key: Annotated[str, Field(pattern=r"^sk-ant-[A-Za-z0-9_-]{8,500}$")]
    password: Optional[ArgValue] = None
    totp: Optional[ArgValue] = None
    reauth: Optional[ReauthToken] = None


@app.post("/admin/api-key")
def set_api_key(body: ApiKeyRequest, request: Request,
                caller: Caller = Depends(require("iam:manage"))) -> dict:
    """Settings → Platform → API key: the organisation's Anthropic key (the
    shared tier). Behind a fresh admin re-authentication bound to the key's
    SHA-256; the key goes to root as the request BODY on stdin, never an
    argument, and is never sent back."""
    sid = _session_for_approval(request, caller, "Saving the API key")
    sha = hashlib.sha256(body.key.encode()).hexdigest()
    g = _authd("approve_action", session_id=sid, password=body.password or "", reauth=body.reauth or "",
               totp=body.totp or "", action={"op": "set-api-key", "sha256": sha,
                                             "resource": iam.ORG_RESOURCE},
               addr=_client_addr(request))
    try:
        return run_agenti("admin", "set-api-key", f"--grant={g['grant']}", stdin_text=body.key + "\n")
    except AgentiError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


class VaultEnableRequest(BaseModel):
    size: Annotated[str, Field(pattern=r"^[1-9][0-9]{0,3}G$")] = "8G"
    passphrase: Annotated[str, Field(min_length=12, max_length=512)]
    password: Optional[ArgValue] = None
    totp: Optional[ArgValue] = None
    reauth: Optional[ReauthToken] = None


@app.post("/admin/vault/enable")
def vault_enable(body: VaultEnableRequest, request: Request,
                 caller: Caller = Depends(require("iam:manage"))) -> dict:
    """Settings → Platform → Vault → Turn on (operator decision 6, audit run 1).
    Behind a fresh admin re-authentication bound to the container size. The
    passphrase goes to root as the request BODY on stdin, never an argument, so
    it is in no command line and no log, and nothing stores it. Unlock, lock,
    disable and passphrase changes stay at the host's terminal."""
    if any(ord(c) < 32 for c in body.passphrase):
        raise HTTPException(status_code=422, detail="the passphrase may not contain line breaks or control characters")
    sid = _session_for_approval(request, caller, "Turning the vault on")
    g = _authd("approve_action", session_id=sid, password=body.password or "", reauth=body.reauth or "",
               totp=body.totp or "", action={"op": "vault-enable", "size": body.size,
                                             "resource": iam.ORG_RESOURCE},
               addr=_client_addr(request))
    try:
        # Allocating, formatting and copying the data in takes minutes, not seconds.
        return run_agenti("vault", "enable", f"--size={body.size}", f"--grant={g['grant']}",
                          stdin_text=body.passphrase + "\n", timeout=1800)
    except AgentiError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


def _agent_build(*args: str, stdin_text: Optional[str] = None, timeout: float = 30) -> dict:
    try:
        return run_agenti("admin", "agent-build", *args, stdin_text=stdin_text, timeout=timeout)
    except AgentiError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


@app.get("/admin/agent-builder/catalog")
def agent_builder_catalog(caller: Caller = Depends(require("iam:manage"))) -> dict:
    return _agent_build("tools")


@app.post("/admin/agent-builder/check")
def agent_builder_check(spec: AgentSpec, caller: Caller = Depends(require("iam:manage"))) -> dict:
    return _agent_build("check", stdin_text=_spec_json(spec))


@app.post("/admin/agent-builder/create")
def agent_builder_create(body: AgentBuildRequest, request: Request,
                         caller: Caller = Depends(require("iam:manage"))) -> dict:
    sid = _session_for_approval(request, caller, "Building an agent")
    text = _spec_json(body.spec)
    checked = _agent_build("check", stdin_text=text)
    action = {"op": "build-agent", "name": checked["spec"]["name"],
              "sha256": checked["sha256"], "resource": iam.ORG_RESOURCE}
    g = _authd("approve_action", session_id=sid, password=body.password or "", reauth=body.reauth or "",
               totp=body.totp or "", action=action, addr=_client_addr(request))
    return _agent_build("create", f"--grant={g['grant']}", stdin_text=text, timeout=180)


class AgentEditSpec(BaseModel):
    # Optional: an agent's kind is fixed when it is built, so an edit that
    # omits it keeps the agent's own (the builder refuses a different one).
    kind: Optional[AgentKind] = None
    name: AgentName
    title: str = Field(max_length=200)
    description: str = Field(max_length=1000)
    programs: list[str] = Field(min_length=1, max_length=60)


class AgentEditRequest(BaseModel):
    spec: AgentEditSpec
    password: Optional[ArgValue] = None
    totp: Optional[ArgValue] = None
    reauth: Optional[ReauthToken] = None


@app.post("/admin/agent-builder/check-update")
def agent_builder_check_update(spec: AgentEditSpec, caller: Caller = Depends(require("iam:manage"))) -> dict:
    return _agent_build("check-update", stdin_text=json.dumps(spec.model_dump(exclude_none=True), ensure_ascii=False))


@app.post("/admin/agent-builder/update")
def agent_builder_update(body: AgentEditRequest, request: Request,
                         caller: Caller = Depends(require("iam:manage"))) -> dict:
    sid = _session_for_approval(request, caller, "Editing an agent")
    text = json.dumps(body.spec.model_dump(exclude_none=True), ensure_ascii=False)
    checked = _agent_build("check-update", stdin_text=text)
    action = {"op": "update-agent", "name": checked["spec"]["name"],
              "sha256": checked["sha256"], "resource": iam.ORG_RESOURCE}
    g = _authd("approve_action", session_id=sid, password=body.password or "", reauth=body.reauth or "",
               totp=body.totp or "", action=action, addr=_client_addr(request))
    return _agent_build("update", f"--grant={g['grant']}", stdin_text=text, timeout=120)


@app.get("/admin/agent-builder/{built_name}/remove-preview")
def agent_builder_remove_preview(built_name: AgentName,
                                 caller: Caller = Depends(require("iam:manage"))) -> dict:
    return _agent_build("preview", built_name)


@app.post("/admin/agent-builder/{built_name}/remove")
def agent_builder_remove(built_name: AgentName, body: AgentRemoveRequest, request: Request,
                         caller: Caller = Depends(require("iam:manage"))) -> dict:
    sid = _session_for_approval(request, caller, "Removing an agent")
    preview = _agent_build("preview", built_name)
    if preview.get("blocked"):
        raise HTTPException(status_code=409, detail=f"Can't remove it yet: {preview['blocked']}.")
    action = {"op": "remove-agent", "name": built_name, "resource": iam.ORG_RESOURCE}
    g = _authd("approve_action", session_id=sid, password=body.password or "", reauth=body.reauth or "",
               totp=body.totp or "", action=action, addr=_client_addr(request))
    return _agent_build("remove", built_name, f"--grant={g['grant']}", timeout=180)


# ---- the command-line program catalog (shared/catalog_admin.py) -------------
# Which programs an admin can switch on for a shell-running agent. Global
# admins only; add/update/remove need a fresh re-authentication bound to the
# exact entry. Adding offers a program — it does not give any agent it.
class CatalogEntry(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    group: str = Field(default="other", max_length=24)
    purpose: str = Field(max_length=300)
    extra_denied: list[str] = Field(default_factory=list, max_length=20)


class CatalogEditRequest(BaseModel):
    entry: CatalogEntry
    password: Optional[ArgValue] = None
    totp: Optional[ArgValue] = None
    reauth: Optional[ReauthToken] = None


class CatalogRemoveRequest(BaseModel):
    password: Optional[ArgValue] = None
    totp: Optional[ArgValue] = None
    reauth: Optional[ReauthToken] = None


def _catalog_call(*args: str, stdin_text: Optional[str] = None) -> dict:
    try:
        return run_agenti("admin", "catalog", *args, stdin_text=stdin_text, timeout=30)
    except AgentiError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


@app.get("/admin/catalog")
def catalog_list(caller: Caller = Depends(require("iam:manage"))) -> dict:
    return _catalog_call("list")


@app.get("/admin/catalog/history")
def catalog_history(caller: Caller = Depends(require("iam:manage"))) -> dict:
    return _catalog_call("history")


@app.post("/admin/catalog/check")
def catalog_check(entry: CatalogEntry, caller: Caller = Depends(require("iam:manage"))) -> dict:
    return _catalog_call("check", stdin_text=json.dumps(entry.model_dump(), ensure_ascii=False))


@app.post("/admin/catalog/check-update")
def catalog_check_update(entry: CatalogEntry, caller: Caller = Depends(require("iam:manage"))) -> dict:
    return _catalog_call("check-update", stdin_text=json.dumps(entry.model_dump(), ensure_ascii=False))


def _catalog_change(change: str, body: CatalogEditRequest, request: Request, caller: "Caller") -> dict:
    sid = _session_for_approval(request, caller, "Changing the program catalog")
    text = json.dumps(body.entry.model_dump(), ensure_ascii=False)
    checked = _catalog_call("check" if change == "add" else "check-update", stdin_text=text)
    action = {"op": "edit-catalog", "name": checked["entry"]["name"], "change": change,
              "sha256": checked["sha256"], "resource": iam.ORG_RESOURCE}
    g = _authd("approve_action", session_id=sid, password=body.password or "", reauth=body.reauth or "",
               totp=body.totp or "", action=action, addr=_client_addr(request))
    return _catalog_call(change, f"--grant={g['grant']}", stdin_text=text)


@app.post("/admin/catalog/add")
def catalog_add(body: CatalogEditRequest, request: Request,
                caller: Caller = Depends(require("iam:manage"))) -> dict:
    return _catalog_change("add", body, request, caller)


@app.post("/admin/catalog/update")
def catalog_update(body: CatalogEditRequest, request: Request,
                   caller: Caller = Depends(require("iam:manage"))) -> dict:
    return _catalog_change("update", body, request, caller)


@app.post("/admin/catalog/{program}/remove")
def catalog_remove(program: Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$")],
                   body: CatalogRemoveRequest, request: Request,
                   caller: Caller = Depends(require("iam:manage"))) -> dict:
    sid = _session_for_approval(request, caller, "Changing the program catalog")
    action = {"op": "edit-catalog", "name": program, "change": "remove", "resource": iam.ORG_RESOURCE}
    g = _authd("approve_action", session_id=sid, password=body.password or "", reauth=body.reauth or "",
               totp=body.totp or "", action=action, addr=_client_addr(request))
    return _catalog_call("remove", program, f"--grant={g['grant']}")


class MemoryRequest(BaseModel):
    text: Optional[str] = Field(default=None, max_length=30000)
    reset: bool = False


@app.get("/agents/{agent}/memory")
def get_memory(agent: AgentName, user: Optional[ArgValue] = None,
               version: Optional[str] = None,
               caller: Caller = Depends(require("agent:read"))) -> dict:
    """A user's preferences for this agent. Your own, or — for an admin on the
    dashboard ladder — someone else's, read-only."""
    owner = _owner(caller, user)
    who = [f"--agent={agent}", f"--user={owner}"]
    if version is not None:
        return _context_view("memory", who, version)
    out = _context_view("memory", who)
    out["owner"] = owner
    out["editable"] = owner == caller.principal
    return out


@app.post("/agents/{agent}/memory")
def set_memory(agent: AgentName, body: MemoryRequest,
               caller: Caller = Depends(require("agent:start"))) -> dict:
    """Save (or clear) the caller's OWN preferences. There is no `user`:
    nobody edits anyone else's."""
    base = ["admin", "context-memory"]
    who = [f"--agent={agent}", f"--user={caller.principal}",
           f"--by={caller.principal}"]
    try:
        if body.reset:
            return run_agenti(*base, "reset", "memory", *who)
        if body.text is None:
            raise HTTPException(status_code=422, detail="'text' or 'reset' is required")
        return run_agenti(*base, "set", "memory", *who, stdin_text=body.text.replace("\r\n", "\n"))
    except AgentiError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)




class ProposalDecision(BaseModel):
    decision: Literal["approve", "dismiss"]


@app.get("/agents/{agent}/memory/proposals")
def list_memory_proposals(agent: AgentName,
                          caller: Caller = Depends(require("agent:start"))) -> dict:
    """Preferences this agent SUGGESTED during the caller's own runs, waiting
    for the caller's yes or no. Only the owner sees or decides them."""
    return _call("admin", "context-memory", "proposals", "memory",
                 f"--agent={agent}", f"--user={caller.principal}",
                 f"--by={caller.principal}")


@app.post("/agents/{agent}/memory/proposals/{proposal_id}")
def decide_memory_proposal(agent: AgentName, proposal_id: str,
                           body: ProposalDecision,
                           caller: Caller = Depends(require("agent:start"))) -> dict:
    if not re.fullmatch(r"[0-9a-f]{12}", proposal_id):
        raise HTTPException(status_code=422, detail="not a suggestion id")
    return _call("admin", "context-memory", "decide", "memory",
                 f"--agent={agent}", f"--user={caller.principal}",
                 f"--by={caller.principal}", f"--id={proposal_id}", f"--decision={body.decision}")



class ToolApprovalDecision(BaseModel):
    slot: ArgValue
    decision: Literal["approve", "deny"]


@app.get("/agents/{agent}/tool-approvals")
def list_tool_approvals(agent: AgentName,
                        caller: Caller = Depends(require("agent:chat"))) -> dict:
    """Programs an agent asked to use during the CALLER's own runs and that
    nobody has answered yet. Only the owner sees or decides them: it is their
    run, their call. (Not the admin queue for adding tools to the library —
    that is /tool-requests.)"""
    return _call("admin", "tool-approvals", "pending", f"--agent={agent}", f"--user={caller.principal}")


@app.post("/agents/{agent}/tool-approvals/{approval_id}")
def decide_tool_approval(agent: AgentName, approval_id: str,
                         body: ToolApprovalDecision,
                         caller: Caller = Depends(require("agent:chat"))) -> dict:
    """Allow ONE offered program for one run, or decline. The root verb checks
    the admin actually offered it and that it is still in the catalog."""
    if not re.fullmatch(r"[0-9a-f]{12}", approval_id):
        raise HTTPException(status_code=422, detail="not a request id")
    return _call("admin", "tool-approvals", "decide", f"--agent={agent}",
                 f"--user={caller.principal}", f"--slot={body.slot}", f"--id={approval_id}",
                 f"--decision={body.decision}", f"--by={caller.principal}")


# ---- exploit agent: per-action approval (CLAUDE.md safety invariant 3, ------
# carve-out B). Unlike the tool-approvals offers above, approving one of
# these FIRES a real Metasploit module against a real target the moment it
# is approved — so, unlike agent:chat alone up there, deciding here also
# needs a fresh re-authentication bound to exactly this request (the same
# mechanism admin-sensitive actions use), even though the permission gate
# itself is the ordinary agent:chat every exploit approval already needs,
# not iam:manage. See iam.web_approve_exploit_action.
class ExploitApprovalDecision(BaseModel):
    decision: Literal["approve", "reject"]
    reason: Optional[ArgValue] = None   # required to reject, ignored for approve
    password: Optional[ArgValue] = None
    totp: Optional[ArgValue] = None
    reauth: Optional[ReauthToken] = None


@app.get("/agents/{agent}/action-pending")
@app.get("/agents/{agent}/exploit-pending")  # kept as alias
def list_exploit_pending(agent: AgentName,
                         caller: Caller = Depends(require("agent:chat"))) -> list:
    """Pending action proposals from the CALLER's own plugin-agent runs — each
    with a plain_summary of exactly what approving it would do.
    Only the owner sees or decides them: it is their run, their call."""
    return _call(agent, "action-pending", "--user", caller.principal)


@app.post("/agents/{agent}/action-pending/{request_id}")
@app.post("/agents/{agent}/exploit-pending/{request_id}")  # kept as alias
def decide_exploit_pending(agent: AgentName, request_id: str, body: ExploitApprovalDecision,
                          request: Request,
                          caller: Caller = Depends(require("agent:chat"))) -> dict:
    """Approve or reject one pending proposal from the caller's OWN run.
    The grant is bound to this exact request_id AND options_hash — re-fetched
    fresh here, never trusted from the client."""
    if not re.fullmatch(r"[0-9a-f]{8,32}", request_id):
        raise HTTPException(status_code=422, detail="not a request id")
    if body.decision == "reject" and not (body.reason or "").strip():
        raise HTTPException(status_code=422, detail="reason is required to reject a pending action")
    what = ("Approving a live action" if body.decision == "approve"
           else "Rejecting a pending action")
    sid = _session_for_approval(request, caller, what)
    rows = _call(agent, "action-pending", "--user", caller.principal)
    row = next((r for r in rows if isinstance(r, dict) and r.get("request_id") == request_id), None)
    if row is None:
        raise HTTPException(status_code=404,
                            detail=f"No pending request {request_id!r} — it may have already been "
                                   f"decided, timed out, or belongs to a run that is not yours.")
    action = {"op": f"action-{body.decision}", "agent": agent, "request_id": request_id,
              "options_hash": row.get("options_hash", ""), "owner": caller.principal,
              "resource": iam.ORG_RESOURCE}
    g = _authd("approve_action", session_id=sid, password=body.password or "", reauth=body.reauth or "",
               totp=body.totp or "", action=action, addr=_client_addr(request))
    args = [agent, f"action-{body.decision}", request_id, f"--owner={caller.principal}",
           f"--grant={g['grant']}"]
    if body.decision == "reject":
        args += ["--reason", body.reason]
    return _call(*args)


@app.get("/engagement")
def get_engagement(caller: Caller = Depends(require("agent:read"))) -> dict:
    """THE engagement: client, both scope kinds, validity window,
    data handling, approval status and recent history — the primary read
    for the admin editor. agent:read (not engagement:manage):
    anyone who can see an agent's page should be able to see what it is
    authorized to do, the same level the per-agent view already required."""
    return _call("engagement", "show")


class EngagementSetRequest(BaseModel):
    """A GUI form submits the FULL desired state of both scope kinds every
    time (what-you-see-is-what-you-get for an editor, not an incremental
    merge) — the route always passes --replace-scope for both kinds, so
    an empty list genuinely means "no entries of this kind", not "leave
    it as it was". The CLI itself still supports incremental edits
    (`agenti engagement set --cidr-in ...` alone); this route
    is deliberately the simpler, full-replace shape a form needs."""
    engagement_id: ArgValue
    client: ArgValue
    authorizing_party: ArgValue
    authorizing_title: ArgValue
    authorization_ref: ArgValue
    valid_from: ArgValue
    valid_until: ArgValue
    cidr_in: list[ArgValue] = []
    cidr_out: list[ArgValue] = []
    domain_in: list[ArgValue] = []
    domain_out: list[ArgValue] = []
    emergency_contact: ArgValue = ""
    notes: ArgValue = ""
    capture_payloads: bool = False
    enabled_capabilities: list = []
    exploitation_enabled: bool = False  # alias: adds "exploit" to enabled_capabilities
    retention_days: int = 0
    redact: list[ArgValue] = []
    # Operational policy (CLAUDE.md "Current plan" — replaces the retired
    # --dev/commercial split): full-replace like the scope fields above —
    # the Settings dialog always sends its complete current state, an empty
    # allowed_models clears back to the platform default set (--clear-
    # allowed-models), never "leave it as it was".
    require_approval: bool = True
    max_turns_ceiling: Optional[int] = None
    max_budget_ceiling: Optional[float] = None
    timeout_ceiling: Optional[int] = None
    allowed_models: list[ArgValue] = []
    # A ceiling left blank means "don't touch it" (the number fields above
    # are already None by default) — these are the explicit "revert this
    # ONE ceiling to the platform default" signal, mirroring the CLI's own
    # --clear-max-turns-ceiling/--clear-max-budget-ceiling/--clear-timeout-
    # ceiling, since "blank" already has a different meaning.
    clear_max_turns_ceiling: bool = False
    clear_max_budget_ceiling: bool = False
    clear_timeout_ceiling: bool = False
    # The saving admin re-authenticates (audit run 1, F13): the engagement is
    # the legal boundary, so writing it is an admin action like any other.
    password: Optional[ArgValue] = None
    totp: Optional[ArgValue] = None
    reauth: Optional[ReauthToken] = None


def _engagement_grant(request: Request, caller: Caller, body, action: dict, cli_hint: str) -> str:
    """A single-use grant for exactly `action`, from the caller re-proving
    themselves (password + 2FA, or a passkey token)."""
    sid = request.cookies.get(sessions.COOKIE_NAME)
    if caller.via != "session" or not sid:
        raise HTTPException(
            status_code=400,
            detail="this needs a signed-in browser session: you re-enter your password and a "
                   f"fresh 2FA code (or use a passkey). An API key cannot do it — use the CLI: {cli_hint}")
    g = _authd("approve_action", session_id=sid, password=body.password or "", reauth=body.reauth or "",
               totp=body.totp or "", action=action, addr=_client_addr(request))
    return g["grant"]


@app.post("/engagement")
def set_engagement(body: EngagementSetRequest, request: Request,
                          caller: Caller = Depends(require("engagement:manage"))) -> dict:
    """AUTHOR the engagement — client, authorized scope per kind,
    validity window (CLAUDE.md "Current plan": the engagement belongs to the organisation,
    not per agent). A SEPARATE, more powerful action than the approve
    route below: that answers "may a commercial run start against what is
    already on record"; this defines what the record IS.
    engagement:manage is admin-only by default (shared/iam.py's own
    comment on the permission explains why it is not in `operator`).

    Every field is validated by engagement_context.normalize_record
    before anything is written (CIDR/domain format per kind, real ISO
    dates, at least one kind non-empty) and made safe against injection
    via strict typing + length caps, not a character blacklist — this is
    JSON written by the store's own atomic writer, never interpolated
    into generated source the way the retired engagement_gen.py's output
    once was."""
    args = ["engagement", "set",
           "--engagement-id", body.engagement_id, "--client", body.client,
           "--authorizing-party", body.authorizing_party,
           "--authorizing-title", body.authorizing_title,
           "--authorization-ref", body.authorization_ref,
           "--valid-from", body.valid_from, "--valid-until", body.valid_until,
           "--replace-scope", "cidr", "--replace-scope", "domain"]
    for entry in body.cidr_in:
        args += ["--cidr-in", entry]
    for entry in body.cidr_out:
        args += ["--cidr-out", entry]
    for entry in body.domain_in:
        args += ["--domain-in", entry]
    for entry in body.domain_out:
        args += ["--domain-out", entry]
    if body.emergency_contact:
        args += ["--emergency-contact", body.emergency_contact]
    if body.notes:
        args += ["--notes", body.notes]
    if body.capture_payloads:
        args.append("--capture-payloads")
    caps = list(body.enabled_capabilities)
    if body.exploitation_enabled and "exploit" not in caps:
        caps.append("exploit")
    for c in caps:
        args += ["--enable-capability", c]
    if body.retention_days:
        args += ["--retention-days", str(body.retention_days)]
    for entry in body.redact:
        args += ["--redact", entry]
    args.append("--require-approval" if body.require_approval else "--no-require-approval")
    if body.clear_max_turns_ceiling:
        args.append("--clear-max-turns-ceiling")
    elif body.max_turns_ceiling is not None:
        args += ["--max-turns-ceiling", str(body.max_turns_ceiling)]
    if body.clear_max_budget_ceiling:
        args.append("--clear-max-budget-ceiling")
    elif body.max_budget_ceiling is not None:
        args += ["--max-budget-ceiling", str(body.max_budget_ceiling)]
    if body.clear_timeout_ceiling:
        args.append("--clear-timeout-ceiling")
    elif body.timeout_ceiling is not None:
        args += ["--timeout-ceiling", str(body.timeout_ceiling)]
    if body.allowed_models:
        for m in body.allowed_models:
            args += ["--allowed-models", m]
    else:
        args.append("--clear-allowed-models")
    # The grant is bound to the SHA-256 of exactly the arguments the CLI will
    # receive after "engagement set" (it hashes them the same way), so an
    # approval for one change can never be spent on another.
    sha = hashlib.sha256(json.dumps(args[2:]).encode()).hexdigest()
    grant = _engagement_grant(request, caller, body, {"op": "engagement-set", "sha256": sha,
                                                      "resource": iam.ORG_RESOURCE},
                              "sudo agenti engagement set --help")
    return _call(*args, f"--grant={grant}")


class EngagementApproveRequest(BaseModel):
    engagement_id: ArgValue | None = None
    # The digest of the version the approver reviewed (GET /engagement shows
    # it). The approval is refused if the record changed since (F25).
    digest: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    password: Optional[ArgValue] = None
    totp: Optional[ArgValue] = None
    reauth: Optional[ReauthToken] = None


@app.post("/engagement/approve")
def approve_engagement(body: EngagementApproveRequest, request: Request,
                              caller: Caller = Depends(require("engagement:approve"))) -> dict:
    """Approve the engagement AS IT STANDS — bound to its content
    digest, so editing it again needs a fresh approval (§3g). Optionally
    refuses unless the record's own engagement_id matches `engagement_id`
    (the same "you're approving something specific, not whatever happens
    to be there" guard the old per-agent admin-approve route had)."""
    grant = _engagement_grant(request, caller, body, {"op": "engagement-approve", "digest": body.digest,
                                                      "resource": iam.ORG_RESOURCE},
                              "sudo agenti engagement approve")
    args = ["engagement", "approve", f"--expect-digest={body.digest}", f"--grant={grant}"]
    if body.engagement_id:
        args += ["--engagement-id", body.engagement_id]
    return _call(*args)


@app.get("/agents/{agent}/tools")
def tools(agent: AgentName,
          caller: Caller = Depends(require("agent:read"))) -> dict:
    """The agent's tool/permission descriptor (CLAUDE.md §4 item 26): the MCP
    tools it exposes, the command-line programs it may run (enum's enforced
    allow-list, or the fixed external tools for the others), its scope kind,
    and the refused patterns. Read from the same declarations that enforce
    the boundary, so it cannot overstate what the agent may do. agent:read —
    a viewer should be able to see what an agent is capable of."""
    return _call(agent, "tools")


@app.get("/agents/{agent}/reports")
def reports(agent: AgentName, copy: Optional[CopyLabel] = None,
            user: Optional[PrincipalName] = None,
            caller: Caller = Depends(require("agent:read"))) -> dict:
    out = _call(agent, "reports", *_slot(_owner(caller, user), copy))
    return {"agent": agent, "reports": out.get("reports", [])}


@app.get("/agents/{agent}/scans")
def scans(agent: AgentName, copy: Optional[CopyLabel] = None,
          caller: Caller = Depends(require("agent:read"))) -> dict:
    return {"agent": agent,
            "scans": _call_text(agent, "scans", *_slot(caller.principal, copy))}


@app.get("/agents/{agent}/report")
def report(agent: AgentName,
           last: bool = True, file: Optional[ReportFile] = None,
           copy: Optional[CopyLabel] = None, user: Optional[PrincipalName] = None,
           caller: Caller = Depends(require("agent:read"))) -> dict:
    # cmd_report prints the raw report Markdown — a document, so wrapped as text.
    args = [agent, "report", *_slot(_owner(caller, user), copy)]
    if file:
        args.append(file)
    elif last:
        args.append("--last")
    return {"agent": agent, "report_markdown": _call_text(*args)}


@app.get("/agents/{agent}/report.docx")
def report_docx_route(agent: AgentName,
                      last: bool = True, file: Optional[ReportFile] = None,
                      copy: Optional[CopyLabel] = None, user: Optional[PrincipalName] = None,
                      caller: Caller = Depends(require("agent:read"))) -> RawResponse:
    """The same report as a Word document (shared/api/docx.py — stdlib
    only). Same permission, same CLI call, same file selection as /report;
    only the rendering differs. PDF is deliberately NOT a server route: the
    browser's own print-to-PDF of report.html gives a better document than
    any PDF this process could write without a dependency, and works on a
    phone. The filename is derived from the report's own name, never from
    anything the caller typed."""
    args = [agent, "report", *_slot(_owner(caller, user), copy)]
    if file:
        args.append(file)
    elif last:
        args.append("--last")
    md = _call_text(*args)
    stem = (file or "report").rsplit(".", 1)[0]
    title = f"{agent} — {stem}"
    body = report_docx.markdown_to_docx(md, title=title, creator="Agenti")
    return RawResponse(
        content=body,
        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        headers={"Content-Disposition": f'attachment; filename="{agent}-{stem}.docx"',
                 "Cache-Control": "no-store"})


@app.get("/agents/{agent}/findings")
def findings(agent: AgentName, n: int = 20,
             copy: Optional[CopyLabel] = None, user: Optional[PrincipalName] = None,
             caller: Caller = Depends(require("agent:read"))) -> list:
    return _call(agent, "findings", "-n", str(n),
                 *_slot(_owner(caller, user), copy))


@app.get("/agents/{agent}/approval")
def approval(agent: AgentName,
             caller: Caller = Depends(require("agent:read"))) -> dict:
    return _call(agent, "approval")


@app.get("/agents/{agent}/logs")
def logs(agent: AgentName, n: int = 100, copy: Optional[CopyLabel] = None,
         caller: Caller = Depends(require("agent:read"))) -> dict:
    return {"agent": agent,
            "logs": _call_text(agent, "logs", "-n", str(n),
                               *_slot(caller.principal, copy))}


# ---------------------------------------------------------------------------
# Control endpoints
# ---------------------------------------------------------------------------
# target and model become argv elements too. A list-based subprocess call
# means neither can ever split into extra arguments, so the only real hazard
# is a leading '-' being consumed as a flag by the CLI's own parser (`-t
# --budget` would silently set the target to the literal string "--budget").
# Rejecting it up front turns that into a clear 422 instead of a confusing
# scope-refusal three layers down.
# ArgValue itself moved near the top of the file (defined alongside
# AgentName/PrincipalName) once the self-service routes needed it
# earlier in the module than this section — the reasoning above still holds
# for target/model, it just isn't the only place that needed the guard.


class StartRequest(BaseModel):
    # A network agent always needs one: it never scans a whole engagement scope
    # by default, and the target may only NARROW what the engagement authorizes
    # (the CLI refuses a start without it, naming the fix). A file-analysis
    # agent has none: it works on the files attached to the run.
    target: Optional[ArgValue] = None
    # Mandatory (CLAUDE.md "Current plan": the --dev/commercial split is
    # retired) — there is no more profile-level default to silently fall
    # back to. Pydantic gives a clean 422 if omitted, matching "mandatory"
    # at the boundary closest to the browser; shared/agenti's own cmd_start
    # re-checks it regardless (the CLI is the real enforcement point).
    model: ArgValue
    budget: Optional[float] = None
    turns: Optional[int] = None
    timeout: Optional[int] = None
    window: Optional[int] = None
    linger: Optional[int] = None   # §3h; the CLI already took --linger, the API didn't
    dry_run: bool = False
    # Every start is its own isolated run (its own target, state, reports and
    # unit). None = the CLI generates a label and returns it as "copy"; a form
    # that attached files before starting reserves one up front and sends it.
    copy: Optional[CopyLabel] = None
    # What people call the run. None = the CLI makes one up (two words).
    name: Optional[RunName] = None


@app.post("/agents/{agent}/start")
def start(agent: AgentName, body: StartRequest,
          caller: Caller = Depends(require("agent:start"))) -> dict:
    # Always the caller's own run (the CLI records its owner as who launched
    # it).
    args = [agent, "start", *_slot(caller.principal, body.copy)]
    if body.target:
        args += ["-t", body.target]
    args += ["--launched-via", "api"]
    args += ["--model", body.model]
    if body.budget is not None:
        args += ["--budget", str(body.budget)]
    if body.turns is not None:
        args += ["--turns", str(body.turns)]
    if body.timeout is not None:
        args += ["--timeout", str(body.timeout)]
    if body.window is not None:
        args += ["--window", str(body.window)]
    if body.linger is not None:
        args += ["--linger", str(body.linger)]
    if body.name:
        args += ["--name", body.name]
    if body.dry_run:
        args.append("--dry-run")
    return _call(*args)


@app.post("/agents/{agent}/stop")
def stop(agent: AgentName, copy: Optional[CopyLabel] = None,
         user: Optional[PrincipalName] = None,
         caller: Caller = Depends(require("agent:stop"))) -> dict:
    return _call(agent, "stop", *_slot(_owner(caller, user), copy))


@app.post("/agents/{agent}/pause")
def pause(agent: AgentName,
          copy: Optional[CopyLabel] = None,
          caller: Caller = Depends(require("agent:pause"))) -> dict:
    # cmd_pause's SUCCESS output is plain text, not JSON (see cli_bridge's
    # module docstring for why run_agenti_text, not run_agenti, is correct
    # here — found by hitting this route for real and getting a raw,
    # unparsed CLI string back from run_agenti instead of a clean result).
    _call_text(agent, "pause", *_slot(caller.principal, copy))
    return {"agent": agent, "copy": copy,
            "paused": True, "by": caller.principal}


@app.post("/agents/{agent}/resume")
def resume(agent: AgentName,
           copy: Optional[CopyLabel] = None,
           caller: Caller = Depends(require("agent:resume"))) -> dict:
    _call_text(agent, "resume", *_slot(caller.principal, copy))
    return {"agent": agent, "copy": copy,
            "resumed": True, "by": caller.principal}


# ---------------------------------------------------------------------------
# Operator inbox (CLAUDE.md §3h)
#
# Two routes, two permissions, because they are two different powers. A note is
# recorded and reproduced in the report but NEVER reaches the model, so it is
# safe at viewer level. A message is injected into the live conversation, so it
# is operator level — it steers a process that touches networks.
#
# Neither can widen what the agent may DO: the tool allow-list and the scope
# boundary are enforced in the tool layer and by root, not by the prompt
# (§1 invariants 1 and 2). That is what makes a chat channel defensible on this
# platform specifically, and it is proven rather than asserted — a message
# instructing an out-of-scope scan was sent to a live run and the boundary
# still refused the target.
# ---------------------------------------------------------------------------
class InboxRequest(BaseModel):
    body: ArgValue


@app.post("/agents/{agent}/say")
def say(agent: AgentName, body: InboxRequest,
        copy: Optional[CopyLabel] = None,
        caller: Caller = Depends(require("agent:chat"))) -> dict:
    return _call(agent, "say", body.body,
                 "--author", caller.principal, "--via", "api",
                 *_slot(caller.principal, copy))


@app.post("/agents/{agent}/note")
def note(agent: AgentName, body: InboxRequest,
         copy: Optional[CopyLabel] = None,
         caller: Caller = Depends(require("agent:note"))) -> dict:
    return _call(agent, "note", body.body,
                 "--author", caller.principal, "--via", "api",
                 *_slot(caller.principal, copy))


class RenameRequest(BaseModel):
    name: RunName


@app.post("/agents/{agent}/rename")
def rename(agent: AgentName, body: RenameRequest,
           copy: Optional[CopyLabel] = None,
           caller: Caller = Depends(require("agent:start"))) -> dict:
    # Your own runs only: a name is the owner's label for their work.
    return _call(agent, "rename", body.name, *_slot(caller.principal, copy))


class SetModelRequest(BaseModel):
    model: ArgValue


@app.post("/agents/{agent}/set-model")
def set_model(agent: AgentName, body: SetModelRequest,
              copy: Optional[CopyLabel] = None,
              caller: Caller = Depends(require("agent:chat"))) -> dict:
    """Switch the model of a LIVE run at the next turn boundary (CLAUDE.md
    "Current plan"), via the SDK's own client.set_model() — same permission
    tier as `say` (agent:chat), arguably more consequential since it changes
    real spend rate, not just steering. Delivered through the SAME inbox
    `say`/`note` already use; the actual allowed-model check happens fresh,
    agent-side, at the moment the switch is applied — this route does not
    pre-validate against the allowed list, matching `start`'s own posture
    of leaving model/cap enforcement to the harness, not the API."""
    return _call(agent, "set-model", body.model,
                 "--author", caller.principal, "--via", "api",
                 *_slot(caller.principal, copy))


@app.get("/agents/{agent}/inbox")
def inbox(agent: AgentName, n: int = 50,
          copy: Optional[CopyLabel] = None, user: Optional[PrincipalName] = None,
          caller: Caller = Depends(require("agent:read"))) -> list:
    """The GUI's chat pane reads this alongside /findings — the ledger records
    operator input as `operator:note` / `operator:message` entries, so the two
    interleave into one transcript without the client merging files by
    timestamp and getting it subtly wrong."""
    return _call(agent, "inbox", "-n", str(n), *_slot(_owner(caller, user), copy))


# ---------------------------------------------------------------------------
# Files an operator attaches to a run (CLAUDE.md §4 item 82). The browser
# sends a file's raw bytes (not a multipart form, so no extra dependency);
# they are spooled to an anonymous temp file — no name on disk — and piped
# to `agenti ... attach -` on stdin. Root never opens a path this account
# chose. Every rule (names, limits, where it goes) is the CLI's
# (run_files.py); the cap here only stops a huge body filling the disk.
# ---------------------------------------------------------------------------
UPLOAD_MAX_BYTES = 100 * 1024 ** 2          # = run_files.MAX_FILE_BYTES
UploadName = Annotated[str, Field(min_length=1, max_length=255)]
AttachedName = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")]


# The spool lives in this service's private, RAM-backed /tmp: at most this many
# uploads at once (so at most this many times UPLOAD_MAX_BYTES), and a spool is
# closed, so freed, however its request ends (an aborted upload used to keep its
# spool until the service restarted; audit run 2, confirmed live).
UPLOAD_CONCURRENCY = 3
_upload_slots = asyncio.Semaphore(UPLOAD_CONCURRENCY)


async def _spool_upload(request: Request):
    import tempfile
    f = tempfile.TemporaryFile()
    try:
        size = 0
        async for chunk in request.stream():
            size += len(chunk)
            if size > UPLOAD_MAX_BYTES:
                raise HTTPException(status_code=413, detail="that file is larger than the 100 MB limit.")
            f.write(chunk)
        if not size:
            raise HTTPException(status_code=400, detail="that file is empty.")
        f.seek(0)
        return f
    except BaseException:
        f.close()
        raise


async def _attach(request: Request, *args: str) -> dict:
    from starlette.concurrency import run_in_threadpool
    if _upload_slots.locked():
        raise HTTPException(status_code=429, detail=f"{UPLOAD_CONCURRENCY} uploads are already in progress; "
                                                    f"try again when one has finished.")
    async with _upload_slots:
        f = await _spool_upload(request)
        try:
            return await run_in_threadpool(_call_stdin, f, *args)
        finally:
            f.close()


def _call_stdin(f, *args: str) -> dict:
    try:
        return run_agenti(*args, stdin_file=f, timeout=180)
    except AgentiError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


@app.post("/agents/{agent}/files")
async def attach_file(agent: AgentName, request: Request, name: UploadName,
                      copy: Optional[CopyLabel] = None,
                      caller: Caller = Depends(require("agent:start"))) -> dict:
    """Body: the file's bytes. A run going now gets it at once (and is told);
    otherwise it waits for the caller's next run of this agent."""
    return await _attach(request, agent, "attach", "-", f"--name={name}",
                         *_slot(caller.principal, copy))


@app.get("/agents/{agent}/files")
def list_files(agent: AgentName, copy: Optional[CopyLabel] = None,
               user: Optional[PrincipalName] = None,
               caller: Caller = Depends(require("agent:read"))) -> dict:
    return _call(agent, "files", *_slot(_owner(caller, user), copy))


# ---- hand this run's output to another agent (CLAUDE.md §4 item 85) -------------
# Owner only: it reads the caller's OWN run, so an admin looking at someone's
# dashboard cannot send their output anywhere. The receiver is the caller's own
# main run of the other agent, and sending needs the same permission as
# starting that agent (the files wait for the caller's next run of it).
SendItem = Annotated[str, Field(pattern=r"^(report|output|file):[A-Za-z0-9][A-Za-z0-9._-]{0,199}$")]


class SendBody(BaseModel):
    to: AgentName
    items: list[SendItem] = Field(min_length=1, max_length=50)
    copy: Optional[CopyLabel] = None      # which of the sender's runs the items come from
    to_copy: Optional[CopyLabel] = None   # the receiver's NEXT run (a launch form reserves its label)


@app.get("/agents/{agent}/send-list")
def send_list(agent: AgentName, copy: Optional[CopyLabel] = None,
              caller: Caller = Depends(require("agent:start"))) -> dict:
    """What this run could hand to another agent, plus the model and limits it
    ran with (the quick start defaults to the same)."""
    return _call(agent, "send-list", *_slot(caller.principal, copy))


@app.post("/agents/{agent}/send")
def send_output(agent: AgentName, body: SendBody,
                caller: Caller = Depends(require("agent:start"))) -> dict:
    extra = ["--to-copy", body.to_copy] if body.to_copy else []
    return _call(agent, "send", "--to", body.to, *[f"--item={i}" for i in body.items],
                 *extra, *_slot(caller.principal, body.copy))


@app.delete("/agents/{agent}/files/{fname}")
def remove_file(agent: AgentName, fname: AttachedName, copy: Optional[CopyLabel] = None,
                caller: Caller = Depends(require("agent:start"))) -> dict:
    """Takes back a file still waiting for the next run (a run's own files
    are its record and stay until the 30-day sweep)."""
    return _call(agent, "files", "remove", fname, *_slot(caller.principal, copy))


# ---------------------------------------------------------------------------
# GUI phase 2 (CLAUDE.md §4 step 6): interrupt, run history + acknowledge,
# and the live stream. Same discipline as every route above — each is one
# `agenti ... --json` call, no new execution path.
# ---------------------------------------------------------------------------
@app.post("/agents/{agent}/interrupt")
def interrupt(agent: AgentName,
              copy: Optional[CopyLabel] = None, user: Optional[PrincipalName] = None,
              caller: Caller = Depends(require("agent:stop"))) -> dict:
    """A faster stop: abort the tool call in flight, then end the run with a
    partial report. Same permission as stop — it is a stronger stop, not a
    new capability. NOT a pause-and-redirect; see cmd_interrupt."""
    return _call(agent, "interrupt", *_slot(_owner(caller, user), copy))


class AcknowledgeRequest(BaseModel):
    run_id: ArgValue


@app.post("/agents/{agent}/acknowledge")
def acknowledge(agent: AgentName, body: AcknowledgeRequest,
                copy: Optional[CopyLabel] = None, user: Optional[PrincipalName] = None,
                caller: Caller = Depends(require("agent:note"))) -> dict:
    """Mark a finished run reviewed — the GUI's "mark complete". Recorded
    server-side (acks.jsonl, root-owned), naming who reviewed it — the owner,
    or an admin acting from their dashboard (`user`)."""
    return _call(agent, "acknowledge", body.run_id,
                 "--author", caller.principal, "--via", "api",
                 *_slot(_owner(caller, user), copy))


@app.get("/agents/{agent}/history")
def history(agent: AgentName, n: int = 50, show_all: bool = False,
            copy: Optional[CopyLabel] = None, user: Optional[PrincipalName] = None,
            caller: Caller = Depends(require("agent:read"))) -> list:
    """Every finished run (both profiles), newest first, with status, why it
    ended, and who reviewed it. `show_all=true` also returns rows hidden by
    history/hide below, annotated with who hid them and when (CLAUDE.md
    "Current plan" decision 5) — the default view drops them entirely."""
    args = [agent, "history", "-n", str(n), *_slot(_owner(caller, user), copy)]
    if show_all:
        args.append("--all")
    return _call(*args)


class HideHistoryRequest(BaseModel):
    run_ids: list[ArgValue]


@app.post("/agents/{agent}/history/hide")
def hide_history(agent: AgentName, body: HideHistoryRequest,
                 copy: Optional[CopyLabel] = None,
                 caller: Caller = Depends(require("agent:note"))) -> dict:
    """Soft-delete for Task History (CLAUDE.md decision 5): the GUI's
    multi-select is one call, not N. history.jsonl, the findings ledger,
    reports and the audit log are untouched — this only changes what the
    default history view shows, the same 'annotate, never a record'
    posture note/acknowledge already have at this same permission level.
    Each run_id is resolved independently by the CLI; an unknown one in the
    batch is reported per-item rather than aborting the rest."""
    if not body.run_ids:
        raise HTTPException(400, "no run ids given")
    result = _call(agent, "history", "hide", *body.run_ids, "--by", caller.principal,
                   *_slot(caller.principal, copy))
    return {"agent": agent,
            "results": result.get("results", []) if isinstance(result, dict) else []}


# The live stream. Server-sent events rather than a WebSocket because SSE is
# a plain GET: the browser's EventSource sends the session cookie and this
# route authorizes through the same require() dependency as every other
# read — no second auth path for a WebSocket handshake. The API process
# cannot read state files itself (the org directory is 0750 root:<service
# account>), so the server polls the same two CLI verbs the GUI would
# otherwise poll from the browser and forwards only what CHANGED — one
# connection per open tab instead of N tabs each hammering sudo, and the
# browser sees a new finding within STREAM_POLL_S of it landing on disk.
# Measured on the Pi: status ≈0.3s, findings ≈0.06s per poll.
STREAM_POLL_S = 2.0          # while a run is active
STREAM_IDLE_POLL_S = 6.0     # nothing running: cheap to keep open, no need to hurry
STREAM_MAX_S = 6 * 3600      # a tab left open reconnects (EventSource does that itself)
STREAM_FINDINGS_N = 5000     # the whole ledger; a run's ledger is tens to hundreds of lines


STREAM_REAUTH_S = 30.0       # how often an open stream re-checks who may see it
STREAM_MAX_PER_USER = 6      # open live feeds per signed-in user
STREAM_MAX_TOTAL = 48        # and on the whole box (audit run 1, N03)
_streams: dict[str, int] = {}
_streams_lock = _threading.Lock()
_STREAM_AUTH = require("agent:read")


def _sse(event: str, data) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


def _stream_take(principal: str) -> str:
    """'' when a stream slot was taken for `principal`, else why not."""
    with _streams_lock:
        if sum(_streams.values()) >= STREAM_MAX_TOTAL:
            return "the server has too many live feeds open — reload the page in a minute"
        if _streams.get(principal, 0) >= STREAM_MAX_PER_USER:
            return (f"you have {STREAM_MAX_PER_USER} live feeds open already — close a tab "
                    f"you no longer need, then reload")
        _streams[principal] = _streams.get(principal, 0) + 1
        return ""


def _stream_give(principal: str) -> None:
    with _streams_lock:
        n = _streams.get(principal, 0) - 1
        if n > 0:
            _streams[principal] = n
        else:
            _streams.pop(principal, None)


async def _stream_still_allowed(request: Request, caller: "Caller", user: "str | None") -> str:
    """'' while the viewer may still see this stream, else why not. The
    permission, the session (revoked, logged out, disabled) and the dashboard
    ladder are asked again; an open feed used to keep sending for six hours
    after any of them was taken away (audit run 1, F32)."""
    def check() -> str:
        try:
            now = _STREAM_AUTH(request)
            if now.principal != caller.principal:
                return "you are signed in as someone else now"
            _owner(now, user)
            return ""
        except HTTPException as e:
            return str(e.detail)
    return await asyncio.to_thread(check)


@app.get("/agents/{agent}/stream")
async def stream(agent: AgentName, request: Request,
                 copy: Optional[CopyLabel] = None, user: Optional[PrincipalName] = None,
                 caller: Caller = Depends(require("agent:read"))) -> StreamingResponse:
    # Resolved once, before streaming: every poll below follows this one run.
    poll_args = _slot(_owner(caller, user), copy)

    async def gen() -> AsyncIterator[str]:
        busy = _stream_take(caller.principal)
        if busy:
            yield _sse("ended", {"reason": busy})
            return
        try:
            async for chunk in _agent_feed():
                yield chunk
        finally:
            _stream_give(caller.principal)

    async def _agent_feed() -> AsyncIterator[str]:
        last_snap: dict | None = None
        last_ts = 0.0
        run_id: str | None = None
        t0 = last_auth = time.monotonic()
        yield ": connected\n\n"
        while time.monotonic() - t0 < STREAM_MAX_S:
            if await request.is_disconnected():
                return
            if time.monotonic() - last_auth >= STREAM_REAUTH_S:
                why = await _stream_still_allowed(request, caller, user)
                if why:
                    yield _sse("ended", {"reason": f"this live feed ended: {why}"})
                    return
                last_auth = time.monotonic()
            try:
                st = await asyncio.to_thread(run_agenti, agent, "status", *poll_args)
                fx = await asyncio.to_thread(run_agenti, agent, "findings",
                                             "-n", str(STREAM_FINDINGS_N), *poll_args)
            except AgentiError as e:
                yield _sse("error", {"error": e.message})
                return
            live = st.get("live") or {} if isinstance(st, dict) else {}
            # A new run_id means a fresh run truncated the ledger: tell the
            # client to clear its feed, and re-emit everything from the top.
            if live.get("run_id") != run_id:
                run_id = live.get("run_id")
                last_ts = 0.0
                yield _sse("reset", {"run_id": run_id})
            snap = {k: st.get(k) for k in ("state", "freezer", "target", "last_report")}
            snap["live"] = live
            if snap != last_snap:
                last_snap = snap
                yield _sse("status", snap)
            if isinstance(fx, list):
                for e in fx:
                    ts = float(e.get("ts") or 0)
                    if ts > last_ts:
                        yield _sse("finding", e)
                        last_ts = ts
            yield ": ping\n\n"
            active = isinstance(st, dict) and st.get("state") == "active"
            await asyncio.sleep(STREAM_POLL_S if active else STREAM_IDLE_POLL_S)

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache",
                                      "X-Accel-Buffering": "no"})


# ---------------------------------------------------------------------------
# Multi-agent teams (CLAUDE.md §3i) — phase 4 of that build.
#
# Same discipline as every route above: shells to `agenti team ...`, no new
# execution path. Reuses the existing agent:* permissions for operations that
# are the same category of action as their per-agent counterpart — GET routes
# need agent:read, start/stop/pause/resume need the matching agent:<verb>,
# say/note need agent:chat/agent:note. team:manage gates membership changes
# (create/add-agent/remove-agent/delete): structural actions, the same
# distinction a role split draws from agent:start. Teams are private to their
# owner like runs (§4 item 71).
# ---------------------------------------------------------------------------
@app.get("/teams")
def list_teams_route(user: Optional[PrincipalName] = None,
                     caller: Caller = Depends(require("agent:read"))) -> dict:
    """The teams one user owns — teams are private like runs (§4 item 71)."""
    return _call("team", "list", *_slot(_owner(caller, user)))


class CreateTeamRequest(BaseModel):
    name: TeamName
    agents: list[AgentName]
    fixed: bool = False


@app.post("/teams")
def create_team(body: CreateTeamRequest,
                caller: Caller = Depends(require("team:manage"))) -> dict:
    # The caller owns the team they create (the CLI records them as owner).
    args = ["team", "create", body.name, "--agents", ",".join(body.agents),
            *_slot(caller.principal)]
    if body.fixed:
        args.append("--fixed")
    return _call(*args)


@app.get("/teams/{team}")
def show_team(team: TeamName, user: Optional[PrincipalName] = None,
             caller: Caller = Depends(require("agent:read"))) -> dict:
    return _call("team", team, "show", *_slot(_owner(caller, user)))


@app.delete("/teams/{team}")
def delete_team(team: TeamName,
                caller: Caller = Depends(require("team:manage"))) -> dict:
    return _call("team", team, "delete", *_slot(caller.principal))


class AddTeamAgentRequest(BaseModel):
    agent: AgentName
    scope_mode: Literal["isolated", "shared"] = "isolated"


@app.post("/teams/{team}/add-agent")
def add_team_agent(team: TeamName, body: AddTeamAgentRequest,
                   caller: Caller = Depends(require("team:manage"))) -> dict:
    return _call("team", team, "add-agent", body.agent,
                "--scope-mode", body.scope_mode, *_slot(caller.principal))


class RemoveTeamAgentRequest(BaseModel):
    agent: AgentName


@app.post("/teams/{team}/remove-agent")
def remove_team_agent(team: TeamName, body: RemoveTeamAgentRequest,
                      caller: Caller = Depends(require("team:manage"))) -> dict:
    return _call("team", team, "remove-agent", body.agent, *_slot(caller.principal))


class TeamStartRequest(BaseModel):
    target: Optional[ArgValue] = None
    # Per-member overrides, keyed by agent name — fills --target <agent>=<value>
    # for that one member regardless of its scope_mode; `target` above is the
    # default applied only to "shared" members with no override of their own.
    overrides: dict[AgentName, ArgValue] = {}
    # Per-member role assignment (the teams-in-the-GUI plan): fills
    # --role <agent>=<text> for that member, which cmd_team_start uses to
    # write each agent's own run-role marker and post the one-time kickoff
    # entry to the shared channel. A member with no role here keeps
    # whatever it already had (cmd_team_start's own fallback) — restarting
    # a team to adjust one agent's role does not erase the others'.
    roles: dict[AgentName, ArgValue] = {}
    # Mandatory: one team-wide model, forwarded to every member's start.
    model: ArgValue
    budget: Optional[float] = None
    turns: Optional[int] = None
    timeout: Optional[int] = None
    window: Optional[int] = None
    dry_run: bool = False


@app.post("/teams/{team}/start")
def start_team(team: TeamName, body: TeamStartRequest,
               caller: Caller = Depends(require("agent:start"))) -> dict:
    # Every member runs in the caller's own slot for this team.
    args = ["team", team, "start", *_slot(caller.principal), "--launched-via", "api"]
    if body.target is not None:
        args += ["--target", body.target]
    for agent, value in body.overrides.items():
        args += ["--target", f"{agent}={value}"]
    for agent, value in body.roles.items():
        args += ["--role", f"{agent}={value}"]
    args += ["--model", body.model]
    if body.budget is not None:
        args += ["--budget", str(body.budget)]
    if body.turns is not None:
        args += ["--turns", str(body.turns)]
    if body.timeout is not None:
        args += ["--timeout", str(body.timeout)]
    if body.window is not None:
        args += ["--window", str(body.window)]
    if body.dry_run:
        args.append("--dry-run")
    return _call(*args)


@app.post("/teams/{team}/stop")
def stop_team(team: TeamName, user: Optional[PrincipalName] = None,
             caller: Caller = Depends(require("agent:stop"))) -> dict:
    return _call("team", team, "stop", *_slot(_owner(caller, user)))


@app.post("/teams/{team}/pause")
def pause_team(team: TeamName,
               caller: Caller = Depends(require("agent:pause"))) -> dict:
    return _call("team", team, "pause", *_slot(caller.principal))


@app.post("/teams/{team}/resume")
def resume_team(team: TeamName,
                caller: Caller = Depends(require("agent:resume"))) -> dict:
    return _call("team", team, "resume", *_slot(caller.principal))


@app.get("/teams/{team}/status")
def status_team(team: TeamName, user: Optional[PrincipalName] = None,
                caller: Caller = Depends(require("agent:read"))) -> dict:
    return _call("team", team, "status", *_slot(_owner(caller, user)))


@app.post("/teams/{team}/say")
def say_team(team: TeamName, body: InboxRequest,
            caller: Caller = Depends(require("agent:chat"))) -> dict:
    return _call("team", team, "say", body.body,
                "--author", caller.principal, "--via", "api", *_slot(caller.principal))


@app.post("/teams/{team}/files")
async def attach_team_file(team: TeamName, request: Request, name: UploadName,
                           caller: Caller = Depends(require("agent:start"))) -> dict:
    """Body: the file's bytes, given to every member of the caller's team."""
    return await _attach(request, "team", team, "attach", "-", f"--name={name}",
                         *_slot(caller.principal))


@app.get("/teams/{team}/files")
def list_team_files(team: TeamName, user: Optional[PrincipalName] = None,
                    caller: Caller = Depends(require("agent:read"))) -> dict:
    return _call("team", team, "files", *_slot(_owner(caller, user)))


@app.delete("/teams/{team}/files/{fname}")
def remove_team_file(team: TeamName, fname: AttachedName,
                     caller: Caller = Depends(require("agent:start"))) -> dict:
    return _call("team", team, "files", "remove", fname, *_slot(caller.principal))


@app.post("/teams/{team}/note")
def note_team(team: TeamName, body: InboxRequest,
             caller: Caller = Depends(require("agent:note"))) -> dict:
    return _call("team", team, "note", body.body,
                "--author", caller.principal, "--via", "api", *_slot(caller.principal))


@app.get("/teams/{team}/inbox")
def inbox_team(team: TeamName, n: int = 50,
              user: Optional[PrincipalName] = None,
              caller: Caller = Depends(require("agent:read"))) -> list:
    """The one shared transcript (§3i) — reads channel.jsonl directly, no
    per-member fan-out-then-merge needed, the same reason the CLI verb
    this shells to doesn't need one either."""
    return _call("team", team, "inbox", "-n", str(n), *_slot(_owner(caller, user)))


@app.post("/teams/{team}/acknowledge")
def acknowledge_team(team: TeamName, user: Optional[PrincipalName] = None,
                     caller: Caller = Depends(require("agent:stop"))) -> dict:
    """Close a team project out: stop whatever member is still active (a
    project is not 'done' while something is still running) and record who
    marked it complete — the team-level sibling of the per-agent
    /acknowledge route, at agent:stop's bar rather than agent:note's,
    since unlike a plain note this can actually end a live run."""
    return _call("team", team, "acknowledge",
                 "--author", caller.principal, *_slot(_owner(caller, user)))


@app.get("/teams/{team}/consensus")
def team_consensus_route(team: TeamName,
                         user: Optional[PrincipalName] = None,
                         caller: Caller = Depends(require("agent:read"))) -> dict:
    """Who has voted the project complete, computed by
    agent_runtime.team_consensus() (cmd_team_consensus in shared/agenti) —
    the exact same function an agent's own standby loop uses to decide
    whether to end its run. One implementation, not a second one re-derived
    in the GUI."""
    return _call("team", team, "consensus", *_slot(_owner(caller, user)))


@app.get("/teams/{team}/stream")
async def team_stream(team: TeamName, request: Request,
                      user: Optional[PrincipalName] = None,
                      caller: Caller = Depends(require("agent:read"))) -> StreamingResponse:
    """The team page's live feed — the team-level sibling of /{agent}/stream.

    Same design and same reasons (SSE is a plain GET, so the session cookie and
    require() cover it; the API cannot read org files, so it polls the CLI
    itself, once per open tab, instead of every browser doing it). One event,
    "team", carries the four reads the page paints from — show, status,
    consensus, inbox — and is sent only when the combined snapshot CHANGED.
    A member's live counters sit inside status, so a member working away
    changes the snapshot even when nothing is said on the channel."""
    poll_args = _slot(_owner(caller, user))

    async def gen() -> AsyncIterator[str]:
        busy = _stream_take(caller.principal)
        if busy:
            yield _sse("ended", {"reason": busy})
            return
        try:
            async for chunk in _team_feed():
                yield chunk
        finally:
            _stream_give(caller.principal)

    async def _team_feed() -> AsyncIterator[str]:
        last: str | None = None
        t0 = last_auth = time.monotonic()
        yield ": connected\n\n"
        while time.monotonic() - t0 < STREAM_MAX_S:
            if await request.is_disconnected():
                return
            if time.monotonic() - last_auth >= STREAM_REAUTH_S:
                why = await _stream_still_allowed(request, caller, user)
                if why:
                    yield _sse("ended", {"reason": f"this live feed ended: {why}"})
                    return
                last_auth = time.monotonic()
            try:
                show, status, consensus, inbox = await asyncio.gather(
                    asyncio.to_thread(run_agenti, "team", team, "show", *poll_args),
                    asyncio.to_thread(run_agenti, "team", team, "status", *poll_args),
                    asyncio.to_thread(run_agenti, "team", team, "consensus", *poll_args),
                    asyncio.to_thread(run_agenti, "team", team, "inbox", "-n", "200", *poll_args),
                )
            except AgentiError as e:
                yield _sse("error", {"error": e.message})
                return
            snap = {"show": show, "status": status, "consensus": consensus, "inbox": inbox}
            key = json.dumps(snap, sort_keys=True, default=str)
            if key != last:
                last = key
                yield _sse("team", snap)
            yield ": ping\n\n"
            active = any(
                isinstance(r, dict) and r.get("state") == "active"
                for r in (status.get("results") or []) if isinstance(status, dict))
            await asyncio.sleep(STREAM_POLL_S if active else STREAM_IDLE_POLL_S)

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache",
                                      "X-Accel-Buffering": "no"})


@app.get("/teams/{team}/report")
def team_report(team: TeamName, user: Optional[PrincipalName] = None,
                caller: Caller = Depends(require("agent:read"))) -> dict:
    """The team document — the roster, the full channel transcript, and
    each member's own report, assembled deterministically (cmd_team_report
    in shared/agenti — no extra AI call). Same 'report_markdown' shape as
    the per-agent /report route, so the GUI renders both with the same
    AgentiMarkdown.render() call."""
    # `team report --json` already answers {team, report_markdown}; relay it
    # as is. (This route used to wrap the CLI's whole JSON text a second
    # time, so the report page showed raw JSON.)
    r = _call("team", team, "report", *_slot(_owner(caller, user)))
    return {"team": team, "report_markdown": str(r.get("report_markdown") or "")}


@app.get("/teams/{team}/report.docx")
def team_report_docx(team: TeamName, user: Optional[PrincipalName] = None,
                     caller: Caller = Depends(require("agent:read"))) -> RawResponse:
    """Same team document as a Word document — mirrors the per-agent
    /report.docx route exactly, same docx.py grammar, same rendering."""
    md = str(_call("team", team, "report", *_slot(_owner(caller, user))).get("report_markdown") or "")
    title = f"{team} — project report"
    body = report_docx.markdown_to_docx(md, title=title, creator="Agenti")
    return RawResponse(
        content=body,
        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        headers={"Content-Disposition": f'attachment; filename="team-{team}-report.docx"',
                 "Cache-Control": "no-store"})


# ---------------------------------------------------------------------------
# The web GUI (CLAUDE.md §4 step 6) — static files, served by THIS service.
#
# Mounted LAST, on purpose: Starlette matches routes in registration order,
# so every API route above wins and the mount only sees what nothing else
# claimed. Serving the pages from the same origin as the API is what makes
# the session cookie (HttpOnly, SameSite=Strict — sessions.py) work at all
# without CORS or a second service; a separate GUI process on another port
# would be a different site to the browser and the cookie would never be
# sent. There is no new execution path here — the pages call the routes
# above, and only those.
#
# The directory is installed next to this file (packaging/install-tree.sh); a checkout
# without it (or a dev sandbox) still imports and serves the API — the GUI
# is additive, and its absence is a warning, not a crash.
# ---------------------------------------------------------------------------
GUI_DIR = Path(__file__).resolve().parent / "gui"
if GUI_DIR.is_dir():
    from fastapi.staticfiles import StaticFiles
    app.mount("/", StaticFiles(directory=str(GUI_DIR), html=True), name="gui")
else:
    print(f"[agenti-api] no GUI directory at {GUI_DIR} — API only", file=sys.stderr)
