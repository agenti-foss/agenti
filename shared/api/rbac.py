"""
rbac.py — authentication and authorization for every API route (CLAUDE.md §3g).

One dependency, declared by every route, resolving:

    credential  ->  principal  ->  bindings  ->  permission on THIS resource

The permission is not inferred from the URL. Each route names its permission
explicitly, and the one resource there is — the organisation — is what it is
checked against. **A route that declares no permission gets no access** — there is no fallback that grants, so a new endpoint added without a
decision about who may call it fails closed rather than inheriting one.

WHERE THE ANSWERS COME FROM (§4 item 23)
----------------------------------------
Nothing here opens a database. Every question — "is this session valid",
"whose key is this", "may they do this here" — is asked of agenti-authd
over its Unix socket (authd_client.py), and the decision is logged THERE,
by a process this one cannot write to. This module used to open iam.db
read-only per request and own the session store; both are gone from the
API's reach on purpose: a process that can read TOTP secrets and write
session rows can impersonate anyone, however carefully its routes are
written. The per-request freshness that used to come from re-opening
iam.db comes from authd re-opening it per request instead — a key revoked
by the CLI still stops working on the very next call.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

from fastapi import Depends, HTTPException, Request

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import iam  # noqa: E402  — for the permission catalog and resource grammar ONLY; never opened
import sessions  # noqa: E402
from authd_client import AuthdError, call as authd_call  # noqa: E402


@dataclass(frozen=True)
class Caller:
    """Who is making this request, and how they proved it. Routes thread the
    principal into the CLI (--owner, --author, --by) so every record names a
    person rather than the service account (CLAUDE.md §3g point 2)."""
    principal: str
    via: str                      # "key" | "session"
    key_prefix: str | None = None
    totp_enrolled: bool = False
    mfa_setup_required: bool = False


# A session that is real but must not be used for anything except setting
# up the second factor its policy requires (iam.two_factor_required). The
# list is the smallest set that lets a person comply: who am I, enrol, and
# leave. /auth/password is deliberately NOT here — it is a credential change
# on an account the policy says is under-protected.
MFA_SETUP_ALLOWED_PATHS = frozenset({
    "/auth/me", "/auth/logout", "/auth/mfa/enrol/start", "/auth/mfa/enrol/confirm",
    # A passkey satisfies the 2FA requirement on its own (see
    # iam.mfa_setup_required's docstring) — registering one is a second,
    # equally valid way to comply, so a confined session must be able to
    # reach it exactly like TOTP enrolment above.
    "/auth/webauthn/register/start", "/auth/webauthn/register/finish",
})


def _authd(op: str, **fields) -> dict:
    """Relay a refusal with authd's own status and message — a 401 from
    authd is a 401 here, a 503 ("the authentication service is not
    reachable") is a 503, so a client sees the real cause."""
    try:
        return authd_call(op, **fields)
    except AuthdError as e:
        raise HTTPException(status_code=e.status, detail=e.message)


def _authenticate(request: Request) -> Caller:
    """Two credential types, ONE resulting Caller — so every route's permission
    check is identical regardless of how the caller proved who they are, and no
    route can accidentally be laxer for one than the other.

    A session cookie is tried first: a browser sends it automatically, and a
    caller holding both almost certainly means a human in the GUI."""
    sid = request.cookies.get(sessions.COOKIE_NAME)
    if sid:
        r = _authd("authenticate", session_id=sid)
        sess = sessions.Session(sid, r["principal"], r["csrf"], False)
        sessions.check_csrf(request, sess)
        needs_mfa = bool(r.get("mfa_setup_required"))
        if needs_mfa and request.url.path not in MFA_SETUP_ALLOWED_PATHS:
            # 403, not 401: the session IS valid, and sending the person back
            # to the login page would loop. The structured `code` is what the
            # GUI's fetch wrapper keys on to route them to Settings instead.
            raise HTTPException(
                status_code=403,
                detail={"code": "mfa_setup_required",
                        "message": "two-factor authentication is required for this "
                                   "account and has not been set up yet — enrol an "
                                   "authenticator app in Settings before doing "
                                   "anything else"})
        return Caller(r["principal"], "session", totp_enrolled=bool(r.get("totp_enrolled")),
                      mfa_setup_required=needs_mfa)

    authorization = request.headers.get("authorization", "")
    scheme, _, presented = authorization.partition(" ")
    if scheme.lower() != "bearer" or not presented:
        raise HTTPException(
            status_code=401,
            detail="not authenticated — sign in at /auth/login, or send "
                   "Authorization: Bearer agk_<prefix>_<secret>")
    r = _authd("authenticate_key", key=presented)
    return Caller(r["principal"], "key", r.get("prefix"))


def require(permission: str):
    """Build the dependency a route declares. Usage:

        @app.post("/agents/{agent}/start")
        def start(agent: AgentName, body: StartRequest,
                  caller: Caller = Depends(require("agent:start"))) -> dict:

    The resource is always the organisation, so no route has to construct a
    resource string and get it wrong."""
    if permission not in iam.PERMISSIONS:
        # Raised at import time, not request time: a typo'd permission is a
        # deploy-time failure, never a silent always-deny in production.
        raise RuntimeError(
            f"route declares unknown permission {permission!r}. "
            f"Valid: {', '.join(iam.PERMISSIONS)}")

    def dependency(request: Request) -> Caller:
        caller = _authenticate(request)
        r = _authd("authorize", principal=caller.principal, permission=permission,
                   via=f"api:{caller.via}")
        if not r["allowed"]:
            # 403 with the reason: the caller IS authenticated, so telling
            # them which permission they lack is helpful rather than leaky —
            # they already know who they are, and an opaque denial is the
            # thing that makes people demand admin.
            raise HTTPException(
                status_code=403,
                detail=f"{caller.principal} lacks {permission} — {r['reason']}")
        return caller

    return dependency


def authenticated():
    """Authenticate, but require no specific permission.

    For the handful of routes that every valid principal must be able to call
    regardless of role: "who am I" and "what can I do"."""
    def dependency(request: Request) -> Caller:
        return _authenticate(request)
    return dependency


def can(principal: str, permission: str) -> bool:
    """A bare yes/no for result FILTERING, not for gating a route. Route gating
    goes through require(), which also logs the decision; filtering a list
    would otherwise write one audit row per candidate and drown the log."""
    return bool(_authd("can", principal=principal, permission=permission)["allowed"])


def resolved_permissions(principal: str) -> list[str]:
    """What this principal may do — the GUI's first question, answered
    without it having to probe endpoints to find out."""
    return list(_authd("permissions", principal=principal)["permissions"])


def resolved_role(principal: str) -> str | None:
    """The actual bound role — see iam.effective_role_name."""
    return _authd("permissions", principal=principal)["role"]


__all__ = ["Caller", "require", "authenticated", "can",
           "resolved_permissions", "resolved_role", "Depends", "MFA_SETUP_ALLOWED_PATHS"]
