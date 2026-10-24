"""
sessions.py — the session COOKIE and the CSRF check (CLAUDE.md §3g, §4 item 23).

This module used to own the session store too: creating, rotating, looking
up and revoking rows in runtime.db. That moved into shared/authd.py, the
privileged authentication service, because a session store the API process
can write is a session store a compromised API process can forge (§4 item
23). What is left here is exactly what only the HTTP layer can do: put the
session id in a cookie with the right flags, take it back out, and check the
CSRF header against the value authd returned.

THE COOKIE, AND THE FLAG THAT FOLLOWS THE BIND
----------------------------------------------
HttpOnly (no JS access), SameSite=Strict (no cross-site sends), Path=/, and
Secure ONLY when the service is actually serving HTTPS — a Secure cookie is
never sent over plain HTTP, so setting it unconditionally would break login on
a loopback install, and NOT setting it on a LAN install would hand the session
to anyone on the network. configure.sh (agenti gui configure) permits a
non-loopback bind only with TLS configured, and in that case sets AGENTI_TLS=1 on the unit, which is what
SECURE_COOKIE reads. The flag and the bind are one decision, not two.

CSRF: SameSite=Strict already blocks cross-site form posts in every browser that
implements it, and a required X-Agenti-CSRF header echoing a per-session value
is the belt to those suspenders — the same double-layer shape used for the tool
allow-list and for scope filtering in research-agent.
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass

from fastapi import HTTPException, Request, Response

COOKIE_NAME = "agenti_session"
CSRF_HEADER = "x-agenti-csrf"
# "1" when the BROWSER is on HTTPS: either this process serves TLS itself, or a
# trusted proxy/tunnel on the same host terminates it (--behind-proxy). Both
# cases come from the one decision in configure.sh (agenti gui configure).
SECURE_COOKIE = os.environ.get("AGENTI_TLS", "") == "1"
# Cookie lifetimes only. The authoritative lifetimes live in authd.py; these
# mirror them so the browser drops the cookie at about the time the row
# would have expired anyway. A mismatch is harmless: authd decides.
SESSION_TTL_S = 8 * 60 * 60
PENDING_TTL_S = 5 * 60


@dataclass(frozen=True)
class Session:
    id: str
    principal: str
    csrf: str
    pending_totp: bool


def set_cookie(response: Response, session: Session) -> None:
    response.set_cookie(
        COOKIE_NAME, session.id,
        httponly=True, samesite="strict", path="/",
        max_age=PENDING_TTL_S if session.pending_totp else SESSION_TTL_S,
        secure=SECURE_COOKIE,
    )


def clear_cookie(response: Response) -> None:
    response.delete_cookie(COOKIE_NAME, path="/")


def check_csrf(request: Request, session: Session) -> None:
    """Only for cookie-authenticated requests. A bearer key is not an ambient
    credential — a browser never attaches it automatically — so CSRF does not
    apply to key auth and requiring the header there would break every script
    for no benefit."""
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return
    presented = request.headers.get(CSRF_HEADER, "")
    if not presented or not secrets.compare_digest(presented, session.csrf):
        raise HTTPException(
            status_code=403,
            detail=f"missing or invalid {CSRF_HEADER} header. Cookie-authenticated "
                   f"writes must echo the csrf value returned by /auth/login.")
