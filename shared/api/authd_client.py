"""
authd_client.py — the API's ONLY route to authentication, sessions and
authorization decisions (CLAUDE.md §4 item 23).

Everything here goes over a Unix socket to agenti-authd (shared/authd.py).
This module deliberately imports nothing from iam.py and opens no database:
the API process cannot read iam.db or the session store any more, and a
client that could fall back to doing so locally would quietly re-open the
hole the daemon exists to close.

Protocol: one JSON object + newline out, one JSON object + newline back, then
the connection closes. A refusal arrives as {"ok": false, "status": N,
"error": "..."} and is raised as AuthdError so a route can relay the status
and message unchanged.
"""

from __future__ import annotations

import json
import os
import socket
import time

SOCKET_PATH = os.environ.get("AGENTI_AUTHD_SOCKET", "/run/agenti/authd.sock")
TIMEOUT_S = 15.0            # scrypt is ~0.1s on the Pi; this is headroom, not a budget
MAX_RESPONSE_BYTES = 1024 * 1024


class AuthdError(Exception):
    """`status` is the HTTP status to return, `message` the detail."""

    def __init__(self, status: int, message: str, extra: dict | None = None):
        super().__init__(message)
        self.status = status
        self.message = message
        self.extra = extra or {}


def _connect(path: str, timeout: float) -> socket.socket:
    """Connect, waiting out a FULL queue (EAGAIN: authd is busy with a burst)
    for up to `timeout` instead of failing the request with a 500."""
    deadline = time.monotonic() + timeout
    while True:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect(path)
            return s
        except BlockingIOError:
            s.close()
            if time.monotonic() >= deadline:
                raise AuthdError(503, "the authentication service is busy — try again in a moment")
            time.sleep(0.05)
        except (FileNotFoundError, ConnectionRefusedError, PermissionError) as e:
            s.close()
            raise AuthdError(
                503,
                f"the authentication service is not reachable at {path} "
                f"({type(e).__name__}). It runs as agenti-authd.service; check: "
                f"systemctl status agenti-authd  — and if this is a fresh install, "
                f"recreate it: sudo dpkg-reconfigure agenti")


def call(op: str, *, socket_path: str | None = None, timeout: float = TIMEOUT_S,
         **fields) -> dict:
    path = socket_path or SOCKET_PATH
    payload = (json.dumps({"op": op, **fields}) + "\n").encode()
    s = _connect(path, timeout)
    try:
        s.sendall(payload)
        s.shutdown(socket.SHUT_WR)
        chunks: list[bytes] = []
        total = 0
        while True:
            try:
                chunk = s.recv(65536)
            except socket.timeout:
                raise AuthdError(504, f"the authentication service did not answer "
                                      f"within {timeout}s — check: journalctl -u agenti-authd")
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_RESPONSE_BYTES:
                raise AuthdError(502, "the authentication service sent an oversized response")
            if chunk.endswith(b"\n"):
                break
    finally:
        s.close()
    raw = b"".join(chunks)
    if not raw:
        raise AuthdError(502, "the authentication service closed the connection "
                              "without answering — check: journalctl -u agenti-authd")
    try:
        resp = json.loads(raw)
    except ValueError:
        raise AuthdError(502, "the authentication service sent a non-JSON response")
    if not isinstance(resp, dict):
        raise AuthdError(502, "the authentication service sent an unexpected response shape")
    if not resp.get("ok"):
        raise AuthdError(int(resp.get("status", 500)),
                         str(resp.get("error", "authentication service error")), resp)
    return resp
