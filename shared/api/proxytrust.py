"""Who is really calling, and which name did they use — when a reverse proxy
or tunnel (cloudflared, nginx, Caddy…) sits in front of this service.

Pure functions, no FastAPI import, so shared/test_proxytrust.py can pin them
without a web stack.

WHY THIS EXISTS
---------------
Behind a proxy on the same machine, every request arrives from 127.0.0.1. The
per-address login throttle (iam.record_address_failure) would then see ONE
caller for the whole internet: a single attacker's failures would lock every
user out. The real address is in a header the proxy sets, and that header is
only worth reading when it can only have come from the proxy.

THE TRUST RULE
--------------
A header is trusted only when BOTH hold:
  1. the deploy was made with --behind-proxy (AGENTI_BEHIND_PROXY=1), and
  2. the TCP peer is loopback.
configure.sh refuses --behind-proxy with a non-loopback bind, so (2) is
structurally true; it is checked again here anyway, because a header honoured
from an arbitrary peer lets one client claim a fresh address per attempt, which
switches the throttle off for exactly the caller it exists to slow down.

Anything that does not parse as an IP address is ignored, never passed on:
the value ends up in a database row and a log line.
"""

from __future__ import annotations

import ipaddress
from typing import Callable, Optional

DEFAULT_CLIENT_IP_HEADER = "cf-connecting-ip"

_LOOPBACK_NAMES = ("localhost", "127.0.0.1")


def is_loopback_peer(peer: str) -> bool:
    try:
        return ipaddress.ip_address(peer).is_loopback
    except ValueError:
        return False


def parse_ip(value: str) -> Optional[str]:
    """A bare IP address, normalised, or None. Rejects ports, names, junk."""
    value = (value or "").strip()
    if not value or len(value) > 45:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def client_addr(peer: str, get_header: Callable[[str], Optional[str]], *,
                behind_proxy: bool, header: str = DEFAULT_CLIENT_IP_HEADER) -> str:
    """The source address to throttle on.

    Not behind a proxy: the TCP peer, exactly as before. Behind one: the
    address the proxy put in `header`, if the peer really is loopback and the
    header holds a valid IP. When the header holds a list (X-Forwarded-For),
    the RIGHT-most entry is the one our single trusted proxy appended; the
    left-most entries are whatever the client sent.

    Returns "" when nothing trustworthy is available. The throttle treats an
    empty address as "do not throttle by address" (one shared bucket for
    'unknown' would let one attacker lock out everyone), and the per-account
    lockout still applies.
    """
    if not behind_proxy:
        return peer or ""
    if not is_loopback_peer(peer):
        return ""
    raw = get_header(header)
    if not raw:
        return ""
    return parse_ip(raw.split(",")[-1]) or ""


def allowed_hosts(public_hostname: str) -> list[str]:
    """The Host header values this deploy answers to when behind a proxy: its
    own public domain, plus loopback names so the on-box health checks and the
    proxy's own probes keep working. Anything else is refused, which closes
    DNS-rebinding and stray-vhost routing to a loopback service."""
    hosts = [public_hostname] if public_hostname else []
    return hosts + list(_LOOPBACK_NAMES)
