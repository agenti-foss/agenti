"""
network_policy.py — resolved-IP egress control (CLAUDE.md "Current plan",
phase 3 of the generic-launcher arc, decisions 5 and 6).

WHAT THIS CLOSES: research-agent.py's own documented limitation (CLAUDE.md
§2's "Third agent" note) — its scope check is textual, on the URL's
hostname, not the IP it actually resolves to. A domain that is textually in
scope but resolves (compromised DNS, a deliberate DNS-rebind, or just
infrastructure sitting behind that name) to loopback, a private range,
link-local/cloud-metadata, or the box's own LAN is not caught by a hostname
check alone. This module adds the second check: resolve, then classify
every resolved address, then decide.

THE DEFAULT (decision 5): the public internet only. Loopback, link-local
(which is where cloud metadata endpoints like 169.254.169.254 live),
private ranges (RFC 1918 / ULA), multicast and other reserved ranges are
blocked UNLESS the resolved address is explicitly covered by a LAN
allow-list the operator opted into (decision 6) — which grants REACHABILITY
for a tool that already exists, never new scanning capability. A
DOMAIN allow-list (decision 5, optional) narrows further: when given, only
hostnames covered by it are permitted at all, checked with the exact same
label-boundary rule scope_domain.py already implements and exports as
`domain_in` — imported, not reimplemented, so "is X a subdomain of Y" means
one thing on this whole platform.

WHAT THIS IS NOT: a replacement for a scope boundary. A tool still checks
its own ScopeBoundary first (DomainScope, CIDRScope); this
module is an ADDITIONAL check for a tool that is about to open a network
connection to a resolved address, closing the gap between "the hostname
looked fine" and "the address it actually resolves to is fine too."

A REAL SURPRISE FOUND WHILE BUILDING THIS, NOT ASSUMED FROM DOCS: Python's
`ipaddress` module has no single flag that means "safe to treat as the
public internet." `is_private` does not cover the CGNAT shared address
space (100.64.0.0/10, RFC 6598) at all — `ip_address("100.64.0.1").is_private`
is False — and `is_global` on its own is not enough either, because a
multicast address (e.g. 224.0.0.1) reports `is_global=True`. classify_ip()
below was written and ordered against these actually-observed values (see
shared/test_network_policy.py), not against what the flag names imply.
IPv4-mapped IPv6 addresses (`::ffff:127.0.0.1`) are unmapped to their IPv4
form before classification for the same reason — checking that this
specific Python's `.is_loopback` already handles the mapped case was not
enough to trust that every future Python version will.
"""

from __future__ import annotations

import http.client
import ipaddress
import socket
from typing import Callable, Iterable

from scope_domain import domain_in

__all__ = ["classify_ip", "resolve_host", "check_host", "pin_host", "PinnedHTTPConnection",
           "PinnedHTTPSConnection", "BLOCKED_CATEGORIES"]

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

# Well-known cloud metadata endpoints, named explicitly so a refusal can say
# "cloud metadata" rather than just "link-local" — even though every one of
# these already falls inside a category classify_ip() blocks regardless.
_METADATA_HOSTS = frozenset({
    "169.254.169.254",   # AWS / GCP / Azure / DigitalOcean / OpenStack
    "fd00:ec2::254",     # AWS IMDSv2, IPv6
    "100.100.100.200",   # Alibaba Cloud
})

BLOCKED_CATEGORIES = frozenset({
    "loopback", "link_local", "cloud_metadata", "private", "multicast", "reserved",
})


def classify_ip(ip: IPAddress) -> str:
    """One word describing what `ip` is. "public" is the only category
    `check_host` allows through by default — everything in
    BLOCKED_CATEGORIES needs either no domain allow-list restriction (that's
    a separate, earlier check) or explicit LAN allow-list coverage.

    Order matters, and is deliberately NOT "check is_global and stop there"
    — see the module docstring's note on why that alone lets a multicast
    address through. An IPv4-mapped IPv6 address is unmapped first so a
    tool that resolves to (or is handed) one gets exactly the same verdict
    as its plain IPv4 form."""
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    if str(ip) in _METADATA_HOSTS:
        return "cloud_metadata"
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link_local"
    if ip.is_multicast:
        return "multicast"
    if ip.is_reserved or ip.is_unspecified:
        return "reserved"
    if not ip.is_global:
        # Catches RFC 1918, the CGNAT shared range (100.64.0.0/10, which
        # is_private does NOT cover), ULA (fc00::/7), and anything else
        # IANA has not marked globally routable — the conservative fallback
        # a "public internet only" default policy needs, rather than trying
        # to enumerate every non-public range by name.
        return "private"
    return "public"


def resolve_host(host: str) -> list[IPAddress]:
    """Every address `host` resolves to, deduplicated, order preserved.
    Raises socket.gaierror on a lookup failure — callers decide what that
    means for their own tool (research's fetch_page already treats a DNS
    failure as reportable data, not a crash, and keeps doing so)."""
    infos = socket.getaddrinfo(host, None)
    seen: dict[str, IPAddress] = {}
    for _family, _socktype, _proto, _canon, sockaddr in infos:
        addr = sockaddr[0]
        if addr not in seen:
            seen[addr] = ipaddress.ip_address(addr)
    return list(seen.values())


def check_host(host: str, *,
               domain_allowlist: Iterable[str] | None = None,
               lan_allowlist: Iterable[IPNetwork] | None = None,
               resolver: Callable[[str], list[IPAddress]] = resolve_host,
               ) -> tuple[bool, str]:
    """The verdict of pin_host without the address."""
    ok, reason, _ = pin_host(host, domain_allowlist=domain_allowlist,
                             lan_allowlist=lan_allowlist, resolver=resolver)
    return ok, reason


def pin_host(host: str, *,
             domain_allowlist: Iterable[str] | None = None,
             lan_allowlist: Iterable[IPNetwork] | None = None,
             resolver: Callable[[str], list[IPAddress]] = resolve_host,
             ) -> tuple[bool, str, IPAddress | None]:
    """Is `host` allowed to be connected to, under the default
    public-internet-only policy plus the two optional narrowings/widenings?

    Order mirrors the plan's own decisions:
      1. a domain allow-list, if given, is checked on the HOSTNAME first —
         a narrowing of what may be reached at all, independent of what the
         name resolves to;
      2. every resolved address is then classified; a blocked category is
         refused UNLESS it is covered by the LAN allow-list (decision 6:
         reachability for an existing tool, opted into explicitly, never
         new scanning capability);
      3. anything else (a public address, or an explicitly LAN-approved
         one) is allowed.

    Fails closed on a DNS lookup failure and on a hostname resolving to no
    addresses at all — the platform default is public-internet-only, not
    "allow when in doubt.\""""
    host = host.strip().lower().rstrip(".")
    if not host:
        return False, "empty host", None
    if domain_allowlist:
        allowed_domains = [d.strip().lower().rstrip(".") for d in domain_allowlist]
        if not any(domain_in(host, d) for d in allowed_domains):
            return False, (f"{host!r} is not on the domain allow-list "
                           f"({', '.join(allowed_domains)})"), None
    try:
        addrs = resolver(host)
    except socket.gaierror as e:
        return False, f"could not resolve {host!r}: {e}", None
    if not addrs:
        return False, f"{host!r} resolved to no addresses", None
    lan_nets = list(lan_allowlist or [])
    for addr in addrs:
        category = classify_ip(addr)
        if category == "public":
            continue
        if any(addr in net for net in lan_nets):
            continue
        return False, (
            f"{host!r} resolves to {addr} ({category}), which is blocked by "
            f"default — public internet only, unless this address is covered "
            f"by an approved LAN allow-list. Ask an admin to add it if this "
            f"reachability is actually needed: it is the same opt-in a LAN "
            f"target needs for enum/trafficmon's CIDR scope."
        ), None
    return True, "ok", addrs[0]


# --- connecting to the address that was checked ------------------------------
# Resolving once to check and letting the HTTP library resolve AGAIN to connect
# leaves a window a rebinding DNS server answers differently in (audit run 1,
# F06). These connect to the address pin_host approved; the name is still used
# for the Host header and for TLS (SNI and certificate verification).
class PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host, port=None, *, ip, **kw):
        super().__init__(host, port, **kw)
        self._pinned_ip = str(ip)

    def connect(self):
        self.sock = socket.create_connection((self._pinned_ip, self.port), self.timeout)


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host, port=None, *, ip, **kw):
        super().__init__(host, port, **kw)
        self._pinned_ip = str(ip)

    def connect(self):
        sock = socket.create_connection((self._pinned_ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
