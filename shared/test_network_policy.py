#!/usr/bin/env python3
"""test_network_policy.py — resolved-IP egress control (shared/
network_policy.py, phase 3 of the generic-launcher arc).

    python3 shared/test_network_policy.py

Mostly no network needed (classify_ip and check_host take a fake resolver),
but one section does a REAL DNS lookup of example.com and a real socket
connection attempt to prove the policy's verdict matches what actually
happens on the wire — the same "prove it, don't assume it" standard as
shared/test_sandbox.py's live network test, with the same kind of control
(a known-public address must pass; if this box has no network at all, that
section is skipped loudly rather than silently "passing" on nothing).
"""
import ipaddress
import socket
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import network_policy as npmod  # noqa: E402

PASS = FAIL = 0


def check(label, got, want):
    global PASS, FAIL
    if got == want:
        PASS += 1; print(f"  [ OK ] {label}")
    else:
        FAIL += 1; print(f"  [FAIL] {label}\n         got  {got!r}\n         want {want!r}")


def section(t): print(f"\n=== {t} ===")


def ip(s): return ipaddress.ip_address(s)


section("classify_ip — every category a plain reading of the ipaddress module would miss")
check("a real public IPv4 address", npmod.classify_ip(ip("8.8.8.8")), "public")
check("a real public IPv6 address", npmod.classify_ip(ip("2001:4860:4860::8888")), "public")
check("loopback IPv4", npmod.classify_ip(ip("127.0.0.1")), "loopback")
check("loopback IPv6", npmod.classify_ip(ip("::1")), "loopback")
check("link-local IPv4 (also where cloud metadata usually lives)",
      npmod.classify_ip(ip("169.254.1.1")), "link_local")
check("the AWS/GCP/Azure metadata address is named specifically, not just link-local",
      npmod.classify_ip(ip("169.254.169.254")), "cloud_metadata")
check("the AWS IMDSv2 IPv6 metadata address is named specifically too",
      npmod.classify_ip(ip("fd00:ec2::254")), "cloud_metadata")
check("RFC1918 10/8", npmod.classify_ip(ip("10.1.2.3")), "private")
check("RFC1918 172.16/12", npmod.classify_ip(ip("172.16.5.5")), "private")
check("RFC1918 192.168/16", npmod.classify_ip(ip("192.168.1.1")), "private")
check("ULA IPv6 (fc00::/7)", npmod.classify_ip(ip("fc00::1")), "private")
check("the CGNAT shared range (100.64.0.0/10) — is_private is FALSE for this "
      "in Python's ipaddress module, which is exactly why classify_ip does not "
      "rely on is_private alone",
      npmod.classify_ip(ip("100.64.0.1")), "private")
check("multicast IS reported is_global=True by ipaddress, and must still be blocked",
      npmod.classify_ip(ip("224.0.0.1")), "multicast")
check("the broadcast address is reserved", npmod.classify_ip(ip("255.255.255.255")), "reserved")
check("0.0.0.0 (unspecified)", npmod.classify_ip(ip("0.0.0.0")), "reserved")
check("an IPv4-mapped IPv6 loopback is unmapped before classifying",
      npmod.classify_ip(ip("::ffff:127.0.0.1")), "loopback")
check("an IPv4-mapped IPv6 metadata address is unmapped before classifying",
      npmod.classify_ip(ip("::ffff:169.254.169.254")), "cloud_metadata")
check("an IPv4-mapped IPv6 PUBLIC address is unmapped and correctly public",
      npmod.classify_ip(ip("::ffff:8.8.8.8")), "public")
check("every blocked category is actually IN BLOCKED_CATEGORIES",
      {"loopback", "link_local", "cloud_metadata", "private", "multicast", "reserved"}
      <= npmod.BLOCKED_CATEGORIES, True)
check("public is never in BLOCKED_CATEGORIES", "public" in npmod.BLOCKED_CATEGORIES, False)


section("check_host — with a fake resolver, deterministic and network-free")


def fake_resolver(mapping):
    def _r(host):
        if host not in mapping:
            raise socket.gaierror(f"no fake entry for {host!r}")
        return [ip(a) for a in mapping[host]]
    return _r


ok, reason = npmod.check_host("example.com", resolver=fake_resolver({"example.com": ["93.184.216.34"]}))
check("a hostname resolving to a public address is allowed", ok, True)

ok, reason = npmod.check_host("evil.example", resolver=fake_resolver({"evil.example": ["127.0.0.1"]}))
check("a hostname resolving to loopback is refused", ok, False)
check("...naming the resolved address and category", "127.0.0.1" in reason and "loopback" in reason, True)

ok, reason = npmod.check_host("metadata.internal",
                              resolver=fake_resolver({"metadata.internal": ["169.254.169.254"]}))
check("a hostname resolving to the metadata address is refused", ok, False)
check("...naming it as cloud metadata specifically", "cloud_metadata" in reason, True)

ok, reason = npmod.check_host("rebind.example",
                              resolver=fake_resolver({"rebind.example": ["93.184.216.34", "10.0.0.5"]}))
check("ANY blocked address among several resolved is enough to refuse "
      "(a DNS-rebind trying one public + one private answer does not slip through)",
      ok, False)

ok, reason = npmod.check_host("nowhere.invalid", resolver=fake_resolver({}))
check("a DNS lookup failure fails closed, not open", ok, False)
check("...with a reason naming the lookup failure", "could not resolve" in reason, True)

ok, reason = npmod.check_host("empty.example", resolver=lambda h: [])
check("a hostname resolving to zero addresses fails closed", ok, False)

ok, reason = npmod.check_host("", resolver=fake_resolver({}))
check("an empty host string is refused, not passed to the resolver", ok, False)

ok, reason = npmod.check_host("EXAMPLE.com.", resolver=fake_resolver({"example.com": ["93.184.216.34"]}))
check("host normalization: trailing dot and case do not change the outcome", ok, True)


section("check_host — the LAN allow-list grants reachability, never scanning capability")
lan = [ipaddress.ip_network("192.0.2.0/24")]
ok, reason = npmod.check_host("ftp.lab", lan_allowlist=lan,
                              resolver=fake_resolver({"ftp.lab": ["192.0.2.10"]}))
check("a private address covered by the LAN allow-list is permitted",
      ok, True)
ok, reason = npmod.check_host("ftp.lab", lan_allowlist=lan,
                              resolver=fake_resolver({"ftp.lab": ["198.51.100.10"]}))
check("a private address OUTSIDE the LAN allow-list's CIDR is still refused",
      ok, False)
ok, reason = npmod.check_host("meta.lab", lan_allowlist=lan,
                              resolver=fake_resolver({"meta.lab": ["169.254.169.254"]}))
check("the LAN allow-list does not accidentally cover an unrelated blocked "
      "category (cloud metadata) just because SOME allow-list exists",
      ok, False)


section("check_host — the optional organisation domain allow-list narrows further")
allow = ["example.com", "example.org"]
ok, reason = npmod.check_host("mail.example.com", domain_allowlist=allow,
                              resolver=fake_resolver({"mail.example.com": ["93.184.216.34"]}))
check("a subdomain of an allow-listed domain (label-boundary rule) passes",
      ok, True)
ok, reason = npmod.check_host("evil-example.com", domain_allowlist=allow,
                              resolver=fake_resolver({"evil-example.com": ["93.184.216.34"]}))
check("evil-example.com is NOT a subdomain of example.com — the exact "
      "label-boundary case scope_domain.py exists to get right, reused here "
      "rather than reimplemented",
      ok, False)
ok, reason = npmod.check_host("notallowed.net", domain_allowlist=allow,
                              resolver=fake_resolver({"notallowed.net": ["93.184.216.34"]}))
check("a public address for a domain simply not on the allow-list is refused",
      ok, False)
check("...even though the resolved address itself is perfectly public",
      "domain allow-list" in reason, True)


section("live: a real DNS lookup and the control that makes it meaningful")
try:
    real_addrs = npmod.resolve_host("example.com")
    have_network = True
except socket.gaierror:
    have_network = False

if not have_network:
    print("  [skip] no DNS resolution available in this environment")
else:
    check("resolve_host('example.com') returns at least one real address",
          len(real_addrs) >= 1, True)
    check("every resolved address classifies as public (control: a known-good "
          "public hostname must not be blocked by this policy)",
          all(npmod.classify_ip(a) == "public" for a in real_addrs), True)
    ok, reason = npmod.check_host("example.com")
    check("check_host('example.com') with the real resolver and no allow-lists "
          "is allowed — the default-public-internet policy in practice",
          ok, True)
    ok, reason = npmod.check_host("localhost")
    check("check_host('localhost') with the REAL resolver is refused — "
          "the default policy blocks it exactly as it would in production",
          ok, False)

section("F06: the connection goes to the address that was checked (no DNS rebind)")
answers = iter([[ip("93.184.216.34")], [ip("127.0.0.1")]])   # public first, loopback on re-resolve
ok, why, pinned = npmod.pin_host("rebind.example", resolver=lambda h: next(answers))
check("the first (public) answer passes the check and is pinned", (ok, str(pinned)), (True, "93.184.216.34"))
_seen = []
_real = socket.create_connection
socket.create_connection = lambda addr, *a, **k: _seen.append(addr) or (_ for _ in ()).throw(OSError("stop"))
try:
    for cls in (npmod.PinnedHTTPConnection, npmod.PinnedHTTPSConnection):
        conn = cls("rebind.example", 443 if "HTTPS" in cls.__name__ else 80, ip=pinned, timeout=1)
        try:
            conn.connect()
        except OSError:
            pass
finally:
    socket.create_connection = _real
check("HTTP and HTTPS both connect to the pinned address, never re-resolving the name",
      _seen, [("93.184.216.34", 80), ("93.184.216.34", 443)])
check("the loopback answer a rebinding server would give next is never used",
      any(a[0] == "127.0.0.1" for a in _seen), False)

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
