#!/usr/bin/env python3
"""Tests for shared/api/proxytrust.py — no root, no vault, no web stack."""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "api"))
import proxytrust as pt

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1
    else:
        failed += 1; print(f"FAIL: {name}")

def hdr(d):
    return lambda k: d.get(k.lower())

# --- not behind a proxy: the peer, and headers are never read -------------
check("direct: peer used", pt.client_addr("203.0.113.9", hdr({}), behind_proxy=False) == "203.0.113.9")
check("direct: spoofed header ignored",
      pt.client_addr("203.0.113.9", hdr({"cf-connecting-ip": "1.2.3.4"}), behind_proxy=False) == "203.0.113.9")
check("direct: no peer -> empty", pt.client_addr("", hdr({}), behind_proxy=False) == "")

# --- behind a proxy ---------------------------------------------------------
H = {"cf-connecting-ip": "198.51.100.7"}
check("proxy: header from loopback peer trusted", pt.client_addr("127.0.0.1", hdr(H), behind_proxy=True) == "198.51.100.7")
check("proxy: ipv6 loopback peer trusted", pt.client_addr("::1", hdr(H), behind_proxy=True) == "198.51.100.7")
check("proxy: header from NON-loopback peer ignored",
      pt.client_addr("192.168.1.5", hdr(H), behind_proxy=True) == "")
check("proxy: missing header -> empty (never the shared 127.0.0.1 bucket)",
      pt.client_addr("127.0.0.1", hdr({}), behind_proxy=True) == "")
check("proxy: garbage header -> empty", pt.client_addr("127.0.0.1", hdr({"cf-connecting-ip": "evil'; DROP"}), behind_proxy=True) == "")
check("proxy: hostname rejected", pt.client_addr("127.0.0.1", hdr({"cf-connecting-ip": "example.com"}), behind_proxy=True) == "")
check("proxy: ip:port rejected", pt.client_addr("127.0.0.1", hdr({"cf-connecting-ip": "1.2.3.4:80"}), behind_proxy=True) == "")
check("proxy: ipv6 normalised",
      pt.client_addr("127.0.0.1", hdr({"cf-connecting-ip": "2001:DB8:0::1"}), behind_proxy=True) == "2001:db8::1")
check("proxy: XFF uses the RIGHT-most entry (what our proxy appended)",
      pt.client_addr("127.0.0.1", hdr({"x-forwarded-for": "6.6.6.6, 198.51.100.7"}),
                     behind_proxy=True, header="x-forwarded-for") == "198.51.100.7")
check("proxy: client-forged left entries do not win",
      pt.client_addr("127.0.0.1", hdr({"x-forwarded-for": "198.51.100.7, 6.6.6.6, 203.0.113.1"}),
                     behind_proxy=True, header="x-forwarded-for") == "203.0.113.1")
check("proxy: oversized value rejected", pt.parse_ip("1" * 100) is None)

# --- allowed hosts ----------------------------------------------------------
ah = pt.allowed_hosts("agenti.example.com")
check("hosts: public domain allowed", "agenti.example.com" in ah)
check("hosts: loopback names allowed", "localhost" in ah and "127.0.0.1" in ah)
check("hosts: random name not allowed", "evil.example" not in ah)
check("hosts: no hostname still has loopback", pt.allowed_hosts("") == ["localhost", "127.0.0.1"])

print(f"{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
