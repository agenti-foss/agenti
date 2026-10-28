#!/usr/bin/env python3
"""test_recon_programs.py — the argument rules for recon programs
(shared/recon_programs.py) and the run_scan validator built on them.

    python3 shared/test_recon_programs.py

No root, no network, no SDK. Nothing here runs a scan: the rules are pure
text-in, text-out. What each section pins down:
  * every way audit run 1 reached a host outside the scope (F03) is refused;
  * every argument-rule bypass it found (F01: quoted, attached, abbreviated
    and unlisted options; F02: the raw string checked, a different argv run)
    is refused, because only listed options pass and the checked argv is the
    one that runs;
  * the ordinary recon commands an agent needs are still accepted;
  * every program the catalog can offer has rules, so none is left unguarded;
  * exclusions (out_of_scope) and IPv6-vs-IPv4 checks behave (F05).
"""
import ipaddress
import json
import sys
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import recon_programs as rp  # noqa: E402
import scope_cidr  # noqa: E402
import tool_registry as tr  # noqa: E402

PASS = FAIL = 0


def check(label, got, want):
    global PASS, FAIL
    if got == want:
        PASS += 1; print(f"  [ OK ] {label}")
    else:
        FAIL += 1; print(f"  [FAIL] {label}\n         got  {got!r}\n         want {want!r}")


def section(t): print(f"\n=== {t} ===")


SCOPE = scope_cidr.CIDRScope("enum")
CEILING = SCOPE.ceiling_from_engagement(SimpleNamespace(in_scope=["10.0.0.0/24"], out_of_scope=[]))
NARROW = SCOPE.narrow(CEILING, "10.0.0.5", required=True)
CATALOG = json.loads((HERE / "tool-catalog.json").read_text())
ALL = {p["name"] for p in CATALOG["baseline_programs"]} | {p["name"] for p in CATALOG["programs"]}


def verdict(cmd, scope=NARROW):
    ok, reason, argv = tr.check_shell_command(
        cmd, allowed_binaries=ALL, denied_patterns=list(tr.RECON_DENIED_PATTERNS),
        scope=SCOPE, scope_ceiling=scope)
    return ok, reason, argv


section("F03: targets the old regex never saw are refused (run narrowed to 10.0.0.5)")
for cmd in ("nmap -sV 10.0.0.5.attacker.example", "nmap -sV 10.0.0.5 scanme.example",
            "nmap -sV 10.0.0.5 134744072", "nmap -sV 10.0.0.5-255", "nmap -sV 10.0.0.5,6,200",
            "nmap -sV 10.0.0.5 10.0-255.0-255.5", "nmap -6 -sV 10.0.0.5 2001:db8::1",
            "nmap -sV 10.0.0.5 -iL /etc/hosts", "curl -I http://8.8.8.8/#@10.0.0.5",
            "curl -I http://8.8.8.8/?x=@10.0.0.5", "nmap -sV 10.0.0.5 localhost",
            "nmap -sV --dns-servers=8.8.8.8 10.0.0.5", "curl -I -x8.8.8.8:3128 http://10.0.0.5/",
            "curl -I --proxy=8.8.8.8:3128 http://10.0.0.5/",
            "nmap --script=targets-asn --script-args=targets-asn.asn=15169 10.0.0.5",
            "nmap 8.8.8.8", "nmap scanme.example", "curl -I http://10.0.0.[5-6]/",
            "curl -L http://10.0.0.5/", "dig +trace example.com", "dig @8.8.8.8 example.com",
            "whatweb http://10.0.0.6/", "gobuster dns -d corp.example -w /usr/share/wordlists/x"):
    check(f"refused: {cmd}", verdict(cmd)[0], False)

section("F01/F02: option smuggling is refused because only listed options pass")
for cmd in ("netexec smb 10.0.0.5 -x whoami", "netexec smb 10.0.0.5 '-x' whoami",
            "netexec smb 10.0.0.5 -xwhoami", "netexec smb 10.0.0.5 --put-file a b",
            "netexec smb 10.0.0.5 --put a b", "netexec smb 10.0.0.5 -M spider_plus",
            "netexec smb 10.0.0.5 --sa", "netexec mssql 10.0.0.5 -q x",
            "smbclient //10.0.0.5/c -c 'put x'", "smbclient //10.0.0.5/c --command=deltree",
            "smbclient //10.0.0.5/c -Tx a.tar", "rpcclient -c 'deletedomuser x' 10.0.0.5",
            "curl -X POST http://10.0.0.5/", "curl -d a=1 http://10.0.0.5/",
            "curl -o /tmp/x http://10.0.0.5/", "curl -sx http://10.0.0.5/",
            "nmap -sI 10.0.0.9 10.0.0.5", "nmap -oN /tmp/x 10.0.0.5", "nmap --script=vuln 10.0.0.5",
            "nmap -sC 10.0.0.5", "nmap -A 10.0.0.5", "nmap -- 10.0.0.5",
            "masscan -p80 --rate 100000 10.0.0.0/24", "snmpwalk -v3 -u x 10.0.0.5",
            "ldapsearch -x -D cn=admin -w pw -H ldap://10.0.0.5", "ldapsearch -H ldap://10.0.0.5 -b ''",
            "smbmap -H 10.0.0.5 -x whoami", "smbmap -H 10.0.0.5 --upload a b",
            "netexec smb 10.0.0.5 -u /usr/share/wordlists/users.txt -p x",
            "/usr/bin/nmap 10.0.0.5", "python3 -c 'print(1)'", "bash -c id",
            "GetUserSPNs.py CORP/ -no-pass -dc-ip 10.0.0.10 -outputfile /tmp/x",
            "hashcat -m 1000 x"):
    check(f"refused: {cmd}", verdict(cmd)[0], False)

section("ordinary recon commands are still accepted")
GOOD = ("nmap -sV -p 22,80,443 10.0.0.5", "nmap -sV -p- 10.0.0.5", "nmap -sV -T4 -p80 10.0.0.5",
        "nmap -sn 10.0.0.5", "nmap -sV --top-ports 100 --open 10.0.0.5",
        "nmap -sV --script=http-title,ssl-cert -p 443 10.0.0.5", "ping -c 3 10.0.0.5",
        "dig @10.0.0.5 corp.example AXFR", "dig @10.0.0.5 -x 10.0.0.5 +short",
        "curl -sI http://10.0.0.5/", "curl -sk https://10.0.0.5:8443/login -H 'Accept: */*'",
        "nikto -h 10.0.0.5 -p 80", "nikto -h http://10.0.0.5:8080/",
        "gobuster dir -u http://10.0.0.5/ -w /usr/share/wordlists/dirb/common.txt -q",
        "whatweb http://10.0.0.5/", "enum4linux-ng -A 10.0.0.5", "rpcclient -U '' -N -c enumdomusers 10.0.0.5",
        "smbclient -N -L 10.0.0.5", "smbclient -N //10.0.0.5/public -c ls",
        "netexec smb 10.0.0.5 -u '' -p '' --shares", "nxc ldap 10.0.0.5 -u '' -p '' --users",
        "GetUserSPNs.py CORP.LOCAL/ -no-pass -dc-ip 10.0.0.5", "impacket-GetNPUsers CORP.LOCAL/ -no-pass -dc-ip 10.0.0.5",
        "sslscan --no-colour 10.0.0.5:443", "sslyze --certinfo 10.0.0.5:443", "whois 10.0.0.5",
        "traceroute -n 10.0.0.5", "nbtscan 10.0.0.5",
        "showmount -e 10.0.0.5", "smbmap -H 10.0.0.5 -u '' -p ''", "snmpwalk -v2c -c public 10.0.0.5 system",
        "ldapsearch -x -H ldap://10.0.0.5 -s base -b '' namingContexts", "ike-scan -M 10.0.0.5",
        "wafw00f http://10.0.0.5/")
for cmd in GOOD:
    ok, reason, _ = verdict(cmd)
    check(f"accepted: {cmd}", (ok, reason), (True, "ok"))

section("the checked argv is exactly what runs")
check("prepended safety switches are in the argv",
      verdict("whatweb http://10.0.0.5/")[2], ["whatweb", "--follow-redirect=never", "--color=never", "http://10.0.0.5/"])
check("a quoted option is the same token as an unquoted one, and both are refused",
      [verdict(c)[0] for c in ("netexec smb 10.0.0.5 -x whoami", 'netexec smb 10.0.0.5 "-x" whoami')], [False, False])
check("values are passed as separate tokens", verdict("nmap -sV -p 22 10.0.0.5")[2],
      ["nmap", "-n", "-sV", "-p", "22", "10.0.0.5"])

section("audit run 2: every host value checked, each option once, argv as given")
for cmd in ("nikto -h 10.0.0.5 -h 10.0.0.6", "nikto -h 10.0.0.5 -host 10.0.0.6", "nikto -h 10.0.0.6",
            "nikto -h http://10.0.0.5/,10.0.0.6", "nikto -h 10.0.0.5,10.0.0.6",
            "ldapsearch -x -H 'ldap://10.0.0.5,ldap://10.0.0.6'",
            "ldapsearch -x -H 'ldap://10.0.0.5/x,ldap://10.0.0.6'", "ldapsearch -x -H 'ldap://10.0.0.5/??sub'",
            "curl -sI 'http://10.0.0.5/a;b'", "whatweb 'http://10.0.0.5/,10.0.0.6'",
            "sslscan 10.0.0.5:443 --sni-name 10.0.0.6", "sslscan --sni-name x.example 10.0.0.5:443",
            "sslscan 10.0.0.5:443 --no-colour", "sslscan 10.0.0.5:443 10.0.0.5:8443",
            "netexec smb 10.0.0.5 -u x -p ../run-config.json", "netexec smb 10.0.0.5 -u x -p a/b",
            "netexec smb 10.0.0.5 -u x -p .hidden", "netexec smb 10.0.0.5 -u .x -p ''",
            "nmap -p 22 -p 80 10.0.0.5", "nmap -sV -sV 10.0.0.5", "curl -sI -s http://10.0.0.5/",
            "gobuster dir -u http://10.0.0.5/ --url http://10.0.0.6/ -w /usr/share/wordlists/dirb/common.txt",
            "smbmap -H 10.0.0.5 --host-ip 10.0.0.6"):
    check(f"refused: {cmd}", verdict(cmd)[0], False)
for cmd in ("sslyze fd00:443::5", "sslscan fd00:443::5"):
    try:
        rp.check(cmd)
        check(f"a bare IPv6 address is refused: {cmd}", "accepted", "refused")
    except rp.ArgError as e:
        check(f"a bare IPv6 address is refused: {cmd}", "in brackets" in str(e), True)
check("a bracketed IPv6 address is the checked target", rp.check("sslyze [fd00::5]:443").targets, ["fd00::5/128"])
for cmd in ("sslscan --sni-name=www.example 10.0.0.5:443", "sslscan --timeout=5 10.0.0.5:443",
            "netexec smb 10.0.0.5 -u admin -p 'Summer2026!'", "nikto -host http://10.0.0.5/"):
    check(f"accepted: {cmd}", verdict(cmd)[:2], (True, "ok"))
check("nmap always gets -n (the run's fence blocks DNS; a lookup would hang)",
      verdict("nmap -sT -p 22 10.0.0.5")[2], ["nmap", "-n", "-sT", "-p", "22", "10.0.0.5"])
check("...and once only when the model also gives -n",
      verdict("nmap -n -sT -p 22 10.0.0.5")[2], ["nmap", "-n", "-sT", "-p", "22", "10.0.0.5"])
check("an attached value runs as typed", verdict("nmap -sV -p80 10.0.0.5")[2], ["nmap", "-n", "-sV", "-p80", "10.0.0.5"])
check("an --opt=value runs as typed", verdict("nmap --script=http-title 10.0.0.5")[2],
      ["nmap", "-n", "--script=http-title", "10.0.0.5"])
check("netexec --shares never write-checks", verdict("netexec smb 10.0.0.5 -u '' -p '' --shares")[2][-1],
      "--no-write-check")
check("smbmap never write-checks", "--no-write-check" in verdict("smbmap -H 10.0.0.5 -u '' -p ''")[2], True)

section("every program the catalog can offer has rules")
missing = sorted(n for n in ALL if rp.program_for(n) is None)
check("no baseline or catalog program is without a rule table", missing, [])
check("every example in the rules is accepted (inside 10.0.0.0/8)",
      [e for p in {id(p): p for p in rp.PROGRAMS.values()}.values() for e in p.examples
       if not tr.check_shell_command(e, allowed_binaries=ALL, denied_patterns=[], scope=SCOPE,
                                     scope_ceiling=[ipaddress.ip_network("10.0.0.0/8")])[0]], [])

section("F05: exclusions, and IPv6 against an IPv4 scope")
ceil = SCOPE.ceiling_from_engagement(SimpleNamespace(in_scope=["10.0.0.0/24 (lab)"],
                                                     out_of_scope=["10.0.0.9 (printer)", "10.0.0.128/25"]))
check("an excluded host is refused", verdict("nmap 10.0.0.9", ceil)[0], False)
check("an excluded subnet is refused", verdict("nmap 10.0.0.200", ceil)[0], False)
check("a range overlapping an exclusion is refused", verdict("nmap 10.0.0.0/24", ceil)[0], False)
check("a host beside the exclusion is accepted", verdict("nmap 10.0.0.10", ceil)[0], True)
check("an IPv6 target against an IPv4 scope is a clean refusal, not a crash",
      SCOPE.contains("2001:db8::1", [ipaddress.ip_network("10.0.0.0/24")])[0], False)
try:
    SCOPE.ceiling_from_engagement(SimpleNamespace(in_scope=["10.0.0.0/24"], out_of_scope=["the printer"]))
    check("an unparseable exclusion refuses the run", "allowed", "refused")
except SystemExit as e:
    check("an unparseable exclusion refuses the run", "out_of_scope" in str(e), True)
try:
    SCOPE.narrow(ceil, "10.0.0.9", required=True)
    check("-t naming an excluded host refuses the run", "allowed", "refused")
except SystemExit as e:
    check("-t naming an excluded host refuses the run", "outside the authorized" in str(e), True)

section("audit run 2: an IPv4 host written in IPv6 form is the same host")
mceil = SCOPE.ceiling_from_engagement(SimpleNamespace(in_scope=["10.0.0.0/24"], out_of_scope=["::ffff:10.0.0.9"]))
check("an exclusion written ::ffff:10.0.0.9 excludes 10.0.0.9", verdict("nmap 10.0.0.9", mceil)[0], False)
check("...and the target spelled ::ffff:10.0.0.9", verdict("nmap ::ffff:10.0.0.9", mceil)[0], False)
check("...a neighbour is still allowed", verdict("nmap 10.0.0.10", mceil)[0], True)
mceil = SCOPE.ceiling_from_engagement(SimpleNamespace(in_scope=["::ffff:10.0.0.0/120"], out_of_scope=["10.0.0.9"]))
check("an in_scope range in mapped form is the IPv4 range", [str(n) for n in mceil][:1], ["10.0.0.0/29"])
check("...and an IPv4 exclusion inside it is applied", verdict("nmap 10.0.0.9", mceil)[0], False)
check("a mapped target is checked as IPv4", SCOPE.contains("::ffff:10.0.0.5", NARROW), (True, "in scope"))

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
