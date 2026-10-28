"""
recon_programs.py — the programs a RECON agent may run (run_scan), and the
exact arguments each one accepts.

Until 2026-10-22 run_scan allowed a program NAME, refused a few patterns in the
raw command string, and scope-checked whatever looked like a dotted-quad IP.
Audit run 1 showed that is not a boundary: a hostname, an nmap range, IPv6, a
decimal IP, -iL <file>, a proxy option or a URL with '#@' reached hosts outside
the engagement, and option spellings the patterns did not foresee (quoted,
attached, abbreviated) slipped past them (F01-F03). This module replaces that
with the shape analysis_programs.py already uses for the sandbox:

  * Each program lists the options it MAY be given. Every other option is
    refused by name, with the list of what is allowed, so the model can
    correct itself in one turn. Abbreviations, bundles and unknown spellings
    are simply not on the list.
  * Every non-option argument has a declared meaning (an IP/CIDR target, a URL,
    an SMB share, a query name ...). Anything else is refused.
  * Every argument that names a host the program will contact is returned as a
    TARGET; the caller checks each one against the run's scope (exclusions
    included) and refuses the command if any is outside it. A target must be a
    literal IP or CIDR: names are refused, because a name is resolved by the
    program, after the check, by a resolver nobody here controls.
  * Options that redirect traffic (proxies, DNS servers, redirects, target
    lists, output files, scripts that add their own targets) are absent.
  * The checked argument list is exactly the one that runs: there is no shell,
    and run_scan executes the list this module returns.

New programs are added HERE, by a developer, with their rules reviewed. An
admin may offer a catalog program to an agent (tool-catalog.json); a program
with no rules here cannot run, and the refusal says so.
"""
from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import scope_cidr

MAX_COMMAND_CHARS = 4000
MAX_VALUE_CHARS = 500
WORDLIST_DIRS = ("/usr/share/wordlists/", "/usr/share/seclists/", "/usr/share/dirb/wordlists/",
                 "/usr/share/dirbuster/wordlists/")

__all__ = ["ArgError", "Flag", "Program", "Checked", "PROGRAMS", "check", "program_for", "names"]


class ArgError(Exception):
    """The command is refused. The message says why and what is allowed."""


# --------------------------------------------------------------------------- values
_PORTS = re.compile(r"^(-|[0-9TU:,-]{1,200})$")
_INT = re.compile(r"^[0-9]{1,7}$")
_NUMBER = re.compile(r"^[0-9]{1,6}(\.[0-9]{1,3})?(ms|s|m)?$")
_WORD = re.compile(r"^[A-Za-z0-9_.@-]{1,128}$")                  # domain, workgroup
# netexec and friends read -u/-p as a FILE when one exists by that name, so a
# credential value may never name one: no '/' anywhere and no leading '.', and
# run_scan runs every program in an empty folder, so a bare name finds nothing.
_USER = re.compile(r"^([A-Za-z0-9_@$-][A-Za-z0-9_.@$-]{0,127})?$")   # a user name; empty = null session
_SECRET = re.compile(r"^([^\s/.][^\s/]{0,255})?$")                 # a password or hash (or empty)
_HEADER = re.compile(r"^[A-Za-z0-9-]{1,64}: ?[\x20-\x7e]{0,400}$")
_DNSNAME = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9])?\.)*"
                      r"[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9])?\.?$")


@dataclass(frozen=True)
class Flag:
    """One accepted option. kind: none | int | number | ports | choice | text
    (matching `pattern`) | target (an IP/CIDR the program contacts) | url (an
    http(s) URL whose host it contacts) | ldapurl | wordlist (a file under
    WORDLIST_DIRS) | ip (any literal IP that is only a query, never contacted)."""
    help: str
    kind: str = "none"
    choices: tuple[str, ...] = ()
    pattern: str = ""
    attached: bool = False          # also accept -X<value> / -X<value> glued to the flag

    @property
    def names_host(self) -> bool:
        return self.kind in _HOST_KINDS

    @property
    def takes_value(self) -> bool:
        return self.kind != "none"


@dataclass(frozen=True)
class Program:
    name: str
    flags: dict[str, Flag]
    positional: str                 # how plain arguments are read; see _POSITIONAL
    aliases: tuple[str, ...] = ()   # other binary names for the same program
    prepend: tuple[str, ...] = ()   # always added before the model's arguments
    min_positional: int = 1
    max_positional: int = 64
    needs_target: bool = True       # at least one checked target overall
    bundles: bool = False           # -sI = -s -I, when every letter is a listed no-value switch
    joined_values: bool = False     # the program reads only --opt=value (sslscan)
    target_last: bool = False       # the program scans its LAST argument, so the checked one must be last
    examples: tuple[str, ...] = ()


_HOST_KINDS = ("target", "url", "ldapurl", "target_or_url")


@dataclass
class Checked:
    argv: list[str]                 # exactly what runs
    targets: list[str] = field(default_factory=list)   # IP/CIDR strings to scope-check


# --------------------------------------------------------------------------- parsing
def _ip_target(text: str, what: str) -> str:
    try:
        return str(scope_cidr.network(text))
    except ValueError:
        raise ArgError(f"{what} {text!r} is not a literal IP or CIDR. Name the address itself "
                       f"(e.g. 10.0.0.5 or 10.0.0.0/24): host names, ranges like 10.0.0.1-20, "
                       f"lists and decimal forms are refused because they cannot be checked "
                       f"against the scope before the program resolves them.")


def _url_target(text: str, *, schemes=("http", "https")) -> str:
    # ',' and ';' are refused because nikto, ldapsearch and others read one
    # argument as a LIST of hosts, and only the first would be checked here.
    if any(c in text for c in "@\\,;") or any(ord(c) < 33 for c in text):
        raise ArgError(f"URL {text!r} is refused: give exactly one URL, with no '@', ',', ';', "
                       f"backslash, spaces or control characters.")
    try:
        u = urlsplit(text)
        host = u.hostname
        u.port                                      # raises on a malformed port
    except ValueError:
        raise ArgError(f"URL {text!r} cannot be parsed.")
    if u.scheme not in schemes or not host:
        raise ArgError(f"URL {text!r} is refused: it must be {' or '.join(s + '://' for s in schemes)}"
                       f"<ip>[:port]/path.")
    if u.scheme.startswith("ldap") and (u.path not in ("", "/") or u.query or u.fragment):
        raise ArgError(f"LDAP URL {text!r} is refused: give only ldap[s]://<ip>[:port], with the "
                       f"search base in -b.")
    return _ip_target(host, "the URL's host")


def _target_or_url(text: str, what: str) -> str:
    return _url_target(text) if "://" in text else _ip_target(text, what)


def _host_port_target(text: str) -> str:
    """ip, ip:port, [v6] or [v6]:port. A bare IPv6 address is refused: sslscan and
    sslyze split it at the first ':' and look the first group up as a host name."""
    m = re.fullmatch(r"\[([0-9A-Fa-f:.]+)\](?::[0-9]{1,5})?|([0-9.]+)(?::[0-9]{1,5})?", text)
    if not m:
        raise ArgError(f"{text!r} must be an IPv4 address, optionally with :port, or an IPv6 "
                       f"address in brackets, e.g. [2001:db8::5]:443.")
    return _ip_target(next(g for g in m.groups() if g), "the target")


def _wordlist(text: str) -> str:
    if ".." in text or not text.startswith(WORDLIST_DIRS):
        raise ArgError(f"wordlist {text!r} must be a file under {', '.join(WORDLIST_DIRS)}")
    return text


def _value(flag: Flag, name: str, value: str, out: Checked) -> None:
    if len(value) > MAX_VALUE_CHARS:
        raise ArgError(f"the value for {name} is too long")
    if flag.kind not in ("ports",) and value.startswith("-"):
        raise ArgError(f"the value for {name} must not start with '-' ({value!r})")
    k = flag.kind
    if k == "int" and not _INT.match(value):
        raise ArgError(f"{name} takes a whole number, not {value!r}")
    if k == "number" and not _NUMBER.match(value):
        raise ArgError(f"{name} takes a number (optionally with ms/s/m), not {value!r}")
    if k == "ports" and not _PORTS.match(value):
        raise ArgError(f"{name} takes ports like 22,80,443 or 1-1000, not {value!r}")
    if k == "choice" and value not in flag.choices:
        raise ArgError(f"{name} must be one of: {', '.join(flag.choices)} (not {value!r})")
    if k == "text" and not re.fullmatch(flag.pattern, value):
        raise ArgError(f"the value {value!r} for {name} is refused ({flag.help})")
    if k == "target":
        out.targets.append(_ip_target(value, f"{name}"))
    if k == "url":
        out.targets.append(_url_target(value))
    if k == "target_or_url":
        out.targets.append(_target_or_url(value, name))
    if k == "ldapurl":
        out.targets.append(_url_target(value, schemes=("ldap", "ldaps")))
    if k == "wordlist":
        _wordlist(value)
    if k == "ip":
        _ip_target(value, name)


def _positional(prog: Program, token: str, index: int, out: Checked) -> None:
    kind = prog.positional
    if kind == "targets":
        out.targets.append(_ip_target(token, "target"))
    elif kind == "target_or_url":
        out.targets.append(_target_or_url(token, "target"))
    elif kind == "urls":
        out.targets.append(_url_target(token))
    elif kind == "hostports":
        out.targets.append(_host_port_target(token))
    elif kind == "dig":
        _dig_positional(token, out)
    elif kind == "gobuster":
        if index == 0:
            if token not in ("dir", "vhost"):
                raise ArgError("gobuster's first argument must be the mode: dir or vhost "
                               "(dns mode resolves names outside the scope check)")
        else:
            raise ArgError(f"unexpected argument {token!r} for gobuster: the URL goes in -u")
    elif kind == "netexec":
        if index == 0:
            if token not in NETEXEC_PROTOCOLS:
                raise ArgError(f"netexec's first argument must be the protocol: {', '.join(NETEXEC_PROTOCOLS)}")
        else:
            out.targets.append(_ip_target(token, "target"))
    elif kind == "impacket":
        if index > 0 or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}/[A-Za-z0-9_.$-]{0,64}(:[^\s]{0,128})?", token):
            raise ArgError("give one identity as DOMAIN/user[:password] (the domain controller goes in -dc-ip)")
    elif kind == "share":
        m = re.fullmatch(r"//([^/]+)/([A-Za-z0-9_$.-]{1,80})", token)
        if index > 0 or not m:
            raise ArgError("give one share as //<ip>/<share>")
        out.targets.append(_ip_target(m.group(1), "the share's host"))
    elif kind == "snmp":
        if index == 0:
            out.targets.append(_ip_target(token, "target"))
        elif index == 1 and re.fullmatch(r"[A-Za-z0-9.:_-]{1,128}", token):
            pass                                       # an OID or MIB name
        else:
            raise ArgError("snmpwalk takes the target IP and, optionally, one OID")
    elif kind == "ldapfilter":
        if not re.fullmatch(r"[^\s]{1,400}", token):
            raise ArgError(f"ldapsearch filter/attribute {token!r} is refused")
    else:
        raise ArgError(f"unexpected argument {token!r}")


_DIG_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "SOA", "SRV", "CNAME", "PTR", "ANY", "AXFR", "CAA", "HINFO")
_DIG_PLUS = ("+short", "+noall", "+answer", "+authority", "+additional", "+tcp", "+norecurse",
             "+dnssec", "+nocmd", "+nostats", "+multiline", "+nsid")


def _dig_positional(token: str, out: Checked) -> None:
    if token.startswith("@"):
        out.targets.append(_ip_target(token[1:], "the DNS server (@server)"))
    elif token.startswith("+"):
        if token not in _DIG_PLUS:
            raise ArgError(f"dig option {token!r} is not allowed. Allowed: {' '.join(_DIG_PLUS)} "
                           f"(+trace and friends are refused: they query servers outside the scope)")
    elif token.upper() in _DIG_TYPES or token.upper() == "IN":
        pass
    elif _DNSNAME.match(token):
        pass                                           # the query name: asked of @server, not contacted
    else:
        raise ArgError(f"dig argument {token!r} is not a DNS name, record type or allowed +option")


# --------------------------------------------------------------------------- tables
def _f(help: str, kind: str = "none", **kw) -> Flag:
    return Flag(help, kind, **kw)


def _many(*pairs) -> dict[str, Flag]:
    t: dict[str, Flag] = {}
    for names, flag in pairs:
        for n in names.split():
            t[n] = flag
    return t


NSE_SCRIPTS = ("banner", "http-title", "http-headers", "http-methods", "http-server-header",
               "http-robots.txt", "http-enum", "ssl-cert", "ssl-enum-ciphers", "ssh-hostkey",
               "ssh2-enum-algos", "smb-os-discovery", "smb-protocols", "smb-security-mode",
               "smb2-security-mode", "smb2-time", "nbstat", "rdp-ntlm-info", "ldap-rootdse",
               "snmp-info", "snmp-sysdescr", "ftp-anon", "ftp-syst", "smtp-commands",
               "imap-capabilities", "pop3-capabilities", "rpcinfo", "nfs-showmount", "nfs-ls",
               "mysql-info", "ms-sql-info", "vnc-info", "dns-nsid", "sip-methods", "telnet-ntlm-info")
_NSE = r"^(%s)(,(%s))*$" % ("|".join(map(re.escape, NSE_SCRIPTS)), "|".join(map(re.escape, NSE_SCRIPTS)))

NMAP = Program(
    name="nmap",
    flags=_many(
        # Runs are unprivileged and have no raw packet sockets (operator decision
        # 9), so nmap scans by connecting: -sS, -sU, -O, -PE, --traceroute and
        # --badsum cannot work and are not offered.
        ("-sT -sV -sn -Pn -n -v -vv --open --reason -F -6 --version-light --version-all "
         "--system-dns --no-stylesheet",
         _f("a scan type or switch")),
        ("-p", _f("ports, e.g. 22,80,443 or 1-1000 or - for all", "ports", attached=True)),
        ("--top-ports", _f("scan the N most common ports", "int")),
        ("-T", _f("timing template 0-5", "choice", choices=tuple("012345"), attached=True)),
        ("--max-retries --min-rate --max-rate --min-parallelism --max-parallelism", _f("a number", "int")),
        ("--host-timeout --scan-delay --max-rtt-timeout", _f("a time, e.g. 30s", "number")),
        ("--script", _f("allow-listed NSE scripts, comma separated: " + ", ".join(NSE_SCRIPTS), "text",
                        pattern=_NSE)),
        ("--version-intensity", _f("0-9", "choice", choices=tuple("0123456789"))),
    ),
    positional="targets",
    # -n always: targets are literal IPs, and the run's kernel fence (scope.conf)
    # blocks the DNS server, so nmap's reverse lookups hang until run_scan's own
    # time limit (15 minutes) instead of failing. Found live on 2026-10-28.
    prepend=("-n",),
    examples=("nmap -sT -sV -p 22,80,443 10.0.0.5", "nmap -sn 10.0.0.0/24", "nmap -sV --script=http-title,ssl-cert -p 443 10.0.0.5"),
)

PING = Program("ping", _many(
    ("-n -q -4 -6", _f("a switch")),
    ("-c", _f("number of pings", "int", attached=True)),
    ("-W -w -i", _f("seconds", "number", attached=True)),
), positional="targets", max_positional=1, examples=("ping -c 3 10.0.0.5",))

DIG = Program("dig", _many(
    ("-4 -6", _f("a switch")),
    ("-x", _f("reverse lookup of this address (asked of @server)", "ip")),
    ("-t", _f("record type", "choice", choices=_DIG_TYPES)),
    ("-p", _f("server port", "int")),
), positional="dig", examples=("dig @10.0.0.53 corp.example AXFR", "dig @10.0.0.53 -x 10.0.0.5"))

NIKTO = Program("nikto", _many(
    ("-h -host", _f("the target: an IP or http(s)://<ip>[:port]/", "target_or_url")),
    ("-p -port", _f("ports", "ports")),
    ("-ssl -nossl -nointeractive -no404", _f("a switch")),
    ("-Tuning", _f("test classes, e.g. 123b", "text", pattern=r"^[0-9a-ex]{1,20}$")),
    ("-maxtime", _f("maximum scan time, e.g. 600s", "number")),
    ("-timeout", _f("request timeout in seconds", "int")),
    ("-Display", _f("output detail", "text", pattern=r"^[1234DEPSV]{1,8}$")),
), positional="none", min_positional=0, max_positional=0, examples=("nikto -h 10.0.0.5 -p 80",))

GOBUSTER = Program("gobuster", _many(
    ("-u --url", _f("the base URL, http(s)://<ip>[:port]/", "url")),
    ("-w --wordlist", _f("a wordlist under " + ", ".join(WORDLIST_DIRS), "wordlist")),
    ("-t --threads", _f("threads", "int")),
    ("-x --extensions", _f("extensions, e.g. php,txt", "text", pattern=r"^[A-Za-z0-9,]{1,80}$")),
    ("-s --status-codes -b --status-codes-blacklist", _f("status codes", "text", pattern=r"^[0-9,-]{1,120}$")),
    ("-k --no-tls-validation -q --quiet --no-error -e --expanded -n --no-status --append-domain",
     _f("a switch")),
    ("--timeout --delay", _f("a time, e.g. 10s", "number")),
), positional="gobuster", max_positional=1,
    examples=("gobuster dir -u http://10.0.0.5/ -w /usr/share/wordlists/dirb/common.txt -q",))

WHATWEB = Program("whatweb", _many(
    ("-q --quiet -v --verbose --no-errors", _f("a switch")),
    ("-a --aggression", _f("aggression level", "choice", choices=("1", "3"))),
    ("--open-timeout --read-timeout", _f("seconds", "int")),
), positional="target_or_url", prepend=("--follow-redirect=never", "--color=never"),
    examples=("whatweb http://10.0.0.5/",))

ENUM4LINUX = Program("enum4linux-ng", _many(
    ("-A -As -U -G -S -P -O -L -I -N -R -d -C", _f("an enumeration switch")),
    ("-u", _f("user name (empty for a null session)", "text", pattern=_USER.pattern)),
    ("-p", _f("password", "text", pattern=_SECRET.pattern)),
    ("-w", _f("domain/workgroup", "text", pattern=_WORD.pattern)),
    ("-t", _f("timeout in seconds", "int")),
), positional="targets", max_positional=1, examples=("enum4linux-ng -A 10.0.0.5",))

RPC_COMMANDS = ("srvinfo", "enumdomusers", "enumdomgroups", "enumalsgroups builtin", "querydominfo",
                "getdompwinfo", "lsaquery", "netshareenumall", "enumprivs", "lookupnames administrator")
RPCCLIENT = Program("rpcclient", _many(
    ("-N --no-pass", _f("no password (null session)")),
    ("-U --user", _f("user[%password]", "text", pattern=r"^[A-Za-z0-9_.\\-]{0,64}(%[^\s]{0,128})?$")),
    ("-W --workgroup", _f("workgroup", "text", pattern=_WORD.pattern)),
    ("-p --port", _f("port", "int")),
    ("-c --command", _f("one read-only command: " + ", ".join(RPC_COMMANDS), "choice", choices=RPC_COMMANDS)),
), positional="targets", max_positional=1, examples=("rpcclient -U '' -N -c enumdomusers 10.0.0.5",))

SMBCLIENT = Program("smbclient", _many(
    ("-L --list", _f("list the shares of this host", "target")),
    ("-N --no-pass -g", _f("a switch")),
    ("-U --user", _f("user[%password]", "text", pattern=r"^[A-Za-z0-9_.\\-]{0,64}(%[^\s]{0,128})?$")),
    ("-W --workgroup", _f("workgroup", "text", pattern=_WORD.pattern)),
    ("-p --port", _f("port", "int")),
    ("-m --max-protocol", _f("protocol", "choice", choices=("NT1", "SMB2", "SMB3"))),
    ("-c --command", _f("one read-only listing command", "choice", choices=("ls", "dir"))),
), positional="share", min_positional=0, max_positional=1,
    examples=("smbclient -N -L 10.0.0.5", "smbclient -N //10.0.0.5/public -c ls"))

NETEXEC_PROTOCOLS = ("smb", "ldap", "rdp", "ssh", "winrm", "ftp")
NETEXEC = Program("netexec", _many(
    ("-u", _f("user name, not a file (empty for a null session)", "text", pattern=_USER.pattern)),
    ("-p", _f("password (not a file)", "text", pattern=_SECRET.pattern)),
    ("-H --hash", _f("NT hash", "text", pattern=r"^([0-9a-fA-F]{32}:)?[0-9a-fA-F]{32}$")),
    ("-d --domain", _f("domain", "text", pattern=_WORD.pattern)),
    ("--port", _f("port", "int")),
    ("-t --threads --timeout", _f("a number", "int")),
    ("--local-auth --no-bruteforce --shares --users --groups --local-groups --pass-pol --sessions "
     "--loggedon-users --disks --interfaces --smb-sessions --rid-brute --get-sid --admin-count "
     "--trusted-for-delegation --password-not-required --dc-list --users-export-none",
     _f("a read-only enumeration switch")),
), positional="netexec", min_positional=2, aliases=("nxc",),
    examples=("netexec smb 10.0.0.5 -u '' -p '' --shares",))

def _impacket(name: str) -> Program:
    return Program(name, _many(
        ("-dc-ip", _f("the domain controller's IP (the target)", "target")),
        ("-no-pass -request -k", _f("a switch")),
        ("-hashes", _f("LMHASH:NTHASH", "text", pattern=r"^[0-9a-fA-F]{0,32}:[0-9a-fA-F]{32}$")),
        ("-format", _f("hash format", "choice", choices=("hashcat", "john"))),
    ), positional="impacket", max_positional=1,
        aliases=("impacket-" + name.removesuffix(".py"),),
        examples=(f"{name} CORP.LOCAL/ -no-pass -dc-ip 10.0.0.10",))

GETUSERSPNS = _impacket("GetUserSPNs.py")
GETNPUSERS = _impacket("GetNPUsers.py")

CURL = Program("curl", _many(
    ("-I --head -s --silent -S --show-error -k --insecure -i --include -v --verbose --compressed "
     "--http1.1 --http2 -4 -6 --path-as-is", _f("a switch")),
    ("-m --max-time --connect-timeout", _f("seconds", "int")),
    ("-H --header", _f("one request header, Name: value", "text", pattern=_HEADER.pattern)),
    ("-A --user-agent", _f("user agent", "text", pattern=r"^[\x20-\x7e]{1,200}$")),
), positional="urls", bundles=True, examples=("curl -sI http://10.0.0.5/",))

SSLSCAN = Program("sslscan", _many(
    ("--no-colour --show-certificate --no-fallback --no-renegotiation --no-compression --no-heartbleed "
     "--tlsall --ssl2 --ssl3 --tls10 --tls11 --tls12 --tls13 --ipv4 --ipv6 --show-ciphers", _f("a switch")),
    ("--timeout --connect-timeout", _f("seconds", "int")),
    ("--sni-name", _f("server name to send", "text", pattern=_DNSNAME.pattern)),
), positional="hostports", max_positional=1, joined_values=True, target_last=True,
    examples=("sslscan --no-colour 10.0.0.5:443", "sslscan --sni-name=www.example 10.0.0.5:443"))

SSLYZE = Program("sslyze", _many(
    ("--certinfo --tlsv1_3 --tlsv1_2 --tlsv1_1 --tlsv1 --sslv3 --sslv2 --heartbleed --robot "
     "--openssl_ccs --reneg --compression --fallback --http_headers --elliptic_curves --early_data "
     "--quiet", _f("a check")),
), positional="hostports", examples=("sslyze --certinfo --tlsv1_2 10.0.0.5:443",))

TESTSSL = Program("testssl.sh", _many(
    ("-p --protocols -S --server-defaults -e --each-cipher -E --cipher-per-proto -U --vulnerable "
     "--fast --quiet --ip=one -4 -6", _f("a check or switch")),
    ("--color", _f("0-3", "choice", choices=("0", "1", "2", "3"))),
    ("--warnings", _f("batch or off", "choice", choices=("batch", "off"))),
), positional="hostports", aliases=("testssl",), examples=("testssl.sh --fast --color 0 10.0.0.5:443",))

WHOIS = Program("whois", _many(("-H", _f("hide legal disclaimers")),),
                positional="targets", max_positional=1, examples=("whois 10.0.0.5",))

TRACEROUTE = Program("traceroute", _many(
    ("-n -I -T -U -4 -6", _f("a switch")),
    ("-p --port", _f("port", "int")),
    ("-m --max-hops -q --queries", _f("a number", "int")),
    ("-w --wait", _f("seconds", "number")),
), positional="targets", max_positional=1, examples=("traceroute -n 10.0.0.5",))

NBTSCAN = Program("nbtscan", _many(
    ("-v -h -q", _f("a switch")),
    ("-t", _f("timeout in ms", "int")),
), positional="targets", max_positional=1, examples=("nbtscan 10.0.0.0/24",))

SHOWMOUNT = Program("showmount", _many(
    ("-e --exports -a --all -d --directories --no-headers", _f("a switch")),
), positional="targets", max_positional=1, examples=("showmount -e 10.0.0.5",))

SMBMAP = Program("smbmap", _many(
    ("-H --host-ip", _f("the target IP", "target")),
    ("-u --username", _f("user name (empty for a null session)", "text", pattern=_USER.pattern)),
    ("-p --password", _f("password or LM:NT hash", "text", pattern=_SECRET.pattern)),
    ("-d --domain", _f("domain", "text", pattern=_WORD.pattern)),
    ("-P --port", _f("port", "int")),
    ("-s", _f("share name", "text", pattern=r"^[A-Za-z0-9_$.-]{1,80}$")),
    ("-r", _f("a path to list (read-only)", "text", pattern=r"^[A-Za-z0-9_$./\\ -]{1,200}$")),
    ("--depth", _f("recursion depth", "int")),
    ("-R -q --no-banner --no-color --no-update", _f("a switch")),
), positional="none", min_positional=0, max_positional=0, prepend=("--no-write-check",),
    examples=("smbmap -H 10.0.0.5 -u '' -p ''",))

SNMPWALK = Program("snmpwalk", _many(
    ("-v", _f("SNMP version (v3 is not offered)", "choice", choices=("1", "2c"), attached=True)),
    ("-c", _f("community string", "text", pattern=r"^[A-Za-z0-9_.@-]{1,64}$")),
    ("-t", _f("timeout seconds", "int")),
    ("-r", _f("retries", "int")),
    ("-On -Oq -Os -Ov -Cc", _f("output switch")),
), positional="snmp", max_positional=2, examples=("snmpwalk -v2c -c public 10.0.0.5 system",))

LDAPSEARCH = Program("ldapsearch", _many(
    ("-x", _f("simple (anonymous) bind — required")),
    ("-H", _f("ldap://<ip>[:port] or ldaps://...", "ldapurl")),
    ("-b", _f("search base DN", "text", pattern=r"^[A-Za-z0-9=,_ .-]{0,300}$")),
    ("-s", _f("scope", "choice", choices=("base", "one", "sub", "children"))),
    ("-z -l", _f("size or time limit", "int")),
    ("-L -LL -LLL", _f("output format")),
), positional="ldapfilter", min_positional=0, needs_target=True,
    examples=("ldapsearch -x -H ldap://10.0.0.10 -s base -b '' namingContexts",))

IKESCAN = Program("ike-scan", _many(
    ("-M --multiline -2 --ikev2 -v --verbose -q --quiet", _f("a switch")),
    ("-r --retry -t --timeout --dport", _f("a number", "int")),
    ("--trans", _f("transform spec", "text", pattern=r"^[0-9,/]{1,60}$")),
), positional="targets", examples=("ike-scan -M 10.0.0.1",))

WAFW00F = Program("wafw00f", _many(
    ("-a --findall -v --verbose", _f("a switch")),
), positional="target_or_url", prepend=("--noredirect",), max_positional=1,
    examples=("wafw00f http://10.0.0.5/",))

PROGRAMS: dict[str, Program] = {}
for _p in (NMAP, PING, DIG, NIKTO, GOBUSTER, WHATWEB, ENUM4LINUX, RPCCLIENT, SMBCLIENT, NETEXEC,
           GETUSERSPNS, GETNPUSERS, CURL, SSLSCAN, SSLYZE, TESTSSL, WHOIS, TRACEROUTE,
           NBTSCAN, SHOWMOUNT, SMBMAP, SNMPWALK, LDAPSEARCH, IKESCAN, WAFW00F):
    PROGRAMS[_p.name] = _p
    for _a in _p.aliases:
        PROGRAMS[_a] = _p


def names() -> list[str]:
    return sorted({p.name for p in PROGRAMS.values()})


def program_for(binary: str) -> Program | None:
    return PROGRAMS.get(binary)


def _allowed_list(prog: Program) -> str:
    return " ".join(sorted(prog.flags))


def check(command: str) -> Checked:
    """Parse `command` against its program's table. Returns the argv that runs
    and every target it names; raises ArgError with a usable message."""
    if len(command) > MAX_COMMAND_CHARS:
        raise ArgError("the command is too long")
    try:
        parts = shlex.split(command)
    except ValueError as e:
        raise ArgError(f"the command cannot be parsed ({e})")
    if not parts:
        raise ArgError("empty command")
    if "/" in parts[0]:
        raise ArgError(f"give the program by name ({parts[0].rsplit('/', 1)[-1]}), not by path")
    prog = program_for(parts[0])
    if prog is None:
        raise ArgError(f"'{parts[0]}' has no reviewed argument rules, so it cannot run "
                       f"(rules exist for: {', '.join(names())})")
    out = Checked(argv=[parts[0], *prog.prepend])
    args, i, pos = parts[1:], 0, 0
    seen: set[str] = set()
    host_flags: set[int] = set()

    def once(name: str, flag: Flag) -> None:
        # A program given an option twice uses one of them (nikto the last),
        # so a second copy is refused, and the spellings of one host option
        # (-h/-host, -u/--url) count as one.
        if name in seen or (flag.names_host and id(flag) in host_flags):
            raise ArgError(f"{name} is given more than once; give each option once")
        seen.add(name)
        if flag.names_host:
            host_flags.add(id(flag))

    while i < len(args):
        tok = args[i]
        if tok == "--":
            raise ArgError("'--' is not accepted")
        if tok.startswith("-") and len(tok) > 1 and not (prog.positional == "dig" and tok[0] in "@+"):
            name, eq, val = tok.partition("=") if tok.startswith("--") else (tok, "", "")
            flag = prog.flags.get(name)
            if flag is None and not tok.startswith("--"):
                for n, f in prog.flags.items():          # -p80 / -T4 / -v2c
                    if f.attached and f.takes_value and tok.startswith(n) and len(tok) > len(n) and len(n) == 2:
                        flag, name, eq, val = f, n, "=", tok[len(n):]
                        break
            if flag is None and prog.bundles and re.fullmatch(r"-[A-Za-z0-9]{2,8}", tok) and all(
                    (f := prog.flags.get("-" + c)) is not None and not f.takes_value for c in tok[1:]):
                for c in tok[1:]:
                    once("-" + c, prog.flags["-" + c])
                out.argv.append(tok)
                i += 1
                continue
            if flag is None:
                raise ArgError(f"option {name!r} is not allowed for {prog.name}. "
                               f"Allowed: {_allowed_list(prog)}")
            once(name, flag)
            if not flag.takes_value:
                if eq:
                    raise ArgError(f"{name} takes no value")
                if tok not in prog.prepend:       # already there (nmap -n)
                    out.argv.append(tok)
                i += 1
                continue
            if not eq:
                if prog.joined_values:
                    raise ArgError(f"{prog.name} reads only {name}=<value> as one argument "
                                   f"(a separate value would be read as the host)")
                if i + 1 >= len(args):
                    raise ArgError(f"{name} needs a value ({flag.help})")
                val = args[i + 1]
                _value(flag, name, val, out)
                out.argv += [name, val]
                i += 2
                continue
            _value(flag, name, val, out)
            out.argv.append(tok)              # exactly as given: -p80, --opt=value
            i += 1
            continue
        if pos >= prog.max_positional:
            raise ArgError(f"too many arguments for {prog.name}: {tok!r}")
        _positional(prog, tok, pos, out)
        out.argv.append(tok)
        pos += 1
        i += 1
    if pos < prog.min_positional:
        raise ArgError(f"{prog.name} needs a target. Example: {prog.examples[0] if prog.examples else ''}")
    if prog.name == "ldapsearch" and "-x" not in out.argv:
        raise ArgError("ldapsearch must use -x (anonymous simple bind)")
    if prog.target_last and (not args or args[-1].startswith("-")):
        raise ArgError(f"{prog.name} scans its last argument, so the target must come last. "
                       f"Example: {prog.examples[0]}")
    if prog.name == "netexec" and "--shares" in out.argv:
        out.argv.append("--no-write-check")    # otherwise netexec writes a test file to every writable share
    if prog.needs_target and not out.targets:
        raise ArgError(f"no target in the command. Example: {prog.examples[0] if prog.examples else ''}")
    return out
