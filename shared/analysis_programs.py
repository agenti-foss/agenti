"""
analysis_programs.py — the programs a FILE-ANALYSIS agent may run, and the
exact arguments each one accepts.

A recon agent is allowed a program NAME and the validator checks the target.
That is not enough here. tshark alone has options that run code (-X
lua_script:), write files (-w), sniff the network (-i) and enumerate the host
(-D); a program name on a list says nothing about those. So for each program
this module lists the options it MAY be given — every other option is
refused — and what each option's value must be.

WHAT THE RULES GUARANTEE (shared/test_analysis_programs.py pins each)
  * Only listed options are accepted; anything else is refused by name, with
    the list of what is allowed, so the model can correct itself in one turn.
  * Every option that names a file must name a file ATTACHED TO THIS RUN
    (or /in/<that name>); it is rewritten to its path inside the sandbox
    (sandbox.IN_DIR). Nothing else on the host can be named.
  * tshark must be given -r, and nothing here can write a file, capture, list
    interfaces or load a script. A tshark with no -r would start a live
    capture on the host's interface.
  * There is no shell: the command is split once (shlex) and the pieces are
    passed as an argument list. A pipe, redirect or `;` is just an unexpected
    argument and is refused as one.

This is defence in depth, not the boundary. The boundary is shared/sandbox.py
(no network, no vault, read-only input, hard limits); these rules narrow what
the agent can ASK for, so a mistake or a crafted instruction hits a clear
refusal instead of reaching the sandbox at all.

New programs are added HERE, by a developer, with their rules reviewed — never
from a form. Programs that run code they are handed (interpreters, scripting
engines) do not belong in this file.
"""
from __future__ import annotations

import re
import shlex
import shutil
from dataclasses import dataclass, field

IN_DIR = "/in"            # where an attached file appears inside the sandbox
MAX_COMMAND_CHARS = 4000
MAX_VALUE_CHARS = 2000

__all__ = ["ArgError", "Flag", "Program", "Parsed", "PROGRAMS", "parse_command",
           "names", "offered", "tool_description", "binary_path", "IN_DIR",
           "WORDLISTS_CONTAINER", "wordlist_binds", "wordlist_host_path", "missing_wordlists"]

# Where wordlists appear INSIDE the cracker sandbox. The model names them by
# their full container path, e.g. /wordlists/rockyou.txt. Every mount below is
# read-only; the sandbox (sandbox._bind_args) handles the ones nested inside
# /wordlists. Host paths are checked at dispatch time, not import time.
WORDLISTS_CONTAINER = "/wordlists"
WORDLIST_MOUNTS = (
    ("/usr/share/wordlists", WORDLISTS_CONTAINER),                # Kali's lists (rockyou.txt)
    ("/opt/wordlists", f"{WORDLISTS_CONTAINER}/custom"),         # operator-supplied lists
    ("/usr/share/hashcat/rules", f"{WORDLISTS_CONTAINER}/hashcat-rules"),
    ("/usr/share/john", f"{WORDLISTS_CONTAINER}/john"),          # john's own word/rule files
)
HASHCAT_RULES_CONTAINER = f"{WORDLISTS_CONTAINER}/hashcat-rules"

# Hash files made by the extract_hashes tool (hash_extract.py) live in the
# run's output folder, under this directory inside the sandbox.
DERIVED_HASHES_CONTAINER = "/out/hashes"


def wordlist_binds() -> list[tuple[str, str]]:
    """(host, container) for every wordlist directory present on this host.
    The first (/usr/share/wordlists) is the parent; the rest sit inside it."""
    from pathlib import Path
    return [(h, c) for h, c in WORDLIST_MOUNTS if Path(h).is_dir()]


def wordlist_host_path(container: str) -> str | None:
    """The host file a container wordlist path points at, or None if it is
    not under any mount. Longest mount first, so a rules path is not read as
    a file in the main list directory."""
    for host, cont in sorted(WORDLIST_MOUNTS, key=lambda m: -len(m[1])):
        if container == cont or container.startswith(cont + "/"):
            return host + container[len(cont):]
    return None


def missing_wordlists(argv: list[str]) -> str | None:
    """Why a wordlist/rules path in this argv does not exist on the host, with
    what does exist — or None when every one is there. Checked before the
    sandbox runs, so the model gets a usable answer instead of a bare
    "No such file" from inside it."""
    import os
    for value in argv:
        if value.startswith("--") and "=" in value:
            value = value.split("=", 1)[1]           # john's joined --wordlist=PATH
        if not value.startswith(WORDLISTS_CONTAINER + "/"):
            continue
        host = wordlist_host_path(value)
        if host and os.path.exists(host):
            continue
        folder = os.path.dirname(value)
        hfolder = wordlist_host_path(folder) or ""
        try:
            have = sorted(os.listdir(hfolder))[:40]
        except OSError:
            have = []
        hint = ""
        if os.path.exists((host or "") + ".gz"):
            hint = (f" Only the compressed {os.path.basename(value)}.gz is on this host; an admin "
                    f"unpacks it once with: sudo gunzip -k {host}.gz (the package does this at install).")
        return (f"{value} does not exist on this host.{hint} In {folder}/: "
                + (", ".join(have) if have else "(nothing)") + ".")
    return None


class ArgError(Exception):
    """The command is refused. The message says why and what is allowed."""


@dataclass(frozen=True)
class Flag:
    """One accepted option. `kind`: none (no value), file (an attached
    file's name), int, choice (one of `choices`), text (free text, optionally
    matching `pattern`), wordlist (a path under /wordlists/ — a pre-mounted
    read-only directory; not an attached file)."""
    help: str
    kind: str = "none"
    choices: tuple[str, ...] = ()
    pattern: str = ""
    repeat: bool = True
    value_name: str = "VALUE"
    # When True the option may appear with or without a value: --rules alone OR
    # --rules=Jumbo. The kind/pattern still apply when a value IS given.
    optional_value: bool = False

    @property
    def takes_value(self) -> bool:
        return self.kind != "none" or self.optional_value


@dataclass(frozen=True)
class Program:
    name: str
    purpose: str
    flags: dict[str, Flag]              # every spelling ("-r", "--read-file") -> Flag
    required: tuple[str, ...] = ()      # at least one of these must be present
    positional: str = "none"            # "none" | "files" (attached files)
    prepend: tuple[str, ...] = ()       # always added, before the model's arguments
    examples: tuple[str, ...] = ()
    profile: str = "analysis"           # sandbox profile
    notes: str = ""
    package: str = ""                   # the apt package that provides it, if not its own name
    no_file_flags: tuple[str, ...] = ()  # options that need no file (john --list=formats)
    # Pass a long option's value as one "--opt=value" token. john's own option
    # parser rejects "--format NT" ("Option requires a parameter"), and its
    # --wordlist takes an OPTIONAL value, so "--wordlist PATH" meant "john's
    # default list, and PATH is a hash file" — every valued john command was
    # broken this way until 2026-10-16.
    joined_long_values: bool = False


def _both(table: dict[str, Flag], *spellings: str, flag: Flag) -> None:
    for s in spellings:
        table[s] = flag


# Preferences tshark may be given with -o. A list, not a pattern: some
# preferences name a program for tshark to start (the Snort dissector's
# snort.binary and snort.config) or files to read, so an open "any.name:value"
# let a crafted instruction make tshark run a program of its choosing inside the
# sandbox (audit run 1, F24). These only change how packets are decoded.
TSHARK_PREFS = (
    "tcp.desegment_tcp_streams", "tcp.analyze_sequence_numbers", "tcp.relative_sequence_numbers",
    "tcp.calculate_timestamps", "tcp.check_checksum", "tcp.try_heuristic_first", "udp.try_heuristic_first",
    "udp.check_checksum", "ip.defragment", "ip.check_checksum", "ipv6.defragment",
    "http.desegment_headers", "http.desegment_body", "http.dechunk_body", "http.decompress_body",
    "http.tcp.port", "tls.desegment_ssl_records", "tls.desegment_ssl_application_data",
    "tls.ignore_ssl_mac_failed", "dns.desegment_dns_messages", "smb.trans_reassembly",
)
_TSHARK_PREF_RE = (r"^(" + "|".join(re.escape(n) for n in TSHARK_PREFS) +
                   r"):(TRUE|FALSE|true|false|[0-9,-]{1,100})$")


def _tshark_flags() -> dict[str, Flag]:
    t: dict[str, Flag] = {}
    _both(t, "-r", "--read-file", flag=Flag(
        "the attached capture to read (required)", "file", repeat=False, value_name="FILE"))
    _both(t, "-Y", "--display-filter", flag=Flag(
        "only show packets matching this Wireshark display filter, e.g. "
        "'http.request.method == \"POST\"' or 'frame contains \"pass\"'",
        "text", value_name="FILTER", repeat=False))
    _both(t, "-R", "--read-filter", flag=Flag(
        "like -Y but applied while reading (needs -2)", "text", value_name="FILTER", repeat=False))
    t["-2"] = Flag("two-pass analysis (reassembly across the whole capture)")
    _both(t, "-T", flag=Flag(
        "output format", "choice", choices=("fields", "text", "json", "jsonraw", "ek", "pdml", "psml", "tabs"),
        value_name="FORMAT", repeat=False))
    t["-e"] = Flag("a field to print with -T fields (repeat for more), e.g. -e ip.src -e tcp.port",
                   "text", value_name="FIELD")
    t["-E"] = Flag("options for -T fields: header=y, separator=, occurrence=f|l|a, aggregator=, quote=d|s|n",
                   "text", pattern=r"^(bom|header|separator|occurrence|aggregator|quote)=.{1,40}$",
                   value_name="OPTION=VALUE")
    t["-q"] = Flag("quiet: print only statistics (use with -z)")
    t["-V"] = Flag("print the full decoded packet tree")
    t["-x"] = Flag("also print a hex and ASCII dump of each packet")
    _both(t, "-O", flag=Flag("show decoded detail only for these protocols (comma separated)",
                             "text", value_name="PROTOCOLS", repeat=False))
    t["-c"] = Flag("stop after this many packets", "int", value_name="COUNT", repeat=False)
    _both(t, "-d", flag=Flag("Decode As, e.g. tcp.port==8888,http", "text", value_name="SPEC"))
    t["-t"] = Flag("timestamp format (a, ad, adoy, d, dd, e, r, u, ud, udoy)", "text",
                   pattern=r"^(a|ad|adoy|d|dd|e|r|u|ud|udoy)?(\.[0-9]?)?$", value_name="FORMAT", repeat=False)
    t["-u"] = Flag("format of seconds: s or hms", "choice", choices=("s", "hms"),
                   value_name="s|hms", repeat=False)
    t["-z"] = Flag("a statistic or tap, e.g. io,phs  conv,tcp  endpoints,ip  follow,tcp,ascii,0  "
                   "http,tree  expert  credentials", "text", value_name="STATISTIC")
    t["-o"] = Flag("override one of these preferences: " + ", ".join(TSHARK_PREFS) +
                   ", e.g. -o tcp.desegment_tcp_streams:TRUE", "text",
                   pattern=_TSHARK_PREF_RE,
                   value_name="PREF:VALUE, where PREF is one of " + ", ".join(TSHARK_PREFS))
    _both(t, "-j", "-J", flag=Flag("restrict -T json/ek/pdml output to these protocols", "text",
                                   value_name="PROTOCOLS", repeat=False))
    t["--hexdump"] = Flag("hex dump options", "choice",
                          choices=("all", "frames", "ascii", "delimit", "noascii", "time", "notime"),
                          value_name="OPTION")
    t["--enable-protocol"] = Flag("turn on dissection of a protocol", "text", value_name="PROTO")
    t["--disable-protocol"] = Flag("turn off dissection of a protocol", "text", value_name="PROTO")
    t["--only-protocols"] = Flag("dissect only these protocols", "text", value_name="PROTOCOLS", repeat=False)
    t["--disable-all-protocols"] = Flag("turn off every dissector (pair with --enable-protocol)")
    t["--enable-heuristic"] = Flag("turn on a heuristic dissector", "text", value_name="NAME")
    t["--disable-heuristic"] = Flag("turn off a heuristic dissector", "text", value_name="NAME")
    t["--no-duplicate-keys"] = Flag("with -T json: merge duplicate keys")
    return t


TSHARK = Program(
    name="tshark",
    purpose="Wireshark's engine: decode a capture and print packets, fields, conversations "
            "and statistics. The main tool for reading a pcap.",
    flags=_tshark_flags(),
    required=("-r", "--read-file"),
    prepend=("-n",),            # no name resolution; the sandbox has no network anyway
    examples=(
        "tshark -r capture.pcap -q -z io,phs",
        "tshark -r capture.pcap -q -z conv,tcp",
        "tshark -r capture.pcap -Y 'http.request' -T fields -e frame.number -e ip.src -e http.host -e http.request.uri",
        "tshark -r capture.pcap -q -z follow,tcp,ascii,3",
        "tshark -r capture.pcap -Y 'frame contains \"password\"' -x",
        "tshark -r capture.pcap -q -z credentials",
    ),
    notes="Always give -r. -q with -z prints only the statistic. Use -Y with -T fields -e to pull "
          "exactly the columns you need, and -c to cap a first look.",
)


def _capinfos_flags() -> dict[str, Flag]:
    c: dict[str, Flag] = {}
    for f, h in (("-t", "file type"), ("-E", "encapsulation"), ("-I", "interface information"),
                 ("-F", "additional file information"), ("-H", "SHA256 and SHA1 of the file"),
                 ("-k", "capture comment"), ("-p", "packet comments"), ("-c", "number of packets"),
                 ("-s", "file size"), ("-d", "total length of all packets"), ("-l", "snapshot length"),
                 ("-u", "capture duration"), ("-a", "earliest packet time"), ("-e", "latest packet time"),
                 ("-o", "whether packets are in time order"), ("-S", "start/end times as seconds"),
                 ("-y", "average data rate (bytes/s)"), ("-i", "average data rate (bits/s)"),
                 ("-z", "average packet size"), ("-x", "average packet rate"),
                 ("-n", "number of resolved addresses"), ("-D", "number of decryption secrets"),
                 ("-L", "long report (default)"), ("-T", "table report"), ("-M", "machine-readable values"),
                 ("-R", "table header record"), ("-r", "no table header record"),
                 ("-B", "tab separated"), ("-m", "comma separated"), ("-b", "space separated"),
                 ("-N", "no quoting"), ("-q", "single quotes"), ("-Q", "double quotes"),
                 ("-A", "everything (default)")):
        c[f] = Flag(f"show {h}" if f not in ("-L", "-T", "-M", "-R", "-r", "-B", "-m", "-b", "-N", "-q", "-Q", "-A")
                    else h)
    return c


CAPINFOS = Program(
    name="capinfos",
    purpose="Summarise a capture file: packet count, duration, size, time range, file hashes.",
    flags=_capinfos_flags(),
    positional="files",
    examples=("capinfos capture.pcap", "capinfos -c -u -H capture.pcap"),
    notes="Give the attached file(s) as plain arguments.",
    package="tshark",                   # capinfos ships in the tshark package
)

# Suricata is offered ONE option: -r, the attached capture. Everything else —
# the config, the rules, where logs go, that detection runs offline — is fixed
# by code (shared/suricata_offline.py). The model is not offered -c (a config
# of its choosing), --set (any config key), -l or -S (paths), -i/--af-packet/
# --pcap-buffer-size (live capture), -F (a BPF file) or anything that makes
# Suricata listen, write elsewhere or run Lua. A mistake or a crafted
# instruction therefore meets a refusal rather than the sandbox.
SURICATA = Program(
    name="suricata",
    purpose="Run an intrusion-detection engine over a capture: signature alerts, protocol anomalies "
            "and per-protocol records (dns, http, tls, smb, ssh, flows ...).",
    flags={"-r": Flag("the attached capture to analyse (required)", "file", repeat=False, value_name="FILE")},
    required=("-r",),
    prepend=("-c", "/cfg/suricata.yaml", "-l", "/out"),
    examples=("suricata -r capture.pcap",),
    profile="suricata",
    notes="Takes only -r. You get a summary (alerts grouped by signature, event counts) and the full "
          "eve.json / fast.log saved for read_output: search eve.json with pattern '\"event_type\":\"dns\"' "
          "(or http, tls, smb, flow, alert). It can take a minute. If the summary says only the package's "
          "own rules are installed, an empty alert list means nothing — say so rather than calling the "
          "traffic clean.",
    package="suricata",
)

def _john_flags() -> dict[str, Flag]:
    j: dict[str, Flag] = {}
    j["--format"] = Flag(
        "hash format, e.g. NT (NTLM), LM, md5crypt, sha512crypt, sha256crypt, bcrypt, descrypt, "
        "mscash2, krb5tgs (Kerberoast), krb5asrep (AS-REP), zip, rar, pdf. "
        "Run 'john --list=formats' to see all.",
        "text", pattern=r"^[A-Za-z0-9_.-]{1,40}$", value_name="FORMAT", repeat=False)
    j["--wordlist"] = Flag(
        f"wordlist to use, e.g. {WORDLISTS_CONTAINER}/rockyou.txt. "
        f"All paths must start with {WORDLISTS_CONTAINER}/. "
        f"Operator-supplied lists are under {WORDLISTS_CONTAINER}/custom/.",
        "wordlist", value_name="PATH", repeat=False)
    j["--rules"] = Flag(
        "apply word-mangling rules to the wordlist. Alone uses john's built-in set; "
        "--rules=Jumbo or --rules=best66 names a specific section from john.conf. "
        "Doubles coverage with very little extra time.",
        "text", pattern=r"^[A-Za-z0-9_:.-]{1,40}$", optional_value=True,
        value_name="SET", repeat=False)
    j["--show"] = Flag(
        "show the passwords cracked so far (reads the potfile at /out/john.pot). "
        "Use after a cracking run to display results.")
    j["--list"] = Flag(
        "list what john supports, e.g. --list=formats or --list=inc-modes (no hash file needed)",
        "text", pattern=r"^[a-z][a-z-]{0,30}$", value_name="OPTION", repeat=False)
    j["--incremental"] = Flag(
        "brute-force mode, cycling every character combination. Very slow on long "
        "passwords; use only for short passwords (≤6 chars) with a tight time budget. "
        "Alone uses john's default mode; --incremental=Digits limits to digit-only.",
        "text", pattern=r"^[A-Za-z0-9_]{1,30}$", optional_value=True,
        value_name="MODE", repeat=False)
    j["--mask"] = Flag(
        "mask brute-force: ?l=lowercase, ?u=uppercase, ?d=digit, ?s=special, ?a=all printable. "
        "E.g. --mask=?d?d?d?d for 4-digit PINs.",
        "text", pattern=r"^[?A-Za-z0-9!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>` ]{1,64}$",
        value_name="MASK", repeat=False)
    j["--fork"] = Flag(
        "number of parallel processes (default 1; set to the Pi's core count to "
        "speed up wordlist attacks — e.g. --fork=4)",
        "int", value_name="N", repeat=False)
    return j


JOHN = Program(
    name="john",
    purpose="Password/hash cracker: dictionary, rules and brute-force attacks on a hash file. "
            "Supports NTLM (--format=NT), LM, NTLMv2 (--format=netntlmv2), Kerberoast tickets "
            "(--format=krb5tgs), AS-REP (--format=krb5asrep), and dozens of other formats.",
    flags=_john_flags(),
    positional="files",           # the hash file(s) as positional args, mapped to /in/
    prepend=("--pot=/out/john.pot", "--no-log"),
    examples=(
        f"john --format=NT --wordlist={WORDLISTS_CONTAINER}/rockyou.txt hashes.txt",
        f"john --format=NT --wordlist={WORDLISTS_CONTAINER}/rockyou.txt --rules hashes.txt",
        "john --format=netntlmv2 --wordlist=/wordlists/rockyou.txt ntlmv2.txt",
        "john --show hashes.txt",
    ),
    profile="cracker",
    no_file_flags=("--list",),
    joined_long_values=True,
    notes=f"Give the hash file as a positional argument (list_files to see attached files, or a "
          f"file extract_hashes made). "
          f"Use --wordlist={WORDLISTS_CONTAINER}/rockyou.txt --rules for most attacks. "
          f"--show reads /out/john.pot and displays cracked passwords. "
          f"Potfile is always /out/john.pot — run --show after a cracking attempt to see results. "
          f"Rainbow table lookups are not available in this sandbox; wordlist + rules covers most cases.",
    package="john",
)


def _hashcat_flags() -> dict[str, Flag]:
    h: dict[str, Flag] = {}
    _both(h, "-m", "--hash-type", flag=Flag(
        "hash type: 1000=NTLM, 5600=NTLMv2, 13100=Kerberoast (TGS-REP), "
        "18200=AS-REP, 500=md5crypt, 1800=sha512crypt, 3200=bcrypt, "
        "0=MD5, 100=SHA1. Run 'hashcat --help' for the full list.",
        "int", value_name="TYPE", repeat=False))
    _both(h, "-a", "--attack-mode", flag=Flag(
        "attack mode: 0=dictionary (requires --wordlist), 3=mask/brute-force (requires --mask). "
        "Other modes are not available in this sandbox.",
        "choice", choices=("0", "3"), value_name="MODE", repeat=False))
    h["--wordlist"] = Flag(
        f"wordlist for dictionary attack (-a 0), e.g. {WORDLISTS_CONTAINER}/rockyou.txt. "
        f"Path must start with {WORDLISTS_CONTAINER}/.",
        "wordlist", value_name="PATH", repeat=False)
    _both(h, "-r", "--rules-file", flag=Flag(
        f"rules file for dictionary attack, e.g. "
        f"{WORDLISTS_CONTAINER}/hashcat-rules/best66.rule (best64.rule before hashcat 7) or "
        f"{WORDLISTS_CONTAINER}/hashcat-rules/dive.rule",
        "wordlist", value_name="PATH"))
    h["--mask"] = Flag(
        "mask for brute-force attack (-a 3): ?l=lowercase, ?u=uppercase, ?d=digit, "
        "?s=special, ?a=all printable. E.g. ?u?l?l?l?d?d for 6-char passwords.",
        "text", pattern=r"^[?A-Za-z0-9!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>` ]{1,64}$",
        value_name="MASK", repeat=False)
    _CHARSET_PATTERN = r"^[?A-Za-z0-9!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>` ]{1,64}$"
    _CHARSET_HELP = (
        "custom character set {n} for use as ?{n} in a mask. "
        "E.g. -1=?l?u (mixed case), then --mask=?1?1?d?d. "
        "No file paths — literal charset strings only."
    )
    for _n in ("1", "2", "3", "4"):
        _both(h, f"-{_n}", f"--custom-charset{_n}",
              flag=Flag(_CHARSET_HELP.format(n=_n), "text",
                        pattern=_CHARSET_PATTERN, value_name="CHARS", repeat=False))
    _both(h, "-i", "--increment", flag=Flag(
        "increment mask length from --increment-min to --increment-max (mask attack only)"))
    h["--increment-min"] = Flag(
        "minimum mask length for incremental mode (default 1)",
        "int", value_name="N", repeat=False)
    h["--increment-max"] = Flag(
        "maximum mask length for incremental mode",
        "int", value_name="N", repeat=False)
    _both(h, "-O", "--optimized-kernel-enable", flag=Flag(
        "enable optimized kernels (faster but limits password length to 31 chars)"))
    _both(h, "-w", "--workload-profile", flag=Flag(
        "workload profile: 1=low, 2=default, 3=high, 4=nightmare (use 3 on the Pi)",
        "choice", choices=("1", "2", "3", "4"), value_name="PROFILE", repeat=False))
    h["--status"] = Flag("enable automatic status updates")
    h["--status-timer"] = Flag(
        "seconds between status updates (default 10)",
        "int", value_name="SECS", repeat=False)
    _both(h, "-n", "--accel-ignore-kernel", flag=Flag("skip kernel optimization warnings"))
    h["--username"] = Flag(
        "the hash file has user:hash lines (as extract_hashes writes for NT and LM); "
        "hashcat ignores the user part")
    return h


# hashcat's positional layout is: hashcat [options] hashfile [wordlist] [mask]
# The dispatcher (_analyze_cracker in tool_registry.py) handles the positional
# reconstruction: the hash file comes from the attached files (positional="files"),
# and --wordlist / --mask supply the second positional.  The --wordlist flag is
# stripped from parsed.argv and appended as a positional by the dispatcher.
HASHCAT = Program(
    name="hashcat",
    purpose="GPU/CPU hash cracker: dictionary and mask attacks. Supports NTLM (1000), NTLMv2 (5600), "
            "Kerberoast tickets (13100), AS-REP (18200), bcrypt (3200), sha512crypt (1800) and hundreds more. "
            "On this box (no GPU) CPU cracking is used; rockyou with --optimized-kernel-enable is fastest.",
    flags=_hashcat_flags(),
    positional="files",           # the hash file, mapped to /in/
    # --force: allow CPU cracking. Outfile format 1,2 = hash:plain, so a crack
    # can be matched back to its account (plain alone could not be).
    prepend=("--potfile-path=/out/hashcat.pot", "--outfile=/out/cracked.txt",
             "--outfile-format=1,2", "--force"),
    examples=(
        f"hashcat -m 1000 -a 0 --wordlist={WORDLISTS_CONTAINER}/rockyou.txt hashes.txt",
        f"hashcat -m 1000 -a 0 --wordlist={WORDLISTS_CONTAINER}/rockyou.txt "
        f"-r {WORDLISTS_CONTAINER}/hashcat-rules/best66.rule hashes.txt",
        f"hashcat -m 1000 -a 0 --wordlist={WORDLISTS_CONTAINER}/rockyou.txt --username "
        f"hashes-capture-nt.txt",
        "hashcat -m 5600 -a 0 --wordlist=/wordlists/rockyou.txt ntlmv2.txt",
        "hashcat -m 1000 -a 3 --mask=?u?l?l?l?d?d hashes.txt",
        "hashcat -m 13100 -a 0 --wordlist=/wordlists/rockyou.txt kerberoast.txt",
    ),
    profile="cracker",
    notes=f"Give the hash file as a positional arg. For dictionary attack: -a 0 --wordlist=PATH. "
          f"For mask attack: -a 3 --mask=MASK. The --wordlist flag is converted to hashcat's native "
          f"positional layout by the dispatcher. Exit 1 means the wordlist/mask was exhausted — a "
          f"normal result, not an error. Cracked hash:password lines are saved to /out/cracked.txt and "
          f"/out/hashcat.pot — use read_output to retrieve them. "
          f"Rainbow table attacks are not available in this sandbox.",
    package="hashcat",
)


PROGRAMS: dict[str, Program] = {p.name: p for p in (TSHARK, CAPINFOS, SURICATA, JOHN, HASHCAT)}


def load_plugin_programs(agent_dir) -> dict[str, "Program"]:
    """Merge extra Program definitions from an agent package.

    If `<agent_dir>/programs.py` exists, import it and read its `PROGRAMS`
    dict (or `EXTRA_PROGRAMS` for additive-only packages). Returns the merged
    dict. Safe to call unconditionally — returns the base PROGRAMS when no
    plugin file is present.

    Plugin packages may override existing entries or add new ones. They must
    not remove entries (omitted keys are kept from the base set).
    """
    from pathlib import Path
    import importlib.util
    p = Path(agent_dir) / "programs.py"
    if not p.exists():
        return dict(PROGRAMS)
    try:
        spec = importlib.util.spec_from_file_location("_agent_programs", p)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        extra = getattr(mod, "PROGRAMS", None) or getattr(mod, "EXTRA_PROGRAMS", {})
        merged = dict(PROGRAMS)
        merged.update(extra)
        return merged
    except Exception:
        return dict(PROGRAMS)


def names() -> list[str]:
    return sorted(PROGRAMS)


def binary_path(name: str) -> str | None:
    """Where the program is installed, or None. Only /usr and /bin exist
    inside the sandbox, so anything resolving elsewhere counts as missing."""
    found = shutil.which(name)
    return found if found and found.startswith(("/usr/", "/bin/")) else None


def offered() -> list[dict]:
    """What the agent builder may offer: each program, whether it is installed,
    and its purpose."""
    return [{"name": p.name, "purpose": p.purpose, "installed": bool(binary_path(p.name)),
             "package": p.package or p.name, "examples": list(p.examples)}
            for p in PROGRAMS.values()]


# ---------------------------------------------------------------------------
# the command parser
# ---------------------------------------------------------------------------
@dataclass
class Parsed:
    program: str
    argv: list[str]                     # [binary, args...] with file names mapped into the sandbox
    files: list[str] = field(default_factory=list)   # attached files this command reads


def _flag_summary(p: Program) -> str:
    seen, rows = set(), []
    for spelling, f in p.flags.items():
        if id(f) in seen:
            continue
        seen.add(id(f))
        alts = [s for s, g in p.flags.items() if g is f]
        rows.append(f"  {' / '.join(alts)}{' ' + f.value_name if f.takes_value else ''}  — {f.help}")
    return "\n".join(rows)


_WORDLIST_RE = re.compile(
    r"^/wordlists/[A-Za-z0-9][A-Za-z0-9_./-]{0,119}$"
)


def _check_value(prog: Program, spelling: str, f: Flag, value: str, attached: set[str],
                 derived: set[str] = frozenset()) -> tuple[str, str | None]:
    """(value to pass on, attached file used or None) or raise ArgError.
    `derived`: hash files extract_hashes made for this run (hash_extract.py),
    nameable like an attached file and mapped into the output folder."""
    if len(value) > MAX_VALUE_CHARS or "\x00" in value or "\n" in value or "\r" in value:
        raise ArgError(f"{spelling}: the value is too long or contains a control character.")
    if value.startswith("-"):
        # A value that looks like an option can become one: hashcat's --mask is
        # moved to a trailing positional, where '--outfile=...' would be read as
        # an option (audit run 1, F23). No value here ever needs a leading '-'.
        raise ArgError(f"{spelling}: the value must not start with '-' ({value!r}).")
    if f.kind == "file":
        name = value[len(IN_DIR) + 1:] if value.startswith(IN_DIR + "/") else value
        if name.startswith(DERIVED_HASHES_CONTAINER + "/"):
            name = name[len(DERIVED_HASHES_CONTAINER) + 1:]
        if name in derived and name not in attached:
            return f"{DERIVED_HASHES_CONTAINER}/{name}", name
        if name not in attached:
            have = ", ".join(sorted(attached | set(derived))) or "(none)"
            raise ArgError(f"{spelling} {value!r}: that is not a file attached to this run. "
                           f"Attached: {have}. Use list_files to see them.")
        return f"{IN_DIR}/{name}", name
    if f.kind == "wordlist":
        if not _WORDLIST_RE.match(value) or ".." in value:
            raise ArgError(
                f"{spelling} {value!r}: wordlist path must be under {WORDLISTS_CONTAINER}/ "
                f"with no '..' (e.g. {WORDLISTS_CONTAINER}/rockyou.txt or "
                f"{WORDLISTS_CONTAINER}/hashcat-rules/best66.rule). "
                f"Use list_files to see attached files; these are pre-mounted host wordlists.")
        return value, None
    if f.kind == "int":
        if not re.fullmatch(r"[0-9]{1,9}", value):
            raise ArgError(f"{spelling} needs a whole number, not {value!r}.")
        return value, None
    if f.kind == "choice":
        if value not in f.choices:
            raise ArgError(f"{spelling} must be one of: {', '.join(f.choices)} (not {value!r}).")
        return value, None
    if f.pattern and not re.fullmatch(f.pattern, value):
        raise ArgError(f"{spelling} {value!r}: not in the form {f.value_name}.")
    return value, None


def parse_command(command: str, attached: set[str] | list[str], *,
                  allowed: set[str] | None = None, derived: set[str] = frozenset()) -> Parsed:
    """Validate one command string and return the argument list to run in the
    sandbox. `attached` is the set of file names attached to this run;
    `allowed` the program names this agent may use (default: all). Raises
    ArgError with a message the model can act on."""
    attached = set(attached)
    if not isinstance(command, str) or not command.strip():
        raise ArgError("give a command, e.g.  tshark -r capture.pcap -q -z io,phs")
    if len(command) > MAX_COMMAND_CHARS:
        raise ArgError(f"the command is too long ({len(command)} characters; the limit is {MAX_COMMAND_CHARS}).")
    try:
        tokens = shlex.split(command)
    except ValueError as e:
        raise ArgError(f"the command could not be parsed ({e}). Check the quotes.")
    if not tokens:
        raise ArgError("give a command, e.g.  tshark -r capture.pcap -q -z io,phs")

    name = tokens[0]
    allowed = set(PROGRAMS) if allowed is None else set(allowed) & set(PROGRAMS)
    if name not in allowed:
        raise ArgError(f"'{name}' is not a program this agent may run. Allowed: "
                       f"{', '.join(sorted(allowed)) or '(none)'}. Give the program name alone "
                       f"(no path), then its options.")
    if not attached:
        raise ArgError("no files are attached to this run, so there is nothing to analyse. "
                       "Ask the operator to attach the file (the paperclip on this page).")
    prog = PROGRAMS[name]

    out: list[str] = list(prog.prepend)
    files: list[str] = []
    seen: dict[int, int] = {}
    present: set[str] = set()

    def take(spelling: str, value: str | None) -> None:
        f = prog.flags[spelling]
        if f.takes_value:
            if value is None and f.optional_value:
                # --rules or --incremental with no value: pass the flag alone
                out.append(spelling)
            else:
                checked, used = _check_value(prog, spelling, f, value, attached, derived)
                if prog.joined_long_values and spelling.startswith("--"):
                    out.append(f"{spelling}={checked}")
                else:
                    out.extend([spelling, checked])
                if used and used not in files:
                    files.append(used)
        else:
            out.append(spelling)
        seen[id(f)] = seen.get(id(f), 0) + 1
        if seen[id(f)] > 1 and not f.repeat:
            raise ArgError(f"{spelling} may be given only once.")
        present.add(spelling)

    def refuse_flag(spelling: str) -> ArgError:
        return ArgError(f"{name} does not allow '{spelling}' here. The options this agent may use:\n"
                        f"{_flag_summary(prog)}")

    i, only_positionals = 1, False
    while i < len(tokens):
        tok = tokens[i]
        i += 1
        if only_positionals or not tok.startswith("-") or tok == "-":
            if tok == "-":
                raise ArgError("reading from standard input is not available; name an attached file.")
            if prog.positional != "files":
                raise ArgError(f"{name} takes no bare arguments (got {tok!r}). Pipes, redirects and "
                               f"`;` do not exist here: there is no shell. Use the options of {name} "
                               f"itself (-Y, -c, -z ...) to filter.")
            checked, used = _check_value(prog, "file", Flag("", "file"), tok, attached, derived)
            out.append(checked)
            if used and used not in files:
                files.append(used)
            continue
        if tok == "--":
            only_positionals = True
            continue
        if tok.startswith("--"):
            spelling, eq, val = tok.partition("=")
            if spelling not in prog.flags:
                raise refuse_flag(spelling)
            f = prog.flags[spelling]
            if f.takes_value:
                if not eq:
                    if f.optional_value:
                        take(spelling, None)
                    elif i >= len(tokens):
                        raise ArgError(f"{spelling} needs a value ({f.value_name}).")
                    else:
                        val = tokens[i]; i += 1
                        take(spelling, val)
                else:
                    take(spelling, val)
            else:
                if eq:
                    raise ArgError(f"{spelling} takes no value.")
                take(spelling, None)
            continue
        # a cluster of short options: -qV, -Tfields, -Eheader=y, -c10
        j = 1
        while j < len(tok):
            spelling = "-" + tok[j]
            if spelling not in prog.flags:
                raise refuse_flag(spelling)
            f = prog.flags[spelling]
            if not f.takes_value:
                take(spelling, None)
                j += 1
                continue
            rest = tok[j + 1:]
            if rest:
                val = rest
            elif i < len(tokens):
                val = tokens[i]; i += 1
            else:
                raise ArgError(f"{spelling} needs a value ({f.value_name}).")
            take(spelling, val)
            break

    if prog.required and not any(r in present for r in prog.required):
        raise ArgError(f"{name} needs {' or '.join(prog.required)} to name the attached file to read. "
                       f"Attached: {', '.join(sorted(attached))}.")
    if prog.positional == "files" and not files and not (present & set(prog.no_file_flags)):
        raise ArgError(f"{name} needs the attached file(s) to read. Attached: {', '.join(sorted(attached))}.")
    return Parsed(program=name, argv=[name, *out], files=files)


# ---------------------------------------------------------------------------
# the text the model reads
# ---------------------------------------------------------------------------
def tool_description(program_names: list[str] | set[str]) -> str:
    """The analyze_file tool's description for an agent allowed these programs."""
    lines = ["Run ONE analysis program on a file the operator attached to this run, inside a sandbox "
             "(no network, read-only input, time and memory limits). Pass the whole command as "
             "`command`, starting with the program name and naming attached files by their plain "
             "names (see list_files). There is no shell: no pipes, redirects or `;`. The full output "
             "is saved; you get a trimmed head plus a file name to search with read_output.",
             "Programs:"]
    for n in sorted(set(program_names) & set(PROGRAMS)):
        p = PROGRAMS[n]
        lines.append(f"- {n}: {p.purpose} {p.notes}".rstrip())
        lines += [f"    e.g. {e}" for e in p.examples]
    return "\n".join(lines)
