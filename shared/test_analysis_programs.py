#!/usr/bin/env python3
"""test_analysis_programs.py — the argument rules for file-analysis programs
(shared/analysis_programs.py).

    python3 shared/test_analysis_programs.py

No root, no sandbox, no SDK: the rules are pure text-in, text-out. What
matters, and what each section pins down:
  * a normal analysis command is accepted and its file names are rewritten
    to their path inside the sandbox;
  * every option that writes, captures, lists the host or runs a script is
    refused BY NAME — checked on the rule table itself, so a future edit
    that adds one fails here;
  * a file option can only name a file attached to THIS run;
  * there is no shell, so pipes, redirects and `;` are refused as arguments.
"""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import analysis_programs as ap  # noqa: E402

PASS = FAIL = 0


def check(label, got, want):
    global PASS, FAIL
    if got == want:
        PASS += 1; print(f"  [ OK ] {label}")
    else:
        FAIL += 1; print(f"  [FAIL] {label}\n         got  {got!r}\n         want {want!r}")


def section(t): print(f"\n=== {t} ===")


ATT = {"capture.pcap", "second.pcap", "notes.txt"}


def ok(cmd, attached=ATT, allowed=None, derived=frozenset()):
    try:
        return ap.parse_command(cmd, attached, allowed=allowed, derived=derived)
    except ap.ArgError as e:
        return f"REFUSED: {e}"


def refused(cmd, attached=ATT, allowed=None, mention=None):
    """True if refused (and the message mentions `mention`, when given)."""
    try:
        ap.parse_command(cmd, attached, allowed=allowed)
        return False
    except ap.ArgError as e:
        return mention is None or mention in str(e)


# ---------------------------------------------------------------------------
section("tshark: what is accepted")
p = ok("tshark -r capture.pcap -q -z io,phs")
check("a protocol-hierarchy command is accepted", p.argv, ["tshark", "-n", "-r", "/in/capture.pcap", "-q", "-z", "io,phs"])
check("...name resolution is switched off for every run", p.argv[1], "-n")
check("...and the file used is recorded", p.files, ["capture.pcap"])
check("the sandbox path is accepted too",
      ok("tshark -r /in/capture.pcap -c 5").argv[-4:], ["-r", "/in/capture.pcap", "-c", "5"])
check("a long option with =", ok("tshark --read-file=capture.pcap -c 1").argv[2:4], ["--read-file", "/in/capture.pcap"])
check("clustered short options: -qV", ok("tshark -r capture.pcap -qV").argv[-2:], ["-q", "-V"])
check("an attached value: -Tfields", ok("tshark -r capture.pcap -Tfields -e ip.src").argv[-4:], ["-T", "fields", "-e", "ip.src"])
check("an attached value: -Eheader=y", "header=y" in ok("tshark -r capture.pcap -T fields -e ip.src -Eheader=y").argv, True)
check("an attached count: -c10", ok("tshark -r capture.pcap -c10").argv[-2:], ["-c", "10"])
check("repeated -e is fine",
      ok("tshark -r capture.pcap -T fields -e ip.src -e ip.dst -e tcp.port").argv.count("-e"), 3)
check("a quoted display filter stays ONE argument",
      ok("tshark -r capture.pcap -Y 'http.request.method == \"POST\"'").argv[-1], 'http.request.method == "POST"')
check("a filter containing | and ; is just a string, not a shell",
      ok("tshark -r capture.pcap -Y 'ip.src==1.1.1.1 || tcp.port==80; x'").argv[-1],
      "ip.src==1.1.1.1 || tcp.port==80; x")
check("follow-stream statistics", ok("tshark -r capture.pcap -q -z follow,tcp,ascii,3").argv[-1], "follow,tcp,ascii,3")
check("credentials tap", isinstance(ok("tshark -r capture.pcap -q -z credentials"), ap.Parsed), True)
check("a preference override", isinstance(ok("tshark -r capture.pcap -o tcp.desegment_tcp_streams:TRUE"), ap.Parsed), True)
check("decode-as", isinstance(ok("tshark -r capture.pcap -d tcp.port==8888,http"), ap.Parsed), True)

# ---------------------------------------------------------------------------
section("tshark: options that must NEVER be accepted (by name)")
for flag, why in (("-w out.pcap", "writes a capture file"),
                  ("-i eth0", "captures live"),
                  ("--interface eth0", "captures live (long form)"),
                  ("-D", "lists the host's interfaces"),
                  ("-X lua_script:evil.lua", "runs a script"),
                  ("-F pcap", "chooses an output file type"),
                  ("-G", "dumps the protocol glossary"),
                  ("-C myprofile", "loads a configuration profile"),
                  ("-W n", "writes extra capture-file data"),
                  ("-f 'port 80'", "capture filter (live capture)"),
                  ("-b files:3", "ring-buffer capture output"),
                  ("-a duration:5", "capture autostop"),
                  ("-H hosts.txt", "reads a hosts file"),
                  ("-U tap", "PDU export mode"),
                  ("--export-objects http,/tmp/x", "writes extracted files"),
                  ("--export-tls-session-keys k.log", "writes a key file"),
                  ("--capture-comment hi", "writes a comment"),
                  ("-g", "group-readable output"),
                  ("-I", "monitor mode"),
                  ("-B 4", "capture buffer"),
                  ("-p", "capture promiscuity"),
                  ("-s 100", "snapshot length (capture)"),
                  ("-L", "lists link types"),
                  ("--list-interfaces", "lists interfaces (long form)"),
                  ("-O", "needs a value, not a free-standing flag")):
    cmd = f"tshark -r capture.pcap {flag}"
    check(f"{flag.split()[0]} refused ({why})", refused(cmd), True)
check("the refusal names the option and lists what IS allowed",
      refused("tshark -r capture.pcap -w x", mention="does not allow '-w'") and
      refused("tshark -r capture.pcap -w x", mention="--display-filter"), True)

danger = {"-w", "-i", "--interface", "-D", "-X", "-F", "-G", "-C", "-W", "-f", "-b", "-a", "-H", "-U",
          "--export-objects", "--export-tls-session-keys", "--capture-comment", "-g", "-I", "-B", "-p", "-s", "-L",
          "--list-interfaces", "-y", "--linktype", "--global-profile", "-K", "-S", "-N"}
check("the rule table itself contains none of the dangerous options",
      sorted(danger & set(ap.TSHARK.flags)), [])

# ---------------------------------------------------------------------------
section("tshark: it can only ever read an attached file")
check("-r is required (a bare tshark would start a LIVE capture)", refused("tshark -q -z io,phs", mention="-r"), True)
check("-r of a file that is not attached", refused("tshark -r other.pcap", mention="not a file attached"), True)
check("-r of an absolute host path", refused("tshark -r /etc/shadow", mention="not a file attached"), True)
check("-r with a traversal", refused("tshark -r ../../etc/passwd"), True)
check("-r of the sandbox directory itself", refused("tshark -r /in"), True)
check("-r of another path under /in", refused("tshark -r /in/../etc/passwd"), True)
check("-r - (standard input)", refused("tshark -r -"), True)
check("-r given twice", refused("tshark -r capture.pcap -r second.pcap", mention="only once"), True)
check("no files attached at all", refused("tshark -r capture.pcap", attached=set(), mention="no files are attached"), True)
check("the sandbox path of a file that is NOT attached", refused("tshark -r /in/other.pcap"), True)

# ---------------------------------------------------------------------------
section("there is no shell")
check("a pipe", refused("tshark -r capture.pcap | head", mention="no shell"), True)
check("a redirect", refused("tshark -r capture.pcap > out.txt", mention="no shell"), True)
check("a second command", refused("tshark -r capture.pcap ; id", mention="no shell"), True)
check("a trailing semicolon glued to the file name", refused("tshark -r capture.pcap;"), True)
check("command substitution", refused("tshark -r $(id)"), True)
check("a bare extra argument", refused("tshark -r capture.pcap extra"), True)
check("after --, arguments are still refused", refused("tshark -r capture.pcap -- extra"), True)
check("unbalanced quotes", refused("tshark -r capture.pcap -Y 'oops", mention="quotes"), True)
check("an empty command", refused(""), True)
check("a non-string command", refused(None), True)
check("a newline inside a value", refused("tshark -r capture.pcap -Y 'a\nb'"), True)
check("a very long command", refused("tshark -r capture.pcap -Y " + "a" * 5000), True)

# ---------------------------------------------------------------------------
section("tshark: values are checked")
check("-T with an unlisted format (postscript)", refused("tshark -r capture.pcap -T ps", mention="must be one of"), True)
check("-T fields is accepted", isinstance(ok("tshark -r capture.pcap -T fields -e ip.src"), ap.Parsed), True)
check("-c needs a whole number", refused("tshark -r capture.pcap -c ten", mention="whole number"), True)
check("-c negative", refused("tshark -r capture.pcap -c -5"), True)
check("-c given twice", refused("tshark -r capture.pcap -c 1 -c 2", mention="only once"), True)
check("-E with an unknown option", refused("tshark -r capture.pcap -T fields -e a -E evil=1"), True)
check("-t with a bad format", refused("tshark -r capture.pcap -t bogus"), True)
check("-o without a PREF:VALUE shape", refused("tshark -r capture.pcap -o nonsense"), True)
check("a value flag at the end with no value", refused("tshark -r capture.pcap -z", mention="needs a value"), True)
check("a long flag at the end with no value", refused("tshark --read-file", mention="needs a value"), True)
check("a no-value long flag given a value", refused("tshark -r capture.pcap --disable-all-protocols=x"), True)
check("--hexdump with a bad option", refused("tshark -r capture.pcap -x --hexdump bogus"), True)

# ---------------------------------------------------------------------------
section("which program")
check("the program name must be listed", refused("nmap -sV 10.0.0.1", mention="not a program this agent may run"), True)
check("a path is not a program name", refused("/usr/bin/tshark -r capture.pcap"), True)
check("a program the agent was not given",
      refused("capinfos capture.pcap", allowed={"tshark"}, mention="not a program this agent may run"), True)
check("an agent given both may use either",
      isinstance(ok("capinfos capture.pcap", allowed={"tshark", "capinfos"}), ap.Parsed), True)
check("an unknown name in `allowed` grants nothing",
      refused("bash -c id", allowed={"bash"}), True)

# ---------------------------------------------------------------------------
section("capinfos")
p = ok("capinfos capture.pcap")
check("a plain summary command", p.argv, ["capinfos", "/in/capture.pcap"])
check("options before the file", ok("capinfos -c -u -H capture.pcap").argv, ["capinfos", "-c", "-u", "-H", "/in/capture.pcap"])
check("several attached files", ok("capinfos capture.pcap second.pcap").files, ["capture.pcap", "second.pcap"])
check("a file that is not attached", refused("capinfos /etc/passwd", mention="not a file attached"), True)
check("no file at all", refused("capinfos -c", mention="needs the attached file"), True)
check("an option it does not have", refused("capinfos -w capture.pcap"), True)
check("help is not offered (it would print and exit)", refused("capinfos -h"), True)
check("capinfos takes no value flags",
      [s for s, f in ap.CAPINFOS.flags.items() if f.takes_value], [])

# ---------------------------------------------------------------------------
section("suricata: ONE option, everything else is fixed by code")
p = ok("suricata -r capture.pcap")
check("the command is built with the fixed config and log directory first",
      p.argv, ["suricata", "-c", "/cfg/suricata.yaml", "-l", "/out", "-r", "/in/capture.pcap"])
check("the attached file is recorded as read", p.files, ["capture.pcap"])
check("-r is required (a bare suricata would sniff a live interface)",
      refused("suricata", mention="needs -r"), True)
check("-r may be given once", refused("suricata -r capture.pcap -r second.pcap", mention="only once"), True)
check("-r must name an attached file", refused("suricata -r /etc/passwd", mention="not a file attached"), True)
for flag, why in (("-c /etc/suricata/suricata.yaml", "the model must not choose the config"),
                  ("--set outputs.0.fast.enabled=no", "--set can change any config key"),
                  ("-l /tmp", "the log directory is fixed"),
                  ("-S /etc/shadow", "a rules file of its choosing"),
                  ("-s x.rules", "a rules file of its choosing"),
                  ("-i eth0", "live capture"),
                  ("--af-packet", "live capture"),
                  ("--pcap", "live capture"),
                  ("-q 0", "inline mode"),
                  ("-F filter.bpf", "a BPF file"),
                  ("-k none", "checksum behaviour is set in the config"),
                  ("--runmode workers", "runmode is not the model's"),
                  ("--unix-socket", "a control socket"),
                  ("-T", "test mode"),
                  ("-D", "daemon mode"),
                  ("--pidfile /tmp/x", "a path"),
                  ("--user root", "privilege options"),
                  ("--init-errors-fatal", "not offered"),
                  ("--engine-analysis", "writes into the log directory"),
                  ("--list-keywords", "not offered"),
                  ("-v", "not offered")):
    check(f"suricata {flag.split()[0]} is refused ({why})",
          refused(f"suricata -r capture.pcap {flag}", mention="does not allow"), True)
check("a pipe is refused: there is no shell", refused("suricata -r capture.pcap | head", mention="no bare arguments"), True)
check("it takes no value flag except -r",
      [s for s, f in ap.SURICATA.flags.items() if f.takes_value], ["-r"])
check("it runs under its own sandbox profile", ap.SURICATA.profile, "suricata")
check("capinfos reports tshark as its package, suricata its own",
      (ap.CAPINFOS.package, ap.SURICATA.package), ("tshark", "suricata"))

# ---------------------------------------------------------------------------
section("john: what is accepted")
HATT = {"hashes.txt", "ntlm.txt", "ntlmv2.txt"}
check("john with format and wordlist",
      ok("john --format=NT --wordlist=/wordlists/rockyou.txt hashes.txt", attached=HATT).argv,
      ["john", "--pot=/out/john.pot", "--no-log",
       "--format=NT", "--wordlist=/wordlists/rockyou.txt", "/in/hashes.txt"])
check("john with format, wordlist and rules",
      ok("john --format=NT --wordlist=/wordlists/rockyou.txt --rules hashes.txt", attached=HATT).argv,
      ["john", "--pot=/out/john.pot", "--no-log",
       "--format=NT", "--wordlist=/wordlists/rockyou.txt", "--rules", "/in/hashes.txt"])
check("john --show",
      ok("john --show hashes.txt", attached=HATT).argv,
      ["john", "--pot=/out/john.pot", "--no-log", "--show", "/in/hashes.txt"])
check("john --list=formats",
      ok("john --list=formats hashes.txt", attached=HATT).argv,
      ["john", "--pot=/out/john.pot", "--no-log", "--list=formats", "/in/hashes.txt"])
check("john --fork=4",
      ok("john --format=NT --wordlist=/wordlists/rockyou.txt --fork=4 hashes.txt", attached=HATT).argv[-2:],
      ["--fork=4", "/in/hashes.txt"])
check("john NTLMv2 example",
      isinstance(ok("john --format=netntlmv2 --wordlist=/wordlists/rockyou.txt ntlmv2.txt", attached=HATT), ap.Parsed),
      True)
check("john --incremental (no value)",
      isinstance(ok("john --format=NT --incremental hashes.txt", attached=HATT), ap.Parsed), True)
check("john --incremental=Digits (with value)",
      ok("john --format=NT --incremental=Digits hashes.txt", attached=HATT).argv,
      ["john", "--pot=/out/john.pot", "--no-log", "--format=NT", "--incremental=Digits", "/in/hashes.txt"])
check("john --rules (no value)",
      ok("john --format=NT --wordlist=/wordlists/rockyou.txt --rules hashes.txt", attached=HATT).argv,
      ["john", "--pot=/out/john.pot", "--no-log",
       "--format=NT", "--wordlist=/wordlists/rockyou.txt", "--rules", "/in/hashes.txt"])
check("john --rules=Jumbo (with named set)",
      ok("john --format=NT --wordlist=/wordlists/rockyou.txt --rules=Jumbo hashes.txt", attached=HATT).argv,
      ["john", "--pot=/out/john.pot", "--no-log",
       "--format=NT", "--wordlist=/wordlists/rockyou.txt", "--rules=Jumbo", "/in/hashes.txt"])
check("john --list=inc-modes (hyphenated option name)",
      ok("john --list=inc-modes hashes.txt", attached=HATT).argv,
      ["john", "--pot=/out/john.pot", "--no-log", "--list=inc-modes", "/in/hashes.txt"])
check("john --mask",
      ok("john --format=NT --mask=?d?d?d?d hashes.txt", attached=HATT).argv,
      ["john", "--pot=/out/john.pot", "--no-log", "--format=NT", "--mask=?d?d?d?d", "/in/hashes.txt"])
check("john mask with / is refused",
      refused("john --format=NT --mask=?d/etc hashes.txt", attached=HATT, mention="MASK"), True)
check("john records the hash file",
      ok("john --format=NT --wordlist=/wordlists/rockyou.txt hashes.txt", attached=HATT).files,
      ["hashes.txt"])
check("john runs under cracker profile", ap.JOHN.profile, "cracker")

section("john: what is refused")
check("john without an attached file is refused",
      refused("john --format=NT --wordlist=/wordlists/rockyou.txt hashes.txt",
              attached={"other.txt"}, mention="not a file attached"), True)
check("john with a path-traversal wordlist is refused",
      refused("john --format=NT --wordlist=/wordlists/../etc/shadow hashes.txt",
              attached=HATT, mention="wordlist path"), True)
check("john with an off-path wordlist is refused",
      refused("john --format=NT --wordlist=/etc/shadow hashes.txt",
              attached=HATT, mention="wordlist path"), True)
check("john with a bad format is refused",
      refused("john --format=N T hashes.txt", attached=HATT), True)
check("john with a pipe is refused (| treated as an unrecognised positional file)",
      refused("john --format=NT hashes.txt | tee out", attached=HATT, mention="not a file attached"), True)
check("john with --no-log is refused (it is in prepend, not a user flag)",
      refused("john --no-log --format=NT hashes.txt", attached=HATT, mention="does not allow"), True)
check("john with --pot is refused (prepend handles it)",
      refused("john --pot=/tmp/x --format=NT hashes.txt", attached=HATT, mention="does not allow"), True)
check("john without a positional file is refused",
      refused("john --format=NT --wordlist=/wordlists/rockyou.txt", attached=HATT,
              mention="needs the attached"), True)

section("hashcat: what is accepted")
check("hashcat dictionary attack",
      ok("hashcat -m 1000 -a 0 --wordlist=/wordlists/rockyou.txt hashes.txt", attached=HATT).argv[:6],
      ["hashcat", "--potfile-path=/out/hashcat.pot", "--outfile=/out/cracked.txt",
       "--outfile-format=1,2", "--force", "-m"])
check("hashcat records the hash file",
      ok("hashcat -m 1000 -a 0 --wordlist=/wordlists/rockyou.txt hashes.txt", attached=HATT).files,
      ["hashes.txt"])
check("hashcat with rules file",
      isinstance(ok("hashcat -m 1000 -a 0 --wordlist=/wordlists/rockyou.txt "
                    "-r /wordlists/hashcat-rules/best66.rule hashes.txt", attached=HATT), ap.Parsed), True)
check("hashcat mask attack",
      isinstance(ok("hashcat -m 1000 -a 3 --mask=?u?l?l?l?d?d hashes.txt", attached=HATT), ap.Parsed), True)
check("hashcat NTLMv2 mode",
      isinstance(ok("hashcat -m 5600 -a 0 --wordlist=/wordlists/rockyou.txt ntlmv2.txt", attached=HATT), ap.Parsed), True)
check("hashcat Kerberoast mode",
      isinstance(ok("hashcat -m 13100 -a 0 --wordlist=/wordlists/rockyou.txt hashes.txt", attached=HATT), ap.Parsed), True)
check("hashcat runs under cracker profile", ap.HASHCAT.profile, "cracker")
check("hashcat mask attack with custom charset",
      isinstance(ok("hashcat -m 1000 -a 3 -1=?l?u --mask=?1?1?d?d hashes.txt", attached=HATT), ap.Parsed), True)
check("hashcat custom charset long form",
      isinstance(ok("hashcat -m 1000 -a 3 --custom-charset1=?l?u --mask=?1?1?d?d hashes.txt", attached=HATT), ap.Parsed), True)
check("hashcat mask with / is refused",
      refused("hashcat -m 1000 -a 3 --mask=?d/etc hashes.txt", attached=HATT, mention="MASK"), True)
check("hashcat custom charset with / is refused",
      refused("hashcat -m 1000 -a 3 -1=?l/etc --mask=?1?1 hashes.txt", attached=HATT, mention="CHARS"), True)

section("hashcat: what is refused")
check("hashcat with attack mode 1 (combinator) is refused",
      refused("hashcat -m 1000 -a 1 hashes.txt", attached=HATT, mention="must be one of"), True)
check("hashcat with attack mode 6 (hybrid) is refused",
      refused("hashcat -m 1000 -a 6 hashes.txt", attached=HATT, mention="must be one of"), True)
check("hashcat with a traversal wordlist is refused",
      refused("hashcat -m 1000 -a 0 --wordlist=/wordlists/../etc/shadow hashes.txt",
              attached=HATT, mention="wordlist path"), True)
check("hashcat with an arbitrary rules path is refused",
      refused("hashcat -m 1000 -a 0 --wordlist=/wordlists/rockyou.txt "
              "-r /tmp/evil.rule hashes.txt",
              attached=HATT, mention="wordlist path"), True)
check("hashcat with a pipe is refused (| treated as an unrecognised positional file)",
      refused("hashcat -m 1000 -a 0 hashes.txt | tee out", attached=HATT, mention="not a file attached"), True)
check("hashcat --potfile-path is refused (prepend handles it)",
      refused("hashcat -m 1000 -a 0 --potfile-path=/tmp/x hashes.txt", attached=HATT, mention="does not allow"), True)

section("wordlist kind: boundary checks")
check("a path under /wordlists/ is accepted",
      refused("john --format=NT --wordlist=/wordlists/subdir/list.txt hashes.txt", attached=HATT), False)
check("a path with .. is refused",
      refused("john --format=NT --wordlist=/wordlists/../etc/passwd hashes.txt",
              attached=HATT, mention="wordlist path"), True)
check("an absolute path not under /wordlists/ is refused",
      refused("john --format=NT --wordlist=/etc/passwd hashes.txt",
              attached=HATT, mention="wordlist path"), True)
check("a relative wordlist path is refused",
      refused("john --format=NT --wordlist=rockyou.txt hashes.txt",
              attached=HATT, mention="wordlist path"), True)

# ---------------------------------------------------------------------------
section("what the builder and the model see")
off = {o["name"]: o for o in ap.offered()}
check("all five programs are offered", sorted(off), ["capinfos", "hashcat", "john", "suricata", "tshark"])
check("each offering names the package to install",
      {n: o["package"] for n, o in off.items()},
      {"capinfos": "tshark", "suricata": "suricata", "tshark": "tshark",
       "john": "john", "hashcat": "hashcat"})
check("each offering says whether it is installed", all(isinstance(o["installed"], bool) for o in off.values()), True)
text = ap.tool_description({"tshark"})
check("the tool description names the program and shows an example",
      "tshark" in text and "tshark -r capture.pcap -q -z io,phs" in text, True)
check("...and does not mention a program the agent was not given", "capinfos" in text, False)
check("...and says there is no shell", "no shell" in text.lower(), True)
text_crack = ap.tool_description({"john", "hashcat"})
check("the cracker description mentions both tools", "john" in text_crack and "hashcat" in text_crack, True)
# ---------------------------------------------------------------------------
section("hash files made by extract_hashes, and what needs no file")
D = {"hashes-dump-nt.txt"}
check("a derived hash file maps into the output folder, not /in",
      ok("john --format=NT hashes-dump-nt.txt", attached=HATT, derived=D).argv[-1],
      "/out/hashes/hashes-dump-nt.txt")
check("...also when named by its sandbox path",
      ok("john --format=NT /out/hashes/hashes-dump-nt.txt", attached=HATT, derived=D).argv[-1],
      "/out/hashes/hashes-dump-nt.txt")
check("...and is counted as a file the command reads",
      ok("john --format=NT hashes-dump-nt.txt", attached=HATT, derived=D).files, ["hashes-dump-nt.txt"])
check("a name that is neither attached nor derived is refused",
      refused("john --format=NT hashes-other-nt.txt", attached=HATT, mention="not a file attached"), True)
check("another /out path is not a way in",
      refused("john --format=NT /out/john.pot", attached=HATT, mention="not a file attached"), True)
check("john --list=formats needs no hash file",
      ok("john --list=formats", attached=HATT).argv, ["john", "--pot=/out/john.pot", "--no-log", "--list=formats"])
check("john's valued options stay joined (--format NT is refused by john itself)",
      ok("john --format NT --wordlist /wordlists/rockyou.txt hashes.txt", attached=HATT).argv[3:5],
      ["--format=NT", "--wordlist=/wordlists/rockyou.txt"])
check("...but a plain john still does",
      refused("john --format=NT", attached=HATT, mention="needs the attached file"), True)
check("hashcat accepts --username (user:hash lines)",
      "--username" in ok("hashcat -m 1000 -a 0 --wordlist=/wordlists/rockyou.txt --username hashes.txt",
                         attached=HATT).argv, True)
check("hashcat's outfile keeps the hash with the password (1,2)",
      "--outfile-format=1,2" in ap.HASHCAT.prepend, True)

section("where a wordlist path really points")
check("the main list directory", ap.wordlist_host_path("/wordlists/rockyou.txt"),
      "/usr/share/wordlists/rockyou.txt")
check("hashcat rules resolve to hashcat's own directory, not inside the lists",
      ap.wordlist_host_path("/wordlists/hashcat-rules/best66.rule"), "/usr/share/hashcat/rules/best66.rule")
check("operator lists under custom/", ap.wordlist_host_path("/wordlists/custom/site.txt"),
      "/opt/wordlists/site.txt")
check("anything else is not under a mount", ap.wordlist_host_path("/etc/passwd"), None)
_wl = Path(tempfile.mkdtemp(prefix="agenti-wl-"))
(_wl / "lists").mkdir(); (_wl / "rules").mkdir()
(_wl / "lists" / "small.txt").write_text("a\n")
(_wl / "lists" / "big.txt.gz").write_bytes(b"")
(_wl / "rules" / "best66.rule").write_text(":\n")
_saved = ap.WORDLIST_MOUNTS
ap.WORDLIST_MOUNTS = ((str(_wl / "lists"), "/wordlists"), (str(_wl / "rules"), "/wordlists/hashcat-rules"))
try:
    check("an existing wordlist and rules file pass",
          ap.missing_wordlists(["hashcat", "-r", "/wordlists/hashcat-rules/best66.rule", "/wordlists/small.txt"]), None)
    msg = ap.missing_wordlists(["hashcat", "-r", "/wordlists/hashcat-rules/best64.rule"]) or ""
    check("a missing rules file is named, with the rules that do exist",
          "best64.rule does not exist" in msg and "best66.rule" in msg, True)
    msg = ap.missing_wordlists(["john", "--wordlist=/wordlists/big.txt"]) or ""
    check("a list that is only there gzipped says how to unpack it",
          "gunzip -k" in msg and "big.txt.gz" in msg, True)
    check("the wordlist binds list only directories that exist, parent first",
          [c for _, c in ap.wordlist_binds()], ["/wordlists", "/wordlists/hashcat-rules"])
finally:
    ap.WORDLIST_MOUNTS = _saved

section("audit run 1: F23 (option smuggled in a value) and F24 (tshark -o runs a program)")
for cmd in ("hashcat -m 1000 -a 3 --mask=--outfile=planted.txt hashes.txt",
            "hashcat -m 1000 -a 3 --mask --version hashes.txt",
            "hashcat -m 1000 -a 3 -1 --stdout --mask=?1 hashes.txt",
            "tshark -r capture.pcap -o snort.binary:/usr/bin/bash",
            "tshark -r capture.pcap -o snort.alerts_source:from-running-snort",
            "tshark -r capture.pcap -o snort.config:/usr/bin/x",
            "tshark -r capture.pcap -o tls.keylog_file:/etc/shadow"):
    check(f"refused: {cmd}", str(ok(cmd, attached={"capture.pcap", "hashes.txt"})).startswith("REFUSED"), True)
check("an allowed preference still works",
      ok("tshark -r capture.pcap -o tcp.desegment_tcp_streams:TRUE").argv[-2:],
      ["-o", "tcp.desegment_tcp_streams:TRUE"])
check("the -o refusal names the preferences that are allowed",
      "tcp.desegment_tcp_streams" in str(ok("tshark -r capture.pcap -o snort.binary:/bin/sh")), True)

check("every example in the rules is itself accepted",
      all(isinstance(ok(e, attached={"capture.pcap", "hashes.txt", "ntlm.txt",
                                     "ntlmv2.txt", "kerberoast.txt", "hashes-capture-nt.txt"}), ap.Parsed)
          for prog in ap.PROGRAMS.values() for e in prog.examples), True)

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
