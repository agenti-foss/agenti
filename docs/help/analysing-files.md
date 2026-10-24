# Analysing a file

*For anyone who launches a file-analysis agent such as the Pcap analyser.*

## The short version

- A **file-analysis agent** reads a file you give it and reports what it
  found. The first one is a **packet-capture (pcap) analyser**, built on
  Wireshark's command-line engine (`tshark`), with Suricata available too.
- **Attach the file, then run it.** On **Launch**, pick the agent, choose or
  drop the file (up to 100 MB), pick a model and press **Run**. There is no
  target to enter: the file is the input.
- It never touches the network. Every program runs in a **sandbox** with no
  network, no access to the rest of the server, hard limits on time, memory and
  output, and a **syscall filter** that removes the kernel features a file
  parser has no use for. A capture that is crafted to attack its analyser can
  only hurt itself.
- The report names the file, who attached it and its **SHA-256**, lists every
  command the agent ran, and keeps each command's full output.

## Giving it a file

| Where | How |
|---|---|
| **Launch** | Pick the agent, then **Choose files** or drop the file. The Run button refuses until at least one file is attached. |
| **While it runs** | The **Attach** paperclip on the agent page. The agent sees the file after the step it is on. |
| **From a terminal** | `sudo agenti pcap-analyser attach capture.pcap`, then `sudo agenti pcap-analyser start --model sonnet` |

You can attach several files. In a **team**, one file goes to every member.

## What the agent can do

It can list the attached files, and run **`capinfos`** (size, duration, time
range, file hashes), **`tshark`** (decode packets, print chosen fields,
follow a TCP stream, show conversations and statistics) and **`suricata`** (an
intrusion-detection engine: it flags suspicious traffic and decodes protocols)
on them. An admin chooses which of these a given agent gets. It reads the
output back a piece at a time, so a huge capture doesn't flood it.

### About Suricata and its rules

Suricata is only as good as its **rules**. This server uses, in this order:

1. The set written by **`suricata-update`** (Emerging Threats Open and others),
   if an admin has run it. These are real threat signatures.
2. Otherwise only the **event rules that ship with the Suricata package**.
   These flag protocol oddities (a malformed SMB request, a bad ICMP code).
   They do **not** recognise exploits or malware.

When only the package rules are present, the agent is told to say so, because
an empty alert list then means nothing. To install the real signatures, an admin
runs this once on the server (it downloads from the internet, so the website
never does it for you):

```
sudo suricata-update
```

Re-run it now and then to refresh them. The agent only ever reads the rules; it
can't change them, the configuration, or where Suricata writes.

It **cannot**: capture live traffic, write or export files, run a script,
open any file you didn't attach, use a shell (no pipes or redirects), or
contact anything the capture mentions. A command that asks for any of those is
refused with the reason, and the refusal is listed in the report.

## What it reports about passwords

Whether a password's **value** appears in the report depends on the agent's
instructions, which an admin writes. The Pcap analyser's instructions ask for
credentials, so it reports where each was found (frame, protocol, account) and
the value. An agent without that instruction refers to a credential by location
only.

**Hashes are not passwords.** If a capture holds a password hash (an NTLM or
LM hash in a Windows credential dump, for example), the agent reports the
hash, the account and the frame. Turning a hash back into a password means
cracking it, which these agents don't do. The **Hash cracker** does: use
**Send output** to hand it the analyser's report and the output that holds the
hashes.

## The Hash cracker

The hashes usually arrive mixed into other text: a tshark dump, a report, a
hashdump with noise around it. The cracker first runs **extract_hashes**, which
picks them out with fixed patterns (Windows pwdump NT and LM, NetNTLMv1/v2,
Kerberoast, AS-REP, and Unix md5/sha256/sha512crypt and bcrypt). It writes one clean
file per format. Every line is rebuilt from the pattern, never copied from your
file. It also reads a hex dump of a frame (tshark's `-x` view), where each record is cut
across rows. A record with a field of the wrong length (usually a copying slip) is listed as
not extracted, never dropped in silence. The report lists each file with its SHA-256. Then it runs `john`
or `hashcat` against rockyou and other wordlists, in the same no-network
sandbox.

- **LM hashes go first, with john.** Old Windows dumps carry them, and they
  crack in seconds. hashcat's LM mode does not work on this server's CPU, so
  the cracker uses john for LM.
- A wordlist or rules file that isn't there is refused before anything runs,
  with the list of what is. If only `rockyou.txt.gz` exists, an admin unpacks it
  once with `sudo gunzip -k /usr/share/wordlists/rockyou.txt.gz`. Installing
  the advanced agents package does this too.
- hashcat finishing with **Exhausted** means it tried every candidate and
  found nothing new. That is a normal result, not an error.

## Why there is no engagement or target

A network agent is bounded by what the organisation authorised it to touch. A
file-analysis agent touches nothing: it only reads a file an operator chose to
give it. So it needs no target, no engagement and no approval to start. The
record of what it analysed is the file's name, its SHA-256 and who attached it,
in every report.

## Messages you may see

| Message | What it means |
|---|---|
| *Attach at least one file for this agent to analyse.* | Add a file before pressing Run. |
| *'x' has no file to analyse: none is waiting for this run.* | Same, from a terminal: `agenti <agent> attach <file>` first. |
| *takes no target (-t)* | This kind of agent has no target; start it without `-t`. |
| *DENIED: … does not allow '-w' here* | The agent asked for an option it may not use. The message lists the allowed ones; the agent usually corrects itself. |
| *DENIED: … is not a file attached to this run* | It named a file you didn't attach. |
| *the sandbox is not available on this host* | `bubblewrap` or `libseccomp2` is missing, or the host refuses unprivileged user namespaces; an admin needs to fix the server. |
| *stopped: exceeded the … time limit* | The program ran too long and was stopped. The agent sees this and can narrow its filter. |
| *DENIED: /wordlists/… does not exist on this host* | The cracker named a wordlist or rules file that isn't installed. The message lists what is there. |
| *No hashes in a recognised format were found* | extract_hashes found nothing it knows. Attach a clean hash file (one hash per line) instead. |

For an admin building one, see **Building your own agent**.
