# How Agenti is security-tested

*For anyone deciding whether to trust Agenti, and for administrators.*

## The short version

- Before its first public release, every line of Agenti's code was reviewed by
  two full, structured security audits, then attacked on a freshly installed
  machine.
- Problems are fixed **before** they are described here. Every finding so far
  was fixed before release 0.1.0 (below).
- Found something yourself? See **Reporting a problem** below.

## What is checked

The audit follows Cloudflare's open-source security-audit method
(github.com/cloudflare/security-audit-skill), run in its most thorough mode.

1. **Map.** Every way information gets into Agenti (the web pages, the command
   line, the AI's tools, attached files, the network, the installer) and every
   boundary it must not cross is listed in a checklist. Every code file is on
   that checklist; nothing is skipped.
2. **Hunt.** Separate reviewers each take a few checklist items and try to break
   them, the way an attacker would: no account, an ordinary user, an admin, a
   local user on the machine, a hostile web page or scan result trying to trick
   the AI, a booby-trapped attached file.
3. **Prove it.** A problem only counts when it is shown with a small, safe test
   in a locked-down sandbox (no network, no real data, nothing installed).
4. **Try to disprove it.** A different reviewer, who did not find the problem,
   tries to knock it down. Only what survives is reported.
5. **Attack the real thing.** The installed package is then attacked on a
   disposable, freshly installed Kali machine, to settle anything the code
   alone could not answer.
6. **Fix, then check again.** Each fix gets a test so it cannot quietly come
   back, a live check on real hardware, and a second full audit afterwards.

## How problems are rated

| Rating | Meaning |
|---|---|
| Critical | Someone with no account can take over the machine or all of its data. |
| High | A safety control is fully defeated: for example, an agent reaching outside the approved scope, or one user reading another's runs. |
| Medium | A real control is weakened, with limited reach or unusual conditions. |
| Low | Minor exposure, or something that needs a lot of effort for little gain. |

"Needs checking" means the code suggests a problem but it depends on how the
machine is set up; it is settled on the test machine.

## What the audit found

Two full audit runs (October 2026), each followed by attacks on a freshly
installed machine. **Every finding below was fixed before the first release,
0.1.0.** No released version ever had them, so there is nothing for an
administrator to do. Each fix has a test that keeps it fixed.

| | Run 1 | Run 2 |
|---|---|---|
| High | 3 | 0 |
| Medium | 18 | 11 |
| Low | 18 | 23 |
| "Needs checking" leads, followed up and fixed | 14 | 9 |

Nothing was rated Critical: no one without an account could take over the
machine or its data in either run.

### Keeping agents inside the approved scope

The most serious findings (all three Highs) were here. Agenti checks every
command an agent wants to run, and the checker could be fooled.

| Rating | What could happen | Fixed by |
|---|---|---|
| High | A scan command could carry an out-of-scope target the checker did not recognise (a host name, a range, IPv6, a number written another way, a target hidden inside an option). | Every target must be a plain IP address or range, or a URL with one, and is checked against the scope. Anything the checker does not understand is refused. |
| High | The checker read the command as text, but the computer ran it split into words, so the two could disagree. | The command is split into words once, checked, and run exactly as checked. |
| High | Some programs' dangerous options (running modules, writing files) slipped past a text filter. | Each program has a reviewed list of allowed options. Anything not on it is refused by name. |
| Medium | Hosts marked "out of scope" inside an allowed range were not actually blocked. | Exclusions are cut out of the allowed scope everywhere: at launch, for every command, and in the kernel's network fence. |
| Medium | A run kept going after the engagement ended or its approval was withdrawn. | Root stops runs that are no longer covered, and every scan, capture and exploit step re-checks the dates and approval. |
| Medium | The research agent's check of a website's address could be dodged (DNS rebinding), and its "outside sites" tool could reach engagement hosts. | The connection goes to the exact address that was checked, and outside-site tools refuse every engagement host. |
| Medium | Repeating an option (nikto `-h`, a list inside a URL, sslscan's `--sni-name`) sent the scan somewhere other than the address that was checked. | Each option may appear once, every host value is checked, and URLs may hold only one host. |
| Medium | A netexec user-name or password value could name a file on the Agenti machine. | Credential values must be typed out literally, and scans run in an empty folder. |
| Low | `netexec --shares` (meant to be read-only) wrote a test file to the target's shares; other small gaps (IPv6 written without brackets, IPv4-mapped addresses, a capture length with no limit). | `--no-write-check` is always added; the other gaps are closed; a capture cannot outlast the engagement. |

### Signing in and accounts

| Rating | What could happen | Fixed by |
|---|---|---|
| Medium | An account with only a passkey could sign in with its password alone, skipping two-factor. | Two-factor is required for every password sign-in. |
| Medium | The 5-try lockout could be outrun with many guesses at once, or reset by typing the correct password. | Each attempt is counted before it is checked, and the count survives a correct password. |
| Medium | The web server could create or take over an admin account without anyone re-entering their password. | Creating accounts and giving or restoring authority always needs a fresh sign-in by an admin, every time. The 60-second "grace" window is gone. |
| Low | One-time links and codes could be used twice at the same moment; a password-reset link survived renaming the account; removing a passkey left its sessions open. | Every one-time item is spent exactly once; renames and credential changes end old links and sessions. |

### Keeping users and runs apart

| Rating | What could happen | Fixed by |
|---|---|---|
| Medium | A program on the machine could take over the web interface's port during a restart or after `gui stop`, and collect sign-in cookies. | systemd holds the ports from boot, and `gui stop` ends every session. |
| Medium | An agent could leave a booby-trapped link in its own folder that tricked an administrator's command into reading or deleting other files. | Root reads anything a run wrote through one link-safe reader. |
| Low | A live view kept streaming someone else's run after access was removed; a teammate's run could crash team chat or fake a "done" vote; a reused user name could see the old owner's logs. | Streams re-check access; team messages are validated; logs show only the current owner's runs. |

### The web tier's limits

The web server runs as its own low-privilege account and may only ask the
command-line tool to do things. Several findings let it ask for more than it
should.

| Rating | What could happen | Fixed by |
|---|---|---|
| Medium | The web server could approve engagement changes in an admin's name, mark them as typed at the console, or approve different content from what the admin reviewed. | Approvals are bound to the exact content reviewed, record who and how from the system rather than the request, and refuse abbreviated options. |
| Medium | It could reach console-only commands (vault, logs, export, set-key, creating folders) through option tricks. | Those commands refuse the web server outright. |

### The machine itself

| Rating | What could happen | Fixed by |
|---|---|---|
| Medium | Admin commands could load Python code from whatever folder they were run in. | Root-run code loads only from Agenti's own folder. |
| Medium | Installing or upgrading the package followed links planted in a service's folder. | The installer refuses links in every folder it changes. |
| Low | Other programs could read a run's instructions from the process list, squat the model-traffic relay's port, or see raw scan and session output in the system log. | Instructions go through a private file; systemd holds the relay's port; the log gets one short line per step. |
| Low | The file-analysis sandbox's network filter could be sidestepped, and two analysis programs had options that could run other programs. | The filter is fixed, and those options are removed. |
| Low | The release process would have signed any package file found in the build, not only its own. | Only the exact packages the build made, matched by checksum, are signed. |

### The advanced (paid) agents

The exploit and hash-cracking agents are sold separately, but were audited the
same way.

| Rating | What could happen | Fixed by |
|---|---|---|
| Medium | A line break inside an approved Metasploit option became extra commands nobody approved. | Option values may not contain line breaks or control characters. |
| Low | Approvals could be used by another operator, or fire after the engagement ended; a callback from outside the scope could be kept as a session; the Metasploit service could be impersonated. | Approvals are bound to the run and checked when they fire; a session is kept only if both the target and the connecting address are in scope; the service is checked before every connection. |
| Low | A compromised cracking program could reach files outside its sandbox through links. | Results are read through link-safe readers. |

## Reporting a problem

Please do not open a public issue for a security problem. Report it privately
through GitHub's security advisories for the project, with the version, steps
to reproduce and the impact. Remove any real client data or credentials first.
