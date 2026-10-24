# Installing and setting up

*For whoever installs and looks after the Agenti server.*

## The short version

```
sudo apt install ./agenti-runtime_<version>_<cpu>.deb ./agenti_<version>_all.deb
sudo agenti setup
```

Then open the address `setup` prints, sign in, set up the engagement in
**Settings → Engagement**, and approve it. You can now launch an agent.

## What you need

- Kali Linux (supported), Debian 13 or Ubuntu 24.04, on a regular PC (`amd64`)
  or an ARM board such as a Raspberry Pi 5 (`arm64`).
- An Anthropic API key (console.anthropic.com).
- Written permission for every target you will scan.

## Installing

Install the two packages for your CPU type with `apt`. It also installs the
tools the agents use (nmap, tshark, suricata and others). A tool your system
does not have is skipped without stopping the install.

| Package | What it is |
|---|---|
| `agenti-runtime_<version>_amd64.deb` or `_arm64.deb` | Agenti's own Python and libraries, bundled. Installing downloads one more file: Anthropic's Claude Code program, from PyPI, checked against its pinned SHA-256 (it is Anthropic's, so it is fetched rather than shipped). |
| `agenti_<version>_all.deb` | Agenti itself: the command line, the agents and the web interface. |

When it finishes, the web interface is already running on this machine
(`http://127.0.0.1:8420`), but nobody can sign in until you run setup.

## First-run setup: `sudo agenti setup`

It asks one thing at a time. You can run it again whenever you like; a step
that is already done says so and is skipped.

1. **The first admin.** The name defaults to your Linux username. Keep it:
   runs you start from the terminal then appear on that account's dashboard.
   Type a password twice, then scan the QR code with an authenticator app.
   **Save the recovery codes** it prints. You can add a passkey later in
   **Settings → Security**.
2. **The vault (optional, default no).** An encrypted folder for Agenti's data.
   Read **The vault** before saying yes. It is asked before the API key so the
   key is stored inside it from the start.
3. **The Anthropic API key.** Paste it at the prompt. Nothing appears as you
   type, and it never lands in a log or your shell history.
4. **Opening the web interface.** Only this machine; other computers on your
   network (with a self-signed certificate); or from anywhere through a tunnel
   or proxy such as Cloudflare Tunnel. Change it any time with
   `sudo agenti gui configure --help`.

## Checking the installation

```
sudo agenti verify
```

It tests every safety boundary by trying the forbidden thing (for example, the
web server trying to read the user database), and changes nothing. A **FAIL**
line names the fix. On a new install it warns that no engagement exists yet;
that goes away once you set one up and approve it.

## Before the first run: the engagement

Agents only work inside an approved engagement: the client, the scope
(addresses or domains), the dates and who authorised it.

1. **Settings → Engagement** (or `sudo agenti engagement set --help`).
2. An admin **approves** it (or `sudo agenti engagement approve`).

Any later change to the engagement needs a fresh approval. Until then, every
agent refuses to start and says so.

**Runs already going when the engagement changes.** A run keeps working as long
as the new version still covers it (a note fixed, a scope widened and waiting
for approval). A run the change takes cover from is **stopped straight away**,
and writes its partial report: its target is no longer in scope or is now
excluded (for a research run, also when a new exclusion lands inside its target,
e.g. `payroll.acme.example` under a run on `acme.example`), the engagement's dates have ended, or exploitation was switched off for
an exploit run. The same goes for narrowing one agent's own scope (Settings →
Agents). The confirmation after saving names every run that was stopped and why.
A run also refuses every further action once the engagement's last day has
passed, even if nobody changed anything: an exploit approved before then does not
fire after it, a traffic capture stops at the end of that day, and resuming a run
gets the same checks as starting one (including *require a separate approver*).

Saving and approving each ask you to confirm it's you (password and 2FA code, or
a passkey). An approval covers exactly the version you were looking at: if
someone changes the engagement while you review it, approving is refused and you
review the new version. "Require approval" can be turned off only at the server
(`sudo agenti engagement set --no-require-approval`), never from the web.

Anything on the engagement's **out of scope** list is enforced, not just shown
to the agent: an excluded address or domain can't be a run's target, a range
that contains one is refused, and no command or page fetch may reach it. Start
each exclusion with the address, range or domain itself, then a note, e.g.
`198.51.100.0/24 (payroll)`; an entry that doesn't start that way stops every run
until it is fixed. An IPv4 address written in IPv6 form (`::ffff:198.51.100.7`) is the same
address, in scope lists, exclusions and targets alike. A research agent will not
read an excluded site, or any other site of the engagement outside its own
target, as "background" either.

## Updating

```
sudo apt install --only-upgrade ./agenti_<version>_all.deb ./agenti-runtime_<version>_<cpu>.deb
```

Your users, settings and data are kept. The web interface restarts on the new
version; a run already going finishes on the code it started with.

To replace the API key:
`sudo /usr/lib/agenti/set-secret.sh` (it asks before replacing the old one).

**Separate keys, separate spend caps.** Besides the one shared key you can give
one agent its own key (`sudo agenti <agent> set-key`) or one user their own
(`sudo agenti admin set-user-key <user>`), for example so each has its own
spending limit in the Anthropic Console. A run uses the most specific key there
is: the user's own, then the agent's, then the organisation's, then the shared
one. Renaming a user takes their key (and their memory notes) with them; deleting
a user deletes their key. These commands run only at the server's terminal: a
key is never typed into the web interface.

## Removing Agenti

| Command | What goes | What stays |
|---|---|---|
| `sudo apt remove agenti` | the program, its services, its sudo rule; running agents are stopped; the vault, if on, is **locked** | settings, users, all data |
| `sudo apt purge agenti` | the above and the settings; then it **asks** whether to delete all data too (default: no) | the data, unless you answer yes |

**To delete everything**, run `sudo apt purge agenti agenti-runtime` in a
terminal and answer **Yes**. That removes every report, scan, attached file,
API key, the user database, the vault and Agenti's service accounts. It cannot
be undone.

Without a terminal (a script), purge keeps the data and prints the exact
commands to delete it yourself. A script can answer yes in advance:
`echo "agenti agenti/purge-data boolean true" | sudo debconf-set-selections`.

## Messages you may see

| Message | What to do |
|---|---|
| The sign-in page says *Nobody can sign in yet* | `sudo agenti setup` |
| *this identity store is from an older Agenti (schema v1…)* | Agenti supports fresh installs only. Move the old store aside (the message gives the exact command) and run `sudo agenti setup`. |
| *no Anthropic API key reached this run* | No key is set at any level. `sudo agenti setup`, or set one for the agent or the user (above). |
| The web interface does not load | `agenti gui status`, then `sudo agenti gui logs -n 40` |
| *the vault is locked* | `sudo agenti vault unlock` (see **The vault**) |
| *…is not approved as it stands* | An admin approves the engagement (Settings → Engagement). |
| *REFUSING: target … is outside the authorized engagement scope* | The target isn't in the engagement. Pick one inside it, or have an admin add it and approve again. |
| A run's report says *Invalid API key* | The key was revoked or mistyped. Replace it: `sudo /usr/lib/agenti/set-secret.sh` |
| A run started from the terminal doesn't show on your dashboard | It belongs to your Linux username. Start it with `--owner <your Agenti name>`, or use the same name for both. |
| A report's Findings section is empty | The run hit its turn, budget or time limit before writing its summary. The commands it ran and their output are still in the report. |
| Anything else | `sudo agenti verify`: each FAIL line names the fix. |
