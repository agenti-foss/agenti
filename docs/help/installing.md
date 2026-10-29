# Installing and setting up

*For whoever installs and looks after the Agenti server.*

## The short version

```
curl -fsSL https://apt.agenti-foss.org/install.sh | sudo sh
```

It ends by printing a **setup code**. Open `http://127.0.0.1:8420` in a browser
on the same machine, enter the code and create the first admin. Then set up the
engagement in **Settings → Engagement** and approve it. You can now launch an
agent.

## What you need

- Kali Linux (supported), Debian 13 or Ubuntu 24.04, on a regular PC (`amd64`)
  or an ARM board such as a Raspberry Pi 5 (`arm64`).
- An Anthropic API key (console.anthropic.com). You can add it during setup or
  later.
- Written permission for every target you will scan.

## Installing

The command above adds Agenti's package repository to `apt` and installs
Agenti. `apt` picks the right package for your CPU and installs the tools the
agents use (nmap, tshark, suricata and others). A tool your system does not
have is skipped without stopping the install. The packages are signed: the
installer accepts the repository's key only if its fingerprint is

```
2D6F 55F9 385B 8C76 0C2E 95BD 8111 66F5 1B2D AE49
```

**Prefer to do it by hand?** These are the same steps:

```
curl -fsSL https://apt.agenti-foss.org/agenti-release-key.asc -o agenti.asc
gpg --show-keys agenti.asc        # check the fingerprint above
sudo install -m 0644 agenti.asc /usr/share/keyrings/agenti-archive-keyring.asc
sudo tee /etc/apt/sources.list.d/agenti.sources >/dev/null <<'EOF'
Types: deb
URIs: https://apt.agenti-foss.org
Suites: stable
Components: main
Signed-By: /usr/share/keyrings/agenti-archive-keyring.asc
EOF
sudo apt update && sudo apt install agenti
```

Two packages arrive:

| Package | What it is |
|---|---|
| `agenti-runtime` | Agenti's own Python and libraries, bundled. Installing downloads one more file: Anthropic's Claude Code program, from PyPI, checked against its pinned SHA-256 (it is Anthropic's, so it is fetched rather than shipped). |
| `agenti` | Agenti itself: the command line, the agents and the web interface. |

When it finishes, the web interface is already running on this machine only
(`http://127.0.0.1:8420`), and nobody can sign in until setup is done.

If the installer says **this machine's clock is wrong**, fix the clock
(`sudo timedatectl set-ntp true`, check with `date -u`) and run it again. A
restored virtual machine or a dual-boot PC often has the wrong time.

## First-run setup in the browser

1. Open `http://127.0.0.1:8420` **on the Agenti machine itself**. On a machine
   with no screen, forward the port from your own computer first:
   `ssh -L 8420:127.0.0.1:8420 <the machine>`, then open the same address
   there. The setup page refuses anything else, including a tunnel or proxy,
   so nobody else on the network can claim the server first.
2. Enter the **setup code** the installer printed. To see it again:
   `sudo agenti setup-code`. Twenty wrong tries cancel the code; make a new
   one with `sudo agenti setup-code --new`.
3. Choose the admin's username, then a password, and scan the QR code with an
   authenticator app. **Save the recovery codes** it shows.
4. Sign in. Setup then offers two optional steps, both also in
   **Settings → Platform**:
   - **The Anthropic API key.** Paste it; you confirm it's you, and it is
     stored on the server and never shown again.
   - **The vault.** An encrypted folder for Agenti's data. Read **The vault**
     first.

Both can wait: until a key is saved, the dashboard and the Launch page say
*No Anthropic API key yet: agents can't start*, with a link to add one. Closing
the dashboard's notice hides it until you next sign in.

The setup code stops working as soon as an admin can sign in.

## First-run setup in a terminal: `sudo agenti setup`

The same setup, one question at a time, plus the choice of how the web
interface is reached. You can run it again whenever you like; a step that is
already done says so and is skipped.

1. **The first admin.** The name defaults to your Linux username. Keep it:
   runs you start from the terminal then appear on that account's dashboard.
   Type a password twice, then scan the QR code with an authenticator app.
   **Save the recovery codes** it prints. You can add a passkey later in
   **Settings → Security**.
2. **The vault (optional, default no).** It is asked before the API key so the
   key is stored inside it from the start.
3. **The Anthropic API key (optional).** Paste it at the prompt. Nothing appears
   as you type, and it never lands in a log or your shell history.
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
sudo apt update && sudo apt upgrade
```

Agenti updates with the rest of the system. Your users, settings and data are
kept. The web interface restarts on the new version; a run already going
finishes on the code it started with.

To replace the API key: **Settings → Platform → Anthropic API key**, or at the
server `sudo /usr/lib/agenti/set-secret.sh` (it asks before replacing the old one).

**Separate keys, separate spend caps.** Besides the one shared key you can give
one agent its own key (`sudo agenti <agent> set-key`) or one user their own
(`sudo agenti admin set-user-key <user>`), for example so each has its own
spending limit in the Anthropic Console. A run uses the most specific key there
is: the user's own, then the agent's, then the organisation's, then the shared
one. Renaming a user takes their key (and their memory notes) with them; deleting
a user deletes their key. These per-agent and per-user keys are set only at the
server's terminal; the web interface sets only the shared one.

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
| The sign-in page says *Agenti isn't set up yet* | Open `http://127.0.0.1:8420` on the server itself and enter the setup code (`sudo agenti setup-code`), or run `sudo agenti setup` there. |
| The setup page says *setup works only in a browser on the Agenti machine itself* | You opened it from another computer or through a tunnel. Use the machine's own browser, or `ssh -L 8420:127.0.0.1:8420 <the machine>` and open `http://127.0.0.1:8420`. |
| *that setup code is not right* | `sudo agenti setup-code` shows the current one. |
| *there is no setup code right now* | Too many wrong tries cancelled it: `sudo agenti setup-code --new`. |
| *this machine's clock is wrong* (installer) | `sudo timedatectl set-ntp true`, check with `date -u`, then run the installer again. |
| *this identity store is from an older Agenti (schema v1…)* | Agenti supports fresh installs only. Move the old store aside (the message gives the exact command) and run `sudo agenti setup`. |
| *no Anthropic API key reached this run* | No key is set at any level. **Settings → Platform → Anthropic API key**, or `sudo agenti setup`, or set one for the agent or the user (above). |
| The web interface does not load | `agenti gui status`, then `sudo agenti gui logs -n 40` |
| *the vault is locked* | `sudo agenti vault unlock` (see **The vault**) |
| *…is not approved as it stands* | An admin approves the engagement (Settings → Engagement). |
| *REFUSING: target … is outside the authorized engagement scope* | The target isn't in the engagement. Pick one inside it, or have an admin add it and approve again. |
| A run's report says *Invalid API key* | The key was revoked or mistyped. Replace it in **Settings → Platform**, or `sudo /usr/lib/agenti/set-secret.sh` |
| A run started from the terminal doesn't show on your dashboard | It belongs to your Linux username. Start it with `--owner <your Agenti name>`, or use the same name for both. |
| A report's Findings section is empty | The run hit its turn, budget or time limit before writing its summary. The commands it ran and their output are still in the report. |
| Anything else | `sudo agenti verify`: each FAIL line names the fix. |
