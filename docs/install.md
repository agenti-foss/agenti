# Installing Agenti

*For whoever installs and runs Agenti on a machine (Kali Linux, Debian 13 or
Ubuntu 24.04).*

## The short version

```
sudo apt install ./agenti-runtime_<version>_<cpu>.deb ./agenti_<version>_all.deb
sudo agenti setup
```

Then open **http://127.0.0.1:8420** on that machine and sign in.

## What you need

- A machine running Kali Linux (supported), Debian 13 or Ubuntu 24.04 (tested,
  best effort), on a regular PC (amd64) or an ARM board such as a Raspberry Pi 5
  (arm64).
- An Anthropic API key (https://console.anthropic.com/). Agenti uses it under
  Anthropic's terms; it is your key and your account.
- Written permission for every target you point it at. Agenti only scans what
  your engagement's approved scope allows, and that scope is your
  responsibility.

## Installing

Download the two packages for your CPU type from the release page and install
them with apt (it fetches what they depend on):

| Package | What it is |
|---|---|
| `agenti-runtime_<version>_amd64.deb` or `_arm64.deb` | Agenti's own Python and the libraries it needs, bundled and pinned. Nothing is downloaded after installation. Updated only when a library changes. |
| `agenti_<version>_all.deb` | Agenti itself: the CLI, the agents, the web GUI. |

apt also installs the agents' tools (nmap, tshark, suricata and others) as
*recommended* packages. A tool your distribution does not have, such as netexec
outside Kali, is skipped without stopping the install.

When the install finishes, the web GUI is already running, **on this machine
only** (`http://127.0.0.1:8420`), but nobody can sign in yet.

## First-run setup

```
sudo agenti setup
```

It asks one question at a time, and you can run it again whenever you like:

1. **The first admin.** A name, a password, and a two-factor code you scan with
   an authenticator app. Save the recovery codes it prints. You can add a
   passkey in the GUI afterwards (Settings → Security).
2. **The vault (optional).** See below. The default is no. It comes before
   the key so a key is stored inside it from the start.
3. **The Anthropic API key.** Typed at a hidden prompt; it never appears on
   the command line or in a log.
4. **Opening the GUI from other computers (optional).** Only this machine; or
   your local network with a self-signed certificate; or anywhere through a
   tunnel or proxy on this machine (recommended, see `docs/remote-access.md`).

Then, in the GUI: **Settings → Engagement**. Enter the client, the scope
(addresses or domains) and the dates, and approve it. After that, **Launch**:
pick an agent, a target inside the scope and a model.

## Checking the installation

```
sudo agenti verify
```

It proves every boundary by trying the forbidden thing as the account that must
not be able to do it, for example:

- the web tier cannot read the user database;
- no service account can change the code;
- the API cannot give itself a role;
- each agent is confined to its own run.

It changes nothing. A **FAIL** line names the fix.

## The vault (optional)

Agenti's data (reports, scan data, attached files, API keys) lives in
`/var/lib/agenti/data`. If this machine has full-disk encryption (Kali's
installer offers it), that already protects the data on a stolen, switched-off
machine, and you do not need the vault.

Without full-disk encryption, for example on a small device left on a client's
network, turn the vault on:

```
sudo agenti vault enable          # creates an encrypted container, moves the data in
```

The cost: after **every** reboot, someone must run `sudo agenti vault unlock`
and type the passphrase before anyone can start an agent or read a report.
Sign-in still works while it is locked. There is no recovery if the passphrase
is lost. `sudo agenti vault disable` moves the data back out.

## Updating

```
sudo apt update && sudo apt install --only-upgrade agenti agenti-runtime
```

Your settings, users and data are kept. The GUI restarts on the new version. A
run already in progress finishes on the code it started with. Settings → Platform →
Updates can tell you when a new release is out (off by default; it only reports).

## Uninstalling

| Command | What goes | What stays |
|---|---|---|
| `sudo apt remove agenti` | the program, its services and units, its sudoers entry; every running agent is stopped; the vault, if on, is **locked** | settings, users, all data |
| `sudo apt purge agenti` | the above and the settings; it then **asks** whether to delete all data too (default: no) | the data, unless you answer yes |

To delete everything in one go, run `sudo apt purge agenti` in a terminal and
answer **Yes**. After a remove, the locked vault's data can be read again by
reinstalling and running `sudo agenti vault unlock`; the removal prints the
`cryptsetup` commands that open it without Agenti.

Without a terminal, a purge keeps the data and prints the commands to delete it
yourself.

## Where things are

| Path | What |
|---|---|
| `/usr/bin/agenti` | the CLI (`agenti --help`, `agenti docs`) |
| `/usr/lib/agenti` | the code (read-only, owned by the package) |
| `/usr/lib/agenti-runtime` | the bundled Python |
| `/var/lib/agenti` | the user database, sign-in sessions, the TLS certificate |
| `/var/lib/agenti/data` | the data (the vault's mount point when it is on) |
| `/etc/agenti/api.conf` | how the GUI is reached (`sudo agenti gui configure --help`) |

## When something is wrong

| Symptom | What to do |
|---|---|
| The login page says *Nobody can sign in yet* | `sudo agenti setup` |
| The GUI does not load | `agenti gui status`, then `sudo agenti gui logs -n 40` |
| *the vault is locked* | `sudo agenti vault unlock` |
| Anything else | `sudo agenti verify`: its FAIL lines name the fix |
