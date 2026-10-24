# The vault

*For whoever looks after the Agenti server. Optional, and off unless you turn it on.*

## The short version

- The vault keeps Agenti's data (reports, scan data, attached files, API keys)
  in an **encrypted file**. When it is locked, the data can't be read without
  your passphrase.
- **The cost:** after **every** reboot, someone must run
  `sudo agenti vault unlock` and type the passphrase before anyone can start an
  agent or open a report. Signing in still works while it is locked.
- **There is no recovery if the passphrase is lost.**
- If the machine already has full-disk encryption (Kali's installer offers it),
  you don't need the vault. That is the better choice where you can have it.
- **With neither, agents still run**, but every dashboard, `sudo agenti verify`
  and `sudo agenti setup` say *"Data from agents is currently not encrypted"*,
  with a link to turn the vault on.

## Who should use it

A machine that may be stolen or seized while switched off and has no full-disk
encryption, for example a small device left on a client's network.

It does **not** protect a machine that is running and unlocked (root can read
the data until it is locked or switched off). It doesn't protect Agenti's code
or the operating system either; full-disk encryption does.

## Turning it on

```
sudo agenti vault enable            # an 8 GB vault; --size 16G for more
```

Or say yes during `sudo agenti setup`. You choose a passphrase (typed twice,
then once more to open it).

**From the web interface (admins):** Settings → Platform → Vault → **Turn on the
vault**. Pick a size, type the passphrase twice (at least 12 characters), tick the
box saying you have stored it, then confirm it's you (password and 2FA code, or a
passkey). It takes a few minutes; keep the page open. The passphrase goes from
your browser straight to the server's encryption tool: it is never written on a
command line or in a log, and Agenti stores it nowhere. Turning the vault on is
the only vault action the web can take.

Either way, Agenti then:

1. creates the encrypted file `/var/lib/agenti/vault.img`;
2. copies the data into it and **checks** the copy;
3. **deletes the unencrypted original**;
4. opens the vault where the data used to be, so nothing else changes.

If anything fails before step 3, nothing is lost: the data stays exactly as it
was.

If an API key was stored before the vault was turned on, Agenti tells you to
replace it, because deleted files can linger on the disk until overwritten.
`sudo agenti setup` asks about the vault before the API key, so a key set there
goes straight into the vault.

## Every day

| What | Command |
|---|---|
| After a reboot, before anyone works | `sudo agenti vault unlock` |
| Lock it now (data unreadable until unlocked) | `sudo agenti vault lock` |
| Is it locked? | `sudo agenti vault status` |
| Change the passphrase | `sudo agenti vault passphrase` |
| Turn it off (moves the data back out; asks first) | `sudo agenti vault disable` |

These are terminal-only on purpose: apart from turning it on, the web interface
can't lock, unlock, change or turn off the vault.

## Common questions

**Why does the dashboard say my data is not encrypted?** There is no vault and
the disk Agenti's data sits on is not encrypted (no full-disk encryption). Agenti
checks the disk itself, so this is accurate. Turn the vault on (above), or move to
a machine with full-disk encryption; the message goes away on its own.

**Turning it on from the web failed. Did I lose anything?** No. If anything goes
wrong before the copy is checked, the data stays exactly where it was. The message
says what failed (most often: a run is still going, or there is not enough free
disk for the container plus a copy of the data).

While it is locked, the data folder is empty and nothing can write to it, so no
agent can quietly save data to the unencrypted disk. Agents refuse to start,
and pages that need data say *the vault is locked*.

## Uninstalling with the vault on

`sudo apt remove agenti` **locks** the vault. Nothing is deleted. To read the
data again, reinstall Agenti and run `sudo agenti vault unlock`, or, without
Agenti, with your passphrase:

```
sudo cryptsetup open /var/lib/agenti/vault.img agenti_vault
sudo mount /dev/mapper/agenti_vault /mnt
```

Close it again with `sudo umount /mnt && sudo cryptsetup close agenti_vault`.

To delete the vault along with everything else, see **Installing and setting
up → Removing Agenti**.

## Messages you may see

| Message | What to do |
|---|---|
| *the vault is locked* | `sudo agenti vault unlock` |
| *No key available with this passphrase* | The passphrase was mistyped. Try again; there is no other way in. |
| *an UNENCRYPTED copy of the data from before the vault is still at …* (from `agenti verify`) | Delete it with the command shown, then replace the API key. |
| *cannot unmount — something is using …* | Stop the running agents first, then lock again. |
| *not enough free disk for …* | Free some space, or choose a smaller `--size`. |
