# API key encryption

*For whoever looks after the Agenti server.*

## The short version

- Your AI provider keys (Claude, OpenAI, a self-hosted server's) are **always
  stored encrypted** on the server's disk, whether the vault is on or off.
- **Unlocked**, the keys exist only in the server's memory, in a folder only
  Agenti's own system can read. Agents' tools never see them, and nothing
  writes them back to disk.
- **Locked or powered off**, they can't be read, not even from a stolen disk.
- How they unlock depends on the machine:

| This server has | The keys unlock | You do |
|---|---|---|
| A **TPM** security chip | by themselves, at every start-up | nothing |
| The **vault** turned on | together with the vault | `sudo agenti vault unlock`, as before |
| Neither | with a **key passphrase** you chose | unlock after every restart: Settings → Platform → **API key encryption**, or `sudo agenti keys unlock` |

Settings → Platform → **API key encryption** always shows which one applies
and whether the keys are unlocked.

## Saving the first key

On a server with a TPM or the vault, saving a key in Settings → AI providers
(or `sudo agenti setup`) is all there is to it.

On a server with neither, the first key also asks for a **key passphrase**.
Store it somewhere safe, such as your password manager: an admin types it after
every restart. It is not your sign-in password and not the vault's passphrase.

## After a restart (key passphrase only)

Until someone unlocks the keys, no run can start. Every dashboard says *"The
API keys are locked after a restart"*.

- **In the browser:** Settings → Platform → API key encryption → **Unlock the
  keys**. Confirm it's you, then type the key passphrase.
- **At the server:** `sudo agenti keys unlock`

## Upgrading from an older version

Keys saved before 0.1.4 were plain files. On upgrade:

- **With a TPM or an open vault:** they are encrypted automatically.
- **With neither:** they keep working, and the dashboard says *"The API keys are
  not encrypted yet"* until an admin sets a key passphrase: Settings → Platform
  → **Set a key passphrase**, or `sudo agenti keys seal`.

Deleted files can linger in a disk's free space. After your keys are encrypted,
**create new keys at the provider** and save them, then delete the old ones
there.

## Common questions

**Can someone who breaks into the web server read the keys?** No. The web
server runs as its own account, which can't read the encrypted files or the
unlocked copies. It can only ask for a short list of actions, and none of them
returns a key; saving or unlocking also needs your password and a 2FA code (or
a passkey). Someone who gets full control of the running machine (root) could
read the unlocked keys: no software that uses a key unattended can prevent
that.

**I forgot the key passphrase.** It can't be recovered. Start over:
`sudo agenti keys reset` deletes every saved key, then save them again in
Settings → AI providers (you will choose a new passphrase).

**We replaced the motherboard (TPM) and the keys won't unlock.** The keys were
sealed to the old chip. Run `sudo agenti keys reset`, then save the keys again.

**How do I change the key passphrase?** At the server, with the keys unlocked:
`sudo agenti keys passphrase`.

**Can I lock the keys on purpose?** Yes: `sudo agenti keys lock`. Runs can't
start until they are unlocked again.

## What an error means

| Message | What it means | What to do |
|---|---|---|
| "The API keys are locked: unlock them in Settings → Platform…" | The server restarted, and the keys use a key passphrase. | Unlock them (above). |
| "the API keys are locked with the vault" | The keys unlock with the vault, which is locked. | `sudo agenti vault unlock` |
| "this machine has no TPM chip and the vault is off, so the API keys need a key passphrase" | The first key on this server needs a passphrase. | Fill in the key passphrase fields when saving the key. |
| "that is not the key passphrase" | A typo, or the wrong passphrase. | Try again. Forgotten? See above. |
| "this machine's TPM no longer unseals the API keys" | New motherboard, or the TPM was cleared. | `sudo agenti keys reset`, then save the keys again. |
