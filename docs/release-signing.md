# The release signing key (key ceremony)

*For the maintainer who signs Agenti's apt repository. Done once, by hand, with
the computer's network off. Nobody else — no CI job, no assistant — ever sees
the key, its passphrase or the YubiKey's PINs.*

## The current key

```
pub   ed25519/811166F51B2DAE49 2026-10-28 [C] [expires: 2031-10-27]
      2D6F55F9385B8C760C2E95BD811166F51B2DAE49
uid   Agenti releases <releases@agenti-foss.org>
sub   ed25519/03F1787567F9906B 2026-10-28 [S] [expires: 2028-10-27]
```

The public key is `packaging/apt/agenti-release-key.asc`.

## What this key is for

apt checks that the package list it downloads (`InRelease`) was signed by the
key it trusts for Agenti. This guide makes that key:

- a **main key** that only certifies (it vouches for the signing key). It is
  never on an online machine: its only copies are the backup USB stick(s).
- a **signing subkey**, which signs each release. It lives on the YubiKey and
  cannot be copied off it. Signing needs the YubiKey plugged in, its PIN, and
  a touch.
- a **revocation certificate**, which can only cancel the key (it cannot sign
  anything). One copy goes in the maintainer's password manager.

Losing the YubiKey is recoverable: start the offline computer from the live USB
again, load the main key from the backup, and put a new signing subkey on a new
YubiKey. Users notice nothing, because they trust the main key.

## What you need

- A **YubiKey 5** series key (the blue "Security Key" models have no OpenPGP
  and cannot do this). Firmware 5.2.3 or later for ed25519 keys:
  `ykman info` shows it.
- A computer you can start from a USB stick, and **three USB sticks**:
  1. the **live USB** (Kali Live) the ceremony runs on;
  2. **BACKUP**: the encrypted backup of the main key. Copy it to a second
     stick later and keep the two in different places;
  3. **PUBLIC**: carries the public key and the revocation certificate back to
     an online computer. Nothing secret goes on this one.
- Decided in advance (written on paper, never typed into an online machine):
  - the key's name and email, e.g. `Agenti releases <releases@agenti-foss.org>`;
  - a long passphrase for the main key (six or more random words);
  - a new YubiKey **PIN** (6–8 digits) and **Admin PIN** (8 digits).

## 0. Make the live USB (on any computer, before the ceremony)

Stick 1 becomes a Kali Live USB. Download the "Live" image from
https://www.kali.org/get-kali/#kali-live, check its SHA256SUMS, and write it to
the stick (`sudo dd if=kali-linux-*-live-amd64.iso of=/dev/sdX bs=4M status=progress conv=fsync`,
or balenaEtcher/Rufus). Label the other two sticks **BACKUP** and **PUBLIC**.

## 1. Start the live system, add the tools, then go offline

Boot the computer from stick 1 (choose "Live system", no persistence). While it
is still online, add the tools, because the live image may lack them:

```
date -u                                    # must be the real UTC time, within a minute
sudo timedatectl set-ntp true              # if it is not (a dual-boot PC's clock is often hours off)
sudo apt update && sudo apt install -y yubikey-manager scdaemon pcscd cryptsetup
```

The clock matters twice: apt refuses package lists "not live until" a future
time, and the key is stamped with this clock. A key made in the future is
refused by every other computer until that time comes.

**Now disconnect the network** (unplug the cable, switch Wi-Fi off in the menu)
and keep it off until step 8. The key is only ever made after this point, in
this RAM-only session.

```
export GNUPGHOME=$(mktemp -d)        # a throwaway keyring in RAM, gone at shutdown
cat > "$GNUPGHOME/gpg.conf" <<'EOF'
personal-digest-preferences SHA512
cert-digest-algo SHA512
default-preference-list SHA512 SHA384 SHA256 AES256 AES192 AES ZLIB BZIP2 ZIP Uncompressed
EOF
```

## 2. Make the main key and the signing subkey

```
gpg --quick-generate-key "Agenti releases <releases@agenti-foss.org>" ed25519 cert 5y
FPR=$(gpg --list-keys --with-colons | awk -F: '/^fpr/{print $10; exit}')
gpg --quick-add-key "$FPR" ed25519 sign 2y
gpg --list-keys --keyid-format long        # one [C] main key, one [S] subkey
```

gpg asks for the passphrase when the main key is made. Type the long one.

## 3. The revocation certificate

gpg made one when it made the key; keep a copy under a plain name:

```
cp "$GNUPGHOME/openpgp-revocs.d/$FPR.rev" revoke.asc
```

## 4. The backup (before anything goes onto the YubiKey)

Moving the subkey to the YubiKey deletes it from this keyring, so this is the
only moment a complete backup can be made. **Plug in the BACKUP stick now**
(only the live USB and BACKUP; `/dev/sdX` is the whole BACKUP device, never the
live USB). If Kali opened it, `sudo umount /dev/sdX*` first. Unplug it after.

```
lsblk                                  # find the backup stick, e.g. /dev/sdb — check twice
sudo cryptsetup luksFormat /dev/sdX    # type YES, then a passphrase (may be the same long one)
sudo cryptsetup open /dev/sdX keybackup
sudo mkfs.ext4 -q /dev/mapper/keybackup
sudo mkdir -p /mnt/keybackup && sudo mount /dev/mapper/keybackup /mnt/keybackup
sudo cp -a "$GNUPGHOME" /mnt/keybackup/gnupg-home
gpg --armor --export-secret-keys "$FPR" | sudo tee /mnt/keybackup/main-and-subkeys.asc >/dev/null
sudo cp revoke.asc /mnt/keybackup/
sync && sudo umount /mnt/keybackup && sudo cryptsetup close keybackup
```

## 5. Set the YubiKey's PINs

**Plug in the YubiKey now.** If `ykman` cannot find it: `sudo systemctl start pcscd`.

A new YubiKey's OpenPGP PIN is `123456` and its Admin PIN is `12345678`.

```
ykman openpgp info
ykman openpgp access change-pin           # old 123456, then your new PIN
ykman openpgp access change-admin-pin     # old 12345678, then your new Admin PIN
ykman openpgp keys set-touch sig on       # every signature needs a touch
```

## 6. Move the signing subkey onto the YubiKey

```
gpg --edit-key "$FPR"
  key 1          # selects the [S] subkey (a * appears next to it)
  keytocard      # choose (1) Signature key; passphrase, then the Admin PIN
  save
gpg --card-status                         # "Signature key" shows the subkey's fingerprint
```

If `gpg --card-status` cannot find the card:
`echo disable-ccid > "$GNUPGHOME/scdaemon.conf"; gpgconf --kill scdaemon`.

Check that it signs (you will be asked for the PIN and to touch the key):

```
echo test | gpg --clearsign --default-key "$FPR" | gpg --verify
```

## 7. What leaves the offline computer

**Plug in the PUBLIC stick now** (exFAT or FAT32). Kali opens it under
`/run/media/kali/<name>`; `lsblk -o NAME,SIZE,MOUNTPOINT` shows the path.

```
P=/run/media/kali/<name>
gpg --armor --export "$FPR" > "$P/agenti-release-key.asc"   # the PUBLIC key only
echo "$FPR" > "$P/fingerprint.txt"
cp ~/revoke.asc "$P/"
ls -l "$P"; sync
```

Then shut the computer down. The RAM keyring is gone; the main key now exists
only on the encrypted backup stick.

## 8. Back online

- Put `revoke.asc` into the password manager (Proton Pass), as an attachment,
  then delete it from the stick.
- Give the maintainer's assistant **only** `agenti-release-key.asc` and
  `fingerprint.txt`. They are public: they are published on the website's
  download page and in the repository, so users can check what apt trusts.
- On the computer that signs releases, import the public key and let gpg find
  the YubiKey: `gpg --import agenti-release-key.asc && gpg --card-status`.

## Opening the BACKUP stick later

Every job below starts the same way. The BACKUP stick holds the secret main
key, so it is only ever opened on the **offline live system**, never on an
everyday computer.

1. Boot the Kali live USB, choose "Live system", **turn the network off**, and
   check the clock: `date -u` (fix it while still online with
   `sudo timedatectl set-ntp true` if it is wrong).
2. Plug in BACKUP and open it:
   ```
   lsblk -o NAME,SIZE,MODEL              # BACKUP is the entry that appeared
   sudo cryptsetup open /dev/sdX backup1  # sdX = the whole BACKUP device
   sudo mkdir -p /mnt/b1 && sudo mount /dev/mapper/backup1 /mnt/b1
   ls /mnt/b1                            # gnupg-home  main-and-subkeys.asc  revoke.asc
   ```
3. When finished: `sync && sudo umount /mnt/b1 && sudo cryptsetup close backup1`.

## Making a second backup copy

Keep two BACKUP sticks in two different places. This copies the files onto a
newly encrypted stick, so the new stick may be any size.

1. Open BACKUP as above, but mount it **read-only**:
   `sudo mount -o ro /dev/mapper/backup1 /mnt/b1`.
2. Plug in the new stick and find it with `lsblk -o NAME,SIZE,MODEL,MOUNTPOINT`.
   It is the newest entry: **not the live USB, not BACKUP**. Call it `sdY`.
3. Encrypt it and copy everything (this erases the new stick; type `YES`):
   ```
   sudo umount /dev/sdY* 2>/dev/null
   sudo cryptsetup luksFormat /dev/sdY
   sudo cryptsetup open /dev/sdY backup2
   sudo mkfs.ext4 -q /dev/mapper/backup2
   sudo mkdir -p /mnt/b2 && sudo mount /dev/mapper/backup2 /mnt/b2
   sudo cp -a /mnt/b1/. /mnt/b2/
   sudo diff -r /mnt/b1 /mnt/b2 && echo "COPY OK"
   ```
4. Close both: `sync && sudo umount /mnt/b1 /mnt/b2 && sudo cryptsetup close backup1 && sudo cryptsetup close backup2`.
5. Label it **BACKUP 2** and store it away from the first one and from the YubiKey.

## Renewing the key before it expires

| Key | Lives on | Expires (UTC) | Renew by |
|---|---|---|---|
| Signing subkey `03F1787567F9906B` | YubiKey | **27 October 2028** | August 2028 |
| Main key `811166F51B2DAE49` | BACKUP sticks | **27 October 2031** | August 2031 |

A key is **extended**, not replaced: the fingerprint stays the same, the
YubiKey is not touched, and users only need the updated public key. If a key
is allowed to expire, every user's `apt update` refuses Agenti until it is
extended, so renew about two months early.

1. Open BACKUP as above (read-write), and use its keyring:
   ```
   export GNUPGHOME=/mnt/b1/gnupg-home
   FPR=2D6F55F9385B8C760C2E95BD811166F51B2DAE49
   ```
2. Extend (gpg asks for the main key's passphrase):
   ```
   gpg --quick-set-expire "$FPR" 2y '*'    # the signing subkey: two more years
   gpg --quick-set-expire "$FPR" 5y        # the main key (in 2031): five more years
   gpg --list-keys --keyid-format long     # check the new dates
   ```
3. Refresh the full export on the stick:
   ```
   gpg --armor --export-secret-keys "$FPR" | sudo tee /mnt/b1/main-and-subkeys.asc >/dev/null
   ```
4. Plug in the PUBLIC stick and export the updated public key
   (`P=/run/media/kali/<name>`, from `lsblk`):
   ```
   gpg --armor --export "$FPR" > "$P/agenti-release-key.asc"
   ```
5. Close BACKUP, then bring BACKUP 2 up to date: open both and copy, as in
   "Making a second backup copy" step 3 but skip the `luksFormat`/`mkfs` lines
   and use `sudo rsync -a --delete /mnt/b1/ /mnt/b2/` (or `cp -a`) instead.
6. Back online: replace `packaging/apt/agenti-release-key.asc` with the new
   file and update the dates in "The current key" above. Publishing it on
   the apt host and the website lets users' apt pick up the new dates.

## Other events

- **YubiKey lost:** open BACKUP, add a new signing subkey
  (`gpg --quick-add-key "$FPR" ed25519 sign 2y`), move it to a new YubiKey as
  in step 6, update both BACKUP sticks, and publish the updated public key.
  Revoke the old subkey (`gpg --edit-key "$FPR"`, `key 1`, `revkey`, `save`).
- **Main key compromised:** publish `revoke.asc` (from the password manager)
  and make a new key with this guide; users must be told to trust the new one.
