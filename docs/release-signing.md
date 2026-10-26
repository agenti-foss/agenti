# The release signing key (key ceremony)

*For the maintainer who signs Agenti's apt repository. Done once, by hand, with
the computer's network off. Nobody else — no CI job, no assistant — ever sees
the key, its passphrase or the YubiKey's PINs.*

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
- A computer you can start from a **live USB** (Debian live, or Tails), with
  networking off for the whole ceremony.
- **One USB stick for the backup** (it will be encrypted). Copy it to a second
  stick later and keep the two in different places.
- **One more USB stick** to carry the *public* key and the revocation
  certificate back to an online computer. Nothing secret goes on this one.
- Decided in advance (written on paper, never typed into an online machine):
  - the key's name and email, e.g. `Agenti releases <releases@agenti-foss.org>`;
  - a long passphrase for the main key (six or more random words);
  - a new YubiKey **PIN** (6–8 digits) and **Admin PIN** (8 digits).

## 1. Start offline

Boot the live USB. Turn networking off (unplug the cable, switch Wi-Fi off) and
keep it off until step 8. Open a terminal. If `gpg`, `ykman` and `cryptsetup`
are missing, the live image needs them added beforehand (Tails and Debian live
have `gpg` and `cryptsetup`; `ykman` is the `yubikey-manager` package).

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
only moment a complete backup can be made.

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

Check that it signs (you will be asked for the PIN and to touch the key):

```
echo test | gpg --clearsign --default-key "$FPR" | gpg --verify
```

## 7. What leaves the offline computer

On the second (non-secret) stick:

```
gpg --armor --export "$FPR" > agenti-release-key.asc     # the PUBLIC key only
cp agenti-release-key.asc revoke.asc /media/<stick>/
echo "$FPR" > /media/<stick>/fingerprint.txt
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

## Later

- **Second backup:** copy the encrypted stick to another stick
  (`sudo dd if=/dev/sdX of=/dev/sdY bs=4M status=progress`, then check it opens).
- **Before the signing subkey expires (2 years):** offline again, load the
  backup's `gnupg-home`, `gpg --quick-set-expire "$FPR" 2y '*'`, export the
  public key again and publish it.
- **YubiKey lost:** offline, load the backup, add a new signing subkey
  (`gpg --quick-add-key "$FPR" ed25519 sign 2y`), move it to the new YubiKey,
  publish the updated public key. Revoke the old subkey the same way.
- **Main key compromised:** publish `revoke.asc` (from the password manager)
  and make a new key with this guide; users must be told to trust the new one.
