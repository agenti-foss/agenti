# Signing in, two-factor codes and recovery codes

*For everyone who signs in to Agenti.*

## The short version

- Sign in with your **username and password**, then the **6-digit code** from your
  authenticator app — or, if your admin has turned it on, with a **passkey** (your
  device's own fingerprint, face or PIN check), which needs no password at all.
- **If your only second factor is a passkey, sign in with the passkey.** Your
  password alone is not enough on an account that has one, just as it is not
  enough on an account with a code app.
- **Lost your phone?** Use one of the **recovery codes** you saved when you set
  up two-factor authentication. Click *Lost your device? Use a recovery code*
  under the code field, type one code (it looks like `a1b2c-3d4e5`), and you're
  in. Each recovery code works once.
- Wherever the site asks you to **confirm it's you** before a sensitive action
  (changing your password, creating an account or granting someone access,
  building an agent), the same popup appears: your password and a 2FA code, or a
  passkey — and the same *Lost your device?* link accepts a recovery code there too. It asks every time, even
  for two actions a few seconds apart: a session that someone else got hold of
  can never ride your last confirmation.
- **Admins: creating an account** ends with that popup every time, and one
  confirmation creates the account with the role you picked. Cancel it and nothing
  is created.

## Common questions

**I typed my username with a capital letter and it didn't work.**
Usernames are lowercase. The sign-in page now lowercases what you type, so
`Alex` and `alex` are the same account.

**The code field only shows a number keypad on my phone. How do I type a
recovery code?** Tap *Lost your device? Use a recovery code* first — the
field switches to a normal keyboard and accepts the `xxxxx-xxxxx` format,
with or without the dash.

**I've used all my recovery codes / I never saved them.** An admin has to reset
your two-factor authentication: ask them to run
`sudo agenti admin user reset-2fa <your-username>` on the host, or to use
*Reset MFA* in your user's security settings. You'll set 2FA up again at your
next sign-in.

**Why was I signed out after changing my password, my 2FA or a passkey?**
Changing how you sign in ends every session, including the one you did it from,
so a session someone else might hold can never outlive the old credentials.
Removing a passkey counts too: it is what you do when one is lost. Sign in again
with the new details.

**My password-reset link stopped working.** A link works once, for one day, and
only for the account it was made for. It also ends when an admin sends a newer
one, when the password is changed another way, or when the account is renamed.
Ask an admin for a new link.

**What does "You've signed out." mean on the sign-in page?** Exactly that: you
pressed *Log out*, the server ended your session, and the cookie is dead
everywhere. It's confirmation, not an error.

**How short can a password be?** At least 8 characters, on every page that sets
one (first-time set-up, a reset link, and Settings → Security).

## What an error means

| Message | What it means | What to do |
|---|---|---|
| "Too many attempts — this account is temporarily locked." | Several wrong passwords or codes in a row. Signing in with the right password again does not reset the count; only a complete sign-in does. | Wait 15 minutes, then try again. The lock clears on its own. |
| "this account's second factor is a passkey…" | Your account has a passkey and no code app, so the password alone is not a sign-in. | Use *Sign in with a passkey* (or the passkey button in a confirm popup). Lost it? An admin can reset your 2FA. |
| "…is an admin, and a link for an admin cannot come from the web tier on its own" | Resending a set-up link from Settings → Users works for operators. For an admin account the link is made at the server, so the web tier alone can never choose an admin's first password. (Creating a new admin in Settings → Users still gives you its link, after you confirm it's you.) | At the server: `sudo agenti admin mint-enrolment-link <name>` |
| "too many link attempts from this address" | An enrolment or password-reset link was tried many times from your address in a few minutes. | Wait five minutes, then open the link again. |
| "that code has already been used" | A 2FA code works once per 30 seconds, and two admin actions in a row each need their own confirmation. | Wait for the app to show the next code, or use a passkey. |
| "Enter one of your recovery codes (xxxxx-xxxxx)." | What you typed isn't a recovery code. | Check for a missing character; the dash is optional. |
| "Passkeys need the real domain…" | You opened the site by its IP address or an old bookmark. | Open the address shown in the message and try again. |
