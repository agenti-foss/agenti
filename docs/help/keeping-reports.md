# Keeping a report, and re-enabling a user

## Keep a report

Reports from finished runs are cleared after 30 days. To keep one, open it and
press **Keep this report**. A copy goes into your **Outputs** (Dashboard → Task
History → Outputs), where it stays until you delete it.

- You can only keep reports from **your own** runs. An admin looking at someone
  else's dashboard does not see the button.
- If your storage is nearly full, the page says so. Delete old outputs to make room.

## Disable or re-enable a user (admins)

In Settings → Users, the faint **lock** next to an active user's green dot
disables the account: they are signed out at once and cannot sign in. A
disabled user has a red ring and a faint **check mark** next to it, which
re-enables them with whatever access the account kept. Both ask for your
password and a 2FA code (or a passkey). Only admins can do this, and nobody
can disable their own account or the last admin. The pencil next to a name
renames the account.

## Things the server now refuses

| Message | Why |
|---|---|
| "you cannot disable the account you are currently using" | Ask another admin. |
| "…is the only active admin" | Give someone else global admin first. |
| "password must be at least 8 characters" | Applies everywhere a password is set. |
