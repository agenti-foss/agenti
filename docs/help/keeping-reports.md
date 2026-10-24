# Keeping a report, and re-enabling a user

## Keep a report

Reports from finished runs are cleared after 30 days. To keep one, open it and
press **Keep this report**. A copy goes into your **Outputs** (Dashboard → Task
History → Outputs), where it stays until you delete it.

- You can only keep reports from **your own** runs. An admin looking at someone
  else's dashboard does not see the button.
- If your storage is nearly full, the page says so. Delete old outputs to make room.

## Re-enable a disabled user (admins)

In Settings → Users, a disabled user has a **check-mark** button. It asks for
your password and a 2FA code (or a passkey), because re-enabling gives the
account back whatever access it kept. Only admins can do this.

## Things the server now refuses

| Message | Why |
|---|---|
| "you cannot disable the account you are currently using" | Ask another admin. |
| "…is the only active admin" | Give someone else global admin first. |
| "password must be at least 8 characters" | Applies everywhere a password is set. |
