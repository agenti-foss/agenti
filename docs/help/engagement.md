# The engagement

The engagement is your organization's one authorization record: the client,
who authorized the work, the dates, and the scope (networks and domains)
agents may touch. Every agent shares it, and no agent starts without it.
Admins edit it in **Settings → Engagement** (or `sudo agenti engagement set --help`).

## Saving it

Open **Edit engagement**, make your changes and press **Save and close**. You
confirm it's you once (password and 2FA code, or a passkey). The change takes
effect at once, and it is recorded as approved by you: reports and the history
say who authorized which scope, and when.

Pressing **Save and close** with nothing changed just closes the window.

**Caps, models and prices** (Operational policy) apply at once in every case.
They are operating limits, not a change to what may be touched.

## A second approver (optional)

For teams where one person should not authorize scope alone, turn on the
second-approver policy at the server:

```
sudo agenti admin set-policy engagement-second-approver on
```

It is off by default. Settings → Platform → Policies shows whether it is on.

With it on:

- **Saving submits a change.** The version in force stays in force; the change
  waits for a different admin. The engagement card gets an amber outline, and
  under **Edit engagement** you see *Engagement change submitted, pending
  approval of another admin*. Admins who can approve it also see a banner on
  their dashboard.
- **Until it is decided, a run must fit both versions.** Anything the change
  takes away (a removed host, an earlier end date, the exploit agent or payload
  capture switched off) applies at once, and stops runs it no longer covers.
  Anything it adds waits for approval.
- **Another admin decides.** In the window, **Current | Pending** switches
  between the version in force and the change; each changed field says what is
  in force now. **Approve change** puts it in force, approved by them;
  **Reject** discards it (with an optional reason for the history).
- **Its author can keep editing.** Saving again replaces the waiting change, or
  **Withdraw change** discards it. If someone else saves over it, they become its
  author, and the first author may then approve it.
- **Only one admin?** Nobody else could approve your change. The window says so
  and offers three ways out: add a second admin (Settings → Users), withdraw the
  change, or turn the policy off at the server and approve it yourself.

At the server: `sudo agenti engagement show` lists a waiting change with the
exact commands, `approve-pending`, `reject-pending` and `withdraw-pending`.

This is a different control from **Approver can't start runs**
(`require-separate-approver`): that one stops whoever approved the engagement
from also starting a run against it. You can use either, both or neither.

## Runs already going

A run keeps working as long as the engagement still covers it. A change that
takes away its cover stops it straight away, and it writes its partial report.
The confirmation after saving names every run that was stopped and why.

## Messages

| Message | What it means | What to do |
|---|---|---|
| "the engagement changed after you opened it" | Someone saved, approved or withdrew a change while your window was open. | Close the window, open it again and redo your change. |
| "another admin approves it" | The second-approver policy is on and you made this change. | Ask another admin, or withdraw it. |
| "…was made against an older version" | The version in force changed after this change was saved. | Save it again on top of the current version, or reject it. |
| "…does not start with an IP or CIDR" | An exclusion is free text. A run could not honor it. | Start it with the address, range or domain, then a note, e.g. `198.51.100.0/24 (payroll)`. |
| "is not approved as it stands" | An older record nobody approved. | Open the engagement and press **Save and close** (or, with the second approver on, another admin approves it). |
