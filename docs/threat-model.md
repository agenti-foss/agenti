# Threat model (draft)

Agenti is **auditable, bounded, isolated, and admin-authorised for real targets**.
It is not "safe". It lets an AI model drive security tools, and it assumes the
model can be confused or manipulated by the data it reads. The limits that matter
are therefore enforced outside the model.

## Assets

The approved scope and engagement record; the data in the encrypted vault (run
data, reports, attached files); user credentials and sessions; the Anthropic API
key; the audit trail.

## What it is designed to defend against

| Threat | Defence (design level) |
|---|---|
| A manipulated or confused model acts outside scope | Scope, tool allow-lists and approvals live in root-owned files and an outer harness the model cannot write; out-of-scope commands are refused and logged |
| An operator exceeds their authority | Operators can only narrow the approved scope; an admin approves it; an optional policy stops the approver also starting runs |
| One user reads another's runs | Per-user dashboards; each run is isolated by the kernel |
| A compromised web tier grants itself access | The web tier can create inert identities and remove authority but never grant it without a fresh, single-use, action-bound grant from a separate daemon; it never writes the identity store |
| A malicious input file attacks its parser | File analysis runs in a sandbox with no network, no capabilities and resource limits |
| Disk theft | The operating system's full-disk encryption (recommended), or the optional vault: data in a LUKS container that fails closed until an admin unlocks it, its locked mount point immutable so nothing lands unencrypted |
| Silent misuse | Every decision, run, message and grant is logged |

## Out of scope (what it does not defend against)

- A malicious or careless administrator.
- An attacker with root on the host while the data is readable (vault off, or unlocked).
- Tampering with the code or the OS while the machine is off, without full-disk encryption
  (the code is outside the vault).
- Anything the approved scope permits.
- Side effects of legitimate testing (scans and exploits can disrupt services).
- Flaws in third-party security programs, the Claude Agent SDK, or Anthropic's service.

## Optional capabilities with their own gates

- **Offline hash cracking:** accepts only operator-attached files; no network.
- **Exploitation:** off unless an admin enables it for the engagement; scope applies;
  every module needs explicit human approval; organisation must be enrolled in
  Anthropic's Cyber Verification Program.
- **Update check:** off by default; when allowed it makes one request to GitHub only
  when an admin asks, reports a version, and installs nothing.

## Known gaps

This is a draft written before the open-source security review is complete. The
review's findings will be added here.
