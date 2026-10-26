#!/usr/bin/env python3
"""test-setup.py — drive `sudo agenti setup` the way a person does, in a clean
install (test-install.sh runs it as root in a fresh container).

Reproduces the 2026-10-26 fresh-Kali report: a too-short password used to be
refused AFTER the account was created, and the next setup skipped the
half-made account as "already exists", so nobody could sign in. Now:
  * a half-made admin left by an earlier setup is finished, not skipped;
  * a short password is refused and asked again, before anything changes;
  * the API key can be skipped.
Prints one line per answer it gives; exits 1 if setup did not finish.
"""
import os
import pty
import re
import select
import sys
import time

ANSWERS = [  # (what setup asks, what we type)
    (r"choose a password", "kali"),                 # 4 characters: refused, asked again
    (r"choose a password", "Long-enough-1"),
    (r"type it again", "Long-enough-1"),
    (r"turn the vault on\?", "n"),
    (r"set it now\?", "n"),                          # skip the API key
    (r"choose 1, 2 or 3", "1"),
]


def main() -> int:
    pid, fd = pty.fork()
    if pid == 0:
        os.execvp("agenti", ["agenti", "setup"])
    out, step, deadline = b"", 0, time.time() + 120
    while time.time() < deadline:
        r, _, _ = select.select([fd], [], [], 1)
        if r:
            try:
                chunk = os.read(fd, 4096)
            except OSError:
                break
            if not chunk:
                break
            out += chunk
        text = out.decode(errors="replace")
        if step < len(ANSWERS) and len(re.findall(ANSWERS[step][0], text)) > sum(
                1 for p, _ in ANSWERS[:step] if p == ANSWERS[step][0]):
            os.write(fd, (ANSWERS[step][1] + "\n").encode())
            print(f"  answered {ANSWERS[step][0]!r}")
            step += 1
    _, status = os.waitpid(pid, 0)
    text = out.decode(errors="replace")
    sys.stdout.write(text[-1500:] if os.environ.get("SHOW") else "")
    checks = {
        "finished the half-made admin": "was created by an earlier setup but has no password yet" in text,
        "refused the 4-character password and asked again": "it needs at least 8" in text,
        "the API key was skipped": "skipped — agent runs will refuse to start until a key is set" in text,
        "setup reached the end": "Done." in text and os.waitstatus_to_exitcode(status) == 0,
    }
    for k, v in checks.items():
        print(f"  {'[ OK ]' if v else '[FAIL]'} setup {k}")
    if not all(checks.values()):
        print(text[-3000:])
    return 0 if all(checks.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
