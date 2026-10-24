#!/usr/bin/env python3
"""test_disk_encryption.py — the one answer to "is the data encrypted at rest?"
(shared/disk_encryption.py, audit run 1 decision 5).

    python3 shared/test_disk_encryption.py

findmnt and lsblk are replaced by scripted answers, so this checks the logic
on any machine; one call on the real "/" checks it runs here at all."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import disk_encryption as de  # noqa: E402

PASS = FAIL = 0


def check(label, got, want):
    global PASS, FAIL
    if got == want:
        PASS += 1; print(f"  [ OK ] {label}")
    else:
        FAIL += 1; print(f"  [FAIL] {label}\n         got  {got!r}\n         want {want!r}")


def scripted(source, types, mapper=""):
    def run(*cmd):
        return source if cmd[0] == "findmnt" else "\n".join(types)
    de._run = run
    de._vault_mapper = lambda: mapper


real_run, real_mapper = de._run, de._vault_mapper
scripted("/dev/sda2", ["part", "disk"])
check("a plain partition is not encrypted", (de.status("/x")["encrypted"], de.status("/x")["how"]), (False, "none"))
scripted("/dev/mapper/vg-root", ["lvm", "part", "disk"])
check("plain LVM under /dev/mapper is NOT taken for encryption", de.status("/x")["how"], "none")
scripted("/dev/mapper/vg-root", ["lvm", "crypt", "part", "disk"])
check("LVM on LUKS (full-disk encryption) is encrypted", de.status("/x")["how"], "full-disk")
scripted("/dev/mapper/agenti_vault", ["crypt", "loop"], mapper="agenti_vault")
check("the Agenti vault is recognised as the vault", de.status("/x")["how"], "vault")
scripted("tmpfs", [])
check("a source that is not a block device: unknown, not 'encrypted'",
      (de.status("/x")["encrypted"], de.status("/x")["how"]), (None, "unknown"))
def _bind(*cmd):
    if cmd[0] == "findmnt":
        return "/dev/mapper/agenti_vault[/org/enum/instances/op1.run-1]"
    return "crypt\nloop" if cmd[-1] == "/dev/mapper/agenti_vault" else ""
de._run, de._vault_mapper = _bind, (lambda: "agenti_vault")
check("audit run 2: a run's own slot (a bind mount, 'dev[/path]') on the vault is the vault",
      (de.status("/x")["encrypted"], de.status("/x")["how"], de.status("/x")["device"]),
      (True, "vault", "/dev/mapper/agenti_vault"))
de._run, de._vault_mapper = real_run, real_mapper
check("runs on this machine and answers in the agreed shape",
      set(de.status("/")) >= {"encrypted", "how", "device", "path"}, True)

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
