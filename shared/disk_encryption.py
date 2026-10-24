#!/usr/bin/env python3
"""disk_encryption.py — is the data root encrypted at rest, and how?

    disk_encryption.py <path>        one JSON object on stdout

{"encrypted": true|false|null, "how": "vault"|"full-disk"|"none"|"unknown",
 "device": "/dev/...", "path": <path>}

The vault is optional (operator decision 2026-10-20) and agents may run on an
unencrypted disk with a standing warning (decision 5, audit run 1). This is the
one answer every place asks: preflight, `agenti verify`, setup and the
dashboard. Encrypted means the block device holding <path>, or any device
under it, is a dm-crypt mapping (LUKS) — read from lsblk's inverse tree, not
guessed from a /dev/mapper name (plain LVM lives there too).
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

VAULT_CONF = Path("/etc/agenti/vault.conf")


def _run(*cmd: str) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=10,
                              check=False).stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return ""


def _vault_mapper() -> str:
    try:
        for line in VAULT_CONF.read_text().splitlines():
            if line.startswith("MAPPER="):
                return line.split("=", 1)[1].strip()
    except OSError:
        pass
    return ""


def status(path) -> dict:
    path = str(path)
    dev = _run("findmnt", "-no", "SOURCE", "-T", path).splitlines()[:1]
    dev = dev[0] if dev else ""
    # A bind mount (a run's own slot inside its unit) reads
    # "/dev/mapper/x[/org/enum/instances/slot]": the device is the part before
    # the bracket. Passed whole to lsblk it failed, and every run on the vault
    # warned that its data was not encrypted.
    dev = dev.split("[", 1)[0]
    if not dev.startswith("/dev/"):
        return {"encrypted": None, "how": "unknown", "device": dev, "path": path}
    types = _run("lsblk", "-nso", "TYPE", dev).split()
    if "crypt" not in types:
        return {"encrypted": False, "how": "none", "device": dev, "path": path}
    mapper = _vault_mapper()
    how = "vault" if mapper and dev in (f"/dev/mapper/{mapper}",) else "full-disk"
    return {"encrypted": True, "how": how, "device": dev, "path": path}


WARNING = ("Data from agents is currently not encrypted: reports, scans, attached files "
           "and the API key are stored as plain files on this disk. Turn on the vault "
           "(Settings → Platform → Vault, or sudo agenti vault enable), or use full-disk "
           "encryption.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: disk_encryption.py <path>")
    print(json.dumps(status(sys.argv[1])))
