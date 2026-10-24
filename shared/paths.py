"""paths.py — where Agenti's files live (docs/packaging.md § Layout).

The Python half of shared/paths.sh: the same names, the same defaults, the
same environment overrides, kept equal by test_paths.py. Read at call time,
not import time, so a test (or a caller with --root) can point it elsewhere.
"""
import os
from pathlib import Path


def libdir() -> Path:
    return Path(os.environ.get("AGENTI_LIBDIR", "/usr/lib/agenti"))


def runtime() -> Path:
    return Path(os.environ.get("AGENTI_RUNTIME", "/usr/lib/agenti-runtime"))


def state() -> Path:
    return Path(os.environ.get("AGENTI_STATE", "/var/lib/agenti"))


def data_root() -> Path:
    return Path(os.environ.get("AGENTI_ROOT", str(state() / "data")))


def etc() -> Path:
    return Path(os.environ.get("AGENTI_ETC", "/etc/agenti"))


def agenti_bin() -> Path:
    return Path(os.environ.get("AGENTI_BIN", "/usr/bin/agenti"))


def iam_db() -> Path:
    return Path(os.environ.get("AGENTI_IAM_DB", str(state() / "iam.db")))


def runtime_db() -> Path:
    return Path(os.environ.get("AGENTI_RUNTIME_DB", str(state() / "authd" / "runtime.db")))


def shipped_agents() -> Path:
    return libdir() / "agents"


def built_agents(root=None) -> Path:
    return Path(root if root is not None else data_root()) / "shared" / "agents"


def master_dir(agent: str, root=None) -> Path:
    """The one copy of an agent's code: the package's own if it ships one,
    else the one an admin built in Settings (data root)."""
    shipped = shipped_agents() / agent
    return shipped if shipped.is_dir() else built_agents(root) / agent


def relay_addr() -> str:
    """host:port of the local relay IP-scoped runs reach Anthropic through."""
    return os.environ.get("AGENTI_RELAY_ADDR", "127.0.0.1:8429")


def catalog_file() -> Path:
    """The reviewed program catalog (read-only, shipped with the code)."""
    return libdir() / "tool-catalog.json"


def vault_enabled() -> bool:
    return (etc() / "vault.conf").is_file()
