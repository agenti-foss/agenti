"""
suricata_offline.py — everything specific to running Suricata over an attached
capture, for a file-analysis agent.

Suricata is unlike tshark and capinfos in three ways, and this module is where
they are dealt with so the rest of the code stays generic:

  1. It needs a CONFIG and RULES, which are host files. They are bound
     read-only into the sandbox at fixed paths (see binds()). The model never
     names them: the config is the one shipped beside this file
     (suricata-offline.yaml), `-c` and `--set` are not options it is offered,
     and the rules are whichever set this host has.
  2. It WRITES — eve.json, fast.log, stats.log — so it gets a private log
     directory (the sandbox's only writable path), not just stdout.
  3. Its output is large and structured (one JSON event per line), so the
     model is given a summary and the files to search, not a flood.

WHERE THE RULES COME FROM
  * /var/lib/suricata/rules/suricata.rules — what `sudo suricata-update`
    writes (the Emerging Threats Open set and others). If it exists, this wins.
  * else /etc/suricata/rules/*.rules — the event rules the suricata package
    itself ships. They flag protocol anomalies (a malformed SMB request, a bad
    checksum, a DNS oddity). They are NOT threat signatures: they will not
    say "this is MS17-010". The summary says so, in those words, because an
    empty alert list from a rule set that cannot have matched is not good news.
  The website never downloads rules. Fetching third-party content onto the
  host is an operator act (`sudo suricata-update`), documented in
  docs/help/analysing-files.md.
"""
from __future__ import annotations

import json
import re
import shutil
from collections import Counter
from pathlib import Path

__all__ = ["CONFIG_PATH", "available", "rules_source", "binds", "harvest",
           "summarise", "warnings_only", "LOG_FILES", "RULES_DEST", "CFG_DEST", "OUT_DEST"]

CONFIG_PATH = Path(__file__).resolve().with_name("suricata-offline.yaml")

# Where things appear inside the sandbox (these are the paths the config names).
CFG_DEST = "/cfg"
RULES_DEST = "/rules"
OUT_DEST = "/out"

_PACKAGE_RULES = Path("/etc/suricata/rules")
_UPDATED_RULES = Path("/var/lib/suricata/rules")
# classification.config / reference.config / threshold.config: the package's own; Suricata
# refuses to start without the first two and warns on every run about the third.
_SHARED_CONFIGS = ("classification.config", "reference.config", "threshold.config")
_SYSTEM_CONFIG_DIR = Path("/etc/suricata")

# What a run leaves behind, and what each is for.
LOG_FILES = {
    "eve.json": "one JSON event per line: alerts, flows, and per-protocol records (dns, http, tls, smb, ...)",
    "fast.log": "one line per alert",
    "stats.log": "engine counters",
    "suricata.log": "Suricata's own log",
}

_MAX_EVE_BYTES = 256 * 1024 * 1024     # summarise at most this much of eve.json
_TOP = 12


def available() -> bool:
    """Can a run be set up on this host: the config shipped with Agenti, and
    the shared config files Suricata expects."""
    return CONFIG_PATH.is_file() and all((_SYSTEM_CONFIG_DIR / n).is_file() for n in _SHARED_CONFIGS)


def rules_source() -> tuple[Path | None, str]:
    """(directory to bind at /rules, a one-line description of what it holds)."""
    upd = _UPDATED_RULES / "suricata.rules"
    try:
        if upd.is_file() and upd.stat().st_size > 0:
            return _UPDATED_RULES, ("rules from suricata-update (threat signatures)")
    except OSError:
        pass
    try:
        if any(_PACKAGE_RULES.glob("*.rules")):
            return _PACKAGE_RULES, (
                "only the rules the suricata package ships, which flag protocol anomalies, "
                "NOT threat signatures — a quiet alert list here does not mean the traffic is clean. "
                "The operator can install the Emerging Threats set with `sudo suricata-update`")
    except OSError:
        pass
    return None, "no rule files are installed on this host, so there is no detection — only protocol logging"


def binds(empty_rules_dir: Path | None = None) -> list[tuple[str, str]]:
    """(host path, sandbox path) read-only mappings for one run. `empty_rules_dir`
    is an empty directory to bind when the host has no rules at all."""
    rules, _ = rules_source()
    if rules is None:
        if empty_rules_dir is None:
            raise FileNotFoundError("no Suricata rules on this host and no empty directory given")
        rules = empty_rules_dir
    out = [(str(CONFIG_PATH), f"{CFG_DEST}/suricata.yaml"), (str(rules), RULES_DEST)]
    out += [(str(_SYSTEM_CONFIG_DIR / n), f"{CFG_DEST}/{n}") for n in _SHARED_CONFIGS]
    return out


def harvest(logdir: Path, dest: Path, stem: str) -> dict[str, Path]:
    """Move the files a run produced out of its private log directory into the
    run's saved-output folder as <stem>_<name>. Returns {original name: path}.
    Anything else in the directory is ignored and removed with it."""
    got: dict[str, Path] = {}
    for name in LOG_FILES:
        src = logdir / name
        if src.is_file() and not src.is_symlink():
            target = dest / f"{stem}_{name}"
            shutil.move(str(src), str(target))
            got[name] = target
    shutil.rmtree(logdir, ignore_errors=True)
    return got


def warnings_only(console: str) -> str:
    """Suricata prints a line per thing it does ("i: ...") — on STDOUT, not
    stderr. Only its warnings and errors are worth a model's attention."""
    return "\n".join(ln for ln in console.splitlines() if re.match(r"^[WEC]: ", ln)).strip()


def _packets_read(console: str) -> str | None:
    m = re.search(r"read (\d+) files?, (\d+) packets, (\d+) bytes", console)
    return f"{int(m.group(2)):,} packets ({int(m.group(3)):,} bytes)" if m else None


def summarise(eve: Path | None, *, console: str = "", rules_note: str = "") -> str:
    """A short, honest digest of one run for the model: how much it read, what
    rules it had, the alerts grouped by signature, and the shape of the rest.
    Never raises — a damaged eve.json yields a shorter summary, not an error."""
    lines: list[str] = []
    pk = _packets_read(console)
    lines.append(f"Suricata read {pk}." if pk else "Suricata ran.")
    if rules_note:
        lines.append(f"Rules: {rules_note}.")

    types: Counter[str] = Counter()
    alerts: dict[tuple, dict] = {}
    anomalies: Counter[str] = Counter()
    bad_lines = 0
    truncated = False
    if eve is not None and eve.is_file():
        read = 0
        try:
            with open(eve, "rb") as fh:
                for raw in fh:
                    read += len(raw)
                    if read > _MAX_EVE_BYTES:
                        truncated = True
                        break
                    try:
                        e = json.loads(raw)
                    except ValueError:
                        bad_lines += 1
                        continue
                    if not isinstance(e, dict):
                        continue
                    et = str(e.get("event_type", "?"))
                    types[et] += 1
                    if et == "alert" and isinstance(e.get("alert"), dict):
                        a = e["alert"]
                        key = (str(a.get("signature", "?")), a.get("severity"), a.get("signature_id"))
                        slot = alerts.setdefault(key, {"n": 0, "first": None})
                        slot["n"] += 1
                        if slot["first"] is None:
                            slot["first"] = (f"{e.get('src_ip', '?')}:{e.get('src_port', '')} -> "
                                             f"{e.get('dest_ip', '?')}:{e.get('dest_port', '')}",
                                             str(e.get("timestamp", ""))[:19])
                    elif et == "anomaly" and isinstance(e.get("anomaly"), dict):
                        an = e["anomaly"]
                        anomalies[str(an.get("event") or an.get("type") or "?")] += 1
        except OSError:
            pass

    total_alerts = sum(v["n"] for v in alerts.values())
    lines.append("")
    if total_alerts:
        lines.append(f"Alerts: {total_alerts} ({len(alerts)} distinct). Most frequent first:")
        for (sig, sev, sid), v in sorted(alerts.items(), key=lambda kv: -kv[1]["n"])[:_TOP]:
            src, ts = v["first"]
            lines.append(f"  {v['n']:>5} x  sev {sev}  [{sid}] {sig}   first: {src}  {ts}")
        if len(alerts) > _TOP:
            lines.append(f"  ... and {len(alerts) - _TOP} more signatures (search eve.json for event_type alert)")
    else:
        lines.append("Alerts: none.")
    if anomalies:
        lines.append("Anomalies: " + ", ".join(f"{k} x{v}" for k, v in anomalies.most_common(_TOP)))
    if types:
        lines.append("Events by type: " + ", ".join(f"{k} {v:,}" for k, v in types.most_common()))
    if truncated:
        lines.append(f"(only the first {_MAX_EVE_BYTES // (1024 * 1024)} MB of eve.json was summarised)")
    if bad_lines:
        lines.append(f"({bad_lines} unreadable line(s) in eve.json were skipped)")
    return "\n".join(lines)
