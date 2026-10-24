#!/usr/bin/env python3
"""test_tool_catalog.py — the admin tool-allowlist override (CLAUDE.md
"Current plan" phase 6): shared/tool_catalog.py's pure validation/resolution
logic, and shared/tool_settings_store.py's root-side show/set CLI.

    python3 shared/test_tool_catalog.py

No dependencies, no root, no vault. The property that matters most: an admin
can REMOVE anything the agent's own code allows, but can only ADD a name the
reviewed catalog lists — there is no way to type an arbitrary program name
into the effective set, which is what keeps this from becoming a general-
purpose shell. The store CLI is exercised as a real subprocess, exactly as
shared/agenti calls it, against a real temp directory and a real
capabilities.json — not a mock of either.
"""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import tool_catalog as tc  # noqa: E402

PASS = FAIL = 0


def check(label, got, want):
    global PASS, FAIL
    if got == want:
        PASS += 1; print(f"  [ OK ] {label}")
    else:
        FAIL += 1; print(f"  [FAIL] {label}\n         got  {got!r}\n         want {want!r}")


def section(t): print(f"\n=== {t} ===")


CATALOG = {
    "programs": [
        {"name": "curl", "group": "web", "purpose": "fetch", "extra_denied": [r"-X"]},
        {"name": "sslscan", "group": "tls", "purpose": "tls scan", "extra_denied": []},
    ],
    "rules_for_built_in_programs": {"netexec": [r"--exec"]},
    "never_in_this_catalog": ["msfconsole", "sqlmap"],
}
BASELINE = {"nmap", "ping", "netexec"}

# ---------------------------------------------------------------------------
section("catalog_names / catalog_entry")
check("every program name", tc.catalog_names(CATALOG), {"curl", "sslscan"})
check("entry lookup", tc.catalog_entry(CATALOG, "curl")["purpose"], "fetch")
check("unknown name -> None", tc.catalog_entry(CATALOG, "msfconsole"), None)

# ---------------------------------------------------------------------------
section("validate_settings — the actual boundary")
check("empty settings always valid", tc.validate_settings({}, CATALOG, BASELINE),
      {"enable": [], "disable": [], "approvable": []})
check("enable a real catalog name", tc.validate_settings({"enable": ["curl"]}, CATALOG, BASELINE)["enable"], ["curl"])
check("disable a real baseline name", tc.validate_settings({"disable": ["ping"]}, CATALOG, BASELINE)["disable"], ["ping"])
check("enable+disable both sorted and deduped",
      tc.validate_settings({"enable": ["sslscan", "curl", "curl"]}, CATALOG, BASELINE)["enable"],
      ["curl", "sslscan"])

for bad_kw, why in (
    ({"enable": ["msfconsole"]}, "not in the catalog"),
    ({"enable": ["nmap"]}, "nmap is BASELINE, not catalog — cannot be 'enabled'"),
    ({"disable": ["curl"]}, "curl is catalog, not baseline — cannot be 'disabled' this way"),
    ({"disable": ["nonexistent-binary"]}, "never part of the baseline at all"),
):
    try:
        tc.validate_settings(bad_kw, CATALOG, BASELINE); got = "accepted"
    except tc.CatalogError:
        got = "refused"
    check(f"refused: {why}", got, "refused")

for bad in ({"enable": "curl"}, {"enable": [123]}, {"bogus": []}, "not a dict", None):
    try:
        tc.validate_settings(bad, CATALOG, BASELINE); got = "accepted"
    except tc.CatalogError:
        got = "refused"
    check(f"malformed input refused: {bad!r}", got, "refused")

for bad_name in ("../etc/passwd", "nmap; rm -rf /", "nmap && id", "", " ", "a" * 100):
    try:
        tc.validate_settings({"enable": [bad_name]}, CATALOG, BASELINE); got = "accepted"
    except tc.CatalogError:
        got = "refused"
    check(f"not-a-program-name refused: {bad_name!r}", got, "refused")

# ---------------------------------------------------------------------------
section("effective_binaries — narrow-only / catalog-only-addition")
check("no override -> baseline unchanged", tc.effective_binaries(BASELINE, {}, CATALOG), BASELINE)
eff = tc.effective_binaries(BASELINE, {"enable": ["curl"], "disable": ["ping"]}, CATALOG)
check("add one, remove one", eff, {"nmap", "netexec", "curl"})
check("disabling something not in the baseline changes nothing (defence in depth)",
      tc.effective_binaries(BASELINE, {"disable": ["curl"]}, CATALOG), BASELINE)
check("enabling something already in the baseline changes nothing",
      tc.effective_binaries(BASELINE, {"enable": ["nmap"]}, CATALOG), BASELINE)
check("a retired catalog entry (no longer in catalog_names) is silently NOT granted — fail OPEN to less, never more",
      tc.effective_binaries(BASELINE, {"enable": ["long-gone-tool"]}, CATALOG), BASELINE)

# ---------------------------------------------------------------------------
section("purposes and extra denied patterns")
purp = tc.effective_purposes({"nmap": "scanner"}, {"enable": ["curl"], "disable": []}, CATALOG)
check("baseline purpose kept, catalog purpose added", purp, {"nmap": "scanner", "curl": "fetch"})
purp2 = tc.effective_purposes({"nmap": "scanner", "ping": "ping"}, {"disable": ["ping"]}, CATALOG)
check("a disabled baseline program's purpose is dropped", purp2, {"nmap": "scanner"})
check("extra_denied only for ENABLED catalog programs",
      tc.extra_denied_patterns({"enable": ["curl"]}, CATALOG), [r"-X"])
check("not for a catalog program that was never enabled",
      tc.extra_denied_patterns({"enable": []}, CATALOG), [])
check("builtin rule applies only while that program is in the effective set",
      tc.builtin_extra_denied(CATALOG, {"nmap", "netexec"}), [r"--exec"])
check("...and not once it's removed", tc.builtin_extra_denied(CATALOG, {"nmap"}), [])

# ---------------------------------------------------------------------------
section("load_catalog")
try:
    tc.load_catalog(Path("/no/such/path/here.json")); got = "loaded"
except tc.CatalogError as e:
    got = "refused" if "no tool catalog" in str(e) else str(e)
check("a missing catalog file is a clear error", got, "refused")
_t = Path(tempfile.mkdtemp())
(_t / "tool-catalog.json").write_text(json.dumps(CATALOG))
check("no file of admin additions = none (both modes)",
      (len(tc.load_catalog(_t / "tool-catalog.json")["programs"]),
       len(tc.load_catalog(_t / "tool-catalog.json", strict=True)["programs"])), (2, 2))
(_t / tc.ADMIN_CATALOG_FILENAME).write_text("{ not json")
check("a corrupt additions file counts as none for the admin screens (they can rewrite it)",
      len(tc.load_catalog(_t / "tool-catalog.json")["programs"]), 2)
try:
    tc.load_catalog(_t / "tool-catalog.json", strict=True); got = "loaded"
except tc.CatalogError as e:
    got = "refused" if "additions" in str(e) else str(e)
check("...but strict (what a run uses) refuses it", got, "refused")

# ---------------------------------------------------------------------------
section("the real shared/tool-catalog.json shipped with the project")
real = tc.load_catalog(HERE / "tool-catalog.json")
real_names = tc.catalog_names(real)
check("has at least a handful of reviewed programs", len(real_names) >= 5, True)
never = set(real.get("never_in_this_catalog", []))
check("no overlap between the catalog and its own exclusion list", real_names & never, set())
for n in ("msfconsole", "sqlmap", "hydra", "mimikatz", "crackmapexec"):
    check(f"exploitation tool genuinely absent from the real catalog: {n}", n in real_names, False)
for p in real["programs"]:
    check(f"{p['name']}: has a non-empty purpose", bool(p.get("purpose", "").strip()), True)
    check(f"{p['name']}: extra_denied is a list", isinstance(p.get("extra_denied"), list), True)

# ===========================================================================
# tool_settings_store.py — exercised as a real subprocess against a real
# temp organisation directory and a real capabilities.json, exactly as
# shared/agenti's cmd_tool_settings calls it.
# ===========================================================================
section("tool_settings_store.py CLI, as a real subprocess")
tmp = Path(tempfile.mkdtemp())
try:
    # The installed layout: the reviewed catalog in the code folder
    # (AGENTI_LIBDIR), agents built in Settings under the data root's shared/.
    shared_dir = tmp / "shared"
    (shared_dir / "agents" / "enum").mkdir(parents=True)
    (tmp / "lib").mkdir()
    (tmp / "lib" / "tool-catalog.json").write_text(json.dumps(CATALOG))
    env = {**os.environ, "AGENTI_LIBDIR": str(tmp / "lib")}
    (shared_dir / "agents" / "enum" / "capabilities.json").write_text(json.dumps({
        "agent": "enum", "command_line_tools": {"enforced": True, "items": [
            {"name": "nmap", "purpose": "scanner"}, {"name": "ping", "purpose": "reachability"},
            {"name": "netexec", "purpose": "net enum"}]}}))
    org_dir = tmp / "acme"
    (org_dir / "enum").mkdir(parents=True)

    def store(*a):
        r = subprocess.run([sys.executable, str(HERE / "tool_settings_store.py"),
                            "--org-dir", str(org_dir), "--shared-dir", str(shared_dir),
                            "--agent", "enum", *a], capture_output=True, text=True, env=env)
        return json.loads(r.stdout)

    r = store("show")
    check("show with no settings file yet -> baseline == effective",
          (sorted(r["baseline"]), sorted(r["effective"])),
          (["netexec", "nmap", "ping"], ["netexec", "nmap", "ping"]))
    check("...and the catalog is included for the GUI to render", len(r["catalog"]), 2)

    r = store("set", "--enable", "curl", "--disable", "ping", "--by", "alice")
    check("set succeeds and reports what changed", (sorted(r["added"]), sorted(r["removed"])), (["curl"], ["ping"]))
    check("unchanged is false on a real change", r["unchanged"], False)

    r = store("set", "--enable", "curl", "--disable", "ping", "--by", "mallory-but-unchanged")
    check("saving the identical settings again is a no-op (and does not record a new history row "
          "under a different name)", r["unchanged"], True)

    r = store("show")
    check("the override persisted to disk and is read back", sorted(r["effective"]), ["curl", "netexec", "nmap"])
    check("extra denied patterns include both the enabled catalog program's own rule AND "
          "netexec's builtin rule (netexec is still part of the effective set)",
          sorted(r["extra_denied_patterns"]), sorted([r"-X", r"--exec"]))

    hist = store("show", "-n", "5")["history"]
    check("history is newest-first and records who", hist[0]["by"], "alice")
    check("only the ONE real change is recorded — the identical no-op above left no trace", len(hist), 1)

    r = store("set", "--enable", "sslscan", "--disable", "ping", "--by", "bob")
    check("a genuinely different change creates a second history row", r["unchanged"], False)
    check("sslscan added, curl no longer requested -> curl drops out of effective",
          sorted(store("show")["effective"]), ["netexec", "nmap", "sslscan"])
    hist = store("show", "-n", "5")["history"]
    check("now two real changes are recorded, newest first", [h["by"] for h in hist], ["bob", "alice"])
    store("set", "--enable", "curl", "--disable", "ping", "--by", "alice")  # restore for the rest of the file

    r = store("set", "--enable", "msfconsole", "--by", "mallory")
    check("a CLI attempt to add a non-catalog program fails loudly, writes nothing",
          r.get("ok"), False)
    r2 = store("show")
    check("...and the settings file is untouched by the refused attempt", sorted(r2["effective"]), ["curl", "netexec", "nmap"])

    # A workspace/no-shell agent (no command_line_tools.enforced) is refused
    # cleanly, not with a crash — it has nothing here to narrow or extend.
    (shared_dir / "agents" / "noshell").mkdir(parents=True)
    (shared_dir / "agents" / "noshell" / "capabilities.json").write_text(
        json.dumps({"agent": "noshell", "command_line_tools": {"enforced": False, "items": []}}))
    (org_dir / "noshell").mkdir()
    r = subprocess.run([sys.executable, str(HERE / "tool_settings_store.py"),
                        "--org-dir", str(org_dir), "--shared-dir", str(shared_dir),
                        "--agent", "noshell", "show"], capture_output=True, text=True, env=env)
    out = json.loads(r.stdout)
    check("an agent with no enforced allow-list gets a clear, specific refusal",
          "no enforced shell allow-list" in out.get("error", ""), True)

    # A corrupt settings file stops runs; the admin must still be able to see
    # that and replace it by saving.
    (org_dir / "enum" / "tool-settings.json").write_text("{ broken")
    r = store("show")
    check("show still opens on a corrupt settings file and says runs refuse until it is saved",
          (r.get("ok"), "refuse to start" in (r.get("settings_error") or "")), (True, True))
    r = store("set", "--disable", "ping", "--by", "alice")
    check("saving replaces the corrupt file", (r.get("ok"), r.get("unchanged"), r.get("settings_error")),
          (True, False, None))
    check("...with the new settings", json.loads((org_dir / "enum" / "tool-settings.json").read_text())["disable"],
          ["ping"])
finally:
    import shutil
    shutil.rmtree(tmp, ignore_errors=True)


section("F39: versioned and variant names of blocked programs are blocked too")
import tool_catalog as _tc  # noqa: E402
check("python3.14, vim.basic, nc.openbsd, tclsh8.6, php8.2, sqlite3 all refused",
      [n for n in ("python3.14", "vim.basic", "nc.openbsd", "tclsh8.6", "php8.2", "sqlite3")
       if not _tc.is_blocked(n)], [])
check("real recon/analysis tools are not caught by the version rule",
      [n for n in ("nmap", "testssl.sh", "enum4linux-ng", "impacket-GetUserSPNs", "tshark", "hashcat",
                   "snmpwalk", "onesixtyone", "masscan", "theHarvester") if _tc.is_blocked(n)], [])
try:
    _tc.validate_entry({"name": "python3.14", "purpose": "x"}, {"programs": []}); _res = "accepted"
except _tc.CatalogError as e:
    _res = "refused" if "never be offered" in str(e) else str(e)
check("the catalog's Add refuses python3.14 by name", _res, "refused")


section("a program is found under the name Kali installs it as")
from unittest.mock import patch as _patch  # noqa: E402
with _patch("shutil.which", lambda n, path=None: "/usr/bin/impacket-GetUserSPNs" if n == "impacket-GetUserSPNs" else None):
    check("GetUserSPNs.py is found as impacket-GetUserSPNs", _tc.which_program("GetUserSPNs.py"), "/usr/bin/impacket-GetUserSPNs")
    check("a program with no other name is still just missing", _tc.which_program("nosuchtool"), None)

print(f"\n{'=' * 52}\n  {PASS} passed, {FAIL} failed\n{'=' * 52}")
sys.exit(1 if FAIL else 0)
