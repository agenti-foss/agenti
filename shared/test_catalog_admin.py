#!/usr/bin/env python3
"""test_catalog_admin.py — admin-added command-line programs (catalog_admin.py
and tool_catalog.py's overlay + block-list). No root, no vault.

    python3 shared/test_catalog_admin.py
"""
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import catalog_admin as ca  # noqa: E402
import recon_programs  # noqa: E402
import tool_catalog as tc  # noqa: E402

# Stand-in programs these tests add get test-only (empty) rule tables, as a
# developer would review real ones in recon_programs.py. "uname" and the
# uninstalled names exercise the installed/shell checks, which run first.
for _n in ("uname", "mytool", "ok-tool", "agenti-no-such-program"):
    recon_programs.PROGRAMS[_n] = recon_programs.Program(_n, {}, positional="targets")

PASS = FAIL = 0


def check(label, got, want):
    global PASS, FAIL
    if got == want:
        PASS += 1; print(f"  [ OK ] {label}")
    else:
        FAIL += 1; print(f"  [FAIL] {label}\n         got  {got!r}\n         want {want!r}")


def refused(fn, needle=""):
    try:
        fn()
    except tc.CatalogError as e:
        return needle.lower() in str(e).lower()
    return False


# The installed layout (docs/packaging.md): the reviewed catalog ships in the
# code folder, read-only; what an admin adds lives in the data root.
root = Path(tempfile.mkdtemp(prefix="agenti-test-catalog-"))
lib = root / "lib"
lib.mkdir()
(root / "shared").mkdir()
os.environ["AGENTI_LIBDIR"] = str(lib)
REVIEWED = lib / "tool-catalog.json"
OVERLAY = root / "shared" / tc.ADMIN_CATALOG_FILENAME
shutil.copy(HERE / "tool-catalog.json", REVIEWED)
shutil.copy(HERE / "tool-catalog.json", root / "ref.json")
orig_chown = os.chown
os.chown = lambda *a, **k: None

print("\n=== the block-list ===")
base = ca._base(root)
for name in ("bash", "sh", "python3", "perl", "sudo", "find", "xargs", "env", "rm", "nc", "ssh", "gcc", "awk", "sed", "BASH"):
    check(f"'{name}' can never be offered", refused(lambda n=name: tc.validate_entry({"name": n, "purpose": "x"}, base), "never be offered"), True)
never = [n for n in base.get("never_in_this_catalog", []) if isinstance(n, str)]
check("every name on the catalog's never-list is refused too",
      all(refused(lambda n=n: tc.validate_entry({"name": n, "purpose": "x"}, base)) for n in never), True)
check("a path is not a program name", refused(lambda: tc.validate_entry({"name": "../bin/ls", "purpose": "x"}, base), "letters"), True)
check("a name with a space is refused", refused(lambda: tc.validate_entry({"name": "ls -la", "purpose": "x"}, base)), True)
check("a purpose is required", refused(lambda: tc.validate_entry({"name": "uname", "purpose": " "}, base), "for"), True)
check("a broken pattern is refused", refused(lambda: tc.validate_entry({"name": "uname", "purpose": "x", "extra_denied": ["("]}, base), "pattern"), True)
check("too many patterns refused", refused(lambda: tc.validate_entry({"name": "uname", "purpose": "x", "extra_denied": ["a"] * 21}, base), "20"), True)
check("an unknown field is refused", refused(lambda: tc.validate_entry({"name": "uname", "purpose": "x", "run": "x"}, base), "unknown"), True)
check("a reviewed name cannot be added again", refused(lambda: ca.check(root, {"name": "curl", "purpose": "x"}), "already"), True)

print("\n=== installed, or refused with the install command ===")
check("an uninstalled program names the apt command",
      refused(lambda: ca.check(root, {"name": "agenti-no-such-program", "purpose": "x"}), "sudo apt install agenti-no-such-program"), True)
tmpbin = Path(tempfile.mkdtemp()); (tmpbin / "mytool").symlink_to(shutil.which("sh"))
real = tc.SEARCH_PATH; tc.SEARCH_PATH = str(tmpbin)
check("a program that RESOLVES to a shell is refused under another name",
      refused(lambda: ca.check(root, {"name": "mytool", "purpose": "x"}), "same program"), True)
tc.SEARCH_PATH = real

print("\n=== add / list / load / update / remove ===")
_saved_uname = recon_programs.PROGRAMS.pop("uname")
check("an installed program with no reviewed argument rules is refused, and says why",
      refused(lambda: ca.check(root, {"name": "uname", "purpose": "x"}), "no reviewed argument rules"), True)
recon_programs.PROGRAMS["uname"] = _saved_uname
out = ca.add(root, {"name": "uname", "group": "system", "purpose": "show the kernel name", "extra_denied": ["-a"]}, by="alice")
check("added", out["added"], "uname")
check("stored in the separate admin file, reviewed file untouched",
      (json.loads(REVIEWED.read_text()) == json.loads((root / "ref.json").read_text()),
       OVERLAY.is_file()), (True, True))
check("nothing is written into the code folder", sorted(f.name for f in lib.iterdir()), ["tool-catalog.json"])
lst = ca.listing(root)
row = next(r for r in lst["programs"] if r["name"] == "uname")
check("it lists as admin-added and installed, with who added it", (row["source"], row["installed"], row["added_by"]), ("admin", True, "alice"))
check("reviewed programs list as reviewed", next(r for r in lst["programs"] if r["name"] == "curl")["source"], "reviewed")
loaded = tc.load_catalog(REVIEWED, OVERLAY)
check("an agent's load_catalog sees it", "uname" in tc.catalog_names(loaded), True)
check("...with its blocked patterns", tc.catalog_entry(loaded, "uname")["extra_denied"], ["-a"])
check("a duplicate add is refused", refused(lambda: ca.add(root, {"name": "uname", "purpose": "x"}, by="a"), "already"), True)
ca.update(root, {"name": "uname", "group": "system", "purpose": "kernel name only", "extra_denied": []}, by="bob")
row = next(r for r in ca.listing(root)["programs"] if r["name"] == "uname")
check("update changes the entry and keeps the original adder", (row["purpose"], row["added_by"]), ("kernel name only", "alice"))
check("a reviewed program cannot be updated here", refused(lambda: ca.update(root, {"name": "curl", "purpose": "x"}, by="a"), "reviewed"), True)
check("a reviewed program cannot be removed here", refused(lambda: ca.remove(root, "curl", by="a"), "reviewed"), True)

print("\n=== a hand-edited overlay can never grant what the rules refuse ===")
ov = OVERLAY
d = json.loads(ov.read_text())
d["programs"] += [{"name": "bash", "purpose": "sneaky"}, {"name": "curl", "purpose": "dup"}, {"name": "ok-tool", "purpose": "x", "extra_denied": ["("]}]
ov.write_text(json.dumps(d))
names = tc.catalog_names(tc.load_catalog(REVIEWED, OVERLAY))
check("shell, duplicate and broken-pattern entries are skipped on load", ("bash" in names, "ok-tool" in names, "uname" in names), (False, False, True))
d["programs"] = [e for e in d["programs"] if e["name"] == "uname"]; ov.write_text(json.dumps(d))

print("\n=== removal is blocked while an agent still uses it ===")
td = root / "acme" / "enum"; td.mkdir(parents=True)
(td / "tool-settings.json").write_text(json.dumps({"enable": ["uname"]}))
check("still switched on -> refused, naming where", refused(lambda: ca.remove(root, "uname", by="a"), "acme/enum"), True)
(td / "tool-settings.json").write_text(json.dumps({"enable": []}))
check("switched off -> removed", ca.remove(root, "uname", by="alice")["removed"], "uname")
check("it's gone from the catalog", "uname" in tc.catalog_names(tc.load_catalog(REVIEWED, OVERLAY)), False)
h = ca.history(root, 10)["history"]
check("history keeps add, update, remove (newest first)", [r["action"] for r in h], ["remove", "update", "add"])

print(f"\n{'=' * 52}\n  {PASS} passed, {FAIL} failed\n{'=' * 52}")
shutil.rmtree(root, ignore_errors=True)
sys.exit(1 if FAIL else 0)
