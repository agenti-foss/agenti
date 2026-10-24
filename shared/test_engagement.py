#!/usr/bin/env python3
"""test_engagement.py — the TENANT engagement record (CLAUDE.md "Current
plan", phase 1 of the cybersecurity refocus): shared/engagement_context.py's
schema, validators, per-kind view, content digest and loaders, and
shared/engagement_store.py's set/approve/show/history CLI.

    python3 shared/test_engagement.py

No dependencies, no root, no vault. Two properties matter most and are
pinned here because a regression in either would be SILENT: (1) an agent
gets only ITS kind's scope entries from the shared record (a CIDR agent
must never inherit a domain, nor vice versa), and (2) an approval is bound
to the record's CONTENT — editing a single scope entry, date or note after
approval must make approval_status().current false, or the approval gate
would be theatre. The store CLI is exercised as a real subprocess, exactly
as shared/agenti calls it.
"""
import json
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import engagement_context as ec  # noqa: E402

PASS = FAIL = 0


def check(label, got, want):
    global PASS, FAIL
    if got == want:
        PASS += 1; print(f"  [ OK ] {label}")
    else:
        FAIL += 1; print(f"  [FAIL] {label}\n         got  {got!r}\n         want {want!r}")


def section(t): print(f"\n=== {t} ===")


def refuses(label, fn, *needle):
    try:
        fn()
    except ec.EngagementError as e:
        ok = all(n in str(e) for n in needle)
        check(f"{label} (refused: {str(e)[:70]}…)" if ok else f"{label} — refused, but message lacks {needle}: {e}", ok, True)
    except Exception as e:  # noqa: BLE001
        check(f"{label} — wrong exception type {type(e).__name__}: {e}", False, True)
    else:
        check(f"{label} — was NOT refused", False, True)


def base(**over) -> dict:
    d = {
        "engagement_id": "ACME-01", "client": "Acme", "authorizing_party": "Jane Doe",
        "authorizing_title": "CISO", "authorization_ref": "SOW-1",
        "valid_from": "2026-01-01", "valid_until": "2026-12-31",
        "emergency_contact": "soc@acme.example", "notes": "",
        "scope": {"cidr": {"in_scope": ["10.0.0.0/24 (lab)"], "out_of_scope": ["10.0.5.0/24 (payroll)"]},
                  "domain": {"in_scope": ["acme.example (web)"], "out_of_scope": []}},
    }
    d.update(over)
    return d


tmp = Path(tempfile.mkdtemp(prefix="agenti-test-engagement-"))
try:
    section("validators")
    check("valid_iso_date accepts a real date", ec.valid_iso_date("2026-02-28", "x"), "2026-02-28")
    refuses("valid_iso_date refuses a non-date", lambda: ec.valid_iso_date("soon", "valid_from"), "valid_from", "YYYY-MM-DD")
    refuses("valid_iso_date refuses a non-string", lambda: ec.valid_iso_date(20260101, "valid_from"), "valid_from")
    refuses("valid_iso_date refuses Feb 30", lambda: ec.valid_iso_date("2026-02-30", "valid_until"), "valid_until")
    check("valid_scope_entry cidr: CIDR + label ok", ec.valid_scope_entry(" 10.0.0.0/24 (lab) ", "cidr"), "10.0.0.0/24 (lab)")
    check("valid_scope_entry cidr: bare host ok", ec.valid_scope_entry("192.0.2.199", "cidr"), "192.0.2.199")
    refuses("valid_scope_entry cidr refuses a domain", lambda: ec.valid_scope_entry("acme.example", "cidr"), "IP/CIDR")
    check("valid_scope_entry domain ok", ec.valid_scope_entry("mail.acme.example (mx)", "domain"), "mail.acme.example (mx)")
    refuses("valid_scope_entry domain refuses a CIDR", lambda: ec.valid_scope_entry("10.0.0.0/24", "domain"), "domain")
    refuses("valid_scope_entry domain refuses a bad label", lambda: ec.valid_scope_entry("-bad.example", "domain"), "domain")
    refuses("valid_scope_entry refuses blank", lambda: ec.valid_scope_entry("   ", "cidr"), "blank")
    refuses("valid_scope_entry refuses an unknown kind", lambda: ec.valid_scope_entry("x", "ports"), "unknown scope kind")

    section("normalize_record(): happy path fills defaults, keeps audit fields")
    rec = ec.normalize_record(base(updated_at=1.0, updated_by="alice"))
    check("engagement_id kept", rec["engagement_id"], "ACME-01")
    check("capture_payloads defaults False", rec["capture_payloads"], False)
    check("retention_days defaults 0", rec["retention_days"], 0)
    check("redact defaults []", rec["redact"], [])
    check("both kinds present", sorted(rec["scope"]), ["cidr", "domain"])
    check("entries stripped", rec["scope"]["cidr"]["in_scope"], ["10.0.0.0/24 (lab)"])
    check("audit fields preserved", (rec["updated_at"], rec["updated_by"]), (1.0, "alice"))
    only_cidr = ec.normalize_record(base(scope={"cidr": {"in_scope": ["10.0.0.0/24"]}}))
    check("a record with only a cidr scope is valid; domain filled empty", only_cidr["scope"]["domain"], {"in_scope": [], "out_of_scope": []})
    check("out_of_scope is advisory text: free text accepted",
          ec.normalize_record(base(scope={"cidr": {"in_scope": ["10.0.0.0/24"], "out_of_scope": ["the operator's own SSH session"]}}))["scope"]["cidr"]["out_of_scope"],
          ["the operator's own SSH session"])

    section("normalize_record(): every refusal, against the real function")
    refuses("not an object", lambda: ec.normalize_record([1]), "JSON object")
    refuses("unknown top-level key", lambda: ec.normalize_record(base(colour="red")), "unknown field", "colour")
    refuses("bad engagement_id (space)", lambda: ec.normalize_record(base(engagement_id="LAB 01")), "engagement_id")
    refuses("bad engagement_id (leading dash)", lambda: ec.normalize_record(base(engagement_id="-x")), "engagement_id")
    refuses("empty client", lambda: ec.normalize_record(base(client="  ")), "client cannot be empty")
    refuses("missing authorizing_party", lambda: ec.normalize_record({k: v for k, v in base().items() if k != "authorizing_party"}), "authorizing_party")
    refuses("bad valid_from", lambda: ec.normalize_record(base(valid_from="2026-13-01")), "valid_from")
    refuses("from after until", lambda: ec.normalize_record(base(valid_from="2026-12-31", valid_until="2026-01-01")), "after valid_until")
    refuses("no scope at all", lambda: ec.normalize_record(base(scope={})), "authorizes nothing")
    refuses("both kinds empty", lambda: ec.normalize_record(base(scope={"cidr": {"in_scope": []}, "domain": {"in_scope": []}})), "authorizes nothing")
    refuses("unknown scope kind", lambda: ec.normalize_record(base(scope={"ports": {"in_scope": ["22"]}})), "unknown scope kind", "ports")
    refuses("domain in the cidr list", lambda: ec.normalize_record(base(scope={"cidr": {"in_scope": ["acme.example"]}})), "IP/CIDR")
    refuses("cidr in the domain list", lambda: ec.normalize_record(base(scope={"domain": {"in_scope": ["10.0.0.0/24"]}})), "domain")
    refuses("scope kind not an object", lambda: ec.normalize_record(base(scope={"cidr": ["10.0.0.0/24"]})), "scope.cidr")
    refuses("unknown key inside a kind", lambda: ec.normalize_record(base(scope={"cidr": {"in_scope": ["10.0.0.0/24"], "allow": []}})), "scope.cidr", "allow")
    refuses("too many entries", lambda: ec.normalize_record(base(scope={"cidr": {"in_scope": [f"10.0.{i}.0/24" for i in range(ec.MAX_SCOPE_ENTRIES + 1)]}})), "too many")
    refuses("negative retention", lambda: ec.normalize_record(base(retention_days=-1)), "negative")
    refuses("retention not an int", lambda: ec.normalize_record(base(retention_days="7")), "retention_days")
    refuses("capture_payloads not a bool", lambda: ec.normalize_record(base(capture_payloads="yes")), "capture_payloads")
    refuses("redact not a list of strings", lambda: ec.normalize_record(base(redact=[1])), "redact")
    refuses("notes too long", lambda: ec.normalize_record(base(notes="x" * (ec.MAX_TEXT_LEN + 1))), "notes", "too long")

    section("record_digest(): content-bound, audit-blind")
    d1 = ec.record_digest(base())
    check("stable across calls", ec.record_digest(base()), d1)
    reordered = dict(reversed(list(base().items())))
    check("key order does not matter", ec.record_digest(reordered), d1)
    check("audit fields do not matter", ec.record_digest(base(updated_at=99.0, updated_by="bob", updated_via="api")), d1)
    check("entry whitespace does not matter (normalized first)",
          ec.record_digest(base(scope={"cidr": {"in_scope": ["  10.0.0.0/24 (lab)  "], "out_of_scope": ["10.0.5.0/24 (payroll)"]},
                                      "domain": {"in_scope": ["acme.example (web)"], "out_of_scope": []}})), d1)
    check("one more CIDR changes it", ec.record_digest(base(scope={"cidr": {"in_scope": ["10.0.0.0/24 (lab)", "10.0.1.0/24"], "out_of_scope": ["10.0.5.0/24 (payroll)"]}, "domain": {"in_scope": ["acme.example (web)"], "out_of_scope": []}})) != d1, True)
    check("a date change changes it", ec.record_digest(base(valid_until="2027-01-01")) != d1, True)
    check("a notes change changes it", ec.record_digest(base(notes="fragile DC")) != d1, True)
    check("a label change on an entry changes it (the label is part of what was approved)",
          ec.record_digest(base(scope={"cidr": {"in_scope": ["10.0.0.0/24 (prod)"], "out_of_scope": ["10.0.5.0/24 (payroll)"]}, "domain": {"in_scope": ["acme.example (web)"], "out_of_scope": []}})) != d1, True)
    check("64 hex chars", (len(d1), all(c in "0123456789abcdef" for c in d1)), (64, True))
    check("policy is excluded from the digest entirely",
          ec.record_digest(base(policy={"max_turns_ceiling": 5, "allowed_models": ["haiku"]})), d1)

    section("policy: _validate_policy/resolve_policy/canonical_model/model_allowed "
            "(CLAUDE.md \"Current plan\" — replaces the retired --dev/commercial split)")
    check("absent policy resolves to the platform default, unchanged",
          ec.resolve_policy(None), ec.PLATFORM_DEFAULT_POLICY)
    check("empty policy object resolves to the platform default too",
          ec.resolve_policy({"policy": {}}), ec.PLATFORM_DEFAULT_POLICY)
    partial = ec.resolve_policy({"policy": {"max_turns_ceiling": 5}})
    check("a partial override narrows just that field", partial["max_turns_ceiling"], 5)
    check("...and leaves every other field at the platform default",
          (partial["max_budget_usd_ceiling"], partial["timeout_s_ceiling"], partial["allowed_models"],
           partial["require_approval"]),
          (ec.PLATFORM_DEFAULT_POLICY["max_budget_usd_ceiling"], ec.PLATFORM_DEFAULT_POLICY["timeout_s_ceiling"],
           ec.PLATFORM_DEFAULT_POLICY["allowed_models"], True))
    check("require_approval=False is honoured", ec.resolve_policy({"policy": {"require_approval": False}})["require_approval"], False)
    check("an empty allowed_models list is treated as unset (falls back to the platform default)",
          ec.resolve_policy({"policy": {"allowed_models": []}})["allowed_models"], ec.PLATFORM_DEFAULT_POLICY["allowed_models"])
    check("canonical_model resolves a curated alias", ec.canonical_model("haiku"), "claude-haiku-4-5-20251001")
    check("canonical_model passes an already-canonical id through unchanged",
          ec.canonical_model("claude-sonnet-5"), "claude-sonnet-5")
    check("canonical_model passes an unrecognized string through unchanged (never invents a model)",
          ec.canonical_model("gpt-4"), "gpt-4")
    only_haiku = {"allowed_models": ["haiku"]}
    check("model_allowed matches by alias", ec.model_allowed("haiku", only_haiku), True)
    check("model_allowed matches the SAME model by its canonical id too",
          ec.model_allowed("claude-haiku-4-5-20251001", only_haiku), True)
    check("model_allowed refuses a model not on the list", ec.model_allowed("sonnet", only_haiku), False)

    refuses("unknown policy field refused", lambda: ec.normalize_record(base(policy={"bogus": 1})), "unknown field", "policy")
    refuses("negative max_turns_ceiling refused", lambda: ec.normalize_record(base(policy={"max_turns_ceiling": -1})), "positive")
    refuses("zero max_turns_ceiling refused (must be positive, not just non-negative)",
            lambda: ec.normalize_record(base(policy={"max_turns_ceiling": 0})), "positive")
    refuses("non-numeric max_budget_usd_ceiling refused", lambda: ec.normalize_record(base(policy={"max_budget_usd_ceiling": "a lot"})), "positive")
    refuses("a bool is not a valid ceiling (bool is a subclass of int in Python)",
            lambda: ec.normalize_record(base(policy={"max_turns_ceiling": True})), "positive")
    refuses("non-bool require_approval refused", lambda: ec.normalize_record(base(policy={"require_approval": "yes"})), "true or false")
    refuses("an unrecognized model name is refused, naming the curated list",
            lambda: ec.normalize_record(base(policy={"allowed_models": ["gpt-4"]})), "unrecognized", "haiku")
    ok_rec = ec.normalize_record(base(policy={"allowed_models": ["haiku", "haiku", "sonnet"]}))
    check("allowed_models is de-duplicated and sorted", ok_rec["policy"]["allowed_models"], ["haiku", "sonnet"])
    check("a canonical model id is also accepted, not just the alias",
          ec.normalize_record(base(policy={"allowed_models": ["claude-opus-5"]}))["policy"]["allowed_models"],
          ["claude-opus-5"])

    section("engagement_from_record(): one agent sees only ITS kind")
    cidr_eng = ec.engagement_from_record(base(), "cidr")
    dom_eng = ec.engagement_from_record(base(), "domain")
    check("cidr view in_scope", cidr_eng.in_scope, ["10.0.0.0/24 (lab)"])
    check("cidr view out_of_scope", cidr_eng.out_of_scope, ["10.0.5.0/24 (payroll)"])
    check("domain view in_scope", dom_eng.in_scope, ["acme.example (web)"])
    check("domain view never sees the CIDR", "10.0.0.0/24 (lab)" in dom_eng.in_scope + dom_eng.out_of_scope, False)
    check("metadata carried into both views", (cidr_eng.client, dom_eng.authorization_ref), ("Acme", "SOW-1"))
    check("it is a real Engagement", isinstance(cidr_eng, ec.Engagement), True)
    prompt = ec.build_system_prompt(cidr_eng)
    check("build_system_prompt works on the view: its kind in, the other kind out", ("10.0.0.0/24 (lab)" in prompt and "acme.example (web)" not in prompt), True)
    empty_kind = ec.engagement_from_record(base(scope={"cidr": {"in_scope": ["10.0.0.0/24"]}}), "domain")
    check("a kind with no entries yields an empty in_scope (callers fail closed)", empty_kind.in_scope, [])
    refuses("unknown kind refused", lambda: ec.engagement_from_record(base(), "ports"), "unknown scope kind")

    section("exploitation_enabled: defaults False, round-trips through normalize_record() and engagement_from_record()")
    check("default is False", ec.normalize_record(base())["exploitation_enabled"], False)
    check("explicit true survives normalize_record()", ec.normalize_record(base(exploitation_enabled=True))["exploitation_enabled"], True)
    refuses("non-bool refused", lambda: ec.normalize_record(base(exploitation_enabled="yes")), "exploitation_enabled")
    on_eng = ec.engagement_from_record(base(exploitation_enabled=True), "cidr")
    off_eng = ec.engagement_from_record(base(), "cidr")
    check("Engagement.exploitation_enabled True carried through", on_eng.exploitation_enabled, True)
    check("Engagement.exploitation_enabled defaults False", off_eng.exploitation_enabled, False)

    section("load_engagement(): every failure names the fix")
    root = tmp / "root"; (root / "shared").mkdir(parents=True); (root / "acme").mkdir()
    org_dir = root / "acme"
    refuses("missing record names the set command and the GUI page",
            lambda: ec.load_engagement("cidr", org_dir=org_dir),
            "no engagement yet", "sudo agenti engagement set", "--cidr-in", "Settings")
    (org_dir / ec.ORG_ENGAGEMENT_FILENAME).write_text(json.dumps(base(scope={"cidr": {"in_scope": ["10.0.0.0/24"]}})))
    got = ec.load_engagement("cidr", org_dir=org_dir)
    check("loads the organisation record", got.in_scope, ["10.0.0.0/24"])
    refuses("a kind with no entries is refused, naming the kind and the flag",
            lambda: ec.load_engagement("domain", org_dir=org_dir),
            "no domain scope entries", "--domain-in")
    (org_dir / ec.ORG_ENGAGEMENT_FILENAME).write_text("{not json")
    refuses("invalid JSON names the path", lambda: ec.load_engagement("cidr", org_dir=org_dir), "not valid JSON", str(org_dir))
    (org_dir / ec.ORG_ENGAGEMENT_FILENAME).write_text(json.dumps(base(client="")))
    refuses("invalid record names the path and the field", lambda: ec.load_engagement("cidr", org_dir=org_dir), "invalid", "client")
    check("the repo's engagement.example.json is a valid record", ec.read_record(HERE / "engagement.example.json")["engagement_id"], "ACME-2026-03")

    section("N10: a runner enforces only the approved record (require_approved)")
    _rec = base(scope={"cidr": {"in_scope": ["10.0.0.0/24"]}})
    (org_dir / ec.ORG_ENGAGEMENT_FILENAME).write_text(json.dumps(_rec))
    refuses("no approval: a runner's load is refused, naming the approve command",
            lambda: ec.load_engagement("cidr", org_dir=org_dir, require_approved=True),
            "not approved", "sudo agenti engagement approve")
    (org_dir / ec.APPROVAL_FILENAME).write_text(json.dumps(
        {"engagement_id": _rec["engagement_id"], "digest": ec.record_digest(ec.normalize_record(_rec)),
         "approved_by": "alice", "approved_at": 1700000000}))
    check("the approved record loads", ec.load_engagement("cidr", org_dir=org_dir, require_approved=True).in_scope,
          ["10.0.0.0/24"])
    (org_dir / ec.ORG_ENGAGEMENT_FILENAME).write_text(json.dumps(
        base(scope={"cidr": {"in_scope": ["0.0.0.0/0"]}})))
    refuses("an edit saved after approval (between preflight and the runner) is refused",
            lambda: ec.load_engagement("cidr", org_dir=org_dir, require_approved=True), "not approved")
    check("...while a plain read (no runner) still loads it",
          ec.load_engagement("cidr", org_dir=org_dir).in_scope, ["0.0.0.0/0"])
    _off = base(scope={"cidr": {"in_scope": ["0.0.0.0/0"]}}, policy={"require_approval": False})
    (org_dir / ec.ORG_ENGAGEMENT_FILENAME).write_text(json.dumps(_off))
    check("with approval switched off by policy, no approval is needed",
          ec.load_engagement("cidr", org_dir=org_dir, require_approved=True).in_scope, ["0.0.0.0/0"])
    (org_dir / ec.APPROVAL_FILENAME).unlink()

    section("approval_status(): bound to content")
    rec = ec.normalize_record(base())
    st = ec.approval_status(rec, None)
    check("no approval: not approved, not current", (st["approved"], st["current"]), (False, False))
    check("no record: says so", ec.approval_status(None, {"digest": "x"})["reason"], "no engagement record")
    good = {"engagement_id": "ACME-01", "digest": ec.record_digest(rec), "approved_by": "alice", "approved_at": 1700000000}
    st = ec.approval_status(rec, good)
    check("matching id + digest: current", (st["approved"], st["current"]), (True, True))
    check("...names the approver", "alice" in st["reason"], True)
    st = ec.approval_status(ec.normalize_record(base(notes="edited after approval")), good)
    check("EDIT AFTER APPROVAL: approved but not current", (st["approved"], st["current"]), (True, False))
    check("...reason says it changed after approval", "changed after" in st["reason"], True)
    st = ec.approval_status(ec.normalize_record(base(engagement_id="ACME-02")), good)
    check("id changed: not current, names both ids", (st["current"], "ACME-01" in st["reason"] and "ACME-02" in st["reason"]), (False, True))
    st = ec.approval_status(rec, {"_invalid": True})
    check("unreadable approval file: fail closed", (st["approved"], st["current"]), (False, False))
    check("re-saving identical content keeps approval current",
          ec.approval_status(ec.normalize_record(base(updated_at=5.0, updated_by="someone")), good)["current"], True)

    section("the scope classes expose their kind")
    import scope_cidr, scope_domain  # noqa: E402
    check("CIDRScope.kind", scope_cidr.CIDRScope("a").kind, "cidr")
    check("DomainScope.kind", scope_domain.DomainScope("a").kind, "domain")
    check("kind is a class attribute, not a dataclass field", "kind" in repr(scope_cidr.CIDRScope("a")), False)

    # -----------------------------------------------------------------------
    section("engagement_store.py: the real CLI, as a subprocess")
    store = HERE / "engagement_store.py"
    t2 = tmp / "root2"; (t2 / "shared").mkdir(parents=True); (t2 / "beta").mkdir()
    tdir = t2 / "beta"

    def run(*argv, expect=0):
        p = subprocess.run([sys.executable, str(store), "--org-dir", str(tdir), *argv],
                           capture_output=True, text=True)
        try:
            out = json.loads(p.stdout)
        except json.JSONDecodeError:
            out = {"_raw_stdout": p.stdout, "_stderr": p.stderr}
        check(f"exit {expect} for: {' '.join(argv)[:60]}" + (f" [{p.stderr.strip()[:80]}]" if p.returncode != expect else ""),
              p.returncode, expect)
        return out

    out = run("show")
    check("show on an empty tenant: exists false, status not approved", (out["exists"], out["approval_status"]["approved"]), (False, False))
    out = run("set", "--by", "alice", "--client", "Beta Ltd", expect=2)
    check("create without the core fields refused, naming the missing flags",
          ("no engagement yet" in out["error"] and "--engagement-id" in out["error"] and "--valid-from" in out["error"]), True)
    out = run("approve", "--by", "alice", expect=2)
    check("approve with no record refused, naming set", "set one first" in out["error"], True)
    core = ["--engagement-id", "BETA-01", "--client", "Beta Ltd", "--authorizing-party", "Sam Lee",
            "--authorizing-title", "Head of Security", "--authorization-ref", "SOW-B-1",
            "--valid-from", "2026-01-01", "--valid-until", "2026-12-31"]
    out = run("set", "--by", "alice", *core, expect=2)
    check("create with core fields but NO scope refused (authorizes nothing)", "authorizes nothing" in out["error"], True)
    out = run("set", "--by", "alice", *core, "--cidr-in", "10.9.0.0/24 (dmz)", "--cidr-out", "10.9.9.0/24 (prod)")
    check("create succeeds", (out["ok"], out["created"], out["engagement_id"]), (True, True, "BETA-01"))
    check("...reports not approved yet", out["approval_status"]["approved"], False)
    rec_path = tdir / ec.ORG_ENGAGEMENT_FILENAME
    check("record file mode 0640", stat.S_IMODE(rec_path.stat().st_mode), 0o640)
    check("no tmp file left behind", [p.name for p in tdir.iterdir() if p.name.endswith(".tmp")], [])
    on_disk = json.loads(rec_path.read_text())
    check("audit fields stamped", (on_disk["updated_by"], on_disk["updated_via"]), ("alice", "cli"))
    check("on-disk record validates", ec.normalize_record(on_disk)["scope"]["cidr"]["in_scope"], ["10.9.0.0/24 (dmz)"])
    d_created = out["digest"]

    out = run("show", "--scope-kind", "domain")
    check("show: domain view unusable (no domain entries yet)", out["view"]["usable"], False)
    out = run("show", "--scope-kind", "cidr")
    check("show: cidr view usable with the entry", (out["view"]["usable"], out["view"]["in_scope"]), (True, ["10.9.0.0/24 (dmz)"]))
    check("show: digest matches set's", out["digest"], d_created)

    out = run("approve", "--by", "alice", "--engagement-id", "WRONG", expect=2)
    check("approve with a mismatching --engagement-id refused, naming the real one", "BETA-01" in out["error"], True)
    out = run("approve", "--by", "alice", "--engagement-id", "BETA-01", "--via", "api")
    check("approve succeeds and is current", (out["ok"], out["approval_status"]["current"], out["approval"]["approved_by"]), (True, True, "alice"))
    appr_path = tdir / ec.APPROVAL_FILENAME
    check("approval file mode 0640", stat.S_IMODE(appr_path.stat().st_mode), 0o640)
    check("approval digest == record digest", json.loads(appr_path.read_text())["digest"], d_created)

    out = run("set", "--by", "alice", "--client", "Beta Ltd")
    check("re-saving identical content: unchanged, nothing written", (out.get("unchanged"), out["changed"]), (True, []))
    check("...and approval stays current", out["approval_status"]["current"], True)
    before = rec_path.stat().st_mtime_ns
    out = run("set", "--by", "alice", "--domain-in", "beta.example (web)")
    check("adding a domain kind: changed names scope.domain only", out["changed"], ["scope.domain"])
    check("...cidr lists untouched by a domain-only edit",
          json.loads(rec_path.read_text())["scope"]["cidr"], {"in_scope": ["10.9.0.0/24 (dmz)"], "out_of_scope": ["10.9.9.0/24 (prod)"]})
    check("...APPROVAL IS NOW STALE (edit after approval)", (out["approval_status"]["approved"], out["approval_status"]["current"]), (True, False))
    check("...reason names the approver and that it changed", "alice" in out["approval_status"]["reason"] and "changed after" in out["approval_status"]["reason"], True)
    check("...file actually rewritten", rec_path.stat().st_mtime_ns != before, True)
    out = run("set", "--by", "alice", "--cidr-in", "10.9.1.0/24 (new)")
    check("--cidr-in alone replaces cidr in_scope but keeps cidr out_of_scope",
          json.loads(rec_path.read_text())["scope"]["cidr"], {"in_scope": ["10.9.1.0/24 (new)"], "out_of_scope": ["10.9.9.0/24 (prod)"]})
    out = run("set", "--by", "alice", "--replace-scope", "cidr", "--cidr-in", "10.9.2.0/24")
    check("--replace-scope cidr with only --cidr-in empties cidr out_of_scope",
          json.loads(rec_path.read_text())["scope"]["cidr"], {"in_scope": ["10.9.2.0/24"], "out_of_scope": []})
    out = run("set", "--by", "alice", "--clear-scope", "cidr")
    check("--clear-scope cidr leaves the domain kind, record still valid",
          json.loads(rec_path.read_text())["scope"], {"cidr": {"in_scope": [], "out_of_scope": []}, "domain": {"in_scope": ["beta.example (web)"], "out_of_scope": []}})
    out = run("set", "--by", "alice", "--clear-scope", "domain", expect=2)
    check("clearing the LAST kind refused (would authorize nothing), record untouched",
          ("authorizes nothing" in out["error"], json.loads(rec_path.read_text())["scope"]["domain"]["in_scope"]), (True, ["beta.example (web)"]))
    out = run("set", "--by", "alice", "--cidr-in", "not-a-cidr", expect=2)
    check("a bad CIDR entry refused with the entry named", "not-a-cidr" in out["error"], True)
    out = run("set", "--by", "alice", "--valid-until", "2025-01-01", expect=2)
    check("from > until refused", "after valid_until" in out["error"], True)
    out = run("set", "--by", "alice", "--notes", "window 18:00-06:00", "--retention-days", "7", "--capture-payloads", "--redact", "Authorization", "--redact", "Cookie")
    check("data-handling fields set", sorted(out["changed"]), ["capture_payloads", "notes", "redact", "retention_days"])
    on_disk = json.loads(rec_path.read_text())
    check("...on disk", (on_disk["capture_payloads"], on_disk["retention_days"], on_disk["redact"]), (True, 7, ["Authorization", "Cookie"]))
    out = run("set", "--by", "alice", "--no-capture-payloads", "--clear-redact")
    check("tri-state capture flag + clear-redact", (json.loads(rec_path.read_text())["capture_payloads"], json.loads(rec_path.read_text())["redact"]), (False, []))
    out = run("set", "--by", "alice", "--engagement-id", "BETA-02")
    check("renaming the engagement id: approval stale, reason names both ids",
          (out["approval_status"]["current"], "BETA-01" in out["approval_status"]["reason"] and "BETA-02" in out["approval_status"]["reason"]), (False, True))
    out = run("approve", "--by", "bob")
    check("fresh approval after edits: current again", out["approval_status"]["current"], True)

    section("engagement_store.py: operational policy flags, the real CLI "
            "(CLAUDE.md \"Current plan\" — replaces the retired --dev/commercial split)")
    out = run("show")
    check("no policy set yet: effective_policy is the platform default", out["effective_policy"], ec.PLATFORM_DEFAULT_POLICY)
    d_before_policy = out["digest"]
    out = run("set", "--by", "alice", "--max-turns-ceiling", "15", "--allowed-models", "haiku", "--allowed-models", "sonnet")
    check("ceiling + allowed-models set", out["changed"], ["policy"])
    check("digest UNCHANGED by a pure policy edit (policy is not authorization content)",
          out["digest"], d_before_policy)
    check("effective_policy reflects the override, other fields still default",
          (out["effective_policy"]["max_turns_ceiling"], out["effective_policy"]["allowed_models"],
           out["effective_policy"]["max_budget_usd_ceiling"]),
          (15, ["haiku", "sonnet"], ec.PLATFORM_DEFAULT_POLICY["max_budget_usd_ceiling"]))
    out = run("set", "--by", "alice", "--max-budget-ceiling", "3.5")
    check("a second, independent ceiling field: the first one is untouched (per-field merge)",
          (out["effective_policy"]["max_turns_ceiling"], out["effective_policy"]["max_budget_usd_ceiling"]),
          (15, 3.5))
    out = run("set", "--by", "alice", "--no-require-approval")
    check("require-approval turned off", out["effective_policy"]["require_approval"], False)
    out = run("set", "--by", "alice", "--require-approval")
    check("require-approval turned back on", out["effective_policy"]["require_approval"], True)
    out = run("set", "--by", "alice", "--via", "api", "--no-require-approval", expect=2)
    check("F10: from the web, approval cannot be turned off", "console-only" in out.get("error", ""), True)
    check("...and the record still requires it", run("show")["effective_policy"]["require_approval"], True)
    out = run("set", "--by", "alice", "--via", "api", "--require-approval")
    check("...but re-saving it ON from the web is fine", out["effective_policy"]["require_approval"], True)
    d_now = run("show")["digest"]
    out = run("approve", "--by", "bob", "--expect-digest", "0" * 64, expect=2)
    check("F25: an approval of a version that is no longer on disk is refused",
          "changed after you opened it" in out.get("error", ""), True)
    out = run("approve", "--by", "bob", "--expect-digest", d_now)
    check("...and the reviewed version is approved", out["approval_status"]["current"], True)
    out = run("set", "--by", "alice", "--clear-allowed-models")
    check("clear-allowed-models reverts to the platform default set",
          out["effective_policy"]["allowed_models"], ec.PLATFORM_DEFAULT_POLICY["allowed_models"])
    out = run("set", "--by", "alice", "--allowed-models", "gpt-4", expect=2)
    check("an unrecognized model is refused at the real CLI entry point too", "unrecognized" in out["error"], True)
    out = run("set", "--by", "alice", "--max-turns-ceiling", "0", expect=2)
    check("a non-positive ceiling is refused at the real CLI entry point too", "positive" in out["error"], True)

    out = run("history")
    actions = [(r["action"], r["by"]) for r in out["history"]]
    check("history: first row is the creation", (out["history"][0]["action"], out["history"][0]["created"]), ("set", True))
    check("history: approvals recorded with approver", ("approve", "alice") in actions and ("approve", "bob") in actions, True)
    check("history: an unchanged re-save wrote no row", sum(1 for r in out["history"] if r["action"] == "set" and r.get("changed") == []), 0)
    check("history: the domain-add row names scope.domain", any(r.get("changed") == ["scope.domain"] for r in out["history"]), True)
    out = run("history", "-n", "2")
    check("history -n limits", len(out["history"]), 2)
    out = run("digest")
    check("digest verb matches show", out["digest"], run("show")["digest"])

    out = run("--format", "text", "show")
    check("--format text still exits 0 (non-JSON stdout expected)", "_raw_stdout" in out, True)
    check("...text mentions APPROVED and the tenant", ("APPROVED" in out["_raw_stdout"] and "beta" in out["_raw_stdout"]), True)
    out = run("bogus", expect=2)
    check("an argparse error is clean JSON on stdout", "invalid arguments" in out.get("error", ""), True)
    out = run("set", expect=2)
    check("missing --by is an argparse JSON error", "--by" in out.get("error", ""), True)
    section("engagement_store.py: import (migration/restore path)")
    t3 = tmp / "root3"; (t3 / "shared").mkdir(parents=True); (t3 / "gamma").mkdir()
    gdir = t3 / "gamma"
    blob = tmp / "blob.json"
    blob.write_text(json.dumps(base(engagement_id="GAMMA-01", client="Gamma Inc")))

    def run3(*argv, expect=0, stdin=None):
        p = subprocess.run([sys.executable, str(store), "--org-dir", str(gdir), *argv],
                           input=stdin, capture_output=True, text=True)
        try:
            out = json.loads(p.stdout)
        except json.JSONDecodeError:
            out = {"_raw_stdout": p.stdout, "_stderr": p.stderr}
        check(f"exit {expect} for: {' '.join(argv)[:60]}" + (f" [{p.stderr.strip()[:80]}]" if p.returncode != expect else ""),
              p.returncode, expect)
        return out

    out = run3("import", "--by", "migrator", "--source", "migrate-to-tenant-engagement", "--file", str(blob))
    check("import creates a fresh record", (out["ok"], out["engagement_id"], out["replaced"]), (True, "GAMMA-01", False))
    on_disk = json.loads((gdir / ec.ORG_ENGAGEMENT_FILENAME).read_text())
    check("audit fields stamped by import, not the imported blob's own", (on_disk["updated_by"], on_disk["updated_via"]), ("migrator", "cli"))
    check("no unapproved audit fields leaked from the source blob", "updated_at" in on_disk, True)
    out = run3("import", "--by", "migrator", "--file", str(blob), expect=2)
    check("import without --force refuses to clobber an existing record", "without --force" in out["error"], True)
    check("...record on disk is untouched", json.loads((gdir / ec.ORG_ENGAGEMENT_FILENAME).read_text())["client"], "Gamma Inc")
    blob2 = tmp / "blob2.json"
    blob2.write_text(json.dumps(base(engagement_id="GAMMA-02", client="Gamma Inc Renamed")))
    out = run3("import", "--by", "migrator", "--file", str(blob2), "--force")
    check("import --force replaces it, and says so", (out["engagement_id"], out["replaced"]), ("GAMMA-02", True))
    hist = run3("history")["history"]
    check("both imports recorded with the action and source", [r["action"] for r in hist], ["import", "import"])
    check("...the source label is recorded", hist[0].get("source"), "migrate-to-tenant-engagement")
    out = run3("import", "--by", "migrator", expect=2, stdin=json.dumps(base(engagement_id="GAMMA-03")), )
    check("import reads stdin when --file is not given, but still refuses without --force", "without --force" in out["error"], True)
    out = run3("import", "--by", "migrator", "--force", stdin="{not json", expect=2)
    check("garbage on stdin is refused, not a traceback", out.get("ok"), False)
    check("...naming the fault", "not valid JSON" in out.get("error", ""), True)
    out = run3("import", "--by", "migrator", "--force", "--file", str(tmp / "does-not-exist.json"), expect=2)
    check("a missing --file is refused cleanly", "could not read" in out["error"], True)

    section("engagement_store.py: a corrupt record is recoverable, never a dead end")
    good_before = rec_path.read_text()
    rec_path.write_text("{corrupt")
    out = run("show")
    check("show on a corrupt file: exit 0, record null, invalid names the fault and the fix",
          (out["record"], "not valid JSON" in out.get("invalid", ""), "engagement set" in out.get("invalid", "")), (None, True, True))
    check("...approval status fails closed", out["approval_status"]["current"], False)
    out = run("approve", "--by", "alice", expect=2)
    check("approve on a corrupt file refused, naming set", ("cannot be read" in out["error"] and "engagement set" in out["error"]), True)
    out = run("digest", expect=2)
    check("digest on a corrupt file refused", "cannot be read" in out["error"], True)
    out = run("set", "--by", "alice", "--notes", "x", expect=2)
    check("a partial set on a corrupt file: refused, saying replacing it needs every core field",
          ("cannot be read" in out["error"] and "--engagement-id" in out["error"]), True)
    out = run("set", "--by", "alice", *core, "--cidr-in", "10.9.0.0/24 (dmz)")
    check("the full create command REPLACES the corrupt file", (out["ok"], out["created"], "not valid JSON" in out.get("replaced_invalid", "")), (True, True, True))
    check("...history records the replacement", "replaced_invalid" in run("history", "-n", "1")["history"][-1], True)
    rec_path.write_text(good_before)

    p = subprocess.run([sys.executable, str(store), "--org-dir", str(t2 / "nope"), "show"], capture_output=True, text=True)
    check("nonexistent tenant dir refused with exit 2", (p.returncode, "does not exist" in json.loads(p.stdout)["error"]), (2, True))
    p = subprocess.run([sys.executable, str(store), "--org-dir", str(tdir), "--group", "no-such-group-xyz", "set", "--by", "x", "--notes", "n"], capture_output=True, text=True)
    check("unknown --group refused before anything is written", (p.returncode, "unknown group" in json.loads(p.stdout)["error"]), (2, True))
    check("...record untouched by the refused call", json.loads(rec_path.read_text())["notes"], "window 18:00-06:00")

finally:
    import shutil
    shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------------------
section("per-agent scope: narrows the tenant's, never widens it")
check("cidr: agent entry inside tenant -> that entry",
      ec.intersect_scope("cidr", ["192.0.2.0/24 (lan)"], ["192.0.2.31"]), ["192.0.2.31/32"])
check("cidr: agent entry WIDER than tenant -> the tenant's (overlap)",
      ec.intersect_scope("cidr", ["192.0.2.31/32"], ["192.0.2.0/24"]), ["192.0.2.31/32"])
check("cidr: disjoint -> nothing", ec.intersect_scope("cidr", ["10.0.0.0/8"], ["8.8.8.8"]), [])
check("no agent entries -> the tenant's own list", ec.intersect_scope("cidr", ["10.0.0.0/8"], []), ["10.0.0.0/8"])
check("domain: subdomain kept", ec.intersect_scope("domain", ["example.com"], ["a.example.com"]), ["a.example.com"])
check("domain: label boundary (evil-example.com is NOT inside example.com)",
      ec.intersect_scope("domain", ["example.com"], ["evil-example.com"]), [])
for kind, tenant, bad in (("cidr", ["192.0.2.0/24"], "8.8.8.8"), ("domain", ["example.com"], "evil-example.com")):
    try:
        ec.check_agent_scope_narrows(kind, tenant, [bad]); got = "accepted"
    except ec.EngagementError:
        got = "refused"
    check(f"save refuses a {kind} entry outside the tenant's ({bad})", got, "refused")

atmp = Path(tempfile.mkdtemp())
try:
    (atmp / "enum").mkdir()
    def store(*a):
        r = subprocess.run([sys.executable, str(HERE / "engagement_store.py"), "--org-dir", str(atmp), *a],
                           capture_output=True, text=True)
        return json.loads(r.stdout)
    store("set", "--by", "t", "--engagement-id", "E1", "--client", "C", "--authorizing-party", "P",
          "--authorizing-title", "T", "--authorization-ref", "R", "--valid-from", "2026-01-01",
          "--valid-until", "2027-01-01", "--cidr-in", "192.0.2.0/24", "--cidr-in", "10.1.0.0/16")
    r = store("agent-scope-set", "--agent", "enum", "--scope-kind", "cidr", "--by", "t",
              "--in", "192.0.2.31", "--out", "192.0.2.1")
    check("narrowing saved, effective = the overlap", (r["ok"], r["effective_in_scope"]), (True, ["192.0.2.31/32"]))
    r = store("agent-scope-set", "--agent", "enum", "--scope-kind", "cidr", "--by", "t", "--in", "8.8.8.8")
    check("widening refused by the store", r["ok"], False)
    eng = ec.load_engagement("cidr", org_dir=atmp, agent="enum")
    check("a run's engagement carries only the narrowed scope", eng.in_scope, ["192.0.2.31/32"])
    check("the agent's extra exclusion is added", "192.0.2.1" in eng.out_of_scope, True)
    check("another agent of the tenant is unaffected",
          ec.load_engagement("cidr", org_dir=atmp, agent="other").in_scope,
          ["192.0.2.0/24", "10.1.0.0/16"])
    store("set", "--by", "t", "--cidr-in", "10.1.0.0/16")        # tenant no longer covers the agent's entry
    try:
        ec.load_engagement("cidr", org_dir=atmp, agent="enum"); got = "ran"
    except ec.EngagementError as e:
        got = "refused" if "no longer overlaps" in str(e) else str(e)
    check("a later tenant edit leaving no overlap refuses the run (no silent fallback)", got, "refused")
    (atmp / "enum" / "agent-scope.json").write_text("{ nope")
    try:
        ec.load_engagement("cidr", org_dir=atmp, agent="enum"); got = "ran"
    except ec.EngagementError:
        got = "refused"
    check("an unreadable agent-scope file stops the run rather than meaning 'no narrowing'", got, "refused")
finally:
    import shutil
    shutil.rmtree(atmp, ignore_errors=True)

print(f"\n{'=' * 52}\n  {PASS} passed, {FAIL} failed\n{'=' * 52}")
sys.exit(1 if FAIL else 0)
