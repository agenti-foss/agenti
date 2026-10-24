"""test_authd.py — the privileged auth service (shared/authd.py), §4 item 23.

No framework, no root, no vault, no deployment: throwaway stores in a temp
directory, and a REAL Unix socket in that same directory for the transport
tests, so the peer-credential gate is exercised by an actual connect().

    python3 shared/test_authd.py

WHAT IT PINS DOWN: this daemon is now the only thing that can say "this
session is valid" or "this principal may do that". The failure modes are
silent — a pending session that quietly counts as authenticated, a rotate
that leaves the old id alive, a disabled principal whose session keeps
working, a decision that is not logged, a peer the socket should have
refused — so every one of them is a case here.
"""

import json
import os
import socket
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent / "api"))

import authd  # noqa: E402
import authd_client  # noqa: E402
import iam  # noqa: E402

PASS = FAIL = 0


def check(label, got, want):
    global PASS, FAIL
    if got == want:
        PASS += 1; print(f"  [ OK ] {label}")
    else:
        FAIL += 1; print(f"  [FAIL] {label}\n         got  {got!r}\n         want {want!r}")


def section(t): print(f"\n=== {t} ===")


tmp = Path(tempfile.mkdtemp(prefix="authd-test-"))
iam_path, rt_path = tmp / "iam.db", tmp / "runtime.db"
# Redirected so a test run never touches the real box's
# nothing here writes outside the temp tree.
conn = iam.open_iam(readonly=False, path=iam_path)
rt = iam.open_runtime(rt_path)
iam.add_principal(conn, "alice", "user", "test", role="operator")
iam.set_principal_password(conn, "alice", "correct-horse")
iam.add_principal(conn, "bob", "user", "test", role="operator")
iam.set_principal_password(conn, "bob", "bob-pw-ok")
bob_secret, _codes = iam.enroll_totp(conn, "bob", rt)
iam.add_principal(conn, "svc", "service", "test", role="operator")
svc_key = iam.issue_key(conn, "svc", "test")
conn.close(); rt.close()

svc = authd.Service(iam_path, rt_path)
H = svc.handle

section("request shape: refusals are 400s with a message, never a traceback")
check("non-object request", H(["op"])["status"], 400)
check("missing op", H({})["status"], 400)
check("unknown op", H({"op": "drop_tables"})["status"], 400)
check("private attribute is not an op", H({"op": "_iam"})["status"], 400)
check("missing field named", "principal" in H({"op": "login", "password": "x"})["error"], True)
check("wrong type named", "must be a string" in H({"op": "login", "principal": 1, "password": "x"})["error"], True)
check("oversized field refused", H({"op": "login", "principal": "a" * 65, "password": "x"})["status"], 400)
check("ping answers", H({"op": "ping"})["service"], "agenti-authd")

section("setup status: the login page's 'run sudo agenti setup' hint")
check("people exist: no setup needed", H({"op": "setup_status"}), {"setup_needed": False, "ok": True})
_fresh = tmp / "fresh-iam.db"
_c = iam.open_iam(readonly=False, path=_fresh)
iam.add_principal(_c, "robot", "service", "test", role="operator")
_c.close()
check("a fresh store (a service account, no person): setup needed",
      authd.Service(_fresh, tmp / "fresh-rt.db").handle({"op": "setup_status"})["setup_needed"], True)

section("login: password only (alice has no 2FA)")
r = H({"op": "login", "principal": "alice", "password": "wrong", "addr": "10.0.0.1"})
check("wrong password -> 401", r["status"], 401)
check("...generic message", r["error"], "invalid credentials")
r = H({"op": "login", "principal": "nobody", "password": "x", "addr": "10.0.0.1"})
check("unknown principal -> same 401 message", r["error"], "invalid credentials")
r = H({"op": "login", "principal": "alice", "password": "correct-horse", "addr": "10.0.0.1"})
check("right password -> ok", r["ok"], True)
check("...not pending", r["pending"], False)
check("...csrf returned", bool(r["csrf"]), True)
alice_sid, alice_csrf = r["session_id"], r["csrf"]

section("authenticate: a full session resolves, slides, and dies with its principal")
r = H({"op": "authenticate", "session_id": alice_sid})
check("valid session -> principal", r.get("principal"), "alice")
check("...csrf matches", r.get("csrf"), alice_csrf)
check("garbage session id -> 401", H({"op": "authenticate", "session_id": "nope"})["status"], 401)
rt = iam.open_runtime(rt_path)
before = rt.execute("SELECT expires_at FROM sessions WHERE id=?", (alice_sid,)).fetchone()[0]
rt.execute("UPDATE sessions SET expires_at=? WHERE id=?", (before - 100, alice_sid)); rt.commit()
H({"op": "authenticate", "session_id": alice_sid})
after = rt.execute("SELECT expires_at FROM sessions WHERE id=?", (alice_sid,)).fetchone()[0]
check("a use slides the expiry forward", after > before - 100, True)
rt.close()
conn = iam.open_iam(readonly=False, path=iam_path)
iam.set_principal_active(conn, "alice", False)
r = H({"op": "authenticate", "session_id": alice_sid})
check("disabled principal -> 401 immediately", r["status"], 401)
check("...and the session row is gone", H({"op": "authenticate", "session_id": alice_sid})["error"],
      "session expired or revoked — sign in again")
iam.set_principal_active(conn, "alice", True)
conn.close()

section("login with 2FA: pending session, then rotate on a good code")
r = H({"op": "login", "principal": "bob", "password": "bob-pw-ok"})
check("password ok -> pending", r["pending"], True)
check("...totp_required", r["totp_required"], True)
check("...csrf WITHHELD while pending", r["csrf"], None)
pending_sid = r["session_id"]
r = H({"op": "authenticate", "session_id": pending_sid})
check("a pending session is NOT authenticated", r["status"], 401)
check("...and says why", "second factor" in r["error"], True)
check("wrong code -> 401", H({"op": "totp", "session_id": pending_sid, "code": "000000"})["status"], 401)
r = H({"op": "totp", "session_id": pending_sid, "code": iam.totp_code(bob_secret)})
check("right code -> ok", r["ok"], True)
check("...session id ROTATED", r["session_id"] != pending_sid, True)
check("...csrf now present", bool(r["csrf"]), True)
bob_sid = r["session_id"]
check("old pending id is dead", H({"op": "authenticate", "session_id": pending_sid})["status"], 401)
check("new id authenticates", H({"op": "authenticate", "session_id": bob_sid}).get("principal"), "bob")
check("totp on a NON-pending session -> 401", H({"op": "totp", "session_id": bob_sid, "code": "1"})["status"], 401)

section("logout")
check("logout ok", H({"op": "logout", "session_id": bob_sid})["logged_out"], True)
check("...session gone", H({"op": "authenticate", "session_id": bob_sid})["status"], 401)
check("logout of a nonexistent id is still ok (nothing to leak)",
      H({"op": "logout", "session_id": "never"})["logged_out"], True)

section("require-2fa: a password-only session is flagged for MFA setup (policy default ON)")
# alice has a password and no second factor; the test store never set the
# policy, so the platform default (on) applies.
r = H({"op": "login", "principal": "alice", "password": "correct-horse"})
check("login answers, not refused", r["ok"], True)
check("...but flags mfa_setup_required", r["mfa_setup_required"], True)
flag_sid = r["session_id"]
r = H({"op": "authenticate", "session_id": flag_sid})
check("authenticate carries the flag", r["mfa_setup_required"], True)
check("...and totp_enrolled=false", r["totp_enrolled"], False)
_c = iam.open_iam(readonly=False, path=iam_path)
iam.set_setting(_c, "require-2fa:alice", "off"); _c.close()
check("an exemption lifts it on the NEXT call, no new login", H({"op": "authenticate", "session_id": flag_sid})["mfa_setup_required"], False)
_c = iam.open_iam(readonly=False, path=iam_path)
_c.execute("DELETE FROM settings WHERE key='require-2fa:alice'"); _c.commit(); _c.close()
check("...and returns when the exemption is removed", H({"op": "authenticate", "session_id": flag_sid})["mfa_setup_required"], True)
# bob is enrolled: never flagged, at login or afterwards.
r = H({"op": "login", "principal": "bob", "password": "bob-pw-ok"})
check("an enrolled principal's login is not flagged", r["mfa_setup_required"], False)
H({"op": "logout", "session_id": flag_sid})

section("API keys")
r = H({"op": "authenticate_key", "key": svc_key})
check("valid key -> principal", r.get("principal"), "svc")
check("...prefix returned", bool(r.get("prefix")), True)
r = H({"op": "authenticate_key", "key": "agk_deadbeef_nope"})
check("bad key -> 401", r["status"], 401)
check("...generic message", r["error"], "invalid or expired credentials")
rt = iam.open_runtime(rt_path)
check("a key failure is logged (by prefix)", rt.execute(
    "SELECT count(*) FROM authz_log WHERE permission='authenticate' AND decision='deny'").fetchone()[0] >= 1, True)
check("a key use is recorded", rt.execute("SELECT uses FROM key_usage").fetchone()[0] >= 1, True)
rt.close()

section("authorize: the decision AND its audit row live here")
r = H({"op": "authorize", "principal": "alice", "permission": "agent:start",
       "resource": "org", "via": "api:session"})
check("an operator may start an agent", r["allowed"], True)
r = H({"op": "authorize", "principal": "alice", "permission": "iam:manage",
       "resource": "org", "via": "api:session"})
check("...but an operator may not manage users", r["allowed"], False)
check("...with a reason", bool(r["reason"]), True)
r = H({"op": "authorize", "principal": "alice", "permission": "not:a:permission",
       "resource": "org", "via": "api:session"})
check("unknown permission -> denied, not error", r["allowed"], False)
rt = iam.open_runtime(rt_path)
rows = rt.execute("SELECT decision, via FROM authz_log WHERE principal='alice' ORDER BY id").fetchall()
check("every authorize wrote an audit row (allow AND deny)",
      [(x[0], x[1]) for x in rows], [("allow", "api:session"), ("deny", "api:session"), ("deny", "api:session")])
n_before = rt.execute("SELECT count(*) FROM authz_log").fetchone()[0]
rt.close()
check("can: same answer", H({"op": "can", "principal": "alice", "permission": "agent:start",
                            "resource": "org"})["allowed"], True)
rt = iam.open_runtime(rt_path)
check("can: writes NO audit row (filtering must not drown the log)",
      rt.execute("SELECT count(*) FROM authz_log").fetchone()[0], n_before)
rt.close()
check("permissions: resolved set", "agent:start" in
      H({"op": "permissions", "principal": "alice", "resource": "org"})["permissions"], True)
section("approve_action: re-auth mints a single-use grant bound to the action (§4 item 24)")
conn = iam.open_iam(readonly=False, path=iam_path)
# alice is an admin from here on (she approves the grants below).
iam.set_principal_role(conn, "alice", "admin", "test")
conn.close()
r = H({"op": "login", "principal": "alice", "password": "correct-horse"})
alice_sid = r["session_id"]
act = {"op": "bind", "principal": "svc", "role": "operator", "resource": "org"}
r = H({"op": "approve_action", "session_id": alice_sid, "password": "wrong", "action": act})
check("a wrong password is refused for a grant (every grant checks the password)",
      r["status"] == 403 and "password" in r["error"], True)
r = H({"op": "approve_action", "session_id": alice_sid, "password": "correct-horse",
       "action": {**act, "role": "reader"}})
check("a role the web may not grant is refused BEFORE any credential is spent", r["status"], 400)
r = H({"op": "approve_action", "session_id": alice_sid, "password": "correct-horse",
       "action": {**act, "resource": "tenant/acme"}})
check("a resource other than the organisation is refused likewise", r["status"], 400)
r = H({"op": "approve_action", "session_id": "nope", "password": "correct-horse", "action": act})
check("no session -> 401", r["status"], 401)
r = H({"op": "login", "principal": "bob", "password": "bob-pw-ok"})
bob_pending = r["session_id"]
r = H({"op": "approve_action", "session_id": bob_pending, "password": "bob-pw-ok", "action": act})
check("a PENDING session cannot approve", r["status"], 401)
# This window's code was spent by bob's earlier login (replay protection is
# real), so log in with the NEXT step's code — totp_verify accepts +-1 step.
next_code = iam.totp_code(bob_secret, at=time.time() + 30)
r = H({"op": "totp", "session_id": bob_pending, "code": next_code})
bob_sid = r["session_id"]
r = H({"op": "approve_action", "session_id": bob_sid, "password": "bob-pw-ok", "action": act})
check("2FA-enrolled without a code -> 403 naming the need", r["status"] == 403 and "2FA" in r["error"], True)
r = H({"op": "approve_action", "session_id": bob_sid, "password": "bob-pw-ok",
       "totp": next_code, "action": act})
check("2FA-enrolled with the SAME code as login -> replay refused", r["status"], 403)
prev_code = iam.totp_code(bob_secret, at=time.time() - 30)
r = H({"op": "approve_action", "session_id": bob_sid, "password": "bob-pw-ok",
       "totp": prev_code, "action": act})
check("2FA-enrolled with a fresh, unused code -> grant", bool(r.get("grant")), True)
check("...approved_by is the session's own principal", r.get("approved_by"), "bob")
rt = iam.open_runtime(rt_path)
check("the grant is bound to the action", iam.consume_action_grant(rt, r["grant"], act), "bob")
rt.close()

section("approve_action: every grant needs the password AND a fresh code "
        "(one universal popup with both fields, 2026-10-04)")
conn = iam.open_iam(readonly=False, path=iam_path)
rt = iam.open_runtime(rt_path)
op_act = {"op": "bind", "principal": "svc", "role": "operator", "resource": "org"}

def _fresh_bob_session():
    # Re-enrolling 2FA revokes the old session and clears replay history,
    # so each case gets a genuinely fresh secret and a real re-login.
    secret, _ = iam.enroll_totp(conn, "bob", rt)
    pending = H({"op": "login", "principal": "bob", "password": "bob-pw-ok"})["session_id"]
    sid = H({"op": "totp", "session_id": pending, "code": iam.totp_code(secret)})["session_id"]
    return sid, secret

sid, _secret = _fresh_bob_session()
r = H({"op": "approve_action", "session_id": sid, "password": "bob-pw-ok", "action": op_act})
check("operator grant, no code -> refused naming the need",
      r["status"] == 403 and "2FA" in r["error"], True)
sid, secret = _fresh_bob_session()
r = H({"op": "approve_action", "session_id": sid, "password": "not-bobs-password",
       "totp": iam.totp_code(secret, at=time.time() + 30), "action": op_act})
check("operator grant, WRONG password + correct code -> refused", r["status"], 403)
sid, secret = _fresh_bob_session()
r = H({"op": "approve_action", "session_id": sid,
       "totp": iam.totp_code(secret, at=time.time() + 30), "action": op_act})
check("operator grant, no password at all -> refused", r["status"], 403)
sid, secret = _fresh_bob_session()
r = H({"op": "approve_action", "session_id": sid, "password": "bob-pw-ok", "totp": "000000", "action": op_act})
check("operator grant, wrong code -> refused", r["status"], 403)
sid, secret = _fresh_bob_session()
r = H({"op": "approve_action", "session_id": sid, "password": "bob-pw-ok",
       "totp": iam.totp_code(secret, at=time.time() + 30), "action": {**op_act, "role": "operator"}})
check("operator grant (second case), right password + right code -> grants", bool(r.get("grant")), True)
sid, secret = _fresh_bob_session()
r = H({"op": "approve_action", "session_id": sid, "password": "bob-pw-ok",
       "totp": iam.totp_code(secret, at=time.time() + 30),
       "action": {**op_act, "role": "admin", "resource": "org"}})
check("admin grant, right password + right code -> grants", bool(r.get("grant")), True)

iam.clear_failures(rt, "bob")
conn.close(); rt.close()

section("approve_action: the lifecycle ops share the SAME generalized action validator "
        "_validate_action used to gate 'bind' above")
conn = iam.open_iam(readonly=False, path=iam_path)
iam.add_principal(conn, "gadmin", "user", "test", role="admin")
iam.set_principal_password(conn, "gadmin", "gadmin-pw")
iam.add_principal(conn, "lc-target", "user", "test")
conn.close()

r = H({"op": "login", "principal": "gadmin", "password": "gadmin-pw"})
gadmin_sid = r["session_id"]

r = H({"op": "approve_action", "session_id": gadmin_sid, "password": "gadmin-pw",
       "action": {"op": "frobnicate", "resource": "org"}})
check("an op outside GRANT_OPS is refused before any credential is spent", r["status"], 400)

r = H({"op": "approve_action", "session_id": gadmin_sid, "password": "gadmin-pw",
       "action": {"op": "rename-principal", "principal": "lc-target", "resource": "org"}})
check("rename-principal missing new_name is refused", r["status"], 400)

rp_act = {"op": "rename-principal", "principal": "lc-target", "new_name": "lc-renamed",
         "resource": "org"}
r = H({"op": "approve_action", "session_id": gadmin_sid, "password": "gadmin-pw", "action": rp_act})
check("rename-principal grant, platform-wide, for a real global admin", bool(r.get("grant")), True)
check("...approved_by is the session's own principal", r.get("approved_by"), "gadmin")
conn = iam.open_iam(readonly=False, path=iam_path)
rt = iam.open_runtime(rt_path)
out = iam.web_rename_principal(conn, rt, "lc-target", "lc-renamed", "org", r["grant"])
check("...and the CLI side consumes it and actually performs the rename", out["new"], "lc-renamed")
conn.close(); rt.close()

r = H({"op": "approve_action", "session_id": gadmin_sid, "password": "gadmin-pw",
       "action": {"op": "rename-tenant", "tenant": "acme", "short_name": "acme-2", "resource": "org"}})
check("tenant lifecycle ops no longer exist (there are no tenants)", r["status"], 400)

r = H({"op": "login", "principal": "alice", "password": "correct-horse"})
alice_sid2 = r["session_id"]
dp_act = {"op": "delete-principal", "principal": "lc-renamed", "resource": "org"}
r = H({"op": "approve_action", "session_id": alice_sid2, "password": "correct-horse",
       "action": dp_act})
check("delete-principal is approvable", bool(r.get("grant")), True)

en_act = {"op": "enable-principal", "principal": "lc-renamed", "resource": "org"}
r = H({"op": "approve_action", "session_id": alice_sid2, "password": "correct-horse",
       "action": en_act})
check("enable-principal is approvable and password-gated", bool(r.get("grant")), True)

# ---- edit-context: the instruction files -----------------------------------
GR = "org"
sp_text = "## Objective\nDo the thing.\n"
sp_act = {"op": "edit-context", "kind": "system-prompt", "change": "set", "agent": "enum",
          "resource": GR, "sha256": iam.context_text_sha256(sp_text)}
r = H({"op": "approve_action", "session_id": gadmin_sid, "password": "gadmin-pw", "action": sp_act})
check("edit-context: a global admin may approve a system-prompt save", bool(r.get("grant")), True)
grant_sp = r["grant"]
conn = iam.open_iam(readonly=False, path=iam_path); rt = iam.open_runtime(rt_path)
try:
    iam.web_approve_context_edit(conn, rt, {**sp_act, "sha256": iam.context_text_sha256("different text")}, grant_sp)
    got = "accepted"
except iam.IAMError:
    got = "refused"
check("...the grant cannot be spent on DIFFERENT text (the hash is bound)", got, "refused")
r = H({"op": "approve_action", "session_id": gadmin_sid, "password": "gadmin-pw", "action": sp_act})
check("...approved_by is the session's own principal",
      iam.web_approve_context_edit(conn, rt, sp_act, r["grant"]), "gadmin")
conn.close(); rt.close()

r = H({"op": "approve_action", "session_id": gadmin_sid, "password": "gadmin-pw",
       "action": {**sp_act, "sha256": "not-a-hash"}})
check("a malformed hash is refused before any credential is spent", r["status"], 400)
r = H({"op": "approve_action", "session_id": gadmin_sid, "password": "gadmin-pw",
       "action": {**sp_act, "kind": "memory"}})
check("memory is not editable through an admin grant", r["status"], 400)
r = H({"op": "approve_action", "session_id": gadmin_sid, "password": "gadmin-pw",
       "action": {"op": "edit-context", "kind": "system-prompt", "change": "revert", "agent": "enum",
                  "resource": GR, "version": "../../etc"}})
check("a path-like version id is refused", r["status"], 400)

tp_act = {"op": "edit-context", "kind": "org", "change": "set",
          "resource": "org", "sha256": iam.context_text_sha256("Org policy.\n")}
r = H({"op": "approve_action", "session_id": gadmin_sid, "password": "gadmin-pw", "action": tp_act})
check("an admin may approve an edit of the organisation's policy file", bool(r.get("grant")), True)
conn = iam.open_iam(readonly=False, path=iam_path); rt = iam.open_runtime(rt_path)
check("...and the root side confirms the approver holds iam:manage",
      iam.web_approve_context_edit(conn, rt, tp_act, r["grant"]), "gadmin")
conn.close(); rt.close()
# ---- build-agent / remove-agent: whole agent types (Settings -> Agents) -----
SHA = "a" * 64
ba = {"op": "build-agent", "name": "invoice-checker", "sha256": SHA, "resource": GR}
r = H({"op": "approve_action", "session_id": gadmin_sid, "password": "gadmin-pw", "action": ba})
check("build-agent: a global admin may approve a build", bool(r.get("grant")), True)
conn = iam.open_iam(readonly=False, path=iam_path); rt = iam.open_runtime(rt_path)
try:
    iam.web_approve_agent_build(conn, rt, {**ba, "sha256": "b" * 64}, r["grant"]); got = "accepted"
except iam.IAMError:
    got = "refused"
check("...the grant cannot be spent on a DIFFERENT spec (the hash is bound)", got, "refused")
r = H({"op": "approve_action", "session_id": gadmin_sid, "password": "gadmin-pw", "action": ba})
check("...and the root side names the approver", iam.web_approve_agent_build(conn, rt, ba, r["grant"]), "gadmin")
ra = {"op": "remove-agent", "name": "invoice-checker", "resource": GR}
r = H({"op": "approve_action", "session_id": gadmin_sid, "password": "gadmin-pw", "action": ra})
try:
    iam.web_approve_agent_build(conn, rt, {**ra, "name": "enum"}, r["grant"]); got = "accepted"
except iam.IAMError:
    got = "refused"
check("remove-agent: a grant for one agent cannot remove another", got, "refused")
conn.close(); rt.close()
r = H({"op": "approve_action", "session_id": gadmin_sid, "password": "gadmin-pw",
       "action": {**ba, "sha256": "not-a-hash"}})
check("build-agent: a malformed hash is refused", r["status"], 400)
r = H({"op": "approve_action", "session_id": gadmin_sid, "password": "gadmin-pw",
       "action": {**ba, "name": "../etc"}})
check("build-agent: a path-like name is refused", r["status"], 400)
r = H({"op": "approve_action", "session_id": gadmin_sid, "password": "gadmin-pw",
       "action": {**ba, "resource": "tenant/acme"}})
check("build-agent: a resource other than the organisation is refused", r["status"], 400)
check("build-agent and remove-agent need the password, not just a code",
      (authd.Service._grant_requires_password(ba), authd.Service._grant_requires_password(ra)), (True, True))
ua = {"op": "update-agent", "name": "invoice-checker", "sha256": SHA, "resource": GR}
ce = {"op": "edit-catalog", "name": "whois", "change": "add", "sha256": SHA, "resource": GR}
cr = {"op": "edit-catalog", "name": "whois", "change": "remove", "resource": GR}
conn = iam.open_iam(readonly=False, path=iam_path); rt = iam.open_runtime(rt_path)
for label, act in (("update-agent", ua), ("edit-catalog add", ce), ("edit-catalog remove", cr)):
    r = H({"op": "approve_action", "session_id": gadmin_sid, "password": "gadmin-pw", "action": act})
    check(f"{label}: a global admin may approve", bool(r.get("grant")), True)
    check(f"...and the root side names the approver", iam.web_approve_agent_build(conn, rt, act, r["grant"]), "gadmin")
r = H({"op": "approve_action", "session_id": gadmin_sid, "password": "gadmin-pw", "action": ce})
try:
    iam.web_approve_agent_build(conn, rt, {**ce, "name": "nmap"}, r["grant"]); got = "accepted"
except iam.IAMError:
    got = "refused"
check("edit-catalog: a grant for one program cannot add another", got, "refused")
r = H({"op": "approve_action", "session_id": gadmin_sid, "password": "gadmin-pw", "action": {**ce, "change": "bogus"}})
check("edit-catalog: an unknown change is refused", r["status"], 400)
r = H({"op": "approve_action", "session_id": gadmin_sid, "password": "gadmin-pw", "action": {**ce, "sha256": "x"}})
check("edit-catalog: add without a valid hash is refused", r["status"], 400)
r = H({"op": "approve_action", "session_id": gadmin_sid, "password": "gadmin-pw", "action": {**ce, "resource": "tenant/acme"}})
check("edit-catalog: a resource other than the organisation is refused", r["status"], 400)
conn.close(); rt.close()

# ---- exploit-approve / exploit-reject: the exploit agent's per-action -----
# approval, from the GUI. Unlike the ops above, this is an OPERATOR deciding
# on their own live run (not a global-admin-only action) — alice (operator,
# no iam:manage) proves that the re-auth grant works for a plain operator,
# the same bar the CLI's own exploit-approve already enforces.
r = H({"op": "login", "principal": "alice", "password": "correct-horse"})
alice_sid3 = r["session_id"]
ea = {"op": "action-approve", "agent": "exploit", "request_id": "a1b2c3d4",
      "options_hash": "f" * 16, "owner": "alice", "resource": GR}
r = H({"op": "approve_action", "session_id": alice_sid3, "password": "correct-horse", "action": ea})
check("action-approve: an operator may approve their own request", bool(r.get("grant")), True)
conn = iam.open_iam(readonly=False, path=iam_path); rt = iam.open_runtime(rt_path)
try:
    iam.web_approve_exploit_action(conn, rt, {**ea, "options_hash": "e" * 16}, r["grant"]); got = "accepted"
except iam.IAMError:
    got = "refused"
check("...the grant cannot be spent on DIFFERENT options (the hash is bound)", got, "refused")
r = H({"op": "approve_action", "session_id": alice_sid3, "password": "correct-horse", "action": ea})
check("...and the root side names the approver",
      iam.web_approve_exploit_action(conn, rt, ea, r["grant"]), "alice")
# The legacy exploit-approve name mints the SAME grant the CLI consumes (the
# API used action-*, the CLI exploit-*: every web approval failed, closed).
r = H({"op": "approve_action", "session_id": alice_sid3, "password": "correct-horse",
       "action": {**ea, "op": "exploit-approve"}})
check("a legacy exploit-approve grant is consumed as action-approve",
      iam.web_approve_exploit_action(conn, rt, ea, r["grant"]), "alice")
# F26: bound to the run's owner.
r = H({"op": "approve_action", "session_id": alice_sid3, "password": "correct-horse",
       "action": {**ea, "owner": "bob"}})
try:
    iam.web_approve_exploit_action(conn, rt, {**ea, "owner": "bob"}, r["grant"]); got = "accepted"
except iam.IAMError as e:
    got = "refused" if "belongs to 'bob'" in str(e) else str(e)
check("F26: alice's grant cannot decide a request in bob's run", got, "refused")
r = H({"op": "approve_action", "session_id": alice_sid3, "password": "correct-horse", "action": ea})
try:
    iam.web_approve_exploit_action(conn, rt, {**ea, "owner": "bob"}, r["grant"]); got = "accepted"
except iam.IAMError:
    got = "refused"
check("F26: ...nor can a grant for her own run be spent on bob's", got, "refused")
r = H({"op": "approve_action", "session_id": alice_sid3, "password": "correct-horse",
       "action": {k: v for k, v in ea.items() if k != "owner"}})
check("F26: a grant request that names no owner is refused", r["status"], 400)
er = {"op": "action-reject", "agent": "exploit", "request_id": "a1b2c3d4", "options_hash": "f" * 16,
      "owner": "alice", "resource": GR}
r = H({"op": "approve_action", "session_id": alice_sid3, "password": "correct-horse", "action": er})
check("action-reject: an operator may reject their own request",
      iam.web_approve_exploit_action(conn, rt, er, r["grant"]), "alice")
conn.close(); rt.close()
r = H({"op": "approve_action", "session_id": alice_sid3, "password": "correct-horse",
       "action": {**ea, "request_id": "not-hex!"}})
check("exploit-approve: a malformed request_id is refused", r["status"], 400)
r = H({"op": "approve_action", "session_id": alice_sid3, "password": "correct-horse",
       "action": {**ea, "options_hash": "short"}})
check("exploit-approve: a malformed options_hash is refused", r["status"], 400)
r = H({"op": "approve_action", "session_id": alice_sid3, "password": "correct-horse",
       "action": {**ea, "resource": "tenant/acme"}})
check("exploit-approve: a resource other than the organisation is refused", r["status"], 400)
conn = iam.open_iam(readonly=False, path=iam_path); rt = iam.open_runtime(rt_path)
try:
    iam.web_approve_exploit_action(conn, rt, {"op": "build-agent", **{k: v for k, v in ea.items() if k != "op"}},
                                   "bogus-grant-id")
    got = "accepted"
except iam.IAMError:
    got = "refused"
check("web_approve_exploit_action refuses a non-exploit op outright", got, "refused")
conn.close(); rt.close()

# approve_action only re-authenticates the SESSION's identity and mints a
# grant recording it — it does NOT check whether that principal actually
# holds the permission. That authorization check happens fresh when the grant
# is CONSUMED (web_delete_principal etc.); test_iam.py proves that refusal.
section("approve_action: reset-password / reset-mfa (the operator's own "
        "explicit ask — a global admin resetting a DIFFERENT user's "
        "credentials from the GUI), through the real Service.handle() "
        "dispatch — same generalized _validate_action, but ALWAYS "
        "requiring the password (unlike 'bind' above), never grace-skipped "
        "by accident here since each check below uses its OWN fresh login")
conn = iam.open_iam(readonly=False, path=iam_path)
iam.add_principal(conn, "rpp2-target", "user", "test")
iam.set_principal_password(conn, "rpp2-target", "rpp2-old-pw")
conn.close()

r = H({"op": "login", "principal": "gadmin", "password": "gadmin-pw"})
fresh_gadmin_sid = r["session_id"]
r = H({"op": "approve_action", "session_id": fresh_gadmin_sid, "password": "gadmin-pw",
       "action": {"op": "reset-password", "principal": "rpp2-target", "resource": "org"}})
check("reset-password missing mode is refused", r["status"], 400)

r = H({"op": "login", "principal": "gadmin", "password": "gadmin-pw"})
fresh_gadmin_sid = r["session_id"]
r = H({"op": "approve_action", "session_id": fresh_gadmin_sid, "password": "gadmin-pw",
       "action": {"op": "reset-password", "principal": "rpp2-target", "resource": "org", "mode": "direct"}})
check("reset-password mode=direct missing new_password is refused", r["status"], 400)

r = H({"op": "login", "principal": "gadmin", "password": "gadmin-pw"})
fresh_gadmin_sid = r["session_id"]
r = H({"op": "approve_action", "session_id": fresh_gadmin_sid, "password": "gadmin-pw",
       "action": {"op": "reset-mfa", "principal": "rpp2-target", "resource": "tenant/acme"}})
check("reset-mfa with a resource other than the organisation is refused before any credential "
      "is spent", r["status"], 400)

# Unlike 'bind', which no longer asks for the password at all (item 65), a
# credential reset still requires it unconditionally regardless of role —
# proven here with the SAME "wrong password, correct code" shape the bind
# tests above used to prove the opposite for viewer/operator/tenant-admin/
# admin.
r = H({"op": "login", "principal": "gadmin", "password": "gadmin-pw"})
fresh_gadmin_sid = r["session_id"]
r = H({"op": "approve_action", "session_id": fresh_gadmin_sid,
       "password": "this-is-not-gadmins-password",
       "action": {"op": "reset-password", "principal": "rpp2-target", "resource": "org",
                  "mode": "link"}})
check("reset-password, WRONG password -> refused even with no code needed "
      "(gadmin has no 2FA enrolled) — a credential reset always requires the "
      "password, unlike a bare role grant", r["status"], 403)

r = H({"op": "login", "principal": "gadmin", "password": "gadmin-pw"})
fresh_gadmin_sid = r["session_id"]
rp2_act = {"op": "reset-password", "principal": "rpp2-target", "resource": "org",
          "mode": "direct", "new_password": "rpp2-brand-new-pw"}
r = H({"op": "approve_action", "session_id": fresh_gadmin_sid, "password": "gadmin-pw",
       "action": rp2_act})
check("reset-password grant, mode=direct, for a real global admin", bool(r.get("grant")), True)
check("...approved_by is the session's own principal", r.get("approved_by"), "gadmin")
conn = iam.open_iam(readonly=False, path=iam_path)
rt = iam.open_runtime(rt_path)
out = iam.web_reset_principal_password(conn, rt, "rpp2-target", "org", r["grant"], "rpp2-brand-new-pw")
check("...and the CLI side consumes it and actually resets the password",
      out["password_reset"], True)
check("...the new password genuinely works", iam.verify_login(
    conn, rt, "rpp2-target", "rpp2-brand-new-pw").ok, True)
conn.close(); rt.close()

r = H({"op": "login", "principal": "gadmin", "password": "gadmin-pw"})
fresh_gadmin_sid = r["session_id"]
rm2_act = {"op": "reset-mfa", "principal": "rpp2-target", "resource": "org"}
r = H({"op": "approve_action", "session_id": fresh_gadmin_sid, "password": "gadmin-pw",
       "action": rm2_act})
check("reset-mfa grant, for a real global admin", bool(r.get("grant")), True)
conn = iam.open_iam(readonly=False, path=iam_path)
rt = iam.open_runtime(rt_path)
mfa_out = iam.web_reset_principal_mfa(conn, rt, "rpp2-target", "org", r["grant"])
check("...and the CLI side consumes it and actually resets MFA", mfa_out["mfa_reset"], True)
check("...the password reset just above is UNTOUCHED — two independent jobs",
      iam.verify_login(conn, rt, "rpp2-target", "rpp2-brand-new-pw").ok, True)
conn.close(); rt.close()

section("approve_action: no grace window — every admin action asks (operator decision 2026-10-23)")
r = H({"op": "login", "principal": "gadmin", "password": "gadmin-pw"})
grace_sid = r["session_id"]
_act = {"op": "rename-principal", "principal": "lc-renamed", "new_name": "lc-renamed-2", "resource": "org"}
r = H({"op": "approve_action", "session_id": grace_sid, "action": _act})
check("no credentials -> refused", r["status"], 403)
r = H({"op": "approve_action", "session_id": grace_sid, "password": "gadmin-pw", "action": _act})
check("with the real password -> grants", (bool(r.get("grant")), r.get("approved_by")), (True, "gadmin"))
r = H({"op": "approve_action", "session_id": grace_sid,
       "action": {"op": "rename-principal", "principal": "lc-renamed-2",
                  "new_name": "lc-renamed-3", "resource": "org"}})
check("a SECOND action moments later on the same session, with no credentials -> refused", r["status"], 403)
for _op in ("create-user", "vault-enable"):
    r = H({"op": "approve_action", "session_id": grace_sid,
           "action": {"op": _op, "principal": "x", "kind": "user", "role": "admin", "resource": "org"}
           if _op == "create-user" else {"op": _op, "size": "8G", "resource": "org"}})
    check(f"{_op} right after a successful approval, with no credentials -> refused", r["status"] in (400, 403), True)
r = H({"op": "admin_grace_status", "session_id": grace_sid})
check("the grace-status operation is gone", (r.get("ok"), r.get("status")), (False, 400))

section("transport: a real socket, and the peer-uid gate")
sock = str(tmp / "authd.sock")
me = os.getuid()
srv = authd.serve(sock, svc, {me}, socket_group=None)
try:
    r = authd_client.call("ping", socket_path=sock)
    check("client round trip", r["service"], "agenti-authd")
    r = authd_client.call("login", socket_path=sock, principal="alice", password="correct-horse")
    check("login over the socket", r["ok"], True)
    try:
        authd_client.call("login", socket_path=sock, principal="alice", password="wrong")
        check("refusal raises AuthdError", False, True)
    except authd_client.AuthdError as e:
        check("refusal raises AuthdError with authd's status", e.status, 401)
        check("...and message", e.message, "invalid credentials")
    # Oversized and malformed on the wire
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.connect(sock)
    s.sendall(b"not json\n"); s.shutdown(socket.SHUT_WR)
    check("non-JSON line -> 400", json.loads(s.recv(65536))["status"], 400); s.close()
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.connect(sock)
    s.sendall(b"x" * (authd.MAX_REQUEST_BYTES + 10) + b"\n"); s.shutdown(socket.SHUT_WR)
    check("oversized request -> 413", json.loads(s.recv(65536))["status"], 413); s.close()
    check("socket mode is 0660",
          oct(os.stat(sock).st_mode & 0o777), oct(0o660))
    # audit run 2: a burst of sign-ins overflowed the default backlog of 5
    check("authd queues a burst of connections (backlog >= 64)", srv.request_queue_size >= 64, True)
    _real_connect, _fails = socket.socket.connect, [2]

    def _busy_twice(self, addr):
        if _fails[0] > 0:
            _fails[0] -= 1
            raise BlockingIOError(11, "Resource temporarily unavailable")
        return _real_connect(self, addr)
    socket.socket.connect = _busy_twice
    try:
        r = authd_client.call("ping", socket_path=sock)
        check("a momentarily full queue (EAGAIN) is waited out, not a 500", r["service"], "agenti-authd")
        _fails[0] = 10 ** 6
        try:
            authd_client.call("ping", socket_path=sock, timeout=0.3)
            check("a queue that stays full ends in 503 'busy'", False, True)
        except authd_client.AuthdError as e:
            check("a queue that stays full ends in 503 'busy'", (e.status, "busy" in e.message), (503, True))
    finally:
        socket.socket.connect = _real_connect
finally:
    srv.shutdown(); srv.server_close()

# The same server, but this uid is NOT allowed: every request must be
# refused before it is even parsed. (Root is not special-cased either — the
# deploy verify proves that on the real box by connecting as root.)
srv = authd.serve(sock, svc, {me + 1}, socket_group=None)
try:
    try:
        authd_client.call("ping", socket_path=sock)
        check("wrong peer uid -> refused", False, True)
    except authd_client.AuthdError as e:
        check("wrong peer uid -> refused (403)", e.status, 403)
        check("...names the uid", str(me) in e.message, True)
finally:
    srv.shutdown(); srv.server_close()

try:
    authd_client.call("ping", socket_path=str(tmp / "no-such.sock"))
    check("no daemon -> 503", False, True)
except authd_client.AuthdError as e:
    check("no daemon -> 503 naming the service", e.status == 503 and "agenti-authd" in e.message, True)

# =============================================================================
section("WebAuthn: structural gate — refused cleanly with nothing configured")
# =============================================================================
# A fresh Service/handle, independent of the socket-server tests above (this
# section drives op_* directly, like every other section in this file).
conn = iam.open_iam(readonly=False, path=iam_path)
iam.add_principal(conn, "waalice", "user", "test")
iam.set_principal_password(conn, "waalice", "wa-correct-horse")
conn.close()
svc2 = authd.Service(iam_path, rt_path)
H2 = svc2.handle

check("WEBAUTHN_RP_ID starts unset in this process (no --hostname env var)",
      authd.WEBAUTHN_RP_ID, "")
r = H2({"op": "webauthn_config"})
check("config reports disabled with nothing configured", r["enabled"], False)
check("...and not configured either (the setup wizard's first-step signal)", r["configured"], False)
r = H2({"op": "webauthn_login_begin"})
check("login_begin refused (503) with no RP id configured", r["status"], 503)
check("...names the fix", "--hostname" in r["error"], True)

# =============================================================================
section("WebAuthn: real ceremonies — a genuine EC key pair, real CBOR, real "
        "signatures, generated fresh against THIS run's own server-issued "
        "challenge (unlike test_webauthn_lite.py's pinned fixtures, the "
        "challenge here is dynamic, so it cannot be pre-baked — cryptography "
        "is used as a live oracle, exactly as authd's own venv would)")
# =============================================================================
try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    HAVE_CRYPTOGRAPHY = True
except ImportError:
    HAVE_CRYPTOGRAPHY = False

if not HAVE_CRYPTOGRAPHY:
    print("  [SKIP] entire section — 'cryptography' is not importable in this "
          "environment (only ever required on agenti-authd's dedicated venv, "
          "never to run this suite).")
else:
    # A minimal, hand-rolled CBOR ENCODER — deliberately not the cbor2
    # package, so this test needs exactly the one dependency authd.py's own
    # venv actually carries, nothing extra. Mirrors webauthn_lite.cbor_decode
    # structurally; round-tripped through it below as a self-consistency
    # check before it's trusted for anything.
    def cbor_head(major, n):
        if n < 24:
            return bytes([(major << 5) | n])
        if n < 256:
            return bytes([(major << 5) | 24, n])
        if n < 65536:
            return bytes([(major << 5) | 25]) + n.to_bytes(2, "big")
        return bytes([(major << 5) | 26]) + n.to_bytes(4, "big")

    def cbor_int(n):
        return cbor_head(0, n) if n >= 0 else cbor_head(1, -1 - n)

    def cbor_bstr(b):
        return cbor_head(2, len(b)) + b

    def cbor_tstr(s):
        raw = s.encode("utf-8")
        return cbor_head(3, len(raw)) + raw

    def cbor_value(v):
        """Dispatches on Python type, the exact reverse of what
        webauthn_lite.cbor_decode does on CBOR major type — bytes and str
        are DISTINCT CBOR types (major 2 vs 3) and must not be conflated,
        which is exactly the bug the first version of this encoder had:
        every non-int value went through cbor_bstr, so a text-string map
        key like "fmt" silently became the byte string b"fmt" once
        decoded, and verify_registration's `"authData" not in att_obj`
        check then failed to find it. Caught immediately by the round-trip
        check below, before it was trusted for anything."""
        if isinstance(v, bool):
            raise TypeError("bool not used by anything this encoder builds")
        if isinstance(v, int):
            return cbor_int(v)
        if isinstance(v, (bytes, bytearray)):
            return cbor_bstr(bytes(v))
        if isinstance(v, str):
            return cbor_tstr(v)
        if isinstance(v, dict):
            return cbor_map(list(v.items()))
        if isinstance(v, list):
            return cbor_head(4, len(v)) + b"".join(cbor_value(x) for x in v)
        raise TypeError(f"unsupported type for the hand-rolled test encoder: {type(v)}")

    def cbor_map(pairs):
        out = cbor_head(5, len(pairs))
        for k, v in pairs:
            out += cbor_value(k) + cbor_value(v)
        return out

    import hashlib as _hashlib
    import webauthn_lite as _wl

    roundtrip, _ = _wl.cbor_decode(cbor_map([(1, 2), (3, b"xy"), ("fmt", "none")]))
    check("hand-rolled CBOR encoder round-trips through webauthn_lite's decoder "
          "(int/bytes/text-string all distinguished correctly)",
          roundtrip, {1: 2, 3: b"xy", "fmt": "none"})

    RP_ID = "authd-test.example.com"
    ORIGIN = "https://authd-test.example.com:8420"
    authd.WEBAUTHN_RP_ID = RP_ID
    authd.WEBAUTHN_ORIGIN = ORIGIN

    # The setup wizard's middle step: a domain is configured (Phase A done)
    # but the platform toggle is still off — `configured` must already be
    # true here even though `enabled` isn't yet, or the wizard could never
    # tell "run deploy-api.sh --hostname" apart from "now flip the toggle".
    r = H2({"op": "webauthn_config"})
    check("domain configured but toggle still off -> configured=True, enabled=False",
          (r["configured"], r["enabled"], r["rpId"]), (True, False, RP_ID))

    conn = iam.open_iam(readonly=False, path=iam_path)
    iam.set_webauthn_enabled(conn, True)
    conn.close()

    r = H2({"op": "webauthn_config"})
    check("config now reports enabled with an RP id configured",
          (r["enabled"], r["configured"], r["rpId"]), (True, True, RP_ID))

    FLAG_UP, FLAG_UV, FLAG_AT = 0x01, 0x04, 0x40

    def authenticator_data(rp_id, flags, sign_count, attested_pubkey=None, cred_id=b""):
        rp_hash = _hashlib.sha256(rp_id.encode()).digest()
        out = rp_hash + bytes([flags]) + sign_count.to_bytes(4, "big")
        if attested_pubkey is not None:
            out += b"\x00" * 16 + len(cred_id).to_bytes(2, "big") + cred_id + attested_pubkey
        return out

    def cose_key(pub):
        n = pub.public_numbers()
        x = n.x.to_bytes(32, "big"); y = n.y.to_bytes(32, "big")
        return cbor_map([(1, 2), (3, -7), (-1, 1), (-2, x), (-3, y)])

    r = H2({"op": "login", "principal": "waalice", "password": "wa-correct-horse"})
    wa_sid, wa_csrf = r["session_id"], r["csrf"]
    check("waalice logged in for the WebAuthn tests", r["ok"], True)

    r = H2({"op": "webauthn_register_begin", "session_id": wa_sid,
           "password": "wa-correct-horse"})
    check("register_begin succeeds with the right password", "challenge" in r, True)
    check("...names the configured RP id", r["rp"]["id"], RP_ID)
    reg_challenge = r["challenge"]

    r_bad = H2({"op": "webauthn_register_begin", "session_id": wa_sid, "password": "WRONG"})
    check("register_begin refuses the wrong password", r_bad["status"], 403)

    credential_id = b"authd-test-credential-0001"
    private_key = ec.generate_private_key(ec.SECP256R1())
    reg_auth_data = authenticator_data(RP_ID, FLAG_UP | FLAG_UV | FLAG_AT, 0,
                                       attested_pubkey=cose_key(private_key.public_key()),
                                       cred_id=credential_id)
    reg_client_data = json.dumps({"type": "webauthn.create", "challenge": reg_challenge,
                                  "origin": ORIGIN}, separators=(",", ":")).encode()
    attestation_object = cbor_map([
        ("fmt", "none"), ("attStmt", {}), ("authData", reg_auth_data),
    ])
    finish_req = {
        "op": "webauthn_register_finish", "session_id": wa_sid, "password": "wa-correct-horse",
        "name": "Test Device",
        "credential": {"id": _wl.b64url_encode(credential_id), "response": {
            "clientDataJSON": _wl.b64url_encode(reg_client_data),
            "attestationObject": _wl.b64url_encode(attestation_object),
        }},
    }
    r = H2(finish_req)
    check("register_finish verifies a genuine ceremony", "grant" in r, True)
    check("...extracted the right credential_id", r["credential_id"], _wl.b64url_encode(credential_id))
    check("...alg is ES256", r["alg"], "ES256")
    grant_id = r["grant"]

    # The same finished payload replayed with a FRESH challenge should be
    # refused (the challenge from `r` above was already consumed) —
    # confirms the daemon actually enforces single-use end to end, not just
    # webauthn_lite in isolation.
    r_replay = H2(finish_req)
    check("replaying register_finish (stale/consumed challenge) is refused", "grant" in r_replay, False)

    conn = iam.open_iam(readonly=False, path=iam_path)
    rt2 = iam.open_runtime(rt_path)
    commit = iam.passkey_commit(conn, rt2, "waalice", r["credential_id"], r["alg"],
                                r["x"], r["y"], r["sign_count"], r["name"], grant_id)
    check("the CLI-side commit accepts authd's grant and writes the credential",
          commit["credential_id"], r["credential_id"])
    check("mfa_setup_required now satisfied for waalice", iam.mfa_setup_required(conn, "waalice"),
          False)
    conn.close(); rt2.close()

    section("WebAuthn: passwordless login — a real assertion against the "
            "just-registered credential")
    r = H2({"op": "webauthn_login_begin"})
    check("login_begin issues a discoverable-credential challenge",
          r.get("allowCredentials"), [])
    login_challenge = r["challenge"]

    login_auth_data = authenticator_data(RP_ID, FLAG_UP | FLAG_UV, 1)
    login_client_data = json.dumps({"type": "webauthn.get", "challenge": login_challenge,
                                    "origin": ORIGIN}, separators=(",", ":")).encode()
    signed = login_auth_data + _hashlib.sha256(login_client_data).digest()
    signature = private_key.sign(signed, ec.ECDSA(hashes.SHA256()))
    login_req = {
        "op": "webauthn_login_finish",
        "credential": {"id": _wl.b64url_encode(credential_id), "response": {
            "clientDataJSON": _wl.b64url_encode(login_client_data),
            "authenticatorData": _wl.b64url_encode(login_auth_data),
            "signature": _wl.b64url_encode(signature),
        }},
    }
    r = H2(login_req)
    check("a genuine passwordless login succeeds", r.get("principal"), "waalice")
    check("...mints a REAL, non-pending session", bool(r.get("session_id")), True)
    check("...mfa_setup_required is False (the passkey satisfies it alone)",
          r.get("mfa_setup_required"), False)

    # Replaying the exact same assertion must fail: its challenge was
    # single-use, so this proves replay protection end to end (not just the
    # sign_count check webauthn_lite already covers in isolation).
    r_replay = H2(login_req)
    check("replaying the same assertion (challenge already consumed) is refused",
          r_replay.get("ok", True), False)

    # A tampered signature against a FRESH challenge is refused too.
    r2 = H2({"op": "webauthn_login_begin"})
    login_challenge2 = r2["challenge"]
    login_auth_data2 = authenticator_data(RP_ID, FLAG_UP | FLAG_UV, 2)
    login_client_data2 = json.dumps({"type": "webauthn.get", "challenge": login_challenge2,
                                     "origin": ORIGIN}, separators=(",", ":")).encode()
    bad_sig = bytearray(signature); bad_sig[5] ^= 0xFF
    r3 = H2({"op": "webauthn_login_finish", "credential": {
        "id": _wl.b64url_encode(credential_id), "response": {
            "clientDataJSON": _wl.b64url_encode(login_client_data2),
            "authenticatorData": _wl.b64url_encode(login_auth_data2),
            "signature": _wl.b64url_encode(bytes(bad_sig)),
        }}})
    check("a tampered signature is refused with the SAME generic message as a bad password",
          (r3["status"], r3["error"]), (401, "invalid credentials"))

    # An unknown credential_id is refused the same generic way (no enumeration signal).
    r4 = H2({"op": "webauthn_login_begin"})
    unknown_req = {"op": "webauthn_login_finish", "credential": {
        "id": _wl.b64url_encode(b"no-such-credential"), "response": {
            "clientDataJSON": _wl.b64url_encode(json.dumps(
                {"type": "webauthn.get", "challenge": r4["challenge"], "origin": ORIGIN},
                separators=(",", ":")).encode()),
            "authenticatorData": _wl.b64url_encode(authenticator_data(RP_ID, FLAG_UP | FLAG_UV, 0)),
            "signature": _wl.b64url_encode(b"not-a-real-signature"),
        }}}
    r5 = H2(unknown_req)
    check("an unknown credential_id is refused with the same generic message",
          (r5["status"], r5["error"]), (401, "invalid credentials"))

    section("WebAuthn registration for a principal that ALREADY has 2FA "
            "enrolled — the exact live bug found 2026-09-24")
    # A FRESH principal, not bob: TOTP_WINDOW=1 means only 3 codes (prev/
    # current/next 30s step) ever verify against a given secret inside one
    # 30s wall-clock window, and bob's already spent all 3 earlier in this
    # file. This test needs 3 successful verifications of its own — login
    # promotion, register_begin, and a second login for the "never called
    # begin" check below — so it gets its own untouched secret rather than
    # trying to out-clever the same 3-slot budget a second time.
    #
    # carol is the one principal in this file whose 2FA gets exercised by
    # a multi-step self-service flow exactly like require-2fa's platform
    # default makes universal. The ORIGINAL op_webauthn_register_finish
    # re-verified password+TOTP a SECOND time, and verify_second_factor
    # marks a code used the instant it succeeds — so a client that
    # (reasonably) fills in one current-password/current-code pair and
    # sends it to both begin AND finish always hit "that code has already
    # been used" on finish. No account with 2FA enrolled could ever finish
    # registering a passkey.
    _c = iam.open_iam(readonly=False, path=iam_path)
    _rt = iam.open_runtime(rt_path)
    iam.add_principal(_c, "carol", "user", "test")
    iam.set_principal_password(_c, "carol", "carol-pw")
    carol_secret, _ = iam.enroll_totp(_c, "carol", _rt)
    _c.close(); _rt.close()

    r = H2({"op": "login", "principal": "carol", "password": "carol-pw"})
    carol_sid = r["session_id"]
    r = H2({"op": "totp", "session_id": carol_sid,
           "code": iam.totp_code(carol_secret, at=time.time() - 30)})
    check("carol logged in (password + TOTP) for this regression test", r["ok"], True)
    carol_sid = r["session_id"]  # rotates on promotion — use the real one

    r = H2({"op": "webauthn_register_begin", "session_id": carol_sid,
           "password": "carol-pw", "totp": iam.totp_code(carol_secret)})
    check("register_begin succeeds for a 2FA-enrolled principal", "challenge" in r, True)
    carol_challenge = r["challenge"]

    carol_credential_id = b"authd-test-credential-carol-0001"
    carol_key = ec.generate_private_key(ec.SECP256R1())
    carol_auth_data = authenticator_data(RP_ID, FLAG_UP | FLAG_UV | FLAG_AT, 0,
                                         attested_pubkey=cose_key(carol_key.public_key()),
                                         cred_id=carol_credential_id)
    carol_client_data = json.dumps({"type": "webauthn.create", "challenge": carol_challenge,
                                    "origin": ORIGIN}, separators=(",", ":")).encode()
    carol_attestation = cbor_map([
        ("fmt", "none"), ("attStmt", {}), ("authData", carol_auth_data),
    ])
    # The fix under test: NO password/totp fields at all in this request —
    # under the old code this field would have had to repeat the SAME code
    # just used above, which verify_second_factor would refuse as replayed.
    r = H2({
        "op": "webauthn_register_finish", "session_id": carol_sid, "name": "Carol's key",
        "credential": {"id": _wl.b64url_encode(carol_credential_id), "response": {
            "clientDataJSON": _wl.b64url_encode(carol_client_data),
            "attestationObject": _wl.b64url_encode(carol_attestation),
        }},
    })
    check("register_finish succeeds with NO password/totp — the fix", "grant" in r, True)
    check("...for the right principal's credential",
          r.get("credential_id"), _wl.b64url_encode(carol_credential_id))

    conn = iam.open_iam(readonly=False, path=iam_path)
    rt3 = iam.open_runtime(rt_path)
    carol_commit = iam.passkey_commit(conn, rt3, "carol", r["credential_id"], r["alg"],
                                      r["x"], r["y"], r["sign_count"], r["name"], r["grant"])
    check("the CLI-side commit accepts this grant too", carol_commit["credential_id"],
          r["credential_id"])
    conn.close(); rt3.close()

    # A session that never called register_begin (so has no valid challenge
    # for this principal/purpose) still cannot finish — proving the
    # challenge itself, not the now-removed reauth call, is what gates this.
    r = H2({"op": "login", "principal": "carol", "password": "carol-pw"})
    r = H2({"op": "totp", "session_id": r["session_id"],
           "code": iam.totp_code(carol_secret, at=time.time() + 30)})
    fresh_carol_sid = r["session_id"]
    r_no_begin = H2({
        "op": "webauthn_register_finish", "session_id": fresh_carol_sid, "name": "should not work",
        "credential": {"id": _wl.b64url_encode(b"never-began"), "response": {
            "clientDataJSON": _wl.b64url_encode(json.dumps(
                {"type": "webauthn.create", "challenge": "not-a-real-challenge",
                 "origin": ORIGIN}, separators=(",", ":")).encode()),
            "attestationObject": _wl.b64url_encode(cbor_map([
                ("fmt", "none"), ("attStmt", {}), ("authData", b"\x00" * 37)])),
        }},
    })
    check("register_finish without ever calling begin (no valid challenge) is still refused",
          "grant" in r_no_begin, False)

    section("WebAuthn: a passkey standing in for password + 2FA in ANY "
            "authentication popup (a single-use re-authentication token)")
    # waalice already has a real, committed passkey from the registration
    # section above (credential_id / private_key still in scope) — reused
    # here rather than registering a second one, since what's under test
    # is the grant-approval ceremony, not registration again.
    # F07: waalice's second factor is now a passkey, so her password alone no
    # longer signs her in; the passkey door (tested above) is the way in.
    r = H2({"op": "login", "principal": "waalice", "password": "wa-correct-horse"})
    check("F07: a passkey account's correct password alone is refused, naming the passkey",
          (r["ok"], "passkey" in r.get("error", "")), (False, True))
    _rtf = iam.open_runtime(rt_path)
    wa_sid2 = authd.create_session(_rtf, "waalice", pending_totp=False)["session_id"]
    _rtf.close()
    check("waalice has a fresh session for this section", bool(wa_sid2), True)

    act2 = {"op": "bind", "principal": "svc", "role": "operator", "resource": "org"}
    # A fresh secret, not the file's original bob_secret — bob's real
    # stored secret has since been replaced several times over by the
    # earlier stakes-based re-auth section's own _fresh_bob_session()
    # calls, so the original variable no longer matches what's in the
    # database (each re-enrolment clears bob's replay history too, so a
    # brand-new secret is needed here regardless).
    _cb = iam.open_iam(readonly=False, path=iam_path)
    _rtb = iam.open_runtime(rt_path)
    bob_secret2, _ = iam.enroll_totp(_cb, "bob", _rtb)
    _cb.close(); _rtb.close()
    r = H2({"op": "login", "principal": "bob", "password": "bob-pw-ok"})
    bob_pending2 = r["session_id"]
    r = H2({"op": "totp", "session_id": bob_pending2, "code": iam.totp_code(bob_secret2)})
    bob_sid2 = r["session_id"]
    r = H2({"op": "reauth_webauthn_begin", "session_id": bob_sid2})
    check("a principal with NO passkey enrolled (bob, TOTP only) is refused, "
          "naming the fallback", r["status"] == 403 and "password and 2FA" in r["error"], True)

    r = H2({"op": "reauth_webauthn_begin", "session_id": wa_sid2})
    check("begin succeeds for a principal who DOES have a passkey", "challenge" in r, True)
    check("...allowCredentials names exactly her own credential (scoped, not "
          "discoverable like login)", r["allowCredentials"],
          [{"type": "public-key", "id": _wl.b64url_encode(credential_id)}])
    approve_challenge = r["challenge"]

    approve_auth_data = authenticator_data(RP_ID, FLAG_UP | FLAG_UV, 3)
    approve_client_data = json.dumps({"type": "webauthn.get", "challenge": approve_challenge,
                                      "origin": ORIGIN}, separators=(",", ":")).encode()
    approve_signed = approve_auth_data + _hashlib.sha256(approve_client_data).digest()
    approve_signature = private_key.sign(approve_signed, ec.ECDSA(hashes.SHA256()))
    finish_req2 = {
        "op": "reauth_webauthn_finish", "session_id": wa_sid2,
        "credential": {"id": _wl.b64url_encode(credential_id), "response": {
            "clientDataJSON": _wl.b64url_encode(approve_client_data),
            "authenticatorData": _wl.b64url_encode(approve_auth_data),
            "signature": _wl.b64url_encode(approve_signature),
        }},
    }
    r = H2(finish_req2)
    check("finish verifies a genuine assertion and returns a re-auth token", "reauth" in r, True)
    tok = r.get("reauth", "")
    r = H2({"op": "approve_action", "session_id": bob_sid2, "reauth": tok, "action": act2})
    check("waalice's token cannot approve an action in BOB's session", r["status"], 403)
    r = H2({"op": "approve_action", "session_id": wa_sid2, "reauth": tok, "action": act2})
    check("the token approves any action with no password or code", bool(r.get("grant")), True)
    check("...approved_by is the session's own principal", r.get("approved_by"), "waalice")
    rt4 = iam.open_runtime(rt_path)
    try:
        iam.consume_reauth_token(rt4, tok, "waalice"); got = "accepted"
    except iam.IAMError:
        got = "refused"
    check("...and it is single-use", got, "refused")
    tok2 = iam.mint_reauth_token(rt4, "waalice")
    try:
        iam.consume_reauth_token(rt4, tok2, "bob"); got = "accepted"
    except iam.IAMError:
        got = "refused"
    check("a token for one account never re-authenticates another", got, "refused")
    rt4.close()

    r_replay = H2(finish_req2)
    check("replaying the same finished assertion (challenge already consumed) "
          "is refused", "reauth" in r_replay, False)

    r2 = H2({"op": "reauth_webauthn_begin", "session_id": wa_sid2})
    tamper_challenge = r2["challenge"]
    tamper_auth_data = authenticator_data(RP_ID, FLAG_UP | FLAG_UV, 4)
    tamper_client_data = json.dumps({"type": "webauthn.get", "challenge": tamper_challenge,
                                     "origin": ORIGIN}, separators=(",", ":")).encode()
    bad_sig2 = bytearray(approve_signature); bad_sig2[5] ^= 0xFF
    r3 = H2({"op": "reauth_webauthn_finish", "session_id": wa_sid2,
            "credential": {"id": _wl.b64url_encode(credential_id), "response": {
                "clientDataJSON": _wl.b64url_encode(tamper_client_data),
                "authenticatorData": _wl.b64url_encode(tamper_auth_data),
                "signature": _wl.b64url_encode(bytes(bad_sig2)),
            }}})
    check("a tampered signature is refused", r3["status"], 403)

    r4b = H2({"op": "reauth_webauthn_begin", "session_id": wa_sid2})
    unknown_challenge = r4b["challenge"]
    unknown_client_data = json.dumps({"type": "webauthn.get", "challenge": unknown_challenge,
                                      "origin": ORIGIN}, separators=(",", ":")).encode()
    r5b = H2({"op": "reauth_webauthn_finish", "session_id": wa_sid2,
             "credential": {"id": _wl.b64url_encode(b"no-such-credential"), "response": {
                 "clientDataJSON": _wl.b64url_encode(unknown_client_data),
                 "authenticatorData": _wl.b64url_encode(authenticator_data(RP_ID, FLAG_UP | FLAG_UV, 0)),
                 "signature": _wl.b64url_encode(b"not-a-real-signature"),
             }}})
    check("an unknown credential_id is refused", r5b["status"], 403)

    # carol's own genuine, committed passkey — but submitted against
    # WAALICE's session. Must be refused even though the credential and
    # signature are both perfectly real, because it is not HER credential —
    # the exact cross-principal scoping op_reauth_webauthn_finish's
    # own docstring names explicitly.
    r6 = H2({"op": "reauth_webauthn_begin", "session_id": wa_sid2})
    cross_challenge = r6["challenge"]
    cross_auth_data = authenticator_data(RP_ID, FLAG_UP | FLAG_UV, 1)
    cross_client_data = json.dumps({"type": "webauthn.get", "challenge": cross_challenge,
                                    "origin": ORIGIN}, separators=(",", ":")).encode()
    cross_signed = cross_auth_data + _hashlib.sha256(cross_client_data).digest()
    cross_signature = carol_key.sign(cross_signed, ec.ECDSA(hashes.SHA256()))
    r7 = H2({"op": "reauth_webauthn_finish", "session_id": wa_sid2,
            "credential": {"id": _wl.b64url_encode(carol_credential_id), "response": {
                "clientDataJSON": _wl.b64url_encode(cross_client_data),
                "authenticatorData": _wl.b64url_encode(cross_auth_data),
                "signature": _wl.b64url_encode(cross_signature),
            }}})
    check("a genuine passkey belonging to a DIFFERENT principal is refused "
          "even though the ceremony itself is perfectly valid", r7["status"], 403)

section("dashboard_access: the private-dashboard ladder, asked over the socket")
r = H({"op": "dashboard_access", "viewer": "alice", "target": "alice"})
check("your own dashboard", r["allowed"], True)
r = H({"op": "dashboard_access", "viewer": "alice", "target": "svc"})
check("an admin (alice, by now) may open an operator's", r["allowed"], True)
r = H({"op": "dashboard_access", "viewer": "svc", "target": "alice"})
check("...but the operator may not open hers", r["allowed"], False)
check("...and is told why", "private" in r["reason"], True)
check("a missing field is a 400, not a crash",
      H({"op": "dashboard_access", "viewer": "alice"})["status"], 400)

section("engagement grant shapes (audit run 1, F13)")
check("engagement-set is bound to a SHA-256",
      authd.Service._validate_action({"action": {"op": "engagement-set", "sha256": "a" * 64}}),
      {"op": "engagement-set", "sha256": "a" * 64, "resource": "org"})
check("engagement-approve is bound to a digest",
      authd.Service._validate_action({"action": {"op": "engagement-approve", "digest": "b" * 64}}),
      {"op": "engagement-approve", "digest": "b" * 64, "resource": "org"})
try:
    authd.Service._validate_action({"action": {"op": "engagement-approve", "digest": "not-hex"}})
    check("a malformed digest is refused", "accepted", "refused")
except authd.AuthError:
    check("a malformed digest is refused", True, True)

section("create-user grant shape (operator decision 2026-10-22)")
_ok = authd.Service._validate_action({"action": {"op": "create-user", "principal": "newbie",
                                                  "kind": "user", "role": "operator"}})
check("a create-user action names exactly the account, kind and role",
      _ok, {"op": "create-user", "principal": "newbie", "kind": "user", "role": "operator", "resource": "org"})
for _bad, _why in (({"kind": "robot"}, "kind"), ({"role": "root"}, "role"), ({"principal": "../x"}, "principal")):
    try:
        authd.Service._validate_action({"action": {"op": "create-user", "principal": "newbie",
                                                    "kind": "user", "role": "operator", **_bad}})
        check(f"a bad {_why} is refused before any credential is spent", "accepted", "refused")
    except authd.AuthError:
        check(f"a bad {_why} is refused before any credential is spent", True, True)

print(f"\n{'=' * 52}\n  {PASS} passed, {FAIL} failed\n{'=' * 52}")
sys.exit(1 if FAIL else 0)
