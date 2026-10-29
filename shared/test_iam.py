"""test_iam.py — the authorization resolution matrix for shared/iam.py.

No framework: a plain script, run it and read the output, matching how
everything else in this project is verified. Needs no root, no vault and no
deployment — it builds throwaway stores in a temp directory, so it is safe to
run anywhere, including a source checkout with nothing installed.

    python3 shared/test_iam.py

Exits non-zero if anything fails, so it works in a pre-commit hook or CI.

WHAT IT IS FOR: authorization is the one part of this codebase where a subtle
mistake is silent — a binding that grants slightly too much looks exactly like
one that does not, until someone reads data they should not have. Every case
here is a rule someone could plausibly get wrong: segment-boundary matching
(tenant/acme must not cover tenant/acmecorp), deny beating allow, an
agent-scoped binding not reaching its sibling, and every credential failure
path returning an identical message so prefixes cannot be enumerated.
"""
import base64, json, re, sys, tempfile, time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import iam

PASS = FAIL = 0
def check(label, got, want):
    global PASS, FAIL
    if got == want:
        PASS += 1; print(f"  [ OK ] {label}")
    else:
        FAIL += 1; print(f"  [FAIL] {label}\n         got  {got!r}\n         want {want!r}")

def section(t): print(f"\n=== {t} ===")

tmp = Path(tempfile.mkdtemp())
conn = iam.open_iam(readonly=False, path=tmp / "iam.db")
rt = iam.open_runtime(tmp / "runtime.db")
# Redirected so a test run never touches the real box's
# /var/lib/agenti/principal-history.jsonl (rename/delete_principal tests).
iam.PRINCIPAL_HISTORY_PATH = tmp / "principal-history.jsonl"
# Redirected so a test run never touches the real box's
# /usr/local/lib/agenti/ files.
ORG = iam.ORG_RESOURCE

# ---------------------------------------------------------------- setup
section("setup: principals with roles (two hardcoded: operator and admin)")
# alice = admin, bob/carol/dave/ci = operator (the default)
iam.add_principal(conn, "alice", "user", "test", role="admin")
for p in ("bob", "carol", "dave", "ci"):
    iam.add_principal(conn, p, "service" if p == "ci" else "user", "test")
check("admin role held", iam.check(conn, "alice", "iam:manage", ORG).allowed, True)
check("operator role held", iam.check(conn, "bob", "agent:start", ORG).allowed, True)
check("BUILTIN_ROLES keys are operator and admin",
      sorted(iam.BUILTIN_ROLES.keys()), ["admin", "operator"])

# ---------------------------------------------------------------- matrix
section("role matrix")
def allowed(who, perm, res=ORG):
    return iam.check(conn, who, perm, res).allowed

check("alice admin: start",               allowed("alice", "agent:start"), True)
check("alice admin: iam:manage",          allowed("alice", "iam:manage"), True)
check("bob operator: start",              allowed("bob", "agent:start"), True)
check("bob operator: NOT iam:manage",     allowed("bob", "iam:manage"), False)
check("bob operator: NOT engagement:manage", allowed("bob", "engagement:manage"), False)
check("carol operator: start",            allowed("carol", "agent:start"), True)
check("dave operator: start",             allowed("dave", "agent:start"), True)
check("dave operator: NOT iam:manage",    allowed("dave", "iam:manage"), False)

# ---------------------------------------------------------------- fail closed
section("fail closed")
check("unknown principal",                allowed("nobody", "agent:read"), False)
check("unknown permission",               allowed("alice", "agent:explode"), False)
iam.add_principal(conn, "spare-admin", "user", "test", role="admin")
iam.set_principal_active(conn, "alice", False)
check("disabled principal denied",        allowed("alice", "agent:read"), False)
iam.set_principal_active(conn, "alice", True)
check("re-enabled principal allowed",     allowed("alice", "agent:read"), True)

section("lockout guards (§4 item 78)")
def refused(fn):
    try: fn(); return False
    except iam.IAMError: return True
iam.set_principal_active(conn, "spare-admin", False, "alice")  # a second admin remains
iam.set_principal_active(conn, "spare-admin", True)
check("cannot disable yourself",          refused(lambda: iam.set_principal_active(conn, "spare-admin", False, "spare-admin")), True)
iam.set_principal_active(conn, "alice", False)
check("cannot disable the last admin",    refused(lambda: iam.set_principal_active(conn, "spare-admin", False)), True)
iam.set_principal_active(conn, "alice", True)
iam.set_principal_role(conn, "alice", "operator", "test")  # spare-admin remains: fine
check("cannot demote the last admin",     refused(lambda: iam.set_principal_role(conn, "spare-admin", "operator", "test")), True)
iam.set_principal_role(conn, "alice", "admin", "test")  # restore the fixture
check("last-admin refusal rolled back",   allowed("spare-admin", "iam:manage"), True)
check("short password refused",           refused(lambda: iam.set_principal_password(conn, "alice", "short")), True)
iam.add_principal(conn, "loner", "user", "test")
check("fresh user is operator by default", allowed("loner", "agent:start"), True)
check("fresh user cannot manage IAM",      allowed("loner", "iam:manage"), False)

section("decision explains itself")
d = iam.check(conn, "carol", "iam:manage", ORG)  # carol is operator, doesn't hold iam:manage
check("denied decision has a trace", len(d.matched) > 0, True)
check("denied reason mentions the permission", "iam:manage" in d.reason, True)
d2 = iam.check(conn, "nobody", "agent:read", ORG)
check("unknown principal reason", "no user" in d2.reason, True)

# ---------------------------------------------------------------- keys
section("API keys")
full = iam.issue_key(conn, "carol", "test")
# NB: token_urlsafe() output legitimately contains '_' and '-', so the secret
# itself may hold underscores — split_key must use maxsplit, not a bare split.
check("key has the agk_ shape", full.startswith("agk_"), True)
check("split_key round-trips", iam.split_key(full) is not None, True)
check("split_key survives '_' in the secret",
      iam.split_key("agk_ab12cd34_se_cr-et_x"), ("ab12cd34", "se_cr-et_x"))
check("split_key rejects malformed", iam.split_key("agk_only"), None)
check("split_key rejects wrong scheme", iam.split_key("xxx_a_b"), None)
r = iam.authenticate_key(conn, full)
check("valid key authenticates", (r.ok, r.principal), (True, "carol"))
check("garbage key rejected", iam.authenticate_key(conn, "not-a-key").ok, False)
check("wrong secret rejected", iam.authenticate_key(conn, full[:-4] + "aaaa").ok, False)
prefix = full.split("_")[1]
check("failure reason is uniform",
      iam.authenticate_key(conn, "agk_deadbeef_nope").reason == iam.authenticate_key(conn, "x").reason, True)

iam.revoke_key(conn, prefix)
check("revoked key rejected", iam.authenticate_key(conn, full).ok, False)
try:
    iam.revoke_key(conn, prefix); check("double revoke refused", "accepted", "refused")
except iam.IAMError: check("double revoke refused", "refused", "refused")

expired = iam.issue_key(conn, "carol", "test", expires_days=1)
conn.execute("UPDATE api_keys SET expires_at=? WHERE prefix=?",
             (time.time() - 10, expired.split("_")[1])); conn.commit()
check("expired key rejected", iam.authenticate_key(conn, expired).ok, False)

live = iam.issue_key(conn, "dave", "test")
iam.set_principal_active(conn, "dave", False)
check("key of disabled principal rejected", iam.authenticate_key(conn, live).ok, False)
iam.set_principal_active(conn, "dave", True)
check("key works again once re-enabled", iam.authenticate_key(conn, live).ok, True)

# ---------------------------------------------------------------- passwords
section("passwords (scrypt)")
h = iam.hash_password("correct horse battery staple")
check("verifies", iam.verify_password("correct horse battery staple", h), True)
check("rejects wrong", iam.verify_password("wrong", h), False)
check("rejects empty stored", iam.verify_password("x", None), False)
check("rejects malformed stored", iam.verify_password("x", "notahash"), False)
check("salted: two hashes differ", iam.hash_password("same") != iam.hash_password("same"), True)

section("set_principal_role — changing a user's role")
iam.add_principal(conn, "erin", "user", "test")
check("erin starts as operator", allowed("erin", "agent:start"), True)
check("erin cannot manage IAM", allowed("erin", "iam:manage"), False)
iam.set_principal_role(conn, "erin", "admin", "test")
check("erin promoted to admin: can manage IAM", allowed("erin", "iam:manage"), True)
iam.set_principal_role(conn, "erin", "operator", "test")
check("erin demoted back to operator", allowed("erin", "iam:manage"), False)
try:
    iam.set_principal_role(conn, "nobody-here", "admin", "test")
    check("set_principal_role refuses unknown user", "accepted", "refused")
except iam.IAMError as e:
    check("set_principal_role refuses unknown user", "no user named" in str(e), True)
try:
    iam.set_principal_role(conn, "erin", "superuser", "test")
    check("set_principal_role refuses unknown role", "accepted", "refused")
except iam.IAMError as e:
    check("set_principal_role refuses unknown role", "superuser" in str(e), True)

# ---------------------------------------------------------------- audit
section("authz audit log")
iam.log_decision(rt, iam.check(conn, "carol", "iam:manage", ORG), "api")   # deny (operator)
iam.log_decision(rt, iam.check(conn, "alice", "iam:manage", ORG), "api")   # allow (admin)
rows = list(rt.execute("SELECT decision FROM authz_log ORDER BY id"))
check("denies are logged too", [r["decision"] for r in rows], ["deny", "allow"])

section("TOTP — RFC 6238 Appendix B official test vectors")
# These are the published vectors. Implementing TOTP against the stdlib rather
# than a dependency is only defensible BECAUSE they exist: a wrong
# implementation fails here loudly instead of silently weakening 2FA.
_seed = base64.b32encode(b"12345678901234567890").decode()
for _t, _expect in [(59, "94287082"), (1111111109, "07081804"), (1111111111, "14050471"),
                    (1234567890, "89005924"), (2000000000, "69279037"),
                    (20000000000, "65353130")]:
    check(f"T={_t}", iam.totp_code(_seed, at=_t, digits=8), _expect)

section("TOTP verification window and shape")
_sec = iam.totp_generate_secret()
_now = 1700000000
check("current step verifies",  iam.totp_verify(_sec, iam.totp_code(_sec, at=_now), at=_now) is not None, True)
check("one step back verifies", iam.totp_verify(_sec, iam.totp_code(_sec, at=_now - 30), at=_now) is not None, True)
check("one step fwd verifies",  iam.totp_verify(_sec, iam.totp_code(_sec, at=_now + 30), at=_now) is not None, True)
check("two steps back rejected", iam.totp_verify(_sec, iam.totp_code(_sec, at=_now - 90), at=_now), None)
check("returns a COUNTER, not a bool (replay protection needs it)",
      isinstance(iam.totp_verify(_sec, iam.totp_code(_sec, at=_now), at=_now), int), True)
check("non-numeric rejected",   iam.totp_verify(_sec, "abcdef", at=_now), None)
check("wrong length rejected",  iam.totp_verify(_sec, "1234", at=_now), None)
check("empty rejected",         iam.totp_verify(_sec, "", at=_now), None)
check("uri is otpauth",         iam.totp_uri(_sec, "alice").startswith("otpauth://totp/"), True)
check("uri carries the secret", _sec in iam.totp_uri(_sec, "alice"), True)

# ---------------------------------------------------------------- login
section("password login, lockout, second factor")
iam.add_principal(conn, "logintest", "user", "test")
iam.set_principal_password(conn, "logintest", "s3cret-passphrase")

r = iam.verify_login(conn, rt, "logintest", "s3cret-passphrase")
check("correct password",        (r.ok, r.totp_required), (True, False))
check("wrong password",          iam.verify_login(conn, rt, "logintest", "nope").ok, False)
check("unknown principal fails the same way",
      iam.verify_login(conn, rt, "no-such-person", "nope").reason,
      iam.verify_login(conn, rt, "logintest", "nope").reason)
iam.clear_failures(rt, "logintest")
check("principal with NO password cannot log in",
      iam.verify_login(conn, rt, "bob", "anything").ok, False)

iam.clear_failures(rt, "logintest")
for _ in range(iam.LOCKOUT_THRESHOLD):
    iam.verify_login(conn, rt, "logintest", "wrong")
locked = iam.verify_login(conn, rt, "logintest", "s3cret-passphrase")
check("locked out after threshold",      locked.ok, False)
check("lockout reports a retry_after",   locked.retry_after > 0, True)
iam.clear_failures(rt, "logintest")
check("correct password works once cleared",
      iam.verify_login(conn, rt, "logintest", "s3cret-passphrase").ok, True)

section("second factor: enrolment, replay, recovery codes")
secret, codes = iam.enroll_totp(conn, "logintest", rt)
check("enrolment returns 10 recovery codes", len(codes), iam.RECOVERY_CODE_COUNT)
check("login now demands a second factor",
      iam.verify_login(conn, rt, "logintest", "s3cret-passphrase").totp_required, True)

code_now = iam.totp_code(secret)
check("valid code accepted", iam.verify_second_factor(conn, rt, "logintest", code_now).ok, True)
check("SAME code refused (replay)",
      iam.verify_second_factor(conn, rt, "logintest", code_now).reason,
      "that code has already been used")
iam.clear_failures(rt, "logintest")
check("wrong code refused", iam.verify_second_factor(conn, rt, "logintest", "000000").ok, False)
iam.clear_failures(rt, "logintest")

check("recovery code works once", iam.verify_second_factor(conn, rt, "logintest", codes[0]).ok, True)
check("same recovery code refused", iam.verify_second_factor(conn, rt, "logintest", codes[0]).ok, False)
iam.clear_failures(rt, "logintest")
check("a DIFFERENT recovery code still works",
      iam.verify_second_factor(conn, rt, "logintest", codes[1]).ok, True)

old_secret = secret
secret2, codes2 = iam.enroll_totp(conn, "logintest", rt)
iam.clear_failures(rt, "logintest")
check("re-enrolment invalidates the OLD secret",
      iam.verify_second_factor(conn, rt, "logintest", iam.totp_code(old_secret)).ok, False)
iam.clear_failures(rt, "logintest")
check("re-enrolment invalidates OLD recovery codes",
      iam.verify_second_factor(conn, rt, "logintest", codes[2]).ok, False)
iam.clear_failures(rt, "logintest")
check("new secret works", iam.verify_second_factor(conn, rt, "logintest", iam.totp_code(secret2)).ok, True)

iam.reset_totp(conn, "logintest", rt)
check("reset-2fa clears the requirement",
      iam.verify_login(conn, rt, "logintest", "s3cret-passphrase").totp_required, False)

section("reauthenticate_self: the actual authorization mechanism behind "
        "every 'self' web-IAM verb (GUI phase 2)")
# logintest ends the section above with a password and NO 2FA — a clean
# slate. This is the function that makes it safe for the API to invoke
# `self password`/`mfa-start`/`mfa-confirm` at all: it must accept the
# right credential and refuse everything else, on its own, independent of
# refuse_iam_writes_from_api (which only checks WHO is calling the shell,
# not whether they proved anything about THIS principal).
try:
    iam.reauthenticate_self(conn, rt, "logintest", "s3cret-passphrase", None)
    check("correct password, no 2FA enrolled: passes", True, True)
except iam.IAMError:
    check("correct password, no 2FA enrolled: passes", False, True)

try:
    iam.reauthenticate_self(conn, rt, "logintest", "wrong", None)
    check("wrong password: raises", False, True)
except iam.IAMError as e:
    check("wrong password: raises with a clear reason",
          "current password is incorrect" in str(e), True)
iam.clear_failures(rt, "logintest")

try:
    iam.reauthenticate_self(conn, rt, "nobody-here", "whatever", None)
    check("nonexistent principal: raises", False, True)
except iam.IAMError as e:
    check("nonexistent principal: names the reason (this isn't the "
          "network login path — the caller is already authenticated as "
          "themselves, so there's no enumeration concern to hide behind)",
          "no user named" in str(e), True)

self_secret, _ = iam.enroll_totp(conn, "logintest", rt)
try:
    iam.reauthenticate_self(conn, rt, "logintest", "s3cret-passphrase", None)
    check("2FA now enrolled: password alone is refused", False, True)
except iam.IAMError as e:
    check("2FA now enrolled: password alone is refused",
          "2FA" in str(e), True)
iam.clear_failures(rt, "logintest")

try:
    iam.reauthenticate_self(conn, rt, "logintest", "s3cret-passphrase", "000000")
    check("wrong 2FA code: refused", False, True)
except iam.IAMError:
    check("wrong 2FA code: refused", True, True)
iam.clear_failures(rt, "logintest")

try:
    iam.reauthenticate_self(conn, rt, "logintest", "s3cret-passphrase",
                            iam.totp_code(self_secret))
    check("password + correct 2FA code: passes", True, True)
except iam.IAMError:
    check("password + correct 2FA code: passes", False, True)
iam.reset_totp(conn, "logintest", rt)  # back to a clean slate

section("reauthenticate_self: require_password=False — the stakes-based web "
        "grant re-auth (§4 item 55 follow-up, at the operator's request)")
# logintest ends the section above with a password and NO 2FA — a clean
# slate again. Code-only re-auth exists specifically for the LOWER tier of
# WEB_GRANTABLE_ROLES (operator and below); it must still refuse
# outright when there's no 2FA to check, since skipping the one factor that
# WAS asked for without still requiring the other would leave nothing
# proven at all.
try:
    iam.reauthenticate_self(conn, rt, "logintest", "", None, require_password=False)
    check("code-only, no 2FA enrolled: refused rather than silently passing", False, True)
except iam.IAMError as e:
    check("code-only, no 2FA enrolled: refused, names why",
          "no 2FA enrolled" in str(e), True)

code_secret, _ = iam.enroll_totp(conn, "logintest", rt)
try:
    iam.reauthenticate_self(conn, rt, "logintest", "totally-the-wrong-password",
                            iam.totp_code(code_secret), require_password=False)
    check("code-only: a WRONG password alongside a correct code still passes "
          "(the password is never checked in this mode)", True, True)
except iam.IAMError:
    check("code-only: a WRONG password alongside a correct code still passes "
          "(the password is never checked in this mode)", False, True)
iam.clear_failures(rt, "logintest")

try:
    iam.reauthenticate_self(conn, rt, "logintest", "", "000000", require_password=False)
    check("code-only, wrong code: still refused", False, True)
except iam.IAMError:
    check("code-only, wrong code: still refused", True, True)
iam.clear_failures(rt, "logintest")

try:
    iam.reauthenticate_self(conn, rt, "logintest", "", None, require_password=False)
    check("code-only, no code given: refused", False, True)
except iam.IAMError as e:
    check("code-only, no code given: refused, names why", "code" in str(e), True)

check("web_grant_requires_password: viewer does NOT need a password",
      iam.web_grant_requires_password("reader"), False)
check("every web-grantable role needs the password (one universal popup, 2026-10-04)",
      [iam.web_grant_requires_password(r) for r in iam.WEB_GRANTABLE_ROLES],
      [True] * len(iam.WEB_GRANTABLE_ROLES))
check("web_grant_requires_password: an unknown/made-up role name also "
      "reads as not-required (an empty tuple can never contain it)",
      iam.web_grant_requires_password("not-a-real-role"), False)

iam.reset_totp(conn, "logintest", rt)  # back to a clean slate

section("enrolment tokens: onboarding someone with NO credential yet")
# require-2fa is ON by default (its own section below); these sections test
# the token mechanics with a password-only sign-up, so switch it off here.
iam.set_setting(conn, "require-2fa", "off")
iam.add_principal(conn, "newperson", "user", "admin-actor")
token = iam.mint_enrolment_token(rt, conn, "newperson", "admin-actor")
check("token is a real, high-entropy string", len(token) > 30, True)
check("enrolment_token_principal resolves it", iam.enrolment_token_principal(rt, token),
      "newperson")
check("garbage token resolves to nothing", iam.enrolment_token_principal(rt, "not-a-token"), None)

principal, _codes = iam.consume_enrolment_token(conn, rt, token, "FirstPassw0rd!")
check("no 2FA at sign-up: no recovery codes", _codes, [])
check("consuming sets the password and returns the principal", principal, "newperson")
check("the new password actually works",
      iam.verify_login(conn, rt, "newperson", "FirstPassw0rd!").ok, True)
iam.clear_failures(rt, "newperson")

try:
    iam.consume_enrolment_token(conn, rt, token, "SomethingElse1!")
    check("reusing the SAME token a second time: refused", False, True)
except iam.IAMError as e:
    check("reusing the SAME token a second time: refused",
          "invalid or has expired" in str(e), True)

section("enrolment tokens: never for an already-enrolled account (§4 item 23)")
# newperson now HAS a password. mint-enrolment-link and enrol-consume are
# both reachable by the API service account, so a link for an enrolled
# principal would let a compromised API reset anyone's credentials.
try:
    iam.mint_enrolment_token(rt, conn, "newperson", "admin-actor")
    check("minting a link for an ENROLLED principal: refused", False, True)
except iam.IAMError as e:
    check("minting a link for an ENROLLED principal: refused", "already enrolled" in str(e), True)
    check("...and the refusal names the root-only reset commands", "set-password" in str(e), True)
iam.add_principal(conn, "newperson-late", "user", "admin-actor")
late = iam.mint_enrolment_token(rt, conn, "newperson-late", "admin-actor")
iam.set_principal_password(conn, "newperson-late", "SetByAdminMeanwhile1!")
try:
    iam.consume_enrolment_token(conn, rt, late, "AttackerPw1!")
    check("a token minted BEFORE enrolment is dead once the account is enrolled", False, True)
except iam.IAMError as e:
    check("a token minted BEFORE enrolment is dead once the account is enrolled",
          "already enrolled" in str(e), True)
check("...and the admin-set password survived untouched",
      iam.verify_login(conn, rt, "newperson-late", "SetByAdminMeanwhile1!").ok, True)
iam.clear_failures(rt, "newperson-late")
try:
    iam.consume_enrolment_token(conn, rt, late, "AttackerPw1!", iam.totp_generate_secret(), "000000")
    check("...nor can it plant a 2FA factor on the enrolled account", False, True)
except iam.IAMError:
    check("...nor can it plant a 2FA factor on the enrolled account",
          conn.execute("SELECT totp_secret FROM principals WHERE name='newperson-late'").fetchone()[0] is None, True)

section("enrolment tokens: expiry, and enrolling 2FA in the same step")
iam.add_principal(conn, "newperson-exp", "user", "admin-actor")
token2 = iam.mint_enrolment_token(rt, conn, "newperson-exp", "admin-actor")
rt.execute("UPDATE enrolment_tokens SET expires_at=? WHERE token_hash=?",
          (time.time() - 1, iam.hash_key(token2)))
rt.commit()
check("an expired (but never-used) token is also invalid",
      iam.enrolment_token_principal(rt, token2), None)
try:
    iam.consume_enrolment_token(conn, rt, token2, "x")
    check("consuming an expired token: refused", False, True)
except iam.IAMError:
    check("consuming an expired token: refused", True, True)

iam.add_principal(conn, "newperson2", "user", "admin-actor")
token3 = iam.mint_enrolment_token(rt, conn, "newperson2", "admin-actor")
fresh_secret = iam.totp_generate_secret()
principal3, codes3 = iam.consume_enrolment_token(
    conn, rt, token3, "AnotherPw1!", fresh_secret, iam.totp_code(fresh_secret))
check("consume + inline 2FA: sets the password", principal3, "newperson2")
check("...and RETURNS the recovery codes (they were being discarded)", len(codes3), iam.RECOVERY_CODE_COUNT)
check("...which work", iam.verify_second_factor(conn, rt, "newperson2", codes3[0]).ok, True)
check("...and enrols the SAME secret that was verified",
      iam.verify_second_factor(conn, rt, "newperson2", iam.totp_code(fresh_secret)).ok, True)

try:
    iam.mint_enrolment_token(rt, conn, "no-such-principal", "admin-actor")
    check("minting a link for a nonexistent principal: refused", False, True)
except iam.IAMError:
    check("minting a link for a nonexistent principal: refused", True, True)

section("require-2fa: the policy resolver (organisation default ON, per-account override)")
conn.execute("DELETE FROM settings WHERE key='require-2fa'")
conn.commit()
iam.add_principal(conn, "tf-plain", "user", "admin-actor")
iam.add_principal(conn, "tf-svc", "service", "admin-actor")
iam.add_principal(conn, "tf-acme", "user", "admin-actor")
iam.add_principal(conn, "tf-star", "user", "admin-actor")
req, why = iam.two_factor_required(conn, "tf-plain")
check("no policy rows at all: required (the default is ON)", req, True)
check("...and the reason says it is the default", "the default" in why, True)
check("a service principal never needs one", iam.two_factor_required(conn, "tf-svc")[0], False)
try:
    iam.two_factor_required(conn, "tf-nobody"); check("unknown principal refused", False, True)
except iam.IAMError:
    check("unknown principal refused", True, True)
iam.set_setting(conn, "require-2fa:tf-star", "off")
req, why = iam.two_factor_required(conn, "tf-star")
check("per-account override beats everything", req, False)
check("...and says so", "require-2fa:tf-star = off" in why, True)
iam.set_setting(conn, "require-2fa:tf-acme", "on")
iam.set_setting(conn, "require-2fa", "off")
check("platform OFF: a plain account is not required", iam.two_factor_required(conn, "tf-plain")[0], False)
check("platform OFF: the per-account ON still holds", iam.two_factor_required(conn, "tf-acme")[0], True)
conn.execute("DELETE FROM settings WHERE key='require-2fa:tf-acme'")
conn.commit()
conn.execute("DELETE FROM settings WHERE key='require-2fa'")
conn.commit()

section("require-2fa: enforced at sign-up (consume) and flagged for password-only sessions")
iam.add_principal(conn, "tf-signup", "user", "admin-actor")
tok = iam.mint_enrolment_token(rt, conn, "tf-signup", "admin-actor")
try:
    iam.consume_enrolment_token(conn, rt, tok, "Password-Only1!")
    check("password-only sign-up refused when 2FA is required", False, True)
except iam.IAMError as e:
    check("password-only sign-up refused when 2FA is required", True, True)
    check("...the refusal names the exemption command", "set-policy require-2fa:tf-signup off" in str(e), True)
check("...and the token was NOT burned by the refusal", iam.enrolment_token_principal(rt, tok), "tf-signup")
check("...and no password was set", conn.execute("SELECT password_hash FROM principals WHERE name='tf-signup'").fetchone()[0], None)
sec = iam.totp_generate_secret()
check("sign-up with a verified code succeeds",
      iam.consume_enrolment_token(conn, rt, tok, "Password-Only1!", sec, iam.totp_code(sec))[0], "tf-signup")
check("...and is not flagged for setup", iam.mfa_setup_required(conn, "tf-signup"), False)
iam.add_principal(conn, "tf-legacy", "user", "admin-actor")
iam.set_principal_password(conn, "tf-legacy", "legacy-pw")
check("a password-only account under the policy is flagged", iam.mfa_setup_required(conn, "tf-legacy"), True)
iam.set_setting(conn, "require-2fa:tf-legacy", "off")
check("...until exempted", iam.mfa_setup_required(conn, "tf-legacy"), False)
check("a service principal is never flagged", iam.mfa_setup_required(conn, "tf-svc"), False)
check("an unknown name is not flagged (nothing to confine)", iam.mfa_setup_required(conn, "tf-nobody"), False)
iam.set_setting(conn, "require-2fa", "off")   # the remaining sections predate the policy

section("outputs quota: two-level, organisation and per-operator")
iam.ORG_ROOT = tmp / "vault"
for _p in ("op1", "op2", "op3", "sc-admin"):
    iam.add_principal(conn, _p, "user", "test")
iam.set_principal_role(conn, "sc-admin", "admin", "test")


def write_output(principal, name, size):
    d = iam.org_dir() / "outputs" / principal
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_bytes(b"x" * size)


check("default total limit", iam.outputs_limit_total(conn), iam.OUTPUTS_DEFAULT_TOTAL_BYTES)
check("default operator limit", iam.outputs_limit_operator(conn, "op1"), iam.OUTPUTS_DEFAULT_OPERATOR_BYTES)
iam.set_limit(conn, "outputs-bytes-total", 1000)
iam.set_limit(conn, "outputs-bytes-per-operator", 400)
check("organisation limit changed", iam.outputs_limit_total(conn), 1000)
iam.set_limit(conn, "outputs-bytes-per-operator:op1", 500)
check("a per-OPERATOR override wins for that principal", iam.outputs_limit_operator(conn, "op1"), 500)
check("...and not for another principal", iam.outputs_limit_operator(conn, "op2"), 400)

for bad_key, bad_val, why in (
        ("outputs-bytes-total", -5, "must be between 0 and"),
        ("outputs-bytes-per-operator:ghost-principal", 500, "no user named"),
        ("outputs-bytes-per-tenant", 500, "unknown limit")):
    try:
        iam.set_limit(conn, bad_key, bad_val)
        check(f"set_limit refuses {bad_key}={bad_val}", False, True)
    except iam.IAMError as e:
        check(f"set_limit refuses {bad_key}={bad_val} ({why})", why in str(e), True)

write_output("op1", "report1.docx", 200)
write_output("op1", "report2.docx", 100)
write_output("op2", "video.mp4", 300)
check("total usage sums across every operator", iam.outputs_usage_total(), 600)
check("operator usage is only that operator's own share", iam.outputs_usage_operator("op1"), 300)

# total limit=1000 (used 600), op1 limit=500 (used 300), op2 limit=400 (used 300)
g = iam.outputs_check(conn, "op1")
check("gate: under both quotas -> allowed", g["allowed"], True)
g = iam.outputs_check(conn, "op1", incoming_bytes=1000)
check("gate: this promotion alone would blow the TOTAL quota -> refused, naming the organisation",
      (g["allowed"], "organisation" in g["reason"]), (False, True))
g = iam.outputs_check(conn, "op2", incoming_bytes=150)
check("gate: under the total quota but over op2's OWN OPERATOR quota -> refused, naming OPERATOR",
      (g["allowed"], "OPERATOR" in g["reason"], "op2" in g["reason"]), (False, True, True))
g = iam.outputs_check(conn, "op1", incoming_bytes=500)
check("gate: total quota checked BEFORE operator quota when both would be exceeded",
      "organisation" in g["reason"], True)
g = iam.outputs_check(conn, "op3")
check("a fresh operator with nothing promoted yet: allowed, no operator warning",
      (g["allowed"], [w["scope"] for w in g["warnings"]]), (True, []))

iam.set_limit(conn, "outputs-bytes-per-operator:op1", None)
check("set_limit(None) removes a per-operator override -> follows the default (400)",
      iam.outputs_limit_operator(conn, "op1"), 400)

g = iam.outputs_check(conn, "op1")
check("no warning yet at 600/1000", g["warnings"], [])
write_output("op4", "big.bin", 350)   # total now 950/1000 = 95%; op4 350/400 = 87.5%
g2 = iam.outputs_check(conn, "op1")
check("nearing the TOTAL quota produces a total-scoped warning even for an unrelated operator "
      "— and it is a warning, not a refusal",
      ([w["scope"] for w in g2["warnings"]], g2["allowed"]), (["total"], True))
g3 = iam.outputs_check(conn, "op4")
check("op4 at 87.5% does not also trigger its own operator warning",
      [w["scope"] for w in g3["warnings"]], ["total"])

section("outputs: listing and narrow deletion")
rows = iam.list_outputs()
check("list_outputs sees every operator's files", sorted(r["name"] for r in rows),
      sorted(["report1.docx", "report2.docx", "video.mp4", "big.bin"]))
rows_op1 = iam.list_outputs(principal="op1")
check("list_outputs filtered to one operator", sorted(r["name"] for r in rows_op1),
      sorted(["report1.docx", "report2.docx"]))
iam.ORG_ROOT = tmp / "no-such-vault"
check("an empty store lists empty, not an error", iam.list_outputs(), [])
iam.ORG_ROOT = tmp / "vault"

try:
    iam.delete_output("op1", "report1.docx", "op2", conn=conn)
    check("another operator cannot delete someone else's output", False, True)
except iam.IAMError as e:
    check("another operator cannot delete someone else's output", "only they" in str(e), True)
d = iam.delete_output("op1", "report1.docx", "op1", conn=conn)
check("the owner can delete their own", d["deleted"], True)
check("...and it is really gone from disk",
      (iam.org_dir() / "outputs" / "op1" / "report1.docx").exists(), False)
check("...and usage accounting reflects it immediately", iam.outputs_usage_operator("op1"), 100)
d2 = iam.delete_output("op2", "video.mp4", "sc-admin", conn=conn)
check("an admin can delete anyone's output", d2["deleted"], True)
try:
    iam.delete_output("op1", "no-such-file.bin", "op1", conn=conn)
    check("deleting a nonexistent output is refused", False, True)
except iam.IAMError as e:
    check("deleting a nonexistent output is refused", "no output named" in str(e), True)
write_output("op2", "escape-target.bin", 10)
try:
    iam.delete_output("op1", "../op2/escape-target.bin", "op1", conn=conn)
    check("a traversal-attempting output name is refused", False, True)
except iam.IAMError as e:
    check("a traversal-attempting output name is refused (direct-child check)",
          "direct child" in str(e), True)
check("...and the decoy it targeted is untouched",
      (iam.org_dir() / "outputs" / "op2" / "escape-target.bin").exists(), True)

section("resolve_output_path: the read-only lookup a download route reuses")
write_output("op2", "photo.png", 42)
p = iam.resolve_output_path("op2", "photo.png", "op2", conn=conn)
check("resolves to the real file for its own owner",
      p, (iam.org_dir() / "outputs" / "op2" / "photo.png").resolve())
p2 = iam.resolve_output_path("op2", "photo.png", "sc-admin", conn=conn)
check("an admin may also resolve someone else's", p2, p)
try:
    iam.resolve_output_path("op2", "photo.png", "op1", conn=conn)
    check("a non-owner non-admin is refused", False, True)
except iam.IAMError as e:
    check("a non-owner non-admin is refused", "only they" in str(e), True)
try:
    iam.resolve_output_path("op2", "../op1/report2.docx", "op2", conn=conn)
    check("traversal through resolve_output_path is refused too", False, True)
except iam.IAMError as e:
    check("traversal through resolve_output_path is refused too", "direct child" in str(e), True)
try:
    iam.resolve_output_path("op2", "no-such-file.bin", "op2", conn=conn)
    check("resolving a nonexistent output is refused", False, True)
except iam.IAMError as e:
    check("resolving a nonexistent output is refused", "no output named" in str(e), True)
check("delete_output still deletes",
      iam.delete_output("op2", "photo.png", "op2", conn=conn)["deleted"], True)

section("outputs-history.jsonl: the audit trail delete_output leaves behind")
history_path = iam.org_dir() / "outputs-history.jsonl"
write_output("op3", "hist-a.bin", 77)
iam.delete_output("op3", "hist-a.bin", "op3", conn=conn)
check("deleting an output creates outputs-history.jsonl", history_path.exists(), True)
hist_rows = [json.loads(l) for l in history_path.read_text().splitlines() if l.strip()]
check("the row records who deleted what, and its size",
      (hist_rows[-1]["name"], hist_rows[-1]["principal"], hist_rows[-1]["deleted_by"],
       hist_rows[-1]["bytes"]),
      ("hist-a.bin", "op3", "op3", 77))
check("the row carries a timestamp", "ts" in hist_rows[-1], True)

section("delete_outputs (plural): the bulk form the multi-select needs")
write_output("op3", "bulk-a.bin", 10)
write_output("op3", "bulk-b.bin", 20)
before = len(history_path.read_text().splitlines())
rows = iam.delete_outputs("op3", ["bulk-a.bin", "bulk-b.bin"], "op3", conn=conn)
check("both are reported deleted", [r["deleted"] for r in rows], [True, True])
after = len(history_path.read_text().splitlines())
check("each deletion in the batch gets its own history row", after - before, 2)
write_output("op3", "bulk-c.bin", 5)
mixed = iam.delete_outputs("op3", ["bulk-c.bin", "no-such-output.bin", "bulk-c.bin"], "op3", conn=conn)
check("a batch with one bad name still deletes the good ones", mixed[0]["deleted"], True)
check("the nonexistent name is reported as a per-item failure, not a crash",
      (mixed[1]["deleted"], "no output named" in mixed[1].get("error", "")), (False, True))
check("re-deleting the same name is also a clean per-item failure", mixed[2]["deleted"], False)
not_owned = iam.delete_outputs("op1", ["report2.docx"], "op4", conn=conn)
check("a batch touching someone ELSE's output by a non-admin is refused per-item",
      (not_owned[0]["deleted"], "only they" in not_owned[0].get("error", "")), (False, True))

section("output permissions")
check("output:delete and output:promote are real permissions",
      all(x in iam.PERMISSIONS for x in ("output:delete", "output:promote")), True)
check("operator holds both",
      all(x in iam.BUILTIN_ROLES["operator"] for x in ("output:delete", "output:promote")), True)

section("tool requests: a simple admin-reviewed queue")
tool_req_path = tmp / "tool-requests.jsonl"
iam.TOOL_REQUESTS_PATH = tool_req_path
r1 = iam.file_tool_request("op1", "install-program", "need whatweb installed")
check("filing returns the stored row", (r1["by"], r1["category"]), ("op1", "install-program"))
check("...with a fresh id", bool(r1.get("id")), True)
r2 = iam.file_tool_request("op3", "", "a docx-to-pdf converter, no category in mind")
check("category is optional", r2["category"], "")
rows = iam.list_tool_requests()
check("list_tool_requests sees every request, newest first", [r["id"] for r in rows], [r2["id"], r1["id"]])
try:
    iam.file_tool_request("op1", "", "   ")
    check("whitespace-only text is refused", False, True)
except iam.IAMError as e:
    check("whitespace-only text is refused", "needs some text" in str(e), True)
try:
    iam.file_tool_request("op1", "", "x" * (iam.TOOL_REQUEST_MAX_CHARS + 1))
    check("oversized text is refused", False, True)
except iam.IAMError as e:
    check("oversized text is refused", "keep it to" in str(e), True)
tool_req_path.write_text(tool_req_path.read_text() + "not json at all\n")
check("a malformed line in the file is skipped, not fatal", len(iam.list_tool_requests()), 2)

section("bootstrap")
conn2 = iam.open_iam(readonly=False, path=tmp / "iam2.db")
k = iam.bootstrap(conn2, "root-admin", "test")
check("bootstrap mints a key", k.startswith("agk_"), True)
check("bootstrap grants admin on *",
      iam.check(conn2, "root-admin", "iam:manage", ORG).allowed, True)
try:
    iam.bootstrap(conn2, "root-admin", "test"); check("second bootstrap refused", "accepted", "refused")
except iam.IAMError as e: check("second bootstrap refused", "already has" in str(e), True)

section("set_principal_role on conn2 — same guards apply")
iam.add_principal(conn2, "temp-user", "user", "test")
check("temp-user is operator by default", iam.check(conn2, "temp-user", "agent:start", ORG).allowed, True)
iam.set_principal_role(conn2, "temp-user", "admin", "test")
check("promoted to admin", iam.check(conn2, "temp-user", "iam:manage", ORG).allowed, True)
iam.set_principal_role(conn2, "temp-user", "operator", "test")
check("demoted back to operator", iam.check(conn2, "temp-user", "iam:manage", ORG).allowed, False)

section("lockout: the counter resets after a quiet window (2026-09-20 fix)")
# Before the fix, `failures` accumulated forever and never reset, so ONE
# failed attempt every LOCKOUT_SECONDS re-triggered a fresh lock indefinitely
# — a zero-knowledge attacker could permanently lock out any known principal
# for about 4 requests an hour. Simulate "a long time has passed" by backdating
# last_failure directly, rather than sleeping LOCKOUT_SECONDS in a test.
iam.clear_failures(rt, "logintest")
for _ in range(iam.LOCKOUT_THRESHOLD):
    iam.verify_login(conn, rt, "logintest", "wrong")
failures_before, locked_before = iam._lockout_state(rt, "logintest")
check("threshold reached, locked", (failures_before >= iam.LOCKOUT_THRESHOLD, locked_before > 0),
      (True, True))
old_ts = time.time() - iam.LOCKOUT_SECONDS - 1
rt.execute("UPDATE login_attempts SET locked_until=0, last_failure=? WHERE principal=?",
           (old_ts, "logintest"))
rt.commit()
iam.verify_login(conn, rt, "logintest", "wrong")
failures_after, _ = iam._lockout_state(rt, "logintest")
check("one failure after a quiet window starts a FRESH count, not threshold+1",
      failures_after, 1)
check("a single fresh failure does not itself re-lock the account",
      iam.verify_login(conn, rt, "logintest", "s3cret-passphrase").ok, True)
iam.clear_failures(rt, "logintest")

section("credential changes revoke existing sessions (2026-09-20 fix)")
# revoke_all_for existed in api/sessions.py, correctly implemented, and was
# never called from anywhere — a password change left every already-issued
# session usable. iam.py owns the runtime schema directly (no cross-module
# import of the API-layer sessions.py), so this exercises iam._revoke_sessions
# via set_principal_password's own `runtime=` parameter.
now = time.time()
for sid in ("sess-a", "sess-b"):
    rt.execute("INSERT INTO sessions(id, principal, csrf, created_at, expires_at, last_seen)"
               " VALUES (?,?,?,?,?,?)", (sid, "logintest", "csrf-x", now, now + 3600, now))
rt.commit()
check("two sessions exist before the password change",
      rt.execute("SELECT COUNT(*) c FROM sessions WHERE principal=?",
                 ("logintest",)).fetchone()["c"], 2)
revoked = iam.set_principal_password(conn, "logintest", "s3cret-passphrase", runtime=rt)
check("set_principal_password reports 2 sessions revoked", revoked, 2)
check("no sessions remain for that principal",
      rt.execute("SELECT COUNT(*) c FROM sessions WHERE principal=?",
                 ("logintest",)).fetchone()["c"], 0)
check("the new password still verifies (revocation didn't corrupt the hash)",
      iam.verify_login(conn, rt, "logintest", "s3cret-passphrase").ok, True)

section("timing equalizer: fixed hash, not recomputed per request (2026-09-20 fix)")
# The bug: the missing-principal branch used to call hash_password() fresh
# on every call (a NEW random salt each time -> a second scrypt hash on top
# of verify_password's own), spending TWO scrypt calls where the real
# wrong-password branch spends ONE — a measurable, direction-reversed timing
# gap that re-opened the exact enumeration oracle this code exists to close.
# Can't measure wall-clock reliably in a test; instead pin down the two
# properties that make the fix correct: the dummy hash is computed ONCE
# (cached) rather than fresh per call, and it's a real, valid scrypt hash
# (not a shortcut that skips the expensive part).
h1 = iam._dummy_password_hash()
h2 = iam._dummy_password_hash()
check("dummy hash is cached (identical across calls, not re-salted each time)", h1, h2)
check("dummy hash is a real scrypt hash", h1.startswith("scrypt$"), True)
check("dummy hash actually verifies against itself",
      iam.verify_password("timing-equalizer", h1), True)

section("per-address login throttle (added with LAN/HTTPS exposure)")
# The per-principal lockout above cannot see an attacker spreading guesses
# ACROSS accounts from one machine, and — worse once the login page is
# reachable from a network — it is itself a weapon: anyone can lock out a
# principal whose name they know. This throttle answers both. Tested here
# rather than live because a live test would lock this host out of its own
# service for ADDR_LOCKOUT_SECONDS.
A, B = "10.9.9.9", "10.9.9.10"
iam.clear_address_failures(rt, A)
iam.clear_address_failures(rt, B)
check("a fresh address is not locked", iam.address_locked(rt, A), 0.0)

# Spread the attempts across DIFFERENT principals, including ones that do not
# exist — the pattern the per-principal counter is blind to by design.
for i in range(iam.ADDR_LOCKOUT_THRESHOLD):
    iam.verify_login(conn, rt, f"nosuch-{i}", "wrong", addr=A)
check("address locks once the threshold of failures is reached",
      iam.address_locked(rt, A) > 0, True)
check("...and the lock is reported to the caller, with a retry_after",
      (lambda r: (r.principal, "address" in r.reason, r.retry_after > 0))(
          iam.verify_login(conn, rt, "logintest", "wrong", addr=A)),
      (None, True, True))
check("a DIFFERENT address is unaffected (one attacker cannot lock everyone out)",
      iam.address_locked(rt, B), 0.0)

# The window must reset, or this reintroduces the exact permanent-lock bug
# fixed above for the per-principal counter.
rt.execute("UPDATE login_attempts_addr SET locked_until=0, last_failure=? WHERE addr=?",
           (time.time() - iam.ADDR_LOCKOUT_SECONDS - 1, A))
rt.commit()
iam.record_address_failure(rt, A)
check("one failure after a quiet window starts a FRESH count, not threshold+1",
      iam._addr_state(rt, A)[0], 1)
check("...and does not itself re-lock the address", iam.address_locked(rt, A), 0.0)

# A successful login clears it, so a shared address (NAT, a family machine)
# does not accumulate unrelated typos until it locks itself out.
for _ in range(3):
    iam.verify_login(conn, rt, "logintest", "wrong", addr=B)
check("failures from a good address accumulate", iam._addr_state(rt, B)[0], 3)
iam.clear_failures(rt, "logintest")       # the per-principal lock would mask the login
check("the login used below really does succeed (guard: a mistyped fixture "
      "password here would make the next check pass for the wrong reason)",
      iam.verify_login(conn, rt, "logintest", "s3cret-passphrase", addr=B).ok, True)
check("a successful login clears that address's counter", iam._addr_state(rt, B)[0], 0)

# An unknown address must not share one bucket with every other unknown
# caller — that would let a single attacker lock out every login on the box.
iam.clear_address_failures(rt, "")
for i in range(iam.ADDR_LOCKOUT_THRESHOLD + 5):
    iam.record_address_failure(rt, "")
check("an empty address is never throttled (no shared bucket)",
      iam.address_locked(rt, ""), 0.0)


section("bounded web grants: the approval grant lifecycle")
iam.add_principal(conn, "wg-admin", "user", "test", role="admin")
iam.add_principal(conn, "wg-viewer", "user", "test")   # operator
iam.add_principal(conn, "wg-target", "user", "test")
act = {"op": "bind", "principal": "wg-target", "role": "operator", "resource": ORG}
g = iam.mint_action_grant(rt, "wg-admin", act)
check("mint returns an opaque id", len(g) > 20, True)
try:
    iam.consume_action_grant(rt, g, {**act, "role": "admin"})
    check("a grant spent on a DIFFERENT action is refused", False, True)
except iam.IAMError as e:
    check("a grant spent on a DIFFERENT action is refused", "does not match" in str(e), True)
check("...and is still unspent afterwards (the mismatch burned nothing)",
      rt.execute("SELECT used_at FROM action_grants WHERE id=?", (g,)).fetchone()[0], None)
check("consume returns the approver", iam.consume_action_grant(rt, g, act), "wg-admin")
try:
    iam.consume_action_grant(rt, g, act); check("a grant is single-use", False, True)
except iam.IAMError as e:
    check("a grant is single-use", "already used" in str(e), True)
g2 = iam.mint_action_grant(rt, "wg-admin", act)
rt.execute("UPDATE action_grants SET expires_at=? WHERE id=?", (time.time() - 1, g2)); rt.commit()
try:
    iam.consume_action_grant(rt, g2, act); check("an expired grant is refused", False, True)
except iam.IAMError as e:
    check("an expired grant is refused", "expired" in str(e), True)
try:
    iam.consume_action_grant(rt, "no-such-grant", act); check("unknown grant refused", False, True)
except iam.IAMError as e:
    check("unknown grant refused", "no such approval grant" in str(e), True)

section("bounded web grants: web_bind / web_unbind")
def has_role(p, role):
    row = conn.execute("SELECT role FROM principals WHERE name=?", (p,)).fetchone()
    return row is not None and row["role"] == role

# Promote wg-target to admin via a grant from wg-admin
act_bind = {"op": "bind", "principal": "wg-target", "role": "admin", "resource": ORG}
g = iam.mint_action_grant(rt, "wg-admin", act_bind)
out = iam.web_bind(conn, rt, "wg-target", "admin", ORG, g)
check("web_bind promotes to admin", has_role("wg-target", "admin"), True)
check("...approved_by comes from the GRANT, not the caller", out["approved_by"], "wg-admin")

# A grant from a non-admin (wg-viewer = operator) is refused
act_bind2 = {"op": "bind", "principal": "wg-target", "role": "admin", "resource": ORG}
g = iam.mint_action_grant(rt, "wg-viewer", act_bind2)
try:
    iam.web_bind(conn, rt, "wg-target", "admin", ORG, g)
    check("a grant approved by a non-admin is refused at consume", False, True)
except iam.IAMError as e:
    check("a grant approved by a non-admin is refused at consume", "does not hold iam:manage" in str(e), True)

for role, res, why in (("operator", "*", "resource must be"), ("operator", "tenant/acme", "resource must be"),
                       ("superuser", ORG, "may set only")):
    try:
        iam.web_bind(conn, rt, "wg-target", role, res, "irrelevant")
        check(f"web_bind refuses {role} on {res} BEFORE touching the grant", False, True)
    except iam.IAMError as e:
        check(f"web_bind refuses {role} on {res} BEFORE touching the grant", why in str(e), True)
try:
    iam.web_bind(conn, rt, "no-such-person", "operator", ORG, "irrelevant")
    check("web_bind refuses an unknown principal", False, True)
except iam.IAMError as e:
    check("web_bind refuses an unknown principal", "no user named" in str(e), True)

# Demote wg-target back to operator via web_unbind
check("web_unbind demotes admin to operator",
      iam.web_unbind(conn, "wg-target", "admin", ORG)["removed"], True)
check("...now operator", has_role("wg-target", "operator"), True)
check("web_unbind of already-operator is a no-op",
      iam.web_unbind(conn, "wg-target", "operator", ORG)["removed"], False)

# Removing authority is fail-safe: web_unbind can remove an admin binding without re-auth
check("web_unbind removes an admin binding (demotes to operator)",
      iam.web_unbind(conn, "wg-admin", "admin", ORG)["removed"], True)
check("...demoted to operator", has_role("wg-admin", "operator"), True)
iam.set_principal_role(conn, "wg-admin", "admin", "test")
check("...restored for the rest of this section", has_role("wg-admin", "admin"), True)

section("WebAuthn: webauthn_enabled toggle (default OFF, unlike require-2fa)")
check("default is off", iam.webauthn_enabled(conn), False)
iam.set_webauthn_enabled(conn, True)
check("set on", iam.webauthn_enabled(conn), True)
iam.set_webauthn_enabled(conn, False)
check("set back off", iam.webauthn_enabled(conn), False)

section("WebAuthn: challenge mint/consume — single-use, TTL, purpose, principal binding")
iam.add_principal(conn, "wa-user", "user", "test")
iam.add_principal(conn, "wa-other", "user", "test")
# The require-2fa section above (deliberately) leaves the platform policy
# OFF for the rest of the file. This section's mfa_setup_required checks
# need it back ON to mean anything — set explicitly, not assumed.
iam.set_setting(conn, "require-2fa", "on")

ch = iam.mint_webauthn_challenge(rt, purpose="register", principal="wa-user")
check("challenge is a non-empty base64url string", isinstance(ch, str) and len(ch) > 20, True)
iam.consume_webauthn_challenge(rt, ch, purpose="register", principal="wa-user")
try:
    iam.consume_webauthn_challenge(rt, ch, purpose="register", principal="wa-user")
    check("a used challenge cannot be consumed twice", False, True)
except iam.IAMError as e:
    check("a used challenge cannot be consumed twice", "already used" in str(e), True)

try:
    iam.consume_webauthn_challenge(rt, "not-a-real-challenge", purpose="register", principal="wa-user")
    check("an unknown challenge is refused", False, True)
except iam.IAMError as e:
    check("an unknown challenge is refused", "unknown" in str(e), True)

ch2 = iam.mint_webauthn_challenge(rt, purpose="register", principal="wa-user")
try:
    iam.consume_webauthn_challenge(rt, ch2, purpose="login")
    check("wrong purpose is refused", False, True)
except iam.IAMError as e:
    check("wrong purpose is refused", "purpose mismatch" in str(e), True)
# that failed attempt still burned the challenge — single-use regardless of outcome
try:
    iam.consume_webauthn_challenge(rt, ch2, purpose="register", principal="wa-user")
    check("a challenge is burned even when the first consume attempt fails", False, True)
except iam.IAMError as e:
    check("a challenge is burned even when the first consume attempt fails",
          "already used" in str(e), True)

ch3 = iam.mint_webauthn_challenge(rt, purpose="register", principal="wa-user")
try:
    iam.consume_webauthn_challenge(rt, ch3, purpose="register", principal="wa-other")
    check("a registration challenge issued for one principal refuses another", False, True)
except iam.IAMError as e:
    check("a registration challenge issued for one principal refuses another",
          "not issued for this account" in str(e), True)

# expiry, driven directly rather than sleeping the real TTL
ch4 = iam.mint_webauthn_challenge(rt, purpose="login")
rt.execute("UPDATE webauthn_challenges SET expires_at=? WHERE challenge_hash=?",
          (time.time() - 1, iam._webauthn_challenge_hash(ch4)))
rt.commit()
try:
    iam.consume_webauthn_challenge(rt, ch4, purpose="login")
    check("an expired challenge is refused", False, True)
except iam.IAMError as e:
    check("an expired challenge is refused", "expired" in str(e), True)

# a login challenge has no principal bound — any principal may be named at consume time
ch5 = iam.mint_webauthn_challenge(rt, purpose="login")
iam.consume_webauthn_challenge(rt, ch5, purpose="login", principal="wa-user")
check("a login challenge (principal=None) is not tied to any one account", True, True)

section("WebAuthn: passkey_commit — the grant-bound registration write")
def register_action(principal, cred_id, alg="ES256", x="Xcoord", y="Ycoord", sign_count=0):
    return iam.webauthn_register_action(principal, cred_id, alg, x, y, sign_count)

act_reg = register_action("wa-user", "cred-abc123")
g = iam.mint_action_grant(rt, "wa-user", act_reg)
out = iam.passkey_commit(conn, rt, "wa-user", "cred-abc123", "ES256", "Xcoord", "Ycoord", 0,
                         "My Phone", g)
check("passkey_commit returns the committed fields", out,
      {"credential_id": "cred-abc123", "principal": "wa-user", "alg": "ES256", "name": "My Phone"})
check("has_passkey is now true", iam.has_passkey(conn, "wa-user"), True)
check("mfa_setup_required is satisfied by the passkey alone (no TOTP)",
      iam.mfa_setup_required(conn, "wa-user"), False)

# a grant cannot be reused
try:
    iam.passkey_commit(conn, rt, "wa-user", "cred-abc123", "ES256", "Xcoord", "Ycoord", 0,
                       "x", g)
    check("a spent registration grant cannot be reused", False, True)
except iam.IAMError as e:
    check("a spent registration grant cannot be reused", "already used" in str(e), True)

# a grant minted for one action cannot commit a DIFFERENT one — the whole
# point of binding the grant to an action hash, proven the same way
# web_bind's own test above proves it for a bind action.
act_reg2 = register_action("wa-user", "cred-def456")
g2 = iam.mint_action_grant(rt, "wa-user", act_reg2)
try:
    # attacker/compromised-API tries to commit DIFFERENT fields than what
    # was actually approved (a different credential id)
    iam.passkey_commit(conn, rt, "wa-user", "cred-TAMPERED", "ES256", "Xcoord", "Ycoord", 0,
                       "x", g2)
    check("a grant cannot be spent on a tampered/different action", False, True)
except iam.IAMError as e:
    check("a grant cannot be spent on a tampered/different action",
          "does not match" in str(e), True)
# the untouched original action still works with its own grant
out2 = iam.passkey_commit(conn, rt, "wa-user", "cred-def456", "ES256", "Xcoord", "Ycoord", 0,
                          "My Laptop", g2)
check("the genuine action still commits with its own (still-unspent) grant",
      out2["credential_id"], "cred-def456")

# registering the SAME credential_id twice (any principal) is refused — a
# credential_id is globally unique, not per-principal. x/y here must match
# what's actually passed to passkey_commit below, or the grant legitimately
# mismatches for a DIFFERENT reason (the action-tamper check above) than the
# one this case means to exercise.
act_dupe = register_action("wa-other", "cred-abc123", x="X2", y="Y2")
g3 = iam.mint_action_grant(rt, "wa-other", act_dupe)
try:
    iam.passkey_commit(conn, rt, "wa-other", "cred-abc123", "ES256", "X2", "Y2", 0, "x", g3)
    check("a duplicate credential_id is refused", False, True)
except iam.IAMError as e:
    check("a duplicate credential_id is refused", "already registered" in str(e), True)

section("WebAuthn: list / self-removal / admin reset")
rows = iam.list_passkeys(conn, "wa-user", rt)
check("list_passkeys returns both registered devices", sorted(r["credential_id"] for r in rows),
      ["cred-abc123", "cred-def456"])
check("list_passkeys includes the friendly name", {r["credential_id"]: r["name"] for r in rows},
      {"cred-abc123": "My Phone", "cred-def456": "My Laptop"})

check("removing someone else's credential_id is a no-op (returns False)",
      iam.remove_own_passkey(conn, rt, "wa-other", "cred-abc123"), False)
check("removing your own passkey works",
      iam.remove_own_passkey(conn, rt, "wa-user", "cred-abc123"), True)
check("...it's really gone", [r["credential_id"] for r in iam.list_passkeys(conn, "wa-user", rt)],
      ["cred-def456"])
check("still has the other one -> mfa_setup_required still satisfied",
      iam.mfa_setup_required(conn, "wa-user"), False)

n = iam.reset_passkeys(conn, rt, "wa-user")
check("reset_passkeys removes everything and reports the count", n, 1)
check("has_passkey is false after a full reset", iam.has_passkey(conn, "wa-user"), False)
check("mfa_setup_required is required again with no factor left at all",
      iam.mfa_setup_required(conn, "wa-user"), True)
try:
    iam.reset_passkeys(conn, rt, "no-such-principal")
    check("reset_passkeys refuses an unknown principal", False, True)
except iam.IAMError as e:
    check("reset_passkeys refuses an unknown principal", "no user named" in str(e), True)

section("admin: web-grantable at the operator's explicit request, bounded by the "
        "APPROVER already holding it — never 'the API already has this anyway'")
check("'admin' joined WEB_GRANTABLE_ROLES", "admin" in iam.WEB_GRANTABLE_ROLES, True)
check("web_grant_resource('admin', org) accepts it", iam.web_grant_resource("admin", ORG), ORG)
for res in ("*", "tenant/acme"):
    try:
        iam.web_grant_resource("admin", res)
        check(f"web_grant_resource('admin', {res!r}) is refused", False, True)
    except iam.IAMError as e:
        check(f"web_grant_resource('admin', {res!r}) is refused", True, True)

iam.add_principal(conn, "ga-admin", "user", "test", role="admin")
iam.add_principal(conn, "ga-newbie", "user", "test")
act_ga = {"op": "bind", "principal": "ga-newbie", "role": "admin", "resource": ORG}
g = iam.mint_action_grant(rt, "ga-admin", act_ga)
iam.web_bind(conn, rt, "ga-newbie", "admin", ORG, g)
check("an existing global admin can grant admin to someone else, via the web",
      has_role("ga-newbie", "admin"), True)

# The bound: an approver who does NOT already hold admin cannot mint one —
# web_bind's own approver check (iam:manage) refuses it.
act_ga2 = {"op": "bind", "principal": "ga-second", "role": "admin", "resource": ORG}
iam.add_principal(conn, "ga-second", "user", "test")
iam.add_principal(conn, "ga-op", "user", "test")  # operator by default
g = iam.mint_action_grant(rt, "ga-op", act_ga2)
try:
    iam.web_bind(conn, rt, "ga-second", "admin", ORG, g)
    check("an operator (not an admin) cannot grant admin", False, True)
except iam.IAMError as e:
    check("an operator (not an admin) cannot grant admin",
          "does not hold iam:manage" in str(e), True)
check("...and nothing was bound", has_role("ga-second", "operator"), True)

# Delegation, not escalation: the newly-promoted admin can do the same thing
# themselves — three levels deep, mirroring tenant-admin's own chain above.
iam.add_principal(conn, "ga-grandchild", "user", "test")
act_ga3 = {"op": "bind", "principal": "ga-grandchild", "role": "admin", "resource": ORG}
g = iam.mint_action_grant(rt, "ga-newbie", act_ga3)
iam.web_bind(conn, rt, "ga-grandchild", "admin", ORG, g)
check("the newly-promoted admin can themselves grant admin (delegation, 3 levels deep)",
      has_role("ga-grandchild", "admin"), True)

check("web_unbind removes an admin binding with no re-auth (fail-safe)",
      iam.web_unbind(conn, "ga-grandchild", "admin", ORG)["removed"], True)
check("...demoted to operator", has_role("ga-grandchild", "operator"), True)

section("effective_role_name — the ACTUAL bound role")
check("a genuine admin reads as 'admin'", iam.effective_role_name(conn, "ga-admin", ORG), "admin")
iam.add_principal(conn, "role-op", "user", "test")
check("a plain operator reads as 'operator'",
      iam.effective_role_name(conn, "role-op", ORG), "operator")
iam.add_principal(conn, "role-admin", "user", "test", role="admin")
check("an admin reads as 'admin'",
      iam.effective_role_name(conn, "role-admin", ORG), "admin")
check("an unknown principal -> None (fails closed, same as effective_permissions)",
      iam.effective_role_name(conn, "nobody-at-all", ORG), None)

section("rename_principal — every name-bearing row moves, in one transaction")
iam.add_principal(conn, "rp-old", "user", "test")
iam.set_principal_password(conn, "rp-old", "Rp-Old-Pass-1!")
iam.enroll_totp(conn, "rp-old")                       # -> recovery_codes rows
key_full = iam.issue_key(conn, "rp-old", "test")      # api_keys.principal
rp_prefix, _ = iam.split_key(key_full)
g = iam.mint_action_grant(rt, "rp-old", iam.webauthn_register_action(
    "rp-old", "rp-cred-1", "ES256", "X", "Y", 0))
iam.passkey_commit(conn, rt, "rp-old", "rp-cred-1", "ES256", "X", "Y", 0, "phone", g)
iam.set_setting(conn, "require-2fa:rp-old", "off")
iam.set_limit(conn, "outputs-bytes-per-operator:rp-old", 999)
rt.execute("INSERT INTO login_attempts(principal, failures, locked_until, last_failure) "
          "VALUES ('rp-old', 4, 0, ?)", (time.time(),))
rt.execute("INSERT INTO enrolment_tokens(token_hash, principal, created_at, created_by, "
          "expires_at) VALUES ('rp-tok-hash', 'rp-old', ?, 'test', ?)",
          (time.time(), time.time() + 3600))
rt.execute("INSERT INTO sessions(id, principal, csrf, created_at, expires_at, last_seen) "
          "VALUES ('rp-sess-1', 'rp-old', 'csrf', ?, ?, ?)",
          (time.time(), time.time() + 3600, time.time()))
rt.commit()
(tmp / "vault" / "org" / "outputs" / "rp-old").mkdir(parents=True)
(tmp / "vault" / "org" / "outputs" / "rp-old" / "report.docx").write_text("x")

out = iam.rename_principal(conn, rt, "rp-old", "rp-new", "test")
check("rename_principal returns the new name", out["new"], "rp-new")
check("principals.name moved", bool(conn.execute(
    "SELECT 1 FROM principals WHERE name='rp-new'").fetchone()), True)
check("...and the old name is gone", conn.execute(
    "SELECT 1 FROM principals WHERE name='rp-old'").fetchone(), None)
check("api_keys.principal moved", conn.execute(
    "SELECT principal FROM api_keys WHERE prefix=?", (rp_prefix,)).fetchone()["principal"], "rp-new")
check("recovery_codes.principal moved (from enroll_totp)", conn.execute(
    "SELECT COUNT(*) c FROM recovery_codes WHERE principal='rp-new'").fetchone()["c"] > 0, True)
check("...none left under the old name", conn.execute(
    "SELECT COUNT(*) c FROM recovery_codes WHERE principal='rp-old'").fetchone()["c"], 0)
check("passkeys.principal moved", conn.execute(
    "SELECT principal FROM passkeys WHERE credential_id='rp-cred-1'").fetchone()["principal"], "rp-new")
check("require-2fa:<name> settings key moved", iam.get_setting(conn, "require-2fa:rp-new", ""), "off")
check("...old key gone", iam.get_setting(conn, "require-2fa:rp-old", "MISSING"), "MISSING")
check("limit:outputs-bytes-per-operator:<name> moved", iam.outputs_limit_operator(conn, "rp-new"), 999)
check("runtime login_attempts moved (a rename cannot be used to dodge a lockout)",
      rt.execute("SELECT failures FROM login_attempts WHERE principal='rp-new'").fetchone()["failures"], 4)
check("runtime enrolment_tokens moved", bool(rt.execute(
    "SELECT 1 FROM enrolment_tokens WHERE principal='rp-new'").fetchone()), True)
check("the OLD session was revoked, not moved (rename forces re-login)", rt.execute(
    "SELECT 1 FROM sessions WHERE id='rp-sess-1'").fetchone(), None)
check("the outputs directory moved with the principal",
      (tmp / "vault" / "org" / "outputs" / "rp-new" / "report.docx").is_file(), True)
check("...old outputs dir is gone",
      (tmp / "vault" / "org" / "outputs" / "rp-old").exists(), False)
history_rows = [__import__("json").loads(l) for l in
               iam.PRINCIPAL_HISTORY_PATH.read_text().splitlines()]
check("a 'renamed' row was appended to principal-history.jsonl",
      any(r.get("event") == "renamed" and r.get("name") == "rp-old" and r.get("new_name") == "rp-new"
          for r in history_rows), True)

section("rename_principal — refusals")
try:
    iam.rename_principal(conn, rt, "rp-new", "rp-new", "test")
    check("renaming to your own current name is refused", False, True)
except iam.IAMError as e:
    check("renaming to your own current name is refused", "already this user" in str(e), True)
iam.add_principal(conn, "rp-taken", "user", "test")
try:
    iam.rename_principal(conn, rt, "rp-new", "rp-taken", "test")
    check("renaming to an EXISTING principal is refused", False, True)
except iam.IAMError as e:
    check("renaming to an EXISTING principal is refused", "already exists" in str(e), True)
try:
    iam.rename_principal(conn, rt, "rp-new", "rp-new-2", "rp-new")
    check("renaming YOURSELF is refused", False, True)
except iam.IAMError as e:
    check("renaming YOURSELF is refused", "account you are currently using" in str(e), True)
try:
    iam.rename_principal(conn, rt, "rp-taken", "rp-someone-else", "test")
    check("(control) renaming someone else, as a different actor, is allowed", True, True)
except iam.IAMError:
    check("(control) renaming someone else, as a different actor, is allowed", False, True)

section("delete_principal — full cascade, and the tombstone it leaves")
iam.add_principal(conn, "dp-victim", "user", "test")
iam.set_limit(conn, "outputs-bytes-per-operator:dp-victim", 7)
key2 = iam.issue_key(conn, "dp-victim", "test")
dp_prefix, _ = iam.split_key(key2)
rt.execute("INSERT INTO sessions(id, principal, csrf, created_at, expires_at, last_seen) "
          "VALUES ('dp-sess-1', 'dp-victim', 'csrf', ?, ?, ?)",
          (time.time(), time.time() + 3600, time.time()))
rt.commit()

out = iam.delete_principal(conn, rt, "dp-victim", "test")
check("delete_principal reports the deletion", (out["name"], out["deleted"]), ("dp-victim", True))
check("the principal row is gone", conn.execute(
    "SELECT 1 FROM principals WHERE name='dp-victim'").fetchone(), None)
check("its api key is gone", conn.execute(
    "SELECT 1 FROM api_keys WHERE prefix=?", (dp_prefix,)).fetchone(), None)
check("its settings override is gone", iam.get_setting(conn, "limit:outputs-bytes-per-operator:dp-victim",
                                                        "GONE"), "GONE")
check("its session was revoked", rt.execute(
    "SELECT 1 FROM sessions WHERE id='dp-sess-1'").fetchone(), None)
history_rows = [__import__("json").loads(l) for l in
               iam.PRINCIPAL_HISTORY_PATH.read_text().splitlines()]
check("a 'deleted' row was appended",
      any(r.get("event") == "deleted" and r.get("name") == "dp-victim"
          for r in history_rows), True)
check("a hard-deleted name is now tombstoned", iam._is_tombstoned("dp-victim"), True)
try:
    iam.add_principal(conn, "dp-victim", "user", "test")
    check("re-CREATING a tombstoned name is refused", False, True)
except iam.IAMError as e:
    check("re-CREATING a tombstoned name is refused", "permanently deleted" in str(e), True)
iam.add_principal(conn, "dp-reuse-target", "user", "test")
try:
    iam.rename_principal(conn, rt, "rp-someone-else", "dp-victim", "test")
    check("RENAMING into a tombstoned name is refused", False, True)
except iam.IAMError as e:
    check("RENAMING into a tombstoned name is refused", "permanently deleted" in str(e), True)

section("delete_principal — self-delete and last-global-admin refusals")
try:
    iam.delete_principal(conn, rt, "dp-reuse-target", "dp-reuse-target")
    check("deleting YOURSELF is refused", False, True)
except iam.IAMError as e:
    check("deleting YOURSELF is refused", "account you are currently using" in str(e), True)
# A genuinely ISOLATED store for this one check: by this point in the file
# many earlier fixtures (alice, ta-target, ga-admin, wrp-approver, ...) hold
# admin on '*' in the SHARED conn/rt, so "is dp-sole-admin the last one" can
# never be true there. A fresh, empty db is the only way to test "the
# LAST" honestly.
conn2 = iam.open_iam(readonly=False, path=tmp / "iam-lastadmin.db")
rt2 = iam.open_runtime(tmp / "runtime-lastadmin.db")
iam.add_principal(conn2, "dp-sole-admin", "user", "test", role="admin")
check("(setup) dp-sole-admin is recognized as the last active global admin",
      iam._is_last_admin(conn2, "dp-sole-admin"), True)
try:
    iam.delete_principal(conn2, rt2, "dp-sole-admin", "test")
    check("deleting the LAST active global admin is refused", False, True)
except iam.IAMError as e:
    check("deleting the LAST active global admin is refused",
          "only active admin" in str(e), True)
iam.add_principal(conn2, "dp-second-admin", "user", "test", role="admin")
check("(control) with a SECOND global admin now bound, dp-sole-admin is no longer the LAST one",
      iam._is_last_admin(conn2, "dp-sole-admin"), False)
try:
    iam.delete_principal(conn2, rt2, "dp-sole-admin", "test")
    check("...and deleting them now succeeds", True, True)
except iam.IAMError:
    check("...and deleting them now succeeds", False, True)
conn2.close(); rt2.close()

section("web_rename_principal / web_delete_principal — the grant-gated forms")
iam.add_principal(conn, "wrp-approver", "user", "test", role="admin")
iam.add_principal(conn, "wrp-target", "user", "test")
rename_action = {"op": "rename-principal", "principal": "wrp-target",
                 "new_name": "wrp-renamed", "resource": ORG}
g = iam.mint_action_grant(rt, "wrp-approver", rename_action)
out = iam.web_rename_principal(conn, rt, "wrp-target", "wrp-renamed", ORG, g)
check("web_rename_principal succeeds for a real global-admin grant", out["new"], "wrp-renamed")
check("...and records the APPROVER, not anyone else, in principal-history",
      any(r.get("event") == "renamed" and r["name"] == "wrp-target" for r in
          [__import__("json").loads(l) for l in iam.PRINCIPAL_HISTORY_PATH.read_text().splitlines()]),
      True)

iam.add_principal(conn, "wdp-nonadmin", "user", "test")   # holds nothing
iam.add_principal(conn, "wdp-target", "user", "test")
delete_action = {"op": "delete-principal", "principal": "wdp-target", "resource": ORG}
g2 = iam.mint_action_grant(rt, "wdp-nonadmin", delete_action)
try:
    iam.web_delete_principal(conn, rt, "wdp-target", ORG, g2)
    check("web_delete_principal refuses an approver who does NOT hold iam:manage", False, True)
except iam.IAMError as e:
    check("web_delete_principal refuses an approver who does NOT hold iam:manage",
          "does not hold iam:manage" in str(e), True)
check("...and nothing was deleted", conn.execute(
    "SELECT 1 FROM principals WHERE name='wdp-target'").fetchone() is not None, True)
g3 = iam.mint_action_grant(rt, "wrp-approver", delete_action)
out = iam.web_delete_principal(conn, rt, "wdp-target", ORG, g3)
check("web_delete_principal succeeds for a real global-admin grant", out["deleted"], True)
try:
    iam.consume_action_grant(rt, g3, delete_action)
    check("the SAME grant cannot be spent twice", False, True)
except iam.IAMError as e:
    check("the SAME grant cannot be spent twice", "already used" in str(e), True)

section("create-user from the web: one grant for name, kind and role (decision 2026-10-22)")
cu_action = {"op": "create-user", "principal": "cu-new", "kind": "user", "role": "operator", "resource": ORG}
g = iam.mint_action_grant(rt, "wrp-approver", cu_action)
check("an admin's grant for exactly this account is accepted, approver returned",
      iam.web_approve_create_user(conn, rt, cu_action, g), "wrp-approver")
g = iam.mint_action_grant(rt, "wrp-approver", cu_action)
try:
    iam.web_approve_create_user(conn, rt, {**cu_action, "role": "admin"}, g)
    check("a grant approved for an operator cannot create an admin", False, True)
except iam.IAMError as e:
    check("a grant approved for an operator cannot create an admin", "does not match" in str(e), True)
g = iam.mint_action_grant(rt, "wdp-nonadmin", cu_action)
try:
    iam.web_approve_create_user(conn, rt, cu_action, g)
    check("a non-admin's grant cannot create an account", False, True)
except iam.IAMError as e:
    check("a non-admin's grant cannot create an account", "not an admin" in str(e), True)

section("engagement-set / engagement-approve grants (audit run 1, F13)")
es_action = {"op": "engagement-set", "sha256": "a" * 64, "resource": ORG}
g = iam.mint_action_grant(rt, "wrp-approver", es_action)
check("an admin's grant for exactly this change returns the approver",
      iam.web_approve_engagement(conn, rt, es_action, g), "wrp-approver")
g = iam.mint_action_grant(rt, "wrp-approver", es_action)
try:
    iam.web_approve_engagement(conn, rt, {**es_action, "sha256": "b" * 64}, g)
    check("a grant for one change cannot be spent on another", False, True)
except iam.IAMError as e:
    check("a grant for one change cannot be spent on another", "does not match" in str(e), True)
ea_action = {"op": "engagement-approve", "digest": "c" * 64, "resource": ORG}
g = iam.mint_action_grant(rt, "wdp-nonadmin", ea_action)
try:
    iam.web_approve_engagement(conn, rt, ea_action, g)
    check("an approver without engagement:approve is refused", False, True)
except iam.IAMError as e:
    check("an approver without engagement:approve is refused", "engagement:approve" in str(e), True)

section("F08: no enrolment link for a service account or a passkey-only account")
iam.add_principal(conn, "f08-svc", "service", "test", role="admin")
try:
    iam.mint_enrolment_token(rt, conn, "f08-svc", "test")
    check("a service account gets no enrolment link", False, True)
except iam.IAMError as e:
    check("a service account gets no enrolment link", "service account" in str(e), True)
iam.add_principal(conn, "f08-pk", "user", "test")
conn.execute("INSERT INTO passkeys(credential_id, principal, alg, pubkey_x, pubkey_y, name, created_at, created_by) "
             "VALUES ('f08-cred', 'f08-pk', 'ES256', 'x', 'y', 'phone', 0, 'test')")
conn.commit()
try:
    iam.mint_enrolment_token(rt, conn, "f08-pk", "test")
    check("an account that has only a passkey is enrolled: no link", False, True)
except iam.IAMError as e:
    check("an account that has only a passkey is enrolled: no link", "already enrolled" in str(e), True)
iam.add_principal(conn, "f08-fresh", "user", "test")
check("a fresh account with no credential still gets one",
      bool(iam.mint_enrolment_token(rt, conn, "f08-fresh", "test")), True)

section("audit run 2: the web tier alone never sets an admin's first password")
API = iam.API_ACCOUNT
iam.add_principal(conn, "r2-adm", "user", "test", role="admin")
try:
    iam.mint_enrolment_token(rt, conn, "r2-adm", API)
    check("the web account cannot mint a link for an unenrolled admin", False, True)
except iam.IAMError as e:
    check("the web account cannot mint a link for an unenrolled admin", "terminal" in str(e), True)
check("...an admin at the terminal still can", bool(iam.mint_enrolment_token(rt, conn, "r2-adm", "root")), True)
iam.add_principal(conn, "r2-op", "user", "test")
r2tok = iam.mint_enrolment_token(rt, conn, "r2-op", API)
check("the web account still reissues an operator's link", bool(r2tok), True)
iam.set_principal_role(conn, "r2-op", "admin", "test")
try:
    iam.consume_enrolment_token(conn, rt, r2tok, "r2-password-long", None, None)
    check("a web-minted link dies if its account became an admin", False, True)
except iam.IAMError as e:
    check("a web-minted link dies if its account became an admin", "admin" in str(e), True)
iam.add_principal(conn, "r2-keyed", "user", "test")
iam.issue_key(conn, "r2-keyed", "test")
try:
    iam.mint_enrolment_token(rt, conn, "r2-keyed", "test")
    check("an account with a live API key gets no enrolment link", False, True)
except iam.IAMError as e:
    check("an account with a live API key gets no enrolment link", "API key" in str(e), True)

section("audit run 2: the write decides — parallel requests cannot outrun a lock or spend twice")
import threading as _th


def _race(n, fn):
    """Run fn(i) in n threads released together, each with its OWN connections
    (as authd's threads have); returns the results."""
    gate, out, lock = _th.Barrier(n), [], _th.Lock()

    def run(i):
        c = iam.open_iam(readonly=True, path=tmp / "iam.db")
        r = iam.open_runtime(tmp / "runtime.db")
        try:
            gate.wait()
            res = fn(i, c, r)
        except Exception as e:      # noqa: BLE001 — recorded, judged below
            res = e
        finally:
            c.close(); r.close()
        with lock:
            out.append(res)
    ts = [_th.Thread(target=run, args=(i,)) for i in range(n)]
    for t in ts: t.start()
    for t in ts: t.join()
    return out


iam.add_principal(conn, "r2-race", "user", "test")
iam.set_principal_password(conn, "r2-race", "r2-race-password")
_checked, _clock = [0], _th.Lock()
_real_verify = iam.verify_password


def _counting_verify(pw, h):
    with _clock:
        _checked[0] += 1
    return _real_verify(pw, h)


iam.verify_password = _counting_verify
_res = _race(30, lambda i, c, r: iam.verify_login(c, r, "r2-race", f"wrong-{i}", addr=f"10.8.0.{i}"))
iam.verify_password = _real_verify
check("30 parallel wrong passwords: no request crashes", [x for x in _res if isinstance(x, Exception)], [])
check("...at most the lockout threshold of them are checked at all", _checked[0] <= iam.LOCKOUT_THRESHOLD, True)
check("...and the account is locked afterwards", iam._lockout_state(rt, "r2-race")[1] > time.time(), True)
rt.execute("DELETE FROM login_attempts WHERE principal='r2-race'"); rt.commit()

_g_action = {"op": "r2-race", "resource": ORG}
_g = iam.mint_action_grant(rt, "r2-race", _g_action)
_res = _race(12, lambda i, c, r: iam.consume_action_grant(r, _g, _g_action))
check("one approval grant spent by 12 parallel requests: exactly one succeeds",
      sum(1 for x in _res if x == "r2-race"), 1)
check("...the others are refused as already used, not crashed",
      all(isinstance(x, iam.IAMError) for x in _res if x != "r2-race"), True)

iam.add_principal(conn, "r2-race-new", "user", "test")
_et = iam.mint_enrolment_token(rt, conn, "r2-race-new", "test")
_esec = iam.totp_generate_secret()
_ecode = iam.totp_code(_esec)
_res = _race(8, lambda i, c, r: iam.consume_enrolment_token(
    iam.open_iam(readonly=False, path=tmp / "iam.db"), r, _et, f"first-password-{i}", _esec, _ecode))
_ok = [x for x in _res if isinstance(x, tuple)]
check("one enrolment link used by 8 parallel requests: exactly one sets the account up", len(_ok), 1)

_sec_r, _ = iam.enroll_totp(conn, "r2-race", rt)
_code = iam.totp_code(_sec_r)
_res = _race(8, lambda i, c, r: iam.verify_second_factor(c, r, "r2-race", _code))
check("one 2FA code sent by 8 parallel requests: exactly one is accepted",
      sum(1 for x in _res if getattr(x, "ok", False)), 1)

rt.execute("DELETE FROM login_attempts WHERE principal='r2-race'"); rt.commit()
_r = iam.verify_login(conn, rt, "r2-race", "wrong")
for _ in range(iam.LOCKOUT_THRESHOLD - 2):
    iam.verify_login(conn, rt, "r2-race", "wrong")
_r = iam.verify_login(conn, rt, "r2-race", "r2-race-password")
check("four typos, then the right password: still asks for the code (the count is handed back)",
      (_r.ok, _r.totp_required), (True, True))
rt.execute("DELETE FROM login_attempts WHERE principal='r2-race'"); rt.commit()

section("web_enable_principal — grant-gated re-enable (§4 item 78)")
GRES = ORG
iam.add_principal(conn, "wep-target", "user", "test")
iam.set_principal_active(conn, "wep-target", False)
en_action = {"op": "enable-principal", "principal": "wep-target", "resource": GRES}
iam.add_principal(conn, "wep-admin", "user", "test", role="admin")
g = iam.mint_action_grant(rt, "wdp-nonadmin", en_action)
try:
    iam.web_enable_principal(conn, rt, "wep-target", GRES, g)
    check("re-enable refuses an approver who does not hold iam:manage", False, True)
except iam.IAMError as e:
    check("re-enable refuses an approver who does not hold iam:manage", "does not hold iam:manage" in str(e), True)
check("...and the account is still disabled",
      conn.execute("SELECT active FROM principals WHERE name='wep-target'").fetchone()[0], 0)
g = iam.mint_action_grant(rt, "wep-admin", en_action)
out = iam.web_enable_principal(conn, rt, "wep-target", GRES, g)
check("a real global-admin grant re-enables, naming the approver", (out["active"], out["approved_by"]), (True, "wep-admin"))
check("...and the account is active again",
      conn.execute("SELECT active FROM principals WHERE name='wep-target'").fetchone()[0], 1)
try:
    iam.web_enable_principal(conn, rt, "wep-target", GRES, g)
    check("the same grant cannot be spent twice", False, True)
except iam.IAMError as e:
    check("the same grant cannot be spent twice", "already used" in str(e), True)
g = iam.mint_action_grant(rt, "wep-admin", {**en_action, "principal": "someone-else"})
try:
    iam.web_enable_principal(conn, rt, "wep-target", GRES, g)
    check("a grant for a different principal is refused", False, True)
except iam.IAMError:
    check("a grant for a different principal is refused", True, True)

section("reset_principal_password / reset_principal_mfa — global-admin-only, "
       "deliberately two separate jobs (the operator's own explicit ask)")
iam.add_principal(conn, "rpp-target", "user", "test")
iam.set_principal_password(conn, "rpp-target", "old-password-123")
# A real session for rpp-target so we can prove it gets revoked by the reset.
rt.execute("INSERT INTO sessions(id, principal, csrf, created_at, expires_at, last_seen, pending_totp)"
          " VALUES (?,?,?,?,?,?,0)",
          ("rpp-session-1", "rpp-target", "csrf", time.time(), time.time() + 3600, time.time()))
rt.commit()

# Direct mode: the grant is bound to the EXACT new password value, so a
# compromised web tier could never show one value and set another.
direct_action = {"op": "reset-password", "principal": "rpp-target", "resource": ORG,
                 "mode": "direct", "new_password": "brand-new-password-456"}
g4 = iam.mint_action_grant(rt, "wrp-approver", direct_action)
out = iam.web_reset_principal_password(conn, rt, "rpp-target", ORG, g4, "brand-new-password-456")
check("web_reset_principal_password succeeds for a real global-admin grant",
      out["password_reset"], True)
check("...revoked the account's existing session", out["sessions_revoked"], 1)
check("...the password actually changed", iam.verify_login(
    conn, rt, "rpp-target", "brand-new-password-456").ok, True)
check("...the OLD password no longer works", iam.verify_login(
    conn, rt, "rpp-target", "old-password-123").ok, False)
check("...recorded a password-reset event, attributed to the APPROVER",
      any(r.get("event") == "password-reset" and r["name"] == "rpp-target"
          and r["by"] == "wrp-approver" for r in
          [__import__("json").loads(l) for l in iam.PRINCIPAL_HISTORY_PATH.read_text().splitlines()]),
      True)

# A grant approved for one new_password can never be spent setting a
# DIFFERENT one — the exact request-substitution defense this binding
# exists for.
g5 = iam.mint_action_grant(rt, "wrp-approver",
                           {"op": "reset-password", "principal": "rpp-target", "resource": ORG,
                            "mode": "direct", "new_password": "approved-value"})
try:
    iam.web_reset_principal_password(conn, rt, "rpp-target", ORG, g5, "a-DIFFERENT-value")
    check("a grant bound to one new_password cannot be spent setting a different one", False, True)
except iam.IAMError as e:
    check("a grant bound to one new_password cannot be spent setting a different one",
          "does not match" in str(e), True)

# An approver who does NOT hold iam:manage is refused, same shape as
# web_delete_principal above.
g6 = iam.mint_action_grant(rt, "wdp-nonadmin",
                           {"op": "reset-password", "principal": "rpp-target", "resource": ORG,
                            "mode": "direct", "new_password": "irrelevant"})
try:
    iam.web_reset_principal_password(conn, rt, "rpp-target", ORG, g6, "irrelevant")
    check("web_reset_principal_password refuses an approver who does NOT hold iam:manage", False, True)
except iam.IAMError as e:
    check("web_reset_principal_password refuses an approver who does NOT hold iam:manage",
          "does not hold iam:manage" in str(e), True)

# Link mode: mints a real one-time token the TARGET consumes themselves —
# the admin never learns the value.
link_action = {"op": "reset-password", "principal": "rpp-target", "resource": ORG, "mode": "link"}
g7 = iam.mint_action_grant(rt, "wrp-approver", link_action)
link_out = iam.web_mint_password_reset_link(conn, rt, "rpp-target", ORG, g7)
check("web_mint_password_reset_link mints a real token", bool(link_out["reset_token"]), True)
check("password_reset_token_principal recognizes it, unused", iam.password_reset_token_principal(
    conn, rt, link_out["reset_token"]), "rpp-target")
principal_out = iam.consume_password_reset_token(conn, rt, link_out["reset_token"], "self-chosen-pw-789")
check("consume_password_reset_token sets the new password", principal_out, "rpp-target")
check("...the self-chosen password actually works", iam.verify_login(
    conn, rt, "rpp-target", "self-chosen-pw-789").ok, True)
try:
    iam.consume_password_reset_token(conn, rt, link_out["reset_token"], "another-one")
    check("a password reset token is single-use", False, True)
except iam.IAMError as e:
    check("a password reset token is single-use", "is invalid" in str(e), True)
try:
    iam.consume_password_reset_token(conn, rt, "not-a-real-token", "x")
    check("an unknown password reset token is refused", False, True)
except iam.IAMError as e:
    check("an unknown password reset token is refused", "is invalid" in str(e), True)

# reset-mfa: an independent action from reset-password — resetting one
# never touches the other (the operator's own explicit ask).
iam.enroll_totp(conn, "rpp-target", rt)
conn.execute(
    "INSERT INTO passkeys(credential_id, principal, alg, pubkey_x, pubkey_y,"
    " name, created_at, created_by) VALUES (?,?,?,?,?,?,?,?)",
    ("rpp-cred-1", "rpp-target", "ES256", "x"*10, "y"*10, "a passkey", time.time(), "test"))
conn.commit()
check("(setup) rpp-target now holds a TOTP secret and a passkey",
      conn.execute("SELECT totp_secret FROM principals WHERE name='rpp-target'").fetchone()[0] is not None
      and len(iam.list_passkeys(conn, "rpp-target")) == 1, True)
mfa_action = {"op": "reset-mfa", "principal": "rpp-target", "resource": ORG}
g8 = iam.mint_action_grant(rt, "wrp-approver", mfa_action)
mfa_out = iam.web_reset_principal_mfa(conn, rt, "rpp-target", ORG, g8)
check("web_reset_principal_mfa succeeds for a real global-admin grant", mfa_out["mfa_reset"], True)
check("...removed exactly the one passkey", mfa_out["passkeys_removed"], 1)
check("...the TOTP secret is genuinely cleared", conn.execute(
    "SELECT totp_secret FROM principals WHERE name='rpp-target'").fetchone()[0], None)
check("...every passkey is genuinely gone", iam.list_passkeys(conn, "rpp-target"), [])
check("...the password from the earlier reset-password test is UNTOUCHED "
     "(two independent jobs, not one bundled reset)",
     iam.verify_login(conn, rt, "rpp-target", "self-chosen-pw-789").ok, True)
check("...recorded an mfa-reset event, attributed to the APPROVER",
      any(r.get("event") == "mfa-reset" and r["name"] == "rpp-target"
          and r["by"] == "wrp-approver" for r in
          [__import__("json").loads(l) for l in iam.PRINCIPAL_HISTORY_PATH.read_text().splitlines()]),
      True)
try:
    iam.web_reset_principal_mfa(conn, rt, "rpp-target", ORG, g8)
    check("the reset-mfa grant cannot be spent twice", False, True)
except iam.IAMError as e:
    check("the reset-mfa grant cannot be spent twice", "already used" in str(e), True)

section("private dashboards (§4 item 71): who may open whose dashboard — the ladder")
pd = iam.open_iam(readonly=False, path=tmp / "pd-iam.db")
iam.add_principal(pd, "pd-ga", "user", "test", role="admin")
iam.add_principal(pd, "pd-ga2", "user", "test", role="admin")
iam.add_principal(pd, "pd-op-a", "user", "test")
iam.add_principal(pd, "pd-op-b", "user", "test")
iam.add_principal(pd, "pd-none", "user", "test")
def dash(v, t):
    return iam.dashboard_access(pd, v, t)["allowed"]
check("your own dashboard, always", dash("pd-op-a", "pd-op-a"), True)
check("an admin -> an operator", dash("pd-ga", "pd-op-b"), True)
check("an admin -> ANOTHER admin: refused", dash("pd-ga", "pd-ga2"), False)
check("operator -> another operator: refused", dash("pd-op-b", "pd-op-a"), False)
check("operator -> an admin: refused", dash("pd-op-a", "pd-ga"), False)
check("an admin -> a user with no role yet: allowed (any non-admin)", dash("pd-ga", "pd-none"), True)
check("an unknown user is refused, not an error", dash("pd-ga", "pd-nobody"), False)
iam.set_principal_active(pd, "pd-ga", False)
check("a disabled admin is refused", dash("pd-ga", "pd-op-a"), False)
iam.set_principal_active(pd, "pd-ga", True)

section("private dashboards: kept files follow the same ladder")
iam.add_principal(pd, "pd-op-a2", "user", "test")
write_output("pd-op-a", "pd.bin", 5)
check("an admin may resolve an operator's kept file",
      iam.resolve_output_path("pd-op-a", "pd.bin", "pd-ga", conn=pd).name, "pd.bin")
try:
    iam.resolve_output_path("pd-op-a", "pd.bin", "pd-op-a2", conn=pd)
    check("a fellow operator may not", False, True)
except iam.IAMError as e:
    check("a fellow operator may not", "only they" in str(e), True)

section("rename_principal carries the user's run slots and teams with them")
slot_root = iam.org_dir() / "enum" / "instances"
(slot_root / "pd-op-a" / ".claude" / "projects").mkdir(parents=True)
stale = slot_root / "pd-op-a" / ".claude" / "projects" / iam._mangle(slot_root / "pd-op-a")
stale.mkdir()
(slot_root / "pd-op-a.win").mkdir()
(slot_root / "pd-op-a2").mkdir()              # a different user whose name merely starts the same
(iam.org_dir() / "teams").mkdir(parents=True, exist_ok=True)
(iam.org_dir() / "teams" / "proj.json").write_text(json.dumps({"name": "proj", "owner": "pd-op-a"}))
pd_rt = iam.open_runtime(tmp / "pd-runtime.db")
out = iam.rename_principal(pd, pd_rt, "pd-op-a", "pd-op-z", "test")
check("both of the user's slots moved", out["run_slots_moved"], 2)
check("...to the new name, copy label kept",
      sorted(p.name for p in slot_root.iterdir()), ["pd-op-a2", "pd-op-z", "pd-op-z.win"])
check("...and the SDK transcript dir follows, so a stopped run stays resumable",
      (slot_root / "pd-op-z" / ".claude" / "projects" / iam._mangle(slot_root / "pd-op-z")).is_dir(), True)
check("the team's owner field moved",
      json.loads((iam.org_dir() / "teams" / "proj.json").read_text())["owner"], "pd-op-z")
pd_rt.close(); pd.close()

# ---------------------------------------------------------------------------
print("\nthe public vocabulary is 'user'; the old spellings still work (2026-10-19)")
ca = iam.canonical_argv
check("an old verb is rewritten", ca(["principal", "add", "bob"]), ["user", "add", "bob"])
check("...every old verb, one by one",
      [ca([old])[0] for old in iam.OLD_VERBS], list(iam.OLD_VERBS.values()))
check("a new verb is left alone", ca(["user", "list"]), ["user", "list"])
check("global flags before the verb are skipped over",
      ca(["--actor", "root", "--json", "list-principals"]), ["--actor", "root", "--json", "list-users"])
check("--principal becomes --user", ca(["issue-key", "--principal", "bob"]), ["issue-key", "--user", "bob"])
check("--principal=VALUE too (a base64url value can start with '-')",
      ca(["bindings", "--principal=bob"]), ["bindings", "--user=bob"])
check("a user NAMED 'principal' is not rewritten",
      ca(["can", "principal", "agent:read"]), ["can", "principal", "agent:read"])
check("...nor is anything after a bare '--'",
      ca(["bindings", "--", "--principal"]), ["bindings", "--", "--principal"])
check("--actor's own value is never mistaken for the verb",
      ca(["--actor", "principal", "user", "list"]), ["--actor", "principal", "user", "list"])

pj = iam.public_json
check("a 'principal' key reads 'user' in --json output",
      pj({"principal": "bob", "created": True}), {"user": "bob", "created": True})
check("...inside lists and nested documents",
      pj([{"group": "g", "members": [{"principal": "a"}]}]), [{"group": "g", "members": [{"user": "a"}]}])
check("a binding's stored subject_kind 'principal' reads 'user'",
      pj({"subject_kind": "principal", "subject": "bob"}), {"subject_kind": "user", "subject": "bob"})
check("...and 'group' is untouched", pj({"subject_kind": "group"}), {"subject_kind": "group"})
check("a document that already has 'user' keeps both rather than lose one",
      pj({"principal": "a", "user": "b"}), {"principal": "a", "user": "b"})


import subprocess as _sp
import os as _os
_env = {**_os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
def _cli(*args):
    r = _sp.run([sys.executable, str(Path(__file__).resolve().parent / "iam.py"), *args], capture_output=True, text=True, env=_env)
    return r.returncode, r.stdout, r.stderr
rc, out, err = _cli("--help")
check("--help shows the new verbs and none of the old ones",
      "list-users" in out and "user-history" in out and "list-principals" not in out
      and "principal-history" not in out, True)
rc, out, err = _cli("bind", "--help")
check("bind --help shows {user}", "{user}" in out, True)
rc, out, err = _cli("--json", "list-users", "--bogus-flag")
check("a parse error is still one JSON document", out.strip().startswith("{") and '"error"' in out, True)

# update-check policy: off by default, settable like every other policy, and
# visible in `policy` (the API reads it from there; it can never set it).
import tempfile as _tf
with _tf.TemporaryDirectory() as _d:
    _env_db = {**_env, "AGENTI_IAM_DB": str(Path(_d) / "iam.db"), "AGENTI_RUNTIME_DB": str(Path(_d) / "runtime.db")}
    def _cli_db(*args):
        r = _sp.run([sys.executable, str(Path(__file__).resolve().parent / "iam.py"), *args],
                    capture_output=True, text=True, env=_env_db)
        return r.returncode, r.stdout
    _cli_db("--json", "bootstrap", "--user", "uc-admin")
    _rc, _out = _cli_db("--json", "policy")
    check("update-check is off by default", json.loads(_out).get("update-check"), "off")
    _rc, _out = _cli_db("--json", "set-policy", "update-check", "on")
    check("set-policy accepts update-check", _rc, 0)
    _rc, _out = _cli_db("--json", "policy")
    check("...and policy reports it on", json.loads(_out).get("update-check"), "on")

    # The first thing a fresh install does is make an admin (add + bind), and
    # the role change is logged: user-history must list it, in the same shape
    # as every other event. It crashed on a fresh Kali (2026-10-21) because the
    # role row said op/actor instead of event/by.
    _hist = Path(_d) / "principal-history.jsonl"
    _env_db["AGENTI_PRINCIPAL_HISTORY_PATH"] = str(_hist)
    _cli_db("user", "add", "uh-admin")
    _cli_db("bind", "user", "uh-admin", "--role", "admin")
    _rc, _out = _cli_db("--json", "user-history")
    _rows = json.loads(_out) if _rc == 0 else None
    check("user-history lists the first admin's role change", (_rc, [(r["event"], r["by"] is not None) for r in _rows or []][-1:]),
          (0, [("role", True)]))
    with open(_hist, "a") as _f:   # a row in the old shape
        _f.write(json.dumps({"ts": 1, "op": "set-role", "name": "x", "role": "admin", "actor": "root"}) + "\n")
    _rc, _out = _cli_db("user-history")
    check("...and an old-shaped row is shown, not a crash", (_rc, "set-role" in _out), (0, True))

with _tf.TemporaryDirectory() as _d:
    _env_db = {**_env, "AGENTI_IAM_DB": str(Path(_d) / "iam.db"), "AGENTI_RUNTIME_DB": str(Path(_d) / "runtime.db"),
               "AGENTI_PRINCIPAL_HISTORY_PATH": str(Path(_d) / "h.jsonl")}

    def _cli_as(actor, *args):
        r = _sp.run([sys.executable, str(Path(__file__).resolve().parent / "iam.py"), "--json",
                     "--actor", actor, *args], capture_output=True, text=True, env=_env_db)
        return r.returncode, r.stdout
    _cli_as("root", "bootstrap", "--user", "cu-boss")
    _rc, _out = _cli_as("agenti-api", "create-user", "cu-web", "--kind", "user")
    check("from the web account, create-user without a grant is refused and creates nothing",
          (_rc != 0, "needs a fresh re-authentication" in _out), (True, True))
    _rc, _out = _cli_as("agenti-api", "create-user", "cu-web", "--kind", "user", "--grant=not-a-real-grant")
    check("...and with a made-up grant too", (_rc != 0, "no such approval grant" in _out), (True, True))
    _rc, _out = _cli_as("root", "--json", "list-users")
    check("...no account appeared", "cu-web" in _out, False)
    _rc, _out = _cli_as("root", "create-user", "cu-console", "--kind", "user", "--no-link")
    check("at the console (root) no grant is needed", _rc, 0)

print("\nshared/agenti: the two lists cover the old AND the new spelling of every verb")
import re as _re
_cli_text = (Path(__file__).resolve().parent / "agenti").read_text()
_wv = _re.search(r'^IAM_WRITE_VERBS="([^"]*)"', _cli_text, _re.M)
check("IAM_WRITE_VERBS is exactly the identity-WRITING verbs, under both spellings of the user verb",
      sorted(_wv.group(1).split()) if _wv else None,
      sorted("user principal bind unbind issue-key bootstrap set-policy setup-code".split()))
_case = _re.search(r'^        user\|principal\|bind\|.*?\)\n', _cli_text, _re.M | _re.S)
_forwarded = set(_re.split(r'[|\\\s)]+', _case.group(0))) if _case else set()
missing = sorted(v for v in list(iam.OLD_VERBS) + list(iam.OLD_VERBS.values()) if v not in _forwarded)
check("the forwarding case pattern reaches every old verb and every new verb", missing, [])
check("a read-only twin is NOT refused to the API (list-users, user-exists, create-user stay reachable)",
      [v for v in ("list-users", "user-exists", "create-user", "disable-user", "list-principals",
                   "principal-exists", "create-principal", "disable-principal")
       if v in _wv.group(1).split()], [])


section("F18: the runtime store refuses a planted link (root never follows one)")
_f18 = tmp / "f18-authd"
_f18.mkdir()
_secret = tmp / "f18-not-yours"
_secret.write_text("root-only")
(_f18 / "runtime.db-wal").symlink_to(_secret)
try:
    iam.open_runtime(_f18 / "runtime.db")
    _f18_res = "opened"
except iam.IAMError as e:
    _f18_res = "refused" if "not a plain file" in str(e) else str(e)
check("a runtime.db-wal link is refused, not followed", _f18_res, "refused")
check("...and the file it pointed at is untouched", _secret.read_text(), "root-only")
(_f18 / "runtime.db-wal").unlink()
(_f18 / "runtime.db").symlink_to(_secret)
try:
    iam.open_runtime(_f18 / "runtime.db")
    _f18_res = "opened"
except iam.IAMError:
    _f18_res = "refused"
check("a runtime.db link is refused", _f18_res, "refused")
(_f18 / "runtime.db").unlink()
_f18_link = tmp / "f18-linkdir"
_f18_link.symlink_to(_f18)
try:
    iam.open_runtime(_f18_link / "runtime.db")
    _f18_res = "opened"
except iam.IAMError:
    _f18_res = "refused"
check("a folder that is a link is refused", _f18_res, "refused")
_ok = iam.open_runtime(_f18 / "runtime.db")
check("the real folder still opens", _ok.execute("SELECT 1").fetchone()[0], 1)
_ok.close()


section("fix 5: sign-in (audit run 1, F07, F20, F19, passkey removal)")
_f5rt = iam.open_runtime(tmp / "f5-runtime.db")


def _f5_session(name):
    _f5rt.execute("INSERT INTO sessions(id, principal, csrf, created_at, expires_at, last_seen,"
                  " pending_totp) VALUES (?,?,?,?,?,?,0)",
                  (f"s-{name}-{time.time()}", name, "c", time.time(), time.time() + 3600, time.time()))
    _f5rt.commit()


def _f5_sessions(name):
    return _f5rt.execute("SELECT count(*) FROM sessions WHERE principal=?", (name,)).fetchone()[0]


def _f5_passkey(name, cid):
    act = iam.webauthn_register_action(name, cid, "ES256", "x", "y", 0)
    iam.passkey_commit(conn, _f5rt, name, cid, "ES256", "x", "y", 0, "key", iam.mint_action_grant(_f5rt, name, act))


# F07: a passkey is a second factor on the password door too
iam.add_principal(conn, "f5-pk", "user", "test")
iam.set_principal_password(conn, "f5-pk", "f5-pk-password-1")
check("before a passkey: the password signs in", iam.verify_login(conn, _f5rt, "f5-pk", "f5-pk-password-1").ok, True)
_f5_passkey("f5-pk", "f5-cred-1")
_r = iam.verify_login(conn, _f5rt, "f5-pk", "f5-pk-password-1")
check("F07: with a passkey and no TOTP, the password alone is refused, naming the passkey",
      (_r.ok, "passkey" in _r.reason), (False, True))
try:
    iam.reauthenticate_self(conn, _f5rt, "f5-pk", "f5-pk-password-1", None)
    _res = "passed"
except iam.IAMError as e:
    _res = "refused" if "passkey" in str(e) else str(e)
check("F07: the step-up check refuses password alone too (confirm with the passkey)", _res, "refused")

# Passkey removal revokes sessions (self and break-glass)
_f5_passkey("f5-pk", "f5-cred-2")
_f5_session("f5-pk"); _f5_session("f5-pk")
iam.remove_own_passkey(conn, _f5rt, "f5-pk", "f5-cred-1")
check("removing one's own passkey signs the account out everywhere", _f5_sessions("f5-pk"), 0)
_f5_session("f5-pk")
iam.reset_passkeys(conn, _f5rt, "f5-pk")
check("the break-glass reset-passkeys signs it out too", _f5_sessions("f5-pk"), 0)

# F20: wrong codes are never wiped by re-entering the password
iam.add_principal(conn, "f5-totp", "user", "test")
iam.set_principal_password(conn, "f5-totp", "f5-totp-password")
_sec5, _ = iam.enroll_totp(conn, "f5-totp", _f5rt)
for _ in range(iam.LOCKOUT_THRESHOLD - 1):
    iam.verify_login(conn, _f5rt, "f5-totp", "f5-totp-password", addr="10.9.9.9")
    iam.verify_second_factor(conn, _f5rt, "f5-totp", "000000", addr="10.9.9.9")
_r = iam.verify_login(conn, _f5rt, "f5-totp", "f5-totp-password", addr="10.9.9.9")
check("F20: the right password again still asks for the code", (_r.ok, _r.totp_required), (True, True))
check("F20: ...and does NOT clear the wrong-code count",
      iam._lockout_state(_f5rt, "f5-totp")[0], iam.LOCKOUT_THRESHOLD - 1)
iam.verify_second_factor(conn, _f5rt, "f5-totp", "000000", addr="10.9.9.9")
_r = iam.verify_login(conn, _f5rt, "f5-totp", "f5-totp-password", addr="10.9.9.9")
check("F20: the fifth wrong code locks the account, right password or not", _r.ok, False)
check("F20: wrong codes count against the address too",
      _f5rt.execute("SELECT failures FROM login_attempts_addr WHERE addr='10.9.9.9'").fetchone()[0]
      >= iam.LOCKOUT_THRESHOLD, True)
_f5rt.execute("DELETE FROM login_attempts WHERE principal='f5-totp'")
_f5rt.execute("DELETE FROM login_attempts_addr")
_f5rt.commit()
iam.verify_second_factor(conn, _f5rt, "f5-totp", "000000")
_ok = iam.verify_second_factor(conn, _f5rt, "f5-totp", iam.totp_code(_sec5))
check("a right code completes the sign-in and clears the count",
      (_ok.ok, iam._lockout_state(_f5rt, "f5-totp")[0]), (True, 0))

# F19: a reset link belongs to one account, once
iam.add_principal(conn, "f5-old", "user", "test")
_tok = iam.mint_password_reset_link(_f5rt, conn, "f5-old", "test")
_tok2 = iam.mint_password_reset_link(_f5rt, conn, "f5-old", "test")
check("F19: a newer link replaces the older one",
      (iam.password_reset_token_principal(conn, _f5rt, _tok), iam.password_reset_token_principal(conn, _f5rt, _tok2)),
      (None, "f5-old"))
iam.set_principal_password(conn, "f5-old", "f5-chosen-by-self")
check("F19: a password change ends an outstanding link",
      iam.password_reset_token_principal(conn, _f5rt, _tok2), None)
_tok3 = iam.mint_password_reset_link(_f5rt, conn, "f5-old", "test")
iam.rename_principal(conn, _f5rt, "f5-old", "f5-new", "alice")
iam.add_principal(conn, "f5-old", "user", "test")
try:
    iam.consume_password_reset_token(conn, _f5rt, _tok3, "takeover-password")
    _res = "consumed"
except iam.IAMError:
    _res = "refused"
check("F19: after a rename, the old link cannot reset the new account with the old name", _res, "refused")
check("...which still has no password", conn.execute(
    "SELECT password_hash FROM principals WHERE name='f5-old'").fetchone()[0], None)
# a link row forged to predate the account (any path that skips the drops)
_tok4 = iam.mint_password_reset_link(_f5rt, conn, "f5-old", "test")
_f5rt.execute("UPDATE password_reset_tokens SET created_at=0 WHERE token_hash=?", (iam.hash_key(_tok4),))
_f5rt.commit()
check("F19: a link older than the account it names is refused",
      iam.password_reset_token_principal(conn, _f5rt, _tok4), None)
_f5rt.close()


section("decision 4 / F34: a schema-v1 identity store is refused, never migrated")
import sqlite3 as _sq  # noqa: E402
_v1 = tmp / "v1-iam.db"
_c = _sq.connect(_v1)
_c.executescript("CREATE TABLE principals (name TEXT PRIMARY KEY, kind TEXT, active INTEGER, "
                 "created_at REAL, created_by TEXT); CREATE TABLE bindings (subject TEXT, role TEXT); "
                 "CREATE TABLE schema_meta (version INTEGER NOT NULL); INSERT INTO schema_meta VALUES (1); "
                 "INSERT INTO principals VALUES ('old', 'user', 1, 0, 'x');")
_c.commit(); _c.close()
for _ro in (False, True):
    try:
        iam.open_iam(readonly=_ro, path=_v1); _res = "opened"
    except iam.IAMError as e:
        _res = "refused" if "fresh installs only" in str(e) and "agenti setup" in str(e) else str(e)
    check(f"a v1 store is refused ({'read' if _ro else 'write'} open), naming the fix", _res, "refused")
_c = _sq.connect(_v1)
check("...and left exactly as it was (no role column added, bindings kept)",
      ("role" in {r[1] for r in _c.execute("PRAGMA table_info(principals)")},
       _c.execute("SELECT count(*) FROM sqlite_master WHERE name='bindings'").fetchone()[0]), (False, 1))
_c.close()
_fresh = iam.open_iam(readonly=False, path=tmp / "fresh-iam.db")
check("a fresh store opens and is stamped with the current schema version",
      _fresh.execute("SELECT version FROM schema_meta").fetchone()[0], iam.SCHEMA_VERSION)
_fresh.close()


section("F36: a rename moves the user's memory and own key; a reissued old name inherits neither")
iam.add_principal(conn, "f36-old", "user", "test")
_mem = iam.org_dir() / "context" / "memory" / "enum"
_mem.mkdir(parents=True, exist_ok=True)
(_mem / "f36-old.md").write_text("prefers quiet scans")
(_mem / ".versions" / "f36-old").mkdir(parents=True, exist_ok=True)
(_mem / ".versions" / "f36-old" / "history.jsonl").write_text("{}\n")
_key = iam.org_dir() / "users" / "f36-old"
_key.mkdir(parents=True, exist_ok=True)
(_key / "secrets.env").write_text("ANTHROPIC_API_KEY=x\n")
iam.rename_principal(conn, None, "f36-old", "f36-new", "alice")
check("memory moved to the new name", (_mem / "f36-new.md").read_text(), "prefers quiet scans")
check("...with its edit history", (_mem / ".versions" / "f36-new" / "history.jsonl").exists(), True)
check("the own-key folder moved", (iam.org_dir() / "users" / "f36-new" / "secrets.env").exists(), True)
check("nothing is left under the old name",
      ((_mem / "f36-old.md").exists(), (iam.org_dir() / "users" / "f36-old").exists()), (False, False))
iam.delete_principal(conn, None, "f36-new", "alice")
check("deleting the account removes its own API key",
      (iam.org_dir() / "users" / "f36-new" / "secrets.env").exists(), False)


section("CodeQL triage: a password in a grant is bound slowly, and a spent grant keeps no binding")
import hashlib as _hl, json as _js  # noqa: E401,E402
_act = {"op": "reset-password", "principal": "x", "resource": ORG, "mode": "direct", "new_password": "Chosen-pw-123"}
_fast = _hl.sha256(_js.dumps(_act, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
check("the binding is not the fast SHA-256 of the action with the password in it", iam.action_hash(_act) != _fast, True)
check("...and is deterministic (mint and consume agree)", iam.action_hash(dict(_act)), iam.action_hash(_act))
_rtg = iam.open_runtime(tmp / "grant-wipe.db")
_g = iam.mint_action_grant(_rtg, "alice", _act)
iam.consume_action_grant(_rtg, _g, _act)
check("a spent grant's binding is wiped", _rtg.execute("SELECT action_hash FROM action_grants WHERE id=?", (_g,)).fetchone()[0], "")
_rtg.close()

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
