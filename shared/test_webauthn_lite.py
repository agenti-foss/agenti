#!/usr/bin/env python3
"""test_webauthn_lite.py — CBOR decoding, authenticatorData/COSE parsing,
and WebAuthn ceremony verification (shared/webauthn_lite.py).

No framework, no root, no vault, no dependency at runtime:

    python3 shared/test_webauthn_lite.py

WHAT IT PINS DOWN. The CBOR decoder is checked against RFC 8949 Appendix A's
own published test vectors — a known-answer test, not a guess at correctness.
The ceremony functions (verify_registration/verify_assertion) are checked
against REAL registration/assertion payloads: a genuine P-256 key pair, a
genuine CBOR-encoded attestationObject, and genuine ECDSA signatures, all
generated ONCE by an independent oracle (the `cryptography` + `cbor2`
packages, in a scratch venv — see /tmp/gen_webauthn_fixtures.py, not part of
this repo) and pinned below as hex fixtures. This suite needs neither
package: it only ever calls the hand-written parsing/verification code in
webauthn_lite.py against bytes an independent implementation produced,
which is what makes "genuine accepted, tampered refused" mean something —
the same methodology test_qr.py already uses against segno+OpenCV.

Signature verification itself (verify_es256) still needs the `cryptography`
package to run at all (it's the one function in webauthn_lite.py that isn't
pure stdlib) — those checks are skipped, loudly, if it isn't importable,
rather than silently passing a suite that tested nothing.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import webauthn_lite as w  # noqa: E402

PASS = FAIL = SKIP = 0


def check(label, got, want):
    global PASS, FAIL
    if got == want:
        PASS += 1; print(f"  [ OK ] {label}")
    else:
        FAIL += 1; print(f"  [FAIL] {label}\n         got  {got!r}\n         want {want!r}")


def check_raises(label, exc_type, fn, *a, **kw):
    global PASS, FAIL
    try:
        fn(*a, **kw)
        FAIL += 1; print(f"  [FAIL] {label} (did not raise)")
    except exc_type as e:
        PASS += 1; print(f"  [ OK ] {label}: {str(e)[:70]}")
    except Exception as e:  # noqa: BLE001
        FAIL += 1; print(f"  [FAIL] {label} (wrong exception type: {type(e).__name__}: {e})")


def section(t): print(f"\n=== {t} ===")


try:
    import cryptography  # noqa: F401
    HAVE_CRYPTOGRAPHY = True
except ImportError:
    HAVE_CRYPTOGRAPHY = False


def h(s: str) -> bytes:
    return bytes.fromhex(s)


# =============================================================================
section("CBOR — RFC 8949 Appendix A known-answer vectors")
# =============================================================================

CBOR_VECTORS = [
    ("00", 0), ("01", 1), ("0a", 10), ("17", 23), ("1818", 24), ("1819", 25),
    ("1864", 100), ("1903e8", 1000), ("1a000f4240", 1000000),
    ("20", -1), ("29", -10), ("3863", -100), ("3903e7", -1000),
    ("60", ""), ("6161", "a"), ("6449455446", "IETF"), ("62225c", "\"\\"),
    ("40", b""), ("4401020304", b"\x01\x02\x03\x04"),
    ("80", []), ("83010203", [1, 2, 3]), ("8301820203820405", [1, [2, 3], [4, 5]]),
    ("a0", {}), ("a201020304", {1: 2, 3: 4}), ("a26161016162820203", {"a": 1, "b": [2, 3]}),
]
for hexstr, expected in CBOR_VECTORS:
    raw = h(hexstr)
    val, consumed = w.cbor_decode(raw)
    check(f"decode {hexstr!r} -> {expected!r}", (val, consumed), (expected, len(raw)))

section("CBOR — unsupported/malformed input refused, not mishandled")
check_raises("a tag (major 6) is refused", w.CBORError, w.cbor_decode,
             h("c074323031332d30332d32315432303a30343a30305a"))
check_raises("a simple/bool value (major 7) is refused", w.CBORError, w.cbor_decode, h("f5"))
check_raises("indefinite-length byte string is refused", w.CBORError, w.cbor_decode,
             h("5f42010243030405ff"))
check_raises("truncated uint16 argument is refused", w.CBORError, w.cbor_decode, h("19"))
check_raises("truncated byte string body is refused", w.CBORError, w.cbor_decode, h("44010203"))
check_raises("empty input is refused", w.CBORError, w.cbor_decode, b"")
check_raises("invalid utf-8 text string is refused", w.CBORError, w.cbor_decode, h("61ff"))


# =============================================================================
section("base64url round trip")
# =============================================================================
for raw in (b"", b"\x00", b"\xff\xfe\xfd", bytes(range(256))):
    check(f"b64url round trip of {len(raw)} random-ish bytes", w.b64url_decode(w.b64url_encode(raw)), raw)
# base64url must not contain '+' or '/' (those are the non-url-safe alphabet)
check("b64url_encode never emits '+' or '/'",
      any(c in w.b64url_encode(bytes(range(256))) for c in "+/"), False)
check_raises("b64url_decode refuses garbage", w.WebAuthnError, w.b64url_decode, "!!!not base64!!!")


# =============================================================================
section("authenticatorData — fixed binary layout (WebAuthn §6.1)")
# =============================================================================
import hashlib  # noqa: E402

rp_hash = hashlib.sha256(b"example.com").digest()


def build_ad(flags: int, sign_count: int, attested: bytes = b"", extra: bytes = b"") -> bytes:
    return rp_hash + bytes([flags]) + sign_count.to_bytes(4, "big") + attested + extra


check_raises("too short (< 37 bytes) is refused", w.WebAuthnError,
             w.parse_authenticator_data, rp_hash + b"\x00")

# a minimal, no-attested-data authenticatorData (typical of an assertion)
ad_bytes = build_ad(flags=0x01 | 0x04, sign_count=7)  # UP + UV
parsed = w.parse_authenticator_data(ad_bytes)
check("rp_id_hash extracted correctly", parsed["rp_id_hash"], rp_hash)
check("UP flag parsed", parsed["up"], True)
check("UV flag parsed", parsed["uv"], True)
check("AT flag absent", parsed["at"], False)
check("sign_count parsed", parsed["sign_count"], 7)
check("no credential_id when AT is unset", parsed["credential_id"], None)

# trailing garbage must be refused, not silently ignored
check_raises("unexplained trailing bytes are refused", w.WebAuthnError,
             w.parse_authenticator_data, ad_bytes + b"\x99")

# flags with none set
ad_none = build_ad(flags=0x00, sign_count=0)
parsed_none = w.parse_authenticator_data(ad_none)
check("no flags set -> up/uv/at/ed all False",
      (parsed_none["up"], parsed_none["uv"], parsed_none["at"], parsed_none["ed"]),
      (False, False, False, False))

# a truncated attested-credential-data header (AT set but not enough bytes)
check_raises("AT set but truncated header is refused", w.WebAuthnError,
             w.parse_authenticator_data, build_ad(flags=0x40, sign_count=0, attested=b"\x00" * 10))


# =============================================================================
section("COSE_Key — EC2/P-256/ES256 only, everything else refused")
# =============================================================================
GOOD_X = b"\x11" * 32
GOOD_Y = b"\x22" * 32
good_cose = {1: 2, 3: -7, -1: 1, -2: GOOD_X, -3: GOOD_Y}
x, y = w.parse_cose_ec2_p256(good_cose)
check("EC2/P-256/ES256 key parses to correct (x, y)", (x, y), (GOOD_X, GOOD_Y))

check_raises("not a dict is refused", w.WebAuthnError, w.parse_cose_ec2_p256, "not a map")
check_raises("wrong key type (RSA=3) is refused", w.UnsupportedAlgorithm,
             w.parse_cose_ec2_p256, {**good_cose, 1: 3})
check_raises("wrong algorithm (RS256) is refused", w.UnsupportedAlgorithm,
             w.parse_cose_ec2_p256, {**good_cose, 3: -257})
check_raises("wrong curve (P-384) is refused", w.UnsupportedAlgorithm,
             w.parse_cose_ec2_p256, {**good_cose, -1: 2})
check_raises("non-bytes coordinate is refused", w.WebAuthnError,
             w.parse_cose_ec2_p256, {**good_cose, -2: 12345})
check_raises("wrong-length coordinate is refused", w.WebAuthnError,
             w.parse_cose_ec2_p256, {**good_cose, -2: b"\x11" * 31})


# =============================================================================
section("real WebAuthn payloads — genuine oracle-generated fixtures")
# =============================================================================
# Generated once by an independent implementation (cryptography + cbor2, a
# scratch venv) as described in the module docstring above. A real P-256
# key pair, a real CBOR-encoded attestationObject, real ECDSA signatures.
F = {
    "rp_id": "agenti.example.com",
    "origin": "https://agenti.example.com:8420",
    "x": "243eedcbfc15838aef39605ea26beff684a285518b29a16575272f3d48b65664",
    "y": "aa8054bfcaf5d512e7ac7f9725c3388aa108eab4700bb60811c8d2caa27bd85d",
    "credential_id": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    "reg_challenge_b64": "cmVnaXN0cmF0aW9uLWNoYWxsZW5nZS1ieXRlcy0wMTIzNDU2Nzg5",
    "reg_client_data_json": "7b2274797065223a22776562617574686e2e637265617465222c226368616c6c656e6765223a22636d566e61584e30636d4630615739754c574e6f595778735a57356e5a5331696558526c637930774d54497a4e4455324e7a6735222c226f726967696e223a2268747470733a2f2f6167656e74692e6578616d706c652e636f6d3a38343230227d",
    "attestation_object": "a363666d74646e6f6e656761747453746d74a068617574684461746158a49c77c847a794c6d9517b05f6ce0e28c0f7ee9779d6f9ab522bc9f59347c6d7284500000000000000000000000000000000000000000020000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fa5010203262001215820243eedcbfc15838aef39605ea26beff684a285518b29a16575272f3d48b65664225820aa8054bfcaf5d512e7ac7f9725c3388aa108eab4700bb60811c8d2caa27bd85d",
    "assert_challenge_b64": "YXNzZXJ0aW9uLWNoYWxsZW5nZS1ieXRlcy1hYmNkZWZnaGlqazAx",
    "assert_client_data_json": "7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a2259584e7a5a584a30615739754c574e6f595778735a57356e5a5331696558526c63793168596d4e6b5a575a6e61476c71617a4178222c226f726967696e223a2268747470733a2f2f6167656e74692e6578616d706c652e636f6d3a38343230227d",
    "assert_authenticator_data": "9c77c847a794c6d9517b05f6ce0e28c0f7ee9779d6f9ab522bc9f59347c6d7280500000001",
    "assert_signature": "304402200db5a7e94d5ea853f9bb64fb393a9ef5756b09efd94795ac03fdf011bcf6d36f022042776a048d6f7fa7ab2515ee5009b6042a301cf2c13c8e74231acf6350117357",
    "assert_authenticator_data_count2": "9c77c847a794c6d9517b05f6ce0e28c0f7ee9779d6f9ab522bc9f59347c6d7280500000002",
    "assert_signature_count2": "30460221008e9da1a121ffab5f442741433111f6c1ca17d08629f033785b3e6c8567ce4b4c02210089d036323a09e34439f3d9b075bbc36f9e14453e43015f32de42e09cbfb4812d",
    "assert_authenticator_data_count0": "9c77c847a794c6d9517b05f6ce0e28c0f7ee9779d6f9ab522bc9f59347c6d7280500000000",
    "assert_signature_count0": "3045022100b600b6bfcdaef3ea42197d3b5daf0e62903aca68dc7c3312d9dccb26436ff40e022026ee783e349903018b45ee42187ae978b225238ba1363136769bb617c9faa2d8",
}

if not HAVE_CRYPTOGRAPHY:
    SKIP += 1
    print("  [SKIP] entire section — 'cryptography' is not importable in this "
          "environment (it is only ever required on agenti-authd's dedicated "
          "venv, never for running this suite). Parsing-only checks above "
          "still ran and still count.")
else:
    section("registration — genuine payload verifies, extracted fields correct")
    result = w.verify_registration(
        rp_id=F["rp_id"], origin=F["origin"],
        expected_challenge_b64=F["reg_challenge_b64"],
        client_data_json=h(F["reg_client_data_json"]),
        attestation_object=h(F["attestation_object"]),
    )
    check("credential_id extracted", result["credential_id"], h(F["credential_id"]))
    check("x extracted", result["x"], h(F["x"]))
    check("y extracted", result["y"], h(F["y"]))
    check("alg is ES256", result["alg"], "ES256")
    check("sign_count starts at 0", result["sign_count"], 0)

    section("registration — tampering is refused, each for its own reason")
    check_raises("wrong challenge", w.WebAuthnError, w.verify_registration,
                 rp_id=F["rp_id"], origin=F["origin"], expected_challenge_b64="not-the-real-challenge",
                 client_data_json=h(F["reg_client_data_json"]), attestation_object=h(F["attestation_object"]))
    check_raises("wrong origin", w.WebAuthnError, w.verify_registration,
                 rp_id=F["rp_id"], origin="https://evil.example.net", expected_challenge_b64=F["reg_challenge_b64"],
                 client_data_json=h(F["reg_client_data_json"]), attestation_object=h(F["attestation_object"]))
    check_raises("wrong rp_id (rpIdHash mismatch)", w.WebAuthnError, w.verify_registration,
                 rp_id="other.example.com", origin=F["origin"], expected_challenge_b64=F["reg_challenge_b64"],
                 client_data_json=h(F["reg_client_data_json"]), attestation_object=h(F["attestation_object"]))
    bad_type = h(F["reg_client_data_json"]).replace(b"webauthn.create", b"webauthn.get_____")
    check_raises("wrong clientData.type", w.WebAuthnError, w.verify_registration,
                 rp_id=F["rp_id"], origin=F["origin"], expected_challenge_b64=F["reg_challenge_b64"],
                 client_data_json=bad_type, attestation_object=h(F["attestation_object"]))
    check_raises("corrupt CBOR attestationObject", w.WebAuthnError, w.verify_registration,
                 rp_id=F["rp_id"], origin=F["origin"], expected_challenge_b64=F["reg_challenge_b64"],
                 client_data_json=h(F["reg_client_data_json"]), attestation_object=b"\xff\xff\xff")

    section("assertion — genuine payload verifies, counter advances")
    new_count = w.verify_assertion(
        rp_id=F["rp_id"], origin=F["origin"], expected_challenge_b64=F["assert_challenge_b64"],
        client_data_json=h(F["assert_client_data_json"]),
        authenticator_data=h(F["assert_authenticator_data"]),
        signature=h(F["assert_signature"]),
        stored_x=h(F["x"]), stored_y=h(F["y"]), stored_sign_count=0,
    )
    check("new sign_count returned", new_count, 1)

    section("assertion — tampering and replay are each refused for their own reason")
    bad_sig = bytearray(h(F["assert_signature"])); bad_sig[10] ^= 0xFF
    check_raises("tampered signature bytes", w.WebAuthnError, w.verify_assertion,
                 rp_id=F["rp_id"], origin=F["origin"], expected_challenge_b64=F["assert_challenge_b64"],
                 client_data_json=h(F["assert_client_data_json"]),
                 authenticator_data=h(F["assert_authenticator_data"]), signature=bytes(bad_sig),
                 stored_x=h(F["x"]), stored_y=h(F["y"]), stored_sign_count=0)
    check_raises("wrong challenge", w.WebAuthnError, w.verify_assertion,
                 rp_id=F["rp_id"], origin=F["origin"], expected_challenge_b64="not-the-real-challenge",
                 client_data_json=h(F["assert_client_data_json"]),
                 authenticator_data=h(F["assert_authenticator_data"]), signature=h(F["assert_signature"]),
                 stored_x=h(F["x"]), stored_y=h(F["y"]), stored_sign_count=0)
    check_raises("wrong origin", w.WebAuthnError, w.verify_assertion,
                 rp_id=F["rp_id"], origin="https://evil.example.net", expected_challenge_b64=F["assert_challenge_b64"],
                 client_data_json=h(F["assert_client_data_json"]),
                 authenticator_data=h(F["assert_authenticator_data"]), signature=h(F["assert_signature"]),
                 stored_x=h(F["x"]), stored_y=h(F["y"]), stored_sign_count=0)
    check_raises("wrong rp_id (rpIdHash mismatch)", w.WebAuthnError, w.verify_assertion,
                 rp_id="other.example.com", origin=F["origin"], expected_challenge_b64=F["assert_challenge_b64"],
                 client_data_json=h(F["assert_client_data_json"]),
                 authenticator_data=h(F["assert_authenticator_data"]), signature=h(F["assert_signature"]),
                 stored_x=h(F["x"]), stored_y=h(F["y"]), stored_sign_count=0)
    check_raises("signature valid but wrong stored key", w.WebAuthnError, w.verify_assertion,
                 rp_id=F["rp_id"], origin=F["origin"], expected_challenge_b64=F["assert_challenge_b64"],
                 client_data_json=h(F["assert_client_data_json"]),
                 authenticator_data=h(F["assert_authenticator_data"]), signature=h(F["assert_signature"]),
                 stored_x=h(F["x"]), stored_y=bytes(b ^ 0xFF for b in h(F["y"])), stored_sign_count=0)
    check_raises("counter regression (replayed/cloned authenticator)", w.WebAuthnError, w.verify_assertion,
                 rp_id=F["rp_id"], origin=F["origin"], expected_challenge_b64=F["assert_challenge_b64"],
                 client_data_json=h(F["assert_client_data_json"]),
                 authenticator_data=h(F["assert_authenticator_data_count0"]),
                 signature=h(F["assert_signature_count0"]),
                 stored_x=h(F["x"]), stored_y=h(F["y"]), stored_sign_count=5)

    section("assertion — both-sign-count-zero is tolerated, not treated as regression")
    zero_count = w.verify_assertion(
        rp_id=F["rp_id"], origin=F["origin"], expected_challenge_b64=F["assert_challenge_b64"],
        client_data_json=h(F["assert_client_data_json"]),
        authenticator_data=h(F["assert_authenticator_data_count0"]),
        signature=h(F["assert_signature_count0"]),
        stored_x=h(F["x"]), stored_y=h(F["y"]), stored_sign_count=0,
    )
    check("both counters zero -> tolerated, new_count is 0", zero_count, 0)
    # a genuine advance from 0 -> 2 (skipping 1) must still be accepted;
    # WebAuthn only forbids going backward or repeating, not skipping ahead.
    advanced = w.verify_assertion(
        rp_id=F["rp_id"], origin=F["origin"], expected_challenge_b64=F["assert_challenge_b64"],
        client_data_json=h(F["assert_client_data_json"]),
        authenticator_data=h(F["assert_authenticator_data_count2"]),
        signature=h(F["assert_signature_count2"]),
        stored_x=h(F["x"]), stored_y=h(F["y"]), stored_sign_count=0,
    )
    check("counter may skip ahead (0 -> 2) without being refused", advanced, 2)

    section("verify_es256 — direct checks")
    check("verify_es256 accepts a genuine signature", w.verify_es256(
        h(F["x"]), h(F["y"]),
        h(F["assert_authenticator_data"]) + hashlib.sha256(h(F["assert_client_data_json"])).digest(),
        h(F["assert_signature"]),
    ), True)
    check("verify_es256 rejects a wrong signature (returns False, does not raise)", w.verify_es256(
        h(F["x"]), h(F["y"]), b"different signed data entirely", h(F["assert_signature"]),
    ), False)
    check_raises("verify_es256 raises on a structurally invalid point (not on curve)",
                 w.WebAuthnError, w.verify_es256, b"\x00" * 32, b"\x00" * 32, b"data", h(F["assert_signature"]))


print(f"\n{PASS} passed, {FAIL} failed, {SKIP} section(s) skipped")
sys.exit(1 if FAIL else 0)
