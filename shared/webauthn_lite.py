"""webauthn_lite.py — WebAuthn (passkey) parsing and ceremony verification.

Everything in this module is pure stdlib EXCEPT the one function that does
the actual elliptic-curve signature check (verify_es256), which lazily
imports `cryptography` from the environment agenti-runtime provides only
for agenti-authd (packaging/runtime/authd.lock). The split is deliberate: CBOR decoding,
the authenticatorData byte layout, and the WebAuthn ceremony checks
(challenge/origin/rpIdHash/flags) are ordinary, well-defined, testable code
with no cryptographic stakes if a parsing bug exists — the same category as
this project's stdlib QR encoder (shared/qr.py). Elliptic-curve point
validation and signature verification are NOT that category; hand-rolling
that math is the one thing this module deliberately does not do. See
CLAUDE.md's WebAuthn item for the full reasoning.

Scope, stated explicitly rather than left implicit:
  - CBOR: only major types 0-5 (unsigned/negative integers, byte strings,
    text strings, arrays, maps) are supported — exactly what an
    attestationObject and a COSE_Key ever contain. Tags (major 6) and
    simple values/floats (major 7) are refused with a clear error; nothing
    this module parses ever uses them. Indefinite-length items are refused
    for the same reason: real authenticators encode definite-length CBOR.
  - Algorithm: ES256 (ECDSA P-256 + SHA-256) only, the default for every
    major platform authenticator (iCloud Keychain, Google Password
    Manager, Windows Hello). RS256/EdDSA are refused with a clear
    "unsupported algorithm" error rather than silently mishandled.
  - Attestation trust: NOT verified. This module accepts whatever `fmt` an
    authenticator reports and never checks attStmt's own signature or
    certificate chain. What matters for account security is the assertion
    signature checked on every future login, not proving an authenticator's
    model at registration time — a deliberate, standard simplification for
    this kind of relying party, not an oversight.
  - User verification is REQUIRED (the UV flag), both at registration and
    at every login — a platform/synced passkey always performs a
    biometric/PIN check before releasing a signature, and requiring it here
    is what lets a passkey satisfy this platform's 2FA policy on its own.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Any


class WebAuthnError(ValueError):
    """A WebAuthn ceremony failed verification, for a reason named in the message."""


class UnsupportedAlgorithm(WebAuthnError):
    """The credential uses an algorithm/key type this module does not support."""


class CBORError(WebAuthnError):
    """Malformed or unsupported CBOR."""


# ---------------------------------------------------------------------------
# base64url — WebAuthn's own encoding for every binary field it moves
# through JSON (challenges, credential ids, signatures, public key bytes).
# ---------------------------------------------------------------------------

def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(s: str) -> bytes:
    s = s.strip()
    s += "=" * (-len(s) % 4)
    try:
        return base64.urlsafe_b64decode(s)
    except Exception as e:  # noqa: BLE001 — any decode failure is just "bad input"
        raise WebAuthnError(f"invalid base64url value: {e}") from e


# ---------------------------------------------------------------------------
# CBOR decoding — RFC 8949, major types 0-5 only (see module docstring).
# ---------------------------------------------------------------------------

def _read_uint(data: bytes, pos: int, info: int) -> tuple[int, int]:
    if info < 24:
        return info, pos
    if info == 24:
        if pos + 1 > len(data):
            raise CBORError("truncated CBOR: expected 1 more byte for a uint8 argument")
        return data[pos], pos + 1
    if info == 25:
        if pos + 2 > len(data):
            raise CBORError("truncated CBOR: expected 2 more bytes for a uint16 argument")
        return int.from_bytes(data[pos:pos + 2], "big"), pos + 2
    if info == 26:
        if pos + 4 > len(data):
            raise CBORError("truncated CBOR: expected 4 more bytes for a uint32 argument")
        return int.from_bytes(data[pos:pos + 4], "big"), pos + 4
    if info == 27:
        if pos + 8 > len(data):
            raise CBORError("truncated CBOR: expected 8 more bytes for a uint64 argument")
        return int.from_bytes(data[pos:pos + 8], "big"), pos + 8
    raise CBORError(
        f"unsupported CBOR additional info {info} (indefinite-length items are not supported)"
    )


def _decode(data: bytes, pos: int) -> tuple[Any, int]:
    if pos >= len(data):
        raise CBORError("unexpected end of CBOR data")
    initial = data[pos]
    major = initial >> 5
    info = initial & 0x1F
    pos += 1

    if major == 0:  # unsigned integer
        return _read_uint(data, pos, info)

    if major == 1:  # negative integer
        val, pos = _read_uint(data, pos, info)
        return -1 - val, pos

    if major == 2:  # byte string
        length, pos = _read_uint(data, pos, info)
        if pos + length > len(data):
            raise CBORError("truncated CBOR byte string")
        return data[pos:pos + length], pos + length

    if major == 3:  # text string
        length, pos = _read_uint(data, pos, info)
        if pos + length > len(data):
            raise CBORError("truncated CBOR text string")
        raw = data[pos:pos + length]
        try:
            return raw.decode("utf-8"), pos + length
        except UnicodeDecodeError as e:
            raise CBORError(f"CBOR text string is not valid UTF-8: {e}") from e

    if major == 4:  # array
        count, pos = _read_uint(data, pos, info)
        items: list[Any] = []
        for _ in range(count):
            item, pos = _decode(data, pos)
            items.append(item)
        return items, pos

    if major == 5:  # map
        count, pos = _read_uint(data, pos, info)
        result: dict[Any, Any] = {}
        for _ in range(count):
            key, pos = _decode(data, pos)
            value, pos = _decode(data, pos)
            result[key] = value
        return result, pos

    raise CBORError(
        f"unsupported CBOR major type {major} "
        "(only unsigned/negative integers, byte strings, text strings, "
        "arrays and maps are supported — see webauthn_lite's module docstring)"
    )


def cbor_decode(data: bytes) -> tuple[Any, int]:
    """Decode exactly one CBOR item from the start of `data`.

    Returns (value, bytes_consumed) — the caller decides whether trailing
    bytes are an error (a top-level ceremony payload should have none;
    authenticatorData's embedded COSE key is followed by more bytes it must
    itself keep parsing, which is why this doesn't raise on trailing data
    itself)."""
    if not isinstance(data, (bytes, bytearray)):
        raise CBORError("CBOR input must be bytes")
    return _decode(bytes(data), 0)


# ---------------------------------------------------------------------------
# authenticatorData — a FIXED binary layout, not CBOR (WebAuthn §6.1).
# ---------------------------------------------------------------------------

_FLAG_UP = 0x01  # user present
_FLAG_UV = 0x04  # user verified
_FLAG_AT = 0x40  # attested credential data included
_FLAG_ED = 0x80  # extension data included


def parse_authenticator_data(data: bytes) -> dict[str, Any]:
    if len(data) < 37:
        raise WebAuthnError(
            f"authenticatorData is only {len(data)} bytes (need at least 37 for "
            "rpIdHash + flags + signCount)"
        )
    rp_id_hash = data[0:32]
    flags = data[32]
    sign_count = int.from_bytes(data[33:37], "big")
    pos = 37

    up = bool(flags & _FLAG_UP)
    uv = bool(flags & _FLAG_UV)
    at = bool(flags & _FLAG_AT)
    ed = bool(flags & _FLAG_ED)

    aaguid = credential_id = public_key = None
    if at:
        if pos + 18 > len(data):
            raise WebAuthnError("authenticatorData: truncated attested credential data header")
        aaguid = data[pos:pos + 16]
        pos += 16
        cred_id_len = int.from_bytes(data[pos:pos + 2], "big")
        pos += 2
        if pos + cred_id_len > len(data):
            raise WebAuthnError("authenticatorData: truncated credential id")
        credential_id = data[pos:pos + cred_id_len]
        pos += cred_id_len
        public_key, consumed = cbor_decode(data[pos:])
        pos += consumed

    if ed:
        _extensions, consumed = cbor_decode(data[pos:])
        pos += consumed

    if pos != len(data):
        raise WebAuthnError(
            f"authenticatorData has {len(data) - pos} unexplained trailing byte(s)"
        )

    return {
        "rp_id_hash": rp_id_hash,
        "flags": flags,
        "up": up,
        "uv": uv,
        "at": at,
        "ed": ed,
        "sign_count": sign_count,
        "aaguid": aaguid,
        "credential_id": credential_id,
        "public_key": public_key,
    }


# ---------------------------------------------------------------------------
# COSE_Key — v1 supports EC2/P-256 (ES256) only. See module docstring.
# ---------------------------------------------------------------------------

_COSE_KTY_EC2 = 2
_COSE_ALG_ES256 = -7
_COSE_CRV_P256 = 1


def parse_cose_ec2_p256(cose_key: Any) -> tuple[bytes, bytes]:
    """Extract (x, y) — each a 32-byte big-endian coordinate — from a
    COSE_Key CBOR map, refusing anything that isn't EC2/P-256/ES256."""
    if not isinstance(cose_key, dict):
        raise WebAuthnError("credential public key is not a CBOR map")
    kty = cose_key.get(1)
    alg = cose_key.get(3)
    crv = cose_key.get(-1)
    x = cose_key.get(-2)
    y = cose_key.get(-3)
    if kty != _COSE_KTY_EC2:
        raise UnsupportedAlgorithm(
            f"unsupported COSE key type {kty!r} — only EC2 (P-256/ES256) passkeys are supported"
        )
    if alg != _COSE_ALG_ES256:
        raise UnsupportedAlgorithm(
            f"unsupported COSE algorithm {alg!r} — only ES256 is supported"
        )
    if crv != _COSE_CRV_P256:
        raise UnsupportedAlgorithm(
            f"unsupported COSE curve {crv!r} — only P-256 is supported"
        )
    if not isinstance(x, (bytes, bytearray)) or not isinstance(y, (bytes, bytearray)):
        raise WebAuthnError("EC2 public key coordinates are not byte strings")
    if len(x) != 32 or len(y) != 32:
        raise WebAuthnError(
            f"EC2 public key coordinates are the wrong length (x={len(x)}, y={len(y)}, expected 32 each)"
        )
    return bytes(x), bytes(y)


# ---------------------------------------------------------------------------
# Signature verification — the ONE function in this module that is not pure
# stdlib. Imported lazily so every other function above remains importable
# and independently testable without the dependency present.
# ---------------------------------------------------------------------------

def verify_es256(x: bytes, y: bytes, signed_data: bytes, signature_der: bytes) -> bool:
    """Verify an ECDSA P-256 / SHA-256 signature over `signed_data` against
    the public key given as raw (x, y) coordinates. Returns True/False —
    never raises for an ordinary bad signature, only for a structurally
    invalid key (e.g. a point not on the curve)."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    x_int = int.from_bytes(x, "big")
    y_int = int.from_bytes(y, "big")
    try:
        public_key = ec.EllipticCurvePublicNumbers(x_int, y_int, ec.SECP256R1()).public_key()
    except ValueError as e:
        # A point not on the curve, or otherwise structurally invalid — this
        # is a malformed/hostile key, not "signature didn't match".
        raise WebAuthnError(f"stored public key is not a valid P-256 point: {e}") from e

    try:
        public_key.verify(signature_der, signed_data, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


# ---------------------------------------------------------------------------
# Ceremony-level verification — registration and assertion.
# ---------------------------------------------------------------------------

def _check_client_data(
    client_data_json: bytes, *, expected_type: str, expected_challenge_b64: str, expected_origin: str
) -> None:
    try:
        cd = json.loads(client_data_json.decode("utf-8"))
    except Exception as e:  # noqa: BLE001
        raise WebAuthnError(f"clientDataJSON is not valid JSON: {e}") from e
    if not isinstance(cd, dict):
        raise WebAuthnError("clientDataJSON is not a JSON object")
    if cd.get("type") != expected_type:
        raise WebAuthnError(f"clientDataJSON.type is {cd.get('type')!r}, expected {expected_type!r}")
    # A challenge is single-use and not secret once minted (its whole job is
    # to be echoed back once), so an ordinary == is fine here — unlike a
    # password or TOTP comparison, timing leaks nothing exploitable.
    if cd.get("challenge") != expected_challenge_b64:
        raise WebAuthnError("challenge does not match the one issued for this ceremony")
    if cd.get("origin") != expected_origin:
        raise WebAuthnError(f"origin {cd.get('origin')!r} does not match the expected {expected_origin!r}")


def verify_registration(
    *,
    rp_id: str,
    origin: str,
    expected_challenge_b64: str,
    client_data_json: bytes,
    attestation_object: bytes,
) -> dict[str, Any]:
    """Verify a WebAuthn registration ceremony.

    Returns {"credential_id": bytes, "alg": "ES256", "x": bytes, "y": bytes,
    "sign_count": int} on success. Raises WebAuthnError / UnsupportedAlgorithm
    on any failure. Does NOT verify the attestation statement's own signature
    or trust chain — see the module docstring for why that's deliberate."""
    _check_client_data(
        client_data_json,
        expected_type="webauthn.create",
        expected_challenge_b64=expected_challenge_b64,
        expected_origin=origin,
    )

    att_obj, consumed = cbor_decode(attestation_object)
    if consumed != len(attestation_object):
        raise WebAuthnError(
            f"attestationObject has {len(attestation_object) - consumed} unexplained trailing byte(s)"
        )
    if not isinstance(att_obj, dict) or "authData" not in att_obj:
        raise WebAuthnError("attestationObject is missing authData")
    auth_data_raw = att_obj["authData"]
    if not isinstance(auth_data_raw, (bytes, bytearray)):
        raise WebAuthnError("attestationObject.authData is not a byte string")

    ad = parse_authenticator_data(bytes(auth_data_raw))

    expected_hash = hashlib.sha256(rp_id.encode("utf-8")).digest()
    if not hmac.compare_digest(ad["rp_id_hash"], expected_hash):
        raise WebAuthnError("authenticatorData rpIdHash does not match this deployment's relying-party id")
    if not ad["up"]:
        raise WebAuthnError("the authenticator did not report the user present")
    if not ad["uv"]:
        raise WebAuthnError(
            "the authenticator did not verify the user (no biometric/PIN) — "
            "a platform passkey is required to verify the user on this deployment"
        )
    if not ad["at"] or ad["credential_id"] is None or ad["public_key"] is None:
        raise WebAuthnError("authenticatorData has no attested credential data")

    x, y = parse_cose_ec2_p256(ad["public_key"])

    return {
        "credential_id": ad["credential_id"],
        "alg": "ES256",
        "x": x,
        "y": y,
        "sign_count": ad["sign_count"],
    }


def verify_assertion(
    *,
    rp_id: str,
    origin: str,
    expected_challenge_b64: str,
    client_data_json: bytes,
    authenticator_data: bytes,
    signature: bytes,
    stored_x: bytes,
    stored_y: bytes,
    stored_sign_count: int,
) -> int:
    """Verify a WebAuthn assertion (login) ceremony against a previously
    stored credential's public key. Returns the new sign_count the caller
    must persist. Raises WebAuthnError on any failure, including a
    replayed/regressed signature counter (a real sign of a cloned
    authenticator — except when both counters are exactly zero, which real
    platform authenticators legitimately report since many never track one
    at all)."""
    _check_client_data(
        client_data_json,
        expected_type="webauthn.get",
        expected_challenge_b64=expected_challenge_b64,
        expected_origin=origin,
    )

    ad = parse_authenticator_data(authenticator_data)
    expected_hash = hashlib.sha256(rp_id.encode("utf-8")).digest()
    if not hmac.compare_digest(ad["rp_id_hash"], expected_hash):
        raise WebAuthnError("authenticatorData rpIdHash does not match this deployment's relying-party id")
    if not ad["up"]:
        raise WebAuthnError("the authenticator did not report the user present")
    if not ad["uv"]:
        raise WebAuthnError("the authenticator did not verify the user (no biometric/PIN)")

    signed_data = authenticator_data + hashlib.sha256(client_data_json).digest()
    if not verify_es256(stored_x, stored_y, signed_data, signature):
        raise WebAuthnError("signature does not verify against the registered public key")

    new_count = ad["sign_count"]
    if not (stored_sign_count == 0 and new_count == 0) and new_count <= stored_sign_count:
        raise WebAuthnError(
            f"signature counter did not advance ({new_count} <= {stored_sign_count}) — "
            "possible cloned authenticator or replayed assertion"
        )
    return new_count
