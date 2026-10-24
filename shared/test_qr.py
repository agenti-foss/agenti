#!/usr/bin/env python3
"""test_qr.py — the stdlib QR encoder (shared/qr.py).

No framework, no root, no vault, no dependencies:

    python3 shared/test_qr.py

WHAT IT PINS DOWN. A QR code that does not scan fails silently: the page
renders a plausible square, the person's authenticator app just never
locks on, and they type the secret by hand or give up. So the fixtures
below are known-answer tests: each SHA-256 is of a symbol that, when this
file was written, was (a) decoded back to the same text by an independent
decoder (OpenCV's QRCodeDetector) and (b) bit-for-bit identical to the
output of an independent encoder (segno 1.x) for the same version, level
and mask — with segno's own padding aligned to ISO/IEC 18004 7.4.10, since
segno pads a whole extra codeword when the stream already sits on a byte
boundary. The version-29 fixture is verified by (b) only: OpenCV's detector
gives up on symbols that large. A change that alters ANY module of these
symbols is a regression until it has been re-verified the same way.

The structural checks after them explain a failure rather than just
reporting one: finder patterns, timing, the dark module, format-information
BCH validity, and the byte-mode header the decoder reads first.
"""
import hashlib
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import qr  # noqa: E402

PASS = FAIL = 0


def check(label, got, want):
    global PASS, FAIL
    if got == want:
        PASS += 1; print(f"  [ OK ] {label}")
    else:
        FAIL += 1; print(f"  [FAIL] {label}\n         got  {got!r}\n         want {want!r}")


def section(t): print(f"\n=== {t} ===")


def packed(m): return "".join("".join("1" if v else "0" for v in row) for row in m)
def digest(m): return hashlib.sha256(packed(m).encode()).hexdigest()


def expand(text):
    """'A*300' -> 'A' * 300; anything else is literal."""
    if "*" in text and text.split("*", 1)[1].isdigit():
        ch, n = text.split("*", 1)
        return ch * int(n)
    return text


# (text, ecl, expected version, expected auto-selected mask, sha256 of the modules)
FIXTURES = [
    ('hello', 'M', 1, 0, '99ccedcf0d82e92a63894c8b42e405a3ac50eafa33ee2ce68fa895813fdcb386'),
    ('hello', 'L', 1, 7, 'd591b9a8e941c643b54e2fa15b632976d6484ba5875f37ef715544b1e96a7baf'),
    ('hello', 'Q', 1, 0, 'd001c630fe29ce7f0a8afa6e00f9bfeb0fe34acb5e836944c721a070a5c0572c'),
    ('hello', 'H', 1, 6, '543aec6acc4e37fac7c09aba83f0678cf562adfd4ec0816648eec7ccf39e4dc6'),
    ('otpauth://totp/Agenti:pixel?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=Agenti&algorithm=SHA1&digits=6&period=30', 'M', 7, 4, 'ff219029d781c1de1ccb98b353d0992b7d3027b198fb1046e80d6b0716831e7b'),
    ('A*300', 'L', 11, 3, 'f63f080f5a3c129cc21b7b68916abf056d9dc448d9c082758ff24af28c675cdc'),
    ('unicode: ünïcödé ✓', 'Q', 3, 6, '42bf9e6320cf05f17e10f64fb0163eb8e6cadbb2ddd905de318969da1501583e'),
    ('x*1200', 'M', 29, 0, '98f24e3303dc979c8a802b77da01a74959851d3f71baee5d65ed5063a4af3ef5'),
]

section("known-answer fixtures (decoder-verified when written)")
for text, ecl, ver, mask, sha in FIXTURES:
    m = qr.encode(expand(text), ecl)
    label = f"{ecl} v{ver} {text[:32]!r}"
    check(f"{label}: version", (len(m) - 17) // 4, ver)
    check(f"{label}: modules unchanged", digest(m), sha)
    check(f"{label}: forced mask {mask} reproduces the auto choice", qr.encode(expand(text), ecl, mask=mask) == m, True)

section("structure")
m = qr.encode("hello", "M")
size = len(m)
check("size is 4v+17", size, 21)
check("square", all(len(r) == size for r in m), True)
# Finder pattern top-left: dark ring of 7, light ring of 5, dark 3x3 core.
finder = [[m[r][c] for c in range(7)] for r in range(7)]
expect = [[True] * 7,
          [True, False, False, False, False, False, True],
          [True, False, True, True, True, False, True],
          [True, False, True, True, True, False, True],
          [True, False, True, True, True, False, True],
          [True, False, False, False, False, False, True],
          [True] * 7]
check("top-left finder pattern", finder, expect)
check("top-right finder pattern", [[m[r][size - 7 + c] for c in range(7)] for r in range(7)], expect)
check("bottom-left finder pattern", [[m[size - 7 + r][c] for c in range(7)] for r in range(7)], expect)
check("separator below top-left finder is light", any(m[7][c] for c in range(8)), False)
check("timing row alternates", [m[6][c] for c in range(8, 13)], [True, False, True, False, True])
check("timing column alternates", [m[r][6] for r in range(8, 13)], [True, False, True, False, True])
check("dark module at (size-8, 8)", m[size - 8][8], True)


def read_format(m):
    """The 15 format bits around the top-left finder, as a decoder reads
    them; returns (ecl_bits, mask) after checking the BCH code."""
    size = len(m)
    bits = 0
    for i in range(6):
        bits |= m[i][8] << i
    bits |= m[7][8] << 6
    bits |= m[8][8] << 7
    bits |= m[8][7] << 8
    for i in range(9, 15):
        bits |= m[8][14 - i] << i
    data = (bits ^ 0x5412) >> 10
    rem = data
    for _ in range(10):
        rem = (rem << 1) ^ ((rem >> 9) * 0x537)
    check("format information passes its BCH check", (data << 10 | rem) ^ 0x5412, bits)
    return data >> 3, data & 7


for ecl, want in (("L", 1), ("M", 0), ("Q", 3), ("H", 2)):
    e, k = read_format(qr.encode("hello", ecl, mask=5))
    check(f"format bits carry level {ecl}", e, want)
    check(f"format bits carry mask 5 ({ecl})", k, 5)

# The second copy of the format bits must agree with the first.
mm = qr.encode("hello", "M", mask=3)
copy1 = [mm[i][8] for i in range(6)] + [mm[7][8], mm[8][8], mm[8][7]] + [mm[8][14 - i] for i in range(9, 15)]
copy2 = [mm[8][size - 1 - i] for i in range(8)] + [mm[size - 15 + i][8] for i in range(8, 15)]
check("second copy of format bits matches the first", copy1, copy2)

section("version selection and capacity")
check("1 byte -> version 1", (len(qr.encode("a")) - 17) // 4, 1)
check("14 bytes fit version 1 at M", (len(qr.encode("a" * 14, "M")) - 17) // 4, 1)
check("15 bytes need version 2 at M", (len(qr.encode("a" * 15, "M")) - 17) // 4, 2)
check("min_version is honoured", (len(qr.encode("a", min_version=5)) - 17) // 4, 5)
check("version 40 at L holds 2953 bytes", (len(qr.encode("a" * 2953, "L")) - 17) // 4, 40)
try:
    qr.encode("a" * 2954, "L"); check("2954 bytes at L refused", False, True)
except qr.QRError as e:
    check("2954 bytes at L refused", "version 40" in str(e), True)
try:
    qr.encode(""); check("empty input refused", False, True)
except qr.QRError:
    check("empty input refused", True, True)
try:
    qr.encode("x", "X"); check("bad level refused", False, True)
except qr.QRError:
    check("bad level refused", True, True)
try:
    qr.encode("x", mask=8); check("bad mask refused", False, True)
except qr.QRError:
    check("bad mask refused", True, True)
check("bytes and their utf-8 str encode identically", qr.encode("ünï"), qr.encode("ünï".encode()))
check("deterministic", qr.encode("determinism"), qr.encode("determinism"))

section("renderers")
svg = qr.to_svg(m)
root = ET.fromstring(svg)
check("svg is well-formed xml with the svg root", root.tag, "{http://www.w3.org/2000/svg}svg")
check("svg has a quiet zone of 4 modules (scale 4)", root.get("width"), str((21 + 8) * 4))
check("svg contains no text or script", any(el.tag.endswith(("text", "script")) for el in root.iter()), False)
path = root.find("{http://www.w3.org/2000/svg}path")
check("svg draws dark modules as one path", path is not None and path.get("d", "").startswith("M"), True)
# Every dark module is covered exactly once by the run rectangles.
rects = 0
for r, row in enumerate(m):
    c = 0
    while c < size:
        if row[c]:
            rects += 1
            while c < size and row[c]:
                c += 1
        else:
            c += 1
check("one rectangle per horizontal run of dark modules", path.get("d", "").count("M"), rects)
txt = qr.to_text(m, border=2)
lines = txt.split("\n")
check("text rendering: two module rows per line, quiet zone included", len(lines), (21 + 4 + 1) // 2)
check("text rendering: full width", all(len(l) == 21 + 4 for l in lines), True)
check("text rendering: quiet zone is blank", lines[0].strip(), "")
check("text rendering uses only block glyphs", set("".join(lines)) <= set(" █▀▄"), True)

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
