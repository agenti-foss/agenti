#!/usr/bin/env python3
"""
qr.py — a QR Code encoder in the standard library, for 2FA enrolment.

WHY THIS EXISTS RATHER THAN A DEPENDENCY: the one thing this project renders
as a QR code is an otpauth:// URI carrying a TOTP secret — a credential. It
is generated on the host (shared/iam.py), shown once, and never stored in
plaintext. Rendering it should not add a third-party JavaScript file to the
GUI (which would be the first anywhere in it) or a PyPI package to the API's
venv on the strength of "everyone uses it". This module is ~350 lines of
ISO/IEC 18004 with no dependencies, and shared/test_qr.py pins its output
against symbols that were decoded by an independent decoder (OpenCV) and
compared bit-for-bit against an independent encoder (segno) when it was
written — see that file for the fixtures.

WHAT IT DOES: byte-mode encoding only (an otpauth URI is arbitrary text),
every version 1–40, every error-correction level, automatic mask selection
by the standard's penalty rules, and two renderers: an SVG string for the
browser (data: URI in an <img>, so nothing is ever injected as markup) and
a half-block text rendering for a terminal (`agenti admin user
enroll-2fa`), so the root CLI path shows a scannable code too.

    >>> import qr
    >>> m = qr.encode("otpauth://totp/Agenti:alice?secret=...")
    >>> svg = qr.to_svg(m)
    >>> print(qr.to_text(m))

The implementation follows the reference structure of Project Nayuki's
QR-Code-generator (MIT), re-derived here rather than copied, because that
is the shape of the standard itself: segment → codewords → error correction
→ interleave → placement → mask → format bits.
"""
from __future__ import annotations

from collections import deque

__all__ = ["encode", "to_svg", "to_text", "QRError", "ECL_LEVELS"]

ECL_LEVELS = ("L", "M", "Q", "H")
_ECL_INDEX = {"L": 0, "M": 1, "Q": 2, "H": 3}
_ECL_FORMAT_BITS = {"L": 1, "M": 0, "Q": 3, "H": 2}

MIN_VERSION, MAX_VERSION = 1, 40


class QRError(ValueError):
    pass


# Number of error-correction codewords per block, indexed [ecl][version];
# index 0 is unused. Table 9 of ISO/IEC 18004, transcribed.
_ECC_CODEWORDS_PER_BLOCK = (
    (-1, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30),  # L
    (-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28),  # M
    (-1, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26, 30, 28, 30, 30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30),  # Q
    (-1, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26, 28, 30, 24, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30),  # H
)

# Number of error-correction blocks, same indexing.
_NUM_ERROR_CORRECTION_BLOCKS = (
    (-1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25),  # L
    (-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49),  # M
    (-1, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16, 12, 17, 16, 18, 21, 20, 23, 23, 25, 27, 29, 34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68),  # Q
    (-1, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25, 25, 34, 30, 32, 35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81),  # H
)

_PENALTY_N1, _PENALTY_N2, _PENALTY_N3, _PENALTY_N4 = 3, 3, 40, 10


# ---------------------------------------------------------------------------
# Capacity arithmetic
# ---------------------------------------------------------------------------
def _num_raw_data_modules(ver: int) -> int:
    """Data modules available after every function pattern is placed."""
    result = (16 * ver + 128) * ver + 64
    if ver >= 2:
        numalign = ver // 7 + 2
        result -= (25 * numalign - 10) * numalign - 55
        if ver >= 7:
            result -= 36
    return result


def _num_data_codewords(ver: int, ecl: str) -> int:
    e = _ECL_INDEX[ecl]
    return (_num_raw_data_modules(ver) // 8
            - _ECC_CODEWORDS_PER_BLOCK[e][ver] * _NUM_ERROR_CORRECTION_BLOCKS[e][ver])


def _byte_mode_bits(nbytes: int, ver: int) -> int:
    count_bits = 8 if ver <= 9 else 16
    return 4 + count_bits + 8 * nbytes


def _choose_version(nbytes: int, ecl: str, min_version: int) -> int:
    for ver in range(max(MIN_VERSION, min_version), MAX_VERSION + 1):
        if _byte_mode_bits(nbytes, ver) <= _num_data_codewords(ver, ecl) * 8:
            return ver
    raise QRError(f"{nbytes} bytes do not fit a QR code at error-correction "
                  f"level {ecl} (the maximum is version 40)")


# ---------------------------------------------------------------------------
# Reed–Solomon over GF(2^8) with the QR polynomial 0x11D
# ---------------------------------------------------------------------------
def _gf_mul(x: int, y: int) -> int:
    z = 0
    for i in reversed(range(8)):
        z = (z << 1) ^ ((z >> 7) * 0x11D)
        z ^= ((y >> i) & 1) * x
    return z


def _rs_divisor(degree: int) -> list[int]:
    result = [0] * (degree - 1) + [1]
    root = 1
    for _ in range(degree):
        for j in range(degree):
            result[j] = _gf_mul(result[j], root)
            if j + 1 < degree:
                result[j] ^= result[j + 1]
        root = _gf_mul(root, 2)
    return result


def _rs_remainder(data: list[int], divisor: list[int]) -> list[int]:
    result = [0] * len(divisor)
    for b in data:
        factor = b ^ result.pop(0)
        result.append(0)
        for i, coef in enumerate(divisor):
            result[i] ^= _gf_mul(coef, factor)
    return result


def _add_ecc_and_interleave(data: list[int], ver: int, ecl: str) -> list[int]:
    e = _ECL_INDEX[ecl]
    numblocks = _NUM_ERROR_CORRECTION_BLOCKS[e][ver]
    blockecclen = _ECC_CODEWORDS_PER_BLOCK[e][ver]
    rawcodewords = _num_raw_data_modules(ver) // 8
    numshortblocks = numblocks - rawcodewords % numblocks
    shortblocklen = rawcodewords // numblocks

    blocks: list[list[int]] = []
    rsdiv = _rs_divisor(blockecclen)
    k = 0
    for i in range(numblocks):
        datlen = shortblocklen - blockecclen + (0 if i < numshortblocks else 1)
        dat = data[k:k + datlen]
        k += datlen
        ecc = _rs_remainder(dat, rsdiv)
        if i < numshortblocks:
            dat = dat + [0]          # placeholder, skipped below
        blocks.append(dat + ecc)
    result: list[int] = []
    for i in range(len(blocks[0])):
        for j, blk in enumerate(blocks):
            if i != shortblocklen - blockecclen or j >= numshortblocks:
                result.append(blk[i])
    return result


# ---------------------------------------------------------------------------
# The symbol
# ---------------------------------------------------------------------------
class _Symbol:
    def __init__(self, ver: int, ecl: str):
        self.ver = ver
        self.ecl = ecl
        self.size = ver * 4 + 17
        self.modules = [[False] * self.size for _ in range(self.size)]
        self.isfunction = [[False] * self.size for _ in range(self.size)]

    # -- function patterns -----------------------------------------------
    def _set_function(self, row: int, col: int, dark: bool) -> None:
        self.modules[row][col] = dark
        self.isfunction[row][col] = True

    def _draw_finder(self, row: int, col: int) -> None:
        for dy in range(-4, 5):
            for dx in range(-4, 5):
                r, c = row + dy, col + dx
                if 0 <= r < self.size and 0 <= c < self.size:
                    dist = max(abs(dx), abs(dy))
                    self._set_function(r, c, dist not in (2, 4))

    def _draw_alignment(self, row: int, col: int) -> None:
        for dy in range(-2, 3):
            for dx in range(-2, 3):
                self._set_function(row + dy, col + dx, max(abs(dx), abs(dy)) != 1)

    def _alignment_positions(self) -> list[int]:
        if self.ver == 1:
            return []
        numalign = self.ver // 7 + 2
        step = (self.ver * 8 + numalign * 3 + 5) // (numalign * 4 - 4) * 2
        result = [6]
        pos = self.size - 7
        for _ in range(numalign - 1):
            result.insert(1, pos)
            pos -= step
        return result

    def draw_function_patterns(self) -> None:
        for i in range(self.size):
            self._set_function(6, i, i % 2 == 0)
            self._set_function(i, 6, i % 2 == 0)
        self._draw_finder(3, 3)
        self._draw_finder(3, self.size - 4)
        self._draw_finder(self.size - 4, 3)
        align = self._alignment_positions()
        n = len(align)
        for i in range(n):
            for j in range(n):
                if (i == 0 and j == 0) or (i == 0 and j == n - 1) or (i == n - 1 and j == 0):
                    continue
                self._draw_alignment(align[i], align[j])
        self.draw_format_bits(0)   # dummy mask so the modules are reserved
        self._draw_version()

    def draw_format_bits(self, mask: int) -> None:
        data = _ECL_FORMAT_BITS[self.ecl] << 3 | mask
        rem = data
        for _ in range(10):
            rem = (rem << 1) ^ ((rem >> 9) * 0x537)
        bits = (data << 10 | rem) ^ 0x5412
        bit = lambda i: (bits >> i) & 1 == 1  # noqa: E731
        # Around the top-left finder: (row, col)
        for i in range(6):
            self._set_function(i, 8, bit(i))
        self._set_function(7, 8, bit(6))
        self._set_function(8, 8, bit(7))
        self._set_function(8, 7, bit(8))
        for i in range(9, 15):
            self._set_function(8, 14 - i, bit(i))
        # Second copy: below the top-right finder and right of the bottom-left.
        for i in range(8):
            self._set_function(8, self.size - 1 - i, bit(i))
        for i in range(8, 15):
            self._set_function(self.size - 15 + i, 8, bit(i))
        self._set_function(self.size - 8, 8, True)   # the always-dark module

    def _draw_version(self) -> None:
        if self.ver < 7:
            return
        rem = self.ver
        for _ in range(12):
            rem = (rem << 1) ^ ((rem >> 11) * 0x1F25)
        bits = self.ver << 12 | rem
        for i in range(18):
            dark = (bits >> i) & 1 == 1
            a = self.size - 11 + i % 3
            b = i // 3
            self._set_function(b, a, dark)   # row b, col a
            self._set_function(a, b, dark)   # row a, col b

    # -- data ------------------------------------------------------------
    def draw_codewords(self, data: list[int]) -> None:
        i = 0
        total = len(data) * 8
        right = self.size - 1
        while right >= 1:
            if right == 6:
                right = 5
            for vert in range(self.size):
                for j in range(2):
                    col = right - j
                    upward = ((right + 1) & 2) == 0
                    row = self.size - 1 - vert if upward else vert
                    if not self.isfunction[row][col] and i < total:
                        self.modules[row][col] = (data[i >> 3] >> (7 - (i & 7))) & 1 == 1
                        i += 1
            right -= 2

    def apply_mask(self, mask: int) -> None:
        f = _MASKS[mask]
        for row in range(self.size):
            for col in range(self.size):
                if not self.isfunction[row][col] and f(col, row):
                    self.modules[row][col] = not self.modules[row][col]

    # -- penalty ---------------------------------------------------------
    def penalty(self) -> int:
        size, modules = self.size, self.modules
        result = 0
        for y in range(size):
            result += self._line_penalty(modules[y])
        for x in range(size):
            result += self._line_penalty([modules[y][x] for y in range(size)])
        for y in range(size - 1):
            for x in range(size - 1):
                if modules[y][x] == modules[y][x + 1] == modules[y + 1][x] == modules[y + 1][x + 1]:
                    result += _PENALTY_N2
        dark = sum(row.count(True) for row in modules)
        total = size * size
        k = (abs(dark * 20 - total * 10) + total - 1) // total - 1
        result += k * _PENALTY_N4
        return result

    def _line_penalty(self, line: list[bool]) -> int:
        size = self.size
        result = 0
        runcolor = False
        runlen = 0
        history: deque[int] = deque([0] * 7)

        def add_history(length: int) -> None:
            if history[0] == 0:
                length += size      # light border before the first run
            history.appendleft(length)
            history.pop()

        def count_patterns() -> int:
            n = history[1]
            core = (n > 0 and history[2] == history[4] == history[5] == n
                    and history[3] == n * 3)
            return ((1 if core and history[0] >= n * 4 and history[6] >= n else 0)
                    + (1 if core and history[6] >= n * 4 and history[0] >= n else 0))

        for v in line:
            if v == runcolor:
                runlen += 1
                if runlen == 5:
                    result += _PENALTY_N1
                elif runlen > 5:
                    result += 1
            else:
                add_history(runlen)
                if not runcolor:
                    result += count_patterns() * _PENALTY_N3
                runcolor = v
                runlen = 1
        if runcolor:
            add_history(runlen)
            runlen = 0
        runlen += size              # light border after the last run
        add_history(runlen)
        result += count_patterns() * _PENALTY_N3
        return result


_MASKS = (
    lambda x, y: (x + y) % 2 == 0,
    lambda x, y: y % 2 == 0,
    lambda x, y: x % 3 == 0,
    lambda x, y: (x + y) % 3 == 0,
    lambda x, y: (x // 3 + y // 2) % 2 == 0,
    lambda x, y: x * y % 2 + x * y % 3 == 0,
    lambda x, y: (x * y % 2 + x * y % 3) % 2 == 0,
    lambda x, y: ((x + y) % 2 + x * y % 3) % 2 == 0,
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def encode(text: str | bytes, ecl: str = "M", *, min_version: int = 1,
           mask: int | None = None) -> list[list[bool]]:
    """Encode `text` (UTF-8 if str) in byte mode. Returns the module matrix
    as rows of booleans (True = dark), WITHOUT a quiet zone — the renderers
    add the four-module border the standard requires.

    `ecl` is the error-correction level; M (15%) is the usual choice for a
    screen-displayed code. `mask` forces a mask pattern (0–7) and exists for
    the test suite, which compares against an independent encoder mask by
    mask; leave it None to select the best by the standard's penalty rules."""
    if ecl not in _ECL_INDEX:
        raise QRError(f"error-correction level must be one of {ECL_LEVELS}, not {ecl!r}")
    if mask is not None and not 0 <= mask <= 7:
        raise QRError("mask must be 0..7")
    data = text.encode("utf-8") if isinstance(text, str) else bytes(text)
    if not data:
        raise QRError("nothing to encode")
    ver = _choose_version(len(data), ecl, min_version)

    # Segment: mode 0100, character count, the bytes.
    bits: list[int] = []

    def put(value: int, n: int) -> None:
        bits.extend((value >> i) & 1 for i in reversed(range(n)))

    put(4, 4)
    put(len(data), 8 if ver <= 9 else 16)
    for b in data:
        put(b, 8)
    capacity = _num_data_codewords(ver, ecl) * 8
    assert len(bits) <= capacity
    put(0, min(4, capacity - len(bits)))                 # terminator
    put(0, (8 - len(bits) % 8) % 8)                      # to a byte boundary
    pad = 0xEC
    while len(bits) < capacity:                          # pad codewords
        put(pad, 8)
        pad ^= 0xEC ^ 0x11
    codewords = [0] * (len(bits) // 8)
    for i, b in enumerate(bits):
        codewords[i >> 3] |= b << (7 - (i & 7))

    sym = _Symbol(ver, ecl)
    sym.draw_function_patterns()
    sym.draw_codewords(_add_ecc_and_interleave(codewords, ver, ecl))
    if mask is None:
        best, best_penalty = 0, None
        for m in range(8):
            sym.apply_mask(m)
            sym.draw_format_bits(m)
            p = sym.penalty()
            if best_penalty is None or p < best_penalty:
                best, best_penalty = m, p
            sym.apply_mask(m)          # XOR is its own inverse
        mask = best
    sym.apply_mask(mask)
    sym.draw_format_bits(mask)
    return sym.modules


def to_svg(modules: list[list[bool]], *, scale: int = 4, border: int = 4,
           dark: str = "#000", light: str = "#fff") -> str:
    """A self-contained SVG with the standard four-module quiet zone. One
    <path> for all dark modules, so the document stays small (a version-7
    code is about 3 KB) and contains no text at all — safe to hand a browser
    as a data: URI in an <img>."""
    size = len(modules)
    dim = (size + 2 * border) * scale
    parts = []
    for r, row in enumerate(modules):
        c = 0
        while c < size:                       # one rectangle per horizontal run
            if row[c]:
                start = c
                while c < size and row[c]:
                    c += 1
                w = (c - start) * scale
                parts.append(f"M{(start + border) * scale},{(r + border) * scale}h{w}v{scale}h-{w}z")
            else:
                c += 1
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{dim}" height="{dim}" '
            f'viewBox="0 0 {dim} {dim}" shape-rendering="crispEdges">'
            f'<rect width="100%" height="100%" fill="{light}"/>'
            f'<path d="{"".join(parts)}" fill="{dark}"/></svg>')


def to_text(modules: list[list[bool]], *, border: int = 2) -> str:
    """Two module rows per text line using half-block characters, dark on
    the terminal's own background — readable on a light or a dark terminal
    and scannable at normal font sizes. The quiet zone is drawn explicitly
    (as light) because a scanner needs it, and a terminal's margin is not
    guaranteed to provide one."""
    size = len(modules)
    grid = [[False] * (size + 2 * border) for _ in range(size + 2 * border)]
    for r in range(size):
        for c in range(size):
            grid[r + border][c + border] = modules[r][c]
    if len(grid) % 2:
        grid.append([False] * len(grid[0]))
    lines = []
    for r in range(0, len(grid), 2):
        top, bottom = grid[r], grid[r + 1]
        line = []
        for c in range(len(top)):
            t, b = top[c], bottom[c]
            line.append("█" if t and b else "▀" if t else "▄" if b else " ")
        lines.append("".join(line))
    return "\n".join(lines)


if __name__ == "__main__":  # pragma: no cover
    import sys
    m = encode(" ".join(sys.argv[1:]) or "hello")
    print(to_text(m))
