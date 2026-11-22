"""Text normalisation stages used before rule matching.

Every transformation is recorded so a finding can explain which view of the
text matched. Normalisation is lossy by design; the scanner always reports
against the original character offsets it can map back, or says "decoded
view" when it cannot.
"""
from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass, field
from typing import List

ZERO_WIDTH = {
    "​", "‌", "‍", "⁠", "﻿", "­", "᠎",
}

# Small confusables table. Deliberately incomplete: it covers the Latin
# lookalikes most often seen in injection samples. It is not a full
# confusable-skeleton implementation.
CONFUSABLES = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "і": "i", "ј": "j", "ѕ": "s", "һ": "h", "ո": "n", "м": "m", "т": "t",
    "к": "k", "в": "b", "д": "d", "г": "r", "з": "3", "А": "A", "В": "B",
    "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C",
    "Т": "T", "Х": "X", "0": "o", "1": "l", "3": "e", "5": "s", "7": "t",
    "@": "a", "$": "s", "!": "i", "|": "l",
}

_B64_RE = re.compile(r"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{16,}={0,2})(?![A-Za-z0-9+/=])")
_HEX_RE = re.compile(r"(?<![0-9A-Fa-f])([0-9A-Fa-f]{24,})(?![0-9A-Fa-f])")
_HTML_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.DOTALL)


@dataclass
class NormalizedText:
    """The original text plus derived views produced by normalisation."""

    original: str
    folded: str = ""            # NFKC + confusable-folded, zero-width stripped
    decoded_segments: List[str] = field(default_factory=list)  # base64/hex payloads
    html_comments: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)


def fold_confusables(text: str) -> str:
    return "".join(CONFUSABLES.get(ch, ch) for ch in text)


def strip_zero_width(text: str) -> str:
    return "".join(ch for ch in text if ch not in ZERO_WIDTH)


def _try_b64(segment: str) -> str | None:
    try:
        raw = base64.b64decode(segment, validate=True)
    except (binascii.Error, ValueError):
        return None
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    # Keep only segments that decode to mostly printable text; random binary
    # is common in benign data (hashes, tokens) and is not an injection view.
    printable = sum(1 for ch in decoded if ch.isprintable() or ch in " \t\n")
    if decoded and printable / len(decoded) >= 0.9 and len(decoded) >= 8:
        return decoded
    return None


def _try_hex(segment: str) -> str | None:
    if len(segment) % 2 != 0:
        return None
    try:
        raw = binascii.unhexlify(segment)
    except (binascii.Error, ValueError):
        return None
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    printable = sum(1 for ch in decoded if ch.isprintable() or ch in " \t\n")
    if decoded and printable / len(decoded) >= 0.9 and len(decoded) >= 8:
        return decoded
    return None


def normalize(text: str) -> NormalizedText:
    result = NormalizedText(original=text)
    nfkc = unicodedata.normalize("NFKC", text)
    if nfkc != text:
        result.notes.append("unicode NFKC normalisation changed the text")
    folded = fold_confusables(strip_zero_width(nfkc))
    if folded != nfkc:
        result.notes.append("zero-width characters or confusable lookalikes were folded")
    result.folded = folded

    for match in _B64_RE.finditer(text):
        decoded = _try_b64(match.group(1))
        if decoded is not None:
            result.decoded_segments.append(decoded)
    for match in _HEX_RE.finditer(text):
        decoded = _try_hex(match.group(1))
        if decoded is not None:
            result.decoded_segments.append(decoded)
    if result.decoded_segments:
        result.notes.append(
            "%d encoded segment(s) decoded to printable text" % len(result.decoded_segments)
        )

    result.html_comments = [m.group(1) for m in _HTML_COMMENT_RE.finditer(text)]
    if result.html_comments:
        result.notes.append(
            "%d HTML comment block(s) present" % len(result.html_comments)
        )
    return result
