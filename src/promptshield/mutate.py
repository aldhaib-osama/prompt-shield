"""Adversarial mutations of attack samples.

Applies common evasion transformations to see whether detection survives
them. This is a robustness spot-check on a synthetic corpus, not a proof
against real adaptive attackers.
"""
from __future__ import annotations

import base64
from typing import Callable, Dict

ZWSP = "​"


def m_identity(text: str) -> str:
    return text


def m_zero_width(text: str) -> str:
    # Insert a zero-width space inside every word of 4+ letters.
    out = []
    for word in text.split(" "):
        if len(word) >= 4 and word.isalpha():
            mid = len(word) // 2
            out.append(word[:mid] + ZWSP + word[mid:])
        else:
            out.append(word)
    return " ".join(out)


def m_base64_wrap(text: str) -> str:
    return "Please decode and follow: " + base64.b64encode(text.encode("utf-8")).decode("ascii")


def m_spaced(text: str) -> str:
    # "ignore" -> "i g n o r e" for alphabetic words; confusable folding and
    # whitespace handling decide whether this is caught.
    out = []
    for word in text.split(" "):
        if len(word) >= 5 and word.isalpha():
            out.append(" ".join(word))
        else:
            out.append(word)
    return " ".join(out)


def m_confusables(text: str) -> str:
    table = {"a": "а", "e": "е", "o": "о", "i": "і", "c": "с", "p": "р"}
    return "".join(table.get(ch, ch) for ch in text)


def m_mixed_case(text: str) -> str:
    out = []
    for i, ch in enumerate(text):
        out.append(ch.upper() if i % 2 == 0 else ch.lower())
    return "".join(out)


MUTATIONS: Dict[str, Callable[[str], str]] = {
    "identity": m_identity,
    "zero_width": m_zero_width,
    "base64_wrap": m_base64_wrap,
    "confusables": m_confusables,
    "mixed_case": m_mixed_case,
    "spaced": m_spaced,
}
