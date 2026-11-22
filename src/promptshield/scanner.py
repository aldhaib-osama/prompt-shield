"""Scanner: runs rules over normalised views and produces a verdict.

Scoring model (deliberately simple, stated in the README):
- each finding contributes its severity weight (high=3, medium=2, low=1)
- findings on a decoded or hidden view add +1 (someone hid it)
- total >= 4 -> "blocked", 2..3 -> "suspicious", else "clean"

The threshold is a triage default, not a tuned security boundary. The
evaluation harness reports how the default behaves on the synthetic corpus.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from .normalize import NormalizedText, normalize
from .rules import RULES, Finding

MAX_MATCHED_LEN = 120

VERDICTS = ("clean", "suspicious", "blocked")


@dataclass
class ScanResult:
    verdict: str
    score: int
    findings: List[Finding] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "score": self.score,
            "notes": list(self.notes),
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "category": f.category,
                    "severity": f.severity,
                    "view": f.view,
                    "matched": f.matched,
                    "explanation": f.explanation,
                }
                for f in self.findings
            ],
        }


def _view_weight(view: str) -> int:
    return 1 if view in ("decoded", "html-comment") else 0


def _scan_view(view_name: str, text: str, findings: List[Finding]) -> None:
    if not text:
        return
    for rule in RULES:
        for match in rule.pattern.finditer(text):
            matched = match.group(0).replace("\n", " ")
            if len(matched) > MAX_MATCHED_LEN:
                matched = matched[:MAX_MATCHED_LEN] + "..."
            findings.append(Finding(
                rule_id=rule.rule_id,
                category=rule.category,
                severity=rule.severity,
                view=view_name,
                matched=matched,
                explanation=rule.explanation,
            ))


def scan_text(text: str, normalized: NormalizedText | None = None) -> ScanResult:
    norm = normalized if normalized is not None else normalize(text)
    findings: List[Finding] = []

    _scan_view("original", norm.original, findings)
    if norm.folded != norm.original:
        _scan_view("folded", norm.folded, findings)
    for segment in norm.decoded_segments:
        _scan_view("decoded", segment, findings)
    for comment in norm.html_comments:
        _scan_view("html-comment", comment, findings)

    # A finding on the folded view duplicates the original-view finding when
    # the only change was folding; keep both but note it, because the folded
    # match is what proves evasion was attempted.
    score = 0
    for f in findings:
        score += {"high": 3, "medium": 2, "low": 1}[f.severity]
        score += _view_weight(f.view)

    if score >= 4:
        verdict = "blocked"
    elif score >= 2:
        verdict = "suspicious"
    else:
        verdict = "clean"
    return ScanResult(verdict=verdict, score=score, findings=findings, notes=norm.notes)
