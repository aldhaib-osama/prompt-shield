"""Evaluation harness: scores the corpus and mutation robustness."""
from __future__ import annotations

from typing import Dict, List

from .corpus import SAMPLES
from .mutate import MUTATIONS
from .scanner import scan_text


def evaluate_corpus() -> dict:
    tp = fp = tn = fn = 0
    misses: List[str] = []
    false_alarms: List[str] = []
    for text, label in SAMPLES:
        result = scan_text(text)
        predicted = "attack" if result.verdict in ("suspicious", "blocked") else "benign"
        if label == "attack" and predicted == "attack":
            tp += 1
        elif label == "attack":
            fn += 1
            misses.append(text[:80])
        elif predicted == "attack":
            fp += 1
            false_alarms.append(text[:80])
        else:
            tn += 1
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    return {
        "samples": len(SAMPLES),
        "attacks": tp + fn,
        "benign": tn + fp,
        "true_positives": tp,
        "false_positives": fp,
        "true_negatives": tn,
        "false_negatives": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "missed_attacks": misses,
        "false_alarms": false_alarms,
    }


def evaluate_mutations() -> Dict[str, dict]:
    attacks = [text for text, label in SAMPLES if label == "attack"]
    report: Dict[str, dict] = {}
    for name, mutate in MUTATIONS.items():
        detected = 0
        undetected: List[str] = []
        for text in attacks:
            result = scan_text(mutate(text))
            if result.verdict in ("suspicious", "blocked"):
                detected += 1
            else:
                undetected.append(text[:80])
        report[name] = {
            "attacks": len(attacks),
            "detected": detected,
            "detection_rate": round(detected / len(attacks), 4) if attacks else 0.0,
            "undetected": undetected,
        }
    return report
