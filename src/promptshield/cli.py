"""Command-line interface for promptshield.

Exit codes:
  0  scan finished, verdict clean
  1  invalid arguments or unreadable input
  2  verdict suspicious
  3  verdict blocked
Evaluation and mutation commands exit 0 on success regardless of rates;
they report, they do not gate.
"""
from __future__ import annotations

import argparse
import json
import sys

from .corpus import SAMPLES
from .evaluate import evaluate_corpus, evaluate_mutations
from .scanner import scan_text

EXIT_BY_VERDICT = {"clean": 0, "suspicious": 2, "blocked": 3}


def _print_result(result: dict, as_json: bool) -> None:
    if as_json:
        json.dump(result, sys.stdout, indent=2, ensure_ascii=False)
        sys.stdout.write("\n")
        return
    print("verdict: %s (score %d)" % (result["verdict"], result["score"]))
    for note in result["notes"]:
        print("note: %s" % note)
    for f in result["findings"]:
        print("- [%s|%s|%s] %s" % (f["rule_id"], f["severity"], f["view"], f["explanation"]))
        print("    matched: %s" % f["matched"])
    if not result["findings"]:
        print("no findings")


def cmd_scan(args: argparse.Namespace) -> int:
    if args.file:
        try:
            with open(args.file, "r", encoding="utf-8") as handle:
                text = handle.read()
        except OSError as exc:
            print("error: cannot read %s: %s" % (args.file, exc), file=sys.stderr)
            return 1
    elif args.text is not None:
        text = args.text
    else:
        text = sys.stdin.read()
    if not text.strip():
        print("error: empty input", file=sys.stderr)
        return 1
    result = scan_text(text)
    _print_result(result.to_dict(), args.json)
    return EXIT_BY_VERDICT[result.verdict]


def cmd_batch(args: argparse.Namespace) -> int:
    """Scan a JSONL file: one {"id": ..., "text": ...} object per line."""
    worst = 0
    count = 0
    try:
        handle = open(args.file, "r", encoding="utf-8")
    except OSError as exc:
        print("error: cannot read %s: %s" % (args.file, exc), file=sys.stderr)
        return 1
    with handle:
        for lineno, line in enumerate(handle, 1):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
                text = record["text"]
            except (ValueError, KeyError, TypeError):
                print("error: line %d is not a JSON object with a text field" % lineno,
                      file=sys.stderr)
                return 1
            result = scan_text(text)
            count += 1
            payload = result.to_dict()
            payload["id"] = record.get("id", lineno)
            if args.json:
                json.dump(payload, sys.stdout, ensure_ascii=False)
                sys.stdout.write("\n")
            else:
                print("%s: %s (score %d, %d findings)" % (
                    payload["id"], payload["verdict"], payload["score"],
                    len(payload["findings"])))
            worst = max(worst, EXIT_BY_VERDICT[payload["verdict"]])
    if count == 0:
        print("error: no records in %s" % args.file, file=sys.stderr)
        return 1
    return worst


def cmd_evaluate(args: argparse.Namespace) -> int:
    report = evaluate_corpus()
    if args.json:
        json.dump(report, sys.stdout, indent=2, ensure_ascii=False)
        sys.stdout.write("\n")
    else:
        print("corpus: %d samples (%d attacks, %d benign)" % (
            report["samples"], report["attacks"], report["benign"]))
        print("true positives:  %d" % report["true_positives"])
        print("false positives: %d" % report["false_positives"])
        print("true negatives:  %d" % report["true_negatives"])
        print("false negatives: %d" % report["false_negatives"])
        print("precision: %.3f  recall: %.3f" % (report["precision"], report["recall"]))
        for text in report["missed_attacks"]:
            print("missed attack: %s" % text)
        for text in report["false_alarms"]:
            print("false alarm:   %s" % text)
    return 0


def cmd_mutations(args: argparse.Namespace) -> int:
    report = evaluate_mutations()
    if args.json:
        json.dump(report, sys.stdout, indent=2, ensure_ascii=False)
        sys.stdout.write("\n")
    else:
        for name, stats in report.items():
            print("%-12s detected %d/%d (%.1f%%)" % (
                name, stats["detected"], stats["attacks"],
                100.0 * stats["detection_rate"]))
            for text in stats["undetected"]:
                print("    undetected: %s" % text)
    return 0


def cmd_corpus(args: argparse.Namespace) -> int:
    for i, (text, label) in enumerate(SAMPLES, 1):
        print("%3d [%s] %s" % (i, label, text))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="promptshield",
        description="Offline prompt-injection scanner for inbound text.")
    parser.add_argument("--json", action="store_true", help="JSON output")
    sub = parser.add_subparsers(dest="command")

    p_scan = sub.add_parser("scan", help="scan one text (argument, file, or stdin)")
    p_scan.add_argument("text", nargs="?", help="text to scan; omit to read stdin")
    p_scan.add_argument("--file", help="read text from a file")
    p_scan.set_defaults(func=cmd_scan)

    p_batch = sub.add_parser("batch", help="scan a JSONL file of records")
    p_batch.add_argument("file", help='JSONL file, one {"text": ...} per line')
    p_batch.set_defaults(func=cmd_batch)

    p_eval = sub.add_parser("evaluate", help="score the bundled synthetic corpus")
    p_eval.set_defaults(func=cmd_evaluate)

    p_mut = sub.add_parser("mutations", help="detection rate under evasion mutations")
    p_mut.set_defaults(func=cmd_mutations)

    p_corpus = sub.add_parser("corpus", help="print the labelled corpus")
    p_corpus.set_defaults(func=cmd_corpus)
    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 1
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
