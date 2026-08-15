from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .engine import scan
from .loader import LoaderError, resolve
from .model import Severity
from .report import render_text
from .rules import ALL_RULES


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="aur-manager")
    parser.add_argument("--version", action="version", version=f"aur-manager {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan_p = sub.add_parser("scan", help="scan a PKGBUILD or AUR package checkout for malicious content")
    scan_p.add_argument("path", type=Path, help="path to a PKGBUILD file or a directory containing one")
    scan_p.add_argument("--json", action="store_true", help="emit machine-readable JSON instead of text")
    scan_p.add_argument(
        "--fail-on",
        default="high",
        choices=[s.name.lower() for s in Severity],
        help="exit non-zero if the overall verdict is at or above this severity (default: high)",
    )
    scan_p.add_argument(
        "--severity-min",
        default="info",
        choices=[s.name.lower() for s in Severity],
        help="only display findings at or above this severity, independent of --fail-on (default: info)",
    )
    scan_p.add_argument(
        "--rules",
        metavar="RULE_ID,...",
        help="only run these comma-separated rule ids (default: all rules)",
    )
    scan_p.add_argument(
        "--exclude-rules",
        metavar="RULE_ID,...",
        help="skip these comma-separated rule ids",
    )
    scan_p.add_argument("--no-color", action="store_true", help="disable ANSI colors in text output")

    args = parser.parse_args(argv)

    if args.command == "scan":
        try:
            files = resolve(args.path)
        except LoaderError as e:
            print(f"error: {e}", file=sys.stderr)
            return 2

        active_rules = _select_rules(args.rules, args.exclude_rules)
        if active_rules is None:
            print("error: unknown rule id in --rules/--exclude-rules", file=sys.stderr)
            return 2

        result = scan(files, rules=active_rules)
        severity_min = Severity.from_str(args.severity_min)

        if args.json:
            print(result.to_json(severity_min=severity_min))
        else:
            print(render_text(result, use_color=not args.no_color and sys.stdout.isatty(), severity_min=severity_min))

        threshold = Severity.from_str(args.fail_on)
        return 1 if result.overall_verdict >= threshold else 0

    return 2


def _select_rules(include_csv: str | None, exclude_csv: str | None):
    known = {rule_cls.rule_id: rule_cls for rule_cls in ALL_RULES}

    if include_csv:
        ids = [r.strip() for r in include_csv.split(",") if r.strip()]
        if not ids or not all(i in known for i in ids):
            return None
        selected = [known[i] for i in ids]
    else:
        selected = list(ALL_RULES)

    if exclude_csv:
        exclude_ids = {r.strip() for r in exclude_csv.split(",") if r.strip()}
        if not exclude_ids.issubset(known.keys()):
            return None
        selected = [r for r in selected if r.rule_id not in exclude_ids]

    return selected


if __name__ == "__main__":
    sys.exit(main())
