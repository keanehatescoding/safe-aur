from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .engine import scan
from .loader import LoaderError, resolve
from .model import Severity
from .report import render_text


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
    scan_p.add_argument("--no-color", action="store_true", help="disable ANSI colors in text output")

    args = parser.parse_args(argv)

    if args.command == "scan":
        try:
            files = resolve(args.path)
        except LoaderError as e:
            print(f"error: {e}", file=sys.stderr)
            return 2

        result = scan(files)

        if args.json:
            print(result.to_json())
        else:
            print(render_text(result, use_color=not args.no_color and sys.stdout.isatty()))

        threshold = Severity.from_str(args.fail_on)
        return 1 if result.overall_verdict >= threshold else 0

    return 2


if __name__ == "__main__":
    sys.exit(main())
