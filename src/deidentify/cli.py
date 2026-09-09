from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .engine import build, copilot_request, import_review, initial_fingerprint, load_json, scan, validate_fingerprint, write_json


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="deidentify", description="Create reviewed deidentified text bundles locally.")
    commands = root.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init", help="Create an empty organisation fingerprint JSON file.")
    init.add_argument("fingerprint", type=Path)
    scan_cmd = commands.add_parser("scan", help="Discover local candidate identifiers.")
    scan_cmd.add_argument("source", type=Path)
    scan_cmd.add_argument("--report", type=Path, required=True)
    scan_cmd.add_argument("--copilot-request", type=Path, required=True)
    review = commands.add_parser("import-review", help="Import unapproved entries proposed by internal Copilot.")
    review.add_argument("fingerprint", type=Path)
    review.add_argument("review", type=Path)
    build_cmd = commands.add_parser("build", help="Build a fresh deidentified tarball from approved entries.")
    build_cmd.add_argument("source", type=Path)
    build_cmd.add_argument("fingerprint", type=Path)
    build_cmd.add_argument("output", type=Path)
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "init":
            if args.fingerprint.exists():
                raise ValueError(f"Refusing to overwrite existing file: {args.fingerprint}")
            write_json(args.fingerprint, initial_fingerprint())
            print(f"Created fingerprint: {args.fingerprint}")
        elif args.command == "scan":
            report = scan(args.source)
            write_json(args.report, report)
            write_json(args.copilot_request, copilot_request(report))
            print(f"Scanned {report['source']['scanned_file_count']} text files; found {len(report['candidate_inventory'])} candidate groups.")
            print(f"Report: {args.report}")
            print(f"Internal Copilot request: {args.copilot_request}")
        elif args.command == "import-review":
            fingerprint = load_json(args.fingerprint)
            review = load_json(args.review)
            fingerprint, added, updated = import_review(fingerprint, review)
            write_json(args.fingerprint, fingerprint)
            print(f"Imported review: {added} candidate entries added, {updated} entries updated.")
            print("Review the fingerprint and explicitly set vetted entries to status: approved before building.")
        elif args.command == "build":
            fingerprint = load_json(args.fingerprint)
            validate_fingerprint(fingerprint)
            manifest = build(args.source, fingerprint, args.output)
            print(f"Created archive: {args.output}")
            print(f"Manifest: {args.output.with_suffix(args.output.suffix + '.manifest.json')}")
            print(f"Applied {manifest['fingerprint']['entries_applied']} approved fingerprint entries.")
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
