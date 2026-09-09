from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

from .engine import ai_review_request, audit_request, build, import_review, initial_fingerprint, load_json, preview, reidentify, require_outside_source, scan, validate_fingerprint, write_json


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="deidentify", description="Create reviewed deidentified text bundles locally.")
    commands = root.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init", help="Create an empty organisation fingerprint JSON file.")
    init.add_argument("fingerprint", type=Path)
    scan_cmd = commands.add_parser("scan", help="Discover local candidate identifiers.")
    scan_cmd.add_argument("source", type=Path)
    scan_cmd.add_argument("--report", type=Path, required=True)
    scan_cmd.add_argument("--copilot-request", "--ai-review-request", dest="ai_review_request", type=Path, required=True)
    review = commands.add_parser("import-review", help="Import unapproved entries proposed by sanctioned internal AI.")
    review.add_argument("fingerprint", type=Path)
    review.add_argument("review", type=Path)
    build_cmd = commands.add_parser("build", help="Build a fresh deidentified tarball from approved entries.")
    build_cmd.add_argument("source", type=Path)
    build_cmd.add_argument("fingerprint", type=Path)
    build_cmd.add_argument("output", type=Path)
    build_cmd.add_argument("--unsupported-policy", choices=("reject", "exclude"), default="reject")
    build_cmd.add_argument("--audit-findings", type=Path)
    build_cmd.add_argument("--fail-on-ai-findings", action="store_true")
    build_cmd.add_argument("--mapping-vault", type=Path, help="Write an encrypted token-to-canonical mapping outside the source tree.")
    preview_cmd = commands.add_parser("preview", help="Show planned path/content changes without writing an archive.")
    preview_cmd.add_argument("source", type=Path)
    preview_cmd.add_argument("fingerprint", type=Path)
    preview_cmd.add_argument("--output", type=Path, required=True)
    preview_cmd.add_argument("--unsupported-policy", choices=("reject", "exclude"), default="reject")
    audit_cmd = commands.add_parser("audit-request", help="Create a bounded adversarial audit request from staged content.")
    audit_cmd.add_argument("source", type=Path)
    audit_cmd.add_argument("fingerprint", type=Path)
    audit_cmd.add_argument("--output", type=Path, required=True)
    audit_cmd.add_argument("--unsupported-policy", choices=("reject", "exclude"), default="reject")
    reidentify_cmd = commands.add_parser("reidentify", help="Restore canonical values in a returned tarball using an encrypted mapping vault.")
    reidentify_cmd.add_argument("returned_archive", type=Path)
    reidentify_cmd.add_argument("mapping_vault", type=Path)
    reidentify_cmd.add_argument("output", type=Path)
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
            write_json(args.ai_review_request, ai_review_request(report))
            print(f"Scanned {report['source']['scanned_file_count']} text files; found {len(report['candidate_inventory'])} candidate groups.")
            print(f"Report: {args.report}")
            print(f"Internal-AI review request: {args.ai_review_request}")
        elif args.command == "import-review":
            fingerprint = load_json(args.fingerprint)
            review = load_json(args.review)
            fingerprint, added, updated = import_review(fingerprint, review)
            write_json(args.fingerprint, fingerprint)
            print(f"Imported review: {added} candidate entries added, {updated} entries updated.")
            print("Review the fingerprint and explicitly set vetted entries to status: approved before building.")
        elif args.command == "build":
            require_outside_source(args.source, args.fingerprint, "Fingerprint")
            if args.audit_findings:
                require_outside_source(args.source, args.audit_findings, "Audit findings")
            if args.mapping_vault:
                require_outside_source(args.source, args.mapping_vault, "Mapping vault")
            fingerprint = load_json(args.fingerprint)
            validate_fingerprint(fingerprint)
            audit = load_json(args.audit_findings) if args.audit_findings else None
            vault_passphrase = None
            if args.mapping_vault:
                vault_passphrase = getpass.getpass("New mapping-vault passphrase: ")
                if vault_passphrase != getpass.getpass("Confirm mapping-vault passphrase: "):
                    raise ValueError("Mapping-vault passphrases do not match")
            manifest = build(args.source, fingerprint, args.output, args.unsupported_policy, audit, args.fail_on_ai_findings, args.mapping_vault, vault_passphrase)
            print(f"Created archive: {args.output}")
            print(f"Manifest: {args.output.with_suffix(args.output.suffix + '.manifest.json')}")
            print(f"Applied {manifest['fingerprint']['entries_applied']} approved fingerprint entries.")
            if manifest["omitted_files"]:
                print(f"Warning: {len(manifest['omitted_files'])} files/directories were omitted by policy.")
            if args.mapping_vault:
                print(f"Encrypted mapping vault: {args.mapping_vault}")
        elif args.command == "preview":
            fingerprint = load_json(args.fingerprint)
            write_json(args.output, preview(args.source, fingerprint, args.unsupported_policy))
            print(f"Preview: {args.output}")
        elif args.command == "audit-request":
            fingerprint = load_json(args.fingerprint)
            write_json(args.output, audit_request(args.source, fingerprint, args.unsupported_policy))
            print(f"Adversarial internal-AI audit request: {args.output}")
        elif args.command == "reidentify":
            manifest = reidentify(args.returned_archive, args.mapping_vault, args.output, getpass.getpass("Mapping-vault passphrase: "))
            print(f"Created reidentified archive: {args.output}")
            print(f"Manifest: {args.output.with_suffix(args.output.suffix + '.manifest.json')}")
            print(f"Restored {manifest['reidentified_token_occurrences']} token occurrences to canonical values.")
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
