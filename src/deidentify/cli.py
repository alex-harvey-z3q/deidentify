from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

from .engine import ai_review_request, approve_candidates, audit_request, audit_review_template, build, import_review, initial_fingerprint, load_json, preview, reidentify, require_outside_source, scan, validate_fingerprint, write_json


def require_workflow_artifacts_outside_source(source: Path, **artifacts: Path | None) -> None:
    for label, path in artifacts.items():
        if path is None:
            continue
        try:
            require_outside_source(source, path, label.replace("_", " ").capitalize())
        except ValueError as exc:
            raise ValueError(f"{label.replace('_', ' ')} must be outside the source repository:\nsource: {source.absolute()}\nartifact: {path.absolute()}") from exc


def workspace_paths(workspace: Path, source: Path) -> dict[str, Path]:
    """Return the conventional artifact locations for the short workflow."""
    require_workflow_artifacts_outside_source(source, workspace=workspace)
    bundle_name = f"{source_root_name(source)}-deidentified.tar.gz"
    return {
        "fingerprint": workspace / "fingerprint.json",
        "report": workspace / "scan-report.json",
        "request": workspace / "internal-ai-review-request.json",
        "review": workspace / "internal-ai-review-response.json",
        "archive": workspace / bundle_name,
        "vault": workspace / f"{bundle_name}.mapping.vault.json",
    }


def source_root_name(source: Path) -> str:
    return source.absolute().resolve(strict=True).name


def mapping_vault_passphrase() -> str:
    passphrase = getpass.getpass("New mapping-vault passphrase: ")
    if passphrase != getpass.getpass("Confirm mapping-vault passphrase: "):
        raise ValueError("Mapping-vault passphrases do not match")
    return passphrase


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="deidentify", description="Create reviewed deidentified text bundles locally.")
    commands = root.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init", help="Create an empty organisation fingerprint JSON file.")
    init.add_argument("source", type=Path, help="Source repository the fingerprint will govern; the fingerprint must be outside it.")
    init.add_argument("fingerprint", type=Path)
    scan_cmd = commands.add_parser("scan", help="Discover local candidate identifiers.")
    scan_cmd.add_argument("source", type=Path)
    scan_cmd.add_argument("--report", type=Path, required=True)
    scan_cmd.add_argument("--copilot-request", "--ai-review-request", dest="ai_review_request", type=Path, required=True)
    prepare_cmd = commands.add_parser("prepare", help="Start the short workflow: create/update a workspace and write one internal-AI review request.")
    prepare_cmd.add_argument("source", type=Path)
    prepare_cmd.add_argument("--workspace", type=Path, required=True, help="Secure directory outside the source for the fingerprint and workflow artifacts.")
    review = commands.add_parser("import-review", help="Import unapproved entries proposed by sanctioned internal AI.")
    review.add_argument("source", type=Path)
    review.add_argument("fingerprint", type=Path)
    review.add_argument("review", type=Path)
    review.add_argument("--approve-all", action="store_true", help="Explicitly approve only entries imported or updated by this operation.")
    approve_cmd = commands.add_parser("approve", help="Explicitly approve all current candidate entries in a fingerprint.")
    approve_cmd.add_argument("source", type=Path)
    approve_cmd.add_argument("fingerprint", type=Path)
    approve_cmd.add_argument("--all", action="store_true", required=True, help="Approve every current candidate entry.")
    build_cmd = commands.add_parser("build", help="Build a fresh deidentified tarball from approved entries.")
    build_cmd.add_argument("source", type=Path)
    build_cmd.add_argument("fingerprint", type=Path)
    build_cmd.add_argument("output", type=Path)
    build_cmd.add_argument("--unsupported-policy", choices=("reject", "exclude"), default="reject")
    build_cmd.add_argument("--audit-findings", type=Path)
    build_cmd.add_argument("--audit-review", type=Path, help="Human-reviewed audit dismissals bound to the current tree digest.")
    build_cmd.add_argument("--fail-on-ai-findings", action="store_true")
    build_cmd.add_argument("--mapping-vault", type=Path, help="Write an encrypted token-to-canonical mapping outside the source tree.")
    package_cmd = commands.add_parser("package", help="Finish the short workflow: import and approve this AI review, then build a reversible bundle.")
    package_cmd.add_argument("source", type=Path)
    package_cmd.add_argument("--workspace", type=Path, required=True, help="Workspace previously created by prepare.")
    package_cmd.add_argument("--review", type=Path, help="Internal-AI response JSON; defaults to WORKSPACE/internal-ai-review-response.json.")
    package_cmd.add_argument("--output", type=Path, help="Archive output; defaults inside the workspace.")
    package_cmd.add_argument("--mapping-vault", type=Path, help="Encrypted reverse map; defaults inside the workspace.")
    package_cmd.add_argument("--no-mapping-vault", action="store_true", help="Do not create a reverse map; reidentification will not be possible.")
    package_cmd.add_argument("--unsupported-policy", choices=("reject", "exclude"), default="exclude", help="Defaults to exclude so non-text files do not block this streamlined workflow.")
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
    audit_review_cmd = commands.add_parser("audit-review-template", help="Create a human-review template from raw AI audit findings.")
    audit_review_cmd.add_argument("source", type=Path)
    audit_review_cmd.add_argument("fingerprint", type=Path)
    audit_review_cmd.add_argument("audit_findings", type=Path)
    audit_review_cmd.add_argument("--output", type=Path, required=True)
    audit_review_cmd.add_argument("--unsupported-policy", choices=("reject", "exclude"), default="reject")
    reidentify_cmd = commands.add_parser("reidentify", help="Restore canonical values in a returned tarball using an encrypted mapping vault.")
    reidentify_cmd.add_argument("returned_archive", type=Path)
    reidentify_cmd.add_argument("mapping_vault", type=Path)
    reidentify_cmd.add_argument("output", type=Path)
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "init":
            require_workflow_artifacts_outside_source(args.source, fingerprint=args.fingerprint)
            if args.fingerprint.exists():
                raise ValueError(f"Refusing to overwrite existing file: {args.fingerprint}")
            write_json(args.fingerprint, initial_fingerprint())
            print(f"Created fingerprint: {args.fingerprint}")
        elif args.command == "scan":
            require_workflow_artifacts_outside_source(args.source, scan_report=args.report, ai_review_request=args.ai_review_request)
            report = scan(source=args.source)
            write_json(args.report, report)
            write_json(args.ai_review_request, ai_review_request(report))
            print(f"Scanned {report['source']['scanned_file_count']} text files; found {len(report['candidate_inventory'])} candidate groups.")
            print(f"Report: {args.report}")
            print(f"Internal-AI review request: {args.ai_review_request}")
        elif args.command == "prepare":
            paths = workspace_paths(args.workspace, args.source)
            if paths["fingerprint"].exists():
                fingerprint = load_json(paths["fingerprint"])
                validate_fingerprint(fingerprint)
            else:
                write_json(paths["fingerprint"], initial_fingerprint())
            report = scan(source=args.source)
            write_json(paths["report"], report)
            write_json(paths["request"], ai_review_request(report))
            print(f"Prepared workspace: {args.workspace}")
            print(f"Internal-AI review request: {paths['request']}")
            print("Save the internal-AI response as: " + str(paths["review"]))
        elif args.command == "import-review":
            require_workflow_artifacts_outside_source(args.source, fingerprint=args.fingerprint, ai_review_response=args.review)
            fingerprint = load_json(args.fingerprint)
            review = load_json(args.review)
            fingerprint, added, updated, approved = import_review(fingerprint=fingerprint, review=review, approve_all=args.approve_all)
            write_json(args.fingerprint, fingerprint)
            print(f"Imported review: {added} candidate entries added, {updated} entries updated.")
            if args.approve_all:
                print(f"Approved {approved} imported/updated entries.")
            else:
                print("Review the fingerprint and explicitly set vetted entries to status: approved before building.")
        elif args.command == "approve":
            require_workflow_artifacts_outside_source(args.source, fingerprint=args.fingerprint)
            fingerprint, approved = approve_candidates(fingerprint=load_json(args.fingerprint))
            write_json(args.fingerprint, fingerprint)
            print(f"Approved {approved} candidate entries.")
        elif args.command == "build":
            require_workflow_artifacts_outside_source(args.source, fingerprint=args.fingerprint, audit_findings=args.audit_findings, human_audit_review=args.audit_review, mapping_vault=args.mapping_vault, archive_output=args.output)
            fingerprint = load_json(args.fingerprint)
            validate_fingerprint(fingerprint)
            audit = load_json(args.audit_findings) if args.audit_findings else None
            audit_review = load_json(args.audit_review) if args.audit_review else None
            vault_passphrase = None
            if args.mapping_vault:
                vault_passphrase = mapping_vault_passphrase()
            manifest = build(args.source, fingerprint, args.output, unsupported_policy=args.unsupported_policy, audit=audit, audit_review=audit_review, fail_on_ai_findings=args.fail_on_ai_findings, vault_path=args.mapping_vault, vault_passphrase=vault_passphrase)
            print(f"Created archive: {args.output}")
            print(f"Manifest: {args.output.with_suffix(args.output.suffix + '.manifest.json')}")
            print(f"Applied {manifest['fingerprint']['entries_applied']} approved fingerprint entries.")
            if manifest["omitted_files"]:
                print(f"Warning: {len(manifest['omitted_files'])} files/directories were omitted by policy.")
            if args.mapping_vault:
                print(f"Encrypted mapping vault: {args.mapping_vault}")
        elif args.command == "package":
            paths = workspace_paths(args.workspace, args.source)
            if args.no_mapping_vault and args.mapping_vault:
                raise ValueError("--no-mapping-vault cannot be combined with --mapping-vault")
            review_path = args.review or paths["review"]
            output = args.output or paths["archive"]
            vault_path = None if args.no_mapping_vault else (args.mapping_vault or paths["vault"])
            require_workflow_artifacts_outside_source(args.source, fingerprint=paths["fingerprint"], ai_review_response=review_path, archive_output=output, mapping_vault=vault_path)
            fingerprint, added, updated, approved = import_review(load_json(paths["fingerprint"]), load_json(review_path), approve_all=True)
            write_json(paths["fingerprint"], fingerprint)
            vault_passphrase = mapping_vault_passphrase() if vault_path else None
            manifest = build(args.source, fingerprint, output, unsupported_policy=args.unsupported_policy, vault_path=vault_path, vault_passphrase=vault_passphrase)
            print(f"Imported review: {added} entries added, {updated} entries updated; approved {approved} touched entries.")
            print(f"Created archive: {output}")
            print(f"Manifest: {output.with_suffix(output.suffix + '.manifest.json')}")
            if manifest["omitted_files"]:
                print(f"Warning: {len(manifest['omitted_files'])} files/directories were omitted by policy.")
            if vault_path:
                print(f"Encrypted mapping vault: {vault_path}")
        elif args.command == "preview":
            require_workflow_artifacts_outside_source(args.source, fingerprint=args.fingerprint, preview_output=args.output)
            fingerprint = load_json(args.fingerprint)
            write_json(args.output, preview(source=args.source, fingerprint=fingerprint, unsupported_policy=args.unsupported_policy))
            print(f"Preview: {args.output}")
        elif args.command == "audit-request":
            require_workflow_artifacts_outside_source(args.source, fingerprint=args.fingerprint, audit_request=args.output)
            fingerprint = load_json(args.fingerprint)
            write_json(args.output, audit_request(source=args.source, fingerprint=fingerprint, unsupported_policy=args.unsupported_policy))
            print(f"Adversarial internal-AI audit request: {args.output}")
        elif args.command == "audit-review-template":
            require_workflow_artifacts_outside_source(args.source, fingerprint=args.fingerprint, audit_findings=args.audit_findings, human_audit_review=args.output)
            fingerprint = load_json(args.fingerprint)
            write_json(args.output, audit_review_template(source=args.source, fingerprint=fingerprint, audit=load_json(args.audit_findings), unsupported_policy=args.unsupported_policy))
            print(f"Human audit-review template: {args.output}")
        elif args.command == "reidentify":
            manifest = reidentify(returned_archive=args.returned_archive, vault_path=args.mapping_vault, output=args.output, passphrase=getpass.getpass("Mapping-vault passphrase: "))
            print(f"Created reidentified archive: {args.output}")
            print(f"Manifest: {args.output.with_suffix(args.output.suffix + '.manifest.json')}")
            print(f"Restored {manifest['reidentified_token_occurrences']} token occurrences to canonical values.")
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
