from __future__ import annotations

import argparse
import getpass
import shlex
import sys
from pathlib import Path

from .engine import AUTO_APPROVAL_POLICIES, DEFAULT_REVIEW_BATCH_BYTES, ai_review_batches, ai_review_request, approve_candidates, audit_request, audit_review_template, build, candidate_summary, import_review, initial_fingerprint, load_json, merge_review_batch_responses, policy_entries, preview, preview_check, rebase_fingerprint, reidentify, require_outside_source, review_from_candidate_summary, scan, validate_fingerprint, write_json


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
        "review_directory": workspace / "internal-ai-review",
        "review_index": workspace / "internal-ai-review" / "index.json",
        "review_batches": workspace / "internal-ai-review" / "batches",
        "review_responses": workspace / "internal-ai-review" / "responses",
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


def print_shell_summary(source: Path, workdir: Path, next_command: str) -> None:
    print(f"project={shlex.quote(source_root_name(source))}")
    print(f"source_repo={shlex.quote(str(source.absolute().resolve(strict=True)))}")
    print(f"workdir={shlex.quote(str(workdir.absolute()))}")
    print(f"next_command={shlex.quote(next_command)}")


def print_build_summary(manifest: dict) -> None:
    fingerprint = manifest["fingerprint"]
    print(f"Approved fingerprint entries: {fingerprint['approved_entry_count']}")
    print(f"  Policy-approved technical: {fingerprint['policy_approved']}")
    print(f"  Human/AI-approved: {fingerprint['human_or_ai_approved']}")
    print(f"Applied {fingerprint['entries_applied']} approved fingerprint entries.")
    print(f"Directly applied: {fingerprint['directly_applied']}")
    print(f"Satisfied by overlap: {fingerprint['satisfied_by_overlap']}")
    print(f"Not present: {fingerprint['not_present']}")
    print(f"Unresolved: {fingerprint['unresolved']}")
    print("Approved variants remaining: 0")


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="deidentify", description="Create reviewed deidentified text bundles locally.")
    commands = root.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init", help="Create an empty organisation fingerprint JSON file.")
    init.add_argument("source", type=Path, help="Source repository the fingerprint will govern; keeping the fingerprint outside it is recommended.")
    init.add_argument("fingerprint", type=Path)
    scan_cmd = commands.add_parser("scan", help="Discover local candidate identifiers.")
    scan_cmd.add_argument("source", type=Path)
    scan_cmd.add_argument("--report", type=Path, required=True)
    scan_cmd.add_argument("--copilot-request", "--ai-review-request", dest="ai_review_request", type=Path, help="Optional provider-neutral internal-AI review request JSON.")
    scan_cmd.add_argument("--candidate-summary", type=Path, help="Write a compact, human-editable candidate list outside the source tree.")
    scan_cmd.add_argument("--auto-approve-policy", choices=sorted(AUTO_APPROVAL_POLICIES), default="none", help="Named local policy to separate deterministic technical identifiers from review candidates (default: none).")
    scan_cmd.add_argument("--shell-summary", choices=("bash",), help="Print Git Bash-friendly safe workflow paths and the next command.")
    candidates_cmd = commands.add_parser("candidates", help="Export or import a compact human-reviewed candidate list.")
    candidates = candidates_cmd.add_subparsers(dest="candidates_command", required=True)
    candidates_export = candidates.add_parser("export", help="Export a compact candidate list from a scan report.")
    candidates_export.add_argument("scan_report", type=Path)
    candidates_export.add_argument("--output", type=Path, required=True)
    candidates_import = candidates.add_parser("import", help="Import selected lines from a human-edited candidate list.")
    candidates_import.add_argument("source", type=Path)
    candidates_import.add_argument("fingerprint", type=Path)
    candidates_import.add_argument("scan_report", type=Path)
    candidates_import.add_argument("candidate_summary", type=Path)
    candidates_import.add_argument("--approve-all", action="store_true", help="Explicitly approve only entries selected by this local candidate summary.")
    fingerprint_cmd = commands.add_parser("fingerprint", help="Manage fingerprint source binding.")
    fingerprint = fingerprint_cmd.add_subparsers(dest="fingerprint_command", required=True)
    rebase_cmd = fingerprint.add_parser("rebase", help="Explicitly bind an existing fingerprint to the current source tree.")
    rebase_cmd.add_argument("source", type=Path)
    rebase_cmd.add_argument("fingerprint", type=Path)
    prepare_cmd = commands.add_parser("prepare", help="Start the short workflow: create/update a workspace and write one internal-AI review request.")
    prepare_cmd.add_argument("source", type=Path)
    prepare_cmd.add_argument("--workspace", type=Path, required=True, help="Secure directory outside the source for the fingerprint and workflow artifacts.")
    prepare_cmd.add_argument("--review-batch-bytes", type=int, default=DEFAULT_REVIEW_BATCH_BYTES, help=f"Maximum serialized bytes per Copilot review batch (default: {DEFAULT_REVIEW_BATCH_BYTES}).")
    prepare_cmd.add_argument("--auto-approve-policy", choices=sorted(AUTO_APPROVAL_POLICIES), default="technical-identifiers", help="Named local policy applied before internal-AI review (default: technical-identifiers).")
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
    package_cmd.add_argument("--review", type=Path, help="Legacy single internal-AI response JSON; otherwise package reads all verified Copilot batch responses.")
    package_cmd.add_argument("--review-responses", type=Path, help="Directory containing the Copilot batch response JSON files.")
    package_cmd.add_argument("--output", type=Path, help="Archive output; defaults inside the workspace.")
    package_cmd.add_argument("--mapping-vault", type=Path, help="Encrypted reverse map; defaults inside the workspace.")
    package_cmd.add_argument("--no-mapping-vault", action="store_true", help="Do not create a reverse map; reidentification will not be possible.")
    package_cmd.add_argument("--unsupported-policy", choices=("reject", "exclude"), default="exclude", help="Defaults to exclude so non-text files do not block this streamlined workflow.")
    preview_cmd = commands.add_parser("preview", help="Show planned path/content changes without writing an archive.")
    preview_cmd.add_argument("source", type=Path)
    preview_cmd.add_argument("fingerprint", type=Path)
    preview_cmd.add_argument("--output", type=Path, required=True)
    preview_cmd.add_argument("--unsupported-policy", choices=("reject", "exclude"), default="reject")
    preview_check_cmd = commands.add_parser("preview-check", help="Verify that a preview artifact still matches its source and fingerprint.")
    preview_check_cmd.add_argument("source", type=Path)
    preview_check_cmd.add_argument("fingerprint", type=Path)
    preview_check_cmd.add_argument("preview", type=Path)
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
            if args.fingerprint.exists():
                raise ValueError(f"Refusing to overwrite existing file: {args.fingerprint}")
            write_json(args.fingerprint, initial_fingerprint(args.source))
            print(f"Created fingerprint: {args.fingerprint}")
        elif args.command == "scan":
            require_workflow_artifacts_outside_source(args.source, scan_report=args.report, ai_review_request=args.ai_review_request, candidate_summary=args.candidate_summary)
            report = scan(source=args.source, auto_approve_policy=args.auto_approve_policy)
            write_json(args.report, report)
            if args.ai_review_request:
                write_json(args.ai_review_request, ai_review_request(report))
            if args.candidate_summary:
                args.candidate_summary.parent.mkdir(parents=True, exist_ok=True)
                args.candidate_summary.write_text(candidate_summary(report), encoding="utf-8")
            print(f"Scanned {report['source']['scanned_file_count']} text files; found {len(report['candidate_inventory'])} review candidate groups.")
            print(f"Auto-approval policy: {args.auto_approve_policy}; technical entries identified: {len(policy_entries(report))}.")
            print(f"Source: {report['source']['path']}")
            print(f"Text files scanned: {report['source']['scanned_file_count']}")
            print(f"Top-level files: {report['source']['top_level_file_count']}")
            print(f"Top-level directories: {report['source']['top_level_directory_count']}")
            print(f"Report: {args.report}")
            if args.ai_review_request:
                print(f"Internal-AI review request: {args.ai_review_request}")
            if args.candidate_summary:
                print(f"Compact candidate summary: {args.candidate_summary}")
            if args.shell_summary:
                summary_path = args.candidate_summary or args.report.with_name("candidate-summary.txt")
                next_command = f"deidentify candidates import {args.source.absolute()} {args.report.parent / 'fingerprint.json'} {args.report.absolute()} {summary_path.absolute()} --approve-all"
                print_shell_summary(args.source, args.report.parent, next_command)
        elif args.command == "candidates":
            if args.candidates_command == "export":
                if args.output.exists():
                    raise ValueError(f"Refusing to overwrite existing file: {args.output}")
                report = load_json(args.scan_report)
                report_source = report.get("source", {}).get("path") if isinstance(report.get("source"), dict) else None
                if not isinstance(report_source, str):
                    raise ValueError("Invalid scan report: source.path must be a string")
                require_workflow_artifacts_outside_source(Path(report_source), candidate_summary=args.output)
                args.output.parent.mkdir(parents=True, exist_ok=True)
                args.output.write_text(candidate_summary(report), encoding="utf-8")
                print(f"Compact candidate summary: {args.output}")
            elif args.candidates_command == "import":
                require_workflow_artifacts_outside_source(args.source, fingerprint=args.fingerprint, scan_report=args.scan_report, candidate_summary=args.candidate_summary)
                report = load_json(args.scan_report)
                fingerprint = load_json(args.fingerprint)
                policy = report.get("auto_approval_policy", "none")
                fingerprint, policy_added, policy_updated, policy_approved = import_review(fingerprint, {"entries": policy_entries(report)}, approve_all=True, approval_source="policy", approval_policy=policy)
                review = review_from_candidate_summary(args.source, report, args.candidate_summary.read_text(encoding="utf-8"))
                fingerprint, added, updated, approved = import_review(fingerprint, review, approve_all=args.approve_all, approval_source="local_human_candidate_summary" if args.approve_all else None)
                write_json(args.fingerprint, fingerprint)
                if policy_added or policy_updated:
                    print(f"Policy-approved technical entries: {policy_approved} ({policy_added} added, {policy_updated} updated).")
                print(f"Imported candidate summary: {added} candidate entries added, {updated} entries updated.")
                if args.approve_all:
                    print(f"Approved {approved} imported/updated entries.")
                else:
                    print("Selected entries remain candidates. Re-run with --approve-all to explicitly approve them.")
        elif args.command == "fingerprint":
            if args.fingerprint_command == "rebase":
                require_workflow_artifacts_outside_source(args.source, fingerprint=args.fingerprint)
                fingerprint, presence = rebase_fingerprint(args.source, load_json(args.fingerprint))
                write_json(args.fingerprint, fingerprint)
                print(f"Fingerprint rebound to source tree: {fingerprint['source_tree_digest']}")
                print(f"Approved entries present: {presence['present']}; absent: {presence['absent']}; newly present: {presence['became_present']}; newly absent: {presence['became_absent']}")
        elif args.command == "prepare":
            paths = workspace_paths(args.workspace, args.source)
            if paths["fingerprint"].exists():
                fingerprint = load_json(paths["fingerprint"])
                validate_fingerprint(fingerprint)
            else:
                fingerprint = initial_fingerprint(args.source)
                write_json(paths["fingerprint"], fingerprint)
            report = scan(source=args.source, auto_approve_policy=args.auto_approve_policy)
            fingerprint, policy_added, policy_updated, policy_approved = import_review(fingerprint, {"entries": policy_entries(report)}, approve_all=True, approval_source="policy", approval_policy=args.auto_approve_policy)
            write_json(paths["fingerprint"], fingerprint)
            write_json(paths["report"], report)
            batches = ai_review_batches(report, args.review_batch_bytes)
            index_batches = []
            for batch in batches:
                filename = f"{batch['batch_id']}.json"
                write_json(paths["review_batches"] / filename, batch)
                index_batches.append({"batch_id": batch["batch_id"], "batch_digest": batch["batch_digest"], "request_file": filename, "response_file": filename})
            write_json(paths["review_index"], {"schema_version": 1, "purpose": "Copilot review batch index. Attach every file in batches/ to sanctioned internal Copilot and save the JSON-only response using the same filename in responses/.", "batches": index_batches})
            print(f"Prepared workspace: {args.workspace}")
            print(f"Auto-approval policy: {args.auto_approve_policy}; policy-approved technical entries: {policy_approved} ({policy_added} added, {policy_updated} updated).")
            print(f"Copilot review index: {paths['review_index']}")
            print(f"Copilot review batches: {paths['review_batches']} ({len(batches)} files, at most {args.review_batch_bytes} bytes each)")
            print("Save each JSON-only Copilot response using the same filename in: " + str(paths["review_responses"]))
        elif args.command == "import-review":
            require_workflow_artifacts_outside_source(args.source, fingerprint=args.fingerprint, ai_review_response=args.review)
            fingerprint = load_json(args.fingerprint)
            review = load_json(args.review)
            fingerprint, added, updated, approved = import_review(fingerprint=fingerprint, review=review, approve_all=args.approve_all, approval_source="local_cli" if args.approve_all else None)
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
            print_build_summary(manifest)
            if manifest["omitted_files"]:
                print(f"Warning: {len(manifest['omitted_files'])} files/directories were omitted by policy.")
            if args.mapping_vault:
                print(f"Encrypted mapping vault: {args.mapping_vault}")
        elif args.command == "package":
            paths = workspace_paths(args.workspace, args.source)
            if args.no_mapping_vault and args.mapping_vault:
                raise ValueError("--no-mapping-vault cannot be combined with --mapping-vault")
            if args.review and args.review_responses:
                raise ValueError("--review cannot be combined with --review-responses")
            review_path = args.review
            responses_directory = args.review_responses or paths["review_responses"]
            output = args.output or paths["archive"]
            vault_path = None if args.no_mapping_vault else (args.mapping_vault or paths["vault"])
            require_workflow_artifacts_outside_source(args.source, fingerprint=paths["fingerprint"], ai_review_response=review_path, copilot_review_responses=responses_directory, archive_output=output, mapping_vault=vault_path)
            vault_passphrase = mapping_vault_passphrase() if vault_path else None
            review = load_json(review_path) if review_path else merge_review_batch_responses(load_json(paths["review_index"]), responses_directory)
            fingerprint, added, updated, approved = import_review(load_json(paths["fingerprint"]), review, approve_all=True, approval_source="local_cli_package")
            write_json(paths["fingerprint"], fingerprint)
            manifest = build(args.source, fingerprint, output, unsupported_policy=args.unsupported_policy, vault_path=vault_path, vault_passphrase=vault_passphrase)
            print(f"Imported review: {added} entries added, {updated} entries updated; approved {approved} touched entries.")
            print(f"Created archive: {output}")
            print(f"Manifest: {output.with_suffix(output.suffix + '.manifest.json')}")
            print_build_summary(manifest)
            if manifest["omitted_files"]:
                print(f"Warning: {len(manifest['omitted_files'])} files/directories were omitted by policy.")
            if vault_path:
                print(f"Encrypted mapping vault: {vault_path}")
        elif args.command == "preview":
            require_workflow_artifacts_outside_source(args.source, fingerprint=args.fingerprint, preview_output=args.output)
            fingerprint = load_json(args.fingerprint)
            write_json(args.output, preview(source=args.source, fingerprint=fingerprint, unsupported_policy=args.unsupported_policy))
            print(f"Preview: {args.output}")
        elif args.command == "preview-check":
            require_workflow_artifacts_outside_source(args.source, fingerprint=args.fingerprint, preview_artifact=args.preview)
            preview_check(args.source, load_json(args.fingerprint), load_json(args.preview))
            print("Preview current: yes")
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
            print(f"Restored {manifest['reidentified_token_occurrences']} token occurrences to their original exact values.")
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
