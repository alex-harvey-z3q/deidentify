import os
import shutil
import tarfile
import tempfile
import unittest
from pathlib import Path

from deidentify.engine import MAX_FILE_BYTES, ai_review_request, approved_replacements, audit_request, audit_review_template, build, build_plan, import_review, initial_fingerprint, portable_path_key, preview, reidentify, scan


def approved(*entries):
    fingerprint = initial_fingerprint()
    fingerprint["entries"] = [
        {"canonical": canonical, "category": category, "variants": variants, "status": "approved"}
        for canonical, category, variants in entries
    ]
    return fingerprint


class EngineTests(unittest.TestCase):
    def source(self, parent: Path) -> Path:
        root = parent / "source"
        root.mkdir()
        return root

    def archive_names(self, output: Path) -> set[str]:
        with tarfile.open(output) as archive:
            return set(archive.getnames())

    def archive_text(self, output: Path, name: str) -> str:
        with tarfile.open(output) as archive:
            return archive.extractfile(name).read().decode("utf-8")

    def audit_response(self, request, findings):
        return {"tree_digest": request["tree_digest"], "batches": [{"batch_id": batch["batch_id"], "batch_digest": batch["batch_digest"], "findings": findings if index == 0 else []} for index, batch in enumerate(request["batches"])]}

    def test_scan_excludes_git_and_env(self):
        with tempfile.TemporaryDirectory() as name:
            root = self.source(Path(name))
            (root / "app.py").write_text("SERVICE = 'orion-api'\n", encoding="utf-8")
            (root / ".env").write_text("PASSWORD=secret\n", encoding="utf-8")
            (root / ".git").mkdir()
            report = scan(root)
            self.assertEqual(report["source"]["scanned_file_count"], 1)
            self.assertIn("orion-api", {item["term"] for item in report["candidate_inventory"]})
            self.assertIn(".env", {item["path"] for item in report["excluded_files"]})
            self.assertIn(".git", {item["path"] for item in report["excluded_files"]})

    def test_symlink_file_and_directory_are_never_read_or_archived(self):
        with tempfile.TemporaryDirectory() as name:
            parent = Path(name); root = self.source(parent); outside = parent / "outside"
            outside.mkdir(); (outside / "leak.yml").write_text("Orion external secret", encoding="utf-8")
            (root / "safe.yml").write_text("name: Orion", encoding="utf-8")
            os.symlink(outside / "leak.yml", root / "looks-safe.yml")
            os.symlink(outside, root / "linked-dir")
            (root / "nested").mkdir()
            os.symlink(outside / "leak.yml", root / "nested" / "also-safe.yml")
            report = scan(root)
            skipped = {item["path"]: item["reason"] for item in report["excluded_files"]}
            self.assertIn("security: symlink file skipped", skipped["looks-safe.yml"])
            self.assertIn("security: symlink directory skipped", skipped["linked-dir"])
            self.assertIn("security: symlink file skipped", skipped["nested/also-safe.yml"])
            output = parent / "release.tar.gz"
            manifest = build(root, approved(("Orion", "internal_product", ["Orion"])), output)
            self.assertEqual(self.archive_names(output), {"safe.yml"})
            self.assertNotIn("external", self.archive_text(output, "safe.yml"))
            self.assertEqual(3, len(manifest["omitted_files"]))

    def test_path_only_fingerprints_are_discovered_and_transformed(self):
        with tempfile.TemporaryDirectory() as name:
            parent = Path(name); root = self.source(parent)
            target = root / "docs" / "ProjectOrion" / "CommonwealthBank"
            target.mkdir(parents=True); (target / "mantle-platform.yml").write_text("generic: true\n", encoding="utf-8")
            report = scan(root)
            terms = {item["term"] for item in report["candidate_inventory"]}
            self.assertTrue({"ProjectOrion", "CommonwealthBank", "mantle-platform"}.issubset(terms))
            path_evidence = next(item for item in report["candidate_inventory"] if item["term"] == "ProjectOrion")["evidence"]
            self.assertEqual("path", path_evidence[0]["source"])
            fingerprint = approved(("ProjectOrion", "project", ["ProjectOrion"]), ("CommonwealthBank", "customer", ["CommonwealthBank"]), ("mantle-platform", "internal_system", ["mantle-platform"]))
            output = parent / "release.tar.gz"; build(root, fingerprint, output)
            names = self.archive_names(output)
            self.assertEqual({"docs/__PROJECT_001__/__CUSTOMER_001__/__INTERNAL_SYSTEM_001__.yml"}, names)

    def test_exact_variant_tokens_avoid_path_collision(self):
        with tempfile.TemporaryDirectory() as name:
            parent = Path(name); root = self.source(parent)
            for directory in ("customer-acme", "customer-foo"):
                (root / directory).mkdir(); (root / directory / "config.yml").write_text("ok", encoding="utf-8")
            fingerprint = approved(("Customer", "customer", ["customer-acme", "customer-foo"]))
            output = parent / "release.tar.gz"
            build(root, fingerprint, output)
            self.assertEqual({"__CUSTOMER_001__/config.yml", "__CUSTOMER_002__/config.yml"}, self.archive_names(output))

    def test_overlap_case_and_crlf_replacement_is_longest_first(self):
        with tempfile.TemporaryDirectory() as name:
            parent = Path(name); root = self.source(parent)
            original = "OrionApi\r\norion-api\r\nORION_API\r\nhttps://orion-api.internal/v1\r\n"
            (root / "service.yml").write_bytes(original.encode())
            fingerprint = approved(("Orion API", "internal_system", ["OrionApi", "orion-api", "ORION_API", "orion-api.internal"]))
            output = parent / "release.tar.gz"; build(root, fingerprint, output)
            content = self.archive_text(output, "service.yml")
            self.assertNotIn("orion", content.casefold())
            self.assertIn("__INTERNAL_SYSTEM_001__", content)
            self.assertIn("\r\n", content)

    def test_unsupported_files_reject_by_default_and_can_be_explicitly_excluded(self):
        with tempfile.TemporaryDirectory() as name:
            parent = Path(name); root = self.source(parent)
            (root / "ok.yml").write_text("Orion", encoding="utf-8")
            (root / "image.png").write_bytes(b"\x89PNG\x00")
            fingerprint = approved(("Orion", "project", ["Orion"]))
            with self.assertRaisesRegex(ValueError, "Refusing incomplete export"):
                build(root, fingerprint, parent / "reject.tar.gz")
            manifest = build(root, fingerprint, parent / "exclude.tar.gz", unsupported_policy="exclude")
            self.assertEqual({"ok.yml"}, self.archive_names(parent / "exclude.tar.gz"))
            self.assertEqual("image.png", manifest["omitted_files"][0]["path"])

    def test_content_based_text_detection_includes_unknown_extensions_and_extensionless_files(self):
        with tempfile.TemporaryDirectory() as name:
            parent = Path(name); root = self.source(parent)
            (root / "Jenkinsfile").write_text("pipeline { agent any } // Orion\n", encoding="utf-8")
            (root / "shared.groovy").write_text("def name = 'Orion'\n", encoding="utf-8")
            fingerprint = approved(("Orion", "project", ["Orion"]))
            output = parent / "release.tar.gz"
            build(root, fingerprint, output)
            self.assertEqual({"Jenkinsfile", "shared.groovy"}, self.archive_names(output))
            self.assertNotIn("Orion", self.archive_text(output, "Jenkinsfile"))
            self.assertNotIn("Orion", self.archive_text(output, "shared.groovy"))

    def test_large_and_malformed_utf8_files_are_explicit(self):
        with tempfile.TemporaryDirectory() as name:
            parent = Path(name); root = self.source(parent)
            (root / "ok.yml").write_text("Orion", encoding="utf-8")
            (root / "bad.yml").write_bytes(b"\xff\xfe")
            (root / "large.yml").write_bytes(b"x" * (MAX_FILE_BYTES + 1))
            result = preview(root, approved(("Orion", "project", ["Orion"])), unsupported_policy="exclude")
            reasons = {item["path"]: item["reason"] for item in result["omitted_files"]}
            self.assertIn("not UTF-8", reasons["bad.yml"])
            self.assertIn("exceeds", reasons["large.yml"])

    def test_semantic_request_is_bounded_and_ai_entries_remain_candidates(self):
        with tempfile.TemporaryDirectory() as name:
            root = self.source(Path(name)); (root / "orion.py").write_text("service = 'ProjectOrion'\n" * 100, encoding="utf-8")
            request = ai_review_request(scan(root))
            self.assertLessEqual(len(request["semantic_chunks"]), 200)
            self.assertIn("cannot approve", request["purpose"])
            fingerprint, added, _, _ = import_review(initial_fingerprint(), {"entries": [{"canonical": "ProjectOrion", "category": "project", "variants": ["ProjectOrion"], "status": "approved", "confidence": "high", "rationale": "test", "evidence": []}]})
            self.assertEqual(1, added); self.assertEqual("candidate", fingerprint["entries"][0]["status"])

    def test_import_review_approve_all_affects_only_touched_entries(self):
        fingerprint = initial_fingerprint()
        fingerprint["entries"] = [
            {"canonical": "Existing Candidate", "category": "project", "variants": ["Existing"], "status": "candidate"},
            {"canonical": "Unrelated Candidate", "category": "project", "variants": ["Unrelated"], "status": "candidate"},
            {"canonical": "Already Approved", "category": "project", "variants": ["Already"], "status": "approved"},
        ]
        review = {"entries": [
            {"canonical": "Existing Candidate", "category": "project", "variants": ["ExistingNew"], "confidence": "high", "rationale": "update", "evidence": []},
            {"canonical": "New Candidate", "category": "project", "variants": ["New"], "confidence": "high", "rationale": "add", "evidence": []},
            {"canonical": "Already Approved", "category": "project", "variants": ["AlreadyNew"], "confidence": "high", "rationale": "update", "evidence": []},
        ]}
        updated_fingerprint, added, updated, approved = import_review(fingerprint, review, approve_all=True)
        statuses = {entry["canonical"]: entry["status"] for entry in updated_fingerprint["entries"]}
        self.assertEqual((1, 2, 3), (added, updated, approved))
        self.assertEqual("approved", statuses["Existing Candidate"])
        self.assertEqual("approved", statuses["New Candidate"])
        self.assertEqual("approved", statuses["Already Approved"])
        self.assertEqual("candidate", statuses["Unrelated Candidate"])

    def test_static_discovery_covers_cloud_network_and_identifier_signals(self):
        with tempfile.TemporaryDirectory() as name:
            root = self.source(Path(name))
            (root / "infra.tf").write_text('arn:aws:iam::123456789012:role/Orion\n/subscriptions/123e4567-e89b-12d3-a456-426614174000/resourceGroups/orion-rg\n', encoding="utf-8")
            (root / "notes.md").write_text('ops@orion.internal 10.1.2.3 2001:db8:0:1::1 123e4567-e89b-12d3-a456-426614174000\n', encoding="utf-8")
            (root / "tool.ps1").write_text('$internalProject = "Orion"; $internal_project = "Orion"; $ORION_SERVICE = 1\n', encoding="utf-8")
            inventory = scan(root)["candidate_inventory"]
            kinds = {item["kind"] for item in inventory}
            self.assertTrue({"aws_arn", "azure_resource_id", "email", "ipv4", "ipv6", "uuid", "lower_camel_identifier", "snake_identifier", "upper_snake_identifier"}.issubset(kinds))

    def test_adversarial_audit_can_block_export(self):
        with tempfile.TemporaryDirectory() as name:
            parent = Path(name); root = self.source(parent); (root / "ok.yml").write_text("Orion", encoding="utf-8")
            fingerprint = approved(("Orion", "project", ["Orion"]))
            request = audit_request(root, fingerprint)
            self.assertIn("Adversarial", request["purpose"])
            audit = self.audit_response(request, [{"clue": "unique architecture", "category": "architecture", "path": "ok.yml", "line": 1, "explanation": "distinctive", "confidence": "high", "status": "dismissed"}])
            with self.assertRaisesRegex(ValueError, "audit has 1"):
                build(root, fingerprint, parent / "blocked.tar.gz", audit=audit, fail_on_ai_findings=True)
            review = audit_review_template(root, fingerprint, audit)
            finding_id = review["findings"][0]["finding_id"]
            review["dismissals"] = [{"finding_id": finding_id, "status": "dismissed", "reason": "Human reviewer confirmed this is generic."}]
            build(root, fingerprint, parent / "allowed.tar.gz", audit=audit, audit_review=review, fail_on_ai_findings=True)

    def test_preview_and_manifest_do_not_leak_fingerprint_mapping(self):
        with tempfile.TemporaryDirectory() as name:
            parent = Path(name); root = self.source(parent); (root / "Orion.yml").write_text("Orion", encoding="utf-8")
            fingerprint = approved(("Orion confidential", "project", ["Orion"]))
            result = preview(root, fingerprint)
            self.assertEqual("Orion.yml", result["changes"][0]["source_path"])
            output = parent / "release.tar.gz"; build(root, fingerprint, output)
            manifest = output.with_suffix(".gz.manifest.json").read_text(encoding="utf-8")
            self.assertNotIn("Orion confidential", manifest)
            with tarfile.open(output) as archive:
                info = archive.getmember("__PROJECT_001__.yml")
            self.assertEqual(0, info.uid); self.assertEqual(0, info.gid); self.assertEqual(0, info.mtime)

    def test_archive_output_inside_source_is_rejected(self):
        with tempfile.TemporaryDirectory() as name:
            root = self.source(Path(name)); (root / "ok.yml").write_text("Orion", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Archive output must be outside"):
                build(root, approved(("Orion", "project", ["Orion"])), root / "release.tar.gz")

    def test_existing_archive_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as name:
            parent = Path(name); root = self.source(parent); (root / "ok.yml").write_text("Orion", encoding="utf-8")
            output = parent / "release.tar.gz"; output.write_bytes(b"existing")
            with self.assertRaisesRegex(ValueError, "Refusing to overwrite"):
                build(root, approved(("Orion", "project", ["Orion"])), output)
            self.assertEqual(b"existing", output.read_bytes())

    def test_final_verification_blocks_remaining_approved_variant(self):
        with tempfile.TemporaryDirectory() as name:
            parent = Path(name); root = self.source(parent); (root / "ok.yml").write_text("Orion", encoding="utf-8")
            # A hostile/mistaken variant equal to the generated token must fail closed in final verification.
            fingerprint = approved(("Orion", "project", ["Orion", "__PROJECT_001__"]))
            with self.assertRaisesRegex(ValueError, "Final check"):
                build(root, fingerprint, parent / "release.tar.gz")

    def test_encrypted_mapping_vault_reidentifies_exact_variants(self):
        with tempfile.TemporaryDirectory() as name:
            parent = Path(name); root = self.source(parent); (root / "Orion.yml").write_text("service: orion-api\n", encoding="utf-8")
            fingerprint = approved(("Orion Payments", "internal_product", ["Orion", "orion-api"]))
            deidentified = parent / "deidentified.tar.gz"; vault = parent / "mapping.vault.json"
            build(root, fingerprint, deidentified, vault_path=vault, vault_passphrase="correct horse battery staple")
            self.assertNotIn("Orion Payments", vault.read_text(encoding="utf-8"))
            returned = parent / "returned.tar.gz"; shutil.copyfile(deidentified, returned)
            restored = parent / "restored.tar.gz"
            manifest = reidentify(returned, vault, restored, "correct horse battery staple")
            self.assertEqual("__INTERNAL_PRODUCT_001__.yml", self.archive_names(deidentified).pop())
            self.assertEqual({"Orion.yml"}, self.archive_names(restored))
            self.assertIn("orion-api", self.archive_text(restored, "Orion.yml"))
            self.assertEqual(2, manifest["reidentified_token_occurrences"])
            with self.assertRaisesRegex(ValueError, "Could not decrypt"):
                reidentify(returned, vault, parent / "wrong.tar.gz", "wrong passphrase")

    def test_reidentify_accepts_extensionless_tokenized_filename(self):
        with tempfile.TemporaryDirectory() as name:
            parent = Path(name); root = self.source(parent)
            (root / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
            fingerprint = approved(("Internal Dockerfile", "internal_system", ["Dockerfile"]))
            deidentified = parent / "deidentified.tar.gz"; vault = parent / "mapping.vault.json"
            build(root, fingerprint, deidentified, vault_path=vault, vault_passphrase="passphrase")
            restored = parent / "restored.tar.gz"
            reidentify(deidentified, vault, restored, "passphrase")
            self.assertEqual({"Dockerfile"}, self.archive_names(restored))

    def test_reidentify_round_trips_exact_paths_and_text(self):
        with tempfile.TemporaryDirectory() as name:
            parent = Path(name); root = self.source(parent)
            (root / "Orion-ORION.yml").write_text("Orion ORION orion\n", encoding="utf-8")
            fingerprint = approved(("Orion", "project", ["Orion", "ORION", "orion"]))
            deidentified = parent / "deidentified.tar.gz"; vault = parent / "mapping.vault.json"; restored = parent / "restored.tar.gz"
            build(root, fingerprint, deidentified, vault_path=vault, vault_passphrase="passphrase")
            reidentify(deidentified, vault, restored, "passphrase")
            self.assertEqual({"Orion-ORION.yml"}, self.archive_names(restored))
            self.assertEqual("Orion ORION orion\n", self.archive_text(restored, "Orion-ORION.yml"))

    def test_reidentify_rejects_unsafe_returned_archive_members(self):
        with tempfile.TemporaryDirectory() as name:
            parent = Path(name); vault = parent / "mapping.vault.json"
            fingerprint = approved(("Orion", "project", ["Orion"]))
            from deidentify.engine import write_mapping_vault
            write_mapping_vault(vault, fingerprint, "passphrase")
            returned = parent / "returned.tar.gz"
            with tarfile.open(returned, "w:gz") as archive:
                link = tarfile.TarInfo("link.yml"); link.type = tarfile.SYMTYPE; link.linkname = "/outside"
                archive.addfile(link)
            with self.assertRaisesRegex(ValueError, "non-regular"):
                reidentify(returned, vault, parent / "restored.tar.gz", "passphrase")

    def test_audit_digest_binds_response_to_exact_transformed_tree(self):
        with tempfile.TemporaryDirectory() as name:
            parent = Path(name); root = self.source(parent); source_file = root / "Orion.yml"
            source_file.write_text("Orion", encoding="utf-8"); fingerprint = approved(("Orion", "project", ["Orion"]))
            request = audit_request(root, fingerprint); audit = self.audit_response(request, [])
            self.assertEqual(request["tree_digest"], audit_request(root, fingerprint)["tree_digest"])
            build(root, fingerprint, parent / "exact.tar.gz", audit=audit, fail_on_ai_findings=True)
            source_file.write_text("Orion changed", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "do not apply"):
                build(root, fingerprint, parent / "changed-content.tar.gz", audit=audit, fail_on_ai_findings=True)
            source_file.rename(root / "OrionRenamed.yml")
            with self.assertRaisesRegex(ValueError, "do not apply"):
                build(root, fingerprint, parent / "changed-path.tar.gz", audit=audit, fail_on_ai_findings=True)
            changed_mapping = approved(("Orion", "internal_system", ["Orion"]))
            self.assertNotEqual(request["tree_digest"], audit_request(root, changed_mapping)["tree_digest"])

    def test_audit_response_and_human_review_validation_fail_closed(self):
        with tempfile.TemporaryDirectory() as name:
            parent = Path(name); root = self.source(parent); (root / "ok.yml").write_text("Orion", encoding="utf-8")
            fingerprint = approved(("Orion", "project", ["Orion"])); request = audit_request(root, fingerprint)
            malformed = {"tree_digest": "sha256:not-a-digest", "batches": []}
            with self.assertRaisesRegex(ValueError, "do not apply"):
                build(root, fingerprint, parent / "malformed.tar.gz", audit=malformed, fail_on_ai_findings=True)
            audit = self.audit_response(request, [{"clue": "clue", "category": "project", "path": "ok.yml", "line": 1, "explanation": "why", "confidence": "medium"}])
            bad_review = {"tree_digest": request["tree_digest"], "dismissals": [{"finding_id": "unknown", "status": "dismissed", "reason": "bad"}]}
            with self.assertRaisesRegex(ValueError, "malformed"):
                build(root, fingerprint, parent / "bad-review.tar.gz", audit=audit, audit_review=bad_review, fail_on_ai_findings=True)

    def test_portable_tokens_and_short_variants_transform_normally(self):
        with tempfile.TemporaryDirectory() as name:
            parent = Path(name); root = self.source(parent); (root / "AD.yml").write_text("AD AD", encoding="utf-8")
            (root / "dirAD").mkdir(); (root / "dirAD" / "other.yml").write_text("aD", encoding="utf-8")
            fingerprint = approved(("AD", "project", ["AD", "aD"]))
            token = approved_replacements(fingerprint)[0][1]
            self.assertFalse(set(token) & set('<>:"/\\|?*'))
            self.assertNotIn(token.upper(), {"CON", "PRN", "AUX", "NUL"})
            preview_data = preview(root, fingerprint)
            self.assertEqual({"AD", "aD"}, {risk["variant"] for risk in preview_data["short_variant_risks"]})
            self.assertEqual(5, sum(risk["occurrences"] for risk in preview_data["short_variant_risks"]))
            build(root, fingerprint, parent / "allowed.tar.gz")
            self.assertNotIn("AD", self.archive_text(parent / "allowed.tar.gz", "__PROJECT_001__.yml"))

    def test_portable_path_collisions_are_case_insensitive(self):
        # The host filesystem may itself be case-insensitive, so test the portable collision key directly.
        self.assertEqual(portable_path_key(Path("Foo.yml")), portable_path_key(Path("foo.yml")))
        self.assertEqual(portable_path_key(Path("name.")), portable_path_key(Path("name")))

    def test_audit_coverage_includes_late_high_risk_and_end_of_file_content(self):
        with tempfile.TemporaryDirectory() as name:
            root = self.source(Path(name)); (root / "aaa.py").write_text("x\n", encoding="utf-8")
            (root / "zzz.tf").write_text("line\n" * 120 + "internal_orion_clue\n", encoding="utf-8")
            request = audit_request(root, approved(("unused", "project", ["unused"])))
            chunks = [chunk for batch in request["batches"] for chunk in batch["semantic_chunks"]]
            self.assertTrue(any(chunk["path"] == "zzz.tf" and chunk["end_line"] >= 121 for chunk in chunks))


if __name__ == "__main__":
    unittest.main()
