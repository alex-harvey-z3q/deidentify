import os
import tarfile
import tempfile
import unittest
from pathlib import Path

from deidentify.engine import MAX_FILE_BYTES, ai_review_request, audit_request, build, build_plan, import_review, initial_fingerprint, preview, scan


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
            self.assertEqual({"docs/<PROJECT_001>/<CUSTOMER_001>/<INTERNAL_SYSTEM_001>.yml"}, names)

    def test_path_collision_fails_closed(self):
        with tempfile.TemporaryDirectory() as name:
            parent = Path(name); root = self.source(parent)
            for directory in ("customer-acme", "customer-foo"):
                (root / directory).mkdir(); (root / directory / "config.yml").write_text("ok", encoding="utf-8")
            fingerprint = approved(("Customer", "customer", ["customer-acme", "customer-foo"]))
            with self.assertRaisesRegex(ValueError, "Path collision"):
                build(root, fingerprint, parent / "release.tar.gz")

    def test_overlap_case_and_crlf_replacement_is_longest_first(self):
        with tempfile.TemporaryDirectory() as name:
            parent = Path(name); root = self.source(parent)
            original = "OrionApi\r\norion-api\r\nORION_API\r\nhttps://orion-api.internal/v1\r\n"
            (root / "service.yml").write_bytes(original.encode())
            fingerprint = approved(("Orion API", "internal_system", ["OrionApi", "orion-api", "ORION_API", "orion-api.internal"]))
            output = parent / "release.tar.gz"; build(root, fingerprint, output)
            content = self.archive_text(output, "service.yml")
            self.assertNotIn("orion", content.casefold())
            self.assertIn("<INTERNAL_SYSTEM_001>", content)
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
            fingerprint, added, _ = import_review(initial_fingerprint(), {"entries": [{"canonical": "ProjectOrion", "category": "project", "variants": ["ProjectOrion"], "status": "approved", "confidence": "high", "rationale": "test", "evidence": []}]})
            self.assertEqual(1, added); self.assertEqual("candidate", fingerprint["entries"][0]["status"])

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
            audit = {"findings": [{"clue": "unique architecture", "confidence": "high", "status": "open"}]}
            with self.assertRaisesRegex(ValueError, "audit has 1"):
                build(root, fingerprint, parent / "blocked.tar.gz", audit=audit, fail_on_ai_findings=True)
            build(root, fingerprint, parent / "allowed.tar.gz", audit={"findings": [{"clue": "reviewed", "confidence": "high", "status": "dismissed"}]}, fail_on_ai_findings=True)

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
                info = archive.getmember("<PROJECT_001>.yml")
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
            fingerprint = approved(("Orion", "project", ["Orion", "<PROJECT_001>"]))
            with self.assertRaisesRegex(ValueError, "Final check"):
                build(root, fingerprint, parent / "release.tar.gz")


if __name__ == "__main__":
    unittest.main()
