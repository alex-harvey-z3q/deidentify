import json
import tarfile
import tempfile
import unittest
from pathlib import Path

from deidentify.engine import build, import_review, initial_fingerprint, scan


class EngineTests(unittest.TestCase):
    def test_scan_excludes_git_and_env(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / "app.py").write_text("SERVICE = 'orion-api'\n", encoding="utf-8")
            (root / ".env").write_text("PASSWORD=secret\n", encoding="utf-8")
            (root / ".git").mkdir()
            (root / ".git" / "config").write_text("remote=private\n", encoding="utf-8")
            report = scan(root)
            self.assertEqual(report["source"]["scanned_file_count"], 1)
            self.assertIn("orion-api", {item["term"] for item in report["candidate_inventory"]})
            self.assertIn(".env", {item["path"] for item in report["excluded_files"]})

    def test_review_then_build_replaces_and_omits_map(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name) / "source"
            root.mkdir()
            (root / "service.yml").write_text("name: Orion\nhost: orion.internal\n", encoding="utf-8")
            fingerprint, added, _ = import_review(initial_fingerprint(), {
                "entries": [{
                    "canonical": "Orion",
                    "category": "internal_product",
                    "variants": ["Orion", "orion.internal"],
                    "confidence": "high",
                    "rationale": "internal product",
                    "evidence": [],
                }]
            })
            self.assertEqual(added, 1)
            fingerprint["entries"][0]["status"] = "approved"
            output = Path(name) / "release.tar.gz"
            manifest = build(root, fingerprint, output)
            self.assertTrue(output.exists())
            self.assertTrue(manifest["final_check"]["passed"])
            with tarfile.open(output) as archive:
                content = archive.extractfile("service.yml").read().decode("utf-8")
            self.assertNotIn("Orion", content)
            self.assertNotIn("orion.internal", content)
            self.assertIn("<INTERNAL_PRODUCT_001>", content)
            manifest_text = output.with_suffix(".gz.manifest.json").read_text(encoding="utf-8")
            self.assertNotIn("Orion", manifest_text)


if __name__ == "__main__":
    unittest.main()
