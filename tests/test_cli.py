import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from deidentify.engine import audit_request


class CliTests(unittest.TestCase):
    def run_cli(self, *args: str) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(Path(__file__).parents[1] / "src")
        return subprocess.run([sys.executable, "-m", "deidentify", *args], cwd=Path(__file__).parents[1], env=environment, text=True, capture_output=True, check=False)

    def fingerprint(self, path: Path) -> dict:
        value = {"schema_version": 1, "entries": [{"canonical": "Orion", "category": "project", "variants": ["Orion"], "status": "approved"}]}
        path.write_text(json.dumps(value), encoding="utf-8")
        return value

    def audit_response(self, request: dict, findings: list[dict]) -> dict:
        return {"tree_digest": request["tree_digest"], "batches": [{"batch_id": batch["batch_id"], "batch_digest": batch["batch_digest"], "findings": findings if index == 0 else []} for index, batch in enumerate(request["batches"])]}

    def test_actual_cli_audit_gate_and_human_dismissal(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name); source = root / "source"; source.mkdir(); (source / "ok.yml").write_text("Orion", encoding="utf-8")
            fingerprint_path = root / "fingerprint.json"; fingerprint = self.fingerprint(fingerprint_path)
            request = audit_request(source, fingerprint)
            audit_path = root / "audit.json"
            audit_path.write_text(json.dumps(self.audit_response(request, [{"clue": "unique clue", "category": "project", "path": "ok.yml", "line": 1, "explanation": "distinctive", "confidence": "high", "status": "dismissed"}])), encoding="utf-8")
            advisory = self.run_cli("build", str(source), str(fingerprint_path), str(root / "advisory.tar.gz"), "--audit-findings", str(audit_path))
            self.assertEqual(0, advisory.returncode, advisory.stderr)
            blocked = self.run_cli("build", str(source), str(fingerprint_path), str(root / "blocked.tar.gz"), "--audit-findings", str(audit_path), "--fail-on-ai-findings")
            self.assertEqual(2, blocked.returncode)
            self.assertIn("open medium/high", blocked.stderr)
            template_path = root / "review.json"
            template = self.run_cli("audit-review-template", str(source), str(fingerprint_path), str(audit_path), "--output", str(template_path))
            self.assertEqual(0, template.returncode, template.stderr)
            review = json.loads(template_path.read_text(encoding="utf-8")); review["dismissals"] = [{"finding_id": review["findings"][0]["finding_id"], "status": "dismissed", "reason": "Human verified this is generic."}]
            template_path.write_text(json.dumps(review), encoding="utf-8")
            allowed = self.run_cli("build", str(source), str(fingerprint_path), str(root / "allowed.tar.gz"), "--audit-findings", str(audit_path), "--audit-review", str(template_path), "--fail-on-ai-findings")
            self.assertEqual(0, allowed.returncode, allowed.stderr)

    def test_actual_cli_rejects_stale_and_partial_audit_responses(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name); source = root / "source"; source.mkdir(); (source / "ok.yml").write_text("Orion", encoding="utf-8")
            fingerprint_path = root / "fingerprint.json"; fingerprint = self.fingerprint(fingerprint_path); request = audit_request(source, fingerprint)
            stale = self.audit_response(request, []); stale["tree_digest"] = "sha256:" + "0" * 64
            stale_path = root / "stale.json"; stale_path.write_text(json.dumps(stale), encoding="utf-8")
            result = self.run_cli("build", str(source), str(fingerprint_path), str(root / "stale.tar.gz"), "--audit-findings", str(stale_path), "--fail-on-ai-findings")
            self.assertEqual(2, result.returncode); self.assertIn("do not apply", result.stderr)
            partial = {"tree_digest": request["tree_digest"], "batches": []}
            partial_path = root / "partial.json"; partial_path.write_text(json.dumps(partial), encoding="utf-8")
            result = self.run_cli("build", str(source), str(fingerprint_path), str(root / "partial.tar.gz"), "--audit-findings", str(partial_path), "--fail-on-ai-findings")
            self.assertEqual(2, result.returncode); self.assertIn("missing", result.stderr)

    def test_actual_cli_rejects_workflow_artifacts_inside_source(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name); source = root / "source"; source.mkdir(); (source / "ok.yml").write_text("Orion", encoding="utf-8")
            fingerprint_path = root / "fingerprint.json"; self.fingerprint(fingerprint_path)
            init = self.run_cli("init", str(source), str(source / "fingerprint.json"))
            self.assertEqual(2, init.returncode); self.assertIn("outside the source repository", init.stderr)
            for command in (("scan", str(source), "--report", str(source / "report.json"), "--ai-review-request", str(root / "request.json")), ("audit-request", str(source), str(fingerprint_path), "--output", str(source / "audit.json")), ("preview", str(source), str(fingerprint_path), "--output", str(source / "preview.json")), ("build", str(source), str(fingerprint_path), str(source / "archive.tar.gz"))):
                result = self.run_cli(*command)
                self.assertEqual(2, result.returncode, result.stdout)
                self.assertIn("outside the source repository", result.stderr)
            self.assertFalse((source / "report.json").exists())
