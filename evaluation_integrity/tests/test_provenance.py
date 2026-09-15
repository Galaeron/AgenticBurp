import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from evaluation_integrity.provenance import check_manifest


class ManifestTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.artifact = self.root / "result.json"
        self.artifact.write_text('{"invocation_id":"run-1"}', encoding="utf-8")
        digest = hashlib.sha256(self.artifact.read_bytes()).hexdigest()
        self.manifest = {
            "schema_version": "evaluation-integrity-manifest/v1",
            "experiment_id": "experiment-1",
            "invocation_id": "run-1",
            "revision": "abc123",
            "dirty_tree": False,
            "config_fingerprint": "sha256:config",
            "corpus": {"identifier": "synthetic", "version": "1"},
            "artifacts": [{"path": "result.json", "sha256": digest,
                           "invocation_id": "run-1"}],
            "scoring_policy_version": "policy-1",
            "model_prompt": {"relevant": False},
            "evaluation_mode": "fresh_end_to_end",
            "created_at": "2026-09-15T00:00:00Z",
        }

    def tearDown(self):
        self.temp.cleanup()

    def test_fresh_evaluation_of_stated_build(self):
        result = check_manifest(self.manifest, self.root)
        self.assertTrue(result["valid"])
        self.assertEqual(result["provenance"], "fresh_stated_build")

    def test_rejects_mismatched_hash(self):
        self.manifest["artifacts"][0]["sha256"] = "0" * 64
        result = check_manifest(self.manifest, self.root)
        self.assertFalse(result["valid"])
        self.assertIn("hash mismatch", " ".join(result["errors"]))

    def test_rejects_wrong_invocation_id(self):
        self.manifest["artifacts"][0]["invocation_id"] = "other-run"
        result = check_manifest(self.manifest, self.root)
        self.assertIn("invocation_id", " ".join(result["errors"]))

    def test_rejects_artifact_content_with_wrong_invocation_id(self):
        self.artifact.write_text('{"invocation_id":"other-run"}', encoding="utf-8")
        self.manifest["artifacts"][0]["sha256"] = hashlib.sha256(self.artifact.read_bytes()).hexdigest()
        result = check_manifest(self.manifest, self.root)
        self.assertIn("content invocation_id", " ".join(result["errors"]))

    def test_rejects_missing_metadata(self):
        del self.manifest["config_fingerprint"]
        result = check_manifest(self.manifest, self.root)
        self.assertIn("config_fingerprint", " ".join(result["errors"]))

    def test_rejects_unsupported_schema_version(self):
        self.manifest["schema_version"] = "evaluation-integrity-manifest/v99"
        result = check_manifest(self.manifest, self.root)
        self.assertIn("unsupported", " ".join(result["errors"]))

    def test_historical_rescore_is_valid_but_not_fresh(self):
        self.manifest["evaluation_mode"] = "historical_rescore"
        result = check_manifest(self.manifest, self.root)
        self.assertTrue(result["valid"])
        self.assertEqual(result["provenance"], "historical_rescore")
        self.assertTrue(any("not fresh" in item for item in result["warnings"]))

    def test_dirty_tree_cannot_be_equated_with_revision(self):
        self.manifest["dirty_tree"] = True
        result = check_manifest(self.manifest, self.root)
        self.assertEqual(result["provenance"], "unknown_or_mismatched")

    def test_credentials_are_not_required_or_emitted(self):
        result = check_manifest(self.manifest, self.root)
        self.assertNotIn("credential", json.dumps(result).lower())


if __name__ == "__main__":
    unittest.main()
