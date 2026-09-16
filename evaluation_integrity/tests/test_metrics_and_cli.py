import json
import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from evaluation_integrity.adapters import ArtifactError, adapt, load_json
from evaluation_integrity.audit import build_audit, main, markdown
from evaluation_integrity.evidence_audit import audit_findings
from evaluation_integrity.metrics import diagnose_metrics


class MetricTests(unittest.TestCase):
    def test_occurrences_and_unique_production_issues_differ(self):
        findings = [{"finding_id": "f1", "issue_id": "i1", "parameter_name": "id"},
                    {"finding_id": "f2", "issue_id": "i1", "parameter_name": "id"},
                    {"finding_id": "f3", "issue_id": "i2", "parameter_name": "name"}]
        evidence = {"diagnostics": []}
        result = diagnose_metrics(findings, evidence)
        self.assertEqual(result["finding_occurrences"], 3)
        self.assertEqual(result["unique_issues"], 2)

    def test_missing_issue_identity_is_unknown_not_estimated(self):
        result = diagnose_metrics([{"finding_id": "f1", "issue_id": ""}], {"diagnostics": []})
        self.assertIsNone(result["unique_issues"])
        self.assertEqual(result["unique_issue_identity_basis"], "unavailable")

    def test_repeated_proof_cannot_multiply_proof_status(self):
        findings = [{"finding_id": "f1", "issue_id": "i1"},
                    {"finding_id": "f2", "issue_id": "i1"}]
        evidence = {"diagnostics": [
            {"finding_id": "f1", "support": "supported", "proof_id": "p1"},
            {"finding_id": "f2", "support": "supported", "proof_id": "p1"},
        ]}
        result = diagnose_metrics(findings, evidence)
        self.assertEqual(result["proof_supported_confirmation_occurrences"], 2)
        self.assertEqual(result["distinct_supporting_proofs"], 1)

    def test_case_sensitive_input_names_remain_distinct(self):
        findings = [{"finding_id": "f1", "issue_id": "i1", "parameter_location": "query",
                     "parameter_name": "userId"},
                    {"finding_id": "f2", "issue_id": "i2", "parameter_location": "query",
                     "parameter_name": "userid"}]
        result = diagnose_metrics(findings, {"diagnostics": []})
        self.assertEqual(result["unique_issues"], 2)
        self.assertEqual(len(result["casefold_collisions_preserved_as_distinct"]), 1)

    def test_endpoint_known_recall_is_not_whole_target_recall(self):
        metrics = {"labelled_items": [{"item_id": "GT01", "status": "missed"}]}
        result = diagnose_metrics([], {"diagnostics": []}, metrics=metrics,
                                  benchmark_scope="endpoint_known_items")
        self.assertIn("endpoint_known_detection_recall", result["metric_names"])
        self.assertTrue(any("not whole-target" in item for item in result["warnings"]))

    def test_missing_labels_prevent_confusion_claims(self):
        result = diagnose_metrics([], {"diagnostics": []}, metrics={"recall": 1.0})
        self.assertFalse(result["confusion_matrix_independently_derivable"])
        self.assertTrue(any("TP/FP/FN" in item for item in result["warnings"]))

    def test_labels_without_complete_evidence_inputs_are_not_enough(self):
        result = diagnose_metrics([], {"diagnostics": []},
                                  metrics={"labelled_items": [{"item_id": "x", "status": "hit"}],
                                           "confusion_inputs_complete": False})
        self.assertFalse(result["confusion_matrix_independently_derivable"])


class AdapterAndCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def write(self, name, value):
        path = self.root / name
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def test_unsupported_schema_is_reported(self):
        with self.assertRaises(ArtifactError):
            adapt({"schema_version": "future/v9"}, "future.json")

    def test_invalid_json_cannot_produce_clean_audit(self):
        path = self.root / "bad.json"
        path.write_text("not json", encoding="utf-8")
        report = build_audit([path])
        self.assertFalse(report["audit_valid"])
        self.assertTrue(report["errors"])
        with redirect_stdout(io.StringIO()):
            self.assertEqual(main(["--input", str(path)]), 2)

    def test_source_remains_byte_for_byte_unchanged(self):
        bundle = {"schema_version": "evaluation-integrity-input/v1", "findings": [],
                  "proofs": [], "cases": [], "artifacts": []}
        path = self.write("bundle.json", bundle)
        before = path.read_bytes()
        _, source = load_json(path)
        self.assertEqual(path.read_bytes(), before)
        self.assertTrue(source["source_unchanged_during_read"])

    def test_generic_adapter_extracts_case_embedded_in_proof(self):
        document = {"schema_version": "evaluation-integrity-input/v1", "findings": [],
                    "proofs": [{"proof_id": "p1", "case": {"case_id": "c1"}}],
                    "cases": [], "artifacts": []}
        normalized = adapt(document, "bundle.json")
        self.assertEqual(normalized["cases"], [{"case_id": "c1"}])

    def test_output_omits_raw_sensitive_fields(self):
        bundle = {"schema_version": "evaluation-integrity-input/v1",
                  "findings": [{"id": "f1", "confirmed": True, "evidence": "SECRET",
                                "request_body": "PASSWORD"}],
                  "proofs": [], "cases": [], "artifacts": []}
        path = self.write("bundle.json", bundle)
        output = json.dumps(build_audit([path]))
        self.assertNotIn("SECRET", output)
        self.assertNotIn("PASSWORD", output)

    def test_process_and_evaluation_validity_are_separate(self):
        bundle = {"schema_version": "evaluation-integrity-input/v1", "findings": [],
                  "proofs": [], "cases": [], "artifacts": [],
                  "process": {"finished": True}, "health_controls": []}
        report = build_audit([self.write("bundle.json", bundle)])
        self.assertTrue(report["process_outcome"]["finished"])
        self.assertEqual(report["evaluation_validity"], "unknown")
        self.assertIn("does not imply", " ".join(report["warnings"]))

    def test_markdown_contains_denominators(self):
        bundle = {"schema_version": "evaluation-integrity-input/v1", "findings": [],
                  "proofs": [], "cases": [], "artifacts": [],
                  "coverage": {"total_cells": 2, "attempted": 1}}
        report = build_audit([self.write("bundle.json", bundle)])
        self.assertIn("1 / 2 (50.0%)", markdown(report))


if __name__ == "__main__":
    unittest.main()
