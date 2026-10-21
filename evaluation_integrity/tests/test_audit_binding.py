"""Caller-level tests for ``build_audit`` input binding (R38) and multi-input health (R39).

Synthetic documents only. Each defect-injection test patches the fix with the
behaviour it replaced and shows that the same check then goes red.
"""
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from evaluation_integrity import audit
from evaluation_integrity.audit import build_audit, main
from evaluation_integrity.provenance import load_and_check_manifest

SCHEMA = "evaluation-integrity-input/v1"


def _document(invocation, **extra):
    return {"schema_version": SCHEMA, "invocation_id": invocation, "findings": [], **extra}


def _manifest(invocation, artifacts):
    return {
        "schema_version": "evaluation-integrity-manifest/v1", "experiment_id": "experiment-A",
        "invocation_id": invocation, "revision": "synthetic-revision", "dirty_tree": False,
        "config_fingerprint": "synthetic-config", "corpus": {"identifier": "synthetic", "version": "1"},
        "scoring_policy_version": "1", "model_prompt": {"relevant": False},
        "evaluation_mode": "fresh_end_to_end", "created_at": "2026-10-19T00:00:00Z",
        "artifacts": artifacts,
    }


class _Bundle:
    """A temp directory holding a manifest for run-A and the files it hashes."""

    def __init__(self, testcase):
        temp = tempfile.TemporaryDirectory()
        testcase.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.entries = []

    def write(self, name, document, *, in_manifest=False, invocation="run-A"):
        path = self.root / name
        path.write_text(json.dumps(document), encoding="utf-8")
        if in_manifest:
            self.entries.append({"path": name, "invocation_id": invocation,
                                 "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
        return path

    def manifest(self):
        path = self.root / "manifest.json"
        path.write_text(json.dumps(_manifest("run-A", self.entries)), encoding="utf-8")
        return path


def _check_unrelated_input_not_certified(testcase):
    bundle = _Bundle(testcase)
    bundle.write("covered.json", _document("run-A"), in_manifest=True)
    unrelated = bundle.write("unrelated.json", _document("run-B"))
    report = build_audit([unrelated], bundle.manifest(), bundle.root)
    provenance = report["provenance"]
    testcase.assertNotEqual(provenance["provenance"], "fresh_stated_build")
    testcase.assertFalse(provenance["valid"])
    testcase.assertTrue(any("not in the manifest's hashed artifact set" in e for e in provenance["errors"]))


class ManifestBindingTests(unittest.TestCase):
    def test_input_outside_the_manifest_is_not_certified(self):  # R38
        _check_unrelated_input_not_certified(self)

    def test_matching_input_is_certified(self):  # control
        bundle = _Bundle(self)
        covered = bundle.write("covered.json", _document("run-A"), in_manifest=True)
        report = build_audit([covered], bundle.manifest(), bundle.root)
        self.assertEqual(report["provenance"]["provenance"], "fresh_stated_build")
        self.assertTrue(report["provenance"]["valid"])
        self.assertEqual([i["covered_by_manifest"] for i in report["provenance"]["bound_inputs"]], [True])

    def test_byte_identical_copy_elsewhere_is_certified(self):  # control: binding is by content
        bundle = _Bundle(self)
        covered = bundle.write("covered.json", _document("run-A"), in_manifest=True)
        copy = bundle.root / "copy-of-covered.json"
        copy.write_bytes(covered.read_bytes())
        report = build_audit([copy], bundle.manifest(), bundle.root)
        self.assertEqual(report["provenance"]["provenance"], "fresh_stated_build")

    def test_same_invocation_id_with_different_bytes_is_not_certified(self):
        bundle = _Bundle(self)
        bundle.write("covered.json", _document("run-A"), in_manifest=True)
        tampered = bundle.write("tampered.json", _document("run-A", findings=[{"finding_id": "extra"}]))
        report = build_audit([tampered], bundle.manifest(), bundle.root)
        self.assertNotEqual(report["provenance"]["provenance"], "fresh_stated_build")

    def test_hashed_input_naming_another_invocation_is_not_certified(self):
        # Only *.json manifest artifacts get a content invocation check from the manifest
        # itself, so an opaque-suffixed input must be bound by the audit.
        bundle = _Bundle(self)
        foreign = bundle.write("input.dat", _document("run-B"), in_manifest=True)
        report = build_audit([foreign], bundle.manifest(), bundle.root)
        self.assertNotEqual(report["provenance"]["provenance"], "fresh_stated_build")
        self.assertTrue(any("run-B" in e for e in report["provenance"]["errors"]))

    def test_one_unbound_input_denies_certification_to_all(self):
        bundle = _Bundle(self)
        covered = bundle.write("covered.json", _document("run-A"), in_manifest=True)
        unrelated = bundle.write("unrelated.json", _document("run-B"))
        for order in ([covered, unrelated], [unrelated, covered]):
            with self.subTest(order=[p.name for p in order]):
                report = build_audit(order, bundle.manifest(), bundle.root)
                self.assertNotEqual(report["provenance"]["provenance"], "fresh_stated_build")

    def test_manifest_with_malformed_artifacts_is_reported_not_a_crash(self):
        bundle = _Bundle(self)
        document = bundle.write("input.json", _document("run-A"))
        for artifacts in (5, "x", {"path": "input.json"}, [5, None]):
            with self.subTest(artifacts=artifacts):
                manifest = bundle.root / "manifest.json"
                manifest.write_text(json.dumps(_manifest("run-A", artifacts)), encoding="utf-8")
                report = build_audit([document], manifest, bundle.root)
                self.assertEqual(report["provenance"]["provenance"], "unknown_or_mismatched")
                self.assertFalse(report["provenance"]["valid"])

    def test_unreadable_or_non_object_manifest_is_reported(self):
        bundle = _Bundle(self)
        document = bundle.write("input.json", _document("run-A"))
        missing = bundle.root / "absent.json"
        listy = bundle.root / "list.json"
        listy.write_text("[]", encoding="utf-8")
        for manifest in (missing, listy):
            with self.subTest(manifest=manifest.name):
                report = build_audit([document], manifest, bundle.root)
                self.assertEqual(report["provenance"]["provenance"], "unknown_or_mismatched")
                self.assertFalse(report["provenance"]["valid"])

    def test_command_line_reports_the_binding(self):
        bundle = _Bundle(self)
        bundle.write("covered.json", _document("run-A"), in_manifest=True)
        unrelated = bundle.write("unrelated.json", _document("run-B"))
        out = bundle.root / "report.json"
        main(["--input", str(unrelated), "--manifest", str(bundle.manifest()),
              "--bundle-root", str(bundle.root), "--json", str(out)])
        report = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(report["provenance"]["provenance"], "unknown_or_mismatched")
        self.assertEqual([i["covered_by_manifest"] for i in report["provenance"]["bound_inputs"]], [False])


def _control(outcome):
    return {"health_controls": [{"kind": "ordinary_application", "outcome": outcome,
                                 "control_id": outcome, "affected_interval": [1, 2]}]}


def _audit_documents(testcase, documents):
    temp = tempfile.TemporaryDirectory()
    testcase.addCleanup(temp.cleanup)
    paths = []
    for index, extra in enumerate(documents):
        path = Path(temp.name) / f"input-{index}.json"
        path.write_text(json.dumps(_document("same-run", **extra)), encoding="utf-8")
        paths.append(path)
    return build_audit(paths)


def _check_later_failed_control_is_kept(testcase):
    report = _audit_documents(testcase, [_control("pass"), _control("fail")])
    testcase.assertEqual(report["evaluation_validity"], "invalid_for_affected_intervals")
    testcase.assertEqual([i["control_id"] for i in report["health"]["failed_intervals"]], ["fail"])


class MultiInputHealthTests(unittest.TestCase):
    def test_later_failed_control_is_not_discarded(self):  # R39
        _check_later_failed_control_is_kept(self)

    def test_failed_control_first_is_still_invalid(self):  # control (the order that already worked)
        report = _audit_documents(self, [_control("fail"), _control("pass")])
        self.assertEqual(report["evaluation_validity"], "invalid_for_affected_intervals")

    def test_all_passing_inputs_stay_valid(self):  # control
        report = _audit_documents(self, [_control("pass"), _control("pass")])
        self.assertEqual(report["evaluation_validity"], "valid_for_controlled_intervals")
        self.assertEqual(report["health"]["ordinary_control_count"], 2)

    def test_input_without_controls_does_not_hide_a_failure_on_another(self):
        for documents in ([{}, _control("fail")], [_control("fail"), {}]):
            with self.subTest(first_has_controls="health_controls" in documents[0]):
                report = _audit_documents(self, documents)
                self.assertEqual(report["evaluation_validity"], "invalid_for_affected_intervals")

    def test_malformed_controls_on_a_later_input_are_not_dropped(self):
        report = _audit_documents(self, [_control("pass"), {"health_controls": "pass"}])
        self.assertEqual(report["evaluation_validity"], "unknown")

    def test_logs_from_every_input_are_counted(self):
        logs = lambda service: {"logs": [{"service": service, "timestamp": 1, "status": 200}]}
        report = _audit_documents(self, [logs("target"), logs("proxy")])
        self.assertEqual(report["health"]["log_summary"]["records_by_service"], {"proxy": 1, "target": 1})


class DefectInjectionTests(unittest.TestCase):
    """The checks above must go red when the fixes are removed."""

    def test_removing_input_binding_is_detected(self):
        def unbound(manifest, bundle_root, sources, normalized):  # the pre-fix behaviour
            return load_and_check_manifest(manifest, bundle_root)

        with mock.patch.object(audit, "_manifest_provenance", unbound):
            with self.assertRaises(AssertionError):
                _check_unrelated_input_not_certified(self)

    def test_taking_only_the_first_input_health_is_detected(self):
        with mock.patch.object(audit, "_merged", lambda records, key, malformed: audit._first(records, key)):
            with self.assertRaises(AssertionError):
                _check_later_failed_control_is_kept(self)


if __name__ == "__main__":
    unittest.main()
