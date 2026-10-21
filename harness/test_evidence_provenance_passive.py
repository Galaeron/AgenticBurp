"""R15 passive controls: temp Git/SQLite only; no target or model calls."""
import hashlib
from contextlib import closing
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from harness import evidence_ledger as el, source_identity as si, store
from harness.agents.base_agent import BaseAgent
from harness.models import Finding


class SourceIdentityTests(unittest.TestCase):
    def test_installed_package_without_git_has_content_identity_not_invented_head(self):
        with tempfile.TemporaryDirectory() as tmp:
            # Resolve: Windows temp dirs can be 8.3 short names (RUNNER~1).
            root = Path(tmp).resolve()
            package = root / "harness"
            package.mkdir()
            source = package / "ordinary.py"
            source.write_text("VALUE = 1\n", encoding="utf-8")
            local = package / "config.local.yaml"
            local.write_text("synthetic private local config", encoding="utf-8")
            sibling = root / "unrelated"
            sibling.mkdir()
            (sibling / "module.py").write_text("unrelated", encoding="utf-8")
            original_read = Path.read_bytes
            def only_source(path):
                self.assertEqual(path, source)
                return original_read(path)
            with patch.object(si.subprocess, "run", side_effect=FileNotFoundError("no Git")), \
                    patch.object(Path, "read_bytes", only_source):
                first = si.capture_source_snapshot(root)
                source.write_text("VALUE = 2\n", encoding="utf-8")
                second = si.capture_source_snapshot(root)
            self.assertEqual(first.status, "captured")
            self.assertEqual(first.head, "unknown")
            self.assertIsNone(first.dirty)
            self.assertEqual(first.file_count, 1)
            self.assertNotEqual(first.content_id, second.content_id)
            self.assertIn("installed harness", first.scope)
            a = el.Provenance.capture(source_snapshot=first)
            b = el.Provenance.capture(source_snapshot=second)
            self.assertNotEqual(a.source_identity["content_id"], b.source_identity["content_id"])

    def test_same_head_changed_bytes_and_excluded_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            def git(*args):
                subprocess.run(["git", *args], cwd=root, check=True, capture_output=True)
            git("init")
            path = root / "harness" / "benign.py"
            path.parent.mkdir()
            path.write_text("VALUE = 1\n")
            git("add", "harness/benign.py")
            git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                "commit", "-m", "benign fixture")
            first = si.capture_source_snapshot(root)
            self.assertEqual(first.status, "captured")
            self.assertFalse(first.dirty)
            path.write_text("VALUE = 2\n")
            second = si.capture_source_snapshot(root)
            self.assertEqual(first.head, second.head)
            self.assertNotEqual(first.content_id, second.content_id)
            self.assertTrue(second.dirty)
            # Never open excluded files, even when tracked or untracked.
            excluded = root / "harness" / "config.local.yaml"
            excluded.write_text("synthetic local fixture")
            excluded_key = root / "harness" / "fixture_ANSWER_KEY.py"
            excluded_key.write_text("synthetic forbidden fixture")
            git("add", "harness/config.local.yaml", "harness/fixture_ANSWER_KEY.py")
            original_read = Path.read_bytes
            def guarded_read(p):
                self.assertNotIn(p, {excluded, excluded_key})
                return original_read(p)
            with patch.object(Path, "read_bytes", guarded_read):
                third = si.capture_source_snapshot(root)
            self.assertEqual(second.content_id, third.content_id)
            a = el.Provenance.capture(source_snapshot=first, model="model-a")
            b = el.Provenance.capture(source_snapshot=second, model="model-a")
            self.assertNotEqual(a.source_identity["content_id"], b.source_identity["content_id"])
            self.assertEqual(a.model, b.model)

    def test_process_snapshot_is_captured_once_with_explicit_lifetime(self):
        si.process_source_snapshot.cache_clear()
        try:
            with patch.object(si, "capture_source_snapshot", return_value=si.SourceSnapshot(
                    content_id="sha256:benign", status="captured")) as capture:
                a = el.Provenance.capture()
                b = el.Provenance.capture()
            capture.assert_called_once()
            self.assertEqual(a.source_identity, b.source_identity)
            self.assertIn("process snapshot", a.source_identity["lifetime"])
        finally:
            si.process_source_snapshot.cache_clear()


class PassivePersistenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = patch.object(store, "_DB_PATH", Path(self.tmp.name) / "evidence.db")
        self.db.start()
        self.status = patch.object(el, "_PERSISTENCE_FAILURES", 0)
        self.status.start()
        el.reset_default_ledger(max_events=3)

    def tearDown(self):
        el.reset_default_ledger()
        self.status.stop()
        self.db.stop()
        self.tmp.cleanup()

    def test_passive_agent_caller_failure_visible_sanitized_and_bounded(self):
        class PassiveAgent(BaseAgent):
            name = "passive_fixture"
            @property
            def specialty_prompt(self):
                return "benign captured observation"
        agent = PassiveAgent(None, model="fixture")
        finding = Finding(vulnerability_class="information_disclosure", summary="captured marker",
                          evidence="benign fixture", severity="info", confidence=0.2,
                          suggested_test="review captured observation", basis="response")
        with patch.object(store, "persist_ledger_event", side_effect=OSError("SECRET_SENTINEL")):
            with self.assertLogs("harness.evidence_ledger", level="WARNING") as logs:
                agent._emit_hypotheses([finding])
                for _ in range(9):
                    el.emit(el.EventType.OBSERVATION, finding.finding_id, "benign capture")
        self.assertNotIn("SECRET_SENTINEL", " ".join(logs.output))
        self.assertIn("incomplete", logs.output[0])
        self.assertEqual(finding.confidence, 0.2)
        self.assertTrue(el.evidence_write_status()["persistence_degraded"])
        self.assertLessEqual(len(el.get_default_ledger()), 3)
        memory = el.get_default_ledger().reconstruct(finding.finding_id)
        self.assertTrue(memory["completeness"]["persistence_degraded"])
        # Failure marker eviction/default-ledger reset cannot make durable reads green.
        el.reset_default_ledger()
        el.emit(el.EventType.FINDING_REVISION, finding.finding_id, "passive review concluded")
        one = el.reconstruct_persisted(finding.finding_id)
        many = el.reconstruct_persisted_many([finding.finding_id])[finding.finding_id]
        self.assertEqual(one, many)
        self.assertFalse(one["complete"])
        self.assertFalse(one["completeness"]["resolvable"])
        # Persisted degraded payload survives a simulated process status loss.
        with patch.object(el, "_PERSISTENCE_FAILURES", 0):
            self.assertFalse(el.reconstruct_persisted(finding.finding_id)["complete"])

    def test_successful_passive_caller_and_emit_disabled_negative_control(self):
        class PassiveAgent(BaseAgent):
            name = "passive_fixture"
            @property
            def specialty_prompt(self):
                return "benign capture"
        agent = PassiveAgent(None, model="fixture")
        finding = Finding(vulnerability_class="information_disclosure", summary="captured marker",
                          evidence="benign", severity="info", confidence=0.2,
                          suggested_test="review captured observation", basis="response")
        with patch.object(el, "emit", return_value=None):
            agent._emit_hypotheses([finding])
        self.assertEqual(store.ledger_events_for(finding.finding_id), [])
        agent._emit_hypotheses([finding])
        row = store.ledger_events_for(finding.finding_id)[0]
        self.assertEqual(row["event_type"], "hypothesis")
        self.assertEqual(row["provenance"]["source_identity"]["status"], "captured")
        el.emit(el.EventType.FINDING_REVISION, finding.finding_id, "passive review concluded")
        self.assertTrue(el.reconstruct_persisted(finding.finding_id)["complete"])
        self.assertFalse(el.evidence_write_status()["persistence_degraded"])

    def test_exported_synthetic_blob_pair_hash_checks_and_tamper_fails(self):
        # Metadata only: no transport, no execution, no target call.
        req, resp = b"benign captured request", b"benign captured response"
        req_hash, resp_hash = store.put_evidence_blob(req), store.put_evidence_blob(resp)
        self.assertEqual(req_hash, hashlib.sha256(req).hexdigest())
        event = el.emit(el.EventType.EXECUTION, "synthetic", "fixture metadata",
                        data={"request": "fixture", "response": "fixture",
                              "request_blob": req_hash, "response_blob": resp_hash})
        original = event.to_dict()
        el.emit(el.EventType.FINDING_REVISION, "synthetic", "passive fixture reviewed")
        good = el.reconstruct_persisted("synthetic")
        self.assertTrue(good["completeness"]["resolvable"])
        self.assertTrue(store.evidence_blob_resolves(req_hash))
        with closing(store._connect()) as conn:
            with conn:
                conn.execute("UPDATE evidence_blobs SET data=? WHERE sha256=?", (b"tampered", resp_hash))
        bad = el.reconstruct_persisted("synthetic")
        self.assertFalse(bad["completeness"]["resolvable"])
        self.assertFalse(bad["completeness"]["has_response_blob"])
        self.assertEqual(event.to_dict(), original)

    def test_write_loss_downgrades_previously_resolving_durable_chain(self):
        req = store.put_evidence_blob(b"benign captured request")
        resp = store.put_evidence_blob(b"benign captured response")
        event = el.emit(el.EventType.EXECUTION, "prior", "fixture metadata",
                        data={"request": "fixture", "response": "fixture",
                              "request_blob": req, "response_blob": resp})
        el.emit(el.EventType.FINDING_REVISION, "prior", "passive review concluded")
        before = el.reconstruct_persisted("prior")
        self.assertTrue(before["complete"])
        self.assertTrue(before["completeness"]["resolvable"])
        original = event.to_dict()
        with patch.object(store, "persist_ledger_event", side_effect=OSError("synthetic failure")):
            with self.assertLogs("harness.evidence_ledger", level="WARNING"):
                el.emit(el.EventType.OBSERVATION, "prior", "another benign capture")
        after = el.reconstruct_persisted("prior")
        self.assertTrue(after["completeness"]["has_conclusion"])
        self.assertFalse(after["complete"])
        self.assertFalse(after["completeness"]["resolvable"])
        recipe = el.reproduction_recipe_persisted("prior")
        self.assertFalse(recipe["resolvable"])
        self.assertFalse(recipe["steps"][0]["replayable"])
        self.assertEqual(event.to_dict(), original)

    def test_each_failed_finding_keeps_a_durable_marker_after_process_loss(self):
        # Two already-supported metadata chains; only observation writes fail.
        # Marker writes succeed, so process loss must not erase either loss.
        req = store.put_evidence_blob(b"benign captured request")
        resp = store.put_evidence_blob(b"benign captured response")
        for ref in ("first", "second"):
            el.emit(el.EventType.EXECUTION, ref, "fixture metadata",
                    data={"request": "fixture", "response": "fixture",
                          "request_blob": req, "response_blob": resp})
            el.emit(el.EventType.FINDING_REVISION, ref, "passive review concluded")
            self.assertTrue(el.reconstruct_persisted(ref)["complete"])
        persist = store.persist_ledger_event
        def reject_observations(event):
            if event["event_type"] == "observation":
                raise OSError("synthetic rejected event")
            return persist(event)
        with patch.object(store, "persist_ledger_event", side_effect=reject_observations):
            with self.assertLogs("harness.evidence_ledger", level="WARNING"):
                for ref in ("first", "second"):
                    el.emit(el.EventType.OBSERVATION, ref, "another benign capture")
        self.assertLessEqual(len(el.get_default_ledger()), 3)
        el.reset_default_ledger()
        with patch.object(el, "_PERSISTENCE_FAILURES", 0):
            many = el.reconstruct_persisted_many(["first", "second"])
            for ref in ("first", "second"):
                one = el.reconstruct_persisted(ref)
                self.assertEqual(one, many[ref])
                self.assertFalse(one["complete"], ref)
                self.assertFalse(one["completeness"]["resolvable"], ref)
                self.assertTrue(one["completeness"]["persistence_degraded"], ref)
                self.assertTrue(any(row["event_type"] == "persistence_failure"
                                    for row in store.ledger_events_for(ref)), ref)


if __name__ == "__main__":
    unittest.main()
