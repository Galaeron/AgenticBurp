"""HU-6: write-ups for proof-bound issues, bound to the proof facts.

Caller-level: a real cross-identity confirmation is produced through
Orchestrator.analyze against an owned loopback fixture (the WL-04 harness in
test_cross_identity_ownership_gate: alice owns object 7, bob reads it), then the
write-up is read back through report_generator.export_issues_for_host -- the
existing issue-export path. Only the model is canned.
"""
from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

import yaml

from harness import report_generator, writeups
from harness import test_cross_identity_ownership_gate as xid

_CONFIG = Path(__file__).resolve().parent / "config.yaml"
TWO_USERS = (("alice", "alice-token", "user"), ("bob", "bob-token", "user"))


def _cfg(**writeup_keys) -> dict:
    with open(_CONFIG) as f:
        cfg = yaml.safe_load(f) or {}
    cfg.setdefault("writeups", {}).update(writeup_keys)
    return cfg


class WriteupCallerTests(unittest.TestCase):
    def setUp(self):
        self.h = xid.OwnershipGateCallerTests("test_declared_ownership_confirms_the_vulnerable_object")
        self.h.setUp()
        self.addCleanup(self.h.tearDown)
        self.url = self.h.fx.url("/objects/7")

    def _prove_cross_owner_read(self):
        """bob's captured read of alice's declared-private object: confirmed."""
        resp = self.h._analyze("/objects/7", source="bob-token", identities=TWO_USERS,
                               ledger=self.h._declared("/objects/7", owner="alice"))
        self.assertTrue(self.h._finding(resp).confirmed)

    def _export(self, **keys):
        return report_generator.export_issues_for_host(self.url, config=_cfg(**keys))

    def _writeup(self, **keys) -> dict:
        exports = [e for e in self._export(export_markdown=True, **keys) if e.get("writeup")]
        self.assertEqual(len(exports), 1, [e.get("evidence_state") for e in exports])
        return exports[0]["writeup"]

    # --- acceptance: proven cross-owner read --------------------------------------
    def test_proven_cross_owner_read_names_field_principals_and_exact_request(self):
        self._prove_cross_owner_read()
        w = self._writeup()
        md = w["markdown"]
        self.assertEqual(w["source"], writeups.TEMPLATE)
        impact = md.split("## Impact", 1)[1].split("##", 1)[0]
        self.assertIn("`bob` read `alice`'s object at `GET /objects/7`", impact)
        self.assertIn("`secret`", impact)               # the exposed field, from the response
        self.assertIn("HTTP 403", impact)               # the unauthenticated control
        # the exact request, secrets redacted
        self.assertIn(f"GET /objects/7 HTTP/1.1\nHost: 127.0.0.1:{self.h.fx.port}\nAuthorization: ", md)
        for secret in ("bob-token", "alice-token", self.h.fx.marker("7")):
            self.assertNotIn(secret, md)
        steps = md.split("## Steps to reproduce", 1)[1].split("##", 1)[0]
        self.assertIn("as `bob` (the proof's attack request)", steps)
        self.assertIn("as `alice` (baseline)", steps)
        self.assertIn("without a session (control) and expect HTTP 403", steps)
        remediation = md.split("## Remediation", 1)[1]
        self.assertIn("On `GET /objects/{id}`, add a server-side object-level authorization check", remediation)
        self.assertIn("`bob` must get a denial (403 or 404) for `alice`'s object, and never its `secret`",
                      remediation)
        self.assertIn(report_generator._remediation_for("idor"), remediation)   # generic part only
        with tempfile.TemporaryDirectory() as d:
            exports = self._export(export_markdown=True)
            paths = writeups.write_files(exports, d)
            self.assertEqual(len(paths), 1)
            self.assertEqual(Path(paths[0]).name, w["filename"])
            self.assertEqual(Path(paths[0]).read_text(encoding="utf-8"), md)

    # --- negative control: an unproven candidate ----------------------------------
    def test_unproven_candidate_gets_no_writeup(self):
        resp = self.h._analyze("/objects/7")    # nothing declared: a supported lead only
        self.assertFalse(self.h._finding(resp).confirmed)
        exports = self._export(export_markdown=True)
        self.assertTrue(exports)
        self.assertFalse(any("writeup" in e for e in exports))
        self.assertFalse(any(writeups.proof_bound(e, {}) for e in exports))

    # --- fact binding ---------------------------------------------------------------
    def _bad_model(self, impact: str, remediation: str = "Add an ownership check on `GET /objects/{id}`."):
        return patch("harness.ollama_client.OllamaClient.chat_json",
                     new=AsyncMock(return_value={"impact": impact, "remediation": remediation}))

    def test_model_draft_naming_absent_field_is_rejected_for_the_template(self):
        self._prove_cross_owner_read()
        template = self._writeup()["markdown"]
        for label, impact in {
                "backticked field": "`bob` read `alice`'s object and its `password_hash` field.",
                "bare field": "`bob` read `alice`'s object, including password_hash.",
                "unknown principal": "user mallory read `alice`'s object at `GET /objects/7`.",
                "unknown endpoint": "`bob` can also call /objects/7/export to read `alice`'s data."}.items():
            with self.subTest(label), self._bad_model(impact) as model:
                w = self._writeup(model_phrasing=True)
                self.assertTrue(model.await_count)            # the model was really asked
                self.assertEqual(w["source"], writeups.TEMPLATE)
                self.assertTrue(w["rejected_model_draft"])
                self.assertEqual(w["markdown"], template)
                self.assertNotIn(impact, w["markdown"])

    def test_bound_model_draft_is_accepted(self):
        """The check is not a blanket rejection: a rephrasing that names only proof
        facts replaces the two template sentences."""
        self._prove_cross_owner_read()
        impact = "Principal `bob` obtained `alice`'s object from `GET /objects/7`, including `secret`."
        remediation = "Check ownership on `GET /objects/{id}` before returning `owner` or `secret`."
        with self._bad_model(impact, remediation):
            w = self._writeup(model_phrasing=True)
        self.assertEqual((w["source"], w["rejected_model_draft"]), (writeups.MODEL, []))
        self.assertIn(impact, w["markdown"])
        self.assertIn(remediation, w["markdown"])
        self.assertIn("GET /objects/7 HTTP/1.1", w["markdown"])   # proof block stays the template's

    def test_model_phrasing_off_never_calls_the_model(self):
        self._prove_cross_owner_read()
        with self._bad_model("`password_hash`") as model:
            w = self._writeup()
        self.assertEqual(model.await_count, 0)
        self.assertEqual(w["source"], writeups.TEMPLATE)

    def test_writeups_route_serves_files_only_when_enabled(self):
        from fastapi.testclient import TestClient
        import harness.server as server
        self._prove_cross_owner_read()
        host = self.h.fx.base.split("//", 1)[1]
        client = TestClient(server.app, base_url="http://localhost",
                            headers={"Authorization": f"Bearer {server._mutation_token()}"})
        for enabled in (False, True):
            with self.subTest(enabled=enabled), patch.object(server, "config", _cfg(export_markdown=enabled)):
                body = client.get(f"/engagement/{host}/writeups").json()
                self.assertEqual((body["enabled"], body["sends_traffic"]), (enabled, False))
                self.assertEqual(body["writeup_count"], int(enabled))
                if enabled:
                    self.assertIn("`bob` read `alice`'s object", body["writeups"][0]["markdown"])

    # --- default: export unchanged -------------------------------------------------
    def test_export_key_off_leaves_the_export_unchanged(self):
        self._prove_cross_owner_read()
        self.assertFalse(writeups.settings(_cfg())["export_markdown"])   # shipped default
        off = self._export()
        with patch.object(writeups, "attach_to_exports", lambda exports, *a, **k: exports):
            baseline = self._export()
        self.assertEqual(off, baseline)
        self.assertFalse(any("writeup" in e for e in off))
        self.assertEqual(report_generator.export_issues_for_host(self.url), off)
        on = self._export(export_markdown=True)
        stripped = copy.deepcopy(on)
        for e in stripped:
            e.pop("writeup", None)
        self.assertEqual(stripped, off)          # on only ADDS the write-up


class FactBindingUnitTests(unittest.TestCase):
    FACTS = {"issue_id": "i1", "proof_id": "p1", "case_id": "c1", "validator": "cross_identity",
             "vulnerability_class": "idor", "severity": "high", "host": "http://127.0.0.1:9",
             "method": "GET", "endpoint_family": "/things/{id}", "object": "/things/3",
             "paths": ["/things/3", "/things/{id}"], "endpoints": ["GET /things/3", "GET /things/{id}"],
             "instances": ["http://127.0.0.1:9/things/3"], "attack_url": "http://127.0.0.1:9/things/3",
             "actor": "u2", "owner": "u1", "principals": ["u1", "u2"], "fields": ["id", "note"],
             "sensitive_fields": [], "parameter": "", "controls": [{"status": 401, "principal": "unauthenticated"}],
             "attack_status": 200, "baseline_status": 200, "observed": "", "steps": [],
             "request_raw": "GET /things/3 HTTP/1.1", "response_raw": "HTTP/1.1 200"}

    def test_template_is_bound_and_absent_facts_are_not(self):
        md = writeups.render(self.FACTS)
        hint = (report_generator._remediation_for("idor"),)
        self.assertEqual(writeups.fact_binding_violations(md, self.FACTS, allowed_text=hint), [])
        for bad in ("`ssn`", "user_email", "`GET /things/3/history`", "'u9'", "http://127.0.0.1:9/admin",
                    "account carol"):
            with self.subTest(bad):
                self.assertTrue(writeups.fact_binding_violations(md + f"\n\nAlso {bad}.", self.FACTS,
                                                                 allowed_text=hint))


if __name__ == "__main__":
    unittest.main()
