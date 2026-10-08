"""
RA-3: HTTP-level tests for server.py's GET /report/sarif endpoint --
sarif_adapter.py (export_issues_to_sarif/validate_sarif_shape) was fully
built and tested (test_sarif_adapter.py) but had no production caller
anywhere. This wires it up as a read-only offline export, same
FastAPI TestClient + isolated temp DB + module-reload pattern as
test_server.py/test_local_api_csrf.py.

Covers: a positive round trip (seeded finding -> schema-valid SARIF doc
whose result carries the issue's rule/title), the empty-host control
(no findings -> schema-valid doc with zero results, not a 500), the
read-auth gate (server._READ_AUTH_ENABLED True/False, mirroring
test_server.py::ReadAuthTests' own per-route tests), and that /report's
existing Markdown contract is untouched by this change.

R07/RA-6 (added below): the endpoint was originally built directly on
group_findings_into_issues/export_issue -- the raw, un-enriched chain --
which silently dropped the persisted proof-attempt history and any
operator merge override that report_generator.export_issues_for_host (the
canonical enriched export the Markdown /report and the MCP issues
resource already use) applies, and ignored the reporting.* surfacing
gates /report honors (RA-5). The added tests cover:
  - enrichment: a manual issue merge (store.record_issue_merge) collapses
    two findings into ONE SARIF result, and a case's full persisted proof
    history (an original attempt + a retest, store.persist_proof_record)
    survives into that result's `properties.evidence_refs` -- matching
    report_generator.export_issues_for_host(url) exactly.
  - visibility: with reporting.gate_uncorroborated_catchall enabled, an
    uncorroborated catch-all finding (unconfirmed security_misconfiguration)
    is OMITTED from `runs[0].results` while a concrete sqli finding stays
    (recall guard); with the gate OFF (default), both are present and the
    SARIF is byte-identical to the pre-R07 enriched-but-ungated shape.
"""
import tempfile
import unittest
from pathlib import Path

from harness import sarif_adapter
from harness import store
from harness import report_generator
from harness import issues as issues_mod
from harness.evidence import TestCaseRef, ProofRecord, Verdict
from harness.models import HttpExchange, Finding


class SarifReportEndpointTests(unittest.TestCase):
    def setUp(self):
        # Isolated temp DB, never touch the real harness_state.db.
        self._tmpdir = tempfile.TemporaryDirectory()
        self._original_db_path = store._DB_PATH
        store._DB_PATH = Path(self._tmpdir.name) / "test_harness_state.db"

        # Imported/reloaded after the DB path is patched and inside setUp,
        # same reasoning as test_server.py: server.py's module-level
        # Orchestrator construction must not happen before the test DB is
        # in place, and reloading avoids state bleed across tests.
        import importlib
        import harness.server as server_module
        importlib.reload(server_module)
        self.server = server_module
        from fastapi.testclient import TestClient
        # R03: use the paired token for normal export callers. Auth controls
        # remove the header explicitly to retain their rejection checks.
        self.client = TestClient(server_module.app, base_url="http://localhost",
                                 headers=self._auth_header())

    def tearDown(self):
        store._DB_PATH = self._original_db_path
        self._tmpdir.cleanup()

    def _auth_header(self):
        return {"Authorization": f"Bearer {self.server._mutation_token()}"}

    def _seed_finding(self, url="https://example.com/api/items"):
        exchange = HttpExchange(url=url, method="GET", request_headers={}, request_body="",
                                 response_status=200, response_headers={}, response_body="")
        finding = Finding(vulnerability_class="sqli", confidence=0.9,
                           summary="Boolean-blind SQL injection in id",
                           evidence="db error surfaced", suggested_test="t",
                           basis="derived", severity="high", confirmed=True)
        store.persist_findings(exchange, "sqli_agent", [finding])
        return url

    # --- Positive: seeded finding round-trips into a schema-valid doc -----

    def test_seeded_finding_produces_schema_valid_sarif_with_result(self):
        url = self._seed_finding()
        resp = self.client.get("/report/sarif", params={"url": url})
        self.assertEqual(resp.status_code, 200)
        doc = resp.json()
        self.assertEqual(sarif_adapter.validate_sarif_shape(doc), [])
        results = doc["runs"][0]["results"]
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["ruleId"], "sqli")
        rule_ids = {r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]}
        self.assertIn("sqli", rule_ids)

    # --- Empty-host control: zero findings, not a 500 ---------------------

    def test_host_with_no_findings_returns_zero_result_schema_valid_doc(self):
        resp = self.client.get("/report/sarif", params={"url": "https://nothing-here.example.com/x"})
        self.assertEqual(resp.status_code, 200)
        doc = resp.json()
        self.assertEqual(sarif_adapter.validate_sarif_shape(doc), [])
        self.assertEqual(doc["runs"][0]["results"], [])

    # --- Auth control -------------------------------------------------------

    def test_requires_token_when_read_auth_enabled(self):
        self.server._READ_AUTH_ENABLED = True
        self.client.headers.pop("Authorization", None)
        resp = self.client.get("/report/sarif", params={"url": "https://example.com/x"})
        self.assertEqual(resp.status_code, 401)
        resp = self.client.get("/report/sarif", params={"url": "https://example.com/x"},
                               headers=self._auth_header())
        self.assertEqual(resp.status_code, 200)

    def test_legacy_false_flag_cannot_disable_sensitive_read_auth(self):
        self.server._READ_AUTH_ENABLED = False
        self.client.headers.pop("Authorization", None)
        resp = self.client.get("/report/sarif", params={"url": "https://example.com/x"})
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(self.client.get("/report/sarif", params={"url": "https://example.com/x"},
                                        headers=self._auth_header()).status_code, 200)

    # --- /report's own Markdown contract is untouched ----------------------

    def test_existing_markdown_report_endpoint_is_unchanged(self):
        url = self._seed_finding()
        resp = self.client.get("/report", params={"url": url})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.headers["content-type"].split(";")[0], "text/markdown")
        self.assertIn("sqli", resp.text)

    # --- R07: enrichment -- proof history + operator merges -----------------

    def test_sarif_reflects_merges_and_proof_history_matching_canonical_export(self):
        host = "merge-test.example.com"
        url_a = f"https://{host}/api/orders"
        url_b = f"https://{host}/api/legacy-orders"

        # One case, two persisted proof ATTEMPTS -- an original confirmation
        # plus a later retest (append-only attempt history, R08/T06).
        case = TestCaseRef(run_id="run-merge-1", request_template_id="tmpl-1",
                            check_id="sqlmap-check")
        proof1 = ProofRecord(proof_id="", case=case, validator="sqlmap_validator",
                             verdict=Verdict.CONFIRMED, executed=True,
                             observed_result="boolean-blind diff observed")
        ok, msg = store.persist_proof_record(proof1)
        self.assertTrue(ok, msg)
        proof2 = ProofRecord(proof_id="", case=case, validator="sqlmap_validator",
                             verdict=Verdict.CONFIRMED, executed=True,
                             observed_result="retest after patch: diff observed again",
                             created_at=proof1.created_at + 10)
        ok, msg = store.persist_proof_record(proof2)
        self.assertTrue(ok, msg)

        # B's own case/proof -- one attempt, so the merged issue's evidence
        # combines A's 2-attempt history with B's 1 (3 total).
        case_b = TestCaseRef(run_id="run-merge-2", request_template_id="tmpl-2",
                              check_id="sqlmap-check")
        proof_b = ProofRecord(proof_id="", case=case_b, validator="sqlmap_validator",
                              verdict=Verdict.CONFIRMED, executed=True,
                              observed_result="legacy endpoint diff observed")
        ok, msg = store.persist_proof_record(proof_b)
        self.assertTrue(ok, msg)

        exchange_a = HttpExchange(url=url_a, method="GET", request_headers={}, request_body="",
                                   response_status=200, response_headers={}, response_body="")
        finding_a = Finding(vulnerability_class="sqli", confidence=0.9,
                            summary="Boolean-blind SQL injection in id",
                            evidence="db error surfaced", suggested_test="t",
                            basis="derived", severity="high", confirmed=True,
                            case_id=case.case_id)
        store.persist_findings(exchange_a, "sqli_agent", [finding_a])

        exchange_b = HttpExchange(url=url_b, method="GET", request_headers={}, request_body="",
                                   response_status=200, response_headers={}, response_body="")
        finding_b = Finding(vulnerability_class="sqli", confidence=0.9,
                            summary="Boolean-blind SQL injection in legacy id",
                            evidence="db error surfaced", suggested_test="t",
                            basis="derived", severity="high", confirmed=True,
                            case_id=case_b.case_id)
        store.persist_findings(exchange_b, "sqli_agent", [finding_b])

        # Two distinct endpoints -> two distinct AUTOMATIC issues; discover
        # their (deterministic) ids so a manual merge can be declared.
        all_findings = store.all_host_findings(url_a)
        grouped = issues_mod.group_findings_into_issues(all_findings)
        self.assertEqual(len(grouped), 2)
        issue_id_by_url = {iss.members[0]["url"]: iss.issue_id for iss in grouped}
        issue_id_a = issue_id_by_url[url_a]
        issue_id_b = issue_id_by_url[url_b]

        # Operator-declared merge (P1.8): fold B into A.
        store.record_issue_merge(host, issue_id_b, issue_id_a)

        # Canonical enriched export (the SARIF must match this exactly).
        canonical = report_generator.export_issues_for_host(url_a)
        self.assertEqual(len(canonical), 1)
        self.assertEqual(canonical[0]["issue_id"], issue_id_a)
        # A's 2-attempt history + B's 1 attempt = 3, all preserved post-merge.
        self.assertEqual(len(canonical[0]["proof_references"]), 3)
        case_a_refs = [r for r in canonical[0]["proof_references"] if r["case_id"] == case.case_id]
        self.assertEqual(len(case_a_refs), 2)
        self.assertEqual({r["proof_id"] for r in case_a_refs}, {proof1.proof_id, proof2.proof_id})

        resp = self.client.get("/report/sarif", params={"url": url_a})
        self.assertEqual(resp.status_code, 200)
        doc = resp.json()
        self.assertEqual(sarif_adapter.validate_sarif_shape(doc), [])
        results = doc["runs"][0]["results"]
        # The merge is reflected: ONE result, not two.
        self.assertEqual(len(results), 1)
        result = results[0]
        self.assertEqual(result["properties"]["issue_id"], issue_id_a)
        # The full persisted proof-attempt history (all 3 attempts) survives,
        # identical to the canonical enriched export.
        self.assertEqual(result["properties"]["evidence_refs"], canonical[0]["proof_references"])

    # --- RA-6: visibility -- reporting.* gates omit a demoted catch-all -----

    def test_gate_uncorroborated_catchall_omits_demoted_finding_keeps_concrete(self):
        host = "gate-test.example.com"
        catchall_url = f"https://{host}/admin/config"
        sqli_url = f"https://{host}/api/items"

        exchange_misconfig = HttpExchange(url=catchall_url, method="GET", request_headers={},
                                          request_body="", response_status=200,
                                          response_headers={}, response_body="")
        catchall_finding = Finding(vulnerability_class="Security misconfiguration", confidence=0.7,
                                   summary="Verbose stack trace exposed",
                                   evidence="stack trace in response", suggested_test="t",
                                   basis="assumed", severity="medium", confirmed=False)
        store.persist_findings(exchange_misconfig, "misconfig_agent", [catchall_finding])

        exchange_sqli = HttpExchange(url=sqli_url, method="GET", request_headers={}, request_body="",
                                     response_status=200, response_headers={}, response_body="")
        sqli_finding = Finding(vulnerability_class="sqli", confidence=0.9,
                               summary="Boolean-blind SQL injection in id",
                               evidence="db error surfaced", suggested_test="t",
                               basis="derived", severity="high", confirmed=True)
        store.persist_findings(exchange_sqli, "sqli_agent", [sqli_finding])

        # Negative control: gate OFF (default) -- both classes present, and
        # the SARIF matches export_issues_for_host(url) with NO config
        # (byte-identical to the pre-R07 enriched-but-ungated shape).
        baseline = report_generator.export_issues_for_host(catchall_url)
        resp_off = self.client.get("/report/sarif", params={"url": catchall_url})
        self.assertEqual(resp_off.status_code, 200)
        doc_off = resp_off.json()
        rule_ids_off = sorted(r["ruleId"] for r in doc_off["runs"][0]["results"])
        self.assertEqual(rule_ids_off, sorted(e["vulnerability_class"] for e in baseline))
        self.assertIn("misconfig", rule_ids_off)
        self.assertIn("sqli", rule_ids_off)
        expected_off_doc = sarif_adapter.export_issues_to_sarif(
            baseline, source_revision=doc_off["runs"][0]["properties"]["sourceRevision"])
        self.assertEqual(doc_off, expected_off_doc)

        # Gate ON: the catch-all finding is omitted; the concrete sqli stays.
        self.server.config["reporting"] = {"gate_uncorroborated_catchall": True}
        resp_on = self.client.get("/report/sarif", params={"url": catchall_url})
        self.assertEqual(resp_on.status_code, 200)
        doc_on = resp_on.json()
        self.assertEqual(sarif_adapter.validate_sarif_shape(doc_on), [])
        rule_ids_on = {r["ruleId"] for r in doc_on["runs"][0]["results"]}
        self.assertNotIn("misconfig", rule_ids_on)
        self.assertIn("sqli", rule_ids_on)


if __name__ == "__main__":
    unittest.main()
