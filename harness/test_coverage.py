"""
Tests for the coverage ledger (store.coverage_report and friends).

The core property under test: status is DERIVED from findings/test_plans/
validation_runs rows, never settable directly. If these tests ever need
to insert a status by any path other than persist_findings /
persist_test_plans / persist_validation_submission / set_coverage_override,
that's a sign the ledger grew a backdoor around its own evidence gate.
"""
import os
import tempfile
import unittest

# Point store.py at a throwaway DB file before importing it, so these
# tests never touch the real harness_state.db.
_tmp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_tmp_db.close()
os.environ["HARNESS_TEST_DB_PATH"] = _tmp_db.name

from harness import store  # noqa: E402
store._DB_PATH = __import__("pathlib").Path(_tmp_db.name)

from harness.models import HttpExchange, Finding, TestPlan, ValidationSubmission  # noqa: E402


def _exchange(url="https://target.test/basket/1"):
    return HttpExchange(url=url, method="GET", response_status=200)


class CoverageLedgerTests(unittest.TestCase):
    def setUp(self):
        # Fresh DB file per test to avoid cross-test bleed.
        self.db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db.close()
        store._DB_PATH = __import__("pathlib").Path(self.db.name)

    def tearDown(self):
        os.unlink(self.db.name)

    def test_category_never_dispatched_reads_not_dispatched(self):
        report = store.coverage_report("target.test")
        idor = next(r for r in report if r["category"] == "idor")
        self.assertEqual(idor["status"], "not_dispatched")

    def test_dispatched_but_no_plan_reads_not_tested(self):
        exchange = _exchange()
        finding = Finding(vulnerability_class="idor", confidence=0.4, summary="s",
                           evidence="e", suggested_test="t", basis="assumed")
        store.persist_findings(exchange, "idor", [finding])
        report = store.coverage_report("target.test")
        idor = next(r for r in report if r["category"] == "idor")
        self.assertEqual(idor["status"], "not_tested")

    def test_no_active_validator_category_says_so(self):
        exchange = _exchange()
        finding = Finding(vulnerability_class="misconfig", confidence=0.4, summary="s",
                           evidence="e", suggested_test="t", basis="assumed")
        store.persist_findings(exchange, "misconfig", [finding])
        report = store.coverage_report("target.test")
        misconfig = next(r for r in report if r["category"] == "misconfig")
        self.assertEqual(misconfig["status"], "not_tested")
        self.assertIn("no active validation capability", misconfig["reason"])

    def test_confirmed_validation_run_reads_confirmed(self):
        exchange = _exchange()
        plan = TestPlan(id="p1", capability="cross_identity_compare", finding_class="idor",
                         category="idor", source_exchange_url=exchange.url,
                         source_exchange_hash="h1")
        store.persist_test_plans(exchange, [plan])
        ok, reason = store.persist_validation_submission(ValidationSubmission(
            plan_id="p1", status="confirmed", confidence=0.9, confirmed=True,
            summary="real IDOR", executor="burp:cross_identity_compare",
            source_exchange_hash="h1",
        ))
        self.assertTrue(ok, reason)
        report = store.coverage_report("target.test")
        idor = next(r for r in report if r["category"] == "idor")
        self.assertEqual(idor["status"], "confirmed")
        self.assertEqual(idor["evidence"]["plan_id"], "p1")

    def test_rejected_validation_run_reads_tested_clean_not_not_tested(self):
        exchange = _exchange()
        plan = TestPlan(id="p2", capability="reflection_context_validation",
                         finding_class="xss", category="xss",
                         source_exchange_url=exchange.url, source_exchange_hash="h2")
        store.persist_test_plans(exchange, [plan])
        store.persist_validation_submission(ValidationSubmission(
            plan_id="p2", status="rejected", confidence=0.7, confirmed=False,
            summary="no reflection observed", executor="burp:reflection_context_validation",
            source_exchange_hash="h2",
        ))
        report = store.coverage_report("target.test")
        xss = next(r for r in report if r["category"] == "xss")
        self.assertEqual(xss["status"], "tested_clean")

    def test_error_validation_run_reads_blocked(self):
        exchange = _exchange()
        plan = TestPlan(id="p3", capability="sql_injection_validation",
                         finding_class="sqli", category="sqli",
                         source_exchange_url=exchange.url, source_exchange_hash="h3",
                         execution_plane="local_tool")
        store.persist_test_plans(exchange, [plan])
        # A validator error is submitted the same way a real result would be
        # -- through persist_validation_submission -- there is no separate
        # "mark blocked" backdoor.
        store.persist_validation_submission(ValidationSubmission(
            plan_id="p3", status="error", confidence=0.0, confirmed=False,
            summary="sqlmap executable not found", executor="local_tool:sql_injection_validation",
            source_exchange_hash="h3",
        ))
        report = store.coverage_report("target.test")
        sqli = next(r for r in report if r["category"] == "sqli")
        self.assertEqual(sqli["status"], "blocked")

    def test_confirmed_outranks_earlier_supported_or_clean_runs(self):
        # Two validation runs for the same category: one rejected, one
        # confirmed. The ledger must report the strongest evidence, not
        # whichever happened to be inserted/queried first.
        exchange = _exchange()
        plan_a = TestPlan(id="p4a", capability="cross_identity_compare",
                           finding_class="idor", category="idor",
                           source_exchange_url=exchange.url, source_exchange_hash="h4a")
        plan_b = TestPlan(id="p4b", capability="cross_identity_compare",
                           finding_class="idor", category="idor",
                           source_exchange_url=exchange.url, source_exchange_hash="h4b")
        store.persist_test_plans(exchange, [plan_a, plan_b])
        store.persist_validation_submission(ValidationSubmission(
            plan_id="p4a", status="rejected", confidence=0.6, confirmed=False,
            summary="first attempt found nothing", executor="burp:cross_identity_compare",
            source_exchange_hash="h4a",
        ))
        store.persist_validation_submission(ValidationSubmission(
            plan_id="p4b", status="confirmed", confidence=0.9, confirmed=True,
            summary="second attempt confirmed it", executor="burp:cross_identity_compare",
            source_exchange_hash="h4b",
        ))
        report = store.coverage_report("target.test")
        idor = next(r for r in report if r["category"] == "idor")
        self.assertEqual(idor["status"], "confirmed")

    def test_override_produces_not_applicable_and_nothing_else(self):
        store.set_coverage_override("target.test", "ssrf", "no outbound-fetch surface exists on this app")
        report = store.coverage_report("target.test")
        ssrf = next(r for r in report if r["category"] == "ssrf")
        self.assertEqual(ssrf["status"], "not_applicable")
        self.assertIn("no outbound-fetch", ssrf["reason"])

    def test_override_cannot_be_used_to_assert_confirmed(self):
        # The override function's SQL hardcodes status='not_applicable' in
        # the INSERT; there is no parameter that lets a caller pass
        # 'confirmed'. This test locks that in from the public API side.
        with self.assertRaises(TypeError):
            store.set_coverage_override("target.test", "ssrf", "confirmed", status="confirmed")  # type: ignore[call-arg]

    def test_override_rejects_unknown_category(self):
        with self.assertRaises(ValueError):
            store.set_coverage_override("target.test", "not_a_real_category", "x")

    def test_clear_override_reverts_to_derived_status(self):
        store.set_coverage_override("target.test", "auth", "reason")
        store.clear_coverage_override("target.test", "auth")
        report = store.coverage_report("target.test")
        auth = next(r for r in report if r["category"] == "auth")
        self.assertEqual(auth["status"], "not_dispatched")

    def test_report_covers_every_canonical_category_exactly_once(self):
        from harness.categories import CANONICAL_CATEGORIES
        report = store.coverage_report("target.test")
        categories_seen = [r["category"] for r in report]
        self.assertEqual(sorted(categories_seen), sorted(CANONICAL_CATEGORIES))
        self.assertEqual(len(categories_seen), len(set(categories_seen)))


class ReproducibilityMetadataTests(unittest.TestCase):
    """persist_findings should record which model/prompt produced a
    finding (spec P8: reproducibility) -- without this, a stored finding
    can't be traced back to what generated it once a prompt changes."""

    def test_model_and_prompt_version_persisted(self):
        exchange = _exchange("https://repro.test/x")
        finding = Finding(vulnerability_class="xss", confidence=0.7, severity="medium",
                           summary="s", evidence="e", suggested_test="t", basis="derived")
        store.persist_findings(exchange, "xss_agent", [finding], model="llama3.1:8b", prompt_version="abc123def456")
        conn = store._connect()
        try:
            row = conn.execute("SELECT model, prompt_version FROM findings WHERE url = ?",
                                (exchange.url,)).fetchone()
        finally:
            conn.close()
        self.assertEqual(row[0], "llama3.1:8b")
        self.assertEqual(row[1], "abc123def456")

    def test_defaults_are_empty_string_not_null(self):
        exchange = _exchange("https://repro2.test/x")
        finding = Finding(vulnerability_class="xss", confidence=0.7, severity="medium",
                           summary="s2", evidence="e", suggested_test="t", basis="derived")
        store.persist_findings(exchange, "chain_detector", [finding])  # no model/prompt_version passed
        conn = store._connect()
        try:
            row = conn.execute("SELECT model, prompt_version FROM findings WHERE url = ?",
                                (exchange.url,)).fetchone()
        finally:
            conn.close()
        self.assertEqual(row[0], "")
        self.assertEqual(row[1], "")


if __name__ == "__main__":
    unittest.main()
