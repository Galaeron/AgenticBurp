import tempfile
import unittest
from pathlib import Path

from harness import store
from harness.models import HttpExchange, Finding, TestPlan, ValidationSubmission


class TestFindingsPersistenceRoundTrip(unittest.TestCase):
    """
    Regression test for the report-generation gap found this session:
    evidence, suggested_test, and owasp_category were present on every
    Finding object but silently dropped at the persistence boundary,
    meaning a report built from stored findings had no reproduction
    detail -- only a one-line summary. This confirms the fix actually
    round-trips, not just that the schema migration runs without error.
    """

    def setUp(self):
        # Isolated temp DB per test -- never touch the real harness_state.db.
        self._tmpdir = tempfile.TemporaryDirectory()
        self._original_db_path = store._DB_PATH
        store._DB_PATH = Path(self._tmpdir.name) / "test_harness_state.db"

    def tearDown(self):
        store._DB_PATH = self._original_db_path
        self._tmpdir.cleanup()

    def test_evidence_and_suggested_test_and_owasp_category_round_trip(self):
        exchange = HttpExchange(
            url="https://example.com/api/users", method="GET",
            request_headers={}, request_body="",
            response_status=200, response_headers={}, response_body="",
        )
        finding = Finding(
            vulnerability_class="sqli",
            confidence=0.9,
            summary="Boolean-blind SQL injection in id parameter",
            evidence="Response length differs by 40 bytes between id=1 AND 1=1 and id=1 AND 1=2",
            suggested_test="Send id=1 AND 1=1 vs id=1 AND 1=2 and compare response length",
            basis="derived",
            severity="critical",
            owasp_category="A03:2021-Injection",
            confirmed=True,
        )
        store.persist_findings(exchange, "sqli_agent", [finding])

        results = store.all_host_findings(exchange.url)
        self.assertEqual(len(results), 1)
        r = results[0]
        self.assertEqual(r["evidence"], finding.evidence)
        self.assertEqual(r["suggested_test"], finding.suggested_test)
        self.assertEqual(r["owasp_category"], finding.owasp_category)
        self.assertEqual(r["basis"], "derived")
        self.assertTrue(r["confirmed"])
        self.assertEqual(r["agent"], "sqli_agent")

    def test_owasp_category_none_round_trips_as_none(self):
        exchange = HttpExchange(
            url="https://example.com/x", method="GET",
            request_headers={}, request_body="",
            response_status=200, response_headers={}, response_body="",
        )
        finding = Finding(
            vulnerability_class="info_disclosure", confidence=0.5,
            summary="s", evidence="e", suggested_test="t", basis="derived",
            owasp_category=None,
        )
        store.persist_findings(exchange, "info_disclosure_agent", [finding])
        results = store.all_host_findings(exchange.url)
        self.assertIsNone(results[0]["owasp_category"])

    def test_multiple_findings_same_host_all_persist(self):
        exchange = HttpExchange(
            url="https://example.com/a", method="GET",
            request_headers={}, request_body="",
            response_status=200, response_headers={}, response_body="",
        )
        findings = [
            Finding(vulnerability_class="xss", confidence=0.8, summary="s1",
                    evidence="e1", suggested_test="t1", basis="derived"),
            Finding(vulnerability_class="idor", confidence=0.7, summary="s2",
                    evidence="e2", suggested_test="t2", basis="derived"),
        ]
        store.persist_findings(exchange, "test_agent", findings)
        results = store.all_host_findings(exchange.url)
        self.assertEqual(len(results), 2)
        classes = {r["vulnerability_class"] for r in results}
        self.assertEqual(classes, {"xss", "idor"})


class TestExchangeProvenanceAR3(unittest.TestCase):
    """AR-3 (LOOP half): findings carry the exact id of the exchange that
    produced them (exchange_id), additively, instead of only the
    (method, url) coordinates the findings table already had. Covers the
    round-trip, re-observation-after-dedup, and back-compat/no-op cases the
    Opus scoper's acceptance criteria call for."""

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._original_db_path = store._DB_PATH
        store._DB_PATH = Path(self._tmpdir.name) / "test_ar3_state.db"

    def tearDown(self):
        store._DB_PATH = self._original_db_path
        self._tmpdir.cleanup()

    def test_capture_id_round_trips_through_all_host_findings(self):
        # POSITIVE (round-trip): a finding persisted from a known synthetic
        # exchange with an explicit capture_id reads back carrying that
        # exact exchange id, not just its (method, url).
        exchange = HttpExchange(
            url="https://example.com/api/orders/1", method="GET",
            request_headers={}, request_body="",
            response_status=200, response_headers={}, response_body="",
            capture_id="exch-known-42",
        )
        finding = Finding(
            vulnerability_class="idor", confidence=0.7, summary="s",
            evidence="e", suggested_test="t", basis="derived",
        )
        store.persist_findings(exchange, "idor_agent", [finding])
        results = store.all_host_findings(exchange.url)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["exchange_id"], "exch-known-42")
        # run_id is additive too; absent any bound telemetry run, it is ''.
        self.assertEqual(results[0]["run_id"], "")

    def test_no_capture_id_falls_back_to_content_hash_and_reads_back(self):
        # NEGATIVE (legacy/back-compat, no explicit capture_id): a finding
        # persisted from an exchange with NO capture_id set still reads back
        # fine, and gets a non-empty exchange_id -- the stable content hash
        # fallback (cache.ExchangeCache.compute_exchange_hash), not ''.
        exchange = HttpExchange(
            url="https://example.com/api/orders/2", method="GET",
            request_headers={}, request_body="",
            response_status=200, response_headers={}, response_body="",
        )
        self.assertEqual(exchange.capture_id, "")
        finding = Finding(
            vulnerability_class="idor", confidence=0.6, summary="s",
            evidence="e", suggested_test="t", basis="derived",
        )
        store.persist_findings(exchange, "idor_agent", [finding])
        results = store.all_host_findings(exchange.url)
        self.assertEqual(len(results), 1)
        self.assertNotEqual(results[0]["exchange_id"], "")

        from harness import cache as cache_mod
        expected = cache_mod.ExchangeCache.compute_exchange_hash(exchange)[:16]
        self.assertEqual(results[0]["exchange_id"], expected)

    def test_deduped_finding_records_second_observation_row(self):
        # POSITIVE (re-observation): two exchanges sharing the SAME (host,
        # method, endpoint, vulnerability_class) -- so they fingerprint
        # identically and collapse into ONE findings row (INSERT OR IGNORE,
        # unchanged dedup) -- still each get their own row in
        # finding_observations, keyed by their own exchange_id.
        url = "https://example.com/api/tickets/9"
        exchange_a = HttpExchange(
            url=url, method="GET", request_headers={}, request_body="",
            response_status=200, response_headers={}, response_body="",
            capture_id="exch-a",
        )
        exchange_b = HttpExchange(
            url=url, method="GET", request_headers={}, request_body="",
            response_status=200, response_headers={}, response_body="",
            capture_id="exch-b",
        )
        finding = Finding(
            vulnerability_class="idor", confidence=0.65, summary="s",
            evidence="e", suggested_test="t", basis="derived",
        )
        store.persist_findings(exchange_a, "idor_agent", [finding])
        store.persist_findings(exchange_b, "idor_agent", [finding])

        results = store.all_host_findings(url)
        # Dedup unchanged: one findings row, keeping the first-seen exchange_id.
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["exchange_id"], "exch-a")

        fp = results[0]["fingerprint"]
        observed = store.finding_observations([fp])
        self.assertIn(fp, observed)
        self.assertCountEqual(observed[fp], ["exch-a", "exch-b"])

    def test_pre_ar3_db_migrates_without_error(self):
        # NEGATIVE (migration/back-compat): a DB created by a build that
        # predates AR-3 -- findings table with no exchange_id/run_id columns,
        # no finding_observations table at all -- must migrate cleanly the
        # next time it is opened, with no destructive rewrite of existing
        # rows (they simply default to '').
        import sqlite3
        conn = sqlite3.connect(store._DB_PATH)
        try:
            # Exact pre-AR-3 schema: every column store.py's findings table has
            # had for a while, EXCEPT exchange_id/run_id (the two this item
            # adds) -- so the only thing the migration guard has to do here is
            # add those two, not paper over unrelated pre-existing gaps.
            conn.executescript("""
                CREATE TABLE findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    host TEXT NOT NULL,
                    url TEXT NOT NULL,
                    method TEXT NOT NULL,
                    agent TEXT NOT NULL,
                    vulnerability_class TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    summary TEXT NOT NULL,
                    basis TEXT NOT NULL,
                    evidence TEXT NOT NULL DEFAULT '',
                    suggested_test TEXT NOT NULL DEFAULT '',
                    owasp_category TEXT,
                    review_verdict TEXT,
                    confirmed INTEGER NOT NULL DEFAULT 0,
                    fingerprint TEXT NOT NULL DEFAULT '',
                    model TEXT NOT NULL DEFAULT '',
                    prompt_version TEXT NOT NULL DEFAULT '',
                    finding_id TEXT NOT NULL DEFAULT '',
                    case_id TEXT NOT NULL DEFAULT '',
                    proof_id TEXT NOT NULL DEFAULT '',
                    oracle_verified INTEGER NOT NULL DEFAULT 0,
                    verification_state TEXT NOT NULL DEFAULT 'candidate',
                    oracle_capsule_id TEXT NOT NULL DEFAULT '',
                    created_at REAL NOT NULL
                );
                INSERT INTO findings (host, url, method, agent, vulnerability_class,
                                       severity, confidence, summary, basis, fingerprint, created_at)
                VALUES ('example.com', 'https://example.com/legacy', 'GET', 'legacy_agent',
                        'xss', 'medium', 0.5, 'pre-AR-3 row', 'derived', 'legacy-fp-1', 0.0);
            """)
            conn.commit()
        finally:
            conn.close()

        # Opening it through the normal path must not raise, must add the
        # new columns/table, and the pre-existing row must remain readable
        # with the new columns defaulting to ''.
        conn = store._connect()
        try:
            cols = {row[1] for row in conn.execute("PRAGMA table_info(findings)")}
            self.assertIn("exchange_id", cols)
            self.assertIn("run_id", cols)
            tables = {row[0] for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}
            self.assertIn("finding_observations", tables)
            row = conn.execute(
                "SELECT exchange_id, run_id, summary FROM findings WHERE url = ?",
                ("https://example.com/legacy",),
            ).fetchone()
        finally:
            conn.close()
        self.assertEqual(row[0], "")
        self.assertEqual(row[1], "")
        self.assertEqual(row[2], "pre-AR-3 row")

        results = store.all_host_findings("https://example.com/legacy")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["exchange_id"], "")
        self.assertEqual(results[0]["run_id"], "")


class TestFindingSuppression(unittest.TestCase):
    """
    Tests for the cross-run finding suppression feature -- the workflow
    gap named in this project's own milestones list: without it, a
    re-scan of the same host re-surfaces every previously-dismissed
    finding with no memory of the dismissal.
    """

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._original_db_path = store._DB_PATH
        store._DB_PATH = Path(self._tmpdir.name) / "test_harness_state.db"

    def tearDown(self):
        store._DB_PATH = self._original_db_path
        self._tmpdir.cleanup()

    def _persist_one(self, url="https://example.com/x", vulnerability_class="sqli", summary="s") -> str:
        exchange = HttpExchange(url=url, method="GET", request_headers={}, request_body="",
                                 response_status=200, response_headers={}, response_body="")
        finding = Finding(vulnerability_class=vulnerability_class, confidence=0.8, summary=summary,
                           evidence="e", suggested_test="t", basis="derived")
        store.persist_findings(exchange, "test_agent", [finding])
        results = store.all_host_findings(url, include_suppressed=True)
        matching = [r for r in results if r["vulnerability_class"] == vulnerability_class and r["summary"] == summary]
        self.assertEqual(len(matching), 1)
        return matching[0]["fingerprint"]

    def test_all_host_findings_includes_fingerprint_and_suppressed_fields(self):
        self._persist_one()
        results = store.all_host_findings("https://example.com/x", include_suppressed=True)
        self.assertEqual(len(results), 1)
        self.assertIn("fingerprint", results[0])
        self.assertIn("suppressed", results[0])
        self.assertFalse(results[0]["suppressed"])
        self.assertNotEqual(results[0]["fingerprint"], "")

    def test_suppressed_finding_is_excluded_by_default(self):
        fp = self._persist_one()
        self.assertEqual(len(store.all_host_findings("https://example.com/x")), 1)
        store.suppress_finding(fp, reason="confirmed false positive during manual review")
        self.assertEqual(len(store.all_host_findings("https://example.com/x")), 0)

    def test_suppressed_finding_still_visible_with_include_suppressed(self):
        fp = self._persist_one()
        store.suppress_finding(fp, reason="false positive")
        results = store.all_host_findings("https://example.com/x", include_suppressed=True)
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0]["suppressed"])

    def test_is_suppressed_reflects_current_state(self):
        fp = self._persist_one()
        self.assertFalse(store.is_suppressed(fp))
        store.suppress_finding(fp)
        self.assertTrue(store.is_suppressed(fp))

    def test_unsuppress_restores_visibility(self):
        fp = self._persist_one()
        store.suppress_finding(fp)
        self.assertEqual(len(store.all_host_findings("https://example.com/x")), 0)
        removed = store.unsuppress_finding(fp)
        self.assertTrue(removed)
        self.assertEqual(len(store.all_host_findings("https://example.com/x")), 1)

    def test_unsuppress_unknown_fingerprint_returns_false(self):
        self.assertFalse(store.unsuppress_finding("not-a-real-fingerprint"))

    def test_suppress_is_idempotent_and_updates_reason(self):
        fp = self._persist_one()
        store.suppress_finding(fp, reason="first reason")
        store.suppress_finding(fp, reason="updated reason")
        suppressions = store.list_suppressions()
        self.assertEqual(len(suppressions), 1)
        self.assertEqual(suppressions[0]["reason"], "updated reason")

    def test_list_suppressions_most_recent_first(self):
        fp1 = self._persist_one(url="https://a.example.com/x", summary="finding A")
        fp2 = self._persist_one(url="https://b.example.com/x", summary="finding B")
        store.suppress_finding(fp1, reason="first")
        store.suppress_finding(fp2, reason="second")
        suppressions = store.list_suppressions()
        self.assertEqual([s["fingerprint"] for s in suppressions], [fp2, fp1])

    def test_suppressing_one_finding_does_not_affect_a_different_one(self):
        fp1 = self._persist_one(url="https://example.com/x", vulnerability_class="sqli", summary="s1")
        fp2 = self._persist_one(url="https://example.com/x", vulnerability_class="xss", summary="s2")
        store.suppress_finding(fp1)
        results = store.all_host_findings("https://example.com/x")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["vulnerability_class"], "xss")

    def test_suppressed_findings_do_not_feed_chain_detection(self):
        """
        Side effect worth locking in with a test: orchestrator.py builds
        chain hypotheses from store.all_host_findings()'s default
        (non-suppressed) output, so suppressing a false positive also
        keeps it out of future chain-detection input, not just out of
        the main findings list.
        """
        fp = self._persist_one(vulnerability_class="open_redirect", summary="false positive redirect")
        store.suppress_finding(fp, reason="not actually attacker-controlled")
        results = store.all_host_findings("https://example.com/x")
        classes = [r["vulnerability_class"] for r in results]
        self.assertNotIn("open_redirect", classes)


class TestIssueMergeOverrides(unittest.TestCase):
    """P1.8: persisted, reversible operator issue-merge overrides."""

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._original_db_path = store._DB_PATH
        store._DB_PATH = Path(self._tmpdir.name) / "test_harness_state.db"

    def tearDown(self):
        store._DB_PATH = self._original_db_path
        self._tmpdir.cleanup()

    def test_record_and_read_back_a_merge(self):
        store.record_issue_merge("example.com", "issue-a", "issue-b")
        self.assertEqual(store.all_issue_merges("example.com"), {"issue-a": "issue-b"})

    def test_merge_is_idempotent(self):
        store.record_issue_merge("example.com", "issue-a", "issue-b")
        store.record_issue_merge("example.com", "issue-a", "issue-c")  # re-target
        self.assertEqual(store.all_issue_merges("example.com"), {"issue-a": "issue-c"})

    def test_cannot_merge_an_issue_into_itself(self):
        with self.assertRaises(ValueError):
            store.record_issue_merge("example.com", "issue-a", "issue-a")

    def test_remove_issue_merge_reverses_it(self):
        store.record_issue_merge("example.com", "issue-a", "issue-b")
        removed = store.remove_issue_merge("example.com", "issue-a")
        self.assertTrue(removed)
        self.assertEqual(store.all_issue_merges("example.com"), {})

    def test_remove_unknown_merge_returns_false(self):
        self.assertFalse(store.remove_issue_merge("example.com", "not-a-real-source"))

    def test_merges_are_scoped_per_host(self):
        """Negative control: a merge declared for one host must not leak into
        another host's issue export."""
        store.record_issue_merge("a.example.com", "issue-a", "issue-b")
        self.assertEqual(store.all_issue_merges("b.example.com"), {})


class TestPriorFindingsSummaryStripsBackticks(unittest.TestCase):
    """
    Regression test for a real, severe bug found during this project's
    first real (non-substituted) Ollama run: a model wrote a completely
    ordinary finding summary using Markdown code-formatting for a path
    -- "The `/api/avatar` endpoint returns potentially sensitive data
    ...". prior_findings_summary() embedded that text VERBATIM into
    every subsequent exchange's prompt for the same host, where
    prompt_validator.py's backtick-command-substitution pattern (which
    matches ANY backtick-enclosed span, by design -- see its own
    comment) then failed prompt validation for every agent on every
    remaining exchange for that host, for the rest of the run. Unlike
    raw exchange data, this text is the harness's own prior model
    output, and nothing downstream renders the Markdown anyway -- so
    stripping backticks here breaks the propagation at its source.
    """

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._original_db_path = store._DB_PATH
        store._DB_PATH = Path(self._tmpdir.name) / "test_harness_state.db"

    def tearDown(self):
        store._DB_PATH = self._original_db_path
        self._tmpdir.cleanup()

    def test_backtick_quoted_path_in_summary_does_not_survive_into_prior_context(self):
        exchange = HttpExchange(
            url="https://example.com/api/avatar", method="POST",
            request_headers={}, request_body="",
            response_status=200, response_headers={}, response_body="",
        )
        finding = Finding(
            vulnerability_class="excessive_data_exposure", confidence=0.6,
            summary="The `/api/avatar` endpoint returns potentially sensitive data.",
            evidence="e", suggested_test="t", basis="derived",
        )
        store.persist_findings(exchange, "api_security", [finding])

        summary = store.prior_findings_summary(
            "https://example.com/api/other", exclude_url="https://example.com/api/other"
        )
        self.assertNotIn("`", summary)
        self.assertIn("/api/avatar", summary)


class TestConfirmationCapabilitiesAllowlist(unittest.TestCase):
    """
    Regression test for the exact membership of store.py's
    confirmation_capabilities allowlist -- found live this session that
    20 of 22 implemented Burp-plane capabilities could never durably
    record confirmed=True (silently rejected, with zero signal to the
    analyst -- see the Burp-side fix in ValidationExecutor.submit()).
    After a real audit of each capability's actual confirmation rigor
    (not a decision folded into an unrelated bugfix), this asserts the
    exact resulting set, so any future change to this list is a
    deliberate, visible diff here, not silent drift.
    """

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._original_db_path = store._DB_PATH
        store._DB_PATH = Path(self._tmpdir.name) / "test_harness_state.db"

    def tearDown(self):
        store._DB_PATH = self._original_db_path
        self._tmpdir.cleanup()

    def _try_confirm(self, capability: str) -> tuple[bool, str]:
        plan = TestPlan(
            id=f"plan-{capability}",
            capability=capability,
            finding_class="x",
            category="x",
            source_exchange_url="https://confirmation-allowlist-test.invalid/x",
            execution_plane="burp",
            source_exchange_hash="hash-abc",
        )
        store.persist_retry_plan(plan)
        submission = ValidationSubmission(
            plan_id=plan.id, status="confirmed", confirmed=True,
            executor=f"burp:{capability}", source_exchange_hash="hash-abc",
        )
        return store.persist_validation_submission(submission)

    def test_capabilities_expected_to_allow_confirmation(self):
        for capability in (
            "cross_identity_compare", "authorization_boundary_compare",
            "sql_injection_validation", "cors_misconfiguration_detection",
            "reflection_context_validation", "open_redirect_validation",
            "jwt_validation",
        ):
            ok, reason = self._try_confirm(capability)
            self.assertTrue(ok, f"{capability} should be allowed to confirm, got: {reason}")

    def test_capabilities_expected_to_reject_confirmation(self):
        # A representative sample, not exhaustive: capabilities that
        # provide real evidence but were deliberately NOT added in this
        # session's audit (xxe/ssti: no live false-positive check done
        # yet; command_injection_validation: timing-based, deliberately
        # left off pending a live false-positive check -- see store.py's
        # own comment).
        for capability in (
            "xxe_validation", "ssti_validation", "command_injection_validation",
            "csp_clickjacking_validation",
        ):
            ok, reason = self._try_confirm(capability)
            self.assertFalse(ok, f"{capability} should NOT be allowed to confirm yet")
            self.assertEqual(reason, "this capability may provide evidence but cannot mark the vulnerability confirmed")


class TestConnectConcurrentMigrationIsIdempotent(unittest.TestCase):
    """Regression test: _connect()'s identities-table migration (tenant /
    permissions_json / trust) is a check-then-act -- PRAGMA table_info() read,
    then a conditional ALTER TABLE. Concurrent first callers on a fresh on-disk
    db (e.g. asyncio.to_thread() callers racing inside an asyncio.gather()) can
    all see the column missing and all attempt the ALTER; the losers used to
    raise sqlite3.OperationalError: duplicate column name. Flaky ~1-in-2 on the
    full suite before the fix (see harness/CURRENT_STATE.md), not reproducible
    on a single-threaded run -- hence the concurrent harness below."""

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._original_db_path = store._DB_PATH
        store._DB_PATH = Path(self._tmpdir.name) / "test_harness_state_concurrent.db"

    def tearDown(self):
        store._DB_PATH = self._original_db_path
        self._tmpdir.cleanup()

    def test_concurrent_first_connects_do_not_raise(self):
        import threading

        worker_count = 16
        barrier = threading.Barrier(worker_count)
        errors: list[BaseException] = []
        lock = threading.Lock()

        def worker():
            try:
                barrier.wait(timeout=5)
                conn = store._connect()
                conn.close()
            except BaseException as exc:  # noqa: BLE001 -- capture for the main thread
                with lock:
                    errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(worker_count)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        self.assertEqual(errors, [], f"_connect() raised under concurrency: {errors}")

        conn = store._connect()
        try:
            ident_cols = {row[1] for row in conn.execute("PRAGMA table_info(identities)")}
        finally:
            conn.close()
        self.assertTrue({"tenant", "permissions_json", "trust"}.issubset(ident_cols))


if __name__ == "__main__":
    unittest.main()
