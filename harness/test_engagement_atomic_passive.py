"""R10 synthetic SQLite/HTTP/passive orchestrator controls; no target traffic."""
import asyncio
import json
import subprocess
import sys
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import unittest
from unittest.mock import AsyncMock, patch

from harness import cache, store
from harness.models import HttpExchange
from harness.ollama_client import OllamaResult
from harness.run_context import RunContext
from harness import test_pairing_contract as pairing
from harness.test_run_summary_ledger import _build, _InertStubOllama


class ContextProvider(_InertStubOllama):
    def __init__(self):
        self.marker = "ordinary-A"
        self.prompts = []

    async def chat_json_metered(self, model, system_prompt, user_prompt, temperature=0.1, seed=None):
        self.prompts.append(user_prompt)
        if "coordinator in a security-testing harness" in system_prompt:
            return OllamaResult({"dispatch": ["misconfig"], "reason": "ordinary response metadata"}, 5, 5)
        return OllamaResult({"findings": [{"vulnerability_class": "information_disclosure",
            "severity": "info", "confidence": 0.8, "summary": self.marker,
            "evidence": "ordinary captured metadata " + self.marker,
            "suggested_test": "Review captured metadata", "basis": "derived"}], "components": []}, 5, 5)


class HttpSnapshotTests(unittest.TestCase):
    def setUp(self):
        # Real routes loaded with synthetic config/provider and a private DB.
        pairing.PairingCallerTests.setUp(self)

    def test_concurrent_server_updates_retain_both_and_read_partition(self):
        start = threading.Barrier(2)
        def update(marker):
            start.wait(timeout=5)
            return self.server._update_engagement("captured.example",
                lambda st: st.ingest_identity(marker, "user"), engagement_id="eng-A")
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(update, ["context-A", "context-B"]))
        self.assertTrue(all(results))
        snapshot = store.load_engagement("captured.example", engagement_id="eng-A")
        self.assertEqual({i["name"] for i in snapshot["identities"]}, {"context-A", "context-B"})
        self.assertEqual(snapshot["_snapshot_revision"], 2)
        self.server._update_engagement("captured.example",
            lambda st: st.ingest_findings("https://captured.example/private-A", "GET", []),
            engagement_id="eng-A")
        a = self.client.get("/engagement/captured.example", params={"engagement_id": "eng-A"}, headers=self.auth)
        b = self.client.get("/engagement/captured.example", params={"engagement_id": "eng-B"}, headers=self.auth)
        self.assertEqual(a.status_code, 200)
        self.assertIn("/private-A", a.text)
        self.assertNotIn("/private-A", b.text)
        self.assertEqual(b.json()["endpoint_count"], 0)

    def test_failed_caller_mutation_rolls_back_and_preserves_revision(self):
        initial = self.server._update_engagement("captured.example",
            lambda st: st.ingest_identity("retained", "user"), engagement_id="eng-A")
        def fail(st):
            st.ingest_identity("must-rollback", "user")
            raise RuntimeError("synthetic failure")
        self.assertIsNone(self.server._update_engagement("captured.example", fail, engagement_id="eng-A"))
        self.assertEqual(store.load_engagement("captured.example", engagement_id="eng-A"), initial)

    def test_negative_control_old_load_save_loses_a_concurrent_update(self):
        loaded = threading.Barrier(2)
        def broken_mutation(host, fn, *, engagement_id):
            snapshot = store.load_engagement(host, engagement_id=engagement_id) or {"host": host}
            loaded.wait(timeout=5)
            # Reproduce the previous production caller's unversioned overwrite.
            return store.save_engagement(host, fn(snapshot), engagement_id=engagement_id)
        with patch.object(store, "mutate_engagement", side_effect=broken_mutation):
            with ThreadPoolExecutor(max_workers=2) as pool:
                futures = [pool.submit(self.server._update_engagement, "captured.example",
                    lambda st, marker=marker: st.ingest_identity(marker, "user"),
                    engagement_id="eng-A") for marker in ["context-A", "context-B"]]
                self.assertTrue(all(f.result(timeout=10) for f in futures))
        snapshot = store.load_engagement("captured.example", engagement_id="eng-A")
        self.assertEqual(len(snapshot["identities"]), 1)
        # The production acceptance assertion must fail under this defect.
        with self.assertRaises(AssertionError):
            self.assertEqual({i["name"] for i in snapshot["identities"]}, {"context-A", "context-B"})

    def test_stale_and_cross_partition_replacements_are_rejected(self):
        a = store.save_engagement("captured.example", {"identities": []}, engagement_id="eng-A")
        store.mutate_engagement("captured.example", lambda state: dict(state, marker="retained"), engagement_id="eng-A")
        with self.assertRaises(store.EngagementRevisionConflict):
            store.save_engagement("captured.example", a, engagement_id="eng-A")
        with self.assertRaises(store.EngagementRevisionConflict):
            store.save_engagement("captured.example", a, engagement_id="eng-B")
        self.assertEqual(store.load_engagement("captured.example", engagement_id="eng-A")["marker"], "retained")
        self.assertIsNone(store.load_engagement("captured.example", engagement_id="eng-B"))

    def test_legacy_snapshot_never_seeds_explicit_partition(self):
        with store._connect() as conn:
            conn.execute("INSERT INTO engagement_state VALUES (?,?,?)",
                ("captured.example", json.dumps({"host": "captured.example", "context": "legacy-private"}), 1))
        conn.close()
        self.assertEqual(store.load_engagement("captured.example")["context"], "legacy-private")
        self.assertIsNone(store.load_engagement("captured.example", engagement_id="new-context"))

    def test_existing_host_wipe_includes_new_snapshot_partitions(self):
        for host, part in [("captured.example", "eng-A"), ("captured.example", "eng-B"), ("other.example", "eng-A")]:
            store.save_engagement(host, {"context": "benign"}, engagement_id=part)
        counts = store.wipe_engagement("captured.example")
        self.assertEqual(counts["scoped_engagement_state"], 2)
        self.assertIsNone(store.load_engagement("captured.example", engagement_id="eng-A"))
        self.assertIsNone(store.load_engagement("captured.example", engagement_id="eng-B"))
        self.assertIsNotNone(store.load_engagement("other.example", engagement_id="eng-A"))

    def test_http_analyze_propagates_explicit_partition_and_validates_length(self):
        stub = AsyncMock(return_value={"coordinator_model": "synthetic", "dispatched_agents": [], "agent_reports": [], "summary": "benign fixture"})
        with patch.object(self.server.orchestrator, "analyze", stub):
            response = self.client.post("/analyze", json=dict(self.request, engagement_id="eng-A"), headers=self.auth)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(stub.call_args.kwargs["engagement_id"], "eng-A")
            rejected = self.client.post("/analyze", json=dict(self.request, engagement_id="x" * 129), headers=self.auth)
            self.assertEqual(rejected.status_code, 422)
            self.assertEqual(stub.call_count, 1)

    def test_api_default_partition_is_shared_and_visible_by_returned_id(self):
        previous_cache = cache._cache
        self.addCleanup(setattr, cache, "_cache", previous_cache)
        cache.init_cache(db_path=str(Path(self.tmp.name) / "cache.db"))
        provider = ContextProvider()
        self.server.orchestrator = _build(provider)
        with patch("harness.run_context.TargetTransport.execute", side_effect=AssertionError("target forbidden")), \
                patch("httpx.AsyncClient.request", side_effect=AssertionError("upstream forbidden")):
            replies = []
            for marker in ["A", "B"]:
                provider.marker = "API_PRIVATE_" + marker
                reply = self.client.post("/analyze", headers=self.auth, json={"exchange": {
                    "url": "http://run-summary.test/ordinary-" + marker, "method": "GET",
                    "response_status": 200, "response_body": "ok"}})
                self.assertEqual(reply.status_code, 200)
                replies.append(reply.json())
            ids = [reply["engagement_id"] for reply in replies]
            self.assertEqual(ids, ["", ""])
            for marker, other, partition in [("A", "B", ids[0]), ("B", "A", ids[1])]:
                for endpoint in ["/report", "/report/sarif"]:
                    report = self.client.get(endpoint, headers=self.auth, params={
                        "url": "http://run-summary.test/", "engagement_id": partition})
                    self.assertEqual(report.status_code, 200)
                    self.assertIn("ordinary-" + other, report.text)
                self.assertIn("API_PRIVATE_" + marker, self.client.get("/report", headers=self.auth,
                    params={"url": "http://run-summary.test/", "engagement_id": partition}).text)
            self.assertEqual(len(store.all_host_findings("http://run-summary.test/")), 2)
            # Reopening persistence retains the same default report contract.
            for endpoint in ["/report", "/report/sarif"]:
                report = self.client.get(endpoint, headers=self.auth,
                    params={"url": "http://run-summary.test/"})
                self.assertIn("ordinary-A", report.text)
                self.assertIn("ordinary-B", report.text)
                self.assertEqual(self.client.get(endpoint,
                    params={"url": "http://run-summary.test/"}).status_code, 401)
            code = '''import sys,json
from pathlib import Path
from harness.test_pairing_contract import PairingCallerTests
from harness import store
fixture=PairingCallerTests('test_health_is_liveness_and_pairing_requires_credential');fixture.setUp()
try:
 store._DB_PATH=Path(sys.argv[1])
 output={}
 for route in ['/report','/report/sarif']:
  reply=fixture.client.get(route,params={'url':'http://run-summary.test/'},headers=fixture.auth)
  output[route]={'status':reply.status_code,'A':'ordinary-A' in reply.text,'B':'ordinary-B' in reply.text}
 print(json.dumps(output))
finally: fixture.doCleanups()
'''
            child = subprocess.run([sys.executable, '-c', code, str(store._DB_PATH)],
                capture_output=True, text=True, check=True, timeout=30)
            self.assertEqual(json.loads(child.stdout.strip().splitlines()[-1]),
                {route: {'status': 200, 'A': True, 'B': True} for route in ['/report', '/report/sarif']})

    def test_passive_prioritize_partitions_request_owned_or_explicit_context(self):
        from harness.models import PrioritizeResultItem
        self.server.orchestrator.ollama = object()
        async def prioritize(items, *args):
            return [PrioritizeResultItem(method=item.method, url=item.url, ai_priority="low",
                ai_score=0.2, reasoning="ordinary metadata") for item in items]
        with patch.object(self.server.surface_prioritizer, "prioritize", side_effect=prioritize):
            responses = []
            for marker in ["A", "B"]:
                response = self.client.post("/prioritize", headers=self.auth, json={"items": [
                    {"method": "GET", "url": "http://captured.example/ordinary-" + marker}]})
                self.assertEqual(response.status_code, 200)
                responses.append(response)
            ids = [response.json()["engagement_id"] for response in responses]
            self.assertNotEqual(ids[0], ids[1])
            a = store.load_engagement("captured.example", engagement_id=ids[0])
            b = store.load_engagement("captured.example", engagement_id=ids[1])
            self.assertNotIn("ordinary-B", json.dumps(a))
            self.assertNotIn("ordinary-A", json.dumps(b))
            self.assertIsNone(store.load_engagement("captured.example"))
            explicit = self.client.post("/prioritize", headers=self.auth, json={"engagement_id": ids[0],
                "items": [{"method": "GET", "url": "http://captured.example/ordinary-C"}]})
            self.assertEqual(explicit.json()["engagement_id"], ids[0])
            a = store.load_engagement("captured.example", engagement_id=ids[0])
            self.assertIn("GET /ordinary-A", a["endpoints"])
            self.assertIn("GET /ordinary-C", a["endpoints"])
            # Inject the former host-only caller. The legacy exclusion
            # acceptance fails even though the response still carries an ID.
            scoped_update = self.server._update_engagement
            def legacy_update(host, apply_fn, **kwargs):
                return scoped_update(host, apply_fn)
            with patch.object(self.server, "_update_engagement", side_effect=legacy_update):
                defective = self.client.post("/prioritize", headers=self.auth, json={"items": [
                    {"method": "GET", "url": "http://captured.example/ordinary-D"}]})
            self.assertEqual(defective.status_code, 200)
            with self.assertRaises(AssertionError):
                self.assertIsNone(store.load_engagement("captured.example"))

    def test_shared_read_contract_is_explicit_and_never_falls_back_to_named_records(self):
        self.server._update_engagement("captured.example",
            lambda st: st.ingest_findings("https://captured.example/owned", "GET", []), engagement_id="eng-A")
        legacy = self.client.get("/engagement/captured.example", headers=self.auth)
        self.assertEqual(legacy.json()["state_partition"], "shared-site-history")
        self.assertNotIn("/owned", legacy.text)
        markdown = self.client.get("/report", headers=self.auth, params={"url": "https://captured.example/"})
        self.assertIn("Shared site history", markdown.text)
        sarif = self.client.get("/report/sarif", headers=self.auth, params={"url": "https://captured.example/"})
        self.assertEqual(sarif.json()["runs"][0]["properties"]["state_partition"], "shared-site-history")

    def test_real_passive_http_findings_context_markdown_and_sarif_isolation(self):
        previous_cache = cache._cache
        self.addCleanup(setattr, cache, "_cache", previous_cache)
        cache.init_cache(db_path=str(Path(self.tmp.name) / "cache.db"))
        provider = ContextProvider()
        self.server.orchestrator = _build(provider)
        # ASGI TestClient is in-process. The real passive inference has an inert
        # provider, and every target send raises rather than reaching a socket.
        with patch("harness.run_context.TargetTransport.execute", side_effect=AssertionError("target forbidden")), \
                patch("httpx.AsyncClient.request", side_effect=AssertionError("upstream forbidden")):
            def analyze(path, part):
                return self.client.post("/analyze", headers=self.auth, json={"engagement_id": part,
                    "exchange": {"url": "http://run-summary.test/" + path, "method": "GET",
                        "request_headers": {"Cookie": "session=" + part}, "response_status": 200,
                        "response_body": "ok"}})
            a = analyze("ordinary-A", "eng-A")
            self.assertEqual(a.status_code, 200)
            self.assertTrue(a.json()["agent_reports"][0]["findings"])
            provider.marker = "ordinary-B"
            provider.prompts.clear()
            b = analyze("ordinary-B", "eng-B")
            self.assertEqual(b.status_code, 200)
            self.assertNotIn("ordinary-A", " ".join(provider.prompts))
            for endpoint in ["/report", "/report/sarif"]:
                read_a = self.client.get(endpoint, headers=self.auth,
                    params={"url": "http://run-summary.test/", "engagement_id": "eng-A"})
                read_b = self.client.get(endpoint, headers=self.auth,
                    params={"url": "http://run-summary.test/", "engagement_id": "eng-B"})
                self.assertEqual(read_a.status_code, 200)
                self.assertEqual(read_b.status_code, 200)
                self.assertIn("ordinary-A", read_a.text)
                self.assertNotIn("ordinary-B", read_a.text)
                self.assertIn("ordinary-B", read_b.text)
                self.assertNotIn("ordinary-A", read_b.text)
            self.assertEqual(store.all_host_findings("http://run-summary.test/"), [])
            # Regression detector: injecting the former host-wide query into
            # /report imports A into B, and the isolation assertion must fail.
            scoped = store.all_host_findings
            def broken(url, include_suppressed=False, **kw):
                return scoped(url, include_suppressed, engagement_id="eng-A") + scoped(url, include_suppressed, engagement_id="eng-B")
            with patch.object(store, "all_host_findings", side_effect=broken):
                leaked = self.client.get("/report", headers=self.auth,
                    params={"url": "http://run-summary.test/", "engagement_id": "eng-B"})
            with self.assertRaises(AssertionError):
                self.assertNotIn("ordinary-A", leaked.text)

    def test_shared_finding_reference_evidence_reads_are_partitioned(self):
        from harness import evidence_ledger
        previous_cache = cache._cache
        self.addCleanup(setattr, cache, "_cache", previous_cache)
        cache.init_cache(db_path=str(Path(self.tmp.name) / "cache.db"))
        self.server.orchestrator = _build(ContextProvider())
        refs = []
        with patch("harness.run_context.TargetTransport.execute", side_effect=AssertionError("target forbidden")), \
                patch("httpx.AsyncClient.request", side_effect=AssertionError("upstream forbidden")):
            for part in ["eng-A", "eng-B"]:
                response = self.client.post("/analyze", headers=self.auth, json={"engagement_id": part,
                    "exchange": {"url": "http://run-summary.test/shared", "method": "GET",
                                 "response_status": 200, "response_body": "ok"}})
                self.assertEqual(response.status_code, 200)
                refs.append(response.json()["agent_reports"][0]["findings"][0]["finding_id"])
            self.assertEqual(refs[0], refs[1], "fixture must exercise a shared deterministic finding reference")
            @store.isolate_engagement_context
            async def record_owned_marker():
                store.bind_engagement_context("eng-A")
                evidence_ledger.emit(evidence_ledger.EventType.OBSERVATION, refs[0], "A_ONLY_CONTEXT")
            asyncio.run(record_owned_marker())
            reads = [self.client.get(f"/findings/{refs[0]}/evidence", headers=self.auth,
                params={"engagement_id": part}) for part in ["eng-A", "eng-B"]]
            self.assertTrue(all(response.status_code == 200 for response in reads))
            self.assertIn("A_ONLY_CONTEXT", reads[0].text)
            self.assertNotIn("A_ONLY_CONTEXT", reads[1].text)
            self.assertEqual(self.client.get(f"/findings/{refs[0]}/evidence", headers=self.auth).status_code, 404)
            self.assertEqual(self.client.get(f"/findings/{refs[0]}/evidence", headers=self.auth,
                params={"engagement_id": "unowned"}).status_code, 404)
            self.assertEqual(store._CURRENT_ENGAGEMENT.get(), "")

    def test_legacy_findings_and_ledger_migrate_without_seeding_owned_context(self):
        from harness.models import Finding
        exchange = HttpExchange(url="http://captured.example/legacy", method="GET")
        store.persist_findings(exchange, "synthetic", [Finding(vulnerability_class="information_disclosure",
            confidence=0.8, summary="LEGACY_ONLY_CONTEXT", evidence="ordinary", suggested_test="", basis="derived")])
        conn = store._connect()
        try:
            conn.execute("ALTER TABLE findings DROP COLUMN engagement_id")
            conn.execute("ALTER TABLE ledger_events DROP COLUMN engagement_id")
            conn.commit()
        finally:
            conn.close()
        self.assertEqual(store.all_host_findings(exchange.url)[0]["summary"], "LEGACY_ONLY_CONTEXT")
        self.assertEqual(store.all_host_findings(exchange.url, engagement_id="eng-A"), [])
        self.assertEqual(store.prior_findings_summary(exchange.url, engagement_id="eng-A"), "")
        self.assertEqual(store.ledger_events_for("legacy", engagement_id="eng-A"), [])

    def test_same_engagement_principal_context_and_report_filters(self):
        previous_cache = cache._cache
        self.addCleanup(setattr, cache, "_cache", previous_cache)
        cache.init_cache(db_path=str(Path(self.tmp.name) / "cache.db"))
        provider = ContextProvider()
        self.server.orchestrator = _build(provider)
        def analyze(path, cookie):
            return self.client.post("/analyze", headers=self.auth, json={"engagement_id": "eng-A",
                "exchange": {"url": "http://run-summary.test/" + path, "method": "GET",
                    "request_headers": {"Cookie": cookie} if cookie else {}, "response_status": 200,
                    "response_body": "ok"}})
        with patch("harness.run_context.TargetTransport.execute", side_effect=AssertionError("target forbidden")), \
                patch("httpx.AsyncClient.request", side_effect=AssertionError("upstream forbidden")):
            a = analyze("ordinary-A", "session=private-A")
            self.assertEqual(a.status_code, 200)
            a_id = a.json()["captured_principal_id"]
            self.assertTrue(a_id.startswith("captured:"))
            self.assertNotIn("private-A", a_id)
            provider.marker = "ordinary-B"
            provider.prompts.clear()
            b = analyze("ordinary-B", "session=private-B")
            self.assertEqual(b.status_code, 200)
            b_id = b.json()["captured_principal_id"]
            self.assertNotEqual(a_id, b_id)
            self.assertNotIn("ordinary-A", " ".join(provider.prompts))
            provider.marker = "ordinary-anonymous"
            provider.prompts.clear()
            anonymous = analyze("ordinary-anonymous", "")
            self.assertEqual(anonymous.json()["captured_principal_id"], "anonymous")
            self.assertNotIn("ordinary-A", " ".join(provider.prompts))
            self.assertNotIn("ordinary-B", " ".join(provider.prompts))
            # Reusing A's captured credentials on new surface may use A's context.
            provider.marker = "ordinary-A-second"
            provider.prompts.clear()
            again = analyze("ordinary-A-second", "session=private-A")
            self.assertEqual(again.json()["captured_principal_id"], a_id)
            self.assertIn("ordinary-A", " ".join(provider.prompts))
            self.assertNotIn("ordinary-B", " ".join(provider.prompts))
            conn = store._connect()
            try:
                hmac_key = conn.execute("SELECT value FROM state_metadata WHERE name='principal-hmac-v1'").fetchone()[0]
            finally:
                conn.close()
            for endpoint in ["/report", "/report/sarif"]:
                report = self.client.get(endpoint, headers=self.auth, params={"url": "http://run-summary.test/",
                    "engagement_id": "eng-A", "captured_principal_id": b_id})
                self.assertEqual(report.status_code, 200)
                self.assertIn("ordinary-B", report.text)
                self.assertNotIn("ordinary-A", report.text)
                self.assertIn(b_id, report.text)
                self.assertNotIn(hmac_key, report.text)
                self.assertNotIn("private-A", report.text)
                self.assertNotIn("private-B", report.text)
            # Inject former unpartitioned prior prompt context and demonstrate
            # the exact no-cross-principal assertion detects it.
            summary = store.prior_findings_summary
            def broken_context(url, **kwargs):
                kwargs["captured_principal"] = None
                return summary(url, **kwargs)
            provider.prompts.clear()
            with patch.object(store, "prior_findings_summary", side_effect=broken_context):
                analyze("ordinary-B-second", "session=private-B")
            with self.assertRaises(AssertionError):
                self.assertNotIn("ordinary-A", " ".join(provider.prompts))

    def test_captured_principal_is_keyed_per_database_and_case_normalized(self):
        exchange = HttpExchange(url="http://captured.example/", method="GET",
                                request_headers={"Cookie": "session=low-entropy-fixture"})
        first = store.captured_principal_id(exchange)
        same = store.captured_principal_id(exchange.model_copy(update={"request_headers": {"cookie": "session=low-entropy-fixture"}}))
        self.assertEqual(first, same)
        with patch.object(store, "_DB_PATH", Path(self.tmp.name) / "other.db"):
            other = store.captured_principal_id(exchange)
        self.assertNotEqual(first, other)
        self.assertNotIn("low-entropy-fixture", first)

    def test_same_engagement_shared_reference_evidence_filters_principals(self):
        from harness import evidence_ledger
        previous_cache = cache._cache
        self.addCleanup(setattr, cache, "_cache", previous_cache)
        cache.init_cache(db_path=str(Path(self.tmp.name) / "cache.db"))
        self.server.orchestrator = _build(ContextProvider())
        contexts = []
        refs = []
        with patch("harness.run_context.TargetTransport.execute", side_effect=AssertionError("target forbidden")), \
                patch("httpx.AsyncClient.request", side_effect=AssertionError("upstream forbidden")):
            for marker in ["A", "B"]:
                response = self.client.post("/analyze", headers=self.auth, json={"engagement_id": "eng-A",
                    "exchange": {"url": "http://run-summary.test/shared", "method": "GET",
                        "request_headers": {"Cookie": "session=principal-" + marker}, "response_status": 200, "response_body": "ok"}})
                self.assertEqual(response.status_code, 200)
                contexts.append(response.json()["captured_principal_id"])
                refs.append(response.json()["agent_reports"][0]["findings"][0]["finding_id"])
            self.assertEqual(refs[0], refs[1])
            @store.isolate_engagement_context
            async def record_a():
                store.bind_engagement_context("eng-A")
                store.bind_captured_principal_context(contexts[0])
                evidence_ledger.emit(evidence_ledger.EventType.OBSERVATION, refs[0], "PRINCIPAL_A_ONLY_CONTEXT")
            asyncio.run(record_a())
            reports = [self.client.get(f"/findings/{refs[0]}/evidence", headers=self.auth,
                params={"engagement_id": "eng-A", "captured_principal_id": context}) for context in contexts]
            self.assertTrue(all(report.status_code == 200 for report in reports))
            self.assertIn("PRINCIPAL_A_ONLY_CONTEXT", reports[0].text)
            self.assertNotIn("PRINCIPAL_A_ONLY_CONTEXT", reports[1].text)
            self.assertEqual(len(store.all_host_findings("http://run-summary.test/shared", engagement_id="eng-A")), 2)
            aggregate = self.client.get("/report", headers=self.auth,
                params={"url": "http://run-summary.test/shared", "engagement_id": "eng-A"})
            for context in contexts:
                self.assertIn(context, aggregate.text)
            self.assertEqual(store._CURRENT_CAPTURED_PRINCIPAL.get(), "")


class PassiveAnalyzeSnapshotTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        for obj, field, value in [(store, "_DB_PATH", Path(self.tmp.name) / "state.db"),
                                  (cache, "_cache", None)]:
            p = patch.object(obj, field, value)
            p.start()
            self.addCleanup(p.stop)
        cache.init_cache(db_path=str(Path(self.tmp.name) / "cache.db"))
        self.orch = _build(_InertStubOllama())
        # Any accidentally activated transport/model HTTP fails the control.
        for target in ["harness.run_context.TargetTransport.execute", "httpx.AsyncClient.request", "httpx.Client.request"]:
            p = patch(target, side_effect=AssertionError("network forbidden in R10 fixture"))
            p.start()
            self.addCleanup(p.stop)

    async def analyze(self, path, partition="", ctx=None):
        return await self.orch.analyze(HttpExchange(url="http://run-summary.test/" + path,
            method="GET", request_headers={"Cookie": "session=" + path},
            response_status=200, response_body="ok"), bypass_cache=True,
            engagement_id=partition, run_context=ctx)

    async def test_concurrent_passive_analyze_retains_both_endpoints(self):
        await asyncio.gather(self.analyze("ordinary-A", "eng-A"), self.analyze("ordinary-B", "eng-A"))
        snap = store.load_engagement("run-summary.test", engagement_id="eng-A")
        self.assertEqual(set(snap["endpoints"]), {"GET /ordinary-A", "GET /ordinary-B"})
        self.assertEqual(snap["_snapshot_revision"], 2)
        self.assertNotIn("session=", json.dumps(snap))

    async def test_different_engagements_same_host_are_isolated(self):
        await asyncio.gather(self.analyze("context-A", "eng-A"), self.analyze("context-B", "eng-B"))
        a = store.load_engagement("run-summary.test", engagement_id="eng-A")
        b = store.load_engagement("run-summary.test", engagement_id="eng-B")
        self.assertIn("GET /context-A", a["endpoints"])
        self.assertNotIn("context-A", json.dumps(b))
        self.assertNotIn("context-B", json.dumps(a))
        self.assertIsNone(store.load_engagement("run-summary.test"))

    async def test_direct_legacy_default_keeps_host_only_visibility(self):
        ctx_a = RunContext.create(allowed_hosts=["run-summary.test"], config=self.orch.config)
        ctx_b = RunContext.create(allowed_hosts=["run-summary.test"], config=self.orch.config)
        try:
            response_a = await self.analyze("run-A", ctx=ctx_a)
            response_b = await self.analyze("run-B", ctx=ctx_b)
            self.assertEqual(response_a.engagement_id, "")
            self.assertEqual(response_b.engagement_id, "")
            legacy = store.load_engagement("run-summary.test")
            self.assertIn("run-A", json.dumps(legacy))
            self.assertIn("run-B", json.dumps(legacy))
        finally:
            await ctx_a.aclose()
            await ctx_b.aclose()

    async def test_full_cache_hit_retains_partition_and_other_partition_misses(self):
        provider = ContextProvider()
        self.orch = _build(provider)
        ctx = RunContext.create(allowed_hosts=["run-summary.test"], config=self.orch.config)
        exchange = HttpExchange(url="http://run-summary.test/cache", method="GET", response_status=200, response_body="ok")
        try:
            a = await self.orch.analyze(exchange, run_context=ctx, engagement_id="eng-A")
            calls = len(provider.prompts)
            cached = await self.orch.analyze(exchange, run_context=ctx, engagement_id="eng-A")
            self.assertEqual(len(provider.prompts), calls)
            self.assertIn("(cached)", cached.summary)
            self.assertEqual(cached.engagement_id, "eng-A")
            provider.marker = "ordinary-B"
            b = await self.orch.analyze(exchange, run_context=ctx, engagement_id="eng-B")
            self.assertGreater(len(provider.prompts), calls)
            self.assertEqual(b.engagement_id, "eng-B")
            self.assertNotIn("(cached)", b.summary)
            self.assertNotEqual(store.all_host_findings(exchange.url, engagement_id="eng-A")[0]["fingerprint"],
                                store.all_host_findings(exchange.url, engagement_id="eng-B")[0]["fingerprint"])
        finally:
            await ctx.aclose()

    async def test_hypothesis_cache_reuses_only_owned_unchanged_context(self):
        provider = ContextProvider()
        self.orch = _build(provider)
        self.orch.config.setdefault("runs", {})["hypothesis_cache"] = {"enabled": True}
        exchange = HttpExchange(url="http://run-summary.test/hypothesis", method="GET", response_status=200, response_body="ok")
        await self.orch.analyze(exchange, engagement_id="eng-A")
        calls = len(provider.prompts)
        await self.orch.analyze(exchange, engagement_id="eng-A")
        self.assertEqual(len(provider.prompts), calls)
        provider.marker = "ordinary-B"
        await self.orch.analyze(exchange, engagement_id="eng-B")
        self.assertGreater(len(provider.prompts), calls)
        calls = len(provider.prompts)
        await self.orch.analyze(exchange, engagement_id="eng-A")
        self.assertEqual(len(provider.prompts), calls, "B's cache ownership must not evict A's entry")
        # A later observation in A changes its prior-context cache identity.
        from harness.models import Finding
        store.persist_findings(HttpExchange(url="http://run-summary.test/context", method="GET"), "synthetic", [Finding(
            vulnerability_class="information_disclosure", confidence=0.8, summary="owned-new-context",
            evidence="ordinary metadata", suggested_test="Review captured metadata", basis="derived")], engagement_id="eng-A")
        calls = len(provider.prompts)
        provider.prompts.clear()
        await self.orch.analyze(exchange, engagement_id="eng-A")
        self.assertGreater(len(provider.prompts), 0)
        self.assertIn("owned-new-context", " ".join(provider.prompts))

    async def test_dedup_same_coordinates_different_engagement_retains_both(self):
        from harness.models import Finding
        exchange = HttpExchange(url="http://run-summary.test/same", method="GET")
        finding = Finding(vulnerability_class="information_disclosure", confidence=0.8,
            summary="ordinary-A", evidence="ordinary", suggested_test="", basis="derived")
        store.persist_findings(exchange, "synthetic", [finding], engagement_id="eng-A")
        finding.summary = "ordinary-B"
        store.persist_findings(exchange, "synthetic", [finding], engagement_id="eng-B")
        a = store.all_host_findings(exchange.url, engagement_id="eng-A")
        b = store.all_host_findings(exchange.url, engagement_id="eng-B")
        self.assertEqual(a[0]["summary"], "ordinary-A")
        self.assertEqual(b[0]["summary"], "ordinary-B")
        self.assertNotEqual(a[0]["fingerprint"], b[0]["fingerprint"])
        # Existing suppression ownership follows the partitioned fingerprint.
        store.suppress_finding(a[0]["fingerprint"])
        self.assertEqual(store.all_host_findings(exchange.url, engagement_id="eng-A"), [])
        self.assertEqual(len(store.all_host_findings(exchange.url, engagement_id="eng-B")), 1)

    async def test_full_cache_invalidates_config_guide_note_and_principal(self):
        provider = ContextProvider()
        self.orch = _build(provider)
        ctx = RunContext.create(allowed_hosts=["run-summary.test"], config=self.orch.config)
        exchange = HttpExchange(url="http://run-summary.test/cache-identity", method="GET", response_status=200, response_body="ok")
        try:
            await self.orch.analyze(exchange, run_context=ctx, engagement_id="eng-A")
            calls = len(provider.prompts)
            await self.orch.analyze(exchange, run_context=ctx, engagement_id="eng-A")
            self.assertEqual(len(provider.prompts), calls)
            self.orch.config["synthetic_provider_identity"] = "provider-B"
            await self.orch.analyze(exchange, run_context=ctx, engagement_id="eng-A")
            self.assertGreater(len(provider.prompts), calls)
            calls = len(provider.prompts)
            with patch.object(self.orch.agent_manager.agents["misconfig"], "_guide_version", return_value="guide-B"):
                await self.orch.analyze(exchange, run_context=ctx, engagement_id="eng-A")
                self.assertGreater(len(provider.prompts), calls)
            for changed in [exchange.model_copy(update={"analyst_note": "ordinary note-B"}),
                            exchange.model_copy(update={"request_headers": {"Cookie": "session=principal-B"}})]:
                calls = len(provider.prompts)
                await self.orch.analyze(changed, run_context=ctx, engagement_id="eng-A")
                self.assertGreater(len(provider.prompts), calls)
        finally:
            await ctx.aclose()

    async def test_failed_stage_and_agent_error_are_never_cached_as_success(self):
        from harness.models import StageOutcome, AgentReport
        for mode in ["failed-stage", "agent-error"]:
            with self.subTest(mode=mode):
                self.orch = _build(_InertStubOllama())
                self.orch.config.setdefault("runs", {})["hypothesis_cache"] = {"enabled": True}
                ctx = RunContext.create(allowed_hosts=["run-summary.test"], config=self.orch.config)
                exchange = HttpExchange(url="http://run-summary.test/" + mode, method="GET", response_status=200, response_body="ok")
                failure = ([AgentReport(agent="misconfig", model="synthetic", findings=[], raw_error="synthetic error")] if mode == "agent-error" else [],
                           0, 0, StageOutcome(name="critique", status="failed" if mode == "failed-stage" else "completed"))
                success = ([], 0, 0, StageOutcome(name="critique", status="completed"))
                pipeline = AsyncMock(side_effect=[failure, success])
                try:
                    with patch.object(self.orch, "_choose_agents", AsyncMock(return_value=(["misconfig"], "ordinary"))), \
                            patch.object(self.orch.analysis_pipeline, "run_full_analysis", pipeline):
                        first = await self.orch.analyze(exchange, run_context=ctx, engagement_id=mode)
                        second = await self.orch.analyze(exchange, run_context=ctx, engagement_id=mode)
                        self.assertEqual(pipeline.call_count, 2)
                        self.assertNotIn("(cached)", second.summary)
                        third = await self.orch.analyze(exchange, run_context=ctx, engagement_id=mode)
                        self.assertEqual(pipeline.call_count, 2)
                        self.assertIn("(cached)", third.summary)
                finally:
                    await ctx.aclose()

    async def test_stored_failed_full_and_hypothesis_entries_do_not_skip_recovery(self):
        from types import SimpleNamespace
        from harness.models import AnalysisResponse, StageOutcome
        self.orch.config.setdefault("runs", {})["hypothesis_cache"] = {"enabled": True}
        exchange = HttpExchange(url="http://run-summary.test/stored-failure", method="GET", response_status=200, response_body="ok")
        failed = StageOutcome(name="critique", status="failed")
        full = AnalysisResponse(coordinator_model="synthetic", dispatched_agents=[], agent_reports=[],
                                summary="stored failure", stage_outcomes=[failed], degraded=True)
        hypothesis = SimpleNamespace(reports=[], stage_outcomes=[failed], dispatch=[], reason="stored failure", findings_reviewed=0, findings_rejected=0)
        pipeline = AsyncMock(return_value=([], 0, 0, StageOutcome(name="critique", status="completed")))
        with patch.object(cache.get_cache(), "get", return_value=full), \
                patch.object(cache.get_cache(), "get_hypothesis", return_value=hypothesis), \
                patch.object(self.orch.analysis_pipeline, "run_full_analysis", pipeline), \
                patch.object(self.orch, "_choose_agents", AsyncMock(return_value=(["misconfig"], "ordinary"))):
            response = await self.orch.analyze(exchange, engagement_id="eng-A")
        self.assertEqual(pipeline.call_count, 1)
        self.assertFalse(response.degraded)
        self.assertNotIn("(cached)", response.summary)

    async def test_missing_corrupted_and_expired_hypothesis_entries_redispatch(self):
        provider = ContextProvider()
        self.orch = _build(provider)
        self.orch.config.setdefault("runs", {})["hypothesis_cache"] = {"enabled": True}
        exchange = HttpExchange(url="http://run-summary.test/cache-storage", method="GET", response_status=200, response_body="ok")
        first = await self.orch.analyze(exchange, engagement_id="eng-A")
        self.assertTrue(provider.prompts, "missing entry must invoke passive inference")
        self.assertGreater(cache.get_cache().hypothesis_stats().misses, 0)
        calls = len(provider.prompts)
        with cache.get_cache()._connection() as conn:
            conn.execute("UPDATE hypothesis_cache_entries SET payload_json = '{invalid-json'")
        second = await self.orch.analyze(exchange, engagement_id="eng-A")
        self.assertGreater(len(provider.prompts), calls)
        self.assertFalse(second.degraded)
        calls = len(provider.prompts)
        with cache.get_cache()._connection() as conn:
            conn.execute("UPDATE hypothesis_cache_entries SET created_at = 0, ttl_seconds = 1")
        third = await self.orch.analyze(exchange, engagement_id="eng-A")
        self.assertGreater(len(provider.prompts), calls)
        self.assertFalse(third.degraded)
        self.assertGreater(cache.get_cache().hypothesis_stats().evictions, 0)

    async def test_persisted_hypothesis_authority_is_rejected_before_caller_reuse(self):
        provider = ContextProvider()
        self.orch = _build(provider)
        self.orch.config.setdefault("runs", {})["hypothesis_cache"] = {"enabled": True}
        exchange = HttpExchange(url="http://run-summary.test/cache-authority", method="GET",
                                response_status=200, response_body="ok")
        await self.orch.analyze(exchange, engagement_id="eng-A")

        def poison(field, value):
            with cache.get_cache()._connection() as conn:
                row = conn.execute("SELECT exchange_hash, payload_json FROM hypothesis_cache_entries").fetchone()
                payload = json.loads(row["payload_json"])
                payload["reports"][0]["findings"][0][field] = value
                conn.execute("UPDATE hypothesis_cache_entries SET payload_json=? WHERE exchange_hash=?",
                             (json.dumps(payload), row["exchange_hash"]))

        for field, value in [("proof_id", "foreign-proof"), ("case_id", "foreign-case"),
                             ("confirmed", True), ("confirmed_by_leg", "foreign-leg"),
                             ("oracle_verified", True), ("oracle_capsule_id", "foreign-capsule"),
                             ("oracle_reason", "foreign-reason"), ("verification_state", "verified")]:
            with self.subTest(field=field):
                poison(field, value)
                calls = len(provider.prompts)
                response = await self.orch.analyze(exchange, engagement_id="eng-A")
                self.assertGreater(len(provider.prompts), calls)
                self.assertFalse(response.agent_reports[0].findings[0].confirmed)
                self.assertNotIn("foreign-", response.model_dump_json())

        # Inject the old read behavior. The caller redispatch acceptance must
        # fail, demonstrating that this test detects bypass of the read guard.
        poison("proof_id", "foreign-proof")
        calls = len(provider.prompts)
        with patch.object(cache.ExchangeCache, "_hypothesis_has_authority", return_value=False):
            await self.orch.analyze(exchange, engagement_id="eng-A")
        with self.assertRaises(AssertionError):
            self.assertGreater(len(provider.prompts), calls)

    async def test_scoped_passive_prompts_exclude_unowned_external_knowledge(self):
        from harness import knowledge
        provider = ContextProvider()
        self.orch = _build(provider)
        self.orch.config.setdefault("runs", {})["hypothesis_cache"] = {"enabled": True}
        tags = ["misconfig", "external", "knowledge", "ordinary"]
        for partition, marker in [("", "LEGACY_GLOBAL_PRIVATE_MARKER"),
                                  ("eng-A", "OWNED_BUT_UNATTRIBUTED_MARKER"),
                                  ("eng-B", "FOREIGN_PRIVATE_MARKER")]:
            store.save_knowledge_note(tags, "ordinary external knowledge " + marker, engagement_id=partition)
        exchange = HttpExchange(url="http://run-summary.test/ordinary/external/knowledge", method="GET",
                                response_status=200, response_body="ok")
        await self.orch.analyze(exchange, engagement_id="eng-A")
        self.assertTrue(provider.prompts)
        self.assertNotIn("_MARKER", " ".join(provider.prompts))
        # The policy prevents unowned note edits from changing either prompts
        # or reuse compatibility for this scoped passive context.
        calls = len(provider.prompts)
        store.save_knowledge_note(tags, "ordinary external knowledge GLOBAL_EDIT_MARKER")
        await self.orch.analyze(exchange, engagement_id="eng-A")
        self.assertEqual(len(provider.prompts), calls)
        retrieve = knowledge.retrieve
        def unscoped(agent_name, ex, **kwargs):
            return retrieve(agent_name, ex)
        provider.prompts.clear()
        with patch.object(knowledge, "retrieve", side_effect=unscoped):
            await self.orch.analyze(exchange, engagement_id="eng-A", bypass_cache=True)
        with self.assertRaises(AssertionError):
            self.assertNotIn("_MARKER", " ".join(provider.prompts))

    async def test_legacy_direct_passive_also_excludes_external_knowledge(self):
        provider = ContextProvider()
        self.orch = _build(provider)
        store.save_knowledge_note(["ordinary", "external", "knowledge", "misconfig"],
                                  "ordinary external knowledge LEGACY_SECRET_MARKER")
        await self.orch.analyze(HttpExchange(url="http://run-summary.test/ordinary/external/knowledge",
                                            method="GET", response_status=200, response_body="ok"))
        self.assertNotIn("LEGACY_SECRET_MARKER", " ".join(provider.prompts))


if __name__ == "__main__":
    unittest.main()
