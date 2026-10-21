"""I02 batch C (C2): retained observations through the real callers.

Acceptance cases C01, C03, C04, C08 and C09 from
reviews/2026-10-17-dual-mode-audit-01/ACCEPTANCE_SPEC.md, driven through
Orchestrator.analyze (C01/C03/C04) or the ASGI routes (C08/C09) with real
SQLite storage and retrieval, a temporary cache and a passive configuration.

The model is a canned consumer (_CannedConsumer): it reports a low-confidence
workflow-state review only when its prompt holds an earlier observation whose
supplied state is "shipped" AND the current response shows "placed" -- a
regression that neither capture shows alone -- and it cites the earlier
observation's id. It compares against the LAST earlier observation in prompt
order, so ordering matters. This establishes the retrieval/transport contract
only; real-model usefulness is I14. Every case also asserts that nothing was
sent to the target.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import httpx
import yaml

from harness import cache, safety_gate, store
from harness.models import HttpExchange
from harness.ollama_client import OllamaResult
from harness.orchestrator import Orchestrator

_HARNESS = Path(__file__).resolve().parent
_URL = "http://shop.invalid/api/orders/1001"
_OTHER_URL = "http://shop.invalid/api/orders/2002"
_SHIPPED = '{"id": 1001, "state": "shipped"}'
_PLACED = '{"id": 1001, "state": "placed"}'
_TOKEN_X = "Bearer synthetic-owner-x"
_TOKEN_Y = "Bearer synthetic-owner-y"
_OBS_LINE = re.compile(r"^- obs ([0-9a-f]{32}) \|.*\| state_version (\S+) \|", re.MULTILINE)


class _CannedConsumer:
    def __init__(self):
        self.prompts: list[str] = []

    def _reply(self, user_prompt: str) -> dict:
        self.prompts.append(user_prompt)
        earlier = _OBS_LINE.findall(user_prompt)
        if earlier and earlier[-1][1].startswith("shipped") and '"state": "placed"' in user_prompt:
            cited = earlier[-1][0]
            return {"findings": [{
                "vulnerability_class": "business_logic", "severity": "low", "confidence": 0.3,
                "summary": f"Possible workflow-state regression since observation {cited}",
                "evidence": f"observation {cited} recorded shipped; this response shows placed",
                "suggested_test": "request the missing transition record", "basis": "derived"}],
                "components": []}
        return {"findings": [], "components": []}

    async def chat_json(self, model, system_prompt, user_prompt, temperature=0.1):
        return self._reply(user_prompt)

    async def chat_json_metered(self, model, system_prompt, user_prompt, temperature=0.1):
        return OllamaResult(data=self._reply(user_prompt), prompt_tokens=1, completion_tokens=1)


def _config(*, hypothesis_cache: bool = False) -> dict:
    with open(_HARNESS / "config.yaml") as f:
        cfg = yaml.safe_load(f) or {}
    cfg.setdefault("coordinator", {})["cloud_primary"] = False
    cfg.setdefault("critique", {})["enabled"] = False
    cfg.setdefault("validators", {})["active_enabled"] = False   # passive: nothing sent
    for k in ("autonomous_discovery", "github_advisories", "kev_check", "package_registry_checks"):
        cfg.setdefault(k, {})["enabled"] = False
    cfg.setdefault("runs", {}).setdefault("hypothesis_cache", {})["enabled"] = hypothesis_cache
    return cfg


def _orchestrator(*, hypothesis_cache: bool = False) -> tuple[Orchestrator, _CannedConsumer]:
    model = _CannedConsumer()
    orch = Orchestrator(_config(hypothesis_cache=hypothesis_cache))
    orch.ollama = model
    for agent in getattr(orch.agent_manager, "agents", {}).values():
        agent.ollama = model
    if getattr(orch, "analysis_pipeline", None) is not None:
        orch.analysis_pipeline.ollama_client = model
    if getattr(orch, "coordinator", None) is not None and hasattr(orch.coordinator, "ollama"):
        orch.coordinator.ollama = model
    return orch, model


def _exchange(body: str, *, url: str = _URL, token: str = _TOKEN_X, **capture) -> HttpExchange:
    return HttpExchange(url=url, method="GET", request_headers={"Authorization": token},
                        response_status=200, response_headers={"Content-Type": "application/json"},
                        response_body=body, **capture)


def _cited(response) -> set[str]:
    """Observation ids cited by the consumer's findings in an analysis response."""
    reports = response["agent_reports"] if isinstance(response, dict) else \
        [r.model_dump() for r in response.agent_reports]
    found = set()
    for report in reports:
        for finding in report["findings"]:
            found.update(re.findall(r"observation ([0-9a-f]{32})", finding["summary"]))
    return found


class _CallerBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="i02c_caller_")
        self._orig = (store._DB_PATH, cache._cache)
        store._DB_PATH = Path(self._tmp) / "state.db"
        cache.init_cache(db_path=os.path.join(self._tmp, "cache.db"))
        safety_gate.reset_default_gate()
        self.sent: list[str] = []
        real_send = httpx.AsyncClient.send

        async def record_send(client, request, *a, **kw):
            self.sent.append(str(request.url))
            return await real_send(client, request, *a, **kw)

        self._send_patch = patch.object(httpx.AsyncClient, "send", record_send)
        self._send_patch.start()

    def tearDown(self):
        self._send_patch.stop()
        self.assertEqual([u for u in self.sent if "shop.invalid" in u], [],
                         "advisory analysis sent traffic to the target")
        safety_gate.reset_default_gate()
        store._DB_PATH, cache._cache = self._orig
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _analyze(self, orch, exchange, *, engagement_id: str = "", attribution=None, **kw):
        return asyncio.run(orch.analyze(exchange, force_agents=["business_logic"],
                                        engagement_id=engagement_id,
                                        observation_attribution=attribution, **kw))


class PairOnlyConclusionTests(_CallerBase):
    """C01: two nonfinding observations change the comparison; one alone does not."""

    def _pair(self, *, a_url: str = _URL, b_url: str = _URL):
        orch, model = _orchestrator()
        a = self._analyze(orch, _exchange(_SHIPPED, url=a_url, state_version="shipped@3", captured_at=100.0))
        b = self._analyze(orch, _exchange(_PLACED, url=b_url, state_version="placed@2", captured_at=200.0))
        return a, b, model

    def test_two_observations_produce_the_cited_comparison(self):
        a, b, model = self._pair()
        self.assertEqual([f for r in a.agent_reports for f in r.findings], [],
                         "A alone yields no finding")
        self.assertEqual(a.observation_context["write"]["status"], "stored",
                         "a capture with no finding is still retained")
        a_id = a.observation_context["write"]["observation_id"]
        self.assertEqual(_cited(b), {a_id})
        self.assertEqual([s["observation_id"] for s in b.observation_context["selected"]], [a_id])
        self.assertIn(f"obs {a_id}", model.prompts[-1])

    def test_either_observation_alone_is_insufficient(self):
        a, c, _ = self._pair(b_url=_OTHER_URL)   # A, then an unrelated endpoint
        self.assertEqual(_cited(c), set())
        self.assertEqual(c.observation_context["selected"], [])
        orch, _ = _orchestrator()
        b_alone = self._analyze(orch, _exchange(_PLACED, url="http://shop.invalid/api/orders/3003",
                                                state_version="placed@2"))
        self.assertEqual(_cited(b_alone), set())
        self.assertEqual(b_alone.observation_context["write"]["status"], "stored")

    def test_fault_severed_reader_is_detected(self):
        with patch.object(store, "select_observations", side_effect=RuntimeError("severed")):
            _, b, model = self._pair()
        self.assertEqual(_cited(b), set())
        self.assertEqual(b.observation_context["status"], "unavailable")
        self.assertIn("Do not assume that none exist", model.prompts[-1])

    def test_fault_skipped_durable_write_is_detected(self):
        with patch.object(store, "record_observation",
                          return_value={"status": "stored", "observation_id": "", "exchange_id": ""}):
            _, b, _ = self._pair()
        self.assertEqual(_cited(b), set(), "no earlier observation may be synthesized")
        self.assertEqual(b.observation_context["selected"], [])

    def test_engagement_and_harness_fetched_analyses_do_not_retain(self):
        orch, _ = _orchestrator()
        fetched = self._analyze(orch, _exchange(_SHIPPED), retain_observation=False)
        self.assertEqual(fetched.observation_context, {})
        from harness.run_context import RunContext

        async def borrowed():
            ctx = RunContext.create(allowed_hosts=[], config=_config(), max_requests=0)
            try:
                return await orch.analyze(_exchange(_SHIPPED), force_agents=["business_logic"],
                                          run_context=ctx)
            finally:
                await ctx.aclose()
        self.assertEqual(asyncio.run(borrowed()).observation_context, {})
        self.assertEqual(self._observation_count(), 0)

    def _inside_enclosing_run(self):
        """analyze() with no run argument while another run is published around
        it -- engagement-style work that owns a run of its own since I05-A2."""
        from harness.run_context import RunContext
        orch, _ = _orchestrator()

        async def nested():
            async with RunContext.create(allowed_hosts=[], config=_config(), max_requests=0):
                return await orch.analyze(_exchange(_SHIPPED), force_agents=["business_logic"])
        return asyncio.run(nested())

    def test_analysis_inside_an_enclosing_run_is_not_retained(self):
        self.assertEqual(self._inside_enclosing_run().observation_context, {})
        self.assertEqual(self._observation_count(), 0)

    def test_fault_ignoring_the_enclosing_run_is_detected(self):
        with patch("harness.run_context.current_run_context", return_value=None):
            response = self._inside_enclosing_run()
        self.assertEqual(response.observation_context["write"]["status"], "stored")
        self.assertEqual(self._observation_count(), 1)

    def _observation_count(self) -> int:
        conn = store._connect()
        try:
            return conn.execute("SELECT count(*) FROM exchange_observations").fetchone()[0]
        finally:
            conn.close()


class TimeOrderTests(_CallerBase):
    """C03: capture time, not arrival order, decides which state came last."""

    def _late_arrival(self, current_body: str):
        orch, model = _orchestrator()
        self._analyze(orch, _exchange('{"id": 1001, "v": 2}', state_version="shipped@3", captured_at=200.0))
        self._analyze(orch, _exchange('{"id": 1001, "v": 1}', state_version="placed@1", captured_at=100.0))
        return self._analyze(orch, _exchange(current_body, captured_at=300.0)), model

    def test_late_arriving_earlier_capture_is_ordered_by_capture_time(self):
        response, _ = self._late_arrival(_PLACED)
        self.assertEqual(len(_cited(response)), 1, "the latest capture (shipped) is the comparison basis")
        self.assertEqual(response.observation_context["order_basis"], "capture")

    def test_legal_transition_is_consistent(self):
        orch, _ = _orchestrator()
        self._analyze(orch, _exchange('{"id": 1001, "v": 1}', state_version="placed@1", captured_at=100.0))
        response = self._analyze(orch, _exchange(_SHIPPED, captured_at=200.0))
        self.assertEqual(_cited(response), set())

    def test_unknown_capture_time_is_qualified(self):
        orch, model = _orchestrator()
        self._analyze(orch, _exchange(_SHIPPED, state_version="shipped@3"))
        response = self._analyze(orch, _exchange(_PLACED))
        self.assertEqual(response.observation_context["order_basis"], "ingest")
        self.assertIn("capture time unknown (ingest order only)", model.prompts[-1])

    def test_fault_arrival_order_replacing_capture_time_is_detected(self):
        original = store._supplied_capture_fields
        without_time = lambda e: {k: v for k, v in original(e).items() if k != "captured_at"}
        with patch.object(store, "_supplied_capture_fields", without_time):
            response, _ = self._late_arrival(_PLACED)
        self.assertEqual(_cited(response), set(), "arrival order makes the late 'placed' look latest")


class CollisionIsolationTests(_CallerBase):
    """C04: equal paths in different tenants or piles never join."""

    def _two_identities(self, *, a_tenant=None, b_tenant=None, a_pile="", b_pile="", b_token=_TOKEN_Y):
        orch, model = _orchestrator()
        a = self._analyze(orch, _exchange(_SHIPPED, state_version="shipped@3"), engagement_id=a_pile,
                          attribution={"tenant": a_tenant} if a_tenant else None)
        b = self._analyze(orch, _exchange(_PLACED, token=b_token), engagement_id=b_pile,
                          attribution={"tenant": b_tenant} if b_tenant else None)
        return a, b, model

    def test_different_tenants_do_not_join(self):
        a, b, model = self._two_identities(a_tenant="tenant-one", b_tenant="tenant-two")
        a_id = a.observation_context["write"]["observation_id"]
        self.assertEqual(_cited(b), set())
        self.assertEqual(b.observation_context["excluded_counts"], {"tenant-mismatch": 1})
        self.assertNotIn(a_id, json.dumps(b.model_dump()))
        self.assertNotIn(a_id, model.prompts[-1])

    def test_different_piles_do_not_join(self):
        _, b, _ = self._two_identities(a_pile="review-1", b_pile="review-2", b_token=_TOKEN_X)
        self.assertEqual(_cited(b), set())
        self.assertEqual(b.observation_context["selected"], [])

    def test_unattributed_identities_do_not_join(self):
        _, b, _ = self._two_identities()
        self.assertEqual(_cited(b), set())
        self.assertEqual(b.observation_context["excluded_counts"], {"unattributed-context": 1})

    def test_within_tenant_explicit_relation_is_retrieved(self):
        a, b, _ = self._two_identities(a_tenant="tenant-one", b_tenant="tenant-one")
        self.assertEqual(_cited(b), {a.observation_context["write"]["observation_id"]})
        self.assertEqual([s["reason"] for s in b.observation_context["selected"]], ["declared-same-tenant"])

    def test_fault_without_tenant_predicate_is_detected(self):
        with patch.object(store, "_attribution_join", lambda *a: (True, "fault")):
            _, b, _ = self._two_identities(a_tenant="tenant-one", b_tenant="tenant-two")
        self.assertNotEqual(_cited(b), set())


class _ApiBase(_CallerBase):
    def setUp(self):
        super().setUp()
        import importlib
        import harness.server as server_module
        importlib.reload(server_module)
        self.server = server_module
        self._orig_orchestrator = server_module.orchestrator
        self.token = server_module._mutation_token()
        from fastapi.testclient import TestClient
        self.client = TestClient(server_module.app, base_url="http://localhost")

    def tearDown(self):
        self.server.orchestrator = self._orig_orchestrator
        super().tearDown()

    def _use(self, orch) -> None:
        self.server.orchestrator = orch

    def _post_analyze(self, exchange: HttpExchange, *, engagement_id: str = "", attribution=None,
                      force: bool = True) -> dict:
        body = {"exchange": exchange.model_dump(), "engagement_id": engagement_id,
                "force_agents": ["business_logic"] if force else []}
        if attribution:
            body["observation_attribution"] = attribution
        resp = self.client.post("/analyze", json=body, headers={"Authorization": f"Bearer {self.token}"})
        self.assertEqual(resp.status_code, 200, resp.text)
        return resp.json()


_CHILD = r"""
import asyncio, sys
from pathlib import Path
from harness import cache, store
from harness import test_observation_memory_caller as t
store._DB_PATH = Path(sys.argv[1])
cache.init_cache(db_path=sys.argv[2])
if sys.argv[3] == "skip-write":
    store.record_observation = lambda *a, **k: {"status": "stored", "observation_id": "", "exchange_id": ""}
orch, _ = t._orchestrator()
response = asyncio.run(orch.analyze(t._exchange(t._SHIPPED, state_version="shipped@3"),
                                    force_agents=["business_logic"]))
print(response.observation_context["write"]["status"])
"""


class RestartResumeTests(_ApiBase):
    """C08: A persisted by a process that then exits; B arrives through the API."""

    def _a_in_child(self, mode: str = "normal") -> str:
        root = _HARNESS.parent
        env = dict(os.environ)
        env["PYTHONPATH"] = os.pathsep.join(p for p in (str(root), env.get("PYTHONPATH", "")) if p)
        done = subprocess.run([sys.executable, "-c", _CHILD, str(store._DB_PATH),
                               os.path.join(self._tmp, "child-cache.db"), mode],
                              cwd=root, env=env, capture_output=True, text=True, timeout=300)
        self.assertEqual(done.returncode, 0, done.stderr[-2000:])
        return done.stdout.strip().splitlines()[-1]

    def test_observation_survives_process_exit(self):
        self.assertEqual(self._a_in_child(), "stored")
        orch, _ = _orchestrator()
        self._use(orch)
        b = self._post_analyze(_exchange(_PLACED))
        self.assertEqual(len(_cited(b)), 1)
        self.assertEqual(len(b["observation_context"]["selected"]), 1)

    def test_other_pile_cannot_see_it(self):
        self._a_in_child()
        orch, _ = _orchestrator()
        self._use(orch)
        b = self._post_analyze(_exchange(_PLACED), engagement_id="review-2")
        self.assertEqual(_cited(b), set())

    def test_fault_skipped_durable_write_is_detected(self):
        self._a_in_child("skip-write")
        orch, _ = _orchestrator()
        self._use(orch)
        b = self._post_analyze(_exchange(_PLACED))
        self.assertEqual(_cited(b), set(), "memory must not be synthesized after a lost write")
        self.assertEqual(b["observation_context"]["selected"], [])


class CorrectionDeletionTests(_ApiBase):
    """C09: correction and deletion through the API invalidate retrieval and advice."""

    def _a_then_b(self, orch):
        self._use(orch)
        a = self._post_analyze(_exchange(_SHIPPED, state_version="shipped@3"),
                               attribution={"tenant": "tenant-one"}, force=False)
        b = self._post_analyze(_exchange(_PLACED, token=_TOKEN_Y),
                               attribution={"tenant": "tenant-one"}, force=False)
        return a["observation_context"]["write"]["observation_id"], b

    def _correct(self, observation_id: str, tenant: str, expected_revision: int = 1):
        return self.client.post(f"/observations/{observation_id}/attribution",
                                json={"tenant": tenant, "expected_revision": expected_revision,
                                      "reason": "mislabelled"},
                                headers={"Authorization": f"Bearer {self.token}"})

    def test_correction_invalidates_the_cached_comparison(self):
        orch, model = _orchestrator(hypothesis_cache=True)
        a_id, first = self._a_then_b(orch)
        self.assertEqual(_cited(first), {a_id})
        calls = len(model.prompts)
        unchanged = self._post_analyze(_exchange(_PLACED, token=_TOKEN_Y),
                                       attribution={"tenant": "tenant-one"}, force=False)
        self.assertEqual(len(model.prompts), calls, "control: an unchanged repeat is served from cache")
        self.assertEqual(_cited(unchanged), {a_id})
        self.assertEqual(self._correct(a_id, "tenant-two").status_code, 200)
        calls = len(model.prompts)
        again = self._post_analyze(_exchange(_PLACED, token=_TOKEN_Y),
                                   attribution={"tenant": "tenant-one"}, force=False)
        self.assertEqual(_cited(again), set(), "a corrected tenant no longer joins")
        self.assertGreater(len(model.prompts), calls, "the stale cached comparison was not reused")
        self.assertNotEqual(again["observation_context"]["digest"], first["observation_context"]["digest"])
        self.assertEqual(self._correct(a_id, "tenant-three").status_code, 409, "stale revision")

    def test_fault_reusing_a_stale_retrieval_is_detected(self):
        orch, _ = _orchestrator(hypothesis_cache=True)
        a_id, _ = self._a_then_b(orch)
        b = _exchange(_PLACED, token=_TOKEN_Y)
        stale = store.select_observations(   # what B's first analysis was given
            _URL, captured_principal=store.captured_principal_id(b), attribution={"tenant": "tenant-one"},
            exclude_exchange_id=store.exchange_identity(b)[0])
        self.assertEqual([o["observation_id"] for o in stale["selected"]], [a_id])
        self._correct(a_id, "tenant-two")
        with patch.object(store, "select_observations", return_value=stale):
            again = self._post_analyze(_exchange(_PLACED, token=_TOKEN_Y),
                                       attribution={"tenant": "tenant-one"}, force=False)
        self.assertEqual(_cited(again), {a_id}, "the stale selection replays the old citation")

    def test_deletion_makes_the_citation_unavailable_and_keeps_unrelated_evidence(self):
        orch, _ = _orchestrator()
        a_id, first = self._a_then_b(orch)
        self.assertEqual(_cited(first), {a_id})
        unrelated = self._post_analyze(_exchange(_SHIPPED, url=_OTHER_URL),
                                       attribution={"tenant": "tenant-one"}, force=False)
        unrelated_id = unrelated["observation_context"]["write"]["observation_id"]
        auth = {"Authorization": f"Bearer {self.token}"}
        deleted = self.client.delete(f"/observations/{a_id}", headers=auth)
        self.assertEqual(deleted.status_code, 200, deleted.text)
        self.assertTrue(deleted.json()["evidence_deleted"])
        again = self._post_analyze(_exchange(_PLACED, token=_TOKEN_Y),
                                   attribution={"tenant": "tenant-one"}, force=False)
        self.assertEqual(_cited(again), set())
        self.assertEqual(again["observation_context"]["unavailable"],
                         [{"observation_id": a_id, "reason": "deleted"}])
        self.assertEqual(self.client.get(f"/observations/{a_id}", headers=auth).json()["status"], "deleted")
        kept = self.client.get(f"/observations/{unrelated_id}", headers=auth).json()
        self.assertEqual((kept["status"], kept["evidence_status"]), ("active", "resolved"))
        self.assertEqual(self._correct(a_id, "tenant-two").status_code, 410)

    def test_credential_shaped_attribution_is_refused_before_analysis(self):
        self._use(_orchestrator()[0])
        resp = self.client.post("/analyze", json={
            "exchange": _exchange(_SHIPPED).model_dump(),
            "observation_attribution": {"tenant": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln"}},
            headers={"Authorization": f"Bearer {self.token}"})
        self.assertEqual(resp.status_code, 400)
        conn = store._connect()
        try:
            self.assertEqual(conn.execute("SELECT count(*) FROM exchange_observations").fetchone()[0], 0)
        finally:
            conn.close()


if __name__ == "__main__":
    unittest.main()
