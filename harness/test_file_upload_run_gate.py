"""file_upload sends through the run it is bound to.

The leg used to read the process-default (or ambient) gate for its mutating
pre-check and send through a client keyed on that gate, so a run whose own gate
refused mutating replay could be overridden by a default gate that allowed it,
and a bound run's budget and change log never saw the sends. Bound to a run
(`run_context`), the run's gate decides and every send goes through its
executor; unbound, the leg keeps its default-gate path unchanged.

Each test fakes the transport below httpx (the run executor and the private
client both end in httpx.AsyncClient.request), so the gate and the run decide.
"""
import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx

from harness import cache, store
from harness.models import Finding, HttpExchange
from harness.run_context import RunContext
from harness.safety_gate import SafetyGate, SafetyGateConfig, gate_scope
from harness.validators import file_upload_validator
from harness.validators.file_upload_validator import FileUploadValidator

_HOST = "shop.invalid"
_URL = f"http://{_HOST}/profile/avatar"


def _finding() -> Finding:
    return Finding(vulnerability_class="file_upload", confidence=0.5, summary="candidate",
                   evidence="fixture", suggested_test="verify", basis="derived",
                   finding_id="fu-run-gate-1")


def _exchange() -> HttpExchange:
    return HttpExchange(url=_URL, method="POST", request_headers={},
                        request_body="avatar=me.png", response_status=200,
                        response_headers={"Content-Type": "text/html"},
                        response_body="<p>ok</p>")


def _gate(*, mutating: bool) -> SafetyGate:
    return SafetyGate(SafetyGateConfig(active_enabled=True, allow_mutating_replay=mutating,
                                       allowed_hosts=frozenset({_HOST})))


def _target(sent):
    """Accepts any upload with a 200 (no stored URL), 404s everything else."""
    async def request(client, method, url, **kwargs):
        u = str(url)
        sent.append((method, u))
        req = httpx.Request(method, u)
        if method == "POST":
            return httpx.Response(200, text=json.dumps({"ok": True}),
                                  headers={"content-type": "application/json"}, request=req)
        return httpx.Response(404, text="not found", request=req)
    return request


def _run(*, mutating: bool, max_requests: int = 50) -> RunContext:
    return RunContext.create(allowed_hosts=[_HOST], max_requests=max_requests,
                             gate_config={"active_enabled": True,
                                          "allow_mutating_replay": mutating})


# unittest.TestCase is named explicitly so the static orphan-test guard collects these.
class FileUploadRunGateTests(unittest.TestCase):

    def _validate(self, validator, *, ambient_gate, enter_run=None):
        """Validate in a fresh task context: only `ambient_gate` is ambient (the
        'default' gate), plus the run itself when `enter_run` is given."""
        sent = []

        async def go():
            if enter_run is not None:
                async with enter_run:
                    with gate_scope(ambient_gate):
                        return await validator.validate(_finding(), _exchange())
            with gate_scope(ambient_gate):
                return await validator.validate(_finding(), _exchange())

        with patch.object(httpx.AsyncClient, "request", _target(sent)):
            result = asyncio.run(go())
        return result, sent

    def test_run_gate_denying_mutating_replay_wins_over_an_allowing_default_gate(self):
        run = _run(mutating=False)
        try:
            v = FileUploadValidator(allowed_hosts=[_HOST], timeout=1.0, run_context=run)
            result, sent = self._validate(v, ambient_gate=_gate(mutating=True))
        finally:
            asyncio.run(run.aclose())
        self.assertEqual(result.status, "skipped", result.summary)
        self.assertIn("not authorized", result.summary)
        self.assertEqual(sent, [], "a run that refuses mutating replay sent nothing")
        self.assertEqual(run.budget.used, 0)
        self.assertEqual(run.change_log.entries(), [])

    def test_entered_run_denying_is_not_overridden_by_a_gate_pushed_inside_it(self):
        # Before: the pushed gate passed the pre-check and the source-form GET went
        # out through the run before the run refused the upload itself.
        run = _run(mutating=False)
        v = FileUploadValidator(allowed_hosts=[_HOST], timeout=1.0, run_context=run)
        result, sent = self._validate(v, ambient_gate=_gate(mutating=True), enter_run=run)
        self.assertEqual(result.status, "skipped", result.summary)
        self.assertEqual(sent, [])

    def test_bound_run_allowing_sends_through_its_executor_when_the_default_denies(self):
        run = _run(mutating=True)
        try:
            v = FileUploadValidator(allowed_hosts=[_HOST], timeout=1.0, run_context=run)
            result, sent = self._validate(v, ambient_gate=_gate(mutating=False))
        finally:
            asyncio.run(run.aclose())
        self.assertIn(("POST", _URL), sent, result.summary)
        self.assertNotEqual(result.status, "skipped", result.summary)
        # Every send spent the run's budget, and the upload is in its change log.
        self.assertEqual(run.budget.used, len(sent))
        posts = [e for e in run.change_log.entries() if e["method"] == "POST"]
        self.assertEqual([e["path"] for e in posts], ["/profile/avatar"])
        self.assertEqual(posts[0]["capability"], "file_upload")
        self.assertTrue(posts[0]["artifact_id"])

    def test_exhausted_run_budget_sends_nothing_and_is_not_a_negative(self):
        run = _run(mutating=True, max_requests=0)
        try:
            v = FileUploadValidator(allowed_hosts=[_HOST], timeout=1.0, run_context=run)
            result, sent = self._validate(v, ambient_gate=_gate(mutating=True))
        finally:
            asyncio.run(run.aclose())
        self.assertEqual(sent, [])
        self.assertEqual(result.status, "skipped", result.summary)
        self.assertIn("refused by the run", result.summary)
        self.assertIn("budget", result.summary)
        self.assertFalse(result.confirmed)


class FileUploadNoContextControlTests(unittest.TestCase):
    """Unbound, the leg keeps the default-gate path it always had."""

    def _validate(self, gate):
        sent, built = [], []
        real = file_upload_validator.GatedAsyncClient

        def spy(*args, **kwargs):
            built.append((args, kwargs))
            return real(*args, **kwargs)

        async def go():
            with gate_scope(gate):
                return await FileUploadValidator(allowed_hosts=[_HOST], timeout=1.0).validate(
                    _finding(), _exchange())

        with patch.object(httpx.AsyncClient, "request", _target(sent)), \
             patch.object(file_upload_validator, "GatedAsyncClient", spy):
            result = asyncio.run(go())
        return result, sent, built

    def test_default_gate_allowing_sends_through_the_default_gate_client(self):
        gate = _gate(mutating=True)
        result, sent, built = self._validate(gate)
        self.assertIn(("POST", _URL), sent, result.summary)
        self.assertEqual(len(built), 1)
        args, kwargs = built[0]
        self.assertIs(args[0], gate)
        self.assertEqual(args[1], "file_upload")
        self.assertEqual(kwargs, {"timeout": 1.0, "follow_redirects": True, "verify": False})

    def test_default_gate_denying_skips_with_the_old_reason(self):
        result, sent, built = self._validate(_gate(mutating=False))
        self.assertEqual(sent, [])
        self.assertEqual(built, [])
        self.assertEqual(result.status, "skipped")
        self.assertEqual(result.summary,
                         "mutating file upload not authorized (set validators.allow_mutating_replay)")


class FileUploadDriveBindingTests(unittest.TestCase):
    """The coverage drive builds its file_upload leg bound to the engagement's run."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        old = store._DB_PATH, cache._cache
        self.addCleanup(self._restore, old)
        store._DB_PATH = Path(self.temp.name) / "state.db"
        cache.init_cache(db_path=str(Path(self.temp.name) / "cache.db"))

    @staticmethod
    def _restore(old):
        store._DB_PATH, cache._cache = old

    def test_drive_dispatches_file_upload_bound_to_the_run(self):
        from harness import test_smoke_investigate as smoke
        from harness.coverage_tracker import _LEG_CONFIRMATIONS
        from harness.engagement import EngagementState
        from harness.orchestrator import Orchestrator
        from harness.orchestrator_chain_support import _ConfirmationCache
        from harness.role_crawl import RoleCrawlResult
        from harness.test_coverage_capabilities import _controlled_model
        from harness.validators.base import ValidationResult

        cfg = smoke._test_config()
        for name in _LEG_CONFIRMATIONS:
            cfg["validators"].setdefault(name, {})["enabled"] = name == "file_upload"
        seen = {}

        async def dispatch(self_, validator, finding, exchange, case_ref=None):
            seen[validator.name] = validator
            return ValidationResult(validator.name, "blocked", finding.vulnerability_class)

        def build(*args, **kwargs):
            state = EngagementState("localhost")
            state.ingest_role_crawl({"endpoints": [{
                "method": "POST", "path": "/upload", "reachable_roles": ["anonymous"],
                "by_role": {"anonymous": 200},
                "template": {"method": "POST", "query": "name=test", "body": "a=1",
                             "content_type": "application/x-www-form-urlencoded"},
            }]})
            for ep in state.endpoints.values():
                ep.reachable_roles = ["anonymous"]
            return state, RoleCrawlResult(base_url=smoke.BASE_URL)

        orch = Orchestrator(cfg)
        _controlled_model(orch)
        orch.engagement_coverage_drive = True
        orch.engagement_coverage_case_drive = True
        orch.run_active_probe = AsyncMock(
            return_value={"iterative_result": {"findings": []}, "integration": {}})
        run = RunContext.create(allowed_hosts=["localhost"], max_requests=50,
                                gate_config={"active_enabled": True})

        async def go():
            async with run:
                await orch.investigate_engagement(
                    smoke.BASE_URL, [smoke.ROLES[0]], max_nodes=0, step_budget=1,
                    max_chain_rounds=0, run_context=run)

        with patch("harness.engagement_builder.build_engagement", side_effect=build), \
             patch.object(_ConfirmationCache, "validate", dispatch):
            asyncio.run(go())
        self.assertIn("file_upload", seen, sorted(seen))
        self.assertIs(seen["file_upload"].run_context, run)


if __name__ == "__main__":
    unittest.main()
