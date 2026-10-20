"""Code review 02, batch RV-I (I06/I07): recon follows links the captured response already showed (R21).

Drives the production caller the way the reviewer's boundary_checks.py did, with
the reviewer's control as the negative control. Nothing leaves the machine:
requests are answered by a patched ``httpx.AsyncClient``.
"""
import asyncio
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import httpx

from harness import cache, safety_gate, store
from harness.models import AgentReport, Finding
from harness.orchestrator import Orchestrator
from harness.test_default_history_caller import _config, _exchange, _RecordingModel
from harness.validators.recon_validator import ReconValidator


class _StateBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="rvi_")
        self._saved = (store._DB_PATH, cache._cache)
        store._DB_PATH = Path(self._tmp) / "state.db"
        cache.init_cache(db_path=os.path.join(self._tmp, "cache.db"))
        safety_gate.reset_default_gate()

    def tearDown(self):
        store._DB_PATH, cache._cache = self._saved
        safety_gate.reset_default_gate()
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)


def _recon_validator():
    return ReconValidator(allowed_hosts=["shop.invalid"], max_depth=1)


class ReconCapturedLinkTests(_StateBase):
    """R21: links seen in the captured response must still be fetched."""

    def _crawl(self, captured_page, live_page, extra_pages=None):
        """Validate a recon finding; return the URLs the live crawl requested."""
        orch = Orchestrator(self._cfg())
        model = _RecordingModel()
        orch.ollama = model
        for agent in orch.agent_manager.agents.values():
            agent.ollama = model
        orch.validator_registry.active_enabled = True
        orch.validator_registry.validators = {"recon": _recon_validator()}
        ex = _exchange("http://shop.invalid/")
        ex.response_body = captured_page
        ex.response_headers = {"Content-Type": "text/html"}
        finding = Finding(vulnerability_class="recon", confidence=0.5, summary="candidate",
                          evidence="fixture", suggested_test="map", basis="derived")
        sent = []
        pages = dict(extra_pages or {})
        pages[ex.url] = live_page

        async def fake_request(client, method, url, **kwargs):
            sent.append(str(url))
            body = pages.get(str(url))
            return httpx.Response(200 if body is not None else 404, text=body or "",
                                  headers={"Content-Type": "text/html"},
                                  request=httpx.Request(method, url))

        with patch.object(httpx.AsyncClient, "request", fake_request):
            asyncio.run(orch._validate_findings(
                ex, [AgentReport(agent="recon", model="fake", findings=[finding])]))
        return sent

    @staticmethod
    def _cfg():
        cfg = _config()
        cfg["server"]["allowed_hosts"] = ["shop.invalid"]
        return cfg

    def test_recon_follows_link_already_seen_in_captured_response(self):
        page = '<html><a href="/distinct-child">child</a></html>'
        sent = self._crawl(captured_page=page, live_page=page)
        self.assertIn("http://shop.invalid/", sent)
        self.assertIn("http://shop.invalid/distinct-child", sent)

    def test_recon_new_link_control(self):
        # Nothing in the captured response: a link only the live page carries.
        sent = self._crawl(captured_page="<html></html>",
                           live_page='<html><a href="/distinct-child">child</a></html>')
        self.assertIn("http://shop.invalid/distinct-child", sent)

    def test_captured_link_is_still_scope_checked(self):
        page = ('<html><a href="/distinct-child">child</a>'
                '<a href="//evil.invalid/steal">off scope</a></html>')
        sent = self._crawl(captured_page=page, live_page=page)
        self.assertIn("http://shop.invalid/distinct-child", sent)
        self.assertFalse([u for u in sent if "evil.invalid" in u], sent)

    def test_captured_link_is_still_destructive_navigation_filtered(self):
        page = ('<html><a href="/distinct-child">child</a>'
                '<a href="/account/logout">logout</a>'
                '<a href="/orders/42/delete">delete</a></html>')
        sent = self._crawl(captured_page=page, live_page=page)
        self.assertIn("http://shop.invalid/distinct-child", sent)
        self.assertFalse([u for u in sent if "logout" in u or "/delete" in u], sent)

    def test_live_only_link_is_also_destructive_navigation_filtered(self):
        sent = self._crawl(captured_page="<html></html>",
                           live_page='<html><a href="/account/logout">logout</a></html>')
        self.assertFalse([u for u in sent if "logout" in u], sent)

    def test_standalone_crawl_without_a_run_is_scope_and_navigation_checked(self):
        # No RunContext executor on this path, so nothing but the validator's own
        # gates stands between a captured link and the network.
        page = ('<html><a href="/distinct-child">child</a>'
                '<a href="//evil.invalid/steal">off scope</a>'
                '<a href="/account/logout">logout</a></html>')
        ex = _exchange("http://shop.invalid/")
        ex.response_body = page
        ex.response_headers = {"Content-Type": "text/html"}
        finding = Finding(vulnerability_class="recon", confidence=0.5, summary="candidate",
                          evidence="fixture", suggested_test="map", basis="derived")
        sent = []

        async def fake_request(client, method, url, **kwargs):
            sent.append(str(url))
            return httpx.Response(200 if str(url) == ex.url else 404,
                                  text=page if str(url) == ex.url else "",
                                  headers={"Content-Type": "text/html"},
                                  request=httpx.Request(method, url))

        async def go():
            async with _recon_validator() as validator:
                return await validator.validate(finding, ex)

        with patch.object(httpx.AsyncClient, "request", fake_request):
            asyncio.run(go())
        self.assertIn("http://shop.invalid/distinct-child", sent)
        self.assertFalse([u for u in sent if "evil.invalid" in u or "logout" in u], sent)

    def test_each_link_is_fetched_once(self):
        page = '<html><a href="/distinct-child">a</a><a href="/distinct-child">b</a></html>'
        sent = self._crawl(captured_page=page, live_page=page)
        self.assertEqual(sent.count("http://shop.invalid/distinct-child"), 1, sent)


if __name__ == "__main__":
    unittest.main()
