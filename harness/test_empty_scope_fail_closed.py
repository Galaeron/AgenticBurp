"""a1's open items (d2): `transport_for` states its mode, and an empty scope sends nothing.

`transport_for(...)` used to default to `active_mode=False`, which on a standalone
context admits ANY host when the scope is empty. It is now keyword-required, and every
caller that originates a request says `active_mode=True`. Each caller-level test below
drives the real send function against a loopback server with an EMPTY scope and asserts
zero requests arrived. The control for each forces the old passive mode and shows the
request reaches the server, so the test is not vacuous.
"""
import asyncio
import ast
import os
import unittest
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import patch

from harness import global_throttle, run_context as rc_mod
# Import the two modules that bind `transport_for` at import time BEFORE any test patches
# it: a module first imported under a patch would keep the wrapper for good.
import harness.iterative_agent  # noqa: F401
import harness.orchestrator_chain  # noqa: F401
from harness.models import Finding, HttpExchange
from harness.run_context import transport_for
from harness.test_run_context import _Fixture


def _passive(real):
    """`transport_for` with the pre-fix default: whatever the caller said, passive."""
    def wrapper(*a, **kw):
        kw["active_mode"] = False
        return real(*a, **kw)
    return wrapper


def _force_passive():
    """Patch every name `transport_for` is reached by: the module attribute (callers that
    import it inside the function) and the two modules that bind it at import time."""
    stack = ExitStack()
    real = rc_mod.transport_for
    wrapped = _passive(real)
    stack.enter_context(patch.object(rc_mod, "transport_for", wrapped))
    stack.enter_context(patch("harness.orchestrator_chain.transport_for", wrapped))
    stack.enter_context(patch("harness.iterative_agent.transport_for", wrapped))
    return stack


class _Base(unittest.TestCase):
    def setUp(self):
        global_throttle.configure(0)
        self.fixture = _Fixture()
        self.addCleanup(self.fixture.close)

    @property
    def sent(self):
        return len(self.fixture.httpd.received)

    def _both(self, send):
        """Run `send(url)` twice: with the fix (zero sends) and, as the control, with the
        pre-fix passive default (it reaches the server)."""
        asyncio.run(send(self.fixture.base + "/probe"))
        self.assertEqual(self.fixture.httpd.received, [], "an empty scope must send nothing")
        with _force_passive():
            asyncio.run(send(self.fixture.base + "/probe"))
        self.assertGreaterEqual(self.sent, 1, "control: the passive default must reach the server")


class TransportForModeTests(_Base):
    def test_active_mode_is_required(self):
        with self.assertRaises(TypeError):
            transport_for(None, allowed_hosts=["127.0.0.1"])
        with self.assertRaises(TypeError):
            rc_mod.transport_for(None, allowed_hosts=["127.0.0.1"], config={})

    def test_empty_scope_admits_no_host_when_active(self):
        async def go(active):
            tt, owned = transport_for(None, allowed_hosts=[], active_mode=active)
            try:
                return await tt.send("GET", self.fixture.base + "/x", capability="t", max_redirects=0)
            finally:
                await owned.aclose()
        out = asyncio.run(go(True))
        self.assertEqual(out.outcome, "out_of_scope")
        self.assertEqual(self.sent, 0)
        # control: the passive mode the old default gave is what lets it through
        self.assertTrue(asyncio.run(go(False)).ok)
        self.assertEqual(self.sent, 1)

    def test_no_production_caller_leaves_active_mode_to_a_default(self):
        """Every transport_for call in production code names active_mode."""
        root = os.path.dirname(os.path.abspath(rc_mod.__file__))
        missing = []
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d != "__pycache__"]
            for fn in filenames:
                if not fn.endswith(".py") or fn.startswith("test_"):
                    continue
                path = os.path.join(dirpath, fn)
                tree = ast.parse(open(path, encoding="utf-8").read())
                for node in ast.walk(tree):
                    if isinstance(node, ast.Call):
                        f = node.func
                        name = f.id if isinstance(f, ast.Name) else getattr(f, "attr", "")
                        if name == "transport_for" and not any(
                                k.arg == "active_mode" for k in node.keywords):
                            missing.append(f"{fn}:{node.lineno}")
        self.assertEqual(missing, [])


class EmptyScopeCallerTests(_Base):
    def test_second_order_send_through_run(self):
        from harness import second_order

        async def send(url):
            return await second_order.send_through_run(
                None, "GET", url, allowed_hosts=[], config={}, capability="second_order")
        self._both(send)

    def test_credential_probe_in_the_chain(self):
        from harness.orchestrator_chain import ChainMixin
        me = SimpleNamespace(allowed_hosts=[], config={})

        async def send(url):
            return await ChainMixin._credential_grants_access(
                me, url, {"Authorization": "Bearer abc"})
        self._both(send)

    def test_iterative_agent_send(self):
        from harness.iterative_agent import IterativeAgent
        from harness.test_iterative_probe_run_context import _ScriptedOllama

        async def send(url):
            agent = IterativeAgent(_ScriptedOllama([]), "m", [])
            return await agent._execute("GET", url, {}, None)
        self._both(send)

    def test_role_crawl_probe_without_a_run(self):
        from harness import role_crawl

        async def send(url):
            return await role_crawl._probe("GET", url, {}, 5.0, allowed_hosts=[])
        self._both(send)

    def test_surface_discovery_probe_without_a_run(self):
        from harness.api_surface_discovery import SurfaceDiscovery

        async def send(url):
            d = SurfaceDiscovery(url.rsplit("/", 1)[0], allowed_hosts=[])
            return await d._probe("GET", "/probe")
        # SurfaceDiscovery's own scope check already refuses an empty scope, so the
        # pre-fix passive transport is not what is under test there: the check is.
        asyncio.run(send(self.fixture.base + "/probe"))
        self.assertEqual(self.sent, 0)
        with patch("harness.api_surface_discovery._host_in_scope", lambda url, hosts: True):
            asyncio.run(send(self.fixture.base + "/probe"))
        self.assertEqual(self.sent, 0, "the transport still refuses: two fences hold")
        with patch("harness.api_surface_discovery._host_in_scope", lambda url, hosts: True), \
                _force_passive():
            asyncio.run(send(self.fixture.base + "/probe"))
        self.assertGreaterEqual(self.sent, 1, "control: with both fences off it sends")

    def test_cross_identity_probe_without_a_run(self):
        from harness.validators.cross_identity_validator import CrossIdentityValidator

        async def send(url):
            probe = await CrossIdentityValidator(allowed_hosts=[])._probe(url, {})
            if self.sent == 0:
                self.assertEqual(probe.status, 0)      # reported "not reached"
            return probe
        self._both(send)

    def test_scope_discovery_without_a_run(self):
        from harness import scope_discovery

        async def send(url):
            base = url.rsplit("/", 1)[0]
            exchange = HttpExchange(url=base + "/seed", method="GET", request_headers={},
                                    request_body="", response_status=200, response_headers={},
                                    response_body="")
            finding = Finding(vulnerability_class="sqli", confidence=0.9, severity="critical",
                              summary="s", evidence="e", suggested_test="t", basis="derived",
                              confirmed=True)
            cfg = {"autonomous_discovery": {"enabled": True, "trigger_categories": ["sqli"],
                                            "candidate_paths": ["/probe"],
                                            "max_new_requests_per_trigger": 1}}
            return await scope_discovery.discover_from_scope_change(
                exchange, [finding], cfg, allowed_hosts=[])
        self._both(send)

    def test_crawler_without_a_scope_sends_nothing(self):
        """The crawler's own check already fails closed (the audit's crawler.py:105 is
        fixed on this base); this pins it at the caller with a real server."""
        from harness import crawler
        result = asyncio.run(crawler.crawl(self.fixture.base + "/", allowed_hosts=[]))
        self.assertEqual(self.sent, 0)
        self.assertTrue(any("no server.allowed_hosts" in e for e in result.errors))
        with patch.object(crawler, "_host_allowed", lambda url, hosts: True), _force_passive():
            asyncio.run(crawler.crawl(self.fixture.base + "/", allowed_hosts=[], max_pages=1))
        self.assertGreaterEqual(self.sent, 1, "control: both fences off, it sends")


class BurpSitemapIsReadOnlyTests(unittest.TestCase):
    """burp_sitemap._host_allowed keeps its passive empty-scope admission because the
    module only parses an operator-supplied export. Prove it sends nothing."""

    def test_the_module_has_no_sender(self):
        import harness.burp_sitemap as bs
        tree = ast.parse(open(bs.__file__, encoding="utf-8").read())
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        for sender in ("httpx", "requests", "aiohttp", "socket", "urllib3"):
            self.assertNotIn(sender, imported)
        self.assertNotIn("run_context", {n.module.rsplit(".", 1)[-1] for n in ast.walk(tree)
                                         if isinstance(n, ast.ImportFrom) and n.module})
        from harness import transport_inventory as ti
        self.assertEqual([k for k in ti.scan_raw_client_sites() if k[0] == "burp_sitemap.py"], [])

    def test_unset_scope_still_filters_nothing_and_a_scope_still_filters(self):
        import harness.burp_sitemap as bs
        self.assertTrue(bs._host_allowed("http://anything.test/", []))
        self.assertTrue(bs._host_allowed("http://anything.test/", None))
        self.assertFalse(bs._host_allowed("http://other.test/", ["anything.test"]))
        self.assertTrue(bs._host_allowed("http://anything.test/", ["anything.test"]))


if __name__ == "__main__":
    unittest.main()
