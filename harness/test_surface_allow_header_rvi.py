"""Code review 02, batch RV-I (I06/I07): surface discovery keeps the methods a route's Allow header lists (R13).

Drives the production caller the way the reviewer's boundary_checks.py did, with
the reviewer's control as the negative control. Nothing leaves the machine:
requests are answered by a patched ``httpx.AsyncClient``.
"""
import asyncio
import unittest
from unittest.mock import patch

import httpx

from harness.api_surface_discovery import SurfaceDiscovery
from harness.run_context import RunContext


class AllowHeaderCaseTests(unittest.TestCase):
    """R13: a valid ``Allow: GET, POST`` loses POST in surface discovery.

    Through a RunContext the executor hands back response headers as a plain
    dict keyed by LOWERCASE names, so the ``Allow`` lookup never matched, whatever
    the server's capitalisation. The direct-httpx path reads a case-insensitive
    ``httpx.Headers`` and was never affected: it is the control.
    """

    def _methods(self, allow_header_name, *, via_run_context=True):
        async def fake_request(client, method, url, **kwargs):
            status = 200 if str(url).endswith("/item") else 404
            headers = {allow_header_name: "GET, POST"} if method == "OPTIONS" else {}
            return httpx.Response(status, text="fixture", headers=headers,
                                  request=httpx.Request(method, url))

        async def discover(run):
            discovery = SurfaceDiscovery(
                "http://shop.invalid", allowed_hosts=["shop.invalid"], nouns=[],
                collections=[], prefixes=[], actions=[], sensitive_files=[],
                seed_paths=["/item"], use_ffuf=False, max_probes=50, run_context=run)
            return await discovery.discover()

        async def go():
            if not via_run_context:
                return await discover(None)
            async with RunContext.create(allowed_hosts=["shop.invalid"], max_requests=100) as run:
                return await discover(run)

        with patch.object(httpx.AsyncClient, "request", fake_request):
            result = asyncio.run(go())
        return next(r for r in result.routes if r.path == "/item").methods

    def test_scoped_surface_discovery_preserves_allow_methods(self):
        self.assertIn("POST", self._methods("Allow"))

    def test_every_capitalisation_survives_the_scoped_path(self):
        for name in ("allow", "ALLOW", "aLlOw"):
            with self.subTest(header=name):
                self.assertIn("POST", self._methods(name))

    def test_direct_path_control(self):
        for name in ("Allow", "allow"):
            with self.subTest(header=name):
                self.assertIn("POST", self._methods(name, via_run_context=False))

    def test_route_without_allow_header_keeps_its_probe_method(self):
        # Negative control: no Allow header at all must not invent methods.
        self.assertEqual(self._methods("X-Not-Allow"), ("GET",))


if __name__ == "__main__":
    unittest.main()
