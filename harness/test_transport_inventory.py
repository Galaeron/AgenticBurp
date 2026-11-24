"""T08 verification: the transport inventory is complete, current, and enforced.

Two guards. The module registry (`TRANSPORT_SITES`) keeps every production module that
opens an outbound channel named and owned. ARC-7 adds a FUNCTION-level guard: an AST walk
finds every raw httpx client construction by (module, qualified function) and the paired
tests require it to equal `RAW_CLIENT_ALLOWLIST` exactly, so a new raw client -- in any
function, aliased or not, or a second one inside an allowed function -- fails here until
it is routed through `run_context` or listed with a reason. The controls below inject
such a client into a copy of real source and assert the guard fails.
"""
import os
import re
import unittest
from unittest.mock import patch

import harness.transport_inventory as ti

# A target send: the run executor, or the standalone transport_for path.
_SENDS = re.compile(r"executor\(\)\.execute\(|\btransport_for\(")


class InventoryEnforcementTests(unittest.TestCase):
    def test_scan_matches_registry(self):
        scanned = ti.scan_http_client_modules()
        registered = ti.http_modules_in_registry()
        uninventoried = scanned - registered
        stale = registered - scanned
        self.assertFalse(
            uninventoried,
            "A production module constructs an httpx client but is NOT in the "
            "transport inventory. Route it through the run-scoped executor, or add "
            f"a TransportSite for it (with an owner) in transport_inventory.py: {sorted(uninventoried)}")
        self.assertFalse(
            stale,
            "transport_inventory lists an httpx module that no longer constructs a "
            f"client -- update the registry: {sorted(stale)}")

    def test_every_registry_module_exists(self):
        root = ti.harness_dir()
        for site in ti.TRANSPORT_SITES:
            self.assertTrue(os.path.isfile(os.path.join(root, site.module)),
                            f"inventory references a missing module: {site.module}")

    def test_cors_validator_no_longer_constructs_its_own_client(self):
        """W-1: the CORS validator's raw httpx fallback was removed; it now
        sends only through the gate/executor. Recorded in the inventory as an
        executor-routed HTTP site that does not construct its own client, and
        the source must contain no httpx.AsyncClient(...) construction."""
        by_mod = {s.module: s for s in ti.TRANSPORT_SITES}
        cors = by_mod["validators/cors_validator.py"]
        self.assertFalse(cors.constructs_client)
        self.assertEqual(cors.routing, ti.ROUTING_EXECUTOR)
        self.assertNotIn("validators/cors_validator.py", ti.scan_http_client_modules())

    def test_http_sites_actually_use_httpx(self):
        """An HTTP site must actually do HTTP -- catch a module mis-classified as
        HTTP. A site that constructs its OWN client references httpx directly. A
        fully-routed site (constructs_client=False, e.g. cors_validator after W-1 or
        orchestrator_chain/iterative_agent after W-16) delegates client construction
        to the run-scoped transport, so it must instead reference that transport."""
        root = ti.harness_dir()
        routed_markers = ("run_context", "transport_for", "target_transport",
                          "TargetTransport", "GatedAsyncClient")
        for site in ti.TRANSPORT_SITES:
            if site.channel != ti.CHANNEL_HTTP:
                continue
            with open(os.path.join(root, site.module), encoding="utf-8") as f:
                text = f.read()
            if site.constructs_client:
                self.assertIn("httpx", text,
                              f"{site.module} constructs its own client but never imports httpx")
            else:
                self.assertTrue(
                    "httpx" in text or any(m in text for m in routed_markers),
                    f"{site.module} is a routed HTTP site but references neither httpx "
                    f"nor the run-scoped transport")


class RawClientGuardTests(unittest.TestCase):
    """ARC-7: the function-level guard and its negative controls."""

    def _assert_no_drift(self, counts=None):
        unlisted, stale, miscounted = ti.raw_client_drift(counts)
        self.assertFalse(
            unlisted,
            "A production function constructs a raw httpx client but is NOT on "
            "transport_inventory.RAW_CLIENT_ALLOWLIST. Send through run_context "
            "(standalone_context / transport_for), or list it with a reason: "
            f"{unlisted}")
        self.assertFalse(stale, f"the allowlist names a raw client that is gone: {stale}")
        self.assertFalse(miscounted,
                         f"a function holds a different number of raw clients: {miscounted}")

    def _counts_with(self, module, transform):
        """The scan over the real tree with `module`'s source passed through
        `transform` first -- a temp copy, the file on disk is untouched."""
        real = ti._iter_production_py

        def patched(root):
            for rel, text in real(root):
                yield rel, (transform(text) if rel == module else text)

        with patch.object(ti, "_iter_production_py", patched):
            return ti.raw_client_site_counts()

    def test_every_raw_client_site_is_allowlisted_exactly(self):
        self._assert_no_drift()

    def test_allowlist_entries_name_a_real_module_a_category_and_a_reason(self):
        seen = set()
        for site in ti.RAW_CLIENT_ALLOWLIST:
            self.assertNotIn(site.key, seen, f"duplicate allowlist entry {site.key}")
            seen.add(site.key)
            self.assertIn(site.category, ti.RAW_CATEGORIES, site.key)
            self.assertGreater(len(site.reason), 20, f"{site.key} has no real reason")
            self.assertGreaterEqual(site.count, 1)
            self.assertTrue(os.path.isfile(os.path.join(ti.harness_dir(), site.module)),
                            f"allowlist references a missing module: {site.module}")

    def test_target_clients_are_only_the_listed_legacy_and_gate_sites(self):
        """Egress and llm sites talk to non-target services; infra is the transport
        itself. Everything else that can reach a target is named as gate or
        legacy_no_run, so the open ARC-7 list is exactly this set."""
        open_items = {s.module for s in ti.RAW_CLIENT_ALLOWLIST
                      if s.category in (ti.RAW_GATE, ti.RAW_LEGACY_NO_RUN)}
        self.assertIn("safety_gate.py", open_items)
        for module in open_items - {"safety_gate.py"}:
            self.assertTrue(module.startswith("validators/"), module)

    def test_converted_modules_hold_no_raw_client(self):
        scanned_modules = {m for m, _ in ti.scan_raw_client_sites()}
        for module in ti.ARC7_CONVERTED_MODULES:
            self.assertNotIn(module, scanned_modules, f"ARC-7 regressed in {module}")
            self.assertTrue(os.path.isfile(os.path.join(ti.harness_dir(), module)), module)

    def test_scan_sees_aliases_and_module_level_helpers(self):
        cases = {
            "alias": "import httpx as h\n\nasync def f():\n    async with h.AsyncClient() as c:\n        pass\n",
            "from-import": "from httpx import AsyncClient as C\n\ndef f():\n    return C(timeout=1)\n",
            "sync client": "import httpx\n\ndef f():\n    return httpx.Client()\n",
            "helper": "import httpx\n\ndef f(u):\n    return httpx.get(u)\n",
        }
        for name, text in cases.items():
            self.assertEqual([q for q, _ in ti.raw_client_sites_in_source(text)], ["f"], name)
        # not a client: other httpx names, and a same-named attribute of another object
        for text in ("import httpx\n\ndef f():\n    return httpx.Timeout(1)\n",
                     "import httpx\n\ndef f(x):\n    return x.AsyncClient()\n"):
            self.assertEqual(ti.raw_client_sites_in_source(text), [])

    # ---- negative controls: each injection must trip the guard ----
    def test_control_a_new_function_in_a_converted_module_fails_the_guard(self):
        injected = "\n\nasync def sneaky(url):\n    async with httpx.AsyncClient() as c:\n        return await c.get(url)\n"
        for module in ("missing_auth_probe.py", "crawler.py", "feature_workflow.py"):
            counts = self._counts_with(
                module, lambda t: "import httpx\n" + t + injected)
            self.assertIn((module, "sneaky"), counts)
            with self.assertRaises(AssertionError):
                self._assert_no_drift(counts)

    def test_control_an_aliased_client_in_a_converted_module_fails_the_guard(self):
        injected = "\n\ndef sneaky():\n    import httpx as h\n    return h.AsyncClient()\n"
        counts = self._counts_with("role_crawl.py", lambda t: t + injected)
        self.assertIn(("role_crawl.py", "sneaky"), counts)
        with self.assertRaises(AssertionError):
            self._assert_no_drift(counts)

    def test_control_a_second_client_in_an_allowed_function_fails_the_guard(self):
        """The site key alone would miss this -- the count catches it."""
        line = "        self._client = httpx.AsyncClient(**httpx_kwargs)\n"

        def twice(text):
            assert line in text
            return text.replace(line, line + line, 1)

        counts = self._counts_with("safety_gate.py", twice)
        self.assertEqual(counts[("safety_gate.py", "GatedAsyncClient.__init__")], 2)
        with self.assertRaises(AssertionError):
            self._assert_no_drift(counts)

    def test_control_a_new_target_module_with_a_client_fails_the_guard(self):
        real = ti._iter_production_py

        def patched(root):
            yield from real(root)
            yield "brand_new_probe.py", ("import httpx\n\nasync def go(u):\n"
                                         "    async with httpx.AsyncClient() as c:\n"
                                         "        return await c.get(u)\n")

        with patch.object(ti, "_iter_production_py", patched):
            counts = ti.raw_client_site_counts()
        with self.assertRaises(AssertionError):
            self._assert_no_drift(counts)

    def test_control_removing_an_allowlisted_client_is_reported_stale(self):
        counts = self._counts_with(
            "kev_check.py", lambda t: t.replace("httpx.AsyncClient(", "make_client("))
        self.assertNotIn(("kev_check.py", "KevClient._ensure_loaded"), counts)
        with self.assertRaises(AssertionError):
            self._assert_no_drift(counts)

    def test_control_clean_source_passes_the_same_check(self):
        """The injection harness itself is sound: a no-op transform leaves no drift."""
        self._assert_no_drift(self._counts_with("missing_auth_probe.py", lambda t: t))


class RoutingAuditTests(unittest.TestCase):
    def test_every_target_direct_gap_has_owner_and_reason(self):
        # The audit requires each un-migrated target send to be NAMED and OWNED.
        for site in ti.routing_gaps():
            self.assertTrue(site.owner, f"routing gap {site.module} has no owner")
            self.assertTrue(site.gap or site.note,
                            f"routing gap {site.module} documents no specific gap/reason")

    def test_executor_and_gate_are_the_routed_adapters(self):
        by_mod = {s.module: s for s in ti.TRANSPORT_SITES}
        for mod in ("run_context.py", "safety_gate.py"):
            self.assertEqual(by_mod[mod].scope, ti.SCOPE_INFRA)
            self.assertEqual(by_mod[mod].routing, ti.ROUTING_ADAPTER)

    def test_container_browser_socket_channels_inventoried(self):
        by_mod = {s.module: s for s in ti.TRANSPORT_SITES}
        self.assertEqual(by_mod["tool_runner.py"].channel, ti.CHANNEL_CONTAINER)
        self.assertEqual(by_mod["browser_driver.py"].channel, ti.CHANNEL_BROWSER)
        self.assertEqual(by_mod["validators/websocket_validator.py"].channel, ti.CHANNEL_SOCKET)
        self.assertEqual(by_mod["validators/websocket_validator.py"].routing,
                         ti.ROUTING_CAPABILITY_ADAPTER)

    def test_egress_and_llm_are_not_target_scoped(self):
        # public advisory/registry APIs and the model plane must NOT be counted as
        # target-executor routing gaps.
        by_mod = {s.module: s for s in ti.TRANSPORT_SITES}
        for mod in ("github_advisories.py", "kev_check.py", "package_registry_checks.py"):
            self.assertEqual(by_mod[mod].scope, ti.SCOPE_EGRESS)
        self.assertEqual(by_mod["ollama_client.py"].scope, ti.SCOPE_LLM)

    def test_migrated_identity_and_discovery_paths_are_executor_routed(self):
        site = {s.module: s for s in ti.TRANSPORT_SITES}["validators/cross_identity_validator.py"]
        self.assertFalse(site.is_routing_gap)
        self.assertEqual(site.routing, ti.ROUTING_EXECUTOR)
        by_mod = {s.module: s for s in ti.TRANSPORT_SITES}
        for module in ("role_crawl.py", "crawler.py", "api_surface_discovery.py",
                       "api_surface_probe.py", "feature_workflow.py", "scope_discovery.py"):
            self.assertEqual(by_mod[module].routing, ti.ROUTING_EXECUTOR)
        self.assertEqual(by_mod["missing_auth_probe.py"].routing, ti.ROUTING_EXECUTOR)
        self.assertEqual(by_mod["validators/jwt_forge_validator.py"].routing,
                         ti.ROUTING_EXECUTOR)
        self.assertEqual(by_mod["validators/rate_limit_validator.py"].routing,
                         ti.ROUTING_EXECUTOR)
        self.assertEqual(by_mod["validators/toctou_validator.py"].routing,
                         ti.ROUTING_EXECUTOR)
        self.assertEqual(by_mod["validators/race_condition_validator.py"].routing,
                         ti.ROUTING_EXECUTOR)
        self.assertEqual(by_mod["validators/sqlmap.py"].routing, ti.ROUTING_EXECUTOR)
        self.assertEqual(by_mod["validators/cors_validator.py"].routing,
                         ti.ROUTING_EXECUTOR)
        self.assertEqual(by_mod["validators/csp_validator.py"].routing,
                         ti.ROUTING_EXECUTOR)
        self.assertEqual(by_mod["validators/oauth_validator.py"].routing,
                         ti.ROUTING_EXECUTOR)
        self.assertEqual(by_mod["validators/header_injection_validator.py"].routing,
                         ti.ROUTING_EXECUTOR)
        self.assertEqual(by_mod["validators/http_request_smuggling_validator.py"].routing,
                         ti.ROUTING_EXECUTOR)
        self.assertEqual(by_mod["validators/recon_validator.py"].routing,
                         ti.ROUTING_EXECUTOR)
        self.assertEqual(by_mod["validators/subdomain_takeover_validator.py"].routing,
                         ti.ROUTING_EXECUTOR)
        self.assertEqual(by_mod["validators/web_cache_poisoning_validator.py"].routing,
                         ti.ROUTING_EXECUTOR)

    @staticmethod
    def _api_surface_senders(texts):
        """The api_surface_* modules whose source sends through the executor or transport_for."""
        return sorted(name for name, text in texts.items()
                      if _SENDS.search(text))

    def test_arc9_api_surface_sends_are_registered_where_they_live(self):
        """ARC-9 split api_surface_discovery.py into siblings. The registry must name the
        file that holds the sends (api_surface_probe.py), as an executor-routed site
        without its own client, not only the facade that keeps SurfaceDiscovery."""
        root = ti.harness_dir()
        texts = {}
        for name in os.listdir(root):
            if name.startswith("api_surface") and name.endswith(".py"):
                with open(os.path.join(root, name), encoding="utf-8") as f:
                    texts[name] = f.read()
        senders = self._api_surface_senders(texts)
        self.assertEqual(senders, ["api_surface_probe.py"])
        by_mod = {s.module: s for s in ti.TRANSPORT_SITES}
        for name in senders:
            self.assertIn(name, by_mod, f"{name} sends to the target but is not in TRANSPORT_SITES")
            self.assertEqual(by_mod[name].routing, ti.ROUTING_EXECUTOR)
            self.assertFalse(by_mod[name].constructs_client)

    def test_control_a_send_moved_into_another_api_surface_sibling_is_seen(self):
        """Negative control: the sender scan reports a sibling the registry does not name."""
        texts = {"api_surface_probe.py": "await self.run_context.executor().execute(req)",
                 "api_surface_walk.py": "tt, owned = transport_for(None, allowed_hosts=[])",
                 "api_surface_discovery.py": "class SurfaceDiscovery: run_context = None"}
        senders = self._api_surface_senders(texts)
        self.assertEqual(senders, ["api_surface_probe.py", "api_surface_walk.py"])
        registered = {s.module for s in ti.TRANSPORT_SITES}
        self.assertEqual([n for n in senders if n not in registered], ["api_surface_walk.py"])

    def test_summary_is_consistent(self):
        s = ti.summary()
        self.assertEqual(s["total_sites"], len(ti.TRANSPORT_SITES))
        self.assertEqual(s["routing_gaps"], len(ti.routing_gaps()))
        self.assertGreater(s["by_scope"].get(ti.SCOPE_TARGET, 0), 0)

    def test_w16_no_target_routing_gaps_remain(self):
        """W-16 full closure: every target-directed send is on the single
        TargetTransport, so the inventory has ZERO routing gaps. The last two
        migrated modules are executor-routed and construct no client of their own."""
        self.assertEqual(list(ti.routing_gaps()), [],
                         f"unexpected routing gaps: {[s.module for s in ti.routing_gaps()]}")
        by_mod = {s.module: s for s in ti.TRANSPORT_SITES}
        for mod in ("orchestrator_chain.py", "iterative_agent.py"):
            self.assertEqual(by_mod[mod].routing, ti.ROUTING_EXECUTOR)
            self.assertFalse(by_mod[mod].constructs_client)
            self.assertFalse(by_mod[mod].is_routing_gap)
            self.assertNotIn(mod, ti.scan_http_client_modules())  # no direct httpx client


if __name__ == "__main__":
    unittest.main()
