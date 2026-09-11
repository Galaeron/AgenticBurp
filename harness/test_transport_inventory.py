"""T08 verification: the transport inventory is complete, current, and enforced.

The point of these tests is a MODULE-granular routing-regression guard: if a NEW
production module opens an httpx client without either routing it through the
run-scoped executor or recording it in `transport_inventory.TRANSPORT_SITES` with
an owner, `test_scan_matches_registry` fails. This narrows -- but does not close --
the "green tests, dead pipeline" transport risk: the guard is module-granular, so a
second direct site added inside an ALREADY-registered module, an aliased
constructor, or a non-httpx transport API is not caught. That limitation is made
explicit in `test_inventory_is_module_granular` (review R11).
"""
import os
import re
import unittest

import transport_inventory as ti


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

    def test_inventory_is_module_granular(self):
        """R11 limitation control: the guard is a MODULE inventory. Two httpx
        constructions in one file collapse to a single module entry, so a SECOND
        direct site added to an already-registered module would not change the
        scanned set. This test pins that honest limitation so the guard's claim is
        never overstated as site- or alias-level detection."""
        root = ti.harness_dir()
        # a module already in the registry that constructs an httpx client
        sample = next(iter(ti.scan_http_client_modules(root)))
        with open(os.path.join(root, sample), encoding="utf-8") as f:
            text = f.read()
        # the scanner keys on presence, not count -- N occurrences -> 1 module entry
        occurrences = len(re.findall(r"httpx\.(?:AsyncClient|Client)\(", text))
        self.assertGreaterEqual(occurrences, 1)
        self.assertIn(sample, ti.scan_http_client_modules(root))  # counted once regardless of N

    def test_http_sites_actually_use_httpx(self):
        root = ti.harness_dir()
        for site in ti.TRANSPORT_SITES:
            if site.channel != ti.CHANNEL_HTTP:
                continue
            with open(os.path.join(root, site.module), encoding="utf-8") as f:
                text = f.read()
            self.assertIn("httpx", text, f"{site.module} is listed as http but never imports httpx")


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
                       "feature_workflow.py", "scope_discovery.py"):
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

    def test_summary_is_consistent(self):
        s = ti.summary()
        self.assertEqual(s["total_sites"], len(ti.TRANSPORT_SITES))
        self.assertEqual(s["routing_gaps"], len(ti.routing_gaps()))
        self.assertGreater(s["by_scope"].get(ti.SCOPE_TARGET, 0), 0)


if __name__ == "__main__":
    unittest.main()
