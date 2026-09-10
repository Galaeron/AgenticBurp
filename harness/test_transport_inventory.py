"""T08 verification: the transport inventory is complete, current, and enforced.

The point of these tests is the routing-regression guard: if a NEW direct httpx
send is added to a production module without either routing it through the
run-scoped executor or recording it in `transport_inventory.TRANSPORT_SITES` with
an owner, `test_scan_matches_registry` fails -- so the transport surface can never
silently grow a fourth "green tests, dead pipeline" bypass unnoticed.
"""
import os
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

    def test_cross_identity_gap_is_flagged(self):
        # The review's F04 gap must be explicit in the audit (partial T03 migration).
        site = {s.module: s for s in ti.TRANSPORT_SITES}["validators/cross_identity_validator.py"]
        self.assertTrue(site.is_routing_gap)
        self.assertIn("session", site.gap.lower())

    def test_summary_is_consistent(self):
        s = ti.summary()
        self.assertEqual(s["total_sites"], len(ti.TRANSPORT_SITES))
        self.assertEqual(s["routing_gaps"], len(ti.routing_gaps()))
        self.assertGreater(s["by_scope"].get(ti.SCOPE_TARGET, 0), 0)


if __name__ == "__main__":
    unittest.main()
