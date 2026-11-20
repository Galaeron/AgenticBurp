"""ARC-15: POST /settings validates what it applies, and removing the throttle is explicit.

Through the real route (harness.server app, bearer token): a malformed
retry_budget is a 422 and leaves the live policy unchanged; a throttle that is on
is only removed (throttle_rps 0) with confirm_unlimited, and that removal is
recorded in the manifest of a run live at the time. A request that is refused
applies nothing, not even its valid parts.

Negative controls: the policy layer itself (VulnBudgetPolicy.merged_with) takes a
malformed value, so the route's schema is what keeps it out; well-formed values
are still applied; with the throttle already off, throttle_rps 0 (the Burp
field's default) is not refused; a manifest started after the change records none.
"""
from __future__ import annotations

import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from harness import global_throttle


class SettingsValidationTests(unittest.TestCase):
    def setUp(self):
        import harness.server as server_module
        self.server = server_module
        self.client = TestClient(server_module.app, base_url="http://localhost",
                                 headers={"Authorization": f"Bearer {server_module._mutation_token()}"})
        self.addCleanup(self.client.close)
        orch = server_module.orchestrator
        original = orch.retry_budget_policy
        self.addCleanup(setattr, orch, "retry_budget_policy", original)
        global_throttle.configure(0, source="test")
        self.addCleanup(global_throttle.configure, 0, source="test")

    def _policy(self):
        return self.server.orchestrator.retry_budget_policy

    def test_malformed_retry_budget_is_422_and_not_applied(self):
        before = self._policy()
        for bad in ({"max_retries": "7"}, {"max_retries": -1}, {"max_retries": 11},
                    {"max_retries": 2.5}, {"max_retries": True}, {"max_agents": 0},
                    {"max_tokens_per_vuln": -5}, {"stop_on_found": "false"},
                    {"min_actionable_confidence": 2}, {"min_actionable_confidence": "0.5"},
                    {"unknown_knob": 1}, ["max_retries", 7]):
            with self.subTest(retry_budget=bad):
                reply = self.client.post("/settings", json={"retry_budget": bad})
                self.assertEqual(reply.status_code, 422, reply.text)
                self.assertEqual(self._policy(), before)

    def test_refused_request_applies_none_of_its_parts(self):
        before = self._policy()
        reply = self.client.post("/settings", json={"throttle_rps": 5.0,
                                                    "retry_budget": {"max_retries": "x"}})
        self.assertEqual(reply.status_code, 422, reply.text)
        self.assertFalse(global_throttle.throttle.enabled)
        self.assertEqual(self._policy(), before)

    def test_control_policy_layer_alone_accepts_a_malformed_value(self):
        poisoned = self._policy().merged_with({"max_retries": "7"})
        self.assertEqual(poisoned.max_retries, "7")

    def test_control_well_formed_retry_budget_is_applied(self):
        reply = self.client.post("/settings", json={"retry_budget": {
            "max_retries": 4, "max_agents": 2, "max_tokens_per_vuln": 5000,
            "stop_on_found": False, "min_actionable_confidence": 0.6}})
        self.assertEqual(reply.status_code, 200, reply.text)
        p = self._policy()
        self.assertEqual((p.max_retries, p.max_agents, p.max_tokens_per_vuln, p.stop_on_found,
                          p.min_actionable_confidence), (4, 2, 5000, False, 0.6))
        # 0 = no per-vulnerability token cap, as the Burp field and config.yaml say.
        reply = self.client.post("/settings", json={"retry_budget": {"max_tokens_per_vuln": 0}})
        self.assertEqual(reply.status_code, 200, reply.text)
        self.assertIsNone(self._policy().max_tokens_per_vuln)
        self.assertEqual(self._policy().max_retries, 4)

    def test_invalid_throttle_rates_are_422(self):
        global_throttle.configure(5, source="test")
        for raw in ('{"throttle_rps": -1}', '{"throttle_rps": NaN}', '{"throttle_rps": Infinity}',
                    '{"throttle_rps": "fast"}', '{"throttle_rps": 0, "confirm_unlimited": "true"}'):
            with self.subTest(body=raw):
                reply = self.client.post("/settings", content=raw,
                                         headers={"Content-Type": "application/json"})
                self.assertEqual(reply.status_code, 422, reply.text)
                self.assertEqual(global_throttle.throttle.stats()["rate_per_second"], 5.0)

    def test_removing_a_live_throttle_needs_confirmation(self):
        global_throttle.configure(5, source="test")
        before = self._policy()
        refused = self.client.post("/settings", json={"throttle_rps": 0,
                                                      "retry_budget": {"max_retries": 4}})
        self.assertEqual(refused.status_code, 422, refused.text)
        self.assertIn("confirm_unlimited", refused.text)
        self.assertEqual(global_throttle.throttle.stats()["rate_per_second"], 5.0)
        self.assertEqual(self._policy(), before)
        self.assertEqual(global_throttle.throttle.changes()[-1]["source"], "test")

        confirmed = self.client.post("/settings", json={"throttle_rps": 0, "confirm_unlimited": True})
        self.assertEqual(confirmed.status_code, 200, confirmed.text)
        self.assertFalse(global_throttle.throttle.enabled)
        event = global_throttle.throttle.changes()[-1]
        self.assertEqual((event["source"], event["rate_per_second"], event["previous_rate_per_second"],
                          event.get("confirmed_unlimited")), ("settings", 0.0, 5.0, True))

    def test_control_zero_while_already_off_is_not_refused(self):
        reply = self.client.post("/settings", json={"throttle_rps": 0,
                                                    "retry_budget": {"max_retries": 3}})
        self.assertEqual(reply.status_code, 200, reply.text)
        self.assertFalse(global_throttle.throttle.enabled)
        self.assertEqual(self._policy().max_retries, 3)

    def test_confirmed_removal_is_in_the_live_run_manifest(self):
        from harness import run_manifest
        global_throttle.configure(5, source="test")
        out = tempfile.TemporaryDirectory()
        self.addCleanup(out.cleanup)
        with patch.object(run_manifest, "_git_state", return_value=(None, None)):
            live = run_manifest.RunManifest.start(run_id="arc15-live", target_identifier="t",
                                                  config={}, output_dir=out.name)
            reply = self.client.post("/settings", json={"throttle_rps": 0, "confirm_unlimited": True})
            self.assertEqual(reply.status_code, 200, reply.text)
            later = run_manifest.RunManifest.start(run_id="arc15-later", target_identifier="t",
                                                   config={}, output_dir=out.name)
            live.finish("done", result={})
            later.finish("done", result={})
        throttle = live.data["throttle"]
        self.assertEqual(throttle["at_start"]["rate_per_second"], 5.0)
        self.assertFalse(throttle["at_finish"]["enabled"])
        self.assertEqual([(c["source"], c.get("confirmed_unlimited")) for c in throttle["changes"]],
                         [("settings", True)])
        self.assertEqual(later.data["throttle"]["changes"], [])


if __name__ == "__main__":
    unittest.main()
