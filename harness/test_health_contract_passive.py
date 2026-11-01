"""Public health route controls with synthetic backend status and no network."""
from unittest.mock import AsyncMock, patch
import unittest

import httpx

from harness.test_pairing_contract import PairingCallerTests
from harness.run_context import TargetTransport


class HealthContractTests(unittest.TestCase):
    def setUp(self):
        self.fixture = PairingCallerTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.server, self.client = self.fixture.server, self.fixture.client
        for patcher in (patch.object(TargetTransport, "execute", side_effect=AssertionError("no target")),
                        patch.object(httpx.AsyncClient, "request", side_effect=AssertionError("no provider"))):
            patcher.start()
            self.addCleanup(patcher.stop)

    def status(self, configured, models):
        self.server.orchestrator.coordinator_model = configured
        self.server.orchestrator.ollama.health_check = AsyncMock(return_value={"reachable": True, "models": models})
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        return response.json()

    def test_exact_model_tag_required_and_latest_alias_is_supported(self):
        response = self.status("synthetic:8b", ["synthetic:4b"])
        self.assertEqual(response["status"], "degraded")
        self.assertEqual(response["ollama"]["missing_models"], ["synthetic:8b"])
        self.assertEqual(self.status("synthetic:8b", ["synthetic:8b"])["status"], "ok")
        self.assertEqual(self.status("synthetic", ["synthetic:latest"])["status"], "ok")
        self.assertEqual(self.status("synthetic", ["synthetic:4b"])["status"], "degraded")

    def test_public_health_withholds_upstream_error_and_url_credentials(self):
        secret = "SYNTHETIC_HEALTH_SECRET"
        self.server.orchestrator.ollama.base_url = f"https://user:{secret}@provider.invalid/?token={secret}"
        self.server.orchestrator.ollama.health_check = AsyncMock(return_value={
            "reachable": False, "models": [], "error": f"opaque {secret}"})
        response = self.client.get("/health")
        self.assertEqual(response.json()["status"], "degraded")
        self.assertNotIn(secret, response.text)
        with patch.object(self.server.security, "redact_secrets_in_url", side_effect=lambda url: url):
            self.assertIn(secret, self.client.get("/health").text)


if __name__ == "__main__":
    unittest.main()
