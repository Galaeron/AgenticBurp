import unittest
from unittest.mock import AsyncMock, patch

import httpx

import scope_discovery
from models import Finding, HttpExchange
from run_context import RunContext, ScopePolicy
from test_run_context import _Fixture


def _confirmed_finding(vulnerability_class="sqli"):
    return Finding(
        vulnerability_class=vulnerability_class, confidence=0.9, severity="critical",
        summary="s", evidence="e", suggested_test="t", basis="derived", confirmed=True,
    )


def _exchange(url="https://target.invalid/rest/user/login"):
    return HttpExchange(
        url=url, method="POST",
        request_headers={"Authorization": "Bearer abc123", "Content-Type": "application/json"},
        request_body="{}", response_status=200, response_headers={}, response_body="",
    )


class IsHostAllowedTests(unittest.TestCase):
    def test_empty_allowed_hosts_fails_open(self):
        self.assertTrue(scope_discovery.is_host_allowed("https://anything.invalid/x", []))

    def test_matching_host_allowed(self):
        self.assertTrue(scope_discovery.is_host_allowed("https://target.invalid/x", ["target.invalid"]))

    def test_non_matching_host_rejected(self):
        self.assertFalse(scope_discovery.is_host_allowed("https://evil.invalid/x", ["target.invalid"]))

    def test_subdomain_of_allowed_host_allowed(self):
        self.assertTrue(scope_discovery.is_host_allowed("https://api.target.invalid/x", ["target.invalid"]))


class DiscoverFromScopeChangeTests(unittest.IsolatedAsyncioTestCase):
    """
    Safety-net coverage for the new top-level scope_discovery.py module --
    test_safety_gate.py's own TestNoValidatorBypassesTheGate only globs
    harness/validators/*.py, so this new module isn't automatically
    covered by that check. This is the equivalent, explicit guarantee for
    it: a candidate path outside server.allowed_hosts must never be sent
    to, verified against a mocked httpx client so no real network call is
    made in this test.
    """

    def _config(self, enabled=True, trigger_categories=None, candidate_paths=None, max_requests=5):
        return {
            "autonomous_discovery": {
                "enabled": enabled,
                "trigger_categories": trigger_categories or ["sqli"],
                "candidate_paths": candidate_paths or ["/api/users", "/admin"],
                "max_new_requests_per_trigger": max_requests,
            }
        }

    async def test_disabled_by_default_returns_nothing(self):
        result = await scope_discovery.discover_from_scope_change(
            _exchange(), [_confirmed_finding()], self._config(enabled=False), []
        )
        self.assertEqual(result, [])

    async def test_no_confirmed_trigger_finding_returns_nothing(self):
        unconfirmed = Finding(
            vulnerability_class="sqli", confidence=0.9, severity="critical",
            summary="s", evidence="e", suggested_test="t", basis="derived", confirmed=False,
        )
        result = await scope_discovery.discover_from_scope_change(
            _exchange(), [unconfirmed], self._config(), []
        )
        self.assertEqual(result, [])

    async def test_confirmed_finding_in_non_trigger_category_returns_nothing(self):
        result = await scope_discovery.discover_from_scope_change(
            _exchange(), [_confirmed_finding("cors")], self._config(trigger_categories=["sqli"]), []
        )
        self.assertEqual(result, [])

    async def test_candidate_outside_allowed_hosts_is_never_sent(self):
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            result = await scope_discovery.discover_from_scope_change(
                _exchange(), [_confirmed_finding()], self._config(),
                allowed_hosts=["some-other-host.invalid"],
            )
        mock_get.assert_not_called()
        self.assertEqual(result, [])

    async def test_confirmed_trigger_probes_candidates_within_scope(self):
        fake_response = httpx.Response(200, headers={}, text="ok", request=httpx.Request("GET", "https://target.invalid/api/users"))
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=fake_response) as mock_get:
            result = await scope_discovery.discover_from_scope_change(
                _exchange(), [_confirmed_finding()], self._config(candidate_paths=["/api/users"]),
                allowed_hosts=["target.invalid"],
            )
        mock_get.assert_called_once()
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].url, "https://target.invalid/api/users")
        self.assertEqual(result[0].response_status, 200)
        # Credentials carried verbatim from the triggering exchange.
        self.assertEqual(mock_get.call_args.kwargs["headers"].get("Authorization"), "Bearer abc123")

    async def test_max_new_requests_per_trigger_caps_candidates(self):
        fake_response = httpx.Response(200, headers={}, text="ok", request=httpx.Request("GET", "https://target.invalid/x"))
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=fake_response) as mock_get:
            await scope_discovery.discover_from_scope_change(
                _exchange(), [_confirmed_finding()],
                self._config(candidate_paths=["/a", "/b", "/c", "/d"], max_requests=2),
                allowed_hosts=["target.invalid"],
            )
        self.assertEqual(mock_get.call_count, 2)

    async def test_per_candidate_network_failure_does_not_raise(self):
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, side_effect=httpx.ConnectError("refused")):
            result = await scope_discovery.discover_from_scope_change(
                _exchange(), [_confirmed_finding()], self._config(candidate_paths=["/api/users"]),
                allowed_hosts=["target.invalid"],
            )
        self.assertEqual(result, [])

    async def test_run_context_routes_actual_scope_probe_as_triggering_session(self):
        fixture = _Fixture()
        ctx = RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=1,
                                gate_config={"active_enabled": True})
        ctx.sessions.register("source", "source", {"Authorization": "Bearer abc123"},
                              allowed_origins=[ScopePolicy.origin_of(fixture.base)])
        exchange = _exchange(fixture.base + "/trigger")
        try:
            result = await scope_discovery.discover_from_scope_change(
                exchange, [_confirmed_finding()],
                self._config(candidate_paths=["/new-surface"]),
                allowed_hosts=["127.0.0.1"], run_context=ctx)
            self.assertEqual(len(result), 1)
            self.assertEqual(ctx.budget.used, 1)
            self.assertEqual(fixture.httpd.received[0]["authorization"], "Bearer abc123")
        finally:
            await ctx.aclose()
            fixture.close()


if __name__ == "__main__":
    unittest.main()
