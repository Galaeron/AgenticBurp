"""A one-request credential is not one of the run's identities (r9 review).

send_creds registers an ephemeral session for credentials no configured identity
owns: the agent's set_header, a credential probe, a tool's proxied request. In r9
those sessions stayed in the run's session list, and cross_identity replayed every
later check "as" each of them. One was the agent's empty `Bearer ` header, which
the HTTP client refuses to send: 355 refused sends (LocalProtocolError) across
the IDOR checks. A forged token the agent tried would equally have become an
"other principal".

Drives Orchestrator._validate_findings (the production caller) with real header
validation (h11, the library httpx sends HTTP/1.1 with). Controls: a configured
identity is still replayed, and putting ephemeral sessions back in the identity
list brings the r9 failure back.
"""
import asyncio
import unittest
from unittest.mock import patch

import h11
import httpx

from harness import experiment
from harness.models import AgentReport
from harness.run_context import RunContext, SessionManager
from harness.test_cross_identity_unsent_rvf import ORIGIN, _CallerBase, _finding
from harness.test_default_history_caller import _exchange

OBJECT = ORIGIN + "/orders/1"
AGENT_CREDENTIALS = ("Bearer ", "Bearer forged")   # empty token (r9), and a forged one


def _h11_validate(method, url, headers):
    """Refuse what h11 refuses before anything is sent (an empty `Bearer `)."""
    try:
        h11.Request(method=method, target=httpx.URL(url).raw_path,
                    headers=[("Host", "shop.invalid")] + [(k, v) for k, v in headers.items()])
    except h11.LocalProtocolError as exc:
        raise httpx.LocalProtocolError(str(exc)) from exc


class EphemeralSessionIdentityTests(_CallerBase, unittest.TestCase):

    def _run(self):
        """The agent sent its own credentials earlier in the run; then a BOLA
        candidate on an object route is validated. Returns (reports, the
        Authorization values cross_identity sent, the agent's sessions)."""
        from harness.validators.cross_identity_validator import CrossIdentityValidator
        orch = self._orch()
        orch.validator_registry.active_enabled = True
        orch.validator_registry.validators = {
            "cross_identity": CrossIdentityValidator(allowed_hosts=["shop.invalid"])}
        ex = _exchange(OBJECT, {"Authorization": "Bearer source"})
        sent = []

        async def fake_request(client, method, request_url, **kwargs):
            headers = dict(kwargs.get("headers") or {})
            _h11_validate(method, str(request_url), headers)
            auth = {k.lower(): v for k, v in headers.items()}.get("authorization", "")
            sent.append(auth)
            return httpx.Response(403, text="forbidden",
                                  request=httpx.Request(method, request_url))

        async def go():
            async with RunContext.create(allowed_hosts=["shop.invalid"], max_requests=100,
                                         gate_config={"active_enabled": True}) as run:
                run.sessions.register("anonymous", "anonymous", {}, allowed_origins=[ORIGIN])
                run.sessions.register("other", "other", {"Authorization": "Bearer other"},
                                      allowed_origins=[ORIGIN], role="user")
                transport = run.target_transport()
                for value in AGENT_CREDENTIALS:
                    await transport.send_creds("GET", ORIGIN + "/me", capability="iterative_agent",
                                               headers={"Authorization": value})
                agent_sessions = [s for s in run.sessions.all() if s.ephemeral]
                sent.clear()   # only what validation sends from here on
                reports, _proofs = await orch._validate_findings(
                    ex, [AgentReport(agent="auth", model="fake",
                                     findings=[_finding("broken_access_control")])],
                    run_context=run)
                return reports, agent_sessions

        with patch.object(httpx.AsyncClient, "request", fake_request):
            reports, agent_sessions = asyncio.run(go())
        return reports, sent, agent_sessions

    def test_agent_credentials_are_not_replayed_as_identities(self):
        reports, sent, agent_sessions = self._run()
        self.assertEqual(len(agent_sessions), len(AGENT_CREDENTIALS))   # still registered, flagged
        for value in AGENT_CREDENTIALS:
            self.assertNotIn(value, sent)
        verdicts = [(v.status, v.summary) for v in reports]
        self.assertTrue(reports)
        self.assertFalse(any(v.status == "error" for v in reports), verdicts)
        self.assertFalse(any("INCONCLUSIVE" in (v.summary or "") or "errored" in (v.summary or "")
                             for v in reports), verdicts)

    def test_control_a_configured_identity_is_still_replayed(self):
        _reports, sent, _agent = self._run()
        self.assertIn("Bearer other", sent)
        self.assertIn("", sent)   # the anonymous baseline

    def test_control_listing_ephemeral_sessions_brings_the_r9_failure_back(self):
        with patch.object(SessionManager, "identities", lambda self: self.all()):
            reports, sent, _agent = self._run()
        self.assertIn("Bearer forged", sent)     # a forged token replayed as a principal
        self.assertNotIn("Bearer ", sent)        # refused before sending, as in r9
        # r9's verdict: the refused probe leaves the check inconclusive
        self.assertTrue(reports)
        self.assertTrue(all("INCONCLUSIVE" in (v.summary or "") and "errored" in (v.summary or "")
                            for v in reports), [(v.status, v.summary) for v in reports])


class ExperimentIdentityTests(unittest.TestCase):
    """experiment.run_sessions (the experiment cycle's identity list) skips them too."""

    def test_run_sessions_lists_configured_identities_only(self):
        async def go():
            async with RunContext.create(allowed_hosts=["shop.invalid"], max_requests=10,
                                         gate_config={"active_enabled": True}) as run:
                run.sessions.register("anonymous", "anonymous", {}, allowed_origins=[ORIGIN])
                run.sessions.register("u1", "u1", {"Authorization": "Bearer u1"},
                                      allowed_origins=[ORIGIN], role="user")
                await run.target_transport().send_creds(
                    "GET", ORIGIN + "/me", capability="iterative_agent",
                    headers={"Authorization": "Bearer forged"})
                return ([pid for _ref, pid in experiment.run_sessions(run)],
                        sum(1 for s in run.sessions.all() if s.ephemeral))

        async def ok(client, method, request_url, **kwargs):
            return httpx.Response(200, text="{}", request=httpx.Request(method, request_url))

        with patch.object(httpx.AsyncClient, "request", ok):
            principals, ephemeral = asyncio.run(go())
        self.assertEqual(ephemeral, 1)
        self.assertEqual(principals, ["u1"])


if __name__ == "__main__":
    unittest.main()
