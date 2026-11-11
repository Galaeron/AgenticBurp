"""A check's own credentials are not the run's identities (r9 review, F5).

4e8742b1 kept send_creds' one-request sessions out of SessionManager.identities(),
but three checks register their own sessions directly: jwt_forge (one per forged
token), the missing-auth probe (its baseline copy and its garbage token) and the
NoSQL login leg (fresh pre-auth sessions). In r9 those stayed identities, and
cross_identity replayed every later object check as each of them: 7,041 of its
8,768 sends were one finding's request again under a forged token the target had
already refused (one object read 750 times, 49 sends per finding, 39 of them 401).

Drives the real JwtForgeValidator against a loopback that refuses forged tokens,
then Orchestrator._validate_findings (the production caller) on an object route.
Controls: a configured identity is still replayed, and registering the forged
tokens as identities again (the r9 behaviour) brings the replays back.
"""
from __future__ import annotations

import asyncio
import base64
import json
import unittest
from unittest.mock import patch

import httpx

from harness import missing_auth_probe
from harness.models import AgentReport, Finding, HttpExchange
from harness.run_context import RunContext, SessionManager
from harness.test_cross_identity_unsent_rvf import ORIGIN, _CallerBase, _finding
from harness.test_default_history_caller import _exchange
from harness.validators.jwt_forge_validator import JwtForgeValidator

OBJECT = ORIGIN + "/orders/1"


def _b64(obj) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


# A test value: an HS256-shaped token with a placeholder signature.
SOURCE_JWT = f"{_b64({'alg': 'HS256', 'typ': 'JWT'})}.{_b64({'sub': 'source'})}.c2lnbmF0dXJl"
SOURCE = f"Bearer {SOURCE_JWT}"
OTHER = "Bearer other"


class CheckSessionIdentityTests(_CallerBase, unittest.TestCase):

    def _run(self, register_as_identities=False):
        """jwt_forge and the missing-auth probe run first (as the worklist runs them);
        then a BOLA candidate is validated. Returns (reports, the Authorization values
        cross_identity sent, sessions the checks registered)."""
        from harness.validators.cross_identity_validator import CrossIdentityValidator
        orch = self._orch()
        orch.validator_registry.active_enabled = True
        orch.validator_registry.validators = {
            "cross_identity": CrossIdentityValidator(allowed_hosts=["shop.invalid"])}
        sent: list[tuple[str, str]] = []

        async def target(client, method, request_url, **kwargs):
            auth = {k.lower(): v for k, v in dict(kwargs.get("headers") or {}).items()
                    }.get("authorization", "")
            path = httpx.URL(str(request_url)).path
            sent.append((path, auth))
            if path == "/me":       # the source's own profile; anything else is refused
                status = 200 if auth == SOURCE else 401
            else:
                status = 401 if auth not in (SOURCE, OTHER, "") else 403
            return httpx.Response(status, text="{}" if status == 200 else "denied",
                                  request=httpx.Request(method, request_url))

        real_register = SessionManager.register

        def register(self_, *a, ephemeral=False, **kw):
            return real_register(self_, *a, ephemeral=ephemeral and not register_as_identities, **kw)

        async def go():
            async with RunContext.create(allowed_hosts=["shop.invalid"], max_requests=200,
                                         gate_config={"active_enabled": True}) as run:
                run.sessions.register("anonymous", "anonymous", {}, allowed_origins=[ORIGIN])
                run.sessions.register("source", "source", {"Authorization": SOURCE},
                                      allowed_origins=[ORIGIN], role="user")
                run.sessions.register("other", "other", {"Authorization": OTHER},
                                      allowed_origins=[ORIGIN], role="user")
                before = {s.session_id for s in run.sessions.all()}
                forge = await JwtForgeValidator(allowed_hosts=["shop.invalid"], run_context=run
                                                ).validate(
                    Finding(vulnerability_class="jwt", confidence=0.5, summary="s", evidence="",
                            suggested_test="t", basis="derived"),
                    HttpExchange(method="GET", url=ORIGIN + "/me",
                                 request_headers={"Authorization": SOURCE}, request_body="",
                                 response_status=200, response_headers={}, response_body="{}"))
                await missing_auth_probe.probe(
                    ORIGIN, ("GET", "/me"), allowed_hosts=["shop.invalid"],
                    baseline_headers={"Authorization": SOURCE}, protected_baseline=True,
                    send_garbage_token=True, run_context=run)
                check_sessions = [s for s in run.sessions.all() if s.session_id not in before]
                sent.clear()   # only what validation sends from here on
                reports, _proofs = await orch._validate_findings(
                    _exchange(OBJECT, {"Authorization": SOURCE}),
                    [AgentReport(agent="auth", model="fake",
                                 findings=[_finding("broken_access_control")])],
                    run_context=run)
                return forge, reports, check_sessions

        with patch.object(httpx.AsyncClient, "request", target), \
                patch.object(SessionManager, "register", register):
            forge, reports, check_sessions = asyncio.run(go())
        return forge, reports, [auth for path, auth in sent if path == "/orders/1"], check_sessions

    def test_a_checks_own_credentials_are_not_replayed_as_identities(self):
        forge, reports, sent, check_sessions = self._run()
        self.assertNotEqual(forge.status, "skipped", forge.summary)       # jwt_forge ran
        names = {s.session_id.split(":")[0] for s in check_sessions}
        self.assertIn("jwt-forge", names)
        self.assertIn("missing-auth", names)
        self.assertTrue(all(s.ephemeral for s in check_sessions))
        self.assertEqual(set(sent) - {SOURCE, OTHER, ""}, set(), sent)    # no forged token
        self.assertTrue(reports)
        self.assertFalse(any("INCONCLUSIVE" in (v.summary or "") for v in reports),
                         [(v.status, v.summary) for v in reports])

    def test_control_a_configured_identity_is_still_replayed(self):
        _forge, _reports, sent, _sessions = self._run()
        self.assertIn(OTHER, sent)

    def test_control_check_sessions_as_identities_bring_the_r9_replays_back(self):
        _forge, _reports, sent, check_sessions = self._run(register_as_identities=True)
        forged = [a for a in sent if a not in (SOURCE, OTHER, "")]
        self.assertTrue(forged, sent)                    # a check's token replayed as a principal
        self.assertFalse(any(s.ephemeral for s in check_sessions))


if __name__ == "__main__":
    unittest.main()
