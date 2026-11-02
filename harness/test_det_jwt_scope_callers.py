"""DET-JWT-SCOPE: JWT forge dispatch beyond role-carried JWTs on GET.

DET-JWT-DETECT covered a GET node reachable by a supplied role whose headers carry a
JWT. The three remaining cases, decided in .test-work/det-jwt-scope-20261102/BATCH.md:

  - analyze() path (in scope): a captured GET that carries a JWT reaches the forge
    leg with no model label; an opaque bearer token does not.
  - JWT only in the captured request, not in a supplied role (in scope, through the
    engagement's capture review, which runs each capture through analyze()).
  - non-GET methods (out of scope): the forge leg replays the request several times,
    which on a write is several writes, and the per-finding mutating ceiling allows
    one. A JWT-bearing write dispatches nothing and sends no forged token, with the
    mutating-replay opt-in off or on.

Each test enters through the real caller (Orchestrator.analyze or
investigate_engagement) with a silent model against an owned loopback target.
"""
from __future__ import annotations

import asyncio
import base64
import json
import unittest
from unittest.mock import patch

from harness import identity_headers
from harness.models import HttpExchange
from harness.orchestrator import Orchestrator
from harness.role_crawl import RoleSession
from harness.test_engagement_transport_callers import (
    _EngagementCallerBase, _Model, _config, _install_model)
from harness.validators.base import ValidationResult


def _jwt() -> str:
    def part(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()
    return f"{part({'alg': 'HS256', 'typ': 'JWT'})}.{part({'sub': 'alice', 'role': 'user'})}.c2lnbmF0dXJl"


_OPAQUE = "opaque-session-0123456789abcdef"


def _captured_get(base, token, path="/api/account"):
    return HttpExchange(url=f"{base}{path}", method="GET",
                        request_headers={"Authorization": f"Bearer {token}"},
                        response_status=200,
                        response_headers={"Content-Type": "application/json"},
                        response_body='{"id": 1, "owner": "alice", "email": "alice@example.test"}')


class _CallerBase(_EngagementCallerBase):
    def setUp(self):
        super().setUp()
        # investigate_engagement registers each role in the process-global
        # identity_headers store under the target host and never clears it. Left in
        # place, these loopback identities become extra "other identities" for a later
        # engagement on 127.0.0.1 (the pipeline gate's cross-identity leg).
        self.addCleanup(identity_headers.clear)


class _ForgeRecorder:
    """Stands in for JwtForgeValidator.validate: records what the dispatcher handed
    the forge leg, sends nothing."""

    def __init__(self):
        self.calls: list[HttpExchange] = []

    def patch(self):
        async def record(_validator, finding, exchange, *a, **kw):
            self.calls.append(exchange)
            return ValidationResult("jwt_forge", "not_confirmed", "jwt", summary="recorded")
        return patch("harness.validators.jwt_forge_validator.JwtForgeValidator.validate", new=record)

    def on(self, path):
        return [ex for ex in self.calls if ex.url.split("?")[0].endswith(path)]


class AnalyzeJwtDispatchCallerTests(_CallerBase, unittest.TestCase):
    """Case 2: Orchestrator.analyze on one captured exchange, model silent."""

    def _analyze(self, exchange, *, defects=()):
        orch = Orchestrator(_config(mutating=False))
        orch.allowed_hosts = ["127.0.0.1"]
        _install_model(orch, _Model([]))
        recorder = _ForgeRecorder()
        patches = [recorder.patch(), *defects]
        for p in patches:
            p.start()
        try:
            response = asyncio.run(orch.analyze(exchange, bypass_cache=True))
        finally:
            for p in reversed(patches):
                p.stop()
        return recorder, response

    def test_captured_get_with_a_jwt_reaches_the_forge_leg_without_a_label(self):
        target = self._target()
        recorder, _ = self._analyze(_captured_get(target.base, _jwt()))
        calls = recorder.on("/api/account")
        self.assertTrue(calls, "a JWT-bearing captured GET did not reach the forge leg")
        self.assertIn(_jwt(), calls[0].request_headers.get("Authorization", ""))

    def test_opaque_bearer_token_does_not_reach_the_forge_leg(self):
        target = self._target()
        recorder, _ = self._analyze(_captured_get(target.base, _OPAQUE))
        self.assertEqual(recorder.calls, [])

    def test_an_unconfirmed_jwt_leg_leaves_no_finding_standing(self):
        target = self._target()
        _, response = self._analyze(_captured_get(target.base, _jwt()))
        derived = [f for r in response.agent_reports for f in r.findings
                   if f.vulnerability_class == "jwt" and f.basis == "derived"]
        self.assertEqual(derived, [], "an unconfirmed shape leg stayed in the report")

    def test_removing_the_analyze_precondition_loses_the_dispatch(self):
        """Defect injection: without the analyze-path shape leg, the forge leg
        depends on a model label and the silent model gives none."""
        target = self._target()
        recorder, _ = self._analyze(_captured_get(target.base, _jwt()), defects=(
            patch("harness.orchestrator_detect.shape_precondition_findings", return_value=[]),))
        self.assertEqual(recorder.calls, [],
                         "dispatch survived without the precondition -- the positive test is vacuous")


_ACCOUNT_NODE = {"method": "GET", "path": "/api/account", "by_role": {"user": 200, "anonymous": 401},
                 "reachable_roles": ["user"], "object_scoped": False}
_OPAQUE_ROLES = [RoleSession("anonymous", {}), RoleSession("user", {"Cookie": f"session={_OPAQUE}"})]


class CapturedOnlyJwtEngagementCallerTests(_CallerBase, unittest.TestCase):
    """Case 3: the JWT is in a captured request; no supplied role carries one."""

    def _engage(self, token, *, defects=()):
        recorder = _ForgeRecorder()
        target = self._target()
        self._run(target, max_requests=500, endpoints=[_ACCOUNT_NODE], roles=_OPAQUE_ROLES,
                  captured=(lambda base: _captured_get(base, token).model_dump(),),
                  extra_patches=[recorder.patch(), *defects])
        return recorder

    def test_jwt_only_in_the_captured_request_reaches_the_forge_leg(self):
        calls = self._engage(_jwt()).on("/api/account")
        self.assertTrue(calls, "a JWT carried only by the capture did not reach the forge leg")
        self.assertIn(_jwt(), calls[0].request_headers.get("Authorization", ""))

    def test_opaque_captured_token_does_not_reach_the_forge_leg(self):
        self.assertEqual(self._engage(_OPAQUE).calls, [])

    def test_removing_the_analyze_precondition_loses_the_dispatch(self):
        recorder = self._engage(_jwt(), defects=(
            patch("harness.orchestrator_detect.shape_precondition_findings", return_value=[]),))
        self.assertEqual(recorder.calls, [],
                         "dispatch survived without the precondition -- the positive test is vacuous")


_WRITE_NODE = {"method": "POST", "path": "/api/notes", "by_role": {"user": 201, "anonymous": 401},
               "reachable_roles": ["user"], "object_scoped": False}


def _captured_write(base, token):
    return HttpExchange(url=f"{base}/api/notes", method="POST",
                        request_headers={"Authorization": f"Bearer {token}",
                                         "Content-Type": "application/json"},
                        request_body='{"note": "hello"}', response_status=201,
                        response_headers={"Content-Type": "application/json"},
                        response_body='{"ok": true}').model_dump()


class NonGetJwtOutOfScopeCallerTests(_CallerBase, unittest.TestCase):
    """Case 1 (out of scope): a JWT-bearing write is never forged, opt-in off or on."""

    def _engage(self, *, mutating, record):
        roles = [RoleSession("anonymous", {}), RoleSession("user", {"Authorization": f"Bearer {_jwt()}"})]
        target = self._target()
        recorder = _ForgeRecorder()
        self._run(target, max_requests=500, endpoints=[_WRITE_NODE], roles=roles,
                  captured=(lambda base: _captured_write(base, _jwt()),), mutating=mutating,
                  extra_patches=[recorder.patch()] if record else [])
        return target, recorder

    @staticmethod
    def _forged_writes(target):
        """Writes the target received whose bearer token is not the real one."""
        out = []
        for method, path, headers, _ in target.requests:
            auth = headers.get("authorization", "")
            if method != "GET" and auth.startswith("Bearer ") and auth != f"Bearer {_jwt()}":
                out.append((method, path, auth))
        return out

    def test_write_with_mutating_replay_off_sends_no_forged_token(self):
        target, _ = self._engage(mutating=False, record=False)
        self.assertEqual(self._forged_writes(target), [])
        writes = [(m, p) for m, p, _, _ in target.requests if m in ("POST", "PUT", "PATCH", "DELETE")]
        self.assertEqual(writes, [], "a write went out with mutating replay off")

    def test_write_with_mutating_replay_on_sends_no_forged_token(self):
        target, _ = self._engage(mutating=True, record=False)
        self.assertEqual(self._forged_writes(target), [])

    def test_write_does_not_dispatch_the_forge_leg(self):
        for mutating in (False, True):
            with self.subTest(mutating=mutating):
                _, recorder = self._engage(mutating=mutating, record=True)
                self.assertEqual(recorder.on("/api/notes"), [])


if __name__ == "__main__":
    unittest.main()
