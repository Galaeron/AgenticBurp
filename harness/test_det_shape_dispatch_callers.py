"""I09: deterministic shape dispatch at the real engagement caller.

DET-SQLI-POST: a captured body-only POST must reach the SQLi leg with its BODY as
the injection target and no model label; an empty-body capture must not.
DET-JWT-DETECT: a JWT carried in a role's session cookie must reach the JWT forge
leg with no model label; an opaque cookie must not.

Each runs Orchestrator.investigate_engagement (discovery canned, model silent)
against an owned loopback target. sqlmap's process launch and the forge leg's
network work are replaced by recorders, so nothing reaches Docker and the tests
observe exactly what the dispatcher handed to each leg. Removing the shape
precondition must make the positive case fail.
"""
from __future__ import annotations

import base64
import json
import subprocess
import unittest
from unittest.mock import AsyncMock, patch

from harness.models import HttpExchange
from harness.role_crawl import RoleSession
from harness.test_engagement_transport_callers import _EngagementCallerBase
from harness.validators.base import ValidationResult


def _post_search(base, body):
    return HttpExchange(url=f"{base}/api/search", method="POST",
                        request_headers={"Content-Type": "application/json"},
                        request_body=body, response_status=200,
                        response_headers={"Content-Type": "application/json"},
                        response_body='{"results": []}').model_dump()


_SEARCH_NODE = {"method": "POST", "path": "/api/search", "by_role": {"anonymous": 200},
                "reachable_roles": ["anonymous"], "object_scoped": False}


class _SqlmapRecorder:
    """Stands in for tool_runner.run_process, the sqlmap validator's host launch."""

    def __init__(self):
        self.commands: list[list[str]] = []

    def __call__(self, cmd, **kwargs):
        self.commands.append(list(cmd))
        return subprocess.CompletedProcess(cmd, 0, "all tested parameters do not appear to be injectable", "")


class SqliBodyDispatchCallerTests(_EngagementCallerBase, unittest.TestCase):
    def _run_sqli(self, body, *, defects=()):
        recorder = _SqlmapRecorder()
        target = self._target()
        patches = [patch("harness.tool_runner.run_process", side_effect=recorder)]
        patches.extend(defects)
        self._run(target, max_requests=500, endpoints=[_SEARCH_NODE],
                  captured=(lambda base: _post_search(base, body),), mutating=True,
                  extra_patches=patches)
        return recorder

    @staticmethod
    def _flag(cmd, name):
        return cmd[cmd.index(name) + 1] if name in cmd else None

    def test_body_only_post_reaches_sqlmap_with_the_body_as_target(self):
        recorder = self._run_sqli('{"q": "widget"}')
        search = [c for c in recorder.commands if (self._flag(c, "-u") or "").endswith("/api/search")]
        self.assertTrue(search, f"the sqli leg never ran for the captured POST: {recorder.commands}")
        cmd = search[0]
        self.assertEqual(json.loads(self._flag(cmd, "--data")), {"q": "widget"})
        self.assertNotIn("?", self._flag(cmd, "-u"), "the body parameter was moved into the query")

    def test_empty_body_post_does_not_dispatch_sqli(self):
        recorder = self._run_sqli("")
        self.assertFalse([c for c in recorder.commands
                          if (self._flag(c, "-u") or "").endswith("/api/search")], recorder.commands)

    def test_removing_the_shape_preconditions_loses_the_dispatch(self):
        """Defect injection: two label-free routes dispatch this leg -- the graph
        precondition and the analyze-path precondition on the captured exchange.
        Without both, the leg depends on a model label, and the silent model gives
        none, so the positive case must fail."""
        recorder = self._run_sqli('{"q": "widget"}', defects=(
            patch("harness.orchestrator_chain.shape_precondition_legs", return_value=[]),
            patch("harness.orchestrator_detect.shape_precondition_findings", return_value=[])))
        self.assertFalse([c for c in recorder.commands
                          if (self._flag(c, "-u") or "").endswith("/api/search")],
                         "dispatch survived without the precondition -- the positive test is vacuous")


def _jwt() -> str:
    def part(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()
    return f"{part({'alg': 'HS256', 'typ': 'JWT'})}.{part({'sub': 'alice', 'role': 'user'})}.c2lnbmF0dXJl"


_PROFILE_NODE = {"method": "GET", "path": "/api/profile", "by_role": {"user": 200, "anonymous": 401},
                 "reachable_roles": ["user"], "object_scoped": False}


class JwtCookieDispatchCallerTests(_EngagementCallerBase, unittest.TestCase):
    def _run_jwt(self, cookie):
        roles = [RoleSession("anonymous", {}), RoleSession("user", {"Cookie": f"session={cookie}"})]
        calls = []

        async def record(self_validator, finding, exchange, *a, **kw):
            calls.append(exchange)
            return ValidationResult("jwt_forge", "not_confirmed", "jwt", summary="recorded")

        target = self._target()
        self._run(target, max_requests=500, endpoints=[_PROFILE_NODE], roles=roles,
                  extra_patches=[patch("harness.validators.jwt_forge_validator.JwtForgeValidator.validate",
                                       new=record)])
        return [ex for ex in calls if ex.url.endswith("/api/profile")]

    def test_jwt_in_session_cookie_dispatches_the_forge_leg_without_a_label(self):
        calls = self._run_jwt(_jwt())
        self.assertTrue(calls, "a JWT-bearing cookie did not reach the forge leg")
        self.assertIn(_jwt(), calls[0].request_headers.get("Cookie", ""))

    def test_opaque_session_cookie_does_not_dispatch_the_forge_leg(self):
        self.assertEqual(self._run_jwt("opaque-session-0123456789"), [])


if __name__ == "__main__":
    unittest.main()
