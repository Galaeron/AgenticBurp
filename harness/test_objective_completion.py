"""
Objective-completion stage tests (owned vulnerable/fixed fixture, no external
target). Per docs/LIVE_OBJECTIVE_CONTINUATION_HANDOFF.md: build and pass these
caller-level controls BEFORE rerunning the external SSTI lab.

The fixture is an in-process fake ERB-evaluating endpoint (same style as
`test_injection_legs.py`'s `_ssti_responder`, extended with a fake filesystem)
rather than a real subprocess server -- network is stubbed at
`httpx.AsyncClient.request`, matching this project's existing validator-test
convention.
"""
import asyncio
import json
import unittest
from unittest.mock import patch

from harness.models import Finding, HttpExchange
from harness.objective_completion import (
    attempt_completion, COMPLETED, NOT_COMPLETED, NOT_ATTEMPTED, POLICY_BLOCKED,
)
from harness.objective_profiles import (
    ObjectiveTask, SSTI_FILE_DELETE, ACCESS_ADMIN_READ, ObjectiveProfile,
)
from harness.run_context import RunContext
from harness.validators.base import ValidationResult


def _finding():
    return Finding(vulnerability_class="ssti", confidence=0.9, severity="high",
                   summary="ssti", evidence="e", suggested_test="t", basis="derived")


def _access_finding():
    return Finding(vulnerability_class="idor", confidence=0.9, severity="medium",
                   summary="idor", evidence="e", suggested_test="t", basis="derived")


def _exchange():
    return HttpExchange(url="http://t.test/render", method="POST",
                        request_headers={"Content-Type": "application/json"},
                        request_body='{"q":"hello"}', response_status=200, response_body="")


def _confirmed():
    return ValidationResult("ssti", "confirmed", "ssti", confidence=0.95, confirmed=True,
                            summary="arithmetic canary confirmed")


class _FakeFixture:
    """An owned vulnerable ERB-like fixture: `/render` evaluates
    `File.delete('path') rescue nil; 'deleted'` inside `<%= ... %>` against an
    in-memory fake filesystem; `/status` reports whether a path is present.
    `vulnerable=False` reproduces the *fixed* control: input is echoed
    literally, never evaluated."""

    def __init__(self, vulnerable: bool, files: set[str] | None = None):
        self.vulnerable = vulnerable
        self.files = files if files is not None else {"/tmp/disposable.txt"}
        self.calls = 0

    async def __call__(self, method, url, content=None, headers=None, **kw):
        self.calls += 1

        class _Resp:
            def __init__(self, text):
                self.text = text
                self.status_code = 200
                self.headers = {}
        if "/status" in url:
            path = url.split("file=", 1)[1] if "file=" in url else ""
            present = path in self.files
            return _Resp("present" if present else "absent")
        payload = json.loads(content).get("q", "") if content else ""
        if not self.vulnerable:
            return _Resp(f"<html>echo {payload}</html>")
        nonce = payload[:6]
        inner = payload[6:-6] if len(payload) > 12 and payload.endswith(nonce) else ""
        if inner.startswith("<%=") and inner.endswith("%>"):
            m = None
            import re
            m = re.match(r"<%=\s*File\.delete\('([^']+)'\)\s*rescue\s*nil;\s*'deleted'\s*%>", inner)
            if m:
                self.files.discard(m.group(1))
                return _Resp(f"<html>{nonce}deleted{nonce}</html>")
        return _Resp(f"<html>echo {payload}</html>")


class _FakeAccessFixture:
    """An owned fixture for a NON-destructive, read-only access-control/IDOR
    reach-state objective: GET /admin/secret returns the protected content
    (and the independent oracle marker) when `vulnerable=True` -- no
    authorization enforced -- and a plain 403 when `vulnerable=False`, the
    *fixed* control where authorization IS enforced. There is no mutation
    anywhere in this fixture; both branches only ever read."""

    MARKER = "ADMIN-SECRET-9f3c21"

    def __init__(self, vulnerable: bool):
        self.vulnerable = vulnerable
        self.calls = 0

    async def __call__(self, method, url, content=None, headers=None, **kw):
        self.calls += 1

        class _Resp:
            def __init__(self, text, status):
                self.text = text
                self.status_code = status
                self.headers = {}
        if "/admin/secret" in url:
            if self.vulnerable:
                return _Resp(f"<html>{_FakeAccessFixture.MARKER}</html>", 200)
            return _Resp("<html>Forbidden</html>", 403)
        return _Resp("<html>not found</html>", 404)


def _access_task():
    return ObjectiveTask(
        profile=ACCESS_ADMIN_READ,
        target_path="http://t.test/admin/secret",
        oracle_url="http://t.test/admin/secret",
        oracle_marker=_FakeAccessFixture.MARKER,
    )


def _access_confirmed():
    return ValidationResult("idor_read", "confirmed", "idor", confidence=0.9, confirmed=True,
                            summary="idor read differential confirmed")


def _ctx(allow_mutating=True, max_requests=10):
    return RunContext.create(
        allowed_hosts=["t.test"], max_requests=max_requests,
        gate_config={"active_enabled": True, "allow_mutating_replay": allow_mutating})


class ObjectiveNotAttemptedTests(unittest.TestCase):
    def test_no_task_never_attempted(self):
        r = asyncio.run(attempt_completion(None, _finding(), _exchange(), _confirmed(),
                                           run_context=_ctx()))
        self.assertEqual(r.status, NOT_ATTEMPTED)

    def test_arithmetic_only_confirmation_without_task_stays_not_attempted(self):
        # Regression for CURRENT_STATE.md's SSTI record: an arithmetic-only
        # confirmation with no declared objective must never silently become
        # "completed" -- it must stay unattempted, not attempted-and-failed.
        r = asyncio.run(attempt_completion(None, _finding(), _exchange(), _confirmed(),
                                           run_context=_ctx()))
        self.assertEqual(r.status, NOT_ATTEMPTED)

    def test_not_attempted_unless_already_confirmed(self):
        unconfirmed = ValidationResult("ssti", "not_confirmed", "ssti", confirmed=False)
        task = ObjectiveTask(profile=SSTI_FILE_DELETE, target_path="/tmp/disposable.txt",
                             oracle_url="http://t.test/status?file=/tmp/disposable.txt")
        r = asyncio.run(attempt_completion(task, _finding(), _exchange(), unconfirmed,
                                           run_context=_ctx()))
        self.assertEqual(r.status, NOT_ATTEMPTED)

    def test_unknown_action_class_never_inferred(self):
        bogus = ObjectiveProfile(vulnerability_class="ssti", action_class="registry_wipe")
        task = ObjectiveTask(profile=bogus, target_path="HKLM\\whatever")
        r = asyncio.run(attempt_completion(task, _finding(), _exchange(), _confirmed(),
                                           run_context=_ctx()))
        self.assertEqual(r.status, NOT_ATTEMPTED)

    def test_mismatched_profile_class_never_attempted(self):
        other = ObjectiveProfile(vulnerability_class="path traversal", action_class="file_delete",
                                 oracle="file_absent")
        task = ObjectiveTask(profile=other, target_path="/tmp/disposable.txt")
        r = asyncio.run(attempt_completion(task, _finding(), _exchange(), _confirmed(),
                                           run_context=_ctx()))
        self.assertEqual(r.status, NOT_ATTEMPTED)


class ObjectiveCompletionPositiveTests(unittest.TestCase):
    def test_completes_and_independent_oracle_confirms_deletion(self):
        fixture = _FakeFixture(vulnerable=True)
        task = ObjectiveTask(profile=SSTI_FILE_DELETE, target_path="/tmp/disposable.txt",
                             oracle_url="http://t.test/status?file=/tmp/disposable.txt")
        ctx = _ctx()
        with patch("httpx.AsyncClient.request", fixture):
            r = asyncio.run(attempt_completion(task, _finding(), _exchange(), _confirmed(),
                                               run_context=ctx))
        self.assertEqual(r.status, COMPLETED)
        self.assertNotIn("/tmp/disposable.txt", fixture.files)
        self.assertEqual(ctx.budget.used, 2)

    def test_llm_proposal_outside_contract_is_rejected_and_fallback_used(self):
        fixture = _FakeFixture(vulnerable=True)
        task = ObjectiveTask(profile=SSTI_FILE_DELETE, target_path="/tmp/disposable.txt",
                             oracle_url="http://t.test/status?file=/tmp/disposable.txt")

        class _RogueProvider:
            async def chat_json(self, *a, **kw):
                class _R:
                    data = {"payload": "<%= system('rm -rf /') %>"}
                return _R()

        ctx = _ctx()
        with patch("httpx.AsyncClient.request", fixture):
            r = asyncio.run(attempt_completion(task, _finding(), _exchange(), _confirmed(),
                                               run_context=ctx, provider=_RogueProvider()))
        # The declared file is still gone (the deterministic fallback ran),
        # and the rogue "rm -rf /" proposal was never sent anywhere.
        self.assertEqual(r.status, COMPLETED)
        self.assertNotIn("rm -rf", r.payload)

    def test_llm_proposal_matching_contract_is_used_verbatim(self):
        fixture = _FakeFixture(vulnerable=True)
        task = ObjectiveTask(profile=SSTI_FILE_DELETE, target_path="/tmp/disposable.txt",
                             oracle_url="http://t.test/status?file=/tmp/disposable.txt")

        class _GoodProvider:
            async def chat_json(self, *a, **kw):
                class _R:
                    data = {"payload": "<%= File.delete('/tmp/disposable.txt') rescue nil; 'deleted' %>"}
                return _R()

        ctx = _ctx()
        with patch("httpx.AsyncClient.request", fixture):
            r = asyncio.run(attempt_completion(task, _finding(), _exchange(), _confirmed(),
                                               run_context=ctx, provider=_GoodProvider()))
        self.assertEqual(r.status, COMPLETED)
        self.assertNotIn("/tmp/disposable.txt", fixture.files)


class ObjectiveFixedControlTests(unittest.TestCase):
    def test_fixed_fixture_never_reports_completed(self):
        # The fixed variant never evaluates the template at all; confirmation
        # itself would not have succeeded against it in production. Here we
        # still exercise completion directly to prove it cannot be tricked
        # into "completed" by a template that only echoes the payload.
        fixture = _FakeFixture(vulnerable=False)
        task = ObjectiveTask(profile=SSTI_FILE_DELETE, target_path="/tmp/disposable.txt",
                             oracle_url="http://t.test/status?file=/tmp/disposable.txt")
        ctx = _ctx()
        with patch("httpx.AsyncClient.request", fixture):
            r = asyncio.run(attempt_completion(task, _finding(), _exchange(), _confirmed(),
                                               run_context=ctx))
        self.assertEqual(r.status, NOT_COMPLETED)
        self.assertIn("/tmp/disposable.txt", fixture.files)


class ObjectivePolicyGateTests(unittest.TestCase):
    def test_zero_budget_blocks_and_preserves_file(self):
        fixture = _FakeFixture(vulnerable=True)
        task = ObjectiveTask(profile=SSTI_FILE_DELETE, target_path="/tmp/disposable.txt",
                             oracle_url="http://t.test/status?file=/tmp/disposable.txt")
        ctx = _ctx(max_requests=0)
        with patch("httpx.AsyncClient.request", fixture):
            r = asyncio.run(attempt_completion(task, _finding(), _exchange(), _confirmed(),
                                               run_context=ctx))
        self.assertEqual(r.status, POLICY_BLOCKED)
        self.assertEqual(ctx.budget.used, 0)
        self.assertEqual(fixture.calls, 0)
        self.assertIn("/tmp/disposable.txt", fixture.files)

    def test_mutating_replay_not_authorized_blocks(self):
        fixture = _FakeFixture(vulnerable=True)
        task = ObjectiveTask(profile=SSTI_FILE_DELETE, target_path="/tmp/disposable.txt",
                             oracle_url="http://t.test/status?file=/tmp/disposable.txt")
        ctx = _ctx(allow_mutating=False)
        with patch("httpx.AsyncClient.request", fixture) as send:
            r = asyncio.run(attempt_completion(task, _finding(), _exchange(), _confirmed(),
                                               run_context=ctx))
        self.assertEqual(r.status, POLICY_BLOCKED)
        self.assertIn("/tmp/disposable.txt", fixture.files)

    def test_no_run_context_blocks(self):
        task = ObjectiveTask(profile=SSTI_FILE_DELETE, target_path="/tmp/disposable.txt")
        r = asyncio.run(attempt_completion(task, _finding(), _exchange(), _confirmed(),
                                           run_context=None))
        self.assertEqual(r.status, POLICY_BLOCKED)


class DestructiveObjectiveNotAttemptedTests(unittest.TestCase):
    """Acceptance: 'a destructive objective returns objective_not_attempted
    without an explicit opt-in'. Both halves of that are already proven
    above -- pinned here as one explicit, named reference point:

      - no task declared at all (the runner's committed default, per
        `testing/run_web_objective_smoke.py`, which never passes
        `objective_task`) -> `ObjectiveNotAttemptedTests.test_no_task_never_attempted`
        returns NOT_ATTEMPTED and never sends anything;
      - a destructive SSTI_FILE_DELETE task IS declared but
        `validators.allow_mutating_replay` is off ->
        `ObjectivePolicyGateTests.test_mutating_replay_not_authorized_blocks`
        returns POLICY_BLOCKED (the declared-but-refused case) and the
        disposable file is preserved -- never COMPLETED either way.
    """

    def test_no_task_declared_is_not_attempted(self):
        r = asyncio.run(attempt_completion(None, _finding(), _exchange(), _confirmed(),
                                           run_context=_ctx()))
        self.assertEqual(r.status, NOT_ATTEMPTED)

    def test_declared_destructive_task_without_opt_in_never_completes(self):
        fixture = _FakeFixture(vulnerable=True)
        task = ObjectiveTask(profile=SSTI_FILE_DELETE, target_path="/tmp/disposable.txt",
                             oracle_url="http://t.test/status?file=/tmp/disposable.txt")
        ctx = _ctx(allow_mutating=False)
        with patch("httpx.AsyncClient.request", fixture):
            r = asyncio.run(attempt_completion(task, _finding(), _exchange(), _confirmed(),
                                               run_context=ctx))
        self.assertEqual(r.status, POLICY_BLOCKED)
        self.assertNotEqual(r.status, COMPLETED)
        self.assertIn("/tmp/disposable.txt", fixture.files)


class ObjectiveAccessReadPositiveTests(unittest.TestCase):
    """LB-6: the one declared NON-destructive objective (ACCESS_ADMIN_READ).
    Read-only (GET), so it needs no `allow_mutating_replay` opt-in -- GET is
    always the safety gate's SAFE risk tier."""

    def test_completes_against_vulnerable_fixture_no_mutating_opt_in_needed(self):
        fixture = _FakeAccessFixture(vulnerable=True)
        ctx = _ctx(allow_mutating=False)
        with patch("httpx.AsyncClient.request", fixture):
            r = asyncio.run(attempt_completion(_access_task(), _access_finding(), _exchange(),
                                               _access_confirmed(), run_context=ctx))
        self.assertEqual(r.status, COMPLETED)
        # action GET + independent oracle GET -- never derived from the same
        # response.
        self.assertEqual(ctx.budget.used, 2)
        self.assertEqual(fixture.calls, 2)

    def test_action_is_a_plain_get_never_a_mutation(self):
        # A callable INSTANCE, not a plain function: `httpx.AsyncClient.request`
        # is patched at the class level, and a plain function assigned there is
        # a descriptor that would get `self` (the client) implicitly bound as
        # its first positional arg. `_FakeAccessFixture.__call__` already
        # avoids this (same reason every other fixture in this file is a
        # class instance) -- this spy wraps it the same way.
        class _MethodSpy:
            def __init__(self, inner):
                self.inner = inner
                self.methods: list[str] = []

            async def __call__(self, method, url, content=None, headers=None, **kw):
                self.methods.append(method.upper())
                return await self.inner(method, url, content=content, headers=headers, **kw)

        spy = _MethodSpy(_FakeAccessFixture(vulnerable=True))
        ctx = _ctx()
        with patch("httpx.AsyncClient.request", spy):
            r = asyncio.run(attempt_completion(_access_task(), _access_finding(), _exchange(),
                                               _access_confirmed(), run_context=ctx))
        self.assertEqual(r.status, COMPLETED)
        self.assertTrue(spy.methods)
        self.assertTrue(all(m == "GET" for m in spy.methods))


class ObjectiveAccessReadFixedControlTests(unittest.TestCase):
    def test_fixed_fixture_never_reports_completed(self):
        # The fixed variant enforces authorization (403); completion must
        # stay NOT_COMPLETED, never over-claim COMPLETED from a reflected
        # payload or the action send's own (403) body.
        fixture = _FakeAccessFixture(vulnerable=False)
        ctx = _ctx()
        with patch("httpx.AsyncClient.request", fixture):
            r = asyncio.run(attempt_completion(_access_task(), _access_finding(), _exchange(),
                                               _access_confirmed(), run_context=ctx))
        self.assertEqual(r.status, NOT_COMPLETED)

    def test_malformed_target_path_never_attempted(self):
        # allow_pattern rejection: a target_path outside the allow-listed
        # http(s)-URL shape is refused before anything is sent.
        bad_task = ObjectiveTask(profile=ACCESS_ADMIN_READ,
                                 target_path="javascript:alert(1)//admin/secret",
                                 oracle_url="http://t.test/admin/secret",
                                 oracle_marker=_FakeAccessFixture.MARKER)
        fixture = _FakeAccessFixture(vulnerable=True)
        ctx = _ctx()
        with patch("httpx.AsyncClient.request", fixture):
            r = asyncio.run(attempt_completion(bad_task, _access_finding(), _exchange(),
                                               _access_confirmed(), run_context=ctx))
        self.assertEqual(r.status, NOT_ATTEMPTED)
        self.assertEqual(fixture.calls, 0)


if __name__ == "__main__":
    unittest.main()
