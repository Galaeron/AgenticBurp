"""FR-6 (F10) tests: `_credential_grants_access` must require a differential
between the credentialed response and BOTH an anonymous and an invalid-token
control on the same URL, not just a single <400 response.

Fully offline: `harness.orchestrator_chain.transport_for` is monkeypatched to
return a fake, in-memory TargetTransport whose `send`/`send_creds` are async
and return canned `ExecutionOutcome`s -- no real network/model. `global_throttle`
is configured to 0 (unlimited/no-op) so `acquire()` never blocks.
"""
import asyncio
import unittest
from unittest.mock import patch

from harness import global_throttle
from harness import orchestrator_chain as oc
from harness.run_context import ExecutionOutcome


class _FakeTransport:
    """Canned-response stand-in for TargetTransport. `send` always answers the
    "anonymous" probe; `send_creds` answers "credentialed" unless the forwarded
    headers carry the FR-6 invalid-token sentinel, in which case it answers
    "invalid". Call counts let a test prove the early-exit path never spends
    the two control probes."""

    def __init__(self, *, cred, anon, invalid=None, anon_exc=None, invalid_exc=None):
        self._cred = cred
        self._anon = anon
        self._invalid = invalid
        self._anon_exc = anon_exc
        self._invalid_exc = invalid_exc
        self.cred_calls = 0
        self.anon_calls = 0
        self.invalid_calls = 0

    async def send(self, method, url, *, capability, max_redirects=0, **kw):
        self.anon_calls += 1
        if self._anon_exc is not None:
            raise self._anon_exc
        return self._anon

    async def send_creds(self, method, url, *, capability, headers=None, max_redirects=0, **kw):
        headers = headers or {}
        is_invalid = any(str(v).endswith(oc._FR6_INVALID_SENTINEL) for v in headers.values())
        if is_invalid:
            self.invalid_calls += 1
            if self._invalid_exc is not None:
                raise self._invalid_exc
            return self._invalid
        self.cred_calls += 1
        return self._cred


class _DummyOrch(oc.ChainMixin):
    """Minimal stand-in for Orchestrator: just enough state for ChainMixin's
    `_credential_grants_access` (allowed_hosts + config), so the caller test
    drives the REAL method, not a mock of it."""

    def __init__(self, allowed_hosts=("shop.test",)):
        self.allowed_hosts = list(allowed_hosts)
        self.config = {}


def _run_grant(fake_transport, *, url="http://shop.test/secret", headers=None, allowed_hosts=("shop.test",)):
    orch = _DummyOrch(allowed_hosts=allowed_hosts)
    if headers is None:
        headers = {"Authorization": "Bearer learned"}
    with patch("harness.orchestrator_chain.transport_for", return_value=(fake_transport, None)):
        return asyncio.run(orch._credential_grants_access(url, headers))


class CredentialGrantDifferentialTests(unittest.TestCase):
    def setUp(self):
        global_throttle.configure(0)

    # ---- caller tests: drive _credential_grants_access end to end ---------

    def test_public_resource_returns_no_grant(self):
        """CALLER TEST: a resource that answers the same for everyone (a public
        200) must NOT count as a credential grant, even though the old
        single-probe check (`out.ok and out.status < 400`) would have called
        this a grant."""
        ft = _FakeTransport(
            cred=ExecutionOutcome(outcome="ok", status=200, body="public page"),
            anon=ExecutionOutcome(outcome="ok", status=200, body="public page"),
            invalid=ExecutionOutcome(outcome="ok", status=200, body="public page"),
        )
        self.assertFalse(_run_grant(ft))
        self.assertEqual((ft.cred_calls, ft.anon_calls, ft.invalid_calls), (1, 1, 1))

    def test_credentialed_matches_both_controls_returns_no_grant(self):
        """CALLER TEST: the credentialed response is <400, but it is identical
        (status + body) to BOTH controls -- the token made no observable
        difference, so this is still not a grant. Distinct from the early-exit
        case: both controls actually ran here."""
        ft = _FakeTransport(
            cred=ExecutionOutcome(outcome="ok", status=200, body="shared dashboard"),
            anon=ExecutionOutcome(outcome="ok", status=200, body="shared dashboard"),
            invalid=ExecutionOutcome(outcome="ok", status=200, body="shared dashboard"),
        )
        self.assertFalse(_run_grant(ft))
        self.assertEqual(ft.anon_calls, 1)
        self.assertEqual(ft.invalid_calls, 1)

    def test_early_exit_error_status_returns_no_grant_without_controls(self):
        """CALLER TEST (early-exit): a credentialed response that is itself an
        error (>=400, here 403) means no access at all -- return False WITHOUT
        spending the two control probes."""
        ft = _FakeTransport(
            cred=ExecutionOutcome(outcome="ok", status=403, body="Forbidden"),
            anon=ExecutionOutcome(outcome="ok", status=403, body="Forbidden"),
            invalid=ExecutionOutcome(outcome="ok", status=403, body="Forbidden"),
        )
        self.assertFalse(_run_grant(ft))
        self.assertEqual(ft.anon_calls, 0)
        self.assertEqual(ft.invalid_calls, 0)

    def test_early_exit_server_error_status_returns_no_grant(self):
        """CALLER TEST (early-exit): same as above for a 500."""
        ft = _FakeTransport(
            cred=ExecutionOutcome(outcome="ok", status=500, body="Internal Server Error"),
            anon=ExecutionOutcome(outcome="ok", status=200, body="whatever"),
            invalid=ExecutionOutcome(outcome="ok", status=200, body="whatever"),
        )
        self.assertFalse(_run_grant(ft))
        self.assertEqual(ft.anon_calls, 0)
        self.assertEqual(ft.invalid_calls, 0)

    def test_genuine_grant_distinguishable_from_both_controls(self):
        """NEGATIVE CONTROL: anonymous and invalid-token are both denied (401),
        but the real credential returns a distinct, successful body -- a
        genuine grant, and the fix must still recognise it as one (this is
        what proves the fix isn't simply "never grant")."""
        ft = _FakeTransport(
            cred=ExecutionOutcome(outcome="ok", status=200, body="account #4471 balance: $500"),
            anon=ExecutionOutcome(outcome="ok", status=401, body="denied"),
            invalid=ExecutionOutcome(outcome="ok", status=401, body="denied"),
        )
        self.assertTrue(_run_grant(ft))

    def test_genuine_grant_same_status_different_body_still_counts(self):
        """NEGATIVE CONTROL variant: even when the anonymous/invalid probes
        happen to share the credentialed response's status code, a distinct
        body is still a real, observable difference and must count."""
        ft = _FakeTransport(
            cred=ExecutionOutcome(outcome="ok", status=200, body="your private inbox: 3 messages"),
            anon=ExecutionOutcome(outcome="ok", status=200, body="please log in"),
            invalid=ExecutionOutcome(outcome="ok", status=200, body="please log in"),
        )
        self.assertTrue(_run_grant(ft))

    def test_control_probe_exception_fails_closed(self):
        """Conservative failure: if a control probe raises, we cannot establish
        a differential, so the method must fail closed (no grant) -- never the
        false grant F10 is about."""
        ft = _FakeTransport(
            cred=ExecutionOutcome(outcome="ok", status=200, body="secret"),
            anon=ExecutionOutcome(outcome="ok", status=401, body="denied"),
            anon_exc=RuntimeError("network blip"),
            invalid=ExecutionOutcome(outcome="ok", status=401, body="denied"),
        )
        self.assertFalse(_run_grant(ft))

    def test_control_probe_incomplete_fails_closed(self):
        """Conservative failure: a control probe that returns but never
        actually completed (e.g. it was itself scope/gate/budget-denied, so
        outcome != 'ok') is not usable evidence -- fail closed."""
        ft = _FakeTransport(
            cred=ExecutionOutcome(outcome="ok", status=200, body="secret"),
            anon=ExecutionOutcome(outcome="blocked", status=None, body=""),
            invalid=ExecutionOutcome(outcome="ok", status=401, body="denied"),
        )
        self.assertFalse(_run_grant(ft))

    def test_out_of_scope_url_returns_false_without_transport(self):
        """Pre-existing guard preserved: an out-of-scope URL is rejected before
        a transport is even built (the fake transport is never actually used)."""
        ft = _FakeTransport(cred=None, anon=None, invalid=None)
        result = _run_grant(ft, url="http://other.test/x", allowed_hosts=("shop.test",))
        self.assertFalse(result)
        self.assertEqual((ft.cred_calls, ft.anon_calls, ft.invalid_calls), (0, 0, 0))

    def test_no_headers_returns_false(self):
        """Pre-existing guard preserved: no credential headers -> no probe at all."""
        ft = _FakeTransport(cred=None, anon=None, invalid=None)
        result = _run_grant(ft, headers={})
        self.assertFalse(result)
        self.assertEqual((ft.cred_calls, ft.anon_calls, ft.invalid_calls), (0, 0, 0))

    # ---- helper unit tests: _invalidated_headers ---------------------------

    def test_invalidated_headers_corrupts_authorization(self):
        out = oc._invalidated_headers({"Authorization": "Bearer real", "X-Trace": "abc"})
        self.assertNotEqual(out["Authorization"], "Bearer real")
        self.assertTrue(out["Authorization"].startswith("Bearer real"))
        self.assertEqual(out["X-Trace"], "abc")  # non-credential header left alone
        self.assertEqual(set(out.keys()), {"Authorization", "X-Trace"})  # names preserved

    def test_invalidated_headers_corrupts_cookie(self):
        out = oc._invalidated_headers({"Cookie": "session=abc123"})
        self.assertNotEqual(out["Cookie"], "session=abc123")
        self.assertTrue(out["Cookie"].startswith("session=abc123"))

    def test_invalidated_headers_corrupts_custom_header_when_no_known_credential_header(self):
        """When none of the supplied headers are recognised credential headers
        (e.g. a bespoke X-Api-Key scheme), every header's value is corrupted
        instead, so the invalid-token control is always genuinely invalid."""
        out = oc._invalidated_headers({"X-Api-Key": "abc123"})
        self.assertNotEqual(out["X-Api-Key"], "abc123")
        self.assertTrue(out["X-Api-Key"].startswith("abc123"))
        self.assertEqual(list(out.keys()), ["X-Api-Key"])  # name preserved

    def test_invalidated_headers_does_not_mutate_input(self):
        original = {"Authorization": "Bearer real"}
        oc._invalidated_headers(original)
        self.assertEqual(original, {"Authorization": "Bearer real"})

    # ---- helper unit tests: _responses_equivalent --------------------------

    def test_responses_equivalent_same_status_and_body(self):
        a = ExecutionOutcome(outcome="ok", status=200, body="x")
        b = ExecutionOutcome(outcome="ok", status=200, body="x")
        self.assertTrue(oc._responses_equivalent(a, b))

    def test_responses_equivalent_different_body_not_equivalent(self):
        a = ExecutionOutcome(outcome="ok", status=200, body="x")
        b = ExecutionOutcome(outcome="ok", status=200, body="y")
        self.assertFalse(oc._responses_equivalent(a, b))

    def test_responses_equivalent_different_status_not_equivalent(self):
        a = ExecutionOutcome(outcome="ok", status=200, body="x")
        b = ExecutionOutcome(outcome="ok", status=401, body="x")
        self.assertFalse(oc._responses_equivalent(a, b))


if __name__ == "__main__":
    unittest.main()
