"""
Off-scope host-lock audit (safety item #12).

Explicit, enumerated proof that no ACTIVE validator sends an HTTP request to a host
outside the engagement scope -- including one it might reach by following an
off-scope link. Patches httpx at the transport so ANY off-scope send raises a
distinctive error that the validators do NOT catch (they catch httpx.HTTPError /
SafetyGateBlocked, not this AssertionError), so a validator that sends off-scope
fails this test by name instead of silently probing a third party.

Also covers the shared scope_lock helper and the safety gate's central OUT_OF_SCOPE
refusal (the defense-in-depth layer that catches a validator which forgets its own
check, or an off-scope redirect).
"""
from __future__ import annotations

import asyncio
import unittest
from unittest import mock

import httpx

from harness.models import Finding, HttpExchange
from harness import scope_lock
from harness.safety_gate import (SafetyGate, SafetyGateConfig, ActionRiskTier,
                                 GatedAsyncClient, SafetyGateBlocked, gate_scope)
from harness.validators.registry import ValidatorRegistry

IN_SCOPE = "127.0.0.1"
OFF_SCOPE = "evil.example.com"


class _OffScopeSendAttempted(BaseException):
    """Raised if any validator actually sends to the off-scope host. Inherits
    BaseException (not Exception) so a validator's broad `except Exception:` cannot
    swallow it -- an off-scope send must surface as a test failure, not be masked."""


def _config():
    return {
        "server": {"allowed_hosts": [IN_SCOPE]},
        "validators": {"enabled": True, "active_enabled": True,
                       "allow_mutating_replay": True, "max_burst_size": 5,
                       "max_mutating_requests_per_finding": 5,
                       # sqlmap: no container so the (guarded) path is deterministic.
                       "sqlmap": {"container_image": None}},
    }


def _offscope_exchange():
    # Rich enough that many validators' applies() passes: URL-shaped query param,
    # numeric id, JSON body with a role field, a JWT-ish auth header, XML-ish body.
    return HttpExchange(
        url=f"http://{OFF_SCOPE}/api/fetch?url=http://internal/&id=1&next=http://x",
        method="GET",
        request_headers={"Authorization": "Bearer a.b.c", "Content-Type": "application/json"},
        request_body='{"role": "user", "xml": "<a>b</a>"}',
        response_status=200,
        response_headers={"Content-Type": "text/html"},
        response_body="<html>ok</html>",
    )


class TestScopeLockHelper(unittest.TestCase):
    def test_unset_scope_allows_all(self):
        self.assertTrue(scope_lock.host_in_scope("http://anything/", []))
        self.assertTrue(scope_lock.host_in_scope("http://anything/", None))

    def test_configured_scope_fails_closed(self):
        self.assertTrue(scope_lock.host_in_scope("http://127.0.0.1/x", ["127.0.0.1"]))
        self.assertFalse(scope_lock.host_in_scope("http://evil.example.com/x", ["127.0.0.1"]))

    def test_unparseable_host_denied_under_scope(self):
        self.assertFalse(scope_lock.host_in_scope("not a url", ["127.0.0.1"]))

    def test_case_insensitive(self):
        self.assertTrue(scope_lock.host_in_scope("http://EVIL.com/x", ["evil.com"]))


class TestGateScopeLock(unittest.TestCase):
    def test_gate_refuses_offscope_even_for_safe_get(self):
        gate = SafetyGate(SafetyGateConfig(allowed_hosts=frozenset({"127.0.0.1"})))
        d = gate.authorize(validator_name="t", method="GET", url="http://evil.example.com/x")
        self.assertFalse(d.allowed)
        self.assertEqual(d.tier, ActionRiskTier.OUT_OF_SCOPE)

    def test_gate_allows_inscope(self):
        gate = SafetyGate(SafetyGateConfig(allowed_hosts=frozenset({"127.0.0.1"})))
        d = gate.authorize(validator_name="t", method="GET", url="http://127.0.0.1/x")
        self.assertTrue(d.allowed)

    def test_empty_scope_unrestricted(self):
        gate = SafetyGate(SafetyGateConfig())  # no allowed_hosts configured
        d = gate.authorize(validator_name="t", method="GET", url="http://anywhere/x")
        self.assertTrue(d.allowed)

    def test_gated_client_blocks_offscope_send(self):
        gate = SafetyGate(SafetyGateConfig(allowed_hosts=frozenset({"127.0.0.1"})))

        async def go():
            with gate_scope(gate):
                async with GatedAsyncClient(gate, "t") as c:
                    with self.assertRaises(SafetyGateBlocked):
                        await c.request("GET", "http://evil.example.com/x")
        asyncio.run(go())


class TestSqlmapScopeRegression(unittest.TestCase):
    """The known gap this item fixed: sqlmap had no scope check at all."""
    def test_sqlmap_skips_offscope(self):
        from harness.validators.sqlmap import SqlmapValidator
        v = SqlmapValidator(allowed_hosts=[IN_SCOPE])
        f = Finding(vulnerability_class="sqli", confidence=0.9, summary="s",
                    evidence="e", suggested_test="t", basis="derived")
        ex = HttpExchange(url=f"http://{OFF_SCOPE}/i?id=1", method="GET")
        res = asyncio.run(v.validate(f, ex))
        self.assertEqual(res.status, "skipped")
        self.assertIn("out of scope", res.summary)


class TestActiveValidatorAudit(unittest.TestCase):
    """Every active validator, run against an off-scope exchange, must not send."""

    def _patched_transport(self):
        # Any real network send raises the sentinel; validators don't catch it.
        def _raise(*a, **k):
            raise _OffScopeSendAttempted("a validator attempted an off-scope HTTP send")
        return _raise

    def test_no_active_validator_sends_offscope(self):
        registry = ValidatorRegistry(_config())
        gate = registry_default_gate()
        exchange = _offscope_exchange()
        active = [(n, v) for n, v in registry.validators.items() if getattr(v, "active", False)]
        self.assertTrue(active, "expected active validators to be registered")

        import socket
        raise_send = self._patched_transport()
        failures = []
        with mock.patch.object(httpx.AsyncClient, "send", raise_send), \
             mock.patch.object(httpx.AsyncClient, "request", raise_send), \
             mock.patch.object(socket, "create_connection", raise_send), \
             gate_scope(gate):
            for name, validator in active:
                fc = sorted(validator.finding_classes)[0] if validator.finding_classes else "sqli"
                finding = Finding(vulnerability_class=fc, confidence=0.9, summary="s",
                                  evidence="e", suggested_test="t", basis="derived")
                try:
                    asyncio.run(validator.validate(finding, exchange))
                except _OffScopeSendAttempted:
                    failures.append(f"{name}: attempted an off-scope HTTP send")
                except Exception:
                    # Any other error is not an off-scope send; the send patch is
                    # what this audit asserts. Passively confirming from the
                    # already-captured exchange (no send) is legitimate and not a
                    # violation. (Missing browser/docker etc. just skip.)
                    continue
        self.assertEqual(failures, [], "off-scope host-lock violations:\n" + "\n".join(failures))


def registry_default_gate():
    # The gate the registry seeded (with server.allowed_hosts folded in).
    from harness.safety_gate import get_default_gate
    return get_default_gate()


if __name__ == "__main__":
    unittest.main()
