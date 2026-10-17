"""W-12: cross-identity confirmation is auto-armed for applicable object-scoped
requests WITHIN an active, scoped engagement that has registered identities --
and only then. Applicability is automatic; authorization to send stays explicit
(active_enabled AND identities for the host)."""
import asyncio
import unittest

from harness import identity_headers
from harness.validators.registry import ValidatorRegistry
from harness.models import Finding, HttpExchange


def _reg(active=True):
    return ValidatorRegistry({
        "validators": {"active_enabled": active, "cross_identity": {"enabled": False}},
        "server": {"allowed_hosts": ["shop.test"]},
    })


def _idor():
    return Finding(vulnerability_class="idor", confidence=0.6, summary="maybe idor",
                   evidence="e", suggested_test="t", basis="derived")


def _obj_get(url="https://shop.test/api/orders/1"):
    return HttpExchange(url=url, method="GET")


class CrossIdentityAutoArmTests(unittest.TestCase):
    def setUp(self):
        identity_headers.clear()

    def tearDown(self):
        identity_headers.clear()

    def _names(self, reg, finding, exchange):
        return {getattr(v, "name", "") for v in reg.for_finding(finding, exchange)}

    def test_auto_armed_when_active_with_identities(self):
        reg = _reg(active=True)
        identity_headers.set_identity("shop.test", "alice", {"Cookie": "s=a"}, "user")
        identity_headers.set_identity("shop.test", "bob", {"Cookie": "s=b"}, "user")
        self.assertIn("cross_identity", self._names(reg, _idor(), _obj_get()))
        # Armed for THIS dispatch only -- the explicit toggle/registration is untouched.
        self.assertFalse(reg.cross_identity_enabled())

    def test_not_armed_without_identities(self):
        reg = _reg(active=True)
        self.assertNotIn("cross_identity", self._names(reg, _idor(), _obj_get()))

    def test_not_armed_when_passive(self):
        reg = _reg(active=False)
        identity_headers.set_identity("shop.test", "alice", {"Cookie": "s=a"}, "user")
        self.assertNotIn("cross_identity", self._names(reg, _idor(), _obj_get()))

    def test_not_armed_for_non_access_control_finding(self):
        reg = _reg(active=True)
        identity_headers.set_identity("shop.test", "alice", {"Cookie": "s=a"}, "user")
        xss = Finding(vulnerability_class="xss", confidence=0.6, summary="s",
                      evidence="e", suggested_test="t", basis="derived")
        self.assertNotIn("cross_identity", self._names(reg, xss, _obj_get()))

    def test_explicit_registration_is_not_duplicated(self):
        reg = _reg(active=True)
        reg.set_cross_identity_enabled(True)
        identity_headers.set_identity("shop.test", "alice", {"Cookie": "s=a"}, "user")
        xids = [v for v in reg.for_finding(_idor(), _obj_get())
                if getattr(v, "name", "") == "cross_identity"]
        self.assertEqual(len(xids), 1)


class SeedIdentitiesFromStoreTests(unittest.TestCase):
    """The standalone /analyze path must seed its fresh RunContext's empty
    SessionManager from the identity_headers store, or a run-context-bound
    cross_identity validator enumerates run_context.sessions (empty) and reports
    'no identities configured' even though identities were registered -- the
    reproduced crAPI miss in REPORT_2026-10-15_decisive_reproducibility.md."""

    def setUp(self):
        identity_headers.clear()

    def tearDown(self):
        identity_headers.clear()

    def _stub(self, active=True):
        from harness.orchestrator_detect import DetectMixin
        stub = DetectMixin.__new__(DetectMixin)
        stub.validator_registry = _reg(active=active)
        stub.config = {"validators": {"active_enabled": active}}
        stub.allowed_hosts = ["shop.test"]
        return stub

    def _ctx(self):
        from harness.run_context import RunContext
        return RunContext.create(allowed_hosts=["shop.test"])

    def _ex(self):
        return HttpExchange(url="https://shop.test/api/orders/1", method="GET")

    def test_seeds_identities_and_anonymous_in_active_mode(self):
        identity_headers.set_identity("shop.test", "alice", {"Authorization": "Bearer a"}, "user")
        identity_headers.set_identity("shop.test", "bob", {"Authorization": "Bearer b"}, "user")
        stub, ctx = self._stub(active=True), self._ctx()
        try:
            stub._seed_identities_from_store(ctx, self._ex())
            self.assertEqual({s.principal_id for s in ctx.sessions.all()},
                             {"alice", "bob", "anonymous"})
            # The run-context-bound validator now enumerates the identities
            # (anonymous excluded from idents) and has its required deny baseline.
            from harness.validators.cross_identity_validator import CrossIdentityValidator
            v = CrossIdentityValidator(allowed_hosts=["shop.test"], run_context=ctx)
            self.assertEqual({i["name"] for i in v._run_identities("shop.test")},
                             {"alice", "bob"})
            self.assertIsNotNone(v._anonymous_session_ref())
        finally:
            asyncio.run(ctx.aclose())

    def test_no_seed_when_passive(self):
        identity_headers.set_identity("shop.test", "alice", {"Authorization": "Bearer a"}, "user")
        stub, ctx = self._stub(active=False), self._ctx()
        try:
            stub._seed_identities_from_store(ctx, self._ex())
            self.assertEqual(ctx.sessions.all(), [])
        finally:
            asyncio.run(ctx.aclose())

    def test_no_seed_without_identities(self):
        stub, ctx = self._stub(active=True), self._ctx()
        try:
            stub._seed_identities_from_store(ctx, self._ex())
            self.assertEqual(ctx.sessions.all(), [])  # no lone anonymous session either
        finally:
            asyncio.run(ctx.aclose())


class PerRunGatePolicyTests(unittest.TestCase):
    """The other half of the /analyze RunContext-inheritance fix: the per-run
    gate must carry the operator's active/mutating POLICY. Without it the gate
    defaults both flags to False and BLOCKS a mutating replay (sqlmap on a POST)
    that the process-global gate allows -- the reproduced "blocked:
    active_enabled off" on a POST SQL-injection in a run configured active=true.
    per_run_gate_config builds the gate_config; these assert the resulting gate
    authorizes a state-changing request when active+replay are on and refuses it
    when they are off."""

    def _gate(self, validators_cfg, registry=None):
        from harness.orchestrator_helpers import per_run_gate_config
        from harness.run_context import RunContext
        ctx = RunContext.create(
            allowed_hosts=["shop.test"],
            gate_config=per_run_gate_config({"validators": validators_cfg}, registry))
        self.addCleanup(lambda: asyncio.run(ctx.aclose()))
        return ctx.gate

    def _authorize_post(self, gate):
        return gate.authorize(validator_name="sqlmap", method="POST",
                              url="https://shop.test/api/orders", body="q=1")

    def test_mutating_allowed_when_active_and_replay_on(self):
        gate = self._gate({"active_enabled": True, "allow_mutating_replay": True})
        self.assertTrue(self._authorize_post(gate).allowed)

    def test_mutating_refused_when_both_off(self):
        gate = self._gate({"active_enabled": False, "allow_mutating_replay": False})
        self.assertFalse(self._authorize_post(gate).allowed)

    def test_mutating_refused_when_active_on_but_replay_off(self):
        # allow_mutating_replay is the stricter, separate opt-in: active alone
        # must not authorize a mutating replay.
        gate = self._gate({"active_enabled": True, "allow_mutating_replay": False})
        self.assertFalse(self._authorize_post(gate).allowed)

    def test_active_enabled_reflects_live_registry_toggle(self):
        # active armed at runtime via the registry (not written back to config)
        # must still reach the per-run gate.
        gate = self._gate({"allow_mutating_replay": True}, registry=_reg(active=True))
        self.assertTrue(self._authorize_post(gate).allowed)


if __name__ == "__main__":
    unittest.main()
