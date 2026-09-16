"""
Mass-assignment vertical slice (internal id AV-MASSASSIGN-01) -- deterministic
regression over ACTUAL HTTP.

This is the reference regression the requirement-coverage manifest points at. It is a
LOCAL FIXTURE self-test plus two harness-leg checks -- explicitly NOT application-wide
or pipeline coverage. Each coverage-bearing test is a SEPARATE aspect with its own
evidence artifact and semantic label (fixture_invariant / harness_confirmation /
harness_control), so one passing artifact never stands in for the others (issue 5).

Aspects (each emits its own evidence via the runner, not the test body -- issue 2):

  1. fixture_invariant   -- the PATCHED fixture leaves server-controlled fields
                            (`role`, `is_admin`, `account_balance`, `id`) unchanged
                            under an ordinary update, verified by an INDEPENDENT
                            re-read of persisted state. (A vulnerable-mode control
                            proves the assertion discriminates.)
  2. harness_confirmation -- the REAL SequenceValidator confirms mass assignment on
                            the vulnerable fixture over the socket.
  3. harness_control      -- the REAL SequenceValidator returns a controlled negative
                            on the patched fixture.

Reproducible + hermetic: no model, loopback only, seeded fixture markers, bounded
timeouts, explicit assertions. The global throttle AND the safety gate are saved in
setUp and restored via addCleanup so a failure never leaks either into the suite
(issue 7).
"""
from __future__ import annotations

import asyncio
import unittest

import httpx

import harness.coverage_manifest as cm
from harness import global_throttle
from harness import safety_gate
from harness.coverage_evidence_case import EvidenceCase, evidence_for
from harness.models import Finding, HttpExchange
from harness.testing_fixtures.mass_assignment import (
    MassAssignmentFixture, PROTECTED_FIELDS, WRITABLE_FIELDS,
)
from harness.validators.sequence_validator import SequenceValidator

HOST = "127.0.0.1"
HTTP_TIMEOUT = 5.0        # bounded: loopback responds instantly
VALIDATE_TIMEOUT = 15.0   # hard ceiling on the whole validator coroutine

# An ordinary update that ALSO carries server-controlled fields a malicious client
# would try to smuggle in. A correct API applies only the writable field.
_ATTACK_BODY = {"username": "attacker", "role": "admin", "is_admin": True,
                "account_balance": 999999}
_INVARIANT = ("an ordinary update must leave server-controlled fields "
              "(role, is_admin, account_balance, id) unchanged")


class MassAssignmentSliceTest(EvidenceCase):
    def setUp(self):
        # Save the previous throttle config and restore it via cleanup (issue 7):
        # cleanups run even if the test fails, so we never leak `configure(0)`.
        st = global_throttle.throttle.stats()
        prev_rate = st["rate_per_second"] if st["enabled"] else 0.0
        prev_burst = st["burst"] if st["enabled"] else None
        self.addCleanup(lambda: global_throttle.configure(prev_rate, prev_burst))
        global_throttle.configure(0)

        # Same for the process-wide safety gate.
        self.addCleanup(safety_gate.reset_default_gate)
        safety_gate.reset_default_gate()
        safety_gate.get_default_gate({"active_enabled": True, "allow_mutating_replay": True})

    def _fixture(self, mode):
        fx = MassAssignmentFixture(mode)
        self.addCleanup(fx.close)
        return fx

    @staticmethod
    def _get(url):
        return httpx.get(url, timeout=HTTP_TIMEOUT)

    @staticmethod
    def _patch(url, body):
        return httpx.patch(url, json=body, timeout=HTTP_TIMEOUT)

    # --- aspect 1: the protected-field invariant (fixture self-test) -------

    @evidence_for(check_id=cm.MASS_ASSIGNMENT_CHECK_ID, aspect=cm.ASPECT_MASS_INVARIANT,
                  label="fixture_invariant", invariant=_INVARIANT)
    def test_patched_upholds_protected_field_invariant(self):
        fx = self._fixture("patched")
        url = fx.user_url("1")

        before = self._get(url).json()
        patch_resp = self._patch(url, _ATTACK_BODY)   # ordinary update + smuggled fields
        self.assertEqual(patch_resp.status_code, 200)
        after = self._get(url).json()                 # INDEPENDENT re-read of persisted state

        # Record the reproducible observation BEFORE asserting, so evidence carries it
        # even when nothing goes wrong (the status is stamped by the runner).
        self.record_observation({
            "protected_before": {k: before.get(k) for k in sorted(PROTECTED_FIELDS)},
            "protected_after": {k: after.get(k) for k in sorted(PROTECTED_FIELDS)},
            "writable_field": "username",
            "writable_before": before.get("username"),
            "writable_after": after.get("username"),
            "attack_body_keys": sorted(_ATTACK_BODY),
            "verified_by": "independent GET re-read of persisted state",
        })

        for f in sorted(PROTECTED_FIELDS):
            self.assertEqual(after.get(f), before.get(f),
                             f"protected field {f!r} changed under an ordinary update "
                             f"({before.get(f)!r} -> {after.get(f)!r}) -- mass assignment")
        # The legitimately-writable field DID change (not a blanket rejection).
        self.assertEqual(after.get("username"), "attacker")
        self.assertNotEqual(after.get("username"), before.get("username"))
        self.assertEqual(after.get("marker"), fx.marker("1"))  # anchors to THIS fixture

    def test_vulnerable_violates_invariant_control(self):
        # Control (not itself coverage): proves the invariant assertion discriminates.
        fx = self._fixture("vulnerable")
        url = fx.user_url("1")
        before = self._get(url).json()
        self.assertEqual(self._patch(url, _ATTACK_BODY).status_code, 200)
        after = self._get(url).json()
        self.assertEqual(after.get("role"), "admin")
        self.assertIs(after.get("is_admin"), True)
        self.assertNotEqual(after.get("role"), before.get("role"),
                            "control is inert: the vulnerable server did not actually "
                            "change a protected field, so the invariant test proves nothing")

    def test_patched_applies_writable_fields(self):
        fx = self._fixture("patched")
        url = fx.user_url("1")
        self.assertEqual(self._patch(url, {"username": "bob", "email": "bob@example.test"}).status_code, 200)
        after = self._get(url).json()
        self.assertEqual(after.get("username"), "bob")
        self.assertEqual(after.get("email"), "bob@example.test")
        self.assertEqual(WRITABLE_FIELDS, frozenset({"username", "email"}))

    # --- aspects 2 & 3: the REAL harness confirmation leg over the socket ---

    def _run_sequence_validator(self, fx):
        exchange = HttpExchange(
            url=fx.user_url("1"), method="PATCH",
            request_headers={"Content-Type": "application/json"},
            request_body='{"username": "alice"}',
            response_status=200, response_headers={}, response_body='{"username":"alice"}')
        finding = Finding(vulnerability_class="mass_assignment", confidence=0.5,
                          severity="high", summary="mass-assignment hypothesis",
                          evidence="", suggested_test="", basis="derived")
        v = SequenceValidator(allowed_hosts=[HOST], timeout=HTTP_TIMEOUT)

        async def scenario():
            return await asyncio.wait_for(v.validate(finding, exchange), VALIDATE_TIMEOUT)

        return asyncio.run(scenario())

    @evidence_for(check_id=cm.MASS_ASSIGNMENT_CHECK_ID, aspect=cm.ASPECT_MASS_CONFIRM,
                  label="harness_confirmation")
    def test_harness_sequence_validator_confirms_vulnerable(self):
        fx = self._fixture("vulnerable")
        res = self._run_sequence_validator(fx)
        after = self._get(fx.user_url("1")).json()
        self.record_observation({"validator": res.validator, "status": res.status,
                                 "confirmed": res.confirmed, "is_admin_after": after.get("is_admin")})
        self.assertEqual(res.status, "confirmed")
        self.assertTrue(res.confirmed)
        self.assertEqual(after.get("is_admin"), True)  # a privileged field persisted

    @evidence_for(check_id=cm.MASS_ASSIGNMENT_CHECK_ID, aspect=cm.ASPECT_MASS_CONTROL,
                  label="harness_control")
    def test_harness_sequence_validator_controlled_negative_on_patched(self):
        fx = self._fixture("patched")
        res = self._run_sequence_validator(fx)
        after = self._get(fx.user_url("1")).json()
        self.record_observation({"validator": res.validator, "status": res.status,
                                 "confirmed": res.confirmed, "role_after": after.get("role"),
                                 "is_admin_after": after.get("is_admin")})
        self.assertEqual(res.status, "not_confirmed")
        self.assertFalse(res.confirmed)
        self.assertEqual(after.get("role"), "user")
        self.assertIs(after.get("is_admin"), False)

    # --- reproducibility + isolation (plain hygiene tests) -----------------

    def test_seeded_markers_are_reproducible(self):
        a = MassAssignmentFixture("patched", seed=42)
        self.addCleanup(a.close)
        b = MassAssignmentFixture("patched", seed=42)
        self.addCleanup(b.close)
        self.assertEqual(a.marker("1"), b.marker("1"))
        c = MassAssignmentFixture("patched", seed=43)
        self.addCleanup(c.close)
        self.assertNotEqual(a.marker("1"), c.marker("1"))

    def test_state_resets_between_instances(self):
        fx1 = self._fixture("vulnerable")
        self._patch(fx1.user_url("1"), {"role": "admin"})
        self.assertEqual(self._get(fx1.user_url("1")).json().get("role"), "admin")
        fx2 = MassAssignmentFixture("vulnerable", seed=1729)
        self.addCleanup(fx2.close)
        self.assertEqual(self._get(fx2.user_url("1")).json().get("role"), "user")


if __name__ == "__main__":
    unittest.main()
