"""
WSTG-CONF-09 mass-assignment vertical slice -- deterministic regression over ACTUAL HTTP.

This is the reference regression the requirement-coverage manifest points at
(coverage_manifest.REQUIREMENT_TESTS). It proves ONE aspect of the requirement:

    THE PROTECTED-FIELD INVARIANT: an ordinary update must leave server-controlled
    fields (`role`, `is_admin`, `account_balance`, `id`) UNCHANGED -- verified by an
    INDEPENDENT re-read of persisted state, not the write's own echo.

It runs against a local, isolated `MassAssignmentFixture` (vulnerable/patched), and:

  1. asserts the invariant holds on the PATCHED server even when the update tries to
     set protected fields, verifying persisted state via a fresh GET;
  2. NEGATIVE CONTROL: the SAME update on the VULNERABLE server violates the invariant
     -- proving the assertion discriminates (not a plumbing tautology);
  3. drives the REAL harness `SequenceValidator` (write->re-read differential) over the
     socket: CONFIRMED on vulnerable, controlled-negative on patched;
  4. emits a deterministic evidence artifact the coverage manifest reconciles.

Reproducible + hermetic: no model, no network beyond loopback, no clock/randomness in
assertions (seeded fixture markers), bounded timeouts, explicit assertions only. State
resets per fixture instance. The safety gate + throttle are configured per test and
reset in tearDown so nothing leaks into the rest of the suite.
"""
from __future__ import annotations

import asyncio
import unittest

import httpx

import coverage_manifest
import global_throttle
import safety_gate
from coverage_manifest import TestStatus
from models import Finding, HttpExchange
from testing_fixtures.mass_assignment import (
    MassAssignmentFixture, PROTECTED_FIELDS, WRITABLE_FIELDS,
)
from validators.sequence_validator import SequenceValidator

HOST = "127.0.0.1"
HTTP_TIMEOUT = 5.0        # bounded: loopback responds instantly
VALIDATE_TIMEOUT = 15.0   # hard ceiling on the whole validator coroutine

# An ordinary update that ALSO carries server-controlled fields a malicious client
# would try to smuggle in. A correct API applies only the writable field.
_ATTACK_BODY = {"username": "attacker", "role": "admin", "is_admin": True,
                "account_balance": 999999}

_TEST_ID = ("test_mass_assignment_slice.MassAssignmentSliceTest."
            "test_patched_upholds_protected_field_invariant")
_INVARIANT = ("an ordinary update must leave server-controlled fields "
              "(role, is_admin, account_balance, id) unchanged")


class MassAssignmentSliceTest(unittest.TestCase):
    def setUp(self):
        global_throttle.configure(0)
        safety_gate.reset_default_gate()
        # Mutating replay is opt-in (the stricter flag) -- the SequenceValidator's
        # write step needs it; the invariant assertions use only GET/PATCH via httpx.
        safety_gate.get_default_gate({"active_enabled": True, "allow_mutating_replay": True})

    def tearDown(self):
        safety_gate.reset_default_gate()

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

    # --- 1. the protected-field invariant (the PASS regression) ------------

    def test_patched_upholds_protected_field_invariant(self):
        fx = self._fixture("patched")
        url = fx.user_url("1")

        before = self._get(url).json()
        # Ordinary update that also tries to set protected fields.
        patch_resp = self._patch(url, _ATTACK_BODY)
        self.assertEqual(patch_resp.status_code, 200)
        # INDEPENDENT re-read of persisted state -- not the write's echo.
        after = self._get(url).json()

        # Invariant: every server-controlled field is UNCHANGED.
        for f in sorted(PROTECTED_FIELDS):
            self.assertEqual(after.get(f), before.get(f),
                             f"protected field {f!r} changed under an ordinary update "
                             f"({before.get(f)!r} -> {after.get(f)!r}) -- mass assignment")
        # And the legitimately-writable field DID change, proving the update was
        # processed (the server is not just rejecting the request wholesale).
        self.assertEqual(after.get("username"), "attacker")
        self.assertNotEqual(after.get("username"), before.get("username"))
        # The per-instance marker anchors this to THIS fixture (no accidental oracle).
        self.assertEqual(after.get("marker"), fx.marker("1"))

        # Emit the deterministic evidence artifact the coverage manifest reconciles.
        observed = {
            "protected_before": {k: before.get(k) for k in sorted(PROTECTED_FIELDS)},
            "protected_after": {k: after.get(k) for k in sorted(PROTECTED_FIELDS)},
            "writable_field": "username",
            "writable_before": before.get("username"),
            "writable_after": after.get("username"),
            "attack_body_keys": sorted(_ATTACK_BODY),
            "verified_by": "independent GET re-read of persisted state",
        }
        path = coverage_manifest.write_evidence(
            check_id="WSTG-CONF-09", test_id=_TEST_ID,
            aspect=coverage_manifest.REQUIREMENT_TESTS[0].aspect,
            status=TestStatus.PASS, invariant=_INVARIANT,
            reason="patched server left all server-controlled fields unchanged after an "
                   "ordinary update carrying privileged fields; verified by re-read",
            observed=observed)
        self.assertTrue(path.exists())
        # The written artifact must reconcile to passing partial coverage.
        loaded = coverage_manifest.load_evidence(coverage_manifest.EVIDENCE_DIR)
        rec = loaded.get(("WSTG-CONF-09", coverage_manifest.REQUIREMENT_TESTS[0].aspect))
        self.assertIsNotNone(rec, "evidence artifact was not written where the manifest reads it")
        self.assertEqual(rec.status, TestStatus.PASS)

    # --- 2. negative control: the invariant is violated when vulnerable ----

    def test_vulnerable_violates_invariant_control(self):
        fx = self._fixture("vulnerable")
        url = fx.user_url("1")
        before = self._get(url).json()
        self.assertEqual(self._patch(url, _ATTACK_BODY).status_code, 200)
        after = self._get(url).json()
        # The vulnerable server DID accept the privileged fields and PERSISTED them.
        self.assertEqual(after.get("role"), "admin")
        self.assertIs(after.get("is_admin"), True)
        self.assertNotEqual(after.get("role"), before.get("role"),
                            "control is inert: the vulnerable server did not actually "
                            "change a protected field, so the invariant test proves nothing")

    # --- 3. an ordinary update still applies the writable fields -----------

    def test_patched_applies_writable_fields(self):
        fx = self._fixture("patched")
        url = fx.user_url("1")
        self.assertEqual(self._patch(url, {"username": "bob", "email": "bob@example.test"}).status_code, 200)
        after = self._get(url).json()
        self.assertEqual(after.get("username"), "bob")
        self.assertEqual(after.get("email"), "bob@example.test")
        self.assertEqual(WRITABLE_FIELDS, frozenset({"username", "email"}))  # documents the whitelist

    # --- 4. the REAL harness confirmation leg over the socket --------------

    def _run_sequence_validator(self, fx):
        # A captured ordinary write; the SequenceValidator augments it with privileged
        # fields and confirms via an independent re-read differential.
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

    def test_harness_sequence_validator_confirms_vulnerable(self):
        fx = self._fixture("vulnerable")
        res = self._run_sequence_validator(fx)
        self.assertEqual(res.status, "confirmed")
        self.assertTrue(res.confirmed)
        # A privileged field actually persisted, proven by the independent re-read.
        self.assertEqual(self._get(fx.user_url("1")).json().get("is_admin"), True)

    def test_harness_sequence_validator_controlled_negative_on_patched(self):
        fx = self._fixture("patched")
        res = self._run_sequence_validator(fx)
        self.assertEqual(res.status, "not_confirmed")
        self.assertFalse(res.confirmed)
        # The controlled negative is real: the write ran but nothing escalated.
        after = self._get(fx.user_url("1")).json()
        self.assertEqual(after.get("role"), "user")
        self.assertIs(after.get("is_admin"), False)

    # --- 5. reproducibility + isolation ------------------------------------

    def test_seeded_markers_are_reproducible(self):
        a = MassAssignmentFixture("patched", seed=42)
        self.addCleanup(a.close)
        b = MassAssignmentFixture("patched", seed=42)
        self.addCleanup(b.close)
        self.assertEqual(a.marker("1"), b.marker("1"))  # same seed -> same marker
        c = MassAssignmentFixture("patched", seed=43)
        self.addCleanup(c.close)
        self.assertNotEqual(a.marker("1"), c.marker("1"))  # different seed -> different marker

    def test_state_resets_between_instances(self):
        fx1 = self._fixture("vulnerable")
        self._patch(fx1.user_url("1"), {"role": "admin"})
        self.assertEqual(self._get(fx1.user_url("1")).json().get("role"), "admin")
        # A fresh instance starts from the seeded baseline -- no state bleed.
        fx2 = MassAssignmentFixture("vulnerable", seed=1729)
        self.addCleanup(fx2.close)
        self.assertEqual(self._get(fx2.user_url("1")).json().get("role"), "user")


if __name__ == "__main__":
    unittest.main()
