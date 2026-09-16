"""
Open-redirect vertical slice (WSTG-INPV-17) -- deterministic regression over ACTUAL HTTP.

The second automated slice behind the requirement-coverage manifest, using a DIFFERENT
validator (OpenRedirectValidator) and a different fixture -- so coverage is not just the
one hand-built mass-assignment fixture. Each aspect is a separate labelled artifact:

  1. fixture_invariant   -- the PATCHED /login neutralises an off-origin `next` and never
                            issues an off-origin redirect (a vulnerable control proves the
                            assertion discriminates). Verified by reading the Location header.
  2. harness_confirmation -- the REAL OpenRedirectValidator confirms open redirect on the
                            vulnerable fixture over the socket.
  3. harness_control      -- the REAL OpenRedirectValidator returns a controlled negative
                            on the patched fixture.

Reproducible + hermetic: loopback only, seeded attacker host, bounded timeouts, explicit
assertions, no model. Outcomes are recorded by the runner (EvidenceCase). Throttle and
gate are saved and restored via addCleanup (survives failures).
"""
from __future__ import annotations

import asyncio
import unittest
from urllib.parse import urlsplit

import httpx

import harness.coverage_manifest as cm
from harness import global_throttle
from harness import safety_gate
from harness.coverage_evidence_case import EvidenceCase, evidence_for
from harness.models import Finding, HttpExchange
from harness.testing_fixtures.open_redirect import OpenRedirectFixture
from harness.validators.open_redirect_validator import OpenRedirectValidator

HOST = "127.0.0.1"
HTTP_TIMEOUT = 5.0
VALIDATE_TIMEOUT = 15.0
_INVARIANT = "an externally-supplied redirect target must not send the user off-origin"


class OpenRedirectSliceTest(EvidenceCase):
    def setUp(self):
        st = global_throttle.throttle.stats()
        prev_rate = st["rate_per_second"] if st["enabled"] else 0.0
        prev_burst = st["burst"] if st["enabled"] else None
        self.addCleanup(lambda: global_throttle.configure(prev_rate, prev_burst))
        global_throttle.configure(0)
        self.addCleanup(safety_gate.reset_default_gate)
        safety_gate.reset_default_gate()
        safety_gate.get_default_gate({"active_enabled": True, "allow_mutating_replay": False})

    def _fixture(self, mode):
        fx = OpenRedirectFixture(mode)
        self.addCleanup(fx.close)
        return fx

    @staticmethod
    def _location(url):
        r = httpx.get(url, follow_redirects=False, timeout=HTTP_TIMEOUT)
        return r.status_code, (r.headers.get("location") or "")

    # --- aspect 1: the patched server neutralises an off-origin redirect ---

    @evidence_for(check_id=cm.OPEN_REDIRECT_CHECK_ID, aspect=cm.ASPECT_OR_INVARIANT,
                  label="fixture_invariant", invariant=_INVARIANT)
    def test_patched_neutralises_off_origin_redirect(self):
        fx = self._fixture("patched")
        status, location = self._location(fx.login_url(fx.off_origin_next()))
        loc_host = urlsplit(location).hostname or ""
        self.record_observation({"status": status, "location": location,
                                 "location_host": loc_host, "attacker_host": fx.attacker_host,
                                 "off_origin_next": fx.off_origin_next()})
        self.assertEqual(status, 302)
        self.assertNotEqual(loc_host, fx.attacker_host,
                            f"patched server redirected off-origin to {location!r}")
        self.assertIn(loc_host, ("", HOST),
                      f"patched Location must stay on-origin, got host {loc_host!r}")

    def test_vulnerable_redirects_off_origin_control(self):
        fx = self._fixture("vulnerable")
        _status, location = self._location(fx.login_url(fx.off_origin_next()))
        self.assertEqual(urlsplit(location).hostname, fx.attacker_host,
                         "control is inert: the vulnerable server did not actually redirect "
                         "off-origin, so the invariant test proves nothing")

    def test_patched_allows_safe_relative_next(self):
        fx = self._fixture("patched")
        status, location = self._location(fx.login_url("/dashboard"))
        self.assertEqual(status, 302)
        self.assertEqual(location, "/dashboard")   # a legitimate relative next still works

    # --- aspects 2 & 3: the REAL harness confirmation leg over the socket ---

    def _run_validator(self, fx):
        exchange = HttpExchange(
            url=fx.login_url("/home"), method="GET", request_headers={},
            request_body="", response_status=302,
            response_headers={"Location": "/home"}, response_body="")
        finding = Finding(vulnerability_class="open_redirect", confidence=0.5,
                          summary="open-redirect hypothesis", evidence="",
                          suggested_test="", basis="derived")
        v = OpenRedirectValidator(allowed_hosts=[HOST], timeout=HTTP_TIMEOUT)

        async def scenario():
            return await asyncio.wait_for(v.validate(finding, exchange), VALIDATE_TIMEOUT)

        return asyncio.run(scenario())

    @evidence_for(check_id=cm.OPEN_REDIRECT_CHECK_ID, aspect=cm.ASPECT_OR_CONFIRM,
                  label="harness_confirmation")
    def test_harness_validator_confirms_vulnerable(self):
        fx = self._fixture("vulnerable")
        res = self._run_validator(fx)
        self.record_observation({"validator": res.validator, "status": res.status,
                                 "confirmed": res.confirmed})
        self.assertEqual(res.status, "confirmed")
        self.assertTrue(res.confirmed)

    @evidence_for(check_id=cm.OPEN_REDIRECT_CHECK_ID, aspect=cm.ASPECT_OR_CONTROL,
                  label="harness_control")
    def test_harness_validator_controlled_negative_on_patched(self):
        fx = self._fixture("patched")
        res = self._run_validator(fx)
        self.record_observation({"validator": res.validator, "status": res.status,
                                 "confirmed": res.confirmed})
        self.assertEqual(res.status, "not_confirmed")
        self.assertFalse(res.confirmed)

    def test_seeded_attacker_host_is_reproducible(self):
        a = OpenRedirectFixture("patched", seed=7)
        self.addCleanup(a.close)
        b = OpenRedirectFixture("patched", seed=7)
        self.addCleanup(b.close)
        self.assertEqual(a.attacker_host, b.attacker_host)


if __name__ == "__main__":
    unittest.main()
