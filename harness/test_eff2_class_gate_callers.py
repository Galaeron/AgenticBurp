"""EFF-2: the R11-1 class gate holds on every confirmation path, not only PASS1.

PASS1 (orchestrator_confirm._validate_findings) refuses a confirmation that proves
another class than the finding's (validators.base.proves_finding_class). The
engagement graph's _confirm, its shape-precondition legs and its coverage drive
chose a leg by label substring, by shape or by check, and bound whatever came back.
They now all pass through orchestrator_chain._ConfirmationCache, which applies the
gate (validators.base.binds_routed_class), and the store binds a proof to rows by
the same class reading (categories.finding_class).

Caller-level: each scenario runs Orchestrator.investigate_engagement against an
owned loopback target, with the leg's network work replaced by a stub that
confirms class X. A finding of class Y must stay unconfirmed. The negative control
forces proves_finding_class to True; each scenario must then confirm, so the
assertions are not vacuous.
"""
from __future__ import annotations

import sqlite3
import unittest
from unittest.mock import patch

from harness import store
from harness.categories import finding_class, legacy_canonicalize
from harness.models import Finding, HttpExchange
from harness.role_crawl import RoleSession
from harness.test_coverage_proof_binding import _LoopbackCase, _row
from harness.test_det_shape_dispatch_callers import _PROFILE_NODE, _jwt
from harness.test_engagement_transport_callers import _EngagementCallerBase
from harness.validators.base import ValidationResult

_FORCE_GATE_OPEN = "harness.validators.base.proves_finding_class"
_JWT_VALIDATE = "harness.validators.jwt_forge_validator.JwtForgeValidator.validate"


def _observation(validator, cls):
    """An informational result: a security.txt was published. Not a vulnerability."""
    return ValidationResult(validator, "confirmed", cls, confidence=0.9, confirmed=True,
                            severity="info", observation=True,
                            mechanism_classes=("security_txt",),
                            summary="Observation (not a vulnerability): a security.txt is published")


def _confirmed(validator, cls):
    return ValidationResult(validator, "confirmed", cls, confidence=0.9, confirmed=True,
                            summary="stub: a forged token was accepted")


class _GraphCase(_EngagementCallerBase):
    def _engage(self, cookie, leg_result, *, probe_findings=(), force_gate_open=False):
        roles = [RoleSession("anonymous", {}), RoleSession("user", {"Cookie": f"session={cookie}"})]
        legs = []

        async def leg(self_validator, finding, exchange, *a, **kw):
            legs.append((finding.vulnerability_class, exchange.url))
            return leg_result()

        patches = [patch(_JWT_VALIDATE, new=leg)]
        if force_gate_open:
            patches.append(patch(_FORCE_GATE_OPEN, return_value=True))
        wrap = None
        if probe_findings:
            def wrap(original):
                async def probe(exchange, hypothesis, specialty, *a, **kw):
                    return {"iterative_result": {"findings": [dict(f) for f in probe_findings],
                                                 "stop_reason": "done"},
                            "integration": {}}
                return probe
        result, _, _ = self._run(self._target(), max_requests=500, endpoints=[_PROFILE_NODE],
                                 roles=roles, wrap_probe=wrap, extra_patches=patches)
        return result, [leg for leg in legs if leg[1].endswith("/api/profile")]


class ShapeLegClassGateCallerTests(_GraphCase, unittest.TestCase):
    """The JWT-cookie shape leg (shape_precondition_legs -> _confirm -> jwt-forge)
    gets back an observation (X = security_txt) for its jwt hypothesis (Y = jwt)."""

    def _shape(self, **kw):
        result, legs = self._engage(_jwt(), lambda: _observation("jwt_forge", "jwt"), **kw)
        self.assertIn("jwt", [cls for cls, _ in legs],
                      "the jwt shape leg never ran: the test would be vacuous")
        return [f for f in result["findings"] if f.get("confirmed")]

    def test_an_observation_does_not_confirm_the_shape_legs_jwt_hypothesis(self):
        self.assertEqual(self._shape(), [])

    def test_negative_control_forcing_the_class_gate_open_confirms_it(self):
        confirmed = self._shape(force_gate_open=True)
        self.assertTrue([f for f in confirmed if f.get("confirmed_by_leg") == "jwt_forge"],
                        "forcing proves_finding_class open changed nothing: the gate is not on this path")


class GraphConfirmClassGateCallerTests(_GraphCase, unittest.TestCase):
    """An agent finding labelled `weak_token` reads as reset_token (categories), but
    the graph's _confirm routes it to jwt-forge by substring. A forged-JWT proof
    (X = jwt) must not confirm it (Y = reset_token). The role's cookie is opaque, so
    no jwt shape leg runs and the only jwt-forge dispatch is the agent finding's."""

    _WEAK = {"vulnerability_class": "weak_token", "confidence": 0.6, "severity": "high",
             "summary": "The session token looks weak", "evidence": "", "suggested_test": "",
             "basis": "derived"}

    def _graph(self, **kw):
        self.assertEqual(finding_class("weak_token"), "reset_token")
        result, legs = self._engage("opaque-session-0123456789",
                                    lambda: _confirmed("jwt_forge", "jwt"),
                                    probe_findings=(self._WEAK,), **kw)
        self.assertIn("weak_token", [cls for cls, _ in legs],
                      "_confirm never routed the weak_token finding to jwt-forge: vacuous")
        weak = [f for f in result["findings"] if f.get("vulnerability_class") == "weak_token"]
        self.assertTrue(weak, "the agent finding did not reach the engagement result")
        return weak

    def test_a_jwt_proof_does_not_confirm_a_reset_token_finding(self):
        weak = self._graph()
        self.assertFalse([f for f in weak if f.get("confirmed")], weak)
        self.assertFalse([f for f in weak if f.get("proof_id")], weak)

    def test_negative_control_forcing_the_class_gate_open_confirms_it(self):
        weak = self._graph(force_gate_open=True)
        self.assertTrue([f for f in weak if f.get("confirmed")],
                        "forcing proves_finding_class open changed nothing: the gate is not on this path")


class CoverageDriveClassGateCallerTests(_LoopbackCase, unittest.TestCase):
    """The coverage drive runs AV-EXPOSURE-01 (content_exposure) for the
    info_disclosure check. A confirmed observation (X = security_txt) must not
    confirm that check's finding (Y = info_disclosure) or bind a stored row."""

    def _drive(self, *, force_gate_open=False):
        calls = []

        async def observe(finding, exchange, *a, **kw):
            calls.append(finding.vulnerability_class)
            return _observation("content_exposure_validator", finding.vulnerability_class)

        self.seed("/metrics", _row("info_disclosure", case="seed-metrics"))
        if force_gate_open:
            with patch(_FORCE_GATE_OPEN, return_value=True):
                result = self.drive(("content_exposure",), validate=observe)
        else:
            result = self.drive(("content_exposure",), validate=observe)
        self.assertIn("info_disclosure", calls, "the coverage leg never ran: vacuous")
        return result

    def _confirmed_proofs(self):
        return [p for p in self.proofs() if p[0] == "content_exposure_validator" and p[1] == "confirmed"]

    def test_an_observation_does_not_confirm_the_coverage_check(self):
        result = self._drive()
        self.assertFalse([f for f in result["findings"]
                          if f.get("confirmed") and f.get("confirmed_by_leg") == "content_exposure_validator"])
        self.assertFalse([r for r in self.rows() if r["confirmed"]], self.rows())
        self.assertEqual(self._confirmed_proofs(), [])

    def test_negative_control_forcing_the_class_gate_open_confirms_it(self):
        result = self._drive(force_gate_open=True)
        self.assertTrue([f for f in result["findings"]
                         if f.get("confirmed") and f.get("confirmed_by_leg") == "content_exposure_validator"],
                        "forcing proves_finding_class open changed nothing: the gate is not on this path")


class StoreBindingReadsTheGatesClassTests(unittest.TestCase):
    """bind_confirmation_proof picks rows by categories.finding_class, the reading
    the gate uses, not the fingerprint's legacy one: an idor proof binds a
    `potential_idor` lead on its route, and still no row of another class."""

    def setUp(self):
        import tempfile
        from pathlib import Path
        self._tmp = tempfile.TemporaryDirectory(prefix="eff2_store_")
        self._saved = store._DB_PATH
        store._DB_PATH = Path(self._tmp.name) / "state.db"

    def tearDown(self):
        store._DB_PATH = self._saved
        self._tmp.cleanup()

    def _bind(self):
        ex = HttpExchange(url="http://127.0.0.1:9/api/orders/7", method="GET", response_status=200)
        store.persist_findings(ex, "seeded_agent", [_row("potential_idor", case="seed-lead"),
                                                    _row("sqli", case="seed-sqli")])
        proof = Finding(vulnerability_class="idor", confidence=0.9, severity="high", summary="replayed",
                        evidence="", suggested_test="", basis="derived", confirmed=True,
                        proof_id="proof-1", case_id="case-1")
        bound = store.bind_confirmation_proof(ex, proof, "cross_identity")
        conn = sqlite3.connect(store._DB_PATH)
        try:
            rows = dict(conn.execute("SELECT vulnerability_class, confirmed FROM findings").fetchall())
        finally:
            conn.close()
        return bound, rows

    def test_an_idor_proof_binds_the_potential_idor_lead_and_not_the_sqli_row(self):
        bound, rows = self._bind()
        self.assertEqual(bound, 1)
        self.assertEqual(rows, {"potential_idor": 1, "sqli": 0})

    def test_negative_control_the_legacy_reading_leaves_the_lead_unbound(self):
        legacy = lambda cls: legacy_canonicalize(cls) or (cls or "").lower()  # noqa: E731
        with patch("harness.categories.finding_class", side_effect=legacy):
            bound, rows = self._bind()
        # The proof gets its own row; the lead stays a lead.
        self.assertEqual(rows, {"potential_idor": 0, "sqli": 0, "idor": 1})
        self.assertEqual(bound, 1)


if __name__ == "__main__":
    unittest.main()
