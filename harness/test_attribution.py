"""Tests for Phase 3.5 category-attribution reliability (attribution.py).

The (b) tests use the roadmap's prescribed precision check: two structurally
similar endpoints differing in exactly one property, asserting the label's
plausibility lands on the one that actually has that shape."""
import unittest

from harness import attribution
from harness.attribution import (relabel_confirmed_finding, shape_consistent,
                         chain_input_speculative, annotate_shape_inconsistent)
from harness.models import HttpExchange, Finding
from harness import chaining


class RelabelTests(unittest.TestCase):
    def test_confirmed_finding_relabelled_from_leg(self):
        # An agent labelled this "algorithm_confusion"; the jwt-forge leg proved
        # it. The confirmed class should be authoritative from the leg.
        f = {"vulnerability_class": "algorithm_confusion", "confirmed": True,
             "evidence": "hyp || jwt-forge CONFIRMED: alg:none accepted"}
        self.assertTrue(relabel_confirmed_finding(f))
        self.assertEqual(f["vulnerability_class"], "jwt")
        self.assertEqual(f["original_vulnerability_class"], "algorithm_confusion")

    def test_unconfirmed_finding_not_relabelled(self):
        f = {"vulnerability_class": "sqli", "confirmed": False,
             "evidence": "xxe CONFIRMED: (stale text)"}
        self.assertFalse(relabel_confirmed_finding(f))
        self.assertEqual(f["vulnerability_class"], "sqli")

    def test_matching_class_is_noop(self):
        f = {"vulnerability_class": "xxe", "confirmed": True,
             "evidence": "xxe CONFIRMED: external entity resolved"}
        self.assertFalse(relabel_confirmed_finding(f))

    def test_confirmed_without_known_leg_is_noop(self):
        f = {"vulnerability_class": "business_logic", "confirmed": True,
             "evidence": "manually verified by analyst"}
        self.assertFalse(relabel_confirmed_finding(f))


def _ex(url="http://t/x", method="GET", ctype=None, body="", headers=None):
    h = dict(headers or {})
    if ctype:
        h["Content-Type"] = ctype
    return HttpExchange(url=url, method=method, request_headers=h, request_body=body,
                        response_status=200, response_headers={}, response_body="")


class ShapeConsistencyTests(unittest.TestCase):
    def test_xxe_paired_fixture(self):
        # Two POSTs differing only in whether the body is XML.
        xml = _ex(method="POST", ctype="application/xml",
                  body="<?xml version='1.0'?><a>1</a>")
        json_ = _ex(method="POST", ctype="application/json", body='{"a":1}')
        self.assertTrue(shape_consistent("xxe", xml))
        self.assertFalse(shape_consistent("xxe", json_))   # label lands only where the shape is

    def test_jwt_paired_fixture(self):
        tok = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcDEF123456"
        with_jwt = _ex(headers={"Authorization": f"Bearer {tok}"})
        without_jwt = _ex(headers={"Authorization": "Bearer opaque-session-token"})
        self.assertTrue(shape_consistent("jwt", with_jwt))
        self.assertFalse(shape_consistent("jwt", without_jwt))

    def test_idor_paired_fixture(self):
        obj = _ex(url="http://t/api/tickets/7")
        coll = _ex(url="http://t/api/tickets")
        self.assertTrue(shape_consistent("idor", obj))
        self.assertFalse(shape_consistent("idor", coll))

    def test_class_without_shape_requirement_never_flagged(self):
        # info_disclosure / misconfig have no strong shape prior -> always consistent.
        self.assertTrue(shape_consistent("info_disclosure", _ex()))
        self.assertTrue(shape_consistent("misconfig", _ex()))

    def test_annotate_flags_only_unconfirmed_inconsistent(self):
        json_ = _ex(method="POST", ctype="application/json", body='{"a":1}')
        findings = [
            {"vulnerability_class": "xxe", "confirmed": False},   # inconsistent -> flagged
            {"vulnerability_class": "xxe", "confirmed": True},    # confirmed -> skipped
            {"vulnerability_class": "info_disclosure", "confirmed": False},  # no shape req
        ]
        n = annotate_shape_inconsistent(findings, json_)
        self.assertEqual(n, 1)
        self.assertTrue(findings[0].get("shape_inconsistent"))
        self.assertNotIn("shape_inconsistent", findings[1])
        self.assertNotIn("shape_inconsistent", findings[2])


class PydanticFindingTests(unittest.TestCase):
    """Regression: the attribution passes run on real pydantic Finding objects in
    analyze() (orchestrator.py), NOT the plain dicts the other tests use. Setting
    an undeclared attribute on a Finding raises ValueError, so this class exercises
    the exact object type the live pipeline passes -- the negative control that a
    dict-only test can never provide ("green tests, dead pipeline")."""

    def _finding(self, **over):
        base = dict(vulnerability_class="algorithm_confusion", confidence=0.6,
                    summary="s", evidence="e", suggested_test="t", basis="derived")
        base.update(over)
        return Finding(**base)

    def test_relabel_on_real_finding_object(self):
        f = self._finding(confirmed=True,
                          evidence="hyp || jwt-forge CONFIRMED: alg:none accepted")
        # Must not raise (previously: Finding has no field original_vulnerability_class).
        self.assertTrue(relabel_confirmed_finding(f))
        self.assertEqual(f.vulnerability_class, "jwt")
        self.assertEqual(f.original_vulnerability_class, "algorithm_confusion")

    def test_annotate_shape_inconsistent_on_real_finding_object(self):
        json_ = _ex(method="POST", ctype="application/json", body='{"a":1}')
        findings = [
            self._finding(vulnerability_class="xxe", confirmed=False),  # inconsistent
            self._finding(vulnerability_class="xxe", confirmed=True),   # confirmed -> skip
            self._finding(vulnerability_class="info_disclosure", confirmed=False),  # no shape req
        ]
        # Must not raise (previously: Finding has no field shape_inconsistent).
        n = annotate_shape_inconsistent(findings, json_)
        self.assertEqual(n, 1)
        self.assertTrue(findings[0].shape_inconsistent)
        self.assertFalse(findings[1].shape_inconsistent)
        self.assertFalse(findings[2].shape_inconsistent)
        # annotation survives serialization into report / recall benchmark
        self.assertTrue(findings[0].model_dump()["shape_inconsistent"])


class ChainInputGatingTests(unittest.TestCase):
    def test_speculative_input_detection(self):
        self.assertTrue(chain_input_speculative({"basis": "assumed", "confirmed": False}))
        self.assertTrue(chain_input_speculative({"basis": "recalled", "confirmed": False}))
        self.assertFalse(chain_input_speculative({"basis": "derived", "confirmed": False}))
        self.assertFalse(chain_input_speculative({"basis": "assumed", "confirmed": True}))

    def _host_findings(self, basis_b):
        # An open_redirect + ssrf pair -- both canonical categories, so they tag
        # the open_redirect+ssrf rule directly and compose one chain. The ssrf
        # input's basis is the variable under test.
        return [
            {"url": "http://t/go?url=x", "vulnerability_class": "open_redirect",
             "severity": "medium", "confidence": 0.6, "summary": "open redirect via url param",
             "basis": "derived", "confirmed": True},
            {"url": "http://t/fetch?target=x", "vulnerability_class": "ssrf",
             "severity": "high", "confidence": 0.6, "summary": "ssrf via target param",
             "basis": basis_b, "confirmed": False},
        ]

    def test_chain_on_solid_inputs_not_speculative(self):
        chains = chaining.detect(self._host_findings("derived"))
        # Whatever chains form, none should be tagged speculative here.
        for c in chains:
            self.assertNotIn("speculative", c.summary.lower())
            self.assertEqual(c.confidence, 0.5)

    def test_chain_on_assumed_input_tagged_speculative(self):
        chains = chaining.detect(self._host_findings("assumed"))
        # At least one chain must form and be tagged speculative with lower conf.
        spec = [c for c in chains if "speculative" in c.summary.lower()]
        self.assertTrue(spec, "a chain built on an assumed-basis input must be tagged speculative")
        for c in spec:
            self.assertEqual(c.confidence, 0.35)
            self.assertIn("SPECULATIVE INPUT", c.evidence)


if __name__ == "__main__":
    unittest.main()
