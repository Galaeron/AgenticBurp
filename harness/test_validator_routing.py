"""
Routing-layer regressions for the 2026-10 review (pts 6 and 7).

Pt 6 -- a finding must reach the validator for its class even when the LLM
writes a SYNONYM the validator doesn't list, or a specific finding TITLE that
embeds the class as a word. This is about Validator.applies() and the
distinctive-token routing aid, NOT about canonicalize() (which stays strict so
the coverage ledger never guesses).

Pt 7 -- the path-traversal leg's shape-decoupled fallback must not fire active
probes off the back of a finding whose class is a response-header/transport
concern with no file-read relationship (CSP/CORS/crypto).
"""
from __future__ import annotations
import unittest

from harness.models import Finding, HttpExchange
from harness.categories import canonicalize, distinctive_token
from harness.validators.verbose_error_validator import VerboseErrorValidator
from harness.validators.csrf_validator import CsrfValidator
from harness.validators.path_traversal_validator import PathTraversalValidator


def _finding(cls: str, severity: str = "high") -> Finding:
    return Finding(vulnerability_class=cls, confidence=0.9, summary="s",
                   evidence="e", suggested_test="t", basis="derived", severity=severity)


class TestDistinctiveToken(unittest.TestCase):
    def test_embedded_tokens_map(self):
        self.assertEqual(distinctive_token("Missing CSRF Token"), "csrf")
        self.assertEqual(distinctive_token("JWT None Algorithm"), "jwt")
        self.assertEqual(distinctive_token("Reflected XSS in q"), "xss")
        self.assertEqual(distinctive_token("IDOR on /orders/5"), "idor")
        self.assertEqual(distinctive_token("BOLA"), "idor")

    def test_word_boundary_only(self):
        # Must not match inside a larger word.
        for s in ("xssi channel", "corsair mouse", "authors list"):
            self.assertIsNone(distinctive_token(s), s)

    def test_conflicting_tokens_return_none(self):
        # Two different class tokens -> do not guess which one.
        self.assertIsNone(distinctive_token("XSS and SQLi combined"))

    def test_canonicalize_stays_strict(self):
        # The routing aid must NOT leak into canonicalize()'s contract.
        self.assertIsNone(canonicalize("Missing CSRF Token"))
        self.assertIsNone(canonicalize("JWT None Algorithm"))


class TestSynonymCanonicalRouting(unittest.TestCase):
    """Pt 6: verbose_error declares the SYNONYM 'information_disclosure' but the
    info_disclosure agent writes the CANONICAL 'info_disclosure'."""

    def setUp(self):
        self.ex = HttpExchange(url="http://t/x", method="GET")
        self.ve = VerboseErrorValidator()

    def test_canonical_label_reaches_synonym_declaring_validator(self):
        self.assertTrue(self.ve.applies(_finding("info_disclosure"), self.ex))

    def test_synonym_label_still_reaches(self):
        self.assertTrue(self.ve.applies(_finding("information_disclosure"), self.ex))
        self.assertTrue(self.ve.applies(_finding("Information Disclosure"), self.ex))

    def test_unrelated_class_does_not_match(self):
        self.assertFalse(self.ve.applies(_finding("sqli"), self.ex))
        self.assertFalse(self.ve.applies(_finding("xss"), self.ex))


class TestTitleRouting(unittest.TestCase):
    """Pt 6: a specific finding TITLE embedding the class routes to its leg."""

    def test_missing_csrf_token_reaches_csrf(self):
        ex = HttpExchange(url="http://t/transfer", method="POST",
                          request_headers={"Cookie": "s=1"},
                          request_body="amount=1")
        self.assertTrue(CsrfValidator().applies(_finding("Missing CSRF Token"), ex))

    def test_csrf_title_does_not_apply_to_safe_method(self):
        # csrf's own override still requires a state-changing method.
        ex = HttpExchange(url="http://t/transfer", method="GET",
                          request_headers={"Cookie": "s=1"})
        self.assertFalse(CsrfValidator().applies(_finding("Missing CSRF Token"), ex))


class TestPathTraversalShapeGate(unittest.TestCase):
    """Pt 7: the shape-decoupled fallback is suppressed for header/transport
    classes that are never a file read, but preserved for generic/unlabelled
    classes and for explicitly-traversal findings."""

    def setUp(self):
        self.pt = PathTraversalValidator()

    def test_header_classes_do_not_trigger_on_fileish_url(self):
        for cls in ("csp", "cors", "crypto", "clickjacking"):
            ex = HttpExchange(url="http://t/uploads/123", method="GET")
            self.assertFalse(self.pt.applies(_finding(cls), ex),
                             f"{cls} should not spawn traversal probes")
        ex2 = HttpExchange(url="http://t/download?file=x.pdf", method="GET")
        self.assertFalse(self.pt.applies(_finding("cors"), ex2))

    def test_generic_classes_still_get_shape_decoupled_probe(self):
        # misconfig / info_disclosure on a file-serving URL is exactly the
        # mislabelled-traversal case the shape-decoupled design exists for.
        for cls in ("misconfig", "info_disclosure", "recon"):
            ex = HttpExchange(url="http://t/uploads/123", method="GET")
            self.assertTrue(self.pt.applies(_finding(cls), ex), cls)

    def test_explicit_traversal_finding_with_param_still_applies(self):
        ex = HttpExchange(url="http://t/item?id=5", method="GET")
        self.assertTrue(self.pt.applies(_finding("path_traversal"), ex))

    def test_non_fileish_url_does_not_apply(self):
        ex = HttpExchange(url="http://t/item?id=5", method="GET")
        self.assertFalse(self.pt.applies(_finding("csp"), ex))


if __name__ == "__main__":
    unittest.main()
