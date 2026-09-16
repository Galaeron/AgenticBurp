"""
Regression tests for categories.canonicalize(), specifically the
normalization fix found live against a real Juice Shop exchange
(PUT /api/BasketItems/<id>): several real, correctly-shaped
vulnerability_class strings failed to canonicalize at all purely due to
cosmetic decoration -- a trailing parenthetical annotation ("Insecure
Direct Object Reference (IDOR)") or a hyphen where the synonym table has
a space ("Object-Level" vs "object level"). This meant findings that
were, in substance, exactly the categories the harness already knows
about were falling through as "uncategorized", which (via planner.py)
meant they got no test plan at all, or fell into an overly-permissive
fallback path instead of their correct one.
"""
import unittest
from harness.categories import canonicalize


class CanonicalizeNormalizationTests(unittest.TestCase):
    def test_trailing_parenthetical_annotation_is_stripped(self):
        self.assertEqual(canonicalize("Insecure Direct Object Reference (IDOR)"), "idor")
        self.assertEqual(canonicalize("Cross-site scripting (reflected)"), "xss")
        self.assertEqual(canonicalize("Cross-site scripting (stored)"), "xss")

    def test_hyphen_vs_space_variation_is_normalized(self):
        self.assertEqual(canonicalize("Broken Object-Level Authorization (BOLA/IDOR)"), "idor")

    def test_exact_matches_still_work_unchanged(self):
        self.assertEqual(canonicalize("idor"), "idor")
        self.assertEqual(canonicalize("sqli"), "sqli")
        self.assertEqual(canonicalize("SQL Injection"), "sqli")

    def test_genuinely_ambiguous_category_still_returns_none(self):
        """"Broken Access Control" is a real OWASP Top 10 category name,
        but it's genuinely ambiguous across idor/auth/business_logic --
        normalization must not force a guess here just because it's
        cosmetically simple. canonicalize()'s "return None rather than
        guess" guarantee is about substance, not just decoration."""
        self.assertIsNone(canonicalize("Broken Access Control"))

    def test_genuinely_unrecognized_phrase_still_returns_none(self):
        self.assertIsNone(canonicalize("Some totally unrecognized made-up phrase (with parens)"))

    def test_none_and_empty_input_still_return_none(self):
        self.assertIsNone(canonicalize(None))
        self.assertIsNone(canonicalize(""))


if __name__ == "__main__":
    unittest.main()
