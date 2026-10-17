"""Tests for testing/corpus_sanitize.py (PR-13). Offline, deterministic.

Synthetic tests (always run) prove the sanitizer removes ground-truth annotations
while preserving realistic disclosed source, plus the mandatory byte-identical
negative control. The real-corpus audit is skip-guarded on file presence -- the
benchmark exchange JSONs live untracked/git-ignored under C:/tmp and
reviews/2026-09-23/benchmark/, so they run in the owner's tree and skip cleanly
in a fresh checkout.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

_TESTING_DIR = Path(__file__).resolve().parent
if str(_TESTING_DIR) not in sys.path:
    sys.path.insert(0, str(_TESTING_DIR))

import corpus_sanitize as cs  # noqa: E402

_ROOT = _TESTING_DIR.parent
_BENCH = _ROOT / "reviews" / "2026-09-23" / "benchmark"
_PIXELMART = Path("C:/tmp/pixelmart_exchanges.json")


class SanitizeTextTests(unittest.TestCase):
    def test_full_line_bug_comment_removed_code_preserved(self):
        src = "def login(u, p):\n    # BUG: SQL injection on the password field\n    return q(u, p)"
        clean, removed = cs.sanitize_text(src)
        self.assertEqual(removed, 1)
        self.assertNotIn("BUG:", clean)
        self.assertIn("def login(u, p):", clean)      # real code preserved
        self.assertIn("return q(u, p)", clean)         # exploit-relevant code preserved

    def test_inline_bug_comment_stripped_keeps_code_before_it(self):
        src = "pw = request.args.get('pw')  # BUG: no validation, SQLi here"
        clean, removed = cs.sanitize_text(src)
        self.assertEqual(removed, 1)
        self.assertNotIn("BUG:", clean)
        self.assertEqual(clean, "pw = request.args.get('pw')")  # inline comment gone, code kept

    def test_answer_key_prose_reference_redacted(self):
        src = "See ANSWER_KEY.md for the full list of planted vulns."
        clean, removed = cs.sanitize_text(src)
        self.assertEqual(removed, 1)
        self.assertNotIn("ANSWER_KEY", clean)
        self.assertIn("[annotation removed]", clean)

    def test_clean_text_is_byte_identical_same_object(self):
        # NEGATIVE CONTROL: nothing to remove -> returns the ORIGINAL object.
        src = "def add(a, b):\n    return a + b  # sums two numbers\n"
        clean, removed = cs.sanitize_text(src)
        self.assertEqual(removed, 0)
        self.assertIs(clean, src)

    def test_ordinary_hash_comment_not_a_marker_is_kept(self):
        src = "x = 1  # initialise counter"
        clean, removed = cs.sanitize_text(src)
        self.assertEqual(removed, 0)
        self.assertIs(clean, src)

    def test_crlf_convention_preserved(self):
        src = "a = 1\r\n# BUG: x\r\nb = 2"
        clean, removed = cs.sanitize_text(src)
        self.assertEqual(removed, 1)
        self.assertIn("\r\n", clean)
        self.assertIn("a = 1", clean)
        self.assertIn("b = 2", clean)


class AuditExchangesTests(unittest.TestCase):
    def test_detects_contaminated_response_body(self):
        exchanges = [
            {"label": "TP1", "response_body": "ok, nothing here"},
            {"label": "TP10", "response_body": "def f():\n    # BUG: idor\n    pass\n# ANSWER_KEY"},
            {"label": "TP2", "response": {"body": "clean body"}},
        ]
        report = cs.audit_exchanges(exchanges)
        self.assertFalse(report["clean"])
        self.assertIn("TP10", report["contaminated_exchange_ids"])
        self.assertNotIn("TP1", report["contaminated_exchange_ids"])
        self.assertEqual(report["n_exchanges"], 3)
        self.assertGreaterEqual(report["total_marker_hits"], 2)

    def test_clean_corpus_reports_clean(self):
        exchanges = [{"label": "TP1", "response_body": "def add(a,b): return a+b"}]
        report = cs.audit_exchanges(exchanges)
        self.assertTrue(report["clean"])
        self.assertEqual(report["contaminated_exchange_ids"], [])

    def test_sanitize_exchanges_only_touches_contaminated_and_deepcopies(self):
        exchanges = [
            {"label": "TP1", "response_body": "clean", "meta": {"k": 1}},
            {"label": "TP10", "response_body": "code()\n# BUG: sqli"},
        ]
        cleaned, total = cs.sanitize_exchanges(exchanges)
        self.assertEqual(total, 1)
        # contaminated body sanitized
        self.assertNotIn("BUG:", cleaned[1]["response_body"])
        self.assertIn("code()", cleaned[1]["response_body"])
        # clean exchange untouched, and it's a copy (original not mutated)
        self.assertEqual(cleaned[0]["response_body"], "clean")
        self.assertIsNot(cleaned[0], exchanges[0])
        self.assertEqual(exchanges[1]["response_body"], "code()\n# BUG: sqli")  # original intact

    def test_after_sanitize_audit_is_clean(self):
        exchanges = [{"label": "TP10", "response_body": "x=1\n# BUG: xss\n# ANSWER_KEY ref"}]
        cleaned, _ = cs.sanitize_exchanges(exchanges)
        self.assertTrue(cs.audit_exchanges(cleaned)["clean"])


class RealCorpusAuditTests(unittest.TestCase):
    """Audits the actual (untracked) benchmark corpora when present."""

    @unittest.skipUnless(_PIXELMART.exists(), "pixelmart corpus absent (untracked, C:/tmp)")
    def test_pixelmart_is_flagged_contaminated(self):
        report = cs.audit_corpus_file(_PIXELMART)
        # PR-2 surfaced this: TP10 discloses app.py source with BUG:/ANSWER_KEY.
        self.assertFalse(report["clean"], "expected PixelMart to carry ground-truth annotations")
        self.assertGreater(report["total_marker_hits"], 0)

    @unittest.skipUnless((_BENCH / "dvwa_exchanges.json").exists(),
                         "dvwa corpus absent (untracked)")
    def test_dvwa_corpus_is_clean(self):
        report = cs.audit_corpus_file(_BENCH / "dvwa_exchanges.json")
        self.assertTrue(report["clean"], "DVWA corpus unexpectedly carries annotations")

    @unittest.skipUnless((_BENCH / "webgoat_exchanges.json").exists(),
                         "webgoat corpus absent (untracked)")
    def test_webgoat_corpus_is_clean(self):
        report = cs.audit_corpus_file(_BENCH / "webgoat_exchanges.json")
        self.assertTrue(report["clean"], "WebGoat corpus unexpectedly carries annotations")


if __name__ == "__main__":
    unittest.main()
