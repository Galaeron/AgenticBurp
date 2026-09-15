"""W-9: structural finding fingerprint.

Dedup keys on stable STRUCTURE (canonical class + host + normalized endpoint +
parameter/object + identity), never the LLM-written summary -- so re-running
and wording the same underlying issue differently produces ONE finding, and
the same endpoint reached with different query VALUES does not duplicate.
"""
import tempfile
import unittest
from pathlib import Path

import store
from models import HttpExchange, Finding


def _f(vuln_class="sqli", summary="s", parameter_name="", parameter_location=""):
    return Finding(vulnerability_class=vuln_class, confidence=0.7, summary=summary,
                   evidence="e", suggested_test="t", basis="derived",
                   parameter_name=parameter_name, parameter_location=parameter_location)


def _ex(url="https://target.test/api/items?id=1", method="GET"):
    return HttpExchange(url=url, method=method)


class FindingFingerprintTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._orig = store._DB_PATH
        store._DB_PATH = Path(self._tmp.name) / "state.db"

    def tearDown(self):
        store._DB_PATH = self._orig
        self._tmp.cleanup()

    def test_same_issue_worded_differently_dedups(self):
        ex = _ex()
        store.persist_findings(ex, "sqli", [_f(summary="Error-based SQLi in the id parameter")])
        store.persist_findings(ex, "sqli", [_f(summary="Completely different prose for the same bug")])
        rows = store.all_host_findings(ex.url)
        self.assertEqual(len(rows), 1, "summary wording must not create a duplicate finding")

    def test_canonical_class_equivalence_dedups(self):
        ex = _ex()
        store.persist_findings(ex, "sqli", [_f(vuln_class="sqli", summary="a")])
        store.persist_findings(ex, "sqli", [_f(vuln_class="SQL Injection", summary="b")])
        rows = store.all_host_findings(ex.url)
        self.assertEqual(len(rows), 1, "canonically-equal classes must share a fingerprint")

    def test_query_value_variation_dedups(self):
        store.persist_findings(_ex(url="https://target.test/api/items?id=1"), "sqli", [_f(summary="x")])
        store.persist_findings(_ex(url="https://target.test/api/items?id=2"), "sqli", [_f(summary="y")])
        rows = store.all_host_findings("https://target.test/api/items?id=1")
        self.assertEqual(len(rows), 1, "different query VALUES on the same endpoint must dedup")

    def test_distinct_endpoints_do_not_collapse(self):
        store.persist_findings(_ex(url="https://target.test/api/a"), "sqli", [_f(summary="x")])
        store.persist_findings(_ex(url="https://target.test/api/b"), "sqli", [_f(summary="x")])
        rows = store.all_host_findings("https://target.test/api/a")
        self.assertEqual(len(rows), 2, "genuinely different endpoints must not be over-collapsed")

    def test_fingerprint_is_summary_independent(self):
        # The function has no summary parameter at all, and differing query
        # values / class synonyms hash identically.
        self.assertEqual(
            store.finding_fingerprint("target.test", "GET", "https://target.test/x?id=1", "sqli"),
            store.finding_fingerprint("target.test", "get", "https://target.test/x?id=999", "SQL Injection"),
        )

    def test_parameter_name_distinguishes(self):
        base = ("target.test", "GET", "https://target.test/x", "xss")
        self.assertNotEqual(
            store.finding_fingerprint(*base, parameter_name="q"),
            store.finding_fingerprint(*base, parameter_name="name"),
        )

    def test_identity_context_distinguishes(self):
        base = ("target.test", "GET", "https://target.test/x", "idor")
        self.assertNotEqual(
            store.finding_fingerprint(*base, principal_id="alice"),
            store.finding_fingerprint(*base, principal_id="bob"),
        )


if __name__ == "__main__":
    unittest.main()
