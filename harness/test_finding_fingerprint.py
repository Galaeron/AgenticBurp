"""W-9: structural finding fingerprint.

Dedup keys on stable STRUCTURE (canonical class + host + normalized endpoint +
parameter/object + identity), never the LLM-written summary -- so re-running
and wording the same underlying issue differently produces ONE finding, and
the same endpoint reached with different query VALUES does not duplicate.
"""
import tempfile
import unittest
from pathlib import Path

from harness import store
from harness.models import HttpExchange, Finding


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

    def test_parameter_name_is_case_sensitive(self):
        """W-9: `userId` and `userid` are frequently distinct fields on the same
        API (a path/object id vs. an unrelated lowercase field) -- collapsing
        them into one fingerprint would merge two different findings and let a
        suppression on one silently swallow the other."""
        base = ("target.test", "GET", "https://target.test/x", "idor")
        self.assertNotEqual(
            store.finding_fingerprint(*base, parameter_name="userId"),
            store.finding_fingerprint(*base, parameter_name="userid"),
        )

    def test_case_distinct_findings_persist_as_two_rows(self):
        ex = _ex(url="https://target.test/api/items")
        store.persist_findings(ex, "idor", [_f(vuln_class="idor", summary="a", parameter_name="userId")])
        store.persist_findings(ex, "idor", [_f(vuln_class="idor", summary="b", parameter_name="userid")])
        rows = store.all_host_findings(ex.url)
        self.assertEqual(len(rows), 2, "case-distinct parameter names must not dedup into one finding")
        self.assertEqual(len({r["fingerprint"] for r in rows}), 2)

    def test_suppression_does_not_leak_across_case_variants(self):
        ex = _ex(url="https://target.test/api/items")
        fp_upper = store.finding_fingerprint(*("target.test", "GET", ex.url, "idor"), parameter_name="userId")
        fp_lower = store.finding_fingerprint(*("target.test", "GET", ex.url, "idor"), parameter_name="userid")
        self.assertNotEqual(fp_upper, fp_lower)
        store.persist_findings(ex, "idor", [_f(vuln_class="idor", summary="a", parameter_name="userId")])
        store.persist_findings(ex, "idor", [_f(vuln_class="idor", summary="b", parameter_name="userid")])
        store.suppress_finding(fp_upper, reason="reviewed, expected")
        remaining = store.all_host_findings(ex.url)
        self.assertEqual(len(remaining), 1, "suppressing one case variant must not suppress its sibling")
        self.assertEqual(remaining[0]["fingerprint"], fp_lower)


if __name__ == "__main__":
    unittest.main()
