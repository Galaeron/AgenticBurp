"""Finding dedup (juice-shop-8h, 2026-11-03): the over-splitting the live 8 h Juice Shop
run exposed (.test-work/finding-dedup-20261103/HANDOFF.md).

C1-C5 are the five largest clusters of that run's DEDUP_ANALYSIS.md, rebuilt as
synthetic rows from their recorded ids, labels, methods, path shapes, principals and
verdicts only. Every grouping test has a negative control: different parameters,
hosts or methods never merge, and a merged group keeps its best verdict and every
member id.
"""
import hashlib
import sqlite3
import tempfile
import unittest
from pathlib import Path

from harness import categories, issues, store
from harness import report_generator as rg
from harness.models import Finding, HttpExchange

HOST = "http://127.0.0.1:3003"
A = "captured:aaaa"
B = "captured:bbbb"


def row(fid, path, vc, *, method="GET", principal=A, verdict="", confirmed=False,
        severity="medium", confidence=0.5, ploc="", pname="", host=HOST, **extra):
    d = {"finding_id": f"f{fid}", "fingerprint": f"fp{fid}", "url": host + path,
         "vulnerability_class": vc, "method": method, "captured_principal_id": principal,
         "review_verdict": verdict, "confirmed": confirmed, "severity": severity,
         "confidence": confidence, "parameter_location": ploc, "parameter_name": pname,
         "summary": "", "evidence": "", "basis": "derived", "agent": "t"}
    d.update(extra)
    return d


# C1: bola_idor GET /rest/basket/{id} -- 10 rows, 9 labels, 2 principals, 3 raw URLs.
# 159's bare "Broken Access Control" stays its own issue: that umbrella term is left
# unmapped on purpose (it can mean bfla, business logic or workflow bypass).
C1 = [
    row(19, "/rest/basket/1", "Broken Object Level Authorization (BOLA)"),
    row(20, "/rest/basket/1", "Broken Object-Level Authorization (BOLA) / IDOR"),
    row(22, "/rest/basket/2", "IDOR/BOLA", principal=B),
    row(23, "/rest/basket/2", "Broken Object-Level Authorization (BOLA)", principal=B),
    row(25, "/rest/basket/1", "Broken Object Level Authorization (BOLA)"),
    row(29, "/rest/basket/3", "Insecure Direct Object Reference / Broken Object-Level "
        "Authorization (IDOR/BOLA)", verdict="inconclusive_unverified"),
    row(85, "/rest/basket/2", "Insecure Direct Object Reference (IDOR)", principal=B,
        verdict="inconclusive_unverified"),
    row(137, "/rest/basket/1", "Insecure Direct Object Reference / Broken Object-Level "
        "Access Control", verdict="inconclusive_unverified"),
    row(157, "/rest/basket/2", "Insecure Direct Object Reference (IDOR) / Broken "
        "Object-Level Access Control", principal=B, verdict="inconclusive_unverified"),
    row(159, "/rest/basket/2", "Broken Access Control", principal=B,
        verdict="unconfirmed_hypothesis"),
]
# C2: bola_idor GET /api/BasketItems/{id} -- 4 rows, 2 principals.
C2 = [
    row(12, "/api/BasketItems/1", "BOLA / IDOR"),
    row(13, "/api/BasketItems/2", "Broken Object Level Authorization (BOLA)", principal=B),
    row(14, "/api/BasketItems/3", "BOLA / Insecure Direct Object Reference (IDOR)"),
    row(90, "/api/BasketItems/2", "Insecure Direct Object Reference (IDOR)", principal=B,
        verdict="inconclusive_unverified"),
]
# C3: insecure transport, filed per endpoint, per agent and per principal.
C3 = [
    row(28, "/rest/basket/1", "Insecure Transport / Cleartext Transmission", verdict="downgraded"),
    row(30, "/rest/basket/1", "Insecure Transport / Token Exposure", verdict="downgraded"),
    row(86, "/rest/basket/2", "Insecure Communication", principal=B, verdict="downgraded"),
    row(138, "/rest/basket/1", "Insecure Transport", verdict="survived"),
    row(301, "/api/Users/", "Insecure Transport / Man-in-the-Middle (MITM)", method="POST"),
    row(302, "/rest/user/whoami", "Token Transmission over HTTP"),
]
# C4: GET /api/Products/{id}?d -- two idor labels plus a business-logic compound.
C4 = [
    row(16, "/api/Products/1?d=1", "BOLA / IDOR"),
    row(71, "/api/Products/1?d=2", "Insecure Direct Object Reference (IDOR)",
        verdict="inconclusive_unverified"),
    row(148, "/api/Products/1?d=1", "Business Logic Flaw / Broken Access Control",
        verdict="inconclusive_unverified"),
]
# C5: POST /api/BasketItems/ -- two SQLi rows on different inputs, plus a chain row.
C5 = [
    row(51, "/api/BasketItems/", "SQL Injection", method="POST", ploc="body", pname="ProductId",
        verdict="unconfirmed_hypothesis"),
    row(52, "/api/BasketItems/", "SQL Injection", method="POST", ploc="body", pname="quantity",
        verdict="unconfirmed_hypothesis"),
    row(54, "/api/BasketItems/", "potential-attack-chain:sqli+idor", method="POST"),
]


def _ids(issue):
    return sorted(issue.member_ids)


class CanonicalizeTests(unittest.TestCase):
    def test_compound_labels_map_when_parts_agree(self):
        for label, want in [
            ("BOLA / IDOR", "idor"), ("IDOR/BOLA", "idor"),
            ("Broken Object-Level Authorization (BOLA) / IDOR", "idor"),
            ("Insecure Direct Object Reference / Broken Object-Level Access Control", "idor"),
            ("Insecure Transport / Token Exposure over HTTP", "insecure_transport"),
            ("Insecure Transport / Man-in-the-Middle (MITM)", "insecure_transport"),
            ("Command Injection / RCE", "command_injection"),
            ("Broken Function-Level Authorization (BFLA) / Injection", "bfla"),
        ]:
            self.assertEqual(categories.canonicalize(label), want, label)

    def test_compound_labels_naming_two_classes_stay_unmapped(self):
        for label in ("Business Logic Flaw / Broken Access Control",
                      "Broken Access Control / Information Disclosure",
                      "SQL Injection / XSS"):
            self.assertIsNone(categories.canonicalize(label), label)

    def test_new_synonyms(self):
        for label, want in [
            ("Insecure Communication", "insecure_transport"),
            ("Insecure Transport", "insecure_transport"),
            ("Missing Security Headers", "missing_headers"),
            ("Missing Security Header", "missing_headers"),
            ("Broken Function-Level Authorization (BFLA)", "bfla"),
            ("Broken Function Level Authorization (API Context)", "bfla"),
            ("Excessive Data Exposure", "api_security"),
            # an existing, more specific reading is unchanged
            ("Missing Security Headers (CSP)", "csp"),
        ]:
            self.assertEqual(categories.canonicalize(label), want, label)
        self.assertIsNone(categories.canonicalize("Broken Access Control"))

    def test_new_classes_are_canonical_and_enumerated(self):
        for cls in ("insecure_transport", "missing_headers", "bfla"):
            self.assertIn(cls, categories.CANONICAL_CATEGORIES)
            self.assertIn(cls, rg._REMEDIATION_HINTS)
            self.assertIn(cls, {r["category"] for r in _coverage_rows()})

    def test_legacy_reading_is_frozen(self):
        for label in ("Insecure Communication", "BOLA / IDOR", "Missing Security Headers",
                      "Broken Access Control", "bfla"):
            self.assertIsNone(categories.legacy_canonicalize(label), label)
        self.assertEqual(categories.legacy_canonicalize("Insecure Direct Object Reference (IDOR)"),
                         "idor")


def _coverage_rows():
    with tempfile.TemporaryDirectory() as tmp:
        old = store._DB_PATH
        store._DB_PATH = Path(tmp) / "cov.db"
        try:
            return store.coverage_report("target.test")
        finally:
            store._DB_PATH = old


class FingerprintStabilityTests(unittest.TestCase):
    def test_stored_fingerprint_keeps_the_raw_label_for_newly_mapped_classes(self):
        url = HOST + "/rest/basket/1"
        expected = hashlib.sha256("\x1f".join(
            ["127.0.0.1:3003", "GET", url, "insecure communication", "", "", ""]).encode()).hexdigest()
        self.assertEqual(store.finding_fingerprint("127.0.0.1:3003", "GET", url,
                                                   "Insecure Communication"), expected)

    def test_two_wordings_still_have_distinct_stored_fingerprints(self):
        url = HOST + "/rest/basket/1"
        self.assertNotEqual(store.finding_fingerprint("h", "GET", url, "BOLA / IDOR"),
                            store.finding_fingerprint("h", "GET", url, "idor"))


class IssueKeyClusterTests(unittest.TestCase):
    def test_c1_groups_into_one_issue_keeping_every_member(self):
        grouped = issues.group_findings_into_issues(C1)
        self.assertEqual(len(grouped), 2)
        idor = next(g for g in grouped if g.vulnerability_class == "idor")
        self.assertEqual(_ids(idor), sorted(f"f{r}" for r in
                                            (19, 20, 22, 23, 25, 29, 85, 137, 157)))
        self.assertEqual([_ids(g) for g in grouped if g is not idor], [["f159"]])
        # the best verdict survives: an open (SUSPECTED) member beats every LEAD member
        self.assertEqual(issues.issue_key(idor.best_member), issues.issue_key(C1[0]))
        self.assertEqual(idor.best_member["review_verdict"], "")

    def test_c2_groups_into_one_issue(self):
        grouped = issues.group_findings_into_issues(C2)
        self.assertEqual([_ids(g) for g in grouped], [["f12", "f13", "f14", "f90"]])

    def test_c3_transport_is_one_issue_per_host_with_its_best_verdict(self):
        other_host = row(400, "/rest/basket/1", "Insecure Transport", host="http://127.0.0.1:3004")
        grouped = issues.group_findings_into_issues(C3 + [other_host])
        self.assertEqual(len(grouped), 2)
        main = next(g for g in grouped if g.host.endswith(":3003"))
        self.assertEqual(main.vulnerability_class, "insecure_transport")
        self.assertEqual(len(main.members), len(C3))
        self.assertEqual(main.best_member["finding_id"], "f138")   # survived beats downgraded
        exported = issues.export_issue(main)
        self.assertEqual(sorted(exported["member_ids"]), sorted(r["finding_id"] for r in C3))
        self.assertIn("affected_routes", exported)

    def test_missing_headers_group_per_host(self):
        rows = [row(1, "/a", "Missing Security Headers"), row(2, "/b", "Missing Security Header",
                                                              method="POST")]
        self.assertEqual(len(issues.group_findings_into_issues(rows)), 1)

    def test_c4_merges_the_idor_labels_but_not_the_business_logic_compound(self):
        grouped = issues.group_findings_into_issues(C4)
        self.assertEqual(sorted(_ids(g) for g in grouped), [["f148"], ["f16", "f71"]])

    def test_c5_different_parameters_stay_apart_and_the_chain_row_is_skipped(self):
        grouped = issues.group_findings_into_issues(C5)
        self.assertEqual(sorted(_ids(g) for g in grouped), [["f51"], ["f52"]])

    def test_c5_legacy_rows_without_a_recorded_input_stay_apart_by_fingerprint(self):
        legacy = [dict(r, parameter_location="", parameter_name="", input_recorded=False)
                  for r in C5[:2]]
        self.assertEqual(len(issues.group_findings_into_issues(legacy)), 2)
        same = [dict(r, fingerprint="fp-same") for r in legacy]
        self.assertEqual(len(issues.group_findings_into_issues(same)), 1)

    def test_recorded_empty_input_merges_canonical_injection_rows(self):
        rows = [dict(r, parameter_location="", parameter_name="", input_recorded=True)
                for r in C5[:2]]
        self.assertEqual(len(issues.group_findings_into_issues(rows)), 1)

    def test_never_merges_across_methods_hosts_or_parameters(self):
        rows = [row(1, "/api/Users/1", "idor"), row(2, "/api/Users/1", "idor", method="PUT"),
                row(3, "/api/Users/1", "idor", method="DELETE"),
                row(4, "/api/Users/1", "idor", host="http://127.0.0.1:3004"),
                row(5, "/api/Users/1", "idor", ploc="query", pname="id"),
                row(6, "/api/Users/1", "idor", ploc="query", pname="UserId")]
        self.assertEqual(len(issues.group_findings_into_issues(rows)), 6)

    def test_unmapped_raw_label_keeps_the_per_row_disambiguator(self):
        rows = [row(1, "/x", "Token Storage Issues"), row(2, "/x", "Token Storage Issues")]
        self.assertEqual(len(issues.group_findings_into_issues(rows)), 2)

    def test_distinctive_token_fallback_groups_with_the_canonical_class(self):
        rows = [row(1, "/rest/basket/1", "idor"),
                row(2, "/rest/basket/4", "Broken Access Control (BOLA) on Workflow Scope")]
        self.assertEqual(len(issues.group_findings_into_issues(rows)), 1)

    def test_dependency_advisories_keep_their_component_identity(self):
        rows = [row(1, "/a", "known-vulnerable-dependency:jwt-lib"),
                row(2, "/b", "known-vulnerable-dependency:express")]
        self.assertEqual(len(issues.group_findings_into_issues(rows)), 2)


class ReportCollapseTests(unittest.TestCase):
    def _collapse(self, rows):
        return rg._collapse_duplicates([rg._from_store_dict(r) for r in rows])

    def test_c1_bola_collapses_across_principals_listing_them(self):
        survivors, removed = self._collapse(C1)
        self.assertEqual((len(survivors), removed), (2, 8))
        s = next(s for s in survivors if len(s.member_ids) > 1)
        self.assertEqual(s.principals, [A, B])
        self.assertEqual(sorted(s.member_ids), sorted(r["finding_id"] for r in C1[:-1]))
        self.assertNotEqual(s.lifecycle_state, "LEAD")
        md = "\n".join(rg._render_finding(s))
        self.assertIn(A, md)
        self.assertIn(B, md)
        self.assertIn("f157", md)

    def test_non_authorization_class_still_splits_by_principal(self):
        rows = [row(1, "/rest/products/search?q=1", "sqli", ploc="query", pname="q"),
                row(2, "/rest/products/search?q=2", "sqli", ploc="query", pname="q", principal=B)]
        survivors, _ = self._collapse(rows)
        self.assertEqual(len(survivors), 2)

    def test_collapse_never_hides_a_stronger_verdict(self):
        rows = [row(1, "/api/Users/1", "idor", severity="critical", confidence=0.9,
                    verdict="downgraded"),
                row(2, "/api/Users/2", "idor", severity="low", confidence=0.2, confirmed=True,
                    principal=B)]
        survivors, _ = self._collapse(rows)
        self.assertEqual(len(survivors), 1)
        self.assertTrue(survivors[0].confirmed)
        self.assertEqual(sorted(survivors[0].member_ids), ["f1", "f2"])

    def test_c3_transport_collapses_host_wide(self):
        survivors, _ = self._collapse(C3)
        # host-wide across routes and methods; still per principal (not an authz class)
        self.assertEqual(sorted(len(s.member_ids) for s in survivors), [1, 5])
        a_group = next(s for s in survivors if len(s.member_ids) == 5)
        self.assertEqual(a_group.finding_id, "f138")   # survived beats downgraded
        self.assertIn("host-wide", "\n".join(rg._render_finding(a_group)))


class StoreParameterPersistenceTests(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._old = store._DB_PATH
        store._DB_PATH = Path(self._tmpdir.name) / "dedup.db"

    def tearDown(self):
        store._DB_PATH = self._old
        self._tmpdir.cleanup()

    def _exchange(self):
        return HttpExchange(url=HOST + "/api/BasketItems/", method="POST", request_headers={},
                            request_body="", response_status=200, response_headers={},
                            response_body="")

    def _finding(self, pname):
        return Finding(vulnerability_class="SQL Injection", confidence=0.5, summary="s",
                       evidence="", suggested_test="", basis="derived", severity="high",
                       parameter_location="body", parameter_name=pname)

    def test_parameters_round_trip_without_a_proof_record(self):
        store.persist_findings(self._exchange(), "sqli", [self._finding("ProductId"),
                                                          self._finding("quantity")])
        rows = store.all_host_findings(HOST)
        self.assertEqual(sorted(r["parameter_name"] for r in rows), ["ProductId", "quantity"])
        self.assertTrue(all(r["input_recorded"] for r in rows))
        self.assertEqual(len(issues.group_findings_into_issues(rows)), 2)

    def test_legacy_rows_migrate_idempotently_and_read_as_unrecorded(self):
        conn = sqlite3.connect(store._DB_PATH)
        try:
            # A store from before finding_inputs: the findings table only.
            conn.executescript(store._SCHEMA)
            conn.execute(
                "INSERT INTO findings (host, url, method, agent, vulnerability_class, severity, "
                "confidence, summary, basis, fingerprint, created_at) VALUES "
                "('127.0.0.1:3003', 'http://127.0.0.1:3003/api/BasketItems/', 'POST', 'a', "
                "'SQL Injection', 'high', 0.5, 's', 'derived', 'legacy-fp', 0.0)")
            conn.commit()
            findings_sql = conn.execute("SELECT sql FROM sqlite_master WHERE name = 'findings'").fetchone()
        finally:
            conn.close()
        store._connect().close()
        store._connect().close()   # second open: the migration is a no-op
        conn = store._connect()
        try:
            # additive: findings itself is untouched, the side table and marker exist once
            self.assertEqual(conn.execute("SELECT sql FROM sqlite_master WHERE name = 'findings'")
                             .fetchone(), findings_sql)
            self.assertEqual(conn.execute("SELECT count(*) FROM finding_inputs").fetchone()[0], 0)
            self.assertEqual(conn.execute("SELECT value FROM state_metadata WHERE name = "
                                          "'finding-inputs-schema'").fetchall(), [("1",)])
        finally:
            conn.close()
        rows = store.all_host_findings(HOST)
        self.assertEqual(len(rows), 1)
        self.assertFalse(rows[0]["input_recorded"])
        self.assertEqual(rows[0]["parameter_name"], "")

    def test_wipe_removes_the_side_rows(self):
        store.persist_findings(self._exchange(), "sqli", [self._finding("ProductId")])
        counts = store.wipe_engagement("127.0.0.1:3003")
        self.assertEqual(counts["finding_inputs"], 1)
        self.assertEqual(store.all_host_findings(HOST), [])

if __name__ == "__main__":
    unittest.main()
