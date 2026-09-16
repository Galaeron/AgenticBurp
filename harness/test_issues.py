"""T06 regressions: stable issue identity + reproducible, secret-free export.

Covers the handoff's explicit test matrix:
  * two SQLi inputs on the same endpoint remain distinct;
  * repeated object ids for the same proven authorization defect group into ONE
    issue without losing the affected instances/cases;
  * read and write boundaries remain distinct;
  * an unknown value never collapses unrelated findings (no wildcard);
  * an issue keeps ALL members (not a winner + a count);
  * exports reference the available case/proof artifacts;
  * secrets are redacted from exports and the local replay view;
  * a patched retest links to the ORIGINAL issue id (stable across runs), so
    history is preserved rather than a new issue spawned.
"""
import unittest

from harness import issues


def F(url, vc, *, method="GET", ploc="", pname="", confirmed=False, severity="high",
      confidence=0.5, case_id="", proof_id="", principal_id="", evidence="", summary=""):
    return {"url": url, "vulnerability_class": vc, "method": method,
            "parameter_location": ploc, "parameter_name": pname, "confirmed": confirmed,
            "severity": severity, "confidence": confidence, "case_id": case_id,
            "proof_id": proof_id, "principal_id": principal_id, "evidence": evidence,
            "summary": summary}


class GroupingTests(unittest.TestCase):
    def test_two_sqli_inputs_on_one_endpoint_stay_distinct(self):
        fs = [
            F("https://x/api/search", "sqli", method="GET", ploc="query", pname="search"),
            F("https://x/api/search", "sqli", method="GET", ploc="query", pname="sort"),
        ]
        grouped = issues.group_findings_into_issues(fs)
        self.assertEqual(len(grouped), 2)
        self.assertNotEqual(grouped[0].issue_id, grouped[1].issue_id)

    def test_repeated_object_ids_group_without_losing_instances(self):
        fs = [F(f"https://x/api/tickets/{i}", "idor", method="GET", confirmed=True,
                case_id=f"c{i}", proof_id=f"p{i}") for i in range(1, 5)]
        grouped = issues.group_findings_into_issues(fs)
        self.assertEqual(len(grouped), 1)
        issue = grouped[0]
        # ALL four instances + their case/proof ids are retained (not a count)
        self.assertEqual(len(issue.members), 4)
        self.assertEqual(len(issue.affected_instances), 4)
        self.assertEqual(sorted(issue.case_ids), ["c1", "c2", "c3", "c4"])
        self.assertTrue(issue.confirmed)

    def test_read_and_write_boundaries_stay_distinct(self):
        fs = [
            F("https://x/api/tickets/1", "idor", method="GET"),
            F("https://x/api/tickets/1", "idor", method="POST"),
        ]
        grouped = issues.group_findings_into_issues(fs)
        self.assertEqual(len(grouped), 2)
        boundaries = {g.authorization_boundary for g in grouped}
        self.assertEqual(boundaries, {"read", "write"})

    def test_unknown_input_does_not_collapse_known_input(self):
        # one finding with an attributed input, one without: they must NOT merge
        fs = [
            F("https://x/api/search", "sqli", method="GET", ploc="query", pname="q"),
            F("https://x/api/search", "sqli", method="GET"),  # unknown input
        ]
        grouped = issues.group_findings_into_issues(fs)
        self.assertEqual(len(grouped), 2)

    def test_distinct_classes_do_not_merge(self):
        fs = [
            F("https://x/api/tickets/1", "idor", method="GET"),
            F("https://x/api/tickets/1", "sqli", method="GET"),
        ]
        self.assertEqual(len(issues.group_findings_into_issues(fs)), 2)

    def test_canonical_synonyms_merge(self):
        fs = [
            F("https://x/api/login", "SQL Injection", method="POST", ploc="body_form", pname="u"),
            F("https://x/api/login", "sqli", method="POST", ploc="body_form", pname="u"),
        ]
        self.assertEqual(len(issues.group_findings_into_issues(fs)), 1)

    def test_chain_hypotheses_are_skipped(self):
        fs = [F("https://x/a", "potential-attack-chain:xss+ssrf")]
        self.assertEqual(issues.group_findings_into_issues(fs), [])

    def test_issue_id_is_run_independent_and_stable(self):
        a = issues.issue_key(F("https://x/api/tickets/7", "idor", method="GET"))
        b = issues.issue_key(F("https://x/api/tickets/999", "idor", method="GET"))
        # object ids collapse to the same family -> same key -> same stable id
        self.assertEqual(issues.issue_id_for(a), issues.issue_id_for(b))


class RetestLinkageTests(unittest.TestCase):
    def test_patched_retest_links_to_original_issue(self):
        # run 1: confirmed on the vulnerable fixture
        run1 = F("https://x/api/tickets/1", "idor", method="GET", confirmed=True,
                 case_id="run1-case", proof_id="run1-proof")
        # run 2 (patched retest): a NEW case/proof, same coordinates -> same issue
        run2 = F("https://x/api/tickets/1", "idor", method="GET", confirmed=False,
                 case_id="run2-case", proof_id="run2-proof")
        i1 = issues.group_findings_into_issues([run1])[0]
        i2 = issues.group_findings_into_issues([run2])[0]
        self.assertEqual(i1.issue_id, i2.issue_id)  # retest maps to the same issue
        # grouped together (history preserved, both cases kept, not overwritten)
        both = issues.group_findings_into_issues([run1, run2])
        self.assertEqual(len(both), 1)
        self.assertEqual(sorted(both[0].case_ids), ["run1-case", "run2-case"])


class ExportTests(unittest.TestCase):
    def _issue(self):
        fs = [
            F("https://x/api/tickets/1", "idor", method="GET", confirmed=True,
              case_id="c1", proof_id="p1", principal_id="user",
              evidence="read ticket 1 as user; Authorization: Bearer eyJabc.def.ghi",
              summary="cross-identity read succeeded"),
            F("https://x/api/tickets/2", "idor", method="GET", confirmed=True,
              case_id="c2", proof_id="p2", principal_id="anonymous",
              evidence="anon read ticket 2"),
        ]
        return issues.group_findings_into_issues(fs)[0]

    def test_export_has_the_required_reproducibility_fields(self):
        exp = issues.export_issue(self._issue(),
                                  proofs_by_case={"c1": [{"proof_id": "p1", "verdict": "confirmed"}]})
        for key in ("issue_id", "title", "vulnerability_class", "severity", "confirmed",
                    "prerequisites", "principal_aliases", "request_sequence",
                    "expected_vs_observed", "impact", "proof_references",
                    "affected_instances", "member_evidence", "artifacts", "limitations", "retest"):
            self.assertIn(key, exp)
        self.assertEqual(exp["expected_vs_observed"].keys(), {"expected", "observed"})

    def test_export_references_available_artifacts(self):
        exp = issues.export_issue(self._issue(), proofs_by_case={
            "c1": [{"proof_id": "p1", "verdict": "confirmed"}]})
        refs = exp["proof_references"]
        self.assertEqual({r["case_id"] for r in refs}, {"c1", "c2"})
        self.assertEqual({r["proof_id"] for r in refs}, {"p1", "p2"})
        self.assertTrue(any(r.get("verdict") == "confirmed" for r in refs))
        # both affected object instances are exported (never dropped)
        self.assertEqual(len(exp["affected_instances"]), 2)
        # every member's own evidence is preserved (not just the best member)
        self.assertEqual(len(exp["member_evidence"]), 2)

    def test_principal_aliases_never_expose_raw_credentials(self):
        exp = issues.export_issue(self._issue())
        aliases = exp["principal_aliases"]
        self.assertEqual(set(aliases.values()), {"user", "anonymous"})
        # aliases are P1/P2 labels; no bearer token anywhere in the export
        blob = repr(exp)
        self.assertNotIn("eyJabc", blob)
        self.assertNotIn("Bearer eyJ", blob)

    def test_export_redacts_secrets_in_evidence(self):
        exp = issues.export_issue(self._issue())
        self.assertIn("<REDACTED", exp["evidence"] + exp["expected_vs_observed"]["observed"])

    def test_retest_note_names_the_stable_issue_id(self):
        issue = self._issue()
        exp = issues.export_issue(issue)
        self.assertIn(issue.issue_id, exp["retest"])

    def test_unconfirmed_issue_flags_limitations(self):
        fs = [F("https://x/api/x", "xss", method="GET", confirmed=False)]
        exp = issues.export_issue(issues.group_findings_into_issues(fs)[0])
        self.assertTrue(any("hypothesis" in l.lower() for l in exp["limitations"]))


class ReviewRegressionTests(unittest.TestCase):
    """Direct regressions for the T05-T08 review (R03/R04/R08/R09/R10)."""

    def test_different_targets_get_distinct_issue_ids(self):  # R04
        left = F("https://a.invalid/items/1", "idor")
        right = F("https://b.invalid/items/1", "idor")
        self.assertNotEqual(issues.issue_id_for(issues.issue_key(left)),
                            issues.issue_id_for(issues.issue_key(right)))

    def test_distinct_unknown_input_findings_do_not_collapse(self):  # R04
        # two distinct unattributed findings (distinct finding_ids) must NOT merge
        fa = F("https://a.invalid/items/1", "idor"); fa["finding_id"] = "A"
        fb = F("https://a.invalid/items/1", "idor"); fb["finding_id"] = "B"
        self.assertEqual(len(issues.group_findings_into_issues([fa, fb])), 2)

    def test_export_redacts_url_query_secret(self):  # R03
        exp = issues.export_issue(issues.group_findings_into_issues([
            F("https://a.invalid/items/1?token=SUPERSECRETVALUE", "idor")])[0])
        import json
        blob = json.dumps(exp)
        self.assertNotIn("SUPERSECRETVALUE", blob)
        self.assertIn("<REDACTED>", blob)

    def test_export_redacts_json_secret_in_evidence(self):  # R03
        exp = issues.export_issue(issues.group_findings_into_issues([
            F("https://a.invalid/x", "idor", evidence='{"password":"JSONSECRETVALUE"}')])[0])
        import json
        self.assertNotIn("JSONSECRETVALUE", json.dumps(exp))

    def test_replay_redacts_url_secret(self):  # R03
        view = issues.replay_view(issues.group_findings_into_issues([
            F("https://a.invalid/x?session=REPLAYSECRET", "idor")])[0])
        import json
        self.assertNotIn("REPLAYSECRET", json.dumps(view))

    def test_proof_verdict_resolved_by_exact_id(self):  # R09
        # member points at proof-old; the case's ledger has a different best proof.
        issue = issues.group_findings_into_issues([
            F("https://a.invalid/items/1", "idor", case_id="case-A", proof_id="proof-old")])[0]
        exp = issues.export_issue(issue, proofs_by_case={
            "case-A": [{"proof_id": "proof-new", "verdict": "confirmed"}]})
        refs = {r["proof_id"]: r.get("verdict") for r in exp["proof_references"]}
        # proof-new is labeled with ITS verdict; proof-old is never mislabeled confirmed.
        self.assertEqual(refs.get("proof-new"), "confirmed")
        self.assertNotEqual(refs.get("proof-old"), "confirmed")

    def test_retest_history_preserves_every_attempt(self):  # R08
        # two attempts for one case (a confirm, then a patched retest) both survive.
        issue = issues.group_findings_into_issues([
            F("https://a.invalid/items/1", "idor", case_id="case-A", proof_id="p1", confirmed=True)])[0]
        exp = issues.export_issue(issue, proofs_by_case={"case-A": [
            {"proof_id": "p1", "verdict": "confirmed"},
            {"proof_id": "p2", "verdict": "inconclusive"}]})
        pids = {r["proof_id"] for r in exp["proof_references"]}
        self.assertEqual(pids, {"p1", "p2"})   # retest attempt not lost

    def test_expected_invariant_is_class_specific(self):  # R10
        idor = issues.export_issue(issues.group_findings_into_issues([
            F("https://a.invalid/x", "sqli", method="GET")])[0])
        # a GET SQLi must NOT get a generic authorization-read invariant
        self.assertIn("SQL", idor["expected_vs_observed"]["expected"])

    def test_export_marks_missing_artifacts_when_no_proof(self):  # R10
        exp = issues.export_issue(issues.group_findings_into_issues([
            F("https://a.invalid/x", "idor")])[0])
        self.assertFalse(exp["artifacts"]["replayable"])
        self.assertTrue(exp["artifacts"]["missing"])


class ReplayViewTests(unittest.TestCase):
    def test_replay_uses_session_placeholders_not_secrets(self):
        fs = [F("https://x/api/tickets/1", "idor", method="GET", principal_id="user",
                evidence="Cookie: session=SECRETVALUE123; Authorization: Bearer eyJx.y.z")]
        view = issues.replay_view(issues.group_findings_into_issues(fs)[0])
        self.assertTrue(view["principals"])
        self.assertTrue(all(p["authorization"].startswith("<<SESSION:") for p in view["principals"]))
        blob = repr(view)
        self.assertNotIn("SECRETVALUE123", blob)
        self.assertNotIn("eyJx.y.z", blob)


class RedactionTests(unittest.TestCase):
    def test_masks_bearer_cookie_jwt_and_query_secrets(self):
        self.assertIn("<REDACTED>", issues.redact("Authorization: Bearer abcdef1234567890"))
        self.assertIn("<REDACTED>", issues.redact("Cookie: session=abc; path=/"))
        self.assertIn("<REDACTED>", issues.redact("reset?token=deadbeefcafebabe"))
        self.assertIn("<REDACTED-JWT>", issues.redact("t=eyJhbGci.eyJzdWvz.SflKxwRJ"))

    def test_redaction_is_idempotent_and_keeps_non_secrets(self):
        once = issues.redact("GET /api/x  status 200 length 412")
        self.assertEqual(once, issues.redact(once))
        self.assertIn("status 200", once)


class StoreExportIntegrationTests(unittest.TestCase):
    """End-to-end: persist real findings + a structured proof, then export the
    issue through the store path -- the T06 'reproducible export' Done criterion."""

    def setUp(self):
        import tempfile
        from harness import store
        from pathlib import Path
        self._tmp = tempfile.mkdtemp(prefix="issues_")
        self._orig = store._DB_PATH
        store._DB_PATH = Path(self._tmp) / "state.db"

    def tearDown(self):
        import shutil
        from harness import store
        store._DB_PATH = self._orig
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_export_issues_for_host_links_a_persisted_proof(self):
        from harness import store, evidence, report_generator
        from harness.models import HttpExchange, Finding
        # a case + confirmed proof (the T05/T01 identity)
        case = evidence.TestCaseRef.make(run_id="run1", request_template_id="tmpl1",
                                         check_id="WSTG-ATHZ-04", principal_id="user",
                                         parameter_location="path", parameter_name="object_id")
        pr = evidence.ProofRecord.from_validation_result(
            case=case, validator="cross_identity", status="confirmed", confirmed=True,
            observed_result="cross-identity read succeeded")
        ok, _ = store.persist_proof_record(pr)
        self.assertTrue(ok)
        ex = HttpExchange(url="https://shop.example.com/api/tickets/1", method="GET",
                          request_headers={}, request_body="")
        f = Finding(vulnerability_class="idor", confidence=0.9, summary="IDOR on ticket",
                    evidence="read another user's ticket", suggested_test="replay as a different user",
                    basis="derived", severity="high", confirmed=True,
                    case_id=case.case_id, proof_id=pr.proof_id, parameter_location="path",
                    parameter_name="object_id")
        store.persist_findings(ex, "idor_agent", [f])

        exports = report_generator.export_issues_for_host(ex.url)
        self.assertEqual(len(exports), 1)
        exp = exports[0]
        self.assertTrue(exp["confirmed"])
        self.assertEqual(exp["method"], "GET")
        # the export links the persisted case/proof and carries its verdict
        refs = exp["proof_references"]
        self.assertTrue(any(r["case_id"] == case.case_id and r["proof_id"] == pr.proof_id
                            and r.get("verdict") == "confirmed" for r in refs))
        # a reproducible sequence is present
        self.assertGreaterEqual(len(exp["request_sequence"]), 2)
        self.assertIn(exp["issue_id"], exp["retest"])

    def test_retest_survives_storage_as_one_issue_with_both_attempts(self):  # R08
        from harness import store, evidence, report_generator
        from harness.models import HttpExchange, Finding
        ex = HttpExchange(url="https://shop.example.com/api/tickets/1", method="GET",
                          request_headers={}, request_body="")

        def _persist(run_id, confirmed):
            case = evidence.TestCaseRef.make(run_id=run_id, request_template_id="tmpl1",
                                             check_id="WSTG-ATHZ-04", principal_id="user")
            pr = evidence.ProofRecord.from_validation_result(
                case=case, validator="cross_identity",
                status="confirmed" if confirmed else "not_confirmed", confirmed=confirmed,
                observed_result=f"{run_id} attempt")
            store.persist_proof_record(pr)
            f = Finding(vulnerability_class="idor", confidence=0.9, summary="IDOR on ticket",
                        evidence="same summary each run", suggested_test="replay as another user",
                        basis="derived", severity="high", confirmed=confirmed,
                        case_id=case.case_id, proof_id=pr.proof_id)
            store.persist_findings(ex, "idor_agent", [f])
            return case.case_id, pr.proof_id

        c1, p1 = _persist("run1", True)      # initial confirm
        c2, p2 = _persist("run2", False)     # patched retest, same coordinates, new case
        self.assertNotEqual(c1, c2)          # distinct case identities across runs

        # both finding rows survived storage (R08 -- retest not IGNORE'd)
        rows = store.all_host_findings(ex.url)
        self.assertEqual({r["case_id"] for r in rows}, {c1, c2})

        exports = report_generator.export_issues_for_host(ex.url)
        self.assertEqual(len(exports), 1)                    # ONE stable issue
        exp = exports[0]
        pids = {r["proof_id"] for r in exp["proof_references"]}
        self.assertEqual(pids, {p1, p2})                     # BOTH attempts preserved
        verdicts = {r["proof_id"]: r.get("verdict") for r in exp["proof_references"]}
        self.assertEqual(verdicts[p1], "confirmed")          # exact verdict per proof (R09)
        self.assertEqual(verdicts[p2], "inconclusive")


if __name__ == "__main__":
    unittest.main()
