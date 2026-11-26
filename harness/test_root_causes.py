"""EFF-3: occurrences, issues and root causes are three counts, each with its unit.

r11 reported "117 unique" vulnerabilities: one group per proof-bound case. By root cause
it had about 16-18 (r11-postmortem.md). One CSP policy was 135 records, and 15 groups
were a proof of one class filed under another. The unit tests pin issues.root_cause_key's
rules on r11-shaped records. The caller tests run the real issue accounting, the real
store and report, and the server job and manifest. Every root-cause assertion has the
old issue_key (or per-case) count beside it as its negative control.
"""
import importlib
import inspect
import json
import pkgutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from harness import issues, store
from harness.assessment_health import (VULNERABILITY_COUNT_UNITS, confirmed_issue_accounting,
                                       headline_counts)
from harness.issues import (ISSUE_UNITS, ROOT_CAUSE_MECHANISMS, count_units, issue_class, issue_key,
                            root_cause_class, root_cause_key)

HOST = "http://127.0.0.1:3002"
# api_security_validator's wording for the r11 password digest inside the session token.
TOKEN_PROOF = ("Excessive data exposure: the API accepts a session token whose payload carries "
               "a credential field (password) to an authenticated caller.")
FIELD_PROOF = "Excessive data exposure: GET /api/Users returns 2 unmasked credential field(s)."


def rec(route, vc, **kw):
    return {"url": HOST + route, "method": kw.pop("method", "GET"), "vulnerability_class": vc, **kw}


def r11_csp_records():
    """r11's CSP pile as stored: 135 csp records confirmed by csp_validator over 54 URLs,
    plus the label variants filed for the same missing policy, confirmed or not."""
    confirmed = {"confirmed": True, "validator": "csp_validator", "policy_fingerprint": "fp-r11"}
    rows = [rec(f"/route{n % 54}/view?id={n}", "csp", **confirmed) for n in range(135)]
    rows += [rec("/page0", "Missing Content Security Policy", **confirmed),
             rec("/", "CSP Weakness", **confirmed)]
    rows += [rec(f"/page{n}", "Missing Content Security Policy") for n in (1, 2, 3)]
    rows += [rec("/rest/admin", "missing_csp_header"),
             # The label is unread; r11's summary names the header (scanner_overlap).
             rec("/api-key", "MissingContentSecurityPolicy",
                 summary="The error page returned for /api-key lacks a Content-Security-Policy "
                         "header, leaving the page vulnerable to clickjacking and XSS attacks.")]
    return rows


def roots(rows):
    return {root_cause_key(r) for r in rows}


def old_issues(rows):
    return {issue_key(r) for r in rows}


class RootCauseRuleTests(unittest.TestCase):
    def test_r11_csp_pile_is_one_root_cause(self):
        rows = r11_csp_records()
        self.assertEqual(len(roots(rows)), 1)
        self.assertEqual(root_cause_key(rows[0]), (HOST, "config", "csp"))
        # Negative control: the old issue_key count splits the same records.
        self.assertGreater(len(old_issues(rows)), 1)

    def test_header_and_config_classes_group_per_host_and_class(self):
        other = "http://shop.invalid"
        rows = [rec("/a", "Missing HSTS header"), rec("/b", "Missing Strict-Transport-Security header"),
                rec("/c", "Missing X-Frame-Options header"), rec("/d", "csp"),
                rec("/e", "Cookie without HttpOnly flag"), rec("/f", "Cookie missing Secure flag"),
                rec("/g", "cors", header_fingerprint="one"), rec("/h", "cors", header_fingerprint="two"),
                {"url": other + "/g", "vulnerability_class": "cors", "method": "GET"}]
        keys = [root_cause_key(r) for r in rows]
        self.assertEqual(keys[0], keys[1])                       # HSTS: missing_headers
        self.assertEqual(keys[2], keys[3])                       # framing is filed as csp
        self.assertEqual(keys[4], keys[5])                       # cookie flags
        self.assertEqual(keys[6], keys[7])                       # one host's CORS policy
        self.assertNotEqual(keys[6], keys[8])                    # another host's is its own
        self.assertEqual(len(set(keys)), 5)
        self.assertEqual({k[1] for k in keys}, {"config"})
        # Negative control: the old count keeps the two CORS policies apart.
        self.assertNotEqual(issue_key(rows[6]), issue_key(rows[7]))

    def test_injection_on_two_parameters_is_two_root_causes(self):
        rows = [rec("/rest/products/search?q=1", "sqli", confirmed=True, validator="sqlmap",
                    parameter_location="query", parameter_name="q"),
                rec("/rest/products/search?q=2", "sqli", confirmed=True, validator="sqlmap",
                    parameter_location="query", parameter_name="q", method="POST"),
                rec("/rest/products/search?sort=x", "sqli", confirmed=True, validator="sqlmap",
                    parameter_location="query", parameter_name="sort")]
        self.assertEqual(len(roots(rows)), 2)
        self.assertEqual(root_cause_key(rows[0])[1:],
                         ("injection", "/rest/products/search", "query:q", "sqli"))
        # Negative control: the old count also splits the method (read/write boundary).
        self.assertEqual(len(old_issues(rows)), 3)

    def test_injection_on_one_parameter_across_object_ids_is_one(self):
        rows = [rec(f"/api/Products/{n}/reviews", "xss", confirmed=True, validator="stored_xss",
                    parameter_location="body_json", parameter_name="message") for n in (1, 2, 3)]
        self.assertEqual(len(roots(rows)), 1)

    def test_wrong_class_duplicates_add_no_root_causes(self):
        well_known = [rec("/.well-known/csaf/provider-metadata.json", label, confirmed=True,
                          validator="well_known_validator")
                      for label in ("sqli", "jwt", "idor", "recon")]
        session = [rec(route, label, confirmed=True, validator="api_security_validator",
                       proof_observed_result=TOKEN_PROOF)
                   for route, label in (("/rest/2fa/status", "sqli"), ("/rest/2fa/status", "xss"),
                                        ("/rest/2fa/status", "ssti"), ("/rest/saveLoginIp", "api_security"),
                                        ("/api/Addresss", "command_injection"))]
        self.assertEqual(len(roots(well_known)), 1)
        self.assertEqual(root_cause_class(well_known[0]), "recon")
        self.assertEqual(len(roots(session)), 1)
        self.assertEqual(root_cause_key(session[0]), (HOST, "session", "api_security"))
        # Negative control: the old count keeps each label as its own issue.
        self.assertEqual(len(old_issues(well_known)), 4)
        self.assertEqual(len(old_issues(session)), 5)

    def test_unconfirmed_label_keeps_its_class(self):
        lead = rec("/rest/2fa/status", "sqli", parameter_location="query", parameter_name="id")
        proven = rec("/rest/2fa/status", "sqli", confirmed=True, validator="api_security_validator",
                     proof_observed_result=TOKEN_PROOF)
        self.assertEqual(root_cause_class(lead), "sqli")
        self.assertNotEqual(root_cause_key(lead), root_cause_key(proven))

    def test_response_field_exposure_is_per_endpoint_not_the_token(self):
        users = rec("/api/Users", "api_security", confirmed=True, validator="api_security_validator",
                    proof_observed_result=FIELD_PROOF)
        token = rec("/api/Users", "api_security", confirmed=True, validator="api_security_validator",
                    proof_observed_result=TOKEN_PROOF)
        self.assertEqual(root_cause_key(users), (HOST, "endpoint", "/api/users", "api_security"))
        self.assertEqual(root_cause_key(token)[1], "session")

    def test_access_control_groups_per_template_and_unordered_principal_pair(self):
        one_to_two = rec("/api/BasketItems/9", "idor", confirmed=True, validator="cross_identity",
                         principal_id="eval-user-1", captured_principal_id="captured:aa",
                         proof_observed_result="Cross-identity (eval-user-2): Identity A's own ...")
        two_to_one = rec("/api/BasketItems/10", "idor", confirmed=True, validator="cross_identity",
                         principal_id="eval-user-2", captured_principal_id="captured:bb",
                         proof_observed_result="Cross-identity (eval-user-1): Identity A's own ...")
        write = rec("/api/BasketItems/10", "bfla", confirmed=True, validator="cross_identity",
                    method="PUT", principal_id="eval-user-2",
                    proof_observed_result="Broken object-level write authorization: 'eval-user-1' PUT ...")
        admin = rec("/api/BasketItems/11", "idor", confirmed=True, validator="cross_identity",
                    principal_id="admin", proof_observed_result="Cross-identity (eval-user-1): ...")
        self.assertEqual(root_cause_key(one_to_two),
                         (HOST, "access", "/api/basketitems/{id}", ("eval-user-1", "eval-user-2")))
        self.assertEqual(root_cause_key(one_to_two), root_cause_key(two_to_one))
        self.assertEqual(root_cause_key(write)[3], ("eval-user-1", "eval-user-2"))
        self.assertNotEqual(root_cause_key(admin), root_cause_key(one_to_two))
        # Negative control: the old count splits the read and the write.
        self.assertNotEqual(issue_key(two_to_one), issue_key(write))

    def test_endpoint_rule_folds_case_and_keeps_distinct_unread_labels(self):
        metrics = [rec(route, label, confirmed=True, validator="metrics_exposure_validator")
                   for route, label in (("/metrics", "exposed_metrics_endpoint"),
                                        ("/Metrics", "exposed metrics endpoint"),
                                        ("/metrics/", "auth"))]
        self.assertEqual(len(roots(metrics)), 1)
        unread = [rec("/socket.io", "websocket"), rec("/socket.io", "session identifier exposed in body")]
        self.assertEqual(len(roots(unread)), 2)
        # An unread label with no header named anywhere is not folded into the CSP root.
        bare = rec("/api-key", "MissingContentSecurityPolicy")
        self.assertNotEqual(root_cause_key(bare), (HOST, "config", "csp"))

    def test_dependency_advisory_and_chain(self):
        dep = rec("/", "known-vulnerable-dependency:express")
        self.assertEqual(root_cause_key(dep), (HOST, "dependency", "known-vulnerable-dependency:express"))
        self.assertIsNone(root_cause_key(rec("/", "potential-attack-chain:sqli->idor")))

    def test_count_units_names_each_unit(self):
        rows = [*r11_csp_records(), rec("/", "potential-attack-chain:a->b")]
        counts = count_units(rows)
        self.assertEqual(counts["occurrences"], 142)
        self.assertEqual(counts["root_causes"], 1)
        self.assertEqual(counts["issues"], len(old_issues(rows[:-1])))
        self.assertEqual(set(counts["units"]), {"occurrences", "issues", "root_causes"})
        for unit in counts["units"].values():
            self.assertNotIn("unique", unit.lower())


class RootCauseTableGuardTests(unittest.TestCase):
    """The static tables read validator names and proof wording: a rename breaks here."""

    def test_every_mechanism_is_a_real_validator_name(self):
        import harness.validators as package
        from harness.validators.base import Validator
        for info in pkgutil.iter_modules(package.__path__):
            importlib.import_module(f"harness.validators.{info.name}")
        names, stack = set(), list(Validator.__subclasses__())
        while stack:
            cls = stack.pop()
            stack.extend(cls.__subclasses__())
            if isinstance(getattr(cls, "name", None), str):
                names.add(cls.name)
        self.assertEqual(set(ROOT_CAUSE_MECHANISMS) - names, set())

    def test_every_proven_class_is_a_class_fixed_point(self):
        for mechanism, classes in ROOT_CAUSE_MECHANISMS.items():
            for cls in classes:
                self.assertEqual(issue_class(cls), cls, mechanism)

    def test_proof_wording_markers_are_the_validators_own(self):
        from harness.validators import api_security_validator, cross_identity_validator
        api = inspect.getsource(api_security_validator)
        self.assertIn(issues._TOKEN_CLAIM_MARK, api)
        self.assertIn(issues._RESPONSE_FIELD_MARK, api)
        cross = inspect.getsource(cross_identity_validator)
        self.assertIn('summary=f"Cross-identity ({', cross)
        self.assertIn('summary=(f"Broken object-level write authorization: {', cross)


def proof(pid, case, validator, *, principal="eval-user-1", location="", name="", observed=""):
    return {"proof_id": pid, "case": {"case_id": case, "run_id": "run", "principal_id": principal,
                                      "parameter_location": location, "parameter_name": name,
                                      "request_template_id": "request-" + case, "check_id": validator},
            "validator": validator, "verdict": "confirmed", "executed": True, "legacy": False,
            "baseline_artifact_id": "b-" + pid, "attack_artifact_id": "a-" + pid,
            "control_artifact_ids": ["control-" + pid], "observed_result": observed}


def finding(p, route, vc):
    return {"confirmed": True, "proof_id": p["proof_id"], "case_id": p["case"]["case_id"],
            "url": HOST + route, "vulnerability_class": vc}


def r11_vulnerability_fixture():
    """Seven proof-bound cases, as r11 grouped them, showing three root causes."""
    proofs = [proof("t1", "t1", "api_security_validator", observed=TOKEN_PROOF),
              proof("t2", "t2", "api_security_validator", principal="eval-user-2", observed=TOKEN_PROOF),
              proof("t3", "t3", "api_security_validator", observed=TOKEN_PROOF),
              proof("q1", "q1", "sqlmap", location="query", name="q"),
              proof("q2", "q2", "sqlmap", principal="eval-user-2", location="query", name="q"),
              proof("e1", "e1", "sqlmap", location="body_json", name="email"),
              proof("c1", "c1", "csp_validator")]
    routes = {"t1": ("/rest/2fa/status", "sqli"), "t2": ("/rest/2fa/status", "xss"),
              "t3": ("/rest/saveLoginIp", "api_security"), "q1": ("/rest/products/search", "sqli"),
              "q2": ("/rest/products/search", "sqli"), "e1": ("/rest/user/login", "sqli"),
              "c1": ("/", "csp")}
    return proofs, [finding(p, *routes[p["proof_id"]]) for p in proofs]


class AccountingCallerTests(unittest.TestCase):
    def account(self, findings, proofs):
        return confirmed_issue_accounting(findings, "run",
                                          lambda cid: [p for p in proofs if p["case"]["case_id"] == cid],
                                          run_proofs=proofs, artifact_resolver=lambda p: True)

    def test_vulnerability_groups_and_root_causes_are_separate_counts(self):
        proofs, findings = r11_vulnerability_fixture()
        result = self.account(findings, proofs)
        counts = result["counts"]
        self.assertEqual(counts["vulnerability_root_causes"], 3)
        self.assertEqual(counts["hardening_root_causes"], 1)
        # Negative control: the per-case count runs report as "vulnerabilities".
        self.assertEqual(counts["vulnerabilities"], 6)
        self.assertEqual(headline_counts(result)["confirmed_vulnerability_root_causes"], 3)
        groups = [g for g in result["groups"] if g["kind"] == "vulnerability"]
        self.assertTrue(all(len(g["root_cause_ids"]) == 1 for g in groups))
        self.assertEqual(len({g["root_cause_ids"][0] for g in groups}), 3)

    def test_explicit_root_cause_id_stays_the_operators(self):
        proofs, findings = r11_vulnerability_fixture()
        findings = [dict(f, root_cause_id="one-root") if f["proof_id"] in ("q1", "e1") else f
                    for f in findings]
        counts = self.account(findings, proofs)["counts"]
        self.assertEqual(counts["vulnerability_root_causes"], 3)  # q2 alone keeps the q root

    def test_no_unit_says_unique(self):
        proofs, findings = r11_vulnerability_fixture()
        units = self.account(findings, proofs)["units"]
        self.assertIn("root_causes", units)
        for name, unit in units.items():
            self.assertNotIn("unique", unit.lower(), name)


class ReportCallerTests(unittest.TestCase):
    """Store -> findings API -> report for the r11 CSP pile and two injectable inputs."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._orig = store._DB_PATH
        store._DB_PATH = Path(self._tmp.name) / "state.db"

    def tearDown(self):
        store._DB_PATH = self._orig
        self._tmp.cleanup()

    def _persist(self, route, vc, method="GET", **kw):
        from harness.models import Finding, HttpExchange
        f = Finding(vulnerability_class=vc, confidence=0.8, severity="medium", summary=f"{vc} on {route}",
                    evidence="e", suggested_test="t", basis="derived", **kw)
        store.persist_findings(HttpExchange(url=HOST + route, method=method), vc, [f])

    def test_report_headline_names_each_count_with_its_unit(self):
        from harness.report_generator import generate_markdown_report
        for n in range(54):
            self._persist(f"/route{n}/view", "csp")
        self._persist("/api/Products/1?q=a", "sqli", parameter_location="query", parameter_name="q")
        # The same input written: one root cause, a second issue (write boundary).
        self._persist("/api/Products/2?q=b", "sqli", method="POST", parameter_location="query",
                      parameter_name="q")
        self._persist("/api/Products/3?sort=a", "sqli", parameter_location="query", parameter_name="sort")
        rows = store.all_host_findings(HOST)
        self.assertEqual(len(rows), 57)
        old = len({issue_key(r) for r in rows})
        md = generate_markdown_report("127.0.0.1", rows)
        self.assertIn("Counts: **57 occurrence(s)** (finding records), "
                      f"**{old} issue(s)** (issue-key groups), "
                      "**3 root cause(s)** (root-cause groups); "
                      "**0 root cause(s) with a confirmed record**.", md)
        # Negative control: the issue-key count is not the root-cause count.
        self.assertNotEqual(old, 3)
        self.assertNotIn("unique", md.lower())


class ServerAndManifestCallerTests(unittest.TestCase):
    def test_result_finding_summary_and_manifest_carry_units(self):
        from harness import assessment_health
        from harness.test_job_status_passive import DurableJobCallerTests
        fixture = DurableJobCallerTests("test_completed_job_survives_registry_loss_without_reexecution")
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        proofs, findings = r11_vulnerability_fixture()
        stored = r11_csp_records()

        async def investigate(*args, **kwargs):
            for p in proofs:
                p["case"]["run_id"] = kwargs["run_context"].run_id
            return {"findings": findings}
        fixture.server.orchestrator.investigate_engagement = investigate
        with patch.object(store, "proofs_for_case",
                          side_effect=lambda c: [p for p in proofs if p["case"]["case_id"] == c]), \
                patch.object(store, "proofs_for_run", return_value=proofs), \
                patch.object(fixture.server, "_attempt_findings", return_value=stored), \
                patch.object(assessment_health, "stored_proof_artifacts_resolve", return_value=True):
            done = fixture.poll(fixture.start(), "done")
        manifest = json.loads(Path(done["manifest_path"]).read_text())
        for result in (done["result"], manifest):
            self.assertEqual(result["confirmed_vulnerability_root_causes"], 3)
            self.assertEqual(result["confirmed_vulnerability_root_causes_unit"], "root_causes")
            # Negative control: the per-case headline, now beside its unit.
            self.assertEqual(result["confirmed_vulnerabilities"], 6)
            self.assertEqual(result["confirmed_vulnerabilities_unit"],
                             VULNERABILITY_COUNT_UNITS["confirmed_vulnerabilities"])
        units = done["result"]["finding_summary"]["issue_units"]
        self.assertEqual((units["occurrences"], units["root_causes"]), (142, 1))
        self.assertGreater(units["issues"], 1)
        self.assertEqual(units["units"], ISSUE_UNITS)


if __name__ == "__main__":
    unittest.main()
