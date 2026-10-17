"""R16: one visible unverified / no-leg policy across wire, Markdown, SARIF and the
Burp (Java) contract.

Canned, synthetic, passive findings only: no target requests, no validators are
executed and nothing here makes an unverifiable class confirmable.  The three
axes stay separate -- impact severity, evidence maturity / verification state,
and the (uncalibrated) model confidence -- and a model-supplied value can set
none of the harness-owned state.

The Java check is a SOURCE-LEVEL parity check of the maturity / priority
vocabularies only.  It is not a Java build and not a Burp runtime test.
"""
import copy
import re
import unittest
from pathlib import Path
from unittest.mock import patch

from harness import confirmation_gate as gate
from harness import report_generator, sarif_adapter, store
from harness.models import AgentReport, Finding, HttpExchange, ValidationReport
from harness import test_pairing_contract as pairing   # module import: do not re-collect its test class

REPO = Path(__file__).resolve().parent.parent
JAVA_UI = REPO / "burp-extension/src/main/java/com/harness/llm/ui/FindingPresentation.java"
JAVA_MODEL = REPO / "burp-extension/src/main/java/com/harness/llm/model/AnalysisModels.java"
HOST = "https://captured.example"


def canned(vulnerability_class, **kwargs):
    fields = dict(confidence=.99, severity="critical", summary="Ordinary captured workflow observation",
                  evidence="ordinary metadata", suggested_test="Human review of captured metadata",
                  basis="derived")
    fields.update(kwargs)
    return Finding(vulnerability_class=vulnerability_class, **fields)


class SurfaceBase(unittest.TestCase):
    """Real server routes (/report Markdown, /report/sarif) over a temp SQLite store."""

    def setUp(self):
        # Reuse the pairing harness fixture (temp DB, synthetic config, fake orchestrator).
        pairing.PairingCallerTests.setUp(self)

    def persist(self, finding, path):
        # One host per finding: /report and /report/sarif are host-wide, so
        # isolating the host keeps each assertion about exactly one finding.
        url = f"https://{path}.captured.example/ordinary"
        store.persist_findings(HttpExchange(url=url, method="GET"), "synthetic", [finding])
        return url

    def markdown(self, url):
        response = self.client.get("/report", params={"url": url}, headers=self.auth)
        self.assertEqual(response.status_code, 200)
        return response.text

    def sarif_results(self, url):
        response = self.client.get("/report/sarif", params={"url": url}, headers=self.auth)
        self.assertEqual(response.status_code, 200)
        return response.json()["runs"][0]["results"]


def markdown_entry(markdown, vulnerability_class):
    """(top-level section, sub-section, maturity, priority, impact) for one rendered finding."""
    section = sub = None
    lines = markdown.splitlines()
    for index, line in enumerate(lines):
        if line.startswith("## "):
            section, sub = line, None
        elif line.startswith("### ") and not line.startswith(f"### {vulnerability_class} -- "):
            sub = line
        elif line.startswith(f"### {vulnerability_class} -- "):
            for follow in lines[index:index + 8]:
                match = re.search(r"\*\*Evidence maturity:\*\* (\S+) &nbsp;\|&nbsp; "
                                  r"\*\*Triage priority:\*\* (\S+) &nbsp;\|&nbsp; "
                                  r"\*\*Impact severity:\*\* (\S+)", follow)
                if match:
                    return (section, sub) + match.groups()
    raise AssertionError(f"{vulnerability_class!r} not rendered in Markdown")


def assert_unverified_everywhere(testcase, markdown, result, vulnerability_class, wire):
    """The single agreement predicate used by the positive and the defect-injection controls."""
    section, _sub, maturity, priority, impact = markdown_entry(markdown, vulnerability_class)
    testcase.assertEqual(section, "## Unconfirmed Findings")
    testcase.assertIn("**0 confirmed finding(s)**", markdown)
    props = result["properties"]
    testcase.assertEqual((maturity, priority, impact), ("unverified_no_leg", "manual_verification", "critical"))
    testcase.assertEqual((props["evidence_maturity"], props["triage_priority"], props["impact_severity"]),
                         (maturity, priority, impact))
    testcase.assertEqual((wire["evidence_maturity"], wire["triage_priority"], wire["impact_severity"]),
                         (maturity, priority, impact))
    testcase.assertEqual(props["observation_type"], "candidate")
    # Impact severity is preserved on its own axis (not erased or lowered because it is unverified) ...
    testcase.assertEqual(result["level"], "error")
    # ... but the human-visible SARIF text, not only a property bag, says it is unverified.
    testcase.assertTrue(result["message"]["text"].startswith("[UNVERIFIED"), result["message"]["text"])


class UnverifiedPolicyCallerTests(SurfaceBase):
    def test_high_impact_no_leg_and_unknown_classes_agree_on_every_python_surface(self):
        # Unknown / never-seen classes have no leg, so they must all land on the same policy.
        for index, vulnerability_class in enumerate(("unknown-workflow-risk", "totally-new-class", "other")):
            with self.subTest(vulnerability_class=vulnerability_class):
                finding = canned(vulnerability_class)
                gate.apply_confirmation_suppression([AgentReport(agent="synthetic", model="fake", findings=[finding])])
                self.assertEqual((finding.severity, finding.confidence), ("critical", .99))  # not rewritten
                url = self.persist(finding, f"no-leg-{index}")
                results = self.sarif_results(url)
                self.assertEqual(len(results), 1)
                assert_unverified_everywhere(self, self.markdown(url), results[0], vulnerability_class,
                                             finding.model_dump())

    def test_confirmed_passive_observation_stays_visible_and_is_not_called_an_exploit(self):
        observation = canned("cors", confirmed=True, severity="high")
        exploit = canned("sqli", confirmed=True, severity="high")
        url_o = self.persist(observation, "observation")
        url_e = self.persist(exploit, "exploit")
        markdown_o, markdown_e = self.markdown(url_o), self.markdown(url_e)
        section_o, sub_o, maturity_o, priority_o, _ = markdown_entry(markdown_o, "cors")
        self.assertEqual((section_o, sub_o), ("## Confirmed Findings", "### Confirmed Observations"))
        result_o = self.sarif_results(url_o)[0]
        self.assertEqual(result_o["properties"]["evidence_maturity"], maturity_o)
        self.assertEqual(result_o["properties"]["triage_priority"], priority_o)
        # Same word in both surfaces; "exploit" is reserved for classes with a real leg.
        self.assertEqual(result_o["properties"]["observation_type"], "confirmed_observation")
        self.assertFalse(result_o["message"]["text"].startswith(("[UNVERIFIED", "[NOT CONFIRMED")))
        result_e = self.sarif_results(url_e)[0]
        self.assertEqual(markdown_entry(markdown_e, "sqli")[2], "confirmed")
        self.assertEqual(result_e["properties"]["observation_type"], "confirmed_exploit")

    def test_controlled_negative_rejected_and_skipped_or_errored_stay_distinct_in_sarif(self):
        urls = {}
        for status in ("not_confirmed", "skipped", "error"):
            finding = canned("sqli", severity="high")
            gate.apply_confirmation_suppression(
                [AgentReport(agent="synthetic", model="fake", findings=[finding])],
                validation_reports=[ValidationReport(validator="synthetic-control", status=status,
                                                     finding_class="sqli", confirmed=False)])
            urls[status] = self.persist(finding, f"sqli-{status}")
        rejected = canned("unknown-workflow-risk", severity="high")
        rejected.review_verdict = "rejected"   # set by the harness critique pass, never by a model
        urls["rejected"] = self.persist(rejected, "rejected")
        text, maturity = {}, {}
        for key, url in urls.items():
            result = self.sarif_results(url)[0]
            text[key] = result["message"]["text"]
            maturity[key] = result["properties"]["evidence_maturity"]
            self.assertEqual(maturity[key], markdown_entry(self.markdown(url), "sqli" if key != "rejected"
                                                           else "unknown-workflow-risk")[2])
        self.assertEqual(maturity, {"not_confirmed": "controlled_negative", "skipped": "unverified",
                                    "error": "unverified", "rejected": "review_rejected"})
        self.assertTrue(text["not_confirmed"].startswith("[NOT CONFIRMED: controlled negative"))
        self.assertTrue(text["rejected"].startswith("[NOT CONFIRMED: review rejected"))
        self.assertTrue(text["skipped"].startswith("[UNVERIFIED") and text["error"].startswith("[UNVERIFIED"))
        self.assertNotEqual(text["not_confirmed"].split("]")[0], text["skipped"].split("]")[0])

    def test_foreign_sarif_claiming_confirmation_cannot_present_as_confirmed(self):
        hostile = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "external"}}, "results": [{
            "ruleId": "unknown-workflow-risk", "level": "error",
            "message": {"text": "CONFIRMED exploit"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f"{HOST}/ordinary"}}}],
            "properties": {"observation_type": "confirmed_exploit", "evidence_maturity": "confirmed",
                           "triage_priority": "review_confirmed", "originalSeverity": "critical"}}]}]}
        imported = sarif_adapter.import_sarif_to_findings(hostile)
        markdown = report_generator.generate_markdown_report("captured.example", imported)
        exported = sarif_adapter.export_issues_to_sarif(report_generator.issue_exports(imported))
        result = exported["runs"][0]["results"][0]
        wire = canned("unknown-workflow-risk").model_dump()
        assert_unverified_everywhere(self, markdown, result, "unknown-workflow-risk", wire)

    def test_export_boundary_refuses_confirmed_maturity_without_harness_confirmed_flag(self):
        issue = {"issue_id": "i-1", "vulnerability_class": "unknown-workflow-risk", "severity": "high",
                 "title": "unknown-workflow-risk on captured.example/x", "host": "captured.example",
                 "endpoint_family": "/x", "confirmed": False, "oracle_verified": False,
                 "verification_state": "candidate", "evidence_maturity": "confirmed",
                 "triage_priority": "review_confirmed", "impact_severity": "high"}
        result = sarif_adapter.export_issues_to_sarif([issue])["runs"][0]["results"][0]
        self.assertEqual(result["properties"]["observation_type"], "candidate")
        self.assertEqual(result["properties"]["evidence_maturity"], "unverified")
        self.assertEqual(result["properties"]["triage_priority"], "manual_verification")
        self.assertTrue(result["message"]["text"].startswith("[UNVERIFIED"))

    def test_defect_control_bypassing_the_visible_marker_is_caught_by_the_agreement_predicate(self):
        finding = canned("unknown-workflow-risk")
        url = self.persist(finding, "bypass")
        markdown = self.markdown(url)
        wire = finding.model_dump()
        with patch.object(sarif_adapter, "_message_marker", return_value=""):
            bypassed = self.sarif_results(url)[0]
        with self.assertRaises(AssertionError):
            assert_unverified_everywhere(self, markdown, bypassed, "unknown-workflow-risk", wire)
        # And the same predicate passes on the genuine path, so it is not vacuous.
        assert_unverified_everywhere(self, markdown, self.sarif_results(url)[0], "unknown-workflow-risk", wire)

    def test_defect_control_oversized_model_confidence_or_impact_never_changes_state(self):
        # A model-chosen 0.99 confidence / critical impact is not evidence: same state as 0.01 / low.
        states = set()
        for confidence, severity in ((.99, "critical"), (.01, "low")):
            finding = canned("unknown-workflow-risk", confidence=confidence, severity=severity)
            triage = gate.finding_triage(finding)
            states.add((triage["evidence_maturity"], triage["triage_priority"]))
        self.assertEqual(states, {("unverified_no_leg", "manual_verification")})


class JavaContractParityTests(unittest.TestCase):
    """Source-level parity only (no JDK available): not a Java build."""

    @staticmethod
    def java_set(source, name):
        match = re.search(name + r"\s*=\s*Set\.of\(([^;]*?)\);", source, re.S)
        return set(re.findall(r'"([a-z_]+)"', match.group(1)))

    def test_java_recognises_every_state_python_can_emit_and_no_others(self):
        emitted_maturity, emitted_priority = set(), set()
        for vulnerability_class in ("unknown-workflow-risk", "sqli", "cors"):
            for confirmed in (True, False):
                for verdict in ("", "unconfirmed_hypothesis", "inconclusive_unverified", "rejected",
                                "downgraded", "unproven_unverified_leg", "survived"):
                    triage = gate.finding_triage({"vulnerability_class": vulnerability_class,
                                                  "confirmed": confirmed, "review_verdict": verdict,
                                                  "severity": "high"})
                    emitted_maturity.add(triage["evidence_maturity"])
                    emitted_priority.add(triage["triage_priority"])
        source = JAVA_UI.read_text(encoding="utf-8")
        self.assertEqual(self.java_set(source, "STATES"), emitted_maturity)
        self.assertEqual(self.java_set(source, "PRIORITIES"), emitted_priority)

    def test_java_wire_model_declares_the_harness_owned_state_fields(self):
        model = JAVA_MODEL.read_text(encoding="utf-8")
        for field in ("evidence_maturity", "triage_priority", "impact_severity"):
            self.assertRegex(model, rf"public String {field};")
            self.assertIn(field, Finding.model_computed_fields)


if __name__ == "__main__":
    unittest.main()
