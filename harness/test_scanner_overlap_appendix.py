"""HU-8: reporting.scanner_overlap_appendix -- scanner-equivalent classes leave the
tester's main view (report) and the agent budget (worklist sweep).

Caller-level through the real store path (store.persist_findings /
persist_proof_record -> report_generator.generate_report_for_host) and the real
worklist_investigator.investigate_worklist loop over an EngagementState. Negative
controls: a proven credentialed CORS read stays in the main report; with the option
off the report is byte-identical and the sweep is unchanged.

Seeded generic findings on an .invalid host; no network, no model.
"""
from __future__ import annotations

import asyncio
import shutil
import tempfile
import unittest
from pathlib import Path

from harness import engagement, evidence, report_generator, scanner_overlap, store
from harness import worklist_investigator as wi
from harness.models import Finding, HttpExchange
from harness.role_crawl import RoleSession
from harness.validators import cors_validator

_URL = "http://overlap.invalid/api/items"
_APPENDIX = "## Appendix: Scanner-Equivalent Findings"
_ON = {"reporting": {"scanner_overlap_appendix": True}}
_OFF = {"reporting": {"scanner_overlap_appendix": False}}


def _undated(report: str) -> str:
    return "\n".join(line for line in report.splitlines() if not line.startswith("Generated:"))


def _exchange(url: str, method: str = "GET") -> HttpExchange:
    return HttpExchange(url=url, method=method, request_headers={}, request_body="",
                        response_status=200, response_headers={}, response_body="")


class _Store(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="hu8_overlap_")
        self._orig = store._DB_PATH
        store._DB_PATH = Path(self._tmp) / "state.db"

    def tearDown(self):
        store._DB_PATH = self._orig
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _seed(self, path: str, vuln_class: str, summary: str, *, severity="low",
              evidence_text="e", proof: tuple[str, str] | None = None) -> None:
        """Persist one finding. `proof` = (validator, observed_result) persists a
        confirmed proof record first and binds the finding to it."""
        kwargs = {}
        if proof is not None:
            case = evidence.TestCaseRef(run_id="run-hu8", request_template_id=path,
                                        check_id=vuln_class)
            record = evidence.ProofRecord.from_validation_result(
                case=case, validator=proof[0], status="confirmed", confirmed=True,
                observed_result=proof[1])
            ok, reason = store.persist_proof_record(record)
            self.assertTrue(ok, reason)
            kwargs = dict(confirmed=True, case_id=case.case_id, proof_id=record.proof_id)
        finding = Finding(vulnerability_class=vuln_class, severity=severity, confidence=0.8,
                          summary=summary, evidence=evidence_text, suggested_test="verify",
                          basis="derived", **kwargs)
        store.persist_findings(_exchange("http://overlap.invalid" + path), "agent", [finding])


class ReportAppendixTests(_Store):
    def setUp(self):
        super().setUp()
        self._seed_mixed()

    def _seed_mixed(self):
        self._seed("/a", "missing_headers", "HDR-1 missing X-Content-Type-Options")
        self._seed("/b", "Content Security Policy missing", "CSP-1 no policy")
        self._seed("/c", "cors", "CORS-1 wildcard origin hypothesis")
        self._seed("/d", "Security misconfiguration", "HDR-2 Missing X-Frame-Options header")
        self._seed("/e", "verbose_error_disclosure", "ERR-1 stack trace in 500 page")
        # A passive confirmation with a proof is still a scanner observation.
        self._seed("/f", "missing_headers", "HDR-3 confirmed nosniff absent",
                   proof=("security_headers_validator", "WSTG-CONF-02 header policy fails"))
        self._seed("/g", "sqli", "SQLI-1 concrete injection", severity="high")

    def _main(self, report: str) -> str:
        return report.split(_APPENDIX, 1)[0]

    def test_on_moves_unproven_header_csp_cors_items_to_a_counted_appendix(self):
        report = report_generator.generate_report_for_host(_URL, config=_ON)
        main = self._main(report)
        for marker in ("HDR-1", "HDR-2", "HDR-3", "CSP-1", "CORS-1", "ERR-1"):
            self.assertNotIn(marker, main, marker)
        self.assertIn("SQLI-1", main)
        self.assertIn("6 scanner-equivalent item(s) in the appendix", main)
        appendix = report.split(_APPENDIX, 1)[1]
        self.assertIn("| Missing security headers | 2 | 1 |", appendix)
        self.assertIn("| Clickjacking / framing | 1 | 0 |", appendix)
        self.assertIn("| Content-Security-Policy | 1 | 0 |", appendix)
        self.assertIn("| CORS policy | 1 | 0 |", appendix)
        self.assertIn("| Verbose error / stack trace | 1 | 0 |", appendix)
        # missing_headers is a host-wide class: /a and /f collapse to one line (x2).
        self.assertIn("HDR-3 confirmed nosniff absent", appendix)
        self.assertIn("confirmed (x2)", appendix)
        for marker in ("HDR-2", "CSP-1", "CORS-1", "ERR-1"):
            self.assertIn(marker, appendix, marker)
        self.assertNotIn("SQLI-1", appendix)

    def test_off_is_byte_identical_to_the_default_report(self):
        default = report_generator.generate_report_for_host(_URL)
        self.assertEqual(default, report_generator.generate_report_for_host(_URL, config={}))
        self.assertEqual(default, report_generator.generate_report_for_host(_URL, config=_OFF))
        # The default output equals generate_markdown_report without the new kwarg.
        findings = store.all_host_findings(_URL, include_chains=True)
        direct = report_generator.generate_markdown_report(store.host_of(_URL), findings)
        self.assertEqual(_undated(default), _undated(direct))
        self.assertNotIn(_APPENDIX, default)
        for marker in ("HDR-2", "HDR-3", "CSP-1", "CORS-1", "ERR-1", "SQLI-1"):
            self.assertIn(marker, default, marker)
        self.assertNotEqual(default, report_generator.generate_report_for_host(_URL, config=_ON))


class ExportSplitTests(_Store):
    """HU-8 (r7): the issue/SARIF export ignored the appendix. With the option on,
    the issues the report moves carry report_section (SARIF: reportSection) and
    no issue mixes main and appendix rows; off, the export is unchanged."""

    def setUp(self):
        super().setUp()
        ReportAppendixTests._seed_mixed(self)

    def _exports(self, config):
        return report_generator.export_issues_for_host(_URL, config=config)

    def _sarif(self, config):
        from harness import sarif_adapter
        return sarif_adapter.export_issues_to_sarif(self._exports(config))

    def test_on_tags_exactly_the_moved_items_in_issues_and_sarif(self):
        exports = self._exports(_ON)
        tagged = [e for e in exports if e.get("report_section")]
        untagged = [e for e in exports if not e.get("report_section")]
        self.assertTrue(tagged)
        self.assertEqual({e["report_section"] for e in tagged},
                         {report_generator.SCANNER_APPENDIX_SECTION})
        self.assertTrue(all(e["scanner_overlap_class"] for e in tagged))
        self.assertEqual([e["vulnerability_class"] for e in untagged], ["sqli"])
        results = self._sarif(_ON)["runs"][0]["results"]
        self.assertEqual(len(results), len(exports))
        sections = [r["properties"].get("reportSection") for r in results]
        self.assertEqual(sections.count(report_generator.SCANNER_APPENDIX_SECTION), len(tagged))
        self.assertEqual(sections.count(None), 1)

    def test_off_export_and_sarif_are_unchanged(self):
        default = self._exports(None)
        self.assertEqual(default, self._exports(_OFF))
        self.assertFalse(any("report_section" in e for e in default))
        off = self._sarif(_OFF)
        self.assertFalse(any("reportSection" in r["properties"]
                             for r in off["runs"][0]["results"]))
        # Off and on carry the same set of classes: the split tags, it never drops.
        self.assertEqual(sorted(e["vulnerability_class"] for e in default),
                         sorted(e["vulnerability_class"] for e in self._exports(_ON)))


class ProvenCorsStaysTests(_Store):
    """Negative control: a credentialed CORS read with a recorded proof stays."""

    def test_proven_credentialed_cors_read_stays_in_the_main_report(self):
        observed = ("CORS misconfiguration CONFIRMED: 1 vulnerability(ies) found   - Origin "
                    "Reflection: " + cors_validator._REFLECTION_CREDENTIALED_DETAIL)
        # The finding kept the agent's own evidence; the proof carries the leg's wording.
        self._seed("/me", "cors", "CORS-PROVEN credentialed read", severity="high",
                   evidence_text="agent saw a reflected origin",
                   proof=("cors_validator", observed))
        uncredentialed = ("CORS misconfiguration CONFIRMED: 1 vulnerability(ies) found   - "
                          "Origin Reflection: " + cors_validator._REFLECTION_UNCREDENTIALED_DETAIL)
        self._seed("/pub", "cors", "CORS-ANON uncredentialed reflection", severity="medium",
                   proof=("cors_validator", uncredentialed))
        self._seed("/x", "cors", "CORS-GUESS unproven", severity="high")
        report = report_generator.generate_report_for_host(_URL, config=_ON)
        main, appendix = report.split(_APPENDIX, 1)
        self.assertIn("CORS-PROVEN", main)
        self.assertNotIn("CORS-PROVEN", appendix)
        # Neither an uncredentialed reflection nor an unproven guess is an exception.
        self.assertNotIn("CORS-ANON", main)
        self.assertNotIn("CORS-GUESS", main)
        self.assertIn("| CORS policy | 2 | 1 |", appendix)


class ClassifierTests(unittest.TestCase):
    def test_emitted_scanner_classes_are_recognised(self):
        cases = {
            "missing_security_header": "missing_headers", "missing_headers": "missing_headers",
            "csp": "csp", "clickjacking": "clickjacking", "cors_misconfiguration": "cors",
            "Insecure cookie flags (HttpOnly missing)": "cookie_flags",
            "verbose_error_disclosure": "verbose_error",
            "information_disclosure_header": "server_banner",
            "JWT alg header hygiene": "jwt_header", "algorithm_confusion": "jwt_header",
        }
        for cls, want in cases.items():
            self.assertEqual(scanner_overlap.overlap_class({"vulnerability_class": cls}), want, cls)
        self.assertEqual(scanner_overlap.overlap_class(
            {"vulnerability_class": "Security misconfiguration", "validator": "security_headers_validator"}),
            "missing_headers")

    def test_real_classes_are_not_scanner_equivalent(self):
        for cls in ("sqli", "idor", "xss", "ssrf", "header_injection", "JWT weak secret",
                    "Security misconfiguration", "info_disclosure", "potential-attack-chain:xss+cors"):
            self.assertIsNone(scanner_overlap.overlap_class(
                {"vulnerability_class": cls, "summary": "debug endpoint exposed"}), cls)

    def test_forged_jwt_with_proof_is_a_proven_exception(self):
        forged = {"vulnerability_class": "jwt alg none accepted", "confirmed": True,
                  "proof_id": "p1", "validator": "jwt_forge"}
        self.assertTrue(scanner_overlap.is_proven_exception(forged))
        self.assertFalse(scanner_overlap.is_proven_exception(dict(forged, confirmed=False)))
        self.assertFalse(scanner_overlap.is_proven_exception(
            dict(forged, evidence_source="tool_reported")))
        # Severity alone never makes an exception.
        self.assertFalse(scanner_overlap.is_proven_exception(
            {"vulnerability_class": "cors", "severity": "critical", "confirmed": True,
             "proof_id": "p2", "evidence": "reflects origin"}))


# --------------------------------------------------------------------------- #
# Worklist budget
# --------------------------------------------------------------------------- #

_ROLES = [RoleSession(role="user", headers={"Authorization": "Bearer u"})]


def _state() -> engagement.EngagementState:
    """Two scanner-noise GET nodes ranked above one real query node."""
    st = engagement.EngagementState(host="overlap.invalid")
    for path, cls in (("/noise1", "cors"), ("/noise2", "missing_headers"), ("/real", None)):
        ep = st._ep("GET", path)
        ep.reachable_roles = ["user"]
        ep.template = {"query": "q=1", "body": "", "content_type": ""}
        if cls:
            ep.add_finding({"vulnerability_class": cls, "severity": "high",
                            "confidence": 0.9, "confirmed": False})
    return st


def _sweep(state, *, with_specialty=False, **kwargs):
    probed: list = []

    async def probe(exchange, hypothesis, specialty, step_budget):
        name = exchange.url.split("?")[0].rsplit("/", 1)[-1]
        probed.append((name, specialty) if with_specialty else name)
        return {"findings": []}

    summary: dict = {}
    asyncio.run(wi.investigate_worklist(probe, state, "http://overlap.invalid", _ROLES,
                                        max_nodes=1, summary_out=summary, **kwargs))
    return probed, summary


def _scanner_prompted_probes(node):
    """Stand-in for a probe a node's scanner findings would prompt (no such probe
    kind exists in _derive_probe today): the noise nodes get a `misconfig` probe
    ahead of their real injection probe."""
    probes = _REAL_DERIVE(node)
    if node.get("path", "").startswith("/noise"):
        return [("misconfig", "scanner-prompted")] + probes
    return probes


_REAL_DERIVE = wi._derive_probe


class WorklistBudgetTests(unittest.TestCase):
    def test_ranking_puts_noise_first(self):
        order = [n["path"] for n in _state().worklist()]
        self.assertEqual(order[-1], "/real")

    def test_on_query_bearing_noise_nodes_keep_their_injection_probe(self):
        """r7: a GET node with query parameters whose findings are all scanner
        classes lost its agent injection probe. It keeps it, on or off."""
        on, on_summary = _sweep(_state(), with_specialty=True, scanner_overlap_appendix=True)
        off, off_summary = _sweep(_state(), with_specialty=True)
        self.assertEqual(on, off)
        self.assertEqual(len(on), 1)
        self.assertEqual(on[0][1], "injection")
        self.assertNotIn(on[0][0], ("real",))  # the top-ranked (noise) node is probed
        self.assertEqual(on_summary["eligible"], 3)
        self.assertNotIn(wi.SKIP_SCANNER_OVERLAP, on_summary["skipped_by_reason"])
        self.assertEqual(on_summary["skipped_by_reason"], off_summary["skipped_by_reason"])

    def test_on_scanner_prompted_probes_take_no_slot_but_injection_stays(self):
        from unittest.mock import patch
        with patch.object(wi, "_derive_probe", _scanner_prompted_probes):
            on, _ = _sweep(_state(), with_specialty=True, scanner_overlap_appendix=True)
            off, _ = _sweep(_state(), with_specialty=True)
        # Off: the noise node's scanner-prompted probe spends the one slot.
        self.assertEqual(off[0][1], "misconfig")
        # On: that probe is dropped; the node's injection probe takes the slot.
        self.assertEqual(on[0][1], "injection")
        self.assertNotIn("misconfig", [s for _, s in on])

    def test_parameterless_noise_node_is_still_skipped(self):
        from unittest.mock import patch
        st = _state()
        for path in ("/noise1", "/noise2"):
            st._ep("GET", path).template = {"query": "", "body": "", "content_type": ""}
        with patch.object(wi, "_derive_probe", _scanner_prompted_probes):
            probed, summary = _sweep(st, scanner_overlap_appendix=True)
        self.assertEqual(probed, ["real"])
        self.assertEqual(summary["skipped_by_reason"], {wi.SKIP_SCANNER_OVERLAP: 2})
        self.assertTrue(all(s["next_action"] for s in summary["skipped"]))

    def test_off_behaviour_is_unchanged(self):
        probed, summary = _sweep(_state())
        self.assertEqual(len(probed), 1)
        self.assertNotEqual(probed, ["real"])
        self.assertEqual(summary["skipped_by_reason"], {wi.SKIP_BUDGET_EXHAUSTED: 2})
        self.assertEqual(_sweep(_state(), scanner_overlap_appendix=False), (probed, summary))

    def test_option_is_read_from_the_enclosing_run_config(self):
        from unittest.mock import patch
        from harness.run_context import RunContext

        async def go(cfg):
            probed: list = []

            async def probe(exchange, hypothesis, specialty, step_budget):
                probed.append(specialty)
                return {"findings": []}
            async with RunContext.create(allowed_hosts=["overlap.invalid"], config=cfg):
                await wi.investigate_worklist(probe, _state(), "http://overlap.invalid",
                                              _ROLES, max_nodes=1)
            return probed
        with patch.object(wi, "_derive_probe", _scanner_prompted_probes):
            self.assertEqual(asyncio.run(go(_ON)), ["injection"])
            self.assertEqual(asyncio.run(go(_OFF)), ["misconfig"])

    def test_a_structural_signal_keeps_a_noisy_node_in_the_budget(self):
        from unittest.mock import patch
        st = _state()
        for path in ("/noise1", "/noise2"):
            st._ep("GET", path).template = {"query": "", "body": "", "content_type": ""}
        st._ep("GET", "/noise1").object_scoped = True
        with patch.object(wi, "_derive_probe", _scanner_prompted_probes):
            probed, summary = _sweep(st, scanner_overlap_appendix=True)
        self.assertEqual(probed, ["noise1"])
        self.assertEqual(summary["skipped_by_reason"].get(wi.SKIP_SCANNER_OVERLAP), 1)

    def test_a_proven_finding_keeps_the_node_in_the_budget(self):
        node = {"findings": [{"vulnerability_class": "jwt alg none", "confirmed": True,
                              "proof_id": "p", "confirmed_by_leg": "jwt_forge"}]}
        self.assertFalse(scanner_overlap.is_scanner_equivalent_node(node))
        node["findings"].append({"vulnerability_class": "sqli", "confirmed": False})
        self.assertFalse(scanner_overlap.is_scanner_equivalent_node(node))


if __name__ == "__main__":
    unittest.main()
