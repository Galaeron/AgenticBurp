import tempfile
import unittest
from pathlib import Path

from harness import store
from harness.models import HttpExchange, Finding
from harness.report_generator import generate_markdown_report, generate_report_for_host, _confidence_label, _basis_note


def sample(url="https://example.com/api/x", vulnerability_class="sqli", severity="critical",
           confidence=0.9, summary="s", evidence="e", suggested_test="t",
           owasp_category=None, basis="derived", confirmed=False, agent="sqli_agent"):
    return {"url": url, "vulnerability_class": vulnerability_class, "severity": severity,
            "confidence": confidence, "summary": summary, "evidence": evidence,
            "suggested_test": suggested_test, "owasp_category": owasp_category,
            "basis": basis, "confirmed": confirmed, "agent": agent}


class TestConfidenceAndBasisLabels(unittest.TestCase):
    def test_confidence_labels_are_ordered_correctly(self):
        self.assertEqual(_confidence_label(0.95), "very likely")
        self.assertEqual(_confidence_label(0.7), "likely")
        self.assertEqual(_confidence_label(0.4), "possible")
        self.assertEqual(_confidence_label(0.1), "speculative")

    def test_derived_basis_has_no_warning_note(self):
        self.assertEqual(_basis_note("derived"), "Derived directly from what's visible in the captured traffic.")

    def test_assumed_and_recalled_have_warning_language(self):
        self.assertIn("confirm", _basis_note("assumed").lower())
        self.assertIn("confirm", _basis_note("recalled").lower())


class TestReportStructure(unittest.TestCase):
    def test_remediation_shaped_suggested_test_is_not_labelled_reproduction(self):
        # Weakness #5: "rotate the signing key" is remediation, not reproduction.
        findings = [sample(vulnerability_class="jwt", confirmed=True, evidence="HMAC-verified key",
                           suggested_test="Rotate the signing key and invalidate issued tokens.")]
        report = generate_markdown_report("example.com", findings)
        self.assertNotIn("Steps to reproduce:** Rotate the signing key", report)
        self.assertIn("Fix note (from the detector):** Rotate the signing key", report)
        # reproduction falls back to replaying the captured evidence
        self.assertIn("replay the exact captured request", report)

    def test_real_reproduction_step_is_still_labelled_reproduction(self):
        findings = [sample(vulnerability_class="sqli", confirmed=True,
                           suggested_test="Send q=1' OR '1'='1 and observe the full row set.")]
        report = generate_markdown_report("example.com", findings)
        self.assertIn("Steps to reproduce:** Send q=1'", report)

    def test_confirmed_and_unconfirmed_are_separated(self):
        findings = [
            sample(vulnerability_class="sqli", confirmed=True),
            sample(vulnerability_class="xss", confirmed=False),
        ]
        report = generate_markdown_report("example.com", findings)
        self.assertIn("## Confirmed Findings", report)
        self.assertIn("## Unconfirmed Findings", report)
        confirmed_idx = report.index("## Confirmed Findings")
        unconfirmed_idx = report.index("## Unconfirmed Findings")
        sqli_idx = report.index("sqli --")
        xss_idx = report.index("xss --")
        self.assertLess(confirmed_idx, sqli_idx)
        self.assertLess(unconfirmed_idx, xss_idx)

    def test_confirmed_exploits_and_observations_are_split(self):
        # 2026-09-17 coverage-recovery plan, Step 4: a passive header/content
        # observation (CORS, no exploit-confirmation leg at all) that happens
        # to set confirmed=True is visible, but distinguished from an actual
        # confirmed exploit (SQLi) -- not bundled into one undifferentiated
        # "confirmed" pile.
        findings = [
            sample(vulnerability_class="sqli", confirmed=True),
            sample(vulnerability_class="cors", confirmed=True),
        ]
        report = generate_markdown_report("example.com", findings)
        self.assertIn("## Confirmed Findings", report)
        self.assertIn("### Confirmed Exploits", report)
        self.assertIn("### Confirmed Observations", report)
        exploits_idx = report.index("### Confirmed Exploits")
        observations_idx = report.index("### Confirmed Observations")
        sqli_idx = report.index("sqli --")
        cors_idx = report.index("cors --")
        self.assertLess(exploits_idx, sqli_idx)
        self.assertLess(observations_idx, cors_idx)
        # both are still counted in the overall confirmed total
        self.assertIn("2 confirmed finding(s)", report)

    def test_no_split_rendered_when_all_confirmed_are_exploits(self):
        # Purely additive: a report with no observation-class confirmations
        # renders exactly as before -- no empty "Confirmed Observations"
        # section, no subheadings clutter.
        findings = [sample(vulnerability_class="sqli", confirmed=True)]
        report = generate_markdown_report("example.com", findings)
        self.assertNotIn("### Confirmed Exploits", report)
        self.assertNotIn("### Confirmed Observations", report)

    def test_confirmed_status_badge_present(self):
        findings = [sample(confirmed=True)]
        report = generate_markdown_report("example.com", findings)
        self.assertIn("✅ CONFIRMED", report)

    def test_suspected_status_badge_present(self):
        # W-7: an open unconfirmed hypothesis renders as SUSPECTED, not a bare
        # "UNCONFIRMED" -- distinct from a demoted LEAD.
        findings = [sample(confirmed=False)]
        report = generate_markdown_report("example.com", findings)
        self.assertIn("❓ SUSPECTED", report)

    def test_lead_status_badge_present(self):
        # W-7: an unconfirmed finding a reliable leg refuted renders as LEAD.
        f = sample(confirmed=False)
        f["review_verdict"] = "unconfirmed_hypothesis"
        report = generate_markdown_report("example.com", [f])
        self.assertIn("🔻 LEAD", report)

    def test_assumed_basis_gets_a_warning_callout(self):
        findings = [sample(basis="assumed")]
        report = generate_markdown_report("example.com", findings)
        self.assertIn("⚠️", report)

    def test_derived_basis_gets_no_warning_callout(self):
        findings = [sample(basis="derived")]
        report = generate_markdown_report("example.com", findings)
        self.assertNotIn("⚠️", report)

    def test_findings_sorted_by_severity_then_confidence(self):
        findings = [
            sample(vulnerability_class="low_one", severity="low", confidence=0.9),
            sample(vulnerability_class="critical_one", severity="critical", confidence=0.5),
            sample(vulnerability_class="high_one", severity="high", confidence=0.9),
        ]
        report = generate_markdown_report("example.com", findings)
        crit_idx = report.index("critical_one")
        high_idx = report.index("high_one")
        low_idx = report.index("low_one")
        self.assertLess(crit_idx, high_idx)
        self.assertLess(high_idx, low_idx)

    def test_evidence_rendered_in_code_block(self):
        findings = [sample(evidence="response length differs by 40 bytes")]
        report = generate_markdown_report("example.com", findings)
        self.assertIn("response length differs by 40 bytes", report)
        self.assertIn("```", report)

    def test_owasp_category_rendered_when_present(self):
        findings = [sample(owasp_category="A03:2021-Injection")]
        report = generate_markdown_report("example.com", findings)
        self.assertIn("A03:2021-Injection", report)

    def test_owasp_category_omitted_when_absent(self):
        findings = [sample(owasp_category=None)]
        report = generate_markdown_report("example.com", findings)
        self.assertNotIn("OWASP category", report)

    def test_remediation_present_for_known_category(self):
        findings = [sample(vulnerability_class="sqli")]
        report = generate_markdown_report("example.com", findings)
        self.assertIn("parameterized queries", report)

    def test_remediation_falls_back_for_unknown_category(self):
        findings = [sample(vulnerability_class="totally_unknown_category_xyz")]
        report = generate_markdown_report("example.com", findings)
        self.assertIn("no category-specific", report)

    def test_every_canonical_category_has_a_remediation_hint(self):
        import sys
        sys.path.insert(0, ".")
        from harness.categories import CANONICAL_CATEGORIES
        from harness.report_generator import _REMEDIATION_HINTS
        missing = [c for c in CANONICAL_CATEGORIES if c not in _REMEDIATION_HINTS and c != "ai_llm" and c != "anomaly"]
        self.assertEqual(missing, [], f"Categories with no remediation guidance: {missing}")

    def test_no_findings_produces_a_clear_empty_state(self):
        report = generate_markdown_report("example.com", [])
        self.assertIn("No findings recorded", report)

    def test_summary_counts_are_accurate(self):
        # Distinct (endpoint-family, class) findings so the dedup pass leaves them
        # all standing -- this exercises the count logic, not the collapse.
        findings = [
            sample(vulnerability_class="sqli", url="https://example.com/a", confirmed=True),
            sample(vulnerability_class="idor", url="https://example.com/b", confirmed=True),
            sample(vulnerability_class="xss", url="https://example.com/c", confirmed=False),
        ]
        report = generate_markdown_report("example.com", findings)
        self.assertIn("2 confirmed finding(s)", report)
        self.assertIn("1 unconfirmed finding(s)", report)


class TestChainSectionSeparation(unittest.TestCase):
    def test_chain_findings_go_in_their_own_section_not_mixed_with_individual_findings(self):
        findings = [
            sample(vulnerability_class="sqli", confirmed=True),
            sample(vulnerability_class="potential-attack-chain:open_redirect+ssrf",
                   evidence="chain narrative here", suggested_test="test together explicitly",
                   confidence=0.5, basis="derived"),
        ]
        report = generate_markdown_report("example.com", findings)
        self.assertIn("## Potential Attack Chains", report)
        chain_section_idx = report.index("## Potential Attack Chains")
        confirmed_section_idx = report.index("## Confirmed Findings")
        # Chain section must not contain the sqli finding's own header format
        chain_section = report[chain_section_idx:]
        self.assertNotIn("### sqli --", chain_section)
        self.assertIn("open_redirect → ssrf", report)

    def test_chain_section_has_its_own_disclaimer(self):
        findings = [sample(vulnerability_class="potential-attack-chain:xss+weak_auth")]
        report = generate_markdown_report("example.com", findings)
        self.assertIn("NOT confirmed exploit paths", report)


class TestStoreIntegrationRoundTrip(unittest.TestCase):
    """Full pipeline: persist real Finding objects, then generate a report from them."""

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._original_db_path = store._DB_PATH
        store._DB_PATH = Path(self._tmpdir.name) / "test_harness_state.db"

    def tearDown(self):
        store._DB_PATH = self._original_db_path
        self._tmpdir.cleanup()

    def test_report_generated_from_real_persisted_findings(self):
        exchange = HttpExchange(
            url="https://shop.example.com/api/login", method="POST",
            request_headers={}, request_body="",
            response_status=200, response_headers={}, response_body="",
        )
        finding = Finding(
            vulnerability_class="sqli", confidence=0.92,
            summary="Boolean-blind SQL injection in username field",
            evidence="id=1 AND 1=1 returns 200; id=1 AND 1=2 returns 401",
            suggested_test="Compare responses for the two payloads above",
            basis="derived", severity="critical",
            owasp_category="A03:2021-Injection", confirmed=True,
        )
        store.persist_findings(exchange, "sqli_agent", [finding])

        report = generate_report_for_host(exchange.url)
        self.assertIn("shop.example.com", report)
        self.assertIn("Boolean-blind SQL injection", report)
        self.assertIn("✅ CONFIRMED", report)
        self.assertIn("A03:2021-Injection", report)
        self.assertIn("parameterized queries", report)


class TestCostAwareRankingOfUnconfirmedFindings(unittest.TestCase):
    """
    Regression/feature tests for wiring risk_allocator into
    report_generator -- previously risk_allocator.rank() had no caller
    anywhere in the live codebase (confirmed by grep before this
    feature was built).
    """

    def _ledger_with_retry_cost(self, tokens: float) -> "EffortLedger":
        from harness.effort import EffortLedger, CallKind
        ledger = EffortLedger()
        # Record one real VALIDATION_RETRY call so average_tokens returns
        # this real (if synthetic-for-the-test) measured value rather
        # than the labeled-as-unmeasured prior.
        ledger.record(CallKind.VALIDATION_RETRY, model="test-model",
                       prompt_tokens=int(tokens), completion_tokens=0)
        return ledger

    def test_without_effort_ledger_behavior_is_unchanged(self):
        """Backward compatibility: omitting effort_ledger must produce
        exactly the same ordering as before this feature existed."""
        findings = [
            sample(vulnerability_class="xss", severity="high", confidence=0.6, confirmed=False),
            sample(vulnerability_class="sqli", severity="critical", confidence=0.9, confirmed=False),
        ]
        report = generate_markdown_report("example.com", findings)
        sqli_pos = report.index("sqli")
        xss_pos = report.index("xss")
        self.assertLess(sqli_pos, xss_pos, "plain severity sort: critical before high")

    def test_confirmed_findings_are_never_reordered_by_cost(self):
        """
        Confirmed findings keep the plain severity/confidence sort even
        when an effort_ledger is supplied -- cost-aware ranking is only
        meaningful for findings that still need validation effort spent
        on them.
        """
        findings = [
            sample(vulnerability_class="xss", severity="high", confidence=0.9, confirmed=True),
            sample(vulnerability_class="sqli", severity="critical", confidence=0.5, confirmed=True),
        ]
        ledger = self._ledger_with_retry_cost(5000)
        report = generate_markdown_report("example.com", findings, effort_ledger=ledger)
        sqli_pos = report.index("sqli")
        xss_pos = report.index("xss")
        self.assertLess(sqli_pos, xss_pos, "confirmed findings stay severity-sorted regardless of cost")

    def test_unconfirmed_findings_reordered_by_value_density_when_ledger_supplied(self):
        """
        The actual feature: a high-severity-but-lower-confidence
        unconfirmed finding can rank below a somewhat-lower-severity but
        much-higher-confidence one, once cost enters the ranking --
        different from the plain severity-first sort.
        """
        findings = [
            # Lower severity but very high confidence -> high expected_risk
            # relative to its severity weight.
            sample(vulnerability_class="xss", severity="high", confidence=0.95, confirmed=False, url="https://x/a"),
            # Highest severity but low confidence -> lower expected_risk
            # than the finding above despite the higher severity tier.
            sample(vulnerability_class="sqli", severity="critical", confidence=0.15, confirmed=False, url="https://x/b"),
        ]
        ledger = self._ledger_with_retry_cost(1000)

        # Plain (no ledger) ordering: severity wins, sqli (critical) first.
        plain_report = generate_markdown_report("example.com", findings)
        plain_sqli_pos = plain_report.index("sqli")
        plain_xss_pos = plain_report.index("xss")
        self.assertLess(plain_sqli_pos, plain_xss_pos)

        # Cost-aware ordering: expected_risk (probability * severity
        # weight) now favors the high-confidence xss finding, since
        # 0.95*0.75 (high) > 0.15*1.0 (critical), and both have the same
        # cost in this test (same ledger, same call kind average).
        ranked_report = generate_markdown_report("example.com", findings, effort_ledger=ledger)
        ranked_sqli_pos = ranked_report.index("sqli")
        ranked_xss_pos = ranked_report.index("xss")
        self.assertLess(ranked_xss_pos, ranked_sqli_pos,
                         "cost-aware ranking should favor the higher expected_risk finding")

    def test_same_category_and_url_findings_are_not_conflated(self):
        """
        Regression guard for `_rank_unconfirmed_by_value_density`: RiskScore has
        no back-reference to which ReportFinding produced it, so the reordering
        rebuilds order by index, not by re-matching (category, url) -- which would
        silently misorder two findings sharing both fields. The public report path
        now collapses same-(endpoint-family, class) duplicates BEFORE ranking, so
        this case can no longer reach the ranker through it; test the ranker
        directly to keep the guard live.
        """
        from harness.report_generator import _rank_unconfirmed_by_value_density, ReportFinding

        def rf(evidence, confidence):
            return ReportFinding(url="https://x/a", vulnerability_class="sqli", severity="critical",
                                 confidence=confidence, summary="s", evidence=evidence, suggested_test="t",
                                 owasp_category=None, basis="derived", confirmed=False, agent="a")
        unconfirmed = [rf("evidence-A", 0.9), rf("evidence-B", 0.2)]
        ledger = self._ledger_with_retry_cost(1000)
        ranked = _rank_unconfirmed_by_value_density(unconfirmed, ledger)
        # Higher confidence -> higher value_density -> first, without conflation.
        self.assertEqual([f.evidence for f in ranked], ["evidence-A", "evidence-B"])

    def test_generate_report_for_host_forwards_the_ledger(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            store._DB_PATH = Path(tmpdir) / "test.db"
            exchange = HttpExchange(url="https://cost-ledger-test.example.com/x", method="GET")
            f1 = Finding(vulnerability_class="xss", confidence=0.95, summary="s", evidence="e",
                         suggested_test="t", basis="derived", severity="high", confirmed=False)
            f2 = Finding(vulnerability_class="sqli", confidence=0.15, summary="s", evidence="e",
                         suggested_test="t", basis="derived", severity="critical", confirmed=False)
            store.persist_findings(exchange, "test_agent", [f1, f2])

            ledger = self._ledger_with_retry_cost(1000)
            report = generate_report_for_host(exchange.url, effort_ledger=ledger)
            self.assertLess(report.index("xss"), report.index("sqli"))


class TestDuplicateCollapse(unittest.TestCase):
    """§6.2: collapse per-(endpoint-family, class), floating confirmed -- turns a
    max-coverage run's heavy-duplicate pile into a real shortlist."""

    def test_same_class_across_object_ids_collapses_to_one(self):
        # The same IDOR proven on ticket 1..4 is ONE finding about /tickets/{id}.
        findings = [sample(vulnerability_class="idor", url=f"https://example.com/api/tickets/{i}",
                           confirmed=True) for i in range(1, 5)]
        report = generate_markdown_report("example.com", findings)
        self.assertIn("1 confirmed finding(s)", report)
        self.assertIn("3 duplicate finding(s) were collapsed", report)
        self.assertEqual(report.count("### idor --"), 1)
        self.assertIn("3 other instance(s)", report)

    def test_confirmed_survivor_beats_unconfirmed_duplicate(self):
        findings = [
            sample(vulnerability_class="idor", url="https://example.com/api/tickets/1",
                   confirmed=False, confidence=0.95, evidence="unconfirmed-guess"),
            sample(vulnerability_class="idor", url="https://example.com/api/tickets/2",
                   confirmed=True, confidence=0.6, evidence="confirmed-proof"),
        ]
        report = generate_markdown_report("example.com", findings)
        self.assertIn("1 confirmed finding(s)", report)
        self.assertIn("0 unconfirmed finding(s)", report)
        self.assertIn("confirmed-proof", report)          # the confirmed one survived
        self.assertNotIn("unconfirmed-guess", report)     # despite its higher confidence

    def test_distinct_classes_on_same_endpoint_not_collapsed(self):
        findings = [
            sample(vulnerability_class="idor", url="https://example.com/api/tickets/1", confirmed=True),
            sample(vulnerability_class="sqli", url="https://example.com/api/tickets/1", confirmed=True),
        ]
        report = generate_markdown_report("example.com", findings)
        self.assertIn("2 confirmed finding(s)", report)
        self.assertNotIn("duplicate finding(s) were collapsed", report)

    def test_canonical_synonyms_collapse_together(self):
        # "SQL Injection" and "sqli" are the same class -- must collapse.
        findings = [
            sample(vulnerability_class="SQL Injection", url="https://example.com/api/login", confirmed=True),
            sample(vulnerability_class="sqli", url="https://example.com/api/login", confirmed=False),
        ]
        report = generate_markdown_report("example.com", findings)
        self.assertIn("1 confirmed finding(s)", report)
        self.assertIn("1 duplicate finding(s) were collapsed", report)


class MarkdownRedactionTests(unittest.TestCase):
    """R03: the Markdown report path shares no redaction with the structured
    issue-export path (issues.redact/redact_url) -- a captured secret quoted
    into url/summary/evidence/suggested_test survived here even though the
    separate JSON export already masked it."""

    def test_secret_query_param_in_url_is_redacted(self):
        findings = [sample(url="https://example.com/api/x?token=abc123secret")]
        report = generate_markdown_report("example.com", findings)
        self.assertNotIn("abc123secret", report)

    def test_authorization_header_in_evidence_is_redacted(self):
        findings = [sample(evidence="Authorization: Bearer sekrit-token-value-12345")]
        report = generate_markdown_report("example.com", findings)
        self.assertNotIn("sekrit-token-value-12345", report)

    def test_cookie_value_in_summary_is_redacted(self):
        findings = [sample(summary="Response set Cookie: session=leaked-cookie-value-999")]
        report = generate_markdown_report("example.com", findings)
        self.assertNotIn("leaked-cookie-value-999", report)

    def test_secret_in_suggested_test_is_redacted(self):
        findings = [sample(suggested_test="Replay with header Authorization: Bearer replay-secret-777")]
        report = generate_markdown_report("example.com", findings)
        self.assertNotIn("replay-secret-777", report)

    def test_non_secret_content_is_unaffected(self):
        findings = [sample(summary="Ordinary SQLi in the id parameter", evidence="db error: syntax near ORDER")]
        report = generate_markdown_report("example.com", findings)
        self.assertIn("Ordinary SQLi in the id parameter", report)
        self.assertIn("db error: syntax near ORDER", report)

    def test_backtick_fence_in_evidence_cannot_escape_the_code_block(self):
        # A literal ``` inside evidence must not prematurely close the fence
        # and let the rest render as ordinary (attacker-influenced) Markdown.
        findings = [sample(evidence="normal text\n```\ninjected heading\n# not actually a heading")]
        report = generate_markdown_report("example.com", findings)
        self.assertNotIn("```\ninjected heading", report)


if __name__ == "__main__":
    unittest.main()
