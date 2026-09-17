"""Tests for the Phase 0.3 recall benchmark harness.

The ground-truth lists here ARE the disposable fixture (data authored by hand,
never from an answer key). The run findings are synthetic where the scoring
logic is under test, and REAL model objects (AnalysisResponse / Finding) where
the adapter is under test -- guarding the integration risk that a Finding
carries no url of its own, so the endpoint context must be stamped in."""
import unittest

import harness.recall_benchmark as rb
from harness.recall_benchmark import (PlantedVuln, score_run, confirmation_leg_of,
                              findings_from_analysis, findings_from_engagement,
                              CONFIRMED, DETECTED, MISSED, EARNED, LUCKY, UNKNOWN)
from harness.models import HttpExchange, Finding, AgentReport, AnalysisResponse


class LegExtractionTests(unittest.TestCase):
    def test_leg_from_evidence_stamp(self):
        f = {"evidence": "hypothesis || cross-identity CONFIRMED: replayed as bob"}
        self.assertEqual(confirmation_leg_of(f), "cross_identity")

    def test_leg_from_proactive_field(self):
        self.assertEqual(confirmation_leg_of({"evidence": "", "proactive_leg": "xxe"}), "xxe")

    def test_leg_from_validation_hint(self):
        self.assertEqual(
            confirmation_leg_of({"validation_hints": ["confidential_info:secret"]}),
            "confidential_info")

    def test_no_leg(self):
        self.assertEqual(confirmation_leg_of({"evidence": "just a hypothesis"}), "")

    def test_structured_field_preferred_over_evidence_text(self):
        # 2026-09-17 coverage-recovery plan, Step 4: confirmed_by_leg is the
        # reliable, structured source -- checked before falling back to
        # regex-parsing free-text evidence, which never has to phrase things
        # a particular way for the leg to be recoverable.
        f = {"confirmed_by_leg": "sqlmap", "evidence": "nothing named here at all"}
        self.assertEqual(confirmation_leg_of(f), "sqlmap")

    def test_structured_field_wins_even_if_evidence_names_a_different_leg(self):
        f = {"confirmed_by_leg": "cross_identity",
            "evidence": "hypothesis || jwt-forge CONFIRMED: unrelated stale text"}
        self.assertEqual(confirmation_leg_of(f), "cross_identity")


class ScoringTests(unittest.TestCase):
    def test_confirmed_detected_missed(self):
        gt = [
            PlantedVuln("V1", "idor", "/api/tickets/{id}"),
            PlantedVuln("V2", "sqli", "/api/search"),
            PlantedVuln("V3", "xxe", "/api/import"),
        ]
        findings = [
            # V1: confirmed (matches, confirmed True)
            {"url": "http://t/api/tickets/7", "vulnerability_class": "idor",
             "confirmed": True, "evidence": "x || cross-identity CONFIRMED: y"},
            # V2: detected but unconfirmed
            {"url": "http://t/api/search", "vulnerability_class": "sqli", "confirmed": False},
            # V3: nothing -> missed
        ]
        score = score_run(gt, findings)
        by_id = {it.planted.id: it for it in score.items}
        self.assertEqual(by_id["V1"].status, CONFIRMED)
        self.assertEqual(by_id["V2"].status, DETECTED)
        self.assertEqual(by_id["V3"].status, MISSED)
        self.assertEqual((score.confirmed, score.detected_unconfirmed, score.missed), (1, 1, 1))
        self.assertIn("1/3 confirmed", score.summary_line())

    def test_unknown_provenance_is_not_lucky(self):
        # #6: confirmed but no leg named -> UNKNOWN provenance, never "lucky".
        gt = [PlantedVuln("V1", "idor", "/api/tickets/{id}", intended_confirmation="cross_identity")]
        findings = [{"url": "http://t/api/tickets/7", "vulnerability_class": "idor",
                     "confirmed": True, "evidence": "confirmed somehow (no leg named)"}]
        score = score_run(gt, findings)
        self.assertEqual(score.items[0].status, CONFIRMED)
        self.assertEqual(score.items[0].provenance, UNKNOWN)
        self.assertEqual(score.lucky_confirms, 0)
        self.assertEqual(score.unknown_provenance_confirms, 1)

    def test_best_proof_prefers_earned_over_unknown_regardless_of_order(self):
        # #6: deterministic best-proof selection, not "first matching confirmation".
        gt = [PlantedVuln("V1", "idor", "/api/tickets/{id}", intended_confirmation="cross_identity")]
        findings = [
            {"url": "http://t/api/tickets/7", "vulnerability_class": "idor",
             "confirmed": True, "evidence": "no leg named"},                        # unknown, first
            {"url": "http://t/api/tickets/7", "vulnerability_class": "idor",
             "confirmed": True, "evidence": "x || cross-identity CONFIRMED: y"},     # earned, second
        ]
        score = score_run(gt, findings)
        self.assertEqual(score.items[0].provenance, EARNED)

    def test_class_alias_and_path_id_normalization_match(self):
        # A free-text label + a concrete id must match a canonical planted vuln.
        gt = [PlantedVuln("V1", "idor", "/api/tickets/{id}")]
        findings = [{"url": "http://t/api/tickets/42",
                     "vulnerability_class": "Insecure Direct Object Reference",
                     "confirmed": False}]
        self.assertEqual(score_run(gt, findings).items[0].status, DETECTED)

    def test_wrong_path_does_not_match(self):
        # Same class on a DIFFERENT endpoint is not a hit for this planted vuln
        # (this is the recall analogue of the mis-attribution precision check).
        gt = [PlantedVuln("V1", "idor", "/api/tickets/{id}")]
        findings = [{"url": "http://t/api/orders/1", "vulnerability_class": "idor",
                     "confirmed": True, "evidence": "cross-identity CONFIRMED"}]
        self.assertEqual(score_run(gt, findings).items[0].status, MISSED)


class ProvenanceTests(unittest.TestCase):
    def _confirmed(self, leg_evidence):
        return [{"url": "http://t/api/tickets/1", "vulnerability_class": "idor",
                 "confirmed": True, "evidence": f"h || {leg_evidence}"}]

    def test_earned_when_confirmed_via_intended_leg(self):
        gt = [PlantedVuln("V1", "idor", "/api/tickets/{id}",
                          intended_confirmation="cross_identity")]
        it = score_run(gt, self._confirmed("cross-identity CONFIRMED: ok")).items[0]
        self.assertEqual(it.status, CONFIRMED)
        self.assertEqual(it.provenance, EARNED)

    def test_lucky_when_confirmed_via_other_leg(self):
        # Meant to be caught via a log-leak path; instead confirmed by cross-
        # identity (sequential-id coincidence). Real bug, wrong detection path.
        gt = [PlantedVuln("V1", "idor", "/api/tickets/{id}",
                          intended_confirmation="log_leak")]
        score = score_run(gt, self._confirmed("cross-identity CONFIRMED: ok"))
        it = score.items[0]
        self.assertEqual(it.status, CONFIRMED)
        self.assertEqual(it.provenance, LUCKY)
        self.assertEqual(score.lucky_confirms, 1)
        self.assertIn("confirmed by luck", score.summary_line())

    def test_no_provenance_without_intended_leg(self):
        gt = [PlantedVuln("V1", "idor", "/api/tickets/{id}")]  # no intended_confirmation
        it = score_run(gt, self._confirmed("cross-identity CONFIRMED: ok")).items[0]
        self.assertEqual(it.status, CONFIRMED)
        self.assertEqual(it.provenance, "")


class AdapterTests(unittest.TestCase):
    def test_findings_from_analysis_stamps_exchange_url(self):
        # A Finding has no url; the adapter must stamp the analyzed exchange's so
        # the scorer can match it to a planted vuln on that endpoint.
        ex = HttpExchange(url="http://t/export/backup", method="GET")
        resp = AnalysisResponse(
            coordinator_model="m", dispatched_agents=[], summary="s",
            agent_reports=[AgentReport(
                agent="confidential_info", model="deterministic",
                findings=[Finding(vulnerability_class="info_disclosure", confidence=0.9,
                                  summary="secret in response", evidence="AKIA…redacted",
                                  suggested_test="", basis="derived", confirmed=False)])])
        gt = [PlantedVuln("V1", "info_disclosure", "/export/backup"),
              PlantedVuln("V2", "info_disclosure", "/health/status")]  # not present -> missed
        score = score_run(gt, findings_from_analysis(ex, resp))
        by_id = {it.planted.id: it for it in score.items}
        self.assertEqual(by_id["V1"].status, DETECTED)
        self.assertEqual(by_id["V2"].status, MISSED)

    def test_findings_from_engagement_stamps_path(self):
        result = {"worklist": [
            {"path": "/api/tickets/{id}", "findings": [
                {"vulnerability_class": "idor", "confirmed": True,
                 "evidence": "h || cross-identity CONFIRMED: bob"}]},
            {"path": "/api/health", "findings": []},
        ]}
        gt = [PlantedVuln("V1", "idor", "/api/tickets/{id}",
                          intended_confirmation="cross_identity")]
        it = score_run(gt, findings_from_engagement(result)).items[0]
        self.assertEqual(it.status, CONFIRMED)
        self.assertEqual(it.provenance, EARNED)


class EarnedRecallTests(unittest.TestCase):
    """2026-09-17 coverage-recovery plan, Step 4: `earned` is the honest
    headline -- confirmed via the SPECIFIC intended leg, structurally
    attributed, not "confirmed by something." A reported `confirmed` count
    has repeatedly overstated real detection-path coverage (a run reporting
    9/13 confirmed had only 4/13 earned once lucky/unknown confirms were
    excluded); `earned` is what a coverage claim should be measured against."""

    def test_earned_counts_only_intended_leg_structured_confirmations(self):
        gt = [
            PlantedVuln("V1", "idor", "/api/tickets/{id}", intended_confirmation="cross_identity"),
            PlantedVuln("V2", "sqli", "/api/search", intended_confirmation="sqlmap"),
            PlantedVuln("V3", "xxe", "/api/import", intended_confirmation="xxe"),
            PlantedVuln("V4", "ssrf", "/api/fetch", intended_confirmation="ssrf"),
        ]
        findings = [
            # V1: earned -- the intended leg, structurally named.
            {"url": "http://t/api/tickets/7", "vulnerability_class": "idor",
             "confirmed": True, "confirmed_by_leg": "cross_identity"},
            # V2: confirmed, but by a DIFFERENT leg than intended -- lucky, not earned.
            {"url": "http://t/api/search", "vulnerability_class": "sqli",
             "confirmed": True, "confirmed_by_leg": "cross_identity"},
            # V3: confirmed, but no leg named at all -- unknown, not earned.
            {"url": "http://t/api/import", "vulnerability_class": "xxe",
             "confirmed": True, "evidence": "confirmed somehow"},
            # V4: missed entirely.
        ]
        score = score_run(gt, findings)
        self.assertEqual(score.confirmed, 3)     # V1, V2, V3 all report confirmed=True
        self.assertEqual(score.earned, 1)        # only V1 is earned
        self.assertIn("1/4 earned", score.summary_line())
        self.assertIn("3/4 confirmed", score.summary_line())

    def test_a_passive_observation_is_visible_but_not_earned(self):
        # A CORS/CSP-style passive observation (no leg tier at all --
        # confirmation_gate.leg_tier("cors") == "none") is a real, visible,
        # matched-and-confirmed item -- but it never counts toward earned
        # EXPLOIT recall, even when its own provenance resolves to EARNED
        # (its declared "intended" leg matched what confirmed it).
        from harness.confirmation_gate import leg_tier
        self.assertEqual(leg_tier("cors"), "none")
        gt = [PlantedVuln("V1", "cors", "/api/data", intended_confirmation="cors")]
        findings = [{"url": "http://t/api/data", "vulnerability_class": "cors",
                    "confirmed": True, "confirmed_by_leg": "cors"}]
        score = score_run(gt, findings)
        item = score.items[0]
        self.assertEqual(item.status, CONFIRMED)   # visible: it IS a matched, confirmed finding
        self.assertEqual(item.provenance, EARNED)  # its own item-level provenance says "earned"
        self.assertEqual(score.earned, 0)          # but excluded from earned EXPLOIT recall


if __name__ == "__main__":
    unittest.main()
