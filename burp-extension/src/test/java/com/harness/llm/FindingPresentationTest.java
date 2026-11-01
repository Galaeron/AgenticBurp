package com.harness.llm;

import com.google.gson.Gson;
import com.harness.llm.model.AnalysisModels.Finding;
import com.harness.llm.ui.FindingPresentation;
import com.harness.llm.ui.FindingPresentation.Tally;
import com.harness.llm.ui.HarnessPanel;
import com.harness.llm.model.AnalysisModels.AgentReport;
import com.harness.llm.model.AnalysisModels.AnalysisResponse;
import java.util.List;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class FindingPresentationTest {
    @Test void actualPanelDetailShowsNoLegMaturityWithoutHidingImpact() throws Exception {
        Finding finding = new Finding();
        finding.vulnerability_class = "unknown-workflow-risk";
        finding.severity = "critical";
        finding.confidence = .99;
        finding.evidence_maturity = "unverified_no_leg";
        finding.triage_priority = "manual_verification";
        finding.impact_severity = "critical";
        AgentReport report = new AgentReport();
        report.agent = "synthetic";
        report.findings = List.of(finding);
        AnalysisResponse response = new AnalysisResponse();
        response.dispatched_agents = List.of("synthetic");
        response.agent_reports = List.of(report);
        SwingUtilities.invokeAndWait(() -> {
            try {
                HarnessPanel panel = new HarnessPanel(() -> false, () -> null, null);
                var method = HarnessPanel.class.getDeclaredMethod("showDetail", HarnessPanel.ResultEntry.class);
                method.setAccessible(true);
                method.invoke(panel, new HarnessPanel.ResultEntry("ordinary capture", response, null));
                var field = HarnessPanel.class.getDeclaredField("detailArea");
                field.setAccessible(true);
                String text = ((JTextArea) field.get(panel)).getText();
                assertTrue(text.contains("severity=critical confidence=0.99"));
                assertTrue(text.contains("Evidence maturity: unverified_no_leg; Triage priority: manual_verification"));
            } catch (ReflectiveOperationException error) { throw new RuntimeException(error); }
        });
    }
    @Test void noLegCriticalWireFindingRemainsUnverifiedAtManualPriority() {
        Finding finding = new Gson().fromJson("{\"vulnerability_class\":\"unknown-workflow-risk\","
                + "\"severity\":\"critical\",\"confidence\":0.99,\"confirmed\":false,"
                + "\"evidence_maturity\":\"unverified_no_leg\",\"triage_priority\":\"manual_verification\","
                + "\"impact_severity\":\"critical\"}", Finding.class);
        assertEquals("Evidence maturity: unverified_no_leg; Triage priority: manual_verification; Impact severity: critical",
                FindingPresentation.evidenceLine(finding));
    }
    // R16 additions (UNBUILT/not executed in the harness checkout unless a JDK run is recorded
    // in the R16 evidence folder): a wire-supplied maturity string alone never presents as confirmed.
    @Test void confirmedMaturityOnTheWireWithoutConfirmedFlagFailsSafeToUnverified() {
        Finding finding = new Gson().fromJson("{\"vulnerability_class\":\"unknown-workflow-risk\","
                + "\"severity\":\"critical\",\"confidence\":0.99,\"confirmed\":false,"
                + "\"evidence_maturity\":\"confirmed\",\"triage_priority\":\"review_confirmed\","
                + "\"impact_severity\":\"critical\"}", Finding.class);
        assertEquals("unverified", FindingPresentation.maturity(finding));
        assertTrue(FindingPresentation.isUnverified(finding));
        assertFalse(FindingPresentation.isConfirmed(finding));
        assertEquals("manual_verification", FindingPresentation.priority(finding));
        assertTrue(FindingPresentation.stateLabel(finding).startsWith("UNVERIFIED"));
        assertTrue(FindingPresentation.evidenceLine(finding).contains("unverified; Triage priority: manual_verification"));
    }

    @Test void stateLabelKeepsObservationNegativeRejectedNoLegAndSkippedDistinct() {
        assertEquals("CONFIRMED OBSERVATION (passive check, not a live exploit)",
                FindingPresentation.stateLabel(finding("confirmed_observation", true)));
        assertEquals("CONFIRMED (leg fired, not oracle-verified)",
                FindingPresentation.stateLabel(finding("confirmed", true)));
        assertEquals("NOT CONFIRMED (controlled negative)",
                FindingPresentation.stateLabel(finding("controlled_negative", false)));
        assertEquals("NOT CONFIRMED (review rejected or downgraded)",
                FindingPresentation.stateLabel(finding("review_rejected", false)));
        assertTrue(FindingPresentation.stateLabel(finding("unverified_no_leg", false)).startsWith("UNVERIFIED (no confirmation leg"));
        assertTrue(FindingPresentation.stateLabel(finding("unverified", false)).startsWith("UNVERIFIED (confirmation not established"));
        assertTrue(FindingPresentation.stateLabel(finding(null, true)).startsWith("UNVERIFIED"));
    }

    @Test void exportHeadlineSeparatesImpactSeverityFromVerification() {
        Finding unverifiedCritical = finding("unverified_no_leg", false);
        unverifiedCritical.severity = "critical";
        Finding observation = finding("confirmed_observation", true);
        observation.severity = "high";
        Finding negative = finding("controlled_negative", false);
        negative.severity = "high";
        Tally tally = FindingPresentation.tally(List.of(unverifiedCritical, observation, negative));
        assertEquals(new Tally(3, 1, 2, 1, 1, 1), tally);
        String line = tally.headline(2);
        assertTrue(line.contains("1 critical, 2 high by impact severity"));
        assertTrue(line.contains("**1 confirmed**"));
        assertTrue(line.contains("**1 unverified (manual verification)**"));
        assertFalse(line.contains("**3 confirmed**"));
    }

    @Test void actualPanelDetailShowsStatusForLowConfidenceConfirmedObservationAndUnverifiedCritical() throws Exception {
        Finding unverified = finding("unverified_no_leg", false);
        unverified.vulnerability_class = "unknown-workflow-risk";
        unverified.severity = "critical";
        unverified.confidence = .99;
        Finding observation = finding("confirmed_observation", true);
        observation.vulnerability_class = "cors";
        observation.severity = "high";
        observation.confidence = .3;
        AgentReport report = new AgentReport();
        report.agent = "synthetic";
        report.findings = List.of(unverified, observation);
        AnalysisResponse response = new AnalysisResponse();
        response.dispatched_agents = List.of("synthetic");
        response.agent_reports = List.of(report);
        SwingUtilities.invokeAndWait(() -> {
            try {
                HarnessPanel panel = new HarnessPanel(() -> false, () -> null, null);
                var method = HarnessPanel.class.getDeclaredMethod("showDetail", HarnessPanel.ResultEntry.class);
                method.setAccessible(true);
                method.invoke(panel, new HarnessPanel.ResultEntry("ordinary capture", response, null));
                var field = HarnessPanel.class.getDeclaredField("detailArea");
                field.setAccessible(true);
                String text = ((JTextArea) field.get(panel)).getText();
                assertTrue(text.contains("status: UNVERIFIED (no confirmation leg; manual verification)"));
                assertTrue(text.contains("status: CONFIRMED OBSERVATION (passive check, not a live exploit)"));
                assertFalse(text.contains("status: CONFIRMED (leg fired"));
            } catch (ReflectiveOperationException error) { throw new RuntimeException(error); }
        });
    }

    private static Finding finding(String maturity, boolean confirmed) {
        Finding finding = new Finding();
        finding.severity = "high";
        finding.evidence_maturity = maturity;
        finding.confirmed = confirmed;
        return finding;
    }

    @Test void negativeAndSkippedAreDistinctAndLegacyMissingMetadataFailsSafe() {
        Finding finding = new Finding();
        finding.severity = "high";
        finding.evidence_maturity = "controlled_negative";
        finding.triage_priority = "review_negative";
        assertTrue(FindingPresentation.evidenceLine(finding).contains("controlled_negative; Triage priority: review_negative"));
        finding.evidence_maturity = "unverified";
        assertTrue(FindingPresentation.evidenceLine(finding).contains("unverified; Triage priority: manual_verification"));
        finding.evidence_maturity = null;
        finding.confirmed = true; // Legacy raw flag alone cannot mint the new evidence state.
        assertTrue(FindingPresentation.evidenceLine(finding).contains("unverified; Triage priority: manual_verification"));
    }
}
