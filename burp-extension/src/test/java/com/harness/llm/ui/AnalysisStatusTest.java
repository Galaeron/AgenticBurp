package com.harness.llm.ui;

import com.google.gson.Gson;
import com.harness.llm.model.AnalysisModels.AnalysisResponse;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * X08: a harness result flagged degraded or partial must not be shown as a
 * clean COMPLETED analysis. Parses the harness's own wire JSON (field names
 * from harness/models.py AnalysisResponse) through Gson, exactly as
 * HarnessClient does, so a renamed or dropped field is caught here.
 */
public final class AnalysisStatusTest {

    private static AnalysisResponse parse(String json) {
        return new Gson().fromJson(json, AnalysisResponse.class);
    }

    @Test
    @DisplayName("partial inference failure is DEGRADED and keeps the agent errors")
    void partialInferenceIsDegraded() {
        AnalysisResponse r = parse("{\"summary\": \"WARNING: 1 of 2 LLM agent(s) failed (sqli)\","
                + " \"degraded\": true, \"partial_inference\": true,"
                + " \"agent_errors\": [\"sqli: OllamaError: operation failed\"]}");
        assertTrue(r.degraded);
        assertTrue(r.partial_inference);
        assertEquals(List.of("sqli: OllamaError: operation failed"), r.agent_errors);
        assertEquals(AnalysisStatus.Status.DEGRADED, AnalysisStatus.completionStatus(r));
    }

    @Test
    @DisplayName("an all-agents outage (degraded, not partial) is DEGRADED")
    void allAgentsFailedIsDegraded() {
        AnalysisResponse r = parse("{\"degraded\": true, \"partial_inference\": false}");
        assertEquals(AnalysisStatus.Status.DEGRADED, AnalysisStatus.completionStatus(r));
    }

    @Test
    @DisplayName("negative control: a healthy result stays COMPLETED")
    void healthyIsCompleted() {
        AnalysisResponse r = parse("{\"degraded\": false, \"partial_inference\": false, \"agent_errors\": []}");
        assertEquals(AnalysisStatus.Status.COMPLETED, AnalysisStatus.completionStatus(r));
    }

    @Test
    @DisplayName("an older server without the health fields reads as COMPLETED")
    void olderServerIsCompleted() {
        AnalysisResponse r = parse("{\"summary\": \"ok\"}");
        assertFalse(r.degraded);
        assertEquals(AnalysisStatus.Status.COMPLETED, AnalysisStatus.completionStatus(r));
    }

    @Test
    @DisplayName("DEGRADED is terminal, so the tracker moves it to completed analyses")
    void degradedIsTerminal() {
        AnalysisTracker tracker = new AnalysisTracker();
        tracker.startAnalysis("GET /x", "req-1", 2);
        tracker.updateStatus("req-1", AnalysisStatus.Status.DEGRADED);
        assertTrue(AnalysisStatus.Status.DEGRADED.isTerminal());
        assertTrue(tracker.getActiveAnalyses().isEmpty());
        assertEquals(AnalysisStatus.Status.DEGRADED, tracker.getCompletedAnalyses().get(0).getStatus());
        assertEquals("", tracker.getCompletedAnalyses().get(0).getEstimatedTimeRemaining());
    }
}
