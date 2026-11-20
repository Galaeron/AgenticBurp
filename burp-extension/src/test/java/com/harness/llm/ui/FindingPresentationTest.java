package com.harness.llm.ui;

import com.harness.llm.model.AnalysisModels.Finding;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Locale;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * EFF-4: the panel shows a finding's evidence tier first and its numeric confidence only as an
 * uncalibrated model score, never as a probability or likelihood.
 */
public final class FindingPresentationTest {

    @Test
    @DisplayName("the model score is labelled uncalibrated and carries no probability wording")
    void modelScoreIsNotAProbability() {
        String text = FindingPresentation.modelScore(0.85);
        assertEquals("model score 0.85 (uncalibrated, not a probability)", text);
        assertFalse(text.contains("%"), text);
        assertFalse(text.toLowerCase(Locale.ROOT).contains("likely"), text);
    }

    @Test
    @DisplayName("the score uses a dot decimal separator whatever the default locale")
    void modelScoreIsLocaleIndependent() {
        Locale saved = Locale.getDefault();
        try {
            Locale.setDefault(Locale.GERMANY);
            assertEquals("model score 0.35 (uncalibrated, not a probability)", FindingPresentation.modelScore(0.35));
        } finally {
            Locale.setDefault(saved);
        }
    }

    @Test
    @DisplayName("control: a high score on an unconfirmed finding still reads UNVERIFIED")
    void highScoreDoesNotPromoteTheState() {
        Finding finding = new Finding();
        finding.confidence = 0.99;
        finding.confirmed = false;
        assertTrue(FindingPresentation.stateLabel(finding).startsWith("UNVERIFIED"),
                FindingPresentation.stateLabel(finding));
    }
}
