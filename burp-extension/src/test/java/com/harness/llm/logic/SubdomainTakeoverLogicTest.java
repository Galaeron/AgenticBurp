package com.harness.llm.logic;

import org.junit.jupiter.api.Test;

import static com.harness.llm.logic.SubdomainTakeoverLogic.*;
import static org.junit.jupiter.api.Assertions.*;

public final class SubdomainTakeoverLogicTest {

    @Test
    void knownFingerprintIsALeadNotConfirmed() {
        Evidence ev = evaluate(404, "<html>There isn't a GitHub Pages site here.</html>");
        assertEquals(Verdict.SUPPORTED, ev.verdict());
        assertFalse(ev.confirmed());
    }

    @Test
    void s3FingerprintIsALeadNotConfirmed() {
        Evidence ev = evaluate(404, "<Error><Code>NoSuchBucket</Code></Error>");
        assertEquals(Verdict.SUPPORTED, ev.verdict());
        assertFalse(ev.confirmed());
    }

    @Test
    void applicationProjectNotFoundIsNotConfirmed() {
        // Code review 02 R29: an application's own 404 wording matches the
        // Surge.sh fingerprint; with no DNS/provider evidence it is a lead.
        Evidence ev = evaluate(404, "Project not found");
        assertFalse(ev.confirmed());
        assertNotEquals(Verdict.CONFIRMED, ev.verdict());
    }

    @Test
    void plain404NoFingerprintIsSupported() {
        assertEquals(Verdict.SUPPORTED, evaluate(404, "generic not found page").verdict());
    }

    @Test
    void ok200NoFingerprintIsRejected() {
        assertEquals(Verdict.REJECTED, evaluate(200, "<html>welcome</html>").verdict());
    }

    @Test
    void nullBodyIsRejected() {
        assertEquals(Verdict.REJECTED, evaluate(200, null).verdict());
    }
}
