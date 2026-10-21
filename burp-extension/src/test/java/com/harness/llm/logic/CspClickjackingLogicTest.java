package com.harness.llm.logic;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static com.harness.llm.logic.CspClickjackingLogic.*;
import static org.junit.jupiter.api.Assertions.*;

public final class CspClickjackingLogicTest {

    @Test
    @DisplayName("non-HTML content type is invalid input, not a finding either way")
    void nonHtmlIsInvalid() {
        Evidence e = evaluate("application/json", null, null);
        assertEquals(Verdict.INVALID, e.verdict());
    }

    @Test
    @DisplayName("CSP frame-ancestors present -> rejected (protected)")
    void cspFrameAncestorsProtects() {
        Evidence e = evaluate("text/html", null, "default-src 'self'; frame-ancestors 'self'");
        assertEquals(Verdict.REJECTED, e.verdict());
    }

    @Test
    @DisplayName("valid X-Frame-Options DENY -> rejected (protected)")
    void validXfoDenyProtects() {
        Evidence e = evaluate("text/html", "DENY", null);
        assertEquals(Verdict.REJECTED, e.verdict());
    }

    @Test
    @DisplayName("valid X-Frame-Options SAMEORIGIN (mixed case) -> rejected (protected)")
    void validXfoSameoriginCaseInsensitive() {
        Evidence e = evaluate("text/html", "sameOrigin", null);
        assertEquals(Verdict.REJECTED, e.verdict());
    }

    @Test
    @DisplayName("malformed X-Frame-Options value -> supported, not rejected")
    void malformedXfoIsSupported() {
        Evidence e = evaluate("text/html", "ALLOW-FROM https://example.com", null);
        assertEquals(Verdict.SUPPORTED, e.verdict());
    }

    @Test
    @DisplayName("neither CSP nor X-Frame-Options present on an HTML page -> supported")
    void missingBothIsSupported() {
        Evidence e = evaluate("text/html; charset=utf-8", null, null);
        assertEquals(Verdict.SUPPORTED, e.verdict());
        assertFalse(e.confirmed());
    }

    @Test
    @DisplayName("R32: frame-ancestors * is not framing protection")
    void wildcardFrameAncestorsIsNotProtection() {
        Evidence e = evaluate("text/html", null, "frame-ancestors *");
        assertEquals(Verdict.SUPPORTED, e.verdict());
    }

    @Test
    @DisplayName("R32: scheme-only and wildcard-host sources admit any origin")
    void schemeOnlyAndWildcardHostSourcesAreNotProtection() {
        assertEquals(Verdict.SUPPORTED, evaluate("text/html", null, "frame-ancestors https:").verdict());
        assertEquals(Verdict.SUPPORTED, evaluate("text/html", null, "frame-ancestors 'self' https://*").verdict());
        assertEquals(Verdict.SUPPORTED, evaluate("text/html", null, "frame-ancestors http: https:").verdict());
    }

    @Test
    @DisplayName("R32: a permissive frame-ancestors overrides X-Frame-Options DENY in browsers that enforce it")
    void permissiveFrameAncestorsWinsOverXfo() {
        Evidence e = evaluate("text/html", "DENY", "frame-ancestors *");
        assertEquals(Verdict.SUPPORTED, e.verdict());
        assertTrue(e.summary().contains("ignore X-Frame-Options"));
    }

    @Test
    @DisplayName("R32: a directive name inside another directive's value is not a frame-ancestors directive")
    void directiveNameInReportUriIsNotProtection() {
        Evidence e = evaluate("text/html", null, "report-uri /frame-ancestors/report");
        assertEquals(Verdict.SUPPORTED, e.verdict());
        assertNotEquals(Verdict.REJECTED, evaluate("text/html", null, "default-src 'self' https://cdn.example/frame-ancestors").verdict());
    }

    @Test
    @DisplayName("R32 controls: 'none', an empty list, named hosts and a case variant still restrict framing")
    void restrictiveSourceListsProtect() {
        assertEquals(Verdict.REJECTED, evaluate("text/html", null, "frame-ancestors 'none'").verdict());
        assertEquals(Verdict.REJECTED, evaluate("text/html", null, "frame-ancestors").verdict());
        assertEquals(Verdict.REJECTED, evaluate("text/html", null, "frame-ancestors https://partner.example *.example.com").verdict());
        assertEquals(Verdict.REJECTED, evaluate("text/html", null, "default-src 'self'; FRAME-ANCESTORS 'SELF'").verdict());
    }

    @Test
    @DisplayName("R32: with several policies, any restrictive frame-ancestors restricts framing")
    void anyRestrictivePolicyProtects() {
        assertEquals(Verdict.REJECTED, evaluate("text/html", null, "frame-ancestors *, frame-ancestors 'self'").verdict());
    }

    @Test
    @DisplayName("R32: only the first frame-ancestors in a policy counts")
    void firstFrameAncestorsInAPolicyWins() {
        assertEquals(Verdict.SUPPORTED, evaluate("text/html", null, "frame-ancestors *; frame-ancestors 'none'").verdict());
    }

    @Test
    @DisplayName("without frame-ancestors, a valid X-Frame-Options still protects")
    void noFrameAncestorsFallsBackToXfo() {
        assertEquals(Verdict.REJECTED, evaluate("text/html", "DENY", "default-src 'self'").verdict());
    }
}
