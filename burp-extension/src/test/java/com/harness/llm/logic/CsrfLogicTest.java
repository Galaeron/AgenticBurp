package com.harness.llm.logic;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Random;

import static com.harness.llm.logic.CsrfLogic.*;
import static org.junit.jupiter.api.Assertions.*;

public final class CsrfLogicTest {

    /** A read-back that saw the forged request's marker stored (RV-N N1). */
    private static final ReadBack SHOWN = new ReadBack(true, "read-back shows the marker");

    @Test
    @DisplayName("known CSRF token names are recognized case-insensitively")
    void tokenNamesRecognized() {
        assertTrue(looksLikeCsrfTokenName("csrf_token"));
        assertTrue(looksLikeCsrfTokenName("X-CSRF-Token"));
        assertTrue(looksLikeCsrfTokenName("csrfmiddlewaretoken"));
        assertTrue(looksLikeCsrfTokenName("authenticity_token"));
        assertTrue(looksLikeCsrfTokenName("__RequestVerificationToken"));
        assertFalse(looksLikeCsrfTokenName("quantity"));
        assertFalse(looksLikeCsrfTokenName(null));
    }

    @Test
    @DisplayName("safe methods are recognized")
    void safeMethodsRecognized() {
        assertTrue(isSafeMethod("GET"));
        assertTrue(isSafeMethod("head"));
        assertTrue(isSafeMethod("OPTIONS"));
        assertFalse(isSafeMethod("POST"));
        assertFalse(isSafeMethod("PUT"));
        assertFalse(isSafeMethod("DELETE"));
    }

    @Test
    @DisplayName("GET request -> invalid, CSRF not applicable")
    void safeMethodIsInvalid() {
        Evidence e = evaluate("GET", true, true, 200, 200, -1);
        assertEquals(Verdict.INVALID, e.verdict());
    }

    @Test
    @DisplayName("non-cookie (Bearer token) auth -> rejected, not applicable the same way")
    void nonCookieAuthIsRejected() {
        Evidence e = evaluate("POST", false, false, 200, -1, -1);
        assertEquals(Verdict.REJECTED, e.verdict());
    }

    @Test
    @DisplayName("token found, removal probe not run -> supported only, presence alone isn't proof")
    void tokenFoundButNotProbedIsSupported() {
        Evidence e = evaluate("POST", true, true, 200, -1, -1);
        assertEquals(Verdict.SUPPORTED, e.verdict());
        assertFalse(e.confirmed());
    }

    @Test
    @DisplayName("token removed, cookie alone still succeeds, no-cookie control refused, change read back -> confirmed")
    void tokenRemovedButStillSucceedsIsConfirmed() {
        Evidence e = evaluate("POST", true, true, 200, 200, 403, SHOWN);
        assertEquals(Verdict.CONFIRMED, e.verdict());
        assertTrue(e.confirmed());
    }

    @Test
    @DisplayName("token found, request correctly rejected after removal -> rejected, properly protected")
    void tokenRemovedAndRejectedIsRejected() {
        Evidence e = evaluate("POST", true, true, 200, 403, -1);
        assertEquals(Verdict.REJECTED, e.verdict());
        assertFalse(e.confirmed());
    }

    @Test
    @DisplayName("no token found at all, cookie-authenticated state change -> supported, passive signal only")
    void noTokenFoundIsSupported() {
        Evidence e = evaluate("PUT", true, false, 200, -1, -1);
        assertEquals(Verdict.SUPPORTED, e.verdict());
        assertFalse(e.confirmed());
    }

    @Test
    @DisplayName("both original and mutated requests succeed within the 2xx range even at different codes -> still confirmed")
    void differentButBothSuccessfulStatusesStillConfirmed() {
        Evidence e = evaluate("POST", true, true, 200, 201, 401, SHOWN);
        assertEquals(Verdict.CONFIRMED, e.verdict());
    }

    @Test
    @DisplayName("R25: the same refusal before and after token removal is not a successful state change")
    void sameRefusalBeforeAndAfterIsNotConfirmed() {
        Evidence e = evaluate("POST", true, true, 403, 403, -1);
        assertFalse(e.confirmed());
        assertEquals(Verdict.INVALID, e.verdict());
    }

    @Test
    @DisplayName("R25: token-free success without the no-cookie control is supported only")
    void forgedSuccessWithoutControlIsSupported() {
        Evidence e = evaluate("POST", true, true, 200, 200, -1);
        assertEquals(Verdict.SUPPORTED, e.verdict());
        assertFalse(e.confirmed());
    }

    @Test
    @DisplayName("R25: an action that also succeeds with no cookie is not gated on the session -> rejected")
    void actionOpenWithoutCookieIsRejected() {
        Evidence e = evaluate("POST", true, true, 200, 200, 200);
        assertEquals(Verdict.REJECTED, e.verdict());
        assertFalse(e.confirmed());
    }

    @Test
    @DisplayName("R25: a no-cookie control that errors is not a clean refusal -> supported only")
    void controlServerErrorIsSupported() {
        Evidence e = evaluate("POST", true, true, 200, 200, 500);
        assertEquals(Verdict.SUPPORTED, e.verdict());
        assertFalse(e.confirmed());
    }

    @Test
    @DisplayName("only 2xx counts as success")
    void successIsTwoHundredRange() {
        assertTrue(isSuccess(200));
        assertTrue(isSuccess(204));
        assertFalse(isSuccess(302));
        assertFalse(isSuccess(403));
        assertFalse(isSuccess(-1));
    }

    // ---------------------------------------------------------------- RV-N N1
    @Test
    @DisplayName("N1: token-free 2xx and a refused no-cookie control, but no read-back -> supported only")
    void forgedSuccessWithoutReadBackIsSupported() {
        Evidence e = evaluate("POST", true, true, 200, 200, 403);
        assertEquals(Verdict.SUPPORTED, e.verdict());
        assertFalse(e.confirmed());
        Evidence notShown = evaluate("POST", true, true, 200, 200, 403,
                readBack("/profile", "display_name", "csrfmarkabc", 200, "Alice", 200, "Alice", 200, "Alice"));
        assertEquals(Verdict.SUPPORTED, notShown.verdict());
        assertTrue(notShown.detail().contains("marker absent"), notShown.detail());
    }

    @Test
    @DisplayName("N1: the read-back shows a change only if absent before and present in both reads after")
    void readBackNeedsAbsentBeforeAndTwoReadsAfter() {
        String m = "csrfmarkabc";
        assertTrue(readBack("/p", "f", m, 200, "x", 200, "x" + m, 204, m).showsChange());
        assertFalse(readBack("/p", "f", m, 200, "x", 200, "x" + m, 200, "x").showsChange(), "one-shot flash");
        assertFalse(readBack("/p", "f", m, 200, m, 200, m, 200, m).showsChange(), "marker already present before");
        assertFalse(readBack("/p", "f", m, 403, "x", 200, m, 200, m).showsChange(), "before read refused");
        assertFalse(readBack("/p", "f", m, 200, "x", 500, m, 200, m).showsChange(), "after read failed");
        assertFalse(readBack("/p", "f", m, 200, "x", 200, m, 302, m).showsChange(), "second read redirected");
        assertFalse(readBack("/p", "f", "", 200, "x", 200, "x", 200, "x").showsChange(), "no marker");
        assertFalse(readBack("/p", "f", null, 200, null, 200, null, 200, null).showsChange(), "nothing read");
        assertFalse(ReadBack.notRun("why").showsChange());
    }

    @Test
    @DisplayName("N2: only headers a cross-site page can make the browser send are kept")
    void crossSiteSendableHeaders() {
        for (String h : new String[] {"Cookie", "Content-Type", "Referer", "Origin", "Host", "User-Agent",
                "Accept-Language", "Sec-Fetch-Site", "sec-ch-ua", ":authority"}) {
            assertTrue(isCrossSiteSendableHeader(h), h);
        }
        for (String h : new String[] {"Authorization", "X-Auth-Token", "X-CSRF-Token", "X-Requested-With",
                "X-Api-Key", "X-Session-Id", "Proxy-Authorization"}) {
            assertFalse(isCrossSiteSendableHeader(h), h);
        }
        assertFalse(isCrossSiteSendableHeader(null));
    }

    @Test
    @DisplayName("Q1: the forged request carries a foreign page's Origin, no Referer and cross-site Fetch Metadata")
    void crossSiteBrowserHeadersAreAForeignPagesOwn() {
        var https = crossSiteBrowserHeaders("https://shop.example/profile/update", false);
        assertEquals("https://" + CROSS_SITE_PAGE_HOST, https.get("Origin"));
        assertTrue(https.containsKey("Referer") && https.get("Referer") == null, "Referer removed");
        assertEquals("cross-site", https.get("Sec-Fetch-Site"), "browsers send Fetch Metadata to https");
        assertEquals("navigate", https.get("Sec-Fetch-Mode"));
        assertEquals("document", https.get("Sec-Fetch-Dest"));
        assertTrue(https.containsKey("Sec-Fetch-User") && https.get("Sec-Fetch-User") == null, "no user activation");
        assertTrue(CROSS_SITE_PAGE_HOST.endsWith(".invalid"), "a reserved name, never a real site");

        var http = crossSiteBrowserHeaders("HTTP://shop.example/x", false);
        assertEquals("http://" + CROSS_SITE_PAGE_HOST, http.get("Origin"), "same scheme as the target");
        assertNull(http.get("Sec-Fetch-Site"), "no Fetch Metadata to plain http unless the capture had it");
        assertTrue(http.containsKey("Sec-Fetch-Site"), "a captured value is still removed");
        assertEquals("cross-site", crossSiteBrowserHeaders("http://localhost:8080/x", true).get("Sec-Fetch-Site"));
        assertEquals("https://" + CROSS_SITE_PAGE_HOST, crossSiteBrowserHeaders(null, false).get("Origin"));
    }

    @Test
    @DisplayName("Q2: only POST with a form enctype (or no body type) is sent cross-site without a preflight")
    void preflightReasons() {
        assertNull(preflightReason("POST", null));
        assertNull(preflightReason("POST", "application/x-www-form-urlencoded"));
        assertNull(preflightReason("post", "multipart/form-data; boundary=----x"));
        assertNull(preflightReason("POST", "Text/Plain;charset=UTF-8"));
        assertNull(preflightReason("GET", "application/json"), "a safe method is INVALID, not a preflight case");
        String json = preflightReason("POST", "application/json; charset=utf-8");
        assertTrue(json != null && json.contains("application/json") && json.contains("preflight"), json);
        assertNotNull(preflightReason("POST", "application/xml"));
        assertNotNull(preflightReason("POST", "text/plainx"), "an essence match, not a prefix");
        for (String m : new String[] {"PUT", "PATCH", "DELETE"}) {
            String reason = preflightReason(m, "application/x-www-form-urlencoded");
            assertTrue(reason != null && reason.contains(m) && reason.contains("preflight"), m + ": " + reason);
        }
        assertTrue(canSendAsTextPlain("POST", "application/json"));
        assertFalse(canSendAsTextPlain("PUT", "application/json"), "no-cors fetch() sends only GET, HEAD and POST");
        assertFalse(canSendAsTextPlain("POST", "application/x-www-form-urlencoded"), "already a simple request");
        assertFalse(canSendAsTextPlain(null, "application/json"));

        var fetch = textPlainFetchHeaders(crossSiteBrowserHeaders("https://shop.example/x", false));
        assertEquals("text/plain;charset=UTF-8", fetch.get("Content-Type"));
        assertEquals("no-cors", fetch.get("Sec-Fetch-Mode"));
        assertEquals("empty", fetch.get("Sec-Fetch-Dest"));
        assertEquals(java.util.Set.of("Content-Type"),
                textPlainFetchHeaders(crossSiteBrowserHeaders("http://shop.example/x", false)).keySet(),
                "no Fetch Metadata to add where the browser sends none");
    }

    @Test
    @DisplayName("Q2: a request that needs a preflight is at most SUPPORTED, naming it; refusals are unchanged")
    void preflightCapsTheVerdict() {
        String reason = preflightReason("POST", "application/json");
        Evidence capped = evaluate("POST", true, true, 200, 200, 403, SHOWN, reason);
        assertEquals(Verdict.SUPPORTED, capped.verdict());
        assertFalse(capped.confirmed());
        assertTrue(capped.confidence() <= 0.5);
        assertTrue(capped.summary().contains("preflight") && capped.summary().contains("application/json"), capped.summary());
        assertTrue(capped.detail().contains("preflight needed"), capped.detail());

        assertEquals(Verdict.CONFIRMED, evaluate("POST", true, true, 200, 200, 403, SHOWN, null).verdict(),
                "no preflight: the same as the seven-argument evaluate");
        assertEquals(Verdict.REJECTED, evaluate("POST", true, true, 200, 403, -1, null, reason).verdict(),
                "a refusal stays a refusal");
        assertEquals(Verdict.REJECTED, evaluate("POST", true, true, 200, 200, 200, SHOWN, reason).verdict(),
                "an action open to anyone stays REJECTED");
        assertEquals(Verdict.INVALID, evaluate("GET", true, true, 200, 200, 403, SHOWN, reason).verdict());
        Evidence passive = evaluate("PUT", true, false, 200, -1, -1, null, preflightReason("PUT", null));
        assertEquals(Verdict.SUPPORTED, passive.verdict());
        assertTrue(passive.summary().contains("PUT") && passive.detail().contains("preflight needed"), passive.detail());
    }

    @Test
    @DisplayName("N1: the change marker goes only on free-text fields, never credentials, contacts, links or ids")
    void markableFields() {
        assertTrue(isMarkableField("display_name", "Alice"));
        assertTrue(isMarkableField("bio", "Hello there"));
        assertTrue(isMarkableField("title", "Q3 plan"));
        assertFalse(isMarkableField("password", "Secret1"));
        assertFalse(isMarkableField("email", "alice"));
        assertFalse(isMarkableField("contact", "a@b.example"));
        assertFalse(isMarkableField("username", "alice"));
        assertFalse(isMarkableField("redirect", "home"));
        assertFalse(isMarkableField("website", "https://example.test"));
        assertFalse(isMarkableField("user_id", "abc"));
        assertFalse(isMarkableField("id", "abc"));
        assertFalse(isMarkableField("qty", "2"));
        assertFalse(isMarkableField("subscribe", "on"));
        assertFalse(isMarkableField("csrf_token", "abc"));
        assertFalse(isMarkableField("note", " "));
        assertFalse(isMarkableField("note", "x".repeat(201)));
        assertFalse(isMarkableField(null, "Alice"));
        assertFalse(isMarkableField("note", null));
    }

    @Test
    @DisplayName("N1: change markers are unique lower-case letters")
    void changeMarkersAreLettersOnly() {
        Random r = new Random(7);
        String a = newChangeMarker(r);
        String b = newChangeMarker(r);
        assertTrue(a.matches("csrfmark[a-z]{10}"), a);
        assertNotEquals(a, b);
    }
}
