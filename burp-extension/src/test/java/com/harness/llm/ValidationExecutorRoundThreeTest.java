package com.harness.llm;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.internal.MontoyaObjectFactory;
import burp.api.montoya.internal.ObjectFactoryLocator;
import com.harness.llm.FakeMontoya.Reply;
import com.harness.llm.FakeMontoya.Run;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.harness.llm.FakeMontoya.execute;
import static com.harness.llm.FakeMontoya.headerOf;
import static com.harness.llm.FakeMontoya.headers;
import static com.harness.llm.FakeMontoya.paramOf;
import static com.harness.llm.FakeMontoya.request;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The third round of Burp executor soundness (batch RV-Q, items Q1-Q5: the
 * residuals RV-N recorded), driven through the public ValidationExecutor.execute()
 * path like ValidationExecutorResidualsTest. A Burp-side confirmation must rest
 * on evidence a real attacker's request would also produce. Each item has the
 * reproduction (what the base got wrong), positive controls and negative controls.
 */
final class ValidationExecutorRoundThreeTest {
    private MontoyaObjectFactory previousFactory;

    @BeforeEach void installFactory() { previousFactory = FakeMontoya.installParameterFactory(); }
    @AfterEach void restoreFactory() { ObjectFactoryLocator.FACTORY = previousFactory; }

    private static String describe(Run run) {
        StringBuilder b = new StringBuilder();
        for (HttpRequest r : run.sent()) b.append(r.method()).append(' ').append(r.path()).append("; ");
        return b.toString();
    }

    private static List<HttpRequest> writes(Run run) {
        return run.sent().stream().filter(r -> !r.method().equals("GET")).toList();
    }

    // ------------------------------------------------------------------ Q1
    // A profile form: a write to /profile/update (display_name, csrf_token) from the page GET /profile.

    private static final String PROFILE_FORM = "/profile/update";
    private static final String SAME_ORIGIN_REFERER = FakeMontoya.ORIGIN + "/profile";

    private static HttpRequest profileUpdate(String method, Map<String, String> headers) {
        return request(method, PROFILE_FORM, "", headers, Map.of("display_name", "Alice", "csrf_token", "real"));
    }

    private static Map<String, String> session(String... more) {
        Map<String, String> h = new LinkedHashMap<>(headers("Cookie", "session=synthetic"));
        h.putAll(headers(more));
        return h;
    }

    /**
     * GET /profile shows the stored name to a session; any other method on
     * /profile/update stores display_name when {@code writeAllowed} passes,
     * else answers {@code refusal}. The CSRF token is never checked.
     */
    private static Function<HttpRequest, Reply> profileServer(AtomicReference<String> name,
                                                              Predicate<HttpRequest> writeAllowed, Reply refusal) {
        return r -> {
            if (r.method().equals("GET") && r.path().equals("/profile")) {
                return headerOf(r, "Cookie") == null ? Reply.of(403, "login required")
                        : Reply.of(200, "<h1>Profile</h1><p>Name: " + name.get() + "</p>");
            }
            if (!r.method().equals("GET") && r.path().equals(PROFILE_FORM)) {
                if (!writeAllowed.test(r)) return refusal;
                name.set(paramOf(r, "display_name"));
                return Reply.of(200, "{\"saved\":true}");
            }
            return Reply.of(404, "not found");
        };
    }

    private static boolean hasSession(HttpRequest r) { return headerOf(r, "Cookie") != null; }

    private static Run csrf(HttpRequest captured, AtomicReference<String> name, Predicate<HttpRequest> writeAllowed) throws Exception {
        return execute("csrf_validation", captured, Reply.of(200, "{\"saved\":true}"),
                profileServer(name, writeAllowed, Reply.of(403, "request refused")));
    }

    private static boolean sameOrigin(String value) {
        return value != null && (value.equals(FakeMontoya.ORIGIN) || value.startsWith(FakeMontoya.ORIGIN + "/"));
    }

    @Test
    @DisplayName("Q1 repro: a server that checks Origin refuses a real cross-site request, so it is not confirmed")
    void csrfOriginCheckedServerIsNotConfirmed() throws Exception {
        AtomicReference<String> name = new AtomicReference<>("Alice");
        Run run = csrf(profileUpdate("POST", session("Origin", FakeMontoya.ORIGIN, "Referer", SAME_ORIGIN_REFERER)),
                name, r -> hasSession(r) && FakeMontoya.ORIGIN.equals(headerOf(r, "Origin")));
        assertFalse(run.confirmed(), "Origin-checked: " + run.status() + " " + run.submission().summary);
        HttpRequest forged = writes(run).get(0);
        assertNotNull(headerOf(forged, "Origin"), "a browser sends Origin on a cross-site POST");
        assertFalse(sameOrigin(headerOf(forged, "Origin")), "the forged Origin is foreign: " + headerOf(forged, "Origin"));
        assertEquals("Alice", name.get(), "the cross-site request changed nothing");
    }

    @Test
    @DisplayName("Q1 repro: a server that checks Referer refuses a real cross-site request, so it is not confirmed")
    void csrfRefererCheckedServerIsNotConfirmed() throws Exception {
        AtomicReference<String> name = new AtomicReference<>("Alice");
        Run run = csrf(profileUpdate("POST", session("Referer", SAME_ORIGIN_REFERER)),
                name, r -> hasSession(r) && sameOrigin(headerOf(r, "Referer")));
        assertFalse(run.confirmed(), "Referer-checked: " + run.status() + " " + run.submission().summary);
        assertFalse(sameOrigin(headerOf(writes(run).get(0), "Referer")), "the forged Referer is not same-origin");
        assertEquals("Alice", name.get(), "the cross-site request changed nothing");
    }

    @Test
    @DisplayName("Q1 repro: a capture without Origin is still sent with a foreign one, as a browser would")
    void csrfMissingOriginIsSentAsCrossSite() throws Exception {
        AtomicReference<String> name = new AtomicReference<>("Alice");
        Predicate<HttpRequest> originIfPresent = r -> hasSession(r)
                && (headerOf(r, "Origin") == null || FakeMontoya.ORIGIN.equals(headerOf(r, "Origin")));
        Run run = csrf(profileUpdate("POST", session("Referer", SAME_ORIGIN_REFERER)), name, originIfPresent);
        assertFalse(run.confirmed(), "Origin checked when present: " + run.status() + " " + run.submission().summary);
        assertEquals("Alice", name.get());
    }

    @Test
    @DisplayName("Q1 repro: a Fetch Metadata check (Sec-Fetch-Site) refuses a real cross-site request")
    void csrfFetchMetadataCheckedServerIsNotConfirmed() throws Exception {
        AtomicReference<String> name = new AtomicReference<>("Alice");
        Run run = csrf(profileUpdate("POST", session("Referer", SAME_ORIGIN_REFERER, "Sec-Fetch-Site", "same-origin")),
                name, r -> hasSession(r) && !"cross-site".equals(headerOf(r, "Sec-Fetch-Site")));
        assertFalse(run.confirmed(), "Fetch Metadata: " + run.status() + " " + run.submission().summary);
        assertEquals("cross-site", headerOf(writes(run).get(0), "Sec-Fetch-Site"));
        assertEquals("Alice", name.get());
    }

    @Test
    @DisplayName("Q1 positive control: a cookie-only server with no Origin/Referer check is still confirmed, sent cross-site")
    void csrfNoOriginCheckIsStillConfirmed() throws Exception {
        AtomicReference<String> name = new AtomicReference<>("Alice");
        Run run = csrf(profileUpdate("POST", session("Origin", FakeMontoya.ORIGIN, "Referer", SAME_ORIGIN_REFERER,
                "Sec-Fetch-Site", "same-origin")), name, ValidationExecutorRoundThreeTest::hasSession);
        assertTrue(run.confirmed(), run.status() + " " + run.submission().summary + " | " + run.submission().evidence);
        assertEquals("GET /profile; POST /profile/update; GET /profile; GET /profile; POST /profile/update; ", describe(run),
                "RV-N's sequence: read before, forged write, two reads after, then the no-cookie control");
        for (HttpRequest write : writes(run)) {
            assertFalse(sameOrigin(headerOf(write, "Origin")), "Origin is foreign on every write");
            assertFalse(sameOrigin(headerOf(write, "Referer")), "Referer is not same-origin on every write");
            assertEquals("cross-site", headerOf(write, "Sec-Fetch-Site"));
        }
        assertTrue(name.get().startsWith("Alice") && name.get().length() > "Alice".length(), "the marked value was stored");
        assertTrue(run.submission().evidence.contains("cross-site"), "the evidence says how it was sent: " + run.submission().evidence);
    }

}
