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

    // ------------------------------------------------------------------ Q2
    // The fakes model a JSON body's fields as request parameters, as Burp lists them.

    private static final String JSON_PROFILE = "{\"display_name\":\"Alice\",\"csrf_token\":\"real\"}";

    private static HttpRequest jsonProfileUpdate() {
        return request("POST", PROFILE_FORM, JSON_PROFILE,
                session("Content-Type", "application/json", "Referer", SAME_ORIGIN_REFERER),
                Map.of("display_name", "Alice", "csrf_token", "real"));
    }

    private static boolean jsonContentType(HttpRequest r) {
        String ct = headerOf(r, "Content-Type");
        return ct != null && ct.toLowerCase(java.util.Locale.ROOT).startsWith("application/json");
    }

    @Test
    @DisplayName("Q2 repro: a JSON request needs a CORS preflight cross-site, so it is not confirmed as CSRF")
    void csrfJsonRequestIsNotConfirmed() throws Exception {
        AtomicReference<String> name = new AtomicReference<>("Alice");
        Run run = csrf(jsonProfileUpdate(), name, r -> hasSession(r) && jsonContentType(r));
        assertFalse(run.confirmed(), "JSON request: " + run.status() + " " + run.submission().summary);
        assertEquals("supported", run.status(), "the token is still not enforced, a lead: " + run.submission().summary);
        assertTrue(run.submission().summary.contains("preflight"), "names the preflight: " + run.submission().summary);
        assertTrue(run.submission().summary.contains("application/json"), run.submission().summary);
        assertEquals("GET /profile; POST /profile/update; POST /profile/update; POST /profile/update; ", describe(run),
                "read before, the text/plain variant (refused), the request as captured, then the no-cookie control");
        assertEquals("text/plain;charset=UTF-8", headerOf(writes(run).get(0), "Content-Type"));
        assertEquals("application/json", headerOf(writes(run).get(1), "Content-Type"));
        assertTrue(run.sent().size() <= 6, "RV-N's request ceiling: " + describe(run));
    }

    @Test
    @DisplayName("Q2 positive control: a JSON body the server reads whatever its type goes as text/plain -> confirmed")
    void csrfJsonBodyReadAsTextPlainIsConfirmed() throws Exception {
        AtomicReference<String> name = new AtomicReference<>("Alice");
        Run run = csrf(jsonProfileUpdate(), name, ValidationExecutorRoundThreeTest::hasSession);
        assertTrue(run.confirmed(), run.status() + " " + run.submission().summary + " | " + run.submission().evidence);
        assertEquals("GET /profile; POST /profile/update; GET /profile; GET /profile; POST /profile/update; ", describe(run));
        HttpRequest forged = writes(run).get(0);
        assertEquals("text/plain;charset=UTF-8", headerOf(forged, "Content-Type"), "a no-cors fetch() can send it");
        assertEquals("no-cors", headerOf(forged, "Sec-Fetch-Mode"));
        assertEquals("empty", headerOf(forged, "Sec-Fetch-Dest"));
        assertTrue(run.submission().evidence.contains("text/plain"), run.submission().evidence);
    }

    @Test
    @DisplayName("Q2 repro: a PUT needs a CORS preflight cross-site, so it is not confirmed as CSRF")
    void csrfPutRequestIsNotConfirmed() throws Exception {
        AtomicReference<String> name = new AtomicReference<>("Alice");
        Run run = csrf(profileUpdate("PUT", session("Referer", SAME_ORIGIN_REFERER)), name, ValidationExecutorRoundThreeTest::hasSession);
        assertFalse(run.confirmed(), "PUT: " + run.status() + " " + run.submission().summary);
        assertEquals("supported", run.status());
        assertTrue(run.submission().summary.contains("preflight") && run.submission().summary.contains("PUT"),
                run.submission().summary);
        assertTrue(run.sent().size() <= 6, "RV-N's request ceiling: " + describe(run));
    }

    @Test
    @DisplayName("Q2 control: a JSON request whose token is enforced is still rejected")
    void csrfJsonRequestWithEnforcedTokenIsRejected() throws Exception {
        AtomicReference<String> name = new AtomicReference<>("Alice");
        Run run = csrf(jsonProfileUpdate(), name, r -> hasSession(r) && "real".equals(paramOf(r, "csrf_token")));
        assertFalse(run.confirmed());
        assertEquals("rejected", run.status(), run.submission().summary);
        assertTrue(run.sent().size() <= 6, "RV-N's request ceiling: " + describe(run));
    }

    @Test
    @DisplayName("Q2 positive control: an urlencoded form request is still confirmed")
    void csrfFormEncodedRequestIsConfirmed() throws Exception {
        AtomicReference<String> name = new AtomicReference<>("Alice");
        Run run = csrf(profileUpdate("POST", session("Content-Type", "application/x-www-form-urlencoded",
                "Referer", SAME_ORIGIN_REFERER)), name, ValidationExecutorRoundThreeTest::hasSession);
        assertTrue(run.confirmed(), run.status() + " " + run.submission().summary + " | " + run.submission().evidence);
    }

    @Test
    @DisplayName("Q2 positive control: a text/plain request (a form or a no-cors fetch can send it) is still confirmed")
    void csrfTextPlainRequestIsConfirmed() throws Exception {
        AtomicReference<String> name = new AtomicReference<>("Alice");
        Run run = csrf(profileUpdate("POST", session("Content-Type", "text/plain;charset=UTF-8",
                "Referer", SAME_ORIGIN_REFERER)), name, ValidationExecutorRoundThreeTest::hasSession);
        assertTrue(run.confirmed(), run.status() + " " + run.submission().summary + " | " + run.submission().evidence);
    }

    // ------------------------------------------------------------------ Q3
    private static final String JWT = "eyJhbGciOiJIUzI1NiJ9.e30.c2ln";
    private static final String ACCOUNT = "{\"account\":\"synthetic\"}";

    private static String cookieValue(HttpRequest r, String name) {
        String cookie = headerOf(r, "Cookie");
        if (cookie == null) return null;
        Matcher m = Pattern.compile("(?:^|;\\s*)" + Pattern.quote(name) + "=([^;]*)").matcher(cookie);
        return m.find() ? m.group(1) : null;
    }

    private static String bearer(HttpRequest r) {
        String auth = headerOf(r, "Authorization");
        return auth != null && auth.startsWith("Bearer ") ? auth.substring(7) : null;
    }

    private static Run jwt(Map<String, String> headers, Predicate<HttpRequest> accepted) throws Exception {
        return execute("jwt_validation", request("GET", "/account", "", headers), Reply.of(200, ACCOUNT),
                r -> accepted.test(r) ? Reply.of(200, ACCOUNT) : Reply.of(401, "unauthorized"));
    }

    @Test
    @DisplayName("Q3 repro (precision): a verified bearer JWT that also needs a non-credential cookie is rejected")
    void jwtVerifiedWithRequiredTenantCookieIsRejected() throws Exception {
        Run run = jwt(headers("Authorization", "Bearer " + JWT, "Cookie", "tenant=acme"),
                r -> "acme".equals(cookieValue(r, "tenant")) && JWT.equals(bearer(r)));
        assertFalse(run.confirmed(), run.status() + " " + run.submission().summary);
        assertEquals("rejected", run.status(), run.submission().summary + " | " + run.submission().evidence);
        assertTrue(run.submission().evidence.contains("tenant"), "the kept cookie is named: " + run.submission().evidence);
    }

    @Test
    @DisplayName("Q3 repro (precision): a verified cookie JWT next to a required non-credential cookie is rejected")
    void jwtCookieVerifiedWithRequiredTenantCookieIsRejected() throws Exception {
        Run run = jwt(headers("Cookie", "tenant=acme; token=" + JWT),
                r -> "acme".equals(cookieValue(r, "tenant")) && JWT.equals(cookieValue(r, "token")));
        assertFalse(run.confirmed(), run.status() + " " + run.submission().summary);
        assertEquals("rejected", run.status(), run.submission().summary + " | " + run.submission().evidence);
    }

    @Test
    @DisplayName("Q3 control: an unverified JWT accepted only beside a kept cookie is a lead, never a confirmation")
    void jwtUnverifiedWithRequiredTenantCookieIsNotConfirmed() throws Exception {
        Run run = jwt(headers("Authorization", "Bearer " + JWT, "Cookie", "tenant=acme"),
                r -> "acme".equals(cookieValue(r, "tenant")) && com.harness.llm.logic.JwtForgeryLogic.looksLikeJwt(bearer(r)));
        assertFalse(run.confirmed(), "a kept cookie could be what authenticates: " + run.status() + " " + run.submission().summary);
        assertNotEquals("rejected", run.status(), "a forged token was accepted: " + run.submission().summary);
    }

    @Test
    @DisplayName("Q3 control: a credential-like cookie is never kept, so a session plus a verified token stays inconclusive")
    void jwtCredentialCookieIsNeverKept() throws Exception {
        Run run = jwt(headers("Authorization", "Bearer " + JWT, "Cookie", "session=valid; tenant=acme"),
                r -> "valid".equals(cookieValue(r, "session")) && "acme".equals(cookieValue(r, "tenant")) && JWT.equals(bearer(r)));
        assertFalse(run.confirmed());
        assertEquals("inconclusive", run.status(), run.submission().summary);
        for (HttpRequest r : run.sent()) assertNull(cookieValue(r, "session"), "no probe carries the session cookie");
    }

    @Test
    @DisplayName("Q3 control: a session cookie the credential name rule misses (PHPSESSID) is not kept either")
    void jwtPhpSessionCookieIsNeverKept() throws Exception {
        Run run = jwt(headers("Authorization", "Bearer " + JWT, "Cookie", "PHPSESSID=abc; tenant=acme"),
                r -> "abc".equals(cookieValue(r, "PHPSESSID")) && JWT.equals(bearer(r)));
        assertFalse(run.confirmed());
        assertEquals("inconclusive", run.status(), run.submission().summary);
        for (HttpRequest r : run.sent()) assertNull(cookieValue(r, "PHPSESSID"), "no probe carries the session cookie");
        assertTrue(run.sent().size() <= 3 + 4, "at most four requests more than RV-N's three: " + run.sent().size());
    }

}
