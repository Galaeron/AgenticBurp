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

    // ------------------------------------------------------------------ Q4
    private static final Pattern ROLE_ADMIN = Pattern.compile("\"role\"\\s*:\\s*\"admin\"");

    /**
     * POST /users creates a user (ids prefix+44 onwards) and answers 201 with
     * the body {@code created} builds from the new id and the request body;
     * GET /users lists ids only; GET /users/{id} shows the user.
     */
    private static Function<HttpRequest, Reply> usersServer(Map<String, String> roles, String prefix,
                                                            java.util.function.BiFunction<String, String, String> created,
                                                            Map<String, String> createdHeaders) {
        int[] next = {44};
        return r -> {
            if (r.method().equals("POST") && r.path().equals("/users")) {
                String id = prefix + next[0]++;
                roles.put(id, ROLE_ADMIN.matcher(r.bodyToString()).find() ? "admin" : "user");
                return new Reply(201, created.apply(id, r.bodyToString()), createdHeaders);
            }
            if (r.method().equals("GET") && r.path().equals("/users")) {
                return Reply.of(200, "[" + String.join(",", roles.keySet().stream().map(k -> "{\"ref\":\"" + k + "\"}").toList()) + "]");
            }
            if (r.method().equals("GET") && r.path().startsWith("/users/")) {
                String id = r.path().substring("/users/".length());
                String role = roles.get(id);
                return role == null ? Reply.of(404, "no such user")
                        : Reply.of(200, "{\"ref\":\"" + id + "\",\"name\":\"sample\",\"role\":\"" + role + "\"}");
            }
            return Reply.of(404, "not found");
        };
    }

    /** The request body echoed with {@code "key": id} added (a string id quoted, a number not). */
    private static String echoWith(String key, String id, String requestBody) {
        String value = id.chars().allMatch(Character::isDigit) ? id : "\"" + id + "\"";
        return requestBody.substring(0, requestBody.lastIndexOf('}')) + ",\"" + key + "\":" + value + "}";
    }

    private static Run createUser(Map<String, String> roles, String prefix, String capturedBody,
                                  java.util.function.BiFunction<String, String, String> created) throws Exception {
        return createUser(roles, prefix, capturedBody, created, Map.of());
    }

    private static Run createUser(Map<String, String> roles, String prefix, String capturedBody,
                                  java.util.function.BiFunction<String, String, String> created,
                                  Map<String, String> createdHeaders) throws Exception {
        return execute("api_security_validation",
                request("POST", "/users", "{\"name\":\"sample\"}", headers("Content-Type", "application/json", "Cookie", "session=synthetic")),
                new Reply(201, capturedBody, createdHeaders), usersServer(roles, prefix, created, createdHeaders));
    }

    @Test
    @DisplayName("Q4 repro (recall): a created object named by \"userId\" is read back -> confirmed")
    void massAssignmentUserIdIsConfirmed() throws Exception {
        Map<String, String> roles = new java.util.concurrent.ConcurrentHashMap<>(Map.of("43", "user"));
        Run run = createUser(roles, "", "{\"name\":\"sample\",\"userId\":43}", (id, body) -> echoWith("userId", id, body));
        assertTrue(run.confirmed(), run.status() + " " + run.submission().summary + " | " + run.submission().evidence);
        assertEquals("GET /users/43; POST /users; GET /users/44; ", describe(run));
    }

    @Test
    @DisplayName("Q4 repro (recall): a created object named by a nested data.id is read back -> confirmed")
    void massAssignmentNestedDataIdIsConfirmed() throws Exception {
        Map<String, String> roles = new java.util.concurrent.ConcurrentHashMap<>(Map.of("43", "user"));
        Run run = createUser(roles, "", "{\"data\":{\"type\":\"users\",\"id\":\"43\"}}",
                (id, body) -> "{\"data\":{\"type\":\"users\",\"id\":\"" + id + "\",\"attributes\":" + body + "}}");
        assertTrue(run.confirmed(), run.status() + " " + run.submission().summary + " | " + run.submission().evidence);
        assertEquals("GET /users/43; POST /users; GET /users/44; ", describe(run));
    }

    @Test
    @DisplayName("Q4 repro (recall): a created object named by \"uuid\" is read back -> confirmed")
    void massAssignmentUuidIsConfirmed() throws Exception {
        Map<String, String> roles = new java.util.concurrent.ConcurrentHashMap<>(Map.of("u-43", "user"));
        Run run = createUser(roles, "u-", "{\"uuid\":\"u-43\",\"name\":\"sample\"}", (id, body) -> echoWith("uuid", id, body));
        assertTrue(run.confirmed(), run.status() + " " + run.submission().summary + " | " + run.submission().evidence);
        assertEquals("GET /users/u-43; POST /users; GET /users/u-44; ", describe(run));
    }

    @Test
    @DisplayName("Q4 control: two candidate ids are ambiguous, so no object is read and the result stays supported")
    void massAssignmentAmbiguousIdsStaySupported() throws Exception {
        Map<String, String> roles = new java.util.concurrent.ConcurrentHashMap<>(Map.of("43", "user", "u-9", "user"));
        Run run = createUser(roles, "", "{\"userId\":43,\"uuid\":\"u-9\",\"name\":\"sample\"}",
                (id, body) -> echoWith("uuid", "u-9", echoWith("userId", id, body)));
        assertFalse(run.confirmed(), run.status() + " " + run.submission().summary);
        assertEquals("supported", run.status(), run.submission().summary);
        assertTrue(run.sent().stream().noneMatch(r -> r.path().startsWith("/users/")), "no object read: " + describe(run));
    }

    @Test
    @DisplayName("Q4 control: a top-level \"id\" keeps its priority (the base rule), even beside another candidate")
    void massAssignmentTopLevelIdKeepsPriority() throws Exception {
        Map<String, String> roles = new java.util.concurrent.ConcurrentHashMap<>(Map.of("43", "user", "7", "user"));
        Run run = createUser(roles, "", "{\"id\":43,\"userId\":7,\"name\":\"sample\"}",
                (id, body) -> echoWith("userId", "7", echoWith("id", id, body)));
        assertTrue(run.confirmed(), run.status() + " " + run.submission().summary + " | " + run.submission().evidence);
        assertEquals("GET /users/43; POST /users; GET /users/44; ", describe(run));
    }

    @Test
    @DisplayName("Q4 control: a cross-origin Location is never read, even when the body also carries an id")
    void massAssignmentCrossOriginLocationWithBodyIdIsNotRead() throws Exception {
        Map<String, String> roles = new java.util.concurrent.ConcurrentHashMap<>(Map.of("43", "user"));
        Run run = createUser(roles, "", "{\"id\":43,\"name\":\"sample\"}", (id, body) -> echoWith("id", id, body),
                Map.of("Location", "https://other.example/users/43"));
        assertFalse(run.confirmed(), run.status() + " " + run.submission().summary);
        assertTrue(run.sent().stream().noneMatch(r -> r.path().startsWith("/users/")), "sent " + describe(run));
    }

    // ------------------------------------------------------------------ Q5
    /** HTML-encodes & < > " but not the single quote, as many templates do. */
    private static String encodeNoApostrophe(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }

    private static Run xss(String before, String after) throws Exception {
        return execute("reflection_context_validation",
                request("GET", "/search", "", Map.of(), Map.of("q", "ordinary")),
                Reply.of(200, "<html></html>"),
                r -> Reply.of(200, "<html><body>" + before + encodeNoApostrophe(paramOf(r, "q")) + after + "</body></html>"));
    }

    @Test
    @DisplayName("Q5 repro: a <script> with a non-JavaScript type is a data block, not script -> not confirmed")
    void xssTemplateScriptTypeIsNotConfirmed() throws Exception {
        Run run = xss("<script type=\"text/template\">var q='", "';</script>");
        assertFalse(run.confirmed(), run.status() + " " + run.submission().summary);
    }

    @Test
    @DisplayName("Q5 repro: a <script type=application/json> data block is not script -> not confirmed")
    void xssJsonScriptTypeIsNotConfirmed() throws Exception {
        Run run = xss("<script type='application/json'>{\"q\": '", "'}</script>");
        assertFalse(run.confirmed(), run.status() + " " + run.submission().summary);
    }

    @Test
    @DisplayName("Q5 repro: a <script> inside <template> content is inert -> not confirmed")
    void xssScriptInsideTemplateIsNotConfirmed() throws Exception {
        Run run = xss("<template><script>var q='", "';</script></template>");
        assertFalse(run.confirmed(), run.status() + " " + run.submission().summary);
    }

    @Test
    @DisplayName("Q5 repro: an event handler inside <template> content is inert -> not confirmed")
    void xssHandlerInsideTemplateIsNotConfirmed() throws Exception {
        Run run = xss("<template><button onclick=\"track('", "')\">Go</button></template>");
        assertFalse(run.confirmed(), run.status() + " " + run.submission().summary);
    }

    @Test
    @DisplayName("Q5 positive control: a plain <script> still confirms")
    void xssPlainScriptIsConfirmed() throws Exception {
        Run run = xss("<script>var q='", "';</script>");
        assertTrue(run.confirmed(), run.status() + " " + run.submission().summary);
    }

    @Test
    @DisplayName("Q5 positive control: type=text/javascript still confirms")
    void xssTextJavascriptTypeIsConfirmed() throws Exception {
        Run run = xss("<script type=\"text/javascript\">var q='", "';</script>");
        assertTrue(run.confirmed(), run.status() + " " + run.submission().summary);
    }

    @Test
    @DisplayName("Q5 positive control: type=module still confirms")
    void xssModuleTypeIsConfirmed() throws Exception {
        Run run = xss("<script type=module>var q='", "';</script>");
        assertTrue(run.confirmed(), run.status() + " " + run.submission().summary);
    }

    @Test
    @DisplayName("Q5 positive control: a <script> after a closed <template> is live again")
    void xssScriptAfterTemplateIsConfirmed() throws Exception {
        Run run = xss("<template><p>row</p></template><script>var q='", "';</script>");
        assertTrue(run.confirmed(), run.status() + " " + run.submission().summary);
    }
}
