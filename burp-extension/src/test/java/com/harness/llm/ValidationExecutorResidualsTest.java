package com.harness.llm;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.internal.MontoyaObjectFactory;
import burp.api.montoya.internal.ObjectFactoryLocator;
import com.harness.llm.FakeMontoya.Reply;
import com.harness.llm.FakeMontoya.Run;
import com.harness.llm.logic.JwtForgeryLogic;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

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
 * The four residuals RV-J recorded (batch RV-N, items N1-N4), driven through
 * the public ValidationExecutor.execute() path like ValidationExecutorSoundnessTest.
 * Each item has the reproduction (what the tip got wrong), a positive control
 * (the check still confirms a real case) and negative controls.
 */
final class ValidationExecutorResidualsTest {
    private static final String SAME = "same response content";
    private MontoyaObjectFactory previousFactory;

    @BeforeEach void installFactory() { previousFactory = FakeMontoya.installParameterFactory(); }
    @AfterEach void restoreFactory() { ObjectFactoryLocator.FACTORY = previousFactory; }

    private static String describe(Run run) {
        StringBuilder b = new StringBuilder();
        for (HttpRequest r : run.sent()) b.append(r.method()).append(' ').append(r.path()).append("; ");
        return b.toString();
    }

    private static List<HttpRequest> posts(Run run) {
        return run.sent().stream().filter(r -> r.method().equals("POST")).toList();
    }

    // ------------------------------------------------------------------ N1
    // A profile form: POST /profile/update (display_name, csrf_token) from the page GET /profile.

    private static final String PROFILE_FORM = "/profile/update";

    private static HttpRequest profileUpdate(Map<String, String> extraHeaders) {
        Map<String, String> h = new java.util.LinkedHashMap<>(headers(
                "Cookie", "session=synthetic", "Referer", FakeMontoya.ORIGIN + "/profile"));
        h.putAll(extraHeaders);
        return request("POST", PROFILE_FORM, "", h, Map.of("display_name", "Alice", "csrf_token", "real"));
    }

    /**
     * GET /profile shows the stored name to a session; POST /profile/update
     * stores display_name when {@code writeAllowed} passes, else answers
     * {@code refusal}.
     */
    private static Function<HttpRequest, Reply> profileServer(AtomicReference<String> name,
                                                              Predicate<HttpRequest> writeAllowed, Reply refusal) {
        return r -> {
            if (r.method().equals("GET") && r.path().equals("/profile")) {
                return headerOf(r, "Cookie") == null ? Reply.of(403, "login required")
                        : Reply.of(200, "<h1>Profile</h1><p>Name: " + name.get() + "</p>");
            }
            if (r.method().equals("POST") && r.path().equals(PROFILE_FORM)) {
                if (!writeAllowed.test(r)) return refusal;
                name.set(paramOf(r, "display_name"));
                return Reply.of(200, "{\"saved\":true}");
            }
            return Reply.of(404, "not found");
        };
    }

    private static boolean hasSession(HttpRequest r) { return headerOf(r, "Cookie") != null; }

    @Test
    @DisplayName("N1 repro: a 200 'invalid CSRF token' page that changes nothing is not confirmed")
    void csrfInvalidTokenPageIsNotConfirmed() throws Exception {
        AtomicReference<String> name = new AtomicReference<>("Alice");
        Function<HttpRequest, Reply> server = r -> {
            if (r.method().equals("POST") && hasSession(r) && !"real".equals(paramOf(r, "csrf_token"))) {
                return Reply.of(200, "<p>Invalid CSRF token. Please reload the form.</p>");
            }
            return profileServer(name, ValidationExecutorResidualsTest::hasSession, Reply.of(403, "login required")).apply(r);
        };
        Run run = execute("csrf_validation", profileUpdate(Map.of()), Reply.of(200, "{\"saved\":true}"), server);
        assertFalse(run.confirmed(), "200 error page: " + run.status() + " " + run.submission().summary);
        assertEquals("supported", run.status(), "still a lead: token-less request answered 2xx; sent " + describe(run));
        assertEquals("Alice", name.get(), "nothing was stored");
    }

    @Test
    @DisplayName("N1 repro: a flashed re-render of the submitted input (one read only) is not stored state")
    void csrfFlashedInputIsNotConfirmed() throws Exception {
        AtomicReference<String> name = new AtomicReference<>("Alice");
        AtomicReference<String> flash = new AtomicReference<>();
        Function<HttpRequest, Reply> server = r -> {
            if (r.method().equals("POST") && hasSession(r) && !"real".equals(paramOf(r, "csrf_token"))) {
                flash.set(paramOf(r, "display_name"));
                return Reply.of(200, "<p>Invalid CSRF token.</p>");
            }
            if (r.method().equals("GET") && r.path().equals("/profile") && hasSession(r) && flash.get() != null) {
                String old = flash.getAndSet(null);
                return Reply.of(200, "<p>Name: " + name.get() + "</p><input name=display_name value=\"" + old + "\">");
            }
            return profileServer(name, ValidationExecutorResidualsTest::hasSession, Reply.of(403, "login required")).apply(r);
        };
        Run run = execute("csrf_validation", profileUpdate(Map.of()), Reply.of(200, "{\"saved\":true}"), server);
        assertFalse(run.confirmed(), "flashed input: " + run.status() + " " + run.submission().summary);
        assertTrue(run.submission().evidence.contains("again status=200 (marker absent)"),
                "the second read is what tells flash from storage: " + run.submission().evidence);
    }

    @Test
    @DisplayName("N1 repro: a token-less 2xx with no field to mark and read back is supported, not confirmed")
    void csrfNoReadableChangeIsSupported() throws Exception {
        Run run = execute("csrf_validation",
                request("POST", "/cart/add", "", headers("Cookie", "session=synthetic"),
                        Map.of("item", "42", "qty", "2", "csrf_token", "real")),
                Reply.of(200, "{\"ok\":true}"),
                r -> hasSession(r) ? Reply.of(200, "{\"ok\":true}") : Reply.of(403, "login required"));
        assertFalse(run.confirmed(), "no read-back: " + run.status() + " " + run.submission().summary);
        assertEquals("supported", run.status());
    }

    @Test
    @DisplayName("N1 positive control: token ignored, the change is stored and read back -> confirmed")
    void csrfStoredChangeIsConfirmed() throws Exception {
        AtomicReference<String> name = new AtomicReference<>("Alice");
        Run run = execute("csrf_validation", profileUpdate(Map.of()), Reply.of(200, "{\"saved\":true}"),
                profileServer(name, ValidationExecutorResidualsTest::hasSession, Reply.of(403, "login required")));
        assertTrue(run.confirmed(), run.status() + " " + run.submission().summary + " | " + run.submission().evidence);
        assertEquals("GET /profile; POST /profile/update; GET /profile; GET /profile; POST /profile/update; ", describe(run),
                "read before, forged write, two reads after, then the no-cookie control");
        HttpRequest forged = posts(run).get(0);
        assertNotEquals("real", paramOf(forged, "csrf_token"), "forged request does not carry the real token");
        assertTrue(paramOf(forged, "display_name").startsWith("Alice"), "marker appended to the submitted value");
        assertTrue(name.get().startsWith("Alice") && name.get().length() > "Alice".length(), "the marked value was stored");
        assertNull(headerOf(posts(run).get(1), "Cookie"), "control is the forged request without the cookie");
    }

    @Test
    @DisplayName("N1 control: a stored change that anyone can make, cookie or not, is not cookie CSRF")
    void csrfPublicActionWithRealChangeIsRejected() throws Exception {
        AtomicReference<String> name = new AtomicReference<>("Alice");
        Function<HttpRequest, Reply> server = r -> {
            if (r.method().equals("POST")) { name.set(paramOf(r, "display_name")); return Reply.of(200, "{\"saved\":true}"); }
            return profileServer(name, x -> true, Reply.of(403, "")).apply(r);
        };
        Run run = execute("csrf_validation", profileUpdate(Map.of()), Reply.of(200, "{\"saved\":true}"), server);
        assertFalse(run.confirmed(), "public action: " + run.status() + " " + run.submission().summary);
        assertEquals("rejected", run.status());
        assertTrue(run.sent().stream().anyMatch(r -> r.method().equals("POST") && headerOf(r, "Cookie") == null),
                "the no-cookie control was sent; sent " + describe(run));
    }

    // ------------------------------------------------------------------ N2 (CSRF)

    @Test
    @DisplayName("N2 repro: a credential in X-Auth-Token is not something a cross-site page can send")
    void csrfCustomHeaderCredentialIsStripped() throws Exception {
        AtomicReference<String> name = new AtomicReference<>("Alice");
        Predicate<HttpRequest> needsHeaderAndCookie = r -> hasSession(r) && "secret".equals(headerOf(r, "X-Auth-Token"));
        Run run = execute("csrf_validation", profileUpdate(Map.of("X-Auth-Token", "secret")),
                Reply.of(200, "{\"saved\":true}"), profileServer(name, needsHeaderAndCookie, Reply.of(401, "unauthorized")));
        assertFalse(run.confirmed(), "custom-header credential: " + run.status() + " " + run.submission().summary);
        HttpRequest forged = posts(run).get(0);
        assertNull(headerOf(forged, "X-Auth-Token"), "forged request drops the custom credential header");
        assertEquals("session=synthetic", headerOf(forged, "Cookie"), "forged request keeps the ambient cookie");
        assertTrue(run.submission().evidence.contains("x-auth-token"), "the stripped carrier is recorded: " + run.submission().evidence);
        assertEquals("Alice", name.get(), "the cross-site request changed nothing");
    }

    @Test
    @DisplayName("N2 repro: with a header token and a form token, both are invalidated")
    void csrfHeaderAndParameterTokensAreBothInvalidated() throws Exception {
        AtomicReference<String> name = new AtomicReference<>("Alice");
        Predicate<HttpRequest> paramTokenChecked = r -> hasSession(r) && "real".equals(paramOf(r, "csrf_token"));
        Run run = execute("csrf_validation", profileUpdate(Map.of("X-CSRF-Token", "real")),
                Reply.of(200, "{\"saved\":true}"), profileServer(name, paramTokenChecked, Reply.of(403, "bad token")));
        assertFalse(run.confirmed(), "form token enforced: " + run.status() + " " + run.submission().summary);
        HttpRequest forged = posts(run).get(0);
        assertNull(headerOf(forged, "X-CSRF-Token"), "header token removed");
        assertNotEquals("real", paramOf(forged, "csrf_token"), "form token invalidated too");
        assertTrue(run.submission().evidence.contains("header X-CSRF-Token")
                && run.submission().evidence.contains("url parameter csrf_token"),
                "both carriers are recorded: " + run.submission().evidence);
    }

    @Test
    @DisplayName("N2 positive control: credential in the cookie only, header token ignored -> still confirmed")
    void csrfCookieOnlyWithHeaderTokenIsConfirmed() throws Exception {
        AtomicReference<String> name = new AtomicReference<>("Alice");
        Run run = execute("csrf_validation", profileUpdate(Map.of("X-CSRF-Token", "real", "X-Requested-With", "XMLHttpRequest")),
                Reply.of(200, "{\"saved\":true}"),
                profileServer(name, ValidationExecutorResidualsTest::hasSession, Reply.of(403, "login required")));
        assertTrue(run.confirmed(), run.status() + " " + run.submission().summary + " | " + run.submission().evidence);
        HttpRequest forged = posts(run).get(0);
        assertNull(headerOf(forged, "X-Requested-With"), "a script-set header is not sent cross-site");
        // RV-Q item Q1: this asserted the captured same-origin Referer was kept,
        // which a cross-site page cannot send; the browser sets its own.
        assertNull(headerOf(forged, "Referer"), "a cross-site form sent with rel=noreferrer carries no Referer");
        assertEquals("https://" + com.harness.llm.logic.CsrfLogic.CROSS_SITE_PAGE_HOST, headerOf(forged, "Origin"),
                "the browser sets the foreign page's Origin");
    }

    // ------------------------------------------------------------------ N2 (JWT)
    private static final String JWT = "eyJhbGciOiJIUzI1NiJ9.e30.c2ln";
    private static final String ACCOUNT = "{\"account\":\"synthetic\"}";

    private static String cookieValue(HttpRequest r, String name) {
        String cookie = headerOf(r, "Cookie");
        if (cookie == null) return null;
        Matcher m = Pattern.compile("(?:^|;\\s*)" + Pattern.quote(name) + "=([^;]*)").matcher(cookie);
        return m.find() ? m.group(1) : null;
    }

    @Test
    @DisplayName("N2 repro: an Authorization presence check behind a session cookie is not a JWT bypass")
    void jwtCookieSessionIsNotConfirmed() throws Exception {
        Run run = execute("jwt_validation",
                request("GET", "/account", "", headers("Authorization", "Bearer " + JWT, "Cookie", "session=valid")),
                Reply.of(200, ACCOUNT),
                r -> headerOf(r, "Authorization") != null && "valid".equals(cookieValue(r, "session"))
                        ? Reply.of(200, ACCOUNT) : Reply.of(401, "unauthorized"));
        assertFalse(run.confirmed(), "cookie-authenticated: " + run.status() + " " + run.submission().summary);
        for (HttpRequest r : run.sent()) assertNull(headerOf(r, "Cookie"), "no probe carries the session cookie");
        assertTrue(run.submission().evidence.contains("token carrier=header Authorization"), run.submission().evidence);
        // The original token alone is refused too, so the refusals are not about the token.
        assertEquals("inconclusive", run.status(), run.submission().summary);
        assertTrue(run.sent().stream().anyMatch(r -> ("Bearer " + JWT).equals(headerOf(r, "Authorization"))),
                "the original token alone was sent; " + run.submission().evidence);
    }

    @Test
    @DisplayName("N2 control: a verified cookie JWT next to other cookies is rejected once the token alone is accepted")
    void jwtInCookieVerifiedWithOtherCookiesIsRejected() throws Exception {
        Run run = execute("jwt_validation",
                request("GET", "/account", "", headers("Cookie", "theme=dark; token=" + JWT)),
                Reply.of(200, ACCOUNT),
                r -> JWT.equals(cookieValue(r, "token")) ? Reply.of(200, ACCOUNT) : Reply.of(401, "unauthorized"));
        assertFalse(run.confirmed(), run.status() + " " + run.submission().summary);
        assertEquals("rejected", run.status(), run.submission().summary);
        assertTrue(run.sent().stream().anyMatch(r -> ("token=" + JWT).equals(headerOf(r, "Cookie"))),
                "the original token alone was sent; sent " + describe(run));
    }

    @Test
    @DisplayName("N2 repro (recall): a JWT carried in a cookie is tested, and an unverified one is confirmed")
    void jwtInCookieIsConfirmed() throws Exception {
        Run run = execute("jwt_validation",
                request("GET", "/account", "", headers("Cookie", "theme=dark; token=" + JWT)),
                Reply.of(200, ACCOUNT),
                r -> JwtForgeryLogic.looksLikeJwt(cookieValue(r, "token")) ? Reply.of(200, ACCOUNT) : Reply.of(401, "unauthorized"));
        assertTrue(run.confirmed(), run.status() + " " + run.submission().summary);
        HttpRequest forged = run.sent().get(0);
        assertNotNull(cookieValue(forged, "token"), "the forged token goes back in its cookie");
        assertNotEquals(JWT, cookieValue(forged, "token"));
        assertNull(cookieValue(forged, "theme"), "no other cookie rides along");
        assertTrue(run.sent().stream().anyMatch(r -> headerOf(r, "Cookie") == null), "a no-token control was sent");
        assertTrue(run.submission().evidence.contains("token carrier=cookie token"), run.submission().evidence);
    }

    @Test
    @DisplayName("N2 control: a cookie JWT whose signature is verified stays unconfirmed")
    void jwtInCookieVerifiedIsNotConfirmed() throws Exception {
        Run run = execute("jwt_validation",
                request("GET", "/account", "", headers("Cookie", "token=" + JWT)),
                Reply.of(200, ACCOUNT),
                r -> JWT.equals(cookieValue(r, "token")) ? Reply.of(200, ACCOUNT) : Reply.of(401, "unauthorized"));
        assertFalse(run.confirmed(), run.status() + " " + run.submission().summary);
        assertEquals("rejected", run.status());
        assertTrue(run.sent().stream().noneMatch(r -> JWT.equals(cookieValue(r, "token"))),
                "the token alone is the captured request, so it is not resent; sent " + describe(run));
    }

    @Test
    @DisplayName("N2 control: a dotted cookie value that is not a JWT is not taken for one")
    void jwtDottedCookieIsNotATokenControl() throws Exception {
        Run run = execute("jwt_validation",
                request("GET", "/account", "", headers("Cookie", "host=www.shop.example")),
                Reply.of(200, ACCOUNT), r -> Reply.of(200, ACCOUNT));
        assertEquals("invalid", run.status(), run.submission().summary);
        assertEquals(0, run.sent().size(), "nothing to forge, nothing sent");
    }

    @Test
    @DisplayName("N2 positive control: a JWT in a custom header with no signature check is confirmed")
    void jwtInCustomHeaderIsConfirmed() throws Exception {
        Run run = execute("jwt_validation",
                request("GET", "/account", "", headers("X-Access-Token", JWT, "Cookie", "theme=dark")),
                Reply.of(200, ACCOUNT),
                r -> JwtForgeryLogic.looksLikeJwt(headerOf(r, "X-Access-Token")) ? Reply.of(200, ACCOUNT) : Reply.of(401, "unauthorized"));
        assertTrue(run.confirmed(), run.status() + " " + run.submission().summary);
        assertTrue(run.submission().evidence.contains("token carrier=header X-Access-Token"), run.submission().evidence);
    }

    // ------------------------------------------------------------------ N3
    private static final Pattern ROLE_ADMIN = Pattern.compile("\"role\"\\s*:\\s*\"admin\"");

    /**
     * POST /users creates a user (id 44 onwards) and answers 201 with its
     * Location; GET /users lists ids only; GET /users/{id} shows the user.
     * {@code bindsRole} decides whether a role in the request is stored.
     */
    private static Function<HttpRequest, Reply> usersServer(Map<String, String> roles, boolean bindsRole) {
        int[] next = {44};
        return r -> {
            if (r.method().equals("POST") && r.path().equals("/users")) {
                String id = String.valueOf(next[0]++);
                roles.put(id, bindsRole && ROLE_ADMIN.matcher(r.bodyToString()).find() ? "admin" : "user");
                return new Reply(201, r.bodyToString(), Map.of("Location", "/users/" + id));
            }
            if (r.method().equals("GET") && r.path().equals("/users")) {
                return Reply.of(200, "[" + String.join(",", roles.keySet().stream().map(k -> "{\"id\":" + k + "}").toList()) + "]");
            }
            if (r.method().equals("GET") && r.path().startsWith("/users/")) {
                String id = r.path().substring("/users/".length());
                String role = roles.get(id);
                return role == null ? Reply.of(404, "no such user")
                        : Reply.of(200, "{\"id\":" + id + ",\"name\":\"sample\",\"role\":\"" + role + "\"}");
            }
            return Reply.of(404, "not found");
        };
    }

    private static HttpRequest createUser() {
        return request("POST", "/users", "{\"name\":\"sample\"}", headers("Content-Type", "application/json", "Cookie", "session=synthetic"));
    }

    @Test
    @DisplayName("N3 repro (recall): a create-style write is read back from the created object -> confirmed")
    void massAssignmentCreateStyleIsConfirmed() throws Exception {
        Map<String, String> roles = new java.util.concurrent.ConcurrentHashMap<>(Map.of("43", "user"));
        Run run = execute("api_security_validation", createUser(),
                new Reply(201, "{\"id\":43,\"name\":\"sample\"}", Map.of("Location", "/users/43")), usersServer(roles, true));
        assertTrue(run.confirmed(), run.status() + " " + run.submission().summary + " | " + run.submission().evidence);
        assertEquals("GET /users/43; POST /users; GET /users/44; ", describe(run),
                "read the captured object, write, read the created object");
    }

    @Test
    @DisplayName("N3 control: a create endpoint that ignores role stays unconfirmed even though it echoes it")
    void massAssignmentCreateStyleAllowlistIsNotConfirmed() throws Exception {
        Map<String, String> roles = new java.util.concurrent.ConcurrentHashMap<>(Map.of("43", "user"));
        Run run = execute("api_security_validation", createUser(),
                new Reply(201, "{\"id\":43,\"name\":\"sample\"}", Map.of("Location", "/users/43")), usersServer(roles, false));
        assertFalse(run.confirmed(), "allowlisted: " + run.status() + " " + run.submission().summary);
        assertEquals("user", roles.get("44"));
    }

    @Test
    @DisplayName("N3 control: an object that was already admin before the write is not a new change")
    void massAssignmentCreateStyleAlreadyAdminIsNotConfirmed() throws Exception {
        Map<String, String> roles = new java.util.concurrent.ConcurrentHashMap<>(Map.of("43", "admin"));
        Run run = execute("api_security_validation", createUser(),
                new Reply(201, "{\"id\":43,\"name\":\"sample\"}", Map.of("Location", "/users/43")), usersServer(roles, true));
        assertFalse(run.confirmed(), "already admin: " + run.status() + " " + run.submission().summary);
    }

    @Test
    @DisplayName("N3 control: a cross-origin Location is never read")
    void massAssignmentCrossOriginLocationIsNotRead() throws Exception {
        Map<String, String> roles = new java.util.concurrent.ConcurrentHashMap<>(Map.of("43", "user"));
        Run run = execute("api_security_validation", createUser(),
                new Reply(201, "{\"name\":\"sample\"}", Map.of("Location", "https://other.example/users/43")),
                usersServer(roles, true));
        assertFalse(run.confirmed(), "cross-origin: " + run.status() + " " + run.submission().summary);
        assertTrue(run.sent().stream().noneMatch(r -> r.path().equals("/users/43")), "sent " + describe(run));
    }

    @Test
    @DisplayName("N3 helper: only same-origin references resolve to a path")
    void sameOriginPathResolvesOnlySameOrigin() {
        String url = "https://shop.example/users";
        assertEquals("/users/43", ValidationExecutor.sameOriginPath(url, "/users/43"));
        assertEquals("/users/43?x=1", ValidationExecutor.sameOriginPath(url, "https://shop.example:443/users/43?x=1"));
        assertEquals("/a/c", ValidationExecutor.sameOriginPath("https://shop.example/a/b", "c"));
        assertNull(ValidationExecutor.sameOriginPath(url, "https://other.example/users/43"));
        assertNull(ValidationExecutor.sameOriginPath(url, "http://shop.example/users/43"));
        assertNull(ValidationExecutor.sameOriginPath(url, "https://shop.example:8443/users/43"));
        assertNull(ValidationExecutor.sameOriginPath(url, "//other.example/x"));
        assertNull(ValidationExecutor.sameOriginPath(url, "javascript:alert(1)"));
        assertNull(ValidationExecutor.sameOriginPath(url, " "));
        assertNull(ValidationExecutor.sameOriginPath(url, null));
    }

    // ------------------------------------------------------------------ N4
    /** HTML-encodes & < > " but not the single quote, as many templates do. */
    private static String encodeNoApostrophe(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }

    private static Function<HttpRequest, Reply> reflectEncoded(String before, String after) {
        return r -> Reply.of(200, "<html><body>" + before + encodeNoApostrophe(paramOf(r, "q")) + after + "</body></html>");
    }

    private static Run xss(String before, String after) throws Exception {
        return execute("reflection_context_validation",
                request("GET", "/search", "", Map.of(), Map.of("q", "ordinary")),
                Reply.of(200, "<html></html>"), reflectEncoded(before, after));
    }

    @Test
    @DisplayName("N4 repro (recall): the quote closes a string in an event-handler attribute -> confirmed")
    void xssEventHandlerStringIsConfirmed() throws Exception {
        Run run = xss("<button onclick=\"track('", "')\">Go</button>");
        assertTrue(run.confirmed(), run.status() + " " + run.submission().summary);
        assertTrue(run.submission().summary.contains("JS_SINGLE_QUOTED_STRING"), run.submission().summary);
    }

    @Test
    @DisplayName("N4 repro (recall): the quote closes a string in a javascript: URL -> confirmed")
    void xssJavascriptUrlStringIsConfirmed() throws Exception {
        Run run = xss("<a href=\"javascript:go('", "')\">Go</a>");
        assertTrue(run.confirmed(), run.status() + " " + run.submission().summary);
    }

    @Test
    @DisplayName("N4 control: the same reflection in a text node is inert")
    void xssTextNodeIsNotConfirmed() throws Exception {
        Run run = xss("<p>Results for ", "</p>");
        assertFalse(run.confirmed(), run.status() + " " + run.submission().summary);
        assertEquals("supported", run.status());
    }

    @Test
    @DisplayName("N4 control: the same reflection in an ordinary attribute value is inert")
    void xssPlainAttributeIsNotConfirmed() throws Exception {
        Run run = xss("<input name=\"q\" value=\"", "\">");
        assertFalse(run.confirmed(), run.status() + " " + run.submission().summary);
    }

    @Test
    @DisplayName("N4 control: a single-quoted handler the quote only closes is not a string breakout")
    void xssSingleQuotedHandlerIsNotConfirmed() throws Exception {
        Run run = xss("<button onclick='track(\"", "\")'>Go</button>");
        assertFalse(run.confirmed(), run.status() + " " + run.submission().summary);
    }

    @Test
    @DisplayName("N4 control: a link that is not a javascript: URL is inert")
    void xssOrdinaryLinkIsNotConfirmed() throws Exception {
        Run run = xss("<a href=\"/go?q='", "'\">Go</a>");
        assertFalse(run.confirmed(), run.status() + " " + run.submission().summary);
    }
}
