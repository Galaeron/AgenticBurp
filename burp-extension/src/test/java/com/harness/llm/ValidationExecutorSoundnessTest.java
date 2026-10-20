package com.harness.llm;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.internal.MontoyaObjectFactory;
import burp.api.montoya.internal.ObjectFactoryLocator;
import com.harness.llm.FakeMontoya.Reply;
import com.harness.llm.FakeMontoya.Run;
import com.harness.llm.logic.FileUploadLogic;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;
import java.util.regex.Pattern;

import static com.harness.llm.FakeMontoya.execute;
import static com.harness.llm.FakeMontoya.headerOf;
import static com.harness.llm.FakeMontoya.headers;
import static com.harness.llm.FakeMontoya.paramOf;
import static com.harness.llm.FakeMontoya.request;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Code review 02 findings R24-R29, R31 and R32 (batch RV-J), driven through
 * the public ValidationExecutor.execute() path: capability dispatch, the
 * fingerprint check, the executor's probes, its Logic class and the
 * submission it sends. Each finding has the reviewer's reproduction, the
 * reviewer's control and a positive control showing the check can still
 * confirm a real case.
 */
final class ValidationExecutorSoundnessTest {
    private static final String SAME = "same response content";
    private MontoyaObjectFactory previousFactory;

    @BeforeEach void installFactory() { previousFactory = FakeMontoya.installParameterFactory(); }
    @AfterEach void restoreFactory() { ObjectFactoryLocator.FACTORY = previousFactory; }

    private static Function<HttpRequest, Reply> always(int status, String body) {
        return r -> Reply.of(status, body);
    }

    // ---------------------------------------------------------------- R24
    private static final String MULTIPART_BODY = "--boundary\r\nContent-Disposition: form-data; name=\"file\"; "
            + "filename=\"sample.txt\"\r\nContent-Type: text/plain\r\n\r\noriginal\r\n--boundary--\r\n";

    @Test
    @DisplayName("R24: upload fetch-back is a GET with no upload body or upload headers; both legs still run")
    void uploadFetchBackUsesGet() throws Exception {
        HttpRequest upload = request("POST", "/upload", MULTIPART_BODY,
                headers("Content-Type", "multipart/form-data; boundary=boundary", "Cookie", "session=synthetic"));
        Run run = execute("file_upload_validation", upload, Reply.of(200, "{\"ok\":true}"), r -> {
            if (r.method().equals("POST") && r.path().equals("/upload")) return Reply.of(200, "{\"url\":\"/uploads/item.txt\"}");
            if (r.method().equals("GET") && r.path().equals("/uploads/item.txt")) return Reply.of(200, FileUploadLogic.EICAR_STRING);
            return Reply.of(405, "method not allowed");
        });
        assertEquals(2, run.sent().size(), "upload and fetch-back both exercised; sent " + describe(run));
        HttpRequest uploadLeg = run.sent().get(0);
        HttpRequest fetchBack = run.sent().get(1);
        assertEquals("POST /upload", uploadLeg.method() + " " + uploadLeg.path());
        assertTrue(uploadLeg.bodyToString().contains(FileUploadLogic.EICAR_STRING), "upload leg carries the test file");
        assertEquals("GET /uploads/item.txt", fetchBack.method() + " " + fetchBack.path(), "fetch-back; sent " + describe(run));
        assertEquals("", fetchBack.bodyToString(), "fetch-back carries no upload body");
        assertNull(headerOf(fetchBack, "Content-Type"), "fetch-back carries no multipart Content-Type");
        assertNull(headerOf(fetchBack, "Content-Length"), "fetch-back carries no upload Content-Length");
        assertEquals("session=synthetic", headerOf(fetchBack, "Cookie"), "fetch-back keeps the session");
        assertTrue(run.confirmed(), "stored, retrievable test file is still confirmed: " + run.submission().summary);
    }

    // ---------------------------------------------------------------- R25
    @Test
    @DisplayName("R25: a bearer-only request is not confirmed as cookie CSRF")
    void csrfBearerOnlyIsNotConfirmed() throws Exception {
        Run run = execute("csrf_validation",
                request("POST", "/change", "", headers("X-CSRF-Token", "test", "Authorization", "Bearer synthetic")),
                Reply.of(200, SAME), always(200, SAME));
        assertFalse(run.confirmed(), "bearer-only: " + run.status() + " " + run.submission().summary);
    }

    @Test
    @DisplayName("R25: HTTP 403 before and after token removal is not a successful CSRF")
    void csrfUnchangedForbiddenIsNotConfirmed() throws Exception {
        Run run = execute("csrf_validation",
                request("POST", "/change", "", headers("X-CSRF-Token", "test", "Cookie", "session=synthetic")),
                Reply.of(403, SAME), always(403, SAME));
        assertFalse(run.confirmed(), "403/403: " + run.status() + " " + run.submission().summary);
    }

    @Test
    @DisplayName("R25 control: a GET stays unconfirmed")
    void csrfGetNegativeControl() throws Exception {
        Run run = execute("csrf_validation", request("GET", "/read", "", headers("X-CSRF-Token", "test")),
                Reply.of(200, SAME), always(200, SAME));
        assertFalse(run.confirmed());
    }

    /** Cookie-gated action: no Cookie is refused; a Cookie without the token still succeeds. */
    private static Reply cookieGatedTokenIgnored(HttpRequest r) {
        String cookie = headerOf(r, "Cookie");
        return cookie == null ? Reply.of(403, "login required") : Reply.of(200, "{\"changed\":true}");
    }

    @Test
    @DisplayName("R25 positive control: token dropped, ambient cookie alone performs the action, anonymous refused")
    void csrfCookieOnlySuccessIsConfirmed() throws Exception {
        Run run = execute("csrf_validation",
                request("POST", "/change", "email=a@b.example", headers("X-CSRF-Token", "test",
                        "Cookie", "session=synthetic", "Authorization", "Bearer synthetic")),
                Reply.of(200, "{\"changed\":true}"), ValidationExecutorSoundnessTest::cookieGatedTokenIgnored);
        assertTrue(run.confirmed(), run.status() + " " + run.submission().summary);
        HttpRequest forged = run.sent().get(0);
        assertNull(headerOf(forged, "X-CSRF-Token"), "forged request drops the token");
        assertNull(headerOf(forged, "Authorization"), "forged request drops the non-ambient credential");
        assertEquals("session=synthetic", headerOf(forged, "Cookie"), "forged request keeps the ambient cookie");
    }

    @Test
    @DisplayName("R25: an action that also succeeds with no cookie at all is not cookie CSRF")
    void csrfPublicActionIsNotConfirmed() throws Exception {
        Run run = execute("csrf_validation",
                request("POST", "/change", "", headers("X-CSRF-Token", "test", "Cookie", "session=synthetic")),
                Reply.of(200, SAME), always(200, SAME));
        assertFalse(run.confirmed(), "public action: " + run.status() + " " + run.submission().summary);
    }

    @Test
    @DisplayName("R25 positive control, form-token path: invalidated token, ambient cookie, anonymous refused")
    void csrfParameterTokenPathIsConfirmed() throws Exception {
        Run run = execute("csrf_validation",
                request("POST", "/change", "", headers("Cookie", "session=synthetic"), Map.of("csrf_token", "real")),
                Reply.of(200, "{\"changed\":true}"), ValidationExecutorSoundnessTest::cookieGatedTokenIgnored);
        assertTrue(run.confirmed(), run.status() + " " + run.submission().summary);
        assertNotEquals("real", paramOf(run.sent().get(0), "csrf_token"), "forged request does not carry the real token");
    }

    // ---------------------------------------------------------------- R26
    private static final String JWT = "eyJhbGciOiJIUzI1NiJ9.e30.c2ln";

    @Test
    @DisplayName("R26: a public constant response does not establish a JWT signature bypass")
    void jwtPublicConstantResponseIsNotConfirmed() throws Exception {
        Run run = execute("jwt_validation",
                request("GET", "/public", "", headers("Authorization", "Bearer " + JWT)),
                Reply.of(200, SAME), always(200, SAME));
        assertFalse(run.confirmed(), "public resource: " + run.status() + " " + run.submission().summary);
    }

    @Test
    @DisplayName("R26 positive control: a token-gated resource accepting a forged token is confirmed")
    void jwtTokenGatedForgeryIsConfirmed() throws Exception {
        Run run = execute("jwt_validation",
                request("GET", "/account", "", headers("Authorization", "Bearer " + JWT)),
                Reply.of(200, "{\"account\":\"synthetic\"}"),
                r -> headerOf(r, "Authorization") == null ? Reply.of(401, "unauthorized") : Reply.of(200, "{\"account\":\"synthetic\"}"));
        assertTrue(run.confirmed(), run.status() + " " + run.submission().summary);
        assertTrue(run.sent().stream().anyMatch(r -> headerOf(r, "Authorization") == null),
                "an unauthenticated control was sent");
    }

    @Test
    @DisplayName("R26: a forged token that is refused stays unconfirmed")
    void jwtRefusedForgeryIsNotConfirmed() throws Exception {
        Run run = execute("jwt_validation",
                request("GET", "/account", "", headers("Authorization", "Bearer " + JWT)),
                Reply.of(200, "{\"account\":\"synthetic\"}"),
                r -> JWT.equals(String.valueOf(headerOf(r, "Authorization")).replace("Bearer ", ""))
                        ? Reply.of(200, "{\"account\":\"synthetic\"}") : Reply.of(401, "unauthorized"));
        assertFalse(run.confirmed());
    }

    // ---------------------------------------------------------------- R27
    private static final String REJECTED_ROLE = "{\"error\":\"Unknown field. Request rejected.\",\"rejected\":{\"role\":\"admin\"}}";
    private static final Pattern ROLE_ADMIN = Pattern.compile("\"role\"\\s*:\\s*\"admin\"");

    @Test
    @DisplayName("R27: HTTP 400 rejecting role=admin is not confirmed as mass assignment")
    void massAssignmentRejectedFieldIsNotConfirmed() throws Exception {
        Run run = execute("api_security_validation",
                request("POST", "/profile", "{\"name\":\"sample\"}", headers("Content-Type", "application/json")),
                Reply.of(400, SAME), always(400, REJECTED_ROLE));
        assertFalse(run.confirmed(), "rejected field: " + run.status() + " " + run.submission().summary);
    }

    @Test
    @DisplayName("R27 control: a response without the injected field stays negative")
    void massAssignmentNoFieldResponseIsNegative() throws Exception {
        Run run = execute("api_security_validation",
                request("POST", "/profile", "{\"name\":\"sample\"}", headers("Content-Type", "application/json")),
                Reply.of(200, SAME), always(200, SAME));
        assertFalse(run.confirmed());
    }

    @Test
    @DisplayName("R27: a 200 that echoes role=admin without persisting it is not confirmed")
    void massAssignmentEchoWithoutPersistenceIsNotConfirmed() throws Exception {
        Run run = execute("api_security_validation",
                request("PATCH", "/profile", "{\"name\":\"sample\"}", headers("Content-Type", "application/json")),
                Reply.of(200, "{\"name\":\"sample\"}"),
                r -> r.method().equals("GET") ? Reply.of(200, "{\"name\":\"sample\",\"role\":\"user\"}")
                        : Reply.of(200, r.bodyToString()));
        assertFalse(run.confirmed(), "echo only: " + run.status() + " " + run.submission().summary);
    }

    @Test
    @DisplayName("R27 positive control: a successful write that persists role=admin is confirmed")
    void massAssignmentPersistedChangeIsConfirmed() throws Exception {
        AtomicReference<String> role = new AtomicReference<>("user");
        Run run = execute("api_security_validation",
                request("PATCH", "/profile", "{\"name\":\"sample\"}", headers("Content-Type", "application/json", "Cookie", "session=synthetic")),
                Reply.of(200, "{\"name\":\"sample\"}"),
                r -> {
                    if (r.method().equals("PATCH") && ROLE_ADMIN.matcher(r.bodyToString()).find()) role.set("admin");
                    return Reply.of(200, "{\"name\":\"sample\",\"role\":\"" + role.get() + "\"}");
                });
        assertTrue(run.confirmed(), run.status() + " " + run.submission().summary);
        for (HttpRequest r : run.sent()) {
            if (!r.method().equals("GET")) continue;
            assertEquals("/profile", r.path());
            assertEquals("", r.bodyToString(), "read-back carries no body");
            assertNull(headerOf(r, "Content-Type"), "read-back carries no write Content-Type");
            assertEquals("session=synthetic", headerOf(r, "Cookie"), "read-back keeps the session");
        }
    }

    // ---------------------------------------------------------------- R28
    private static Function<HttpRequest, Reply> echoQuery(String before, String after) {
        return r -> Reply.of(200, "<html><body>" + before + paramOf(r, "q") + after + "</body></html>");
    }

    @Test
    @DisplayName("R28: an ordinary script without the injected canary is not XSS")
    void xssOrdinaryScriptIsNotConfirmed() throws Exception {
        String page = "<script>console.log('ordinary application script');</script>";
        Run run = execute("reflection_context_validation",
                request("GET", "/search", "", Map.of(), Map.of("q", "ordinary")), Reply.of(200, page), always(200, page));
        assertFalse(run.confirmed(), "ordinary script: " + run.status() + " " + run.submission().summary);
    }

    @Test
    @DisplayName("R28 control: a plain page without any reflection stays unconfirmed")
    void xssPlainPageControl() throws Exception {
        Run run = execute("reflection_context_validation",
                request("GET", "/search", "", Map.of(), Map.of("q", "ordinary")), Reply.of(403, SAME), always(403, SAME));
        assertFalse(run.confirmed());
    }

    @Test
    @DisplayName("R28 positive control: the unique payload reflected raw into HTML is confirmed")
    void xssRawHtmlReflectionIsConfirmed() throws Exception {
        Run run = execute("reflection_context_validation",
                request("GET", "/search", "", Map.of(), Map.of("q", "ordinary")),
                Reply.of(200, "<html></html>"), echoQuery("<p>Results for ", "</p>"));
        assertTrue(run.confirmed(), run.status() + " " + run.submission().summary);
    }

    @Test
    @DisplayName("R28: the payload reflected raw inside a textarea is not in an executable context")
    void xssTextareaReflectionIsNotConfirmed() throws Exception {
        Run run = execute("reflection_context_validation",
                request("GET", "/search", "", Map.of(), Map.of("q", "ordinary")),
                Reply.of(200, "<html></html>"), echoQuery("<textarea>", "</textarea>"));
        assertFalse(run.confirmed(), "textarea: " + run.status() + " " + run.submission().summary);
    }

    // ---------------------------------------------------------------- R29
    @Test
    @DisplayName("R29: an application 'project not found' 404 is a lead, not a confirmed takeover")
    void takeoverApplication404IsNotConfirmed() throws Exception {
        Run run = execute("subdomain_takeover_detection", request("GET", "/projects/missing", "", Map.of()),
                Reply.of(404, "Project not found"), always(404, "Project not found"));
        assertFalse(run.confirmed(), "app 404: " + run.status() + " " + run.submission().summary);
        assertEquals(0, run.sent().size(), "passive check sends nothing");
    }

    @Test
    @DisplayName("R29 control: an ordinary response without a takeover phrase stays unconfirmed")
    void takeoverOrdinaryResponseControl() throws Exception {
        Run run = execute("subdomain_takeover_detection", request("GET", "/projects/existing", "", Map.of()),
                Reply.of(200, SAME), always(200, SAME));
        assertFalse(run.confirmed());
        assertEquals("rejected", run.status());
    }

    // ---------------------------------------------------------------- R31
    private static String oauthAttacker() throws Exception {
        Field f = ValidationExecutor.class.getDeclaredField("OAUTH_ATTACKER_REDIRECT");
        f.setAccessible(true);
        return (String) f.get(null);
    }

    private static Run oauth(String location) throws Exception {
        HttpRequest authorize = request("GET", "/authorize", "", Map.of(),
                Map.of("redirect_uri", "https://client.example/callback", "state", "synthetic"));
        return execute("oauth_flow_validation", authorize, Reply.of(200, "<html>synthetic</html>"),
                r -> new Reply(302, "", Map.of("Location", location)));
    }

    @Test
    @DisplayName("R31: a same-origin error redirect naming the rejected URI is not exfiltration")
    void oauthSameOriginErrorRedirectIsNotConfirmed() throws Exception {
        Run run = oauth("/error?rejected_redirect_uri=" + oauthAttacker());
        assertFalse(run.confirmed(), run.status() + " " + run.submission().summary);
    }

    @Test
    @DisplayName("R31 positive control: a real redirect to the attacker host is confirmed")
    void oauthAttackerRedirectIsConfirmed() throws Exception {
        assertTrue(oauth(oauthAttacker() + "?code=synthetic").confirmed());
    }

    @Test
    @DisplayName("R31 control: a plain local error redirect stays negative")
    void oauthPlainLocalErrorIsNegative() throws Exception {
        assertFalse(oauth("/error?reason=invalid_redirect").confirmed());
    }

    // ---------------------------------------------------------------- R32
    private static Run csp(String policy) throws Exception {
        Map<String, String> h = headers("Content-Type", "text/html", "Content-Security-Policy", policy);
        return execute("csp_clickjacking_validation", request("GET", "/page", "", Map.of()), new Reply(200, "<html></html>", h),
                r -> { throw new AssertionError("passive check must not send"); });
    }

    @Test
    @DisplayName("R32: frame-ancestors * is not reported as restrictive framing protection")
    void cspWildcardFrameAncestorsIsNotProtection() throws Exception {
        assertNotEquals("rejected", csp("frame-ancestors *").status());
    }

    @Test
    @DisplayName("R32: a directive name inside a report URL is not a framing restriction")
    void cspReportUriPathIsNotProtection() throws Exception {
        assertNotEquals("rejected", csp("report-uri /frame-ancestors/report").status());
    }

    @Test
    @DisplayName("R32 control: same-origin frame-ancestors still counts as protection")
    void cspSameOriginFrameAncestorsControl() throws Exception {
        assertEquals("rejected", csp("frame-ancestors 'self'").status());
    }

    private static String describe(Run run) {
        return run.sent().stream().map(r -> r.method() + " " + r.path()).toList().toString();
    }
}
