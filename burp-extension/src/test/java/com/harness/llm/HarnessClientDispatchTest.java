package com.harness.llm;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.harness.llm.logic.PlanePolicy;
import com.harness.llm.model.AnalysisModels.ValidationSubmission;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ARC-4: HarnessClient.dispatchPlan asks the harness for a plan's dispatch
 * and reads its nonce and live policy fail-closed. A loopback stub harness
 * records each request.
 */
public final class HarnessClientDispatchTest {
    private static final String TOKEN = "pairing-token-for-test";
    private static final String NONCE = "Zm9vYmFyYmF6cXV4LW5vbmNlLTAwMDE";

    private HttpServer server;
    private final List<String> requests = new CopyOnWriteArrayList<>();
    private volatile int status = 200;
    private volatile String reply;
    private HarnessClient client;

    @BeforeEach
    void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/", this::handle);
        server.start();
        client = new HarnessClient("http://127.0.0.1:" + server.getAddress().getPort(), 5);
        client.setBearerToken(TOKEN);
        reply = "{\"plan_id\": \"p 1\", \"dispatch_nonce\": \"" + NONCE + "\","
                + " \"policy\": {\"active_enabled\": true, \"allow_mutating_replay\": false}, \"request_budget\": 3}";
    }

    @AfterEach
    void stop() { server.stop(0); }

    private void handle(HttpExchange exchange) throws IOException {
        String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        requests.add(exchange.getRequestMethod() + " " + exchange.getRequestURI().getRawPath() + " " + body);
        byte[] out = reply.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, out.length);
        try (OutputStream o = exchange.getResponseBody()) { o.write(out); }
    }

    private static JsonObject json(String text) { return JsonParser.parseString(text).getAsJsonObject(); }

    @Test
    @DisplayName("dispatchPlan posts the binding to the plan's dispatch route and reads the policy")
    void dispatchReadsNonceAndPolicy() throws Exception {
        HarnessClient.PlaneDispatch dispatch = client.dispatchPlan("p 1", "hash-1");
        assertEquals(List.of("POST /test-plans/p%201/dispatch {\"source_exchange_hash\":\"hash-1\"}"), requests);
        assertEquals(NONCE, dispatch.nonce);
        assertTrue(dispatch.policy.activeEnabled());
        assertFalse(dispatch.policy.allowMutatingReplay());
        assertEquals(3, dispatch.policy.requestBudget());
    }

    @Test
    @DisplayName("a refused dispatch is an exception: the executor sends nothing")
    void refusedDispatchThrows() {
        status = 409;
        reply = "{\"detail\": \"plan_terminal\"}";
        assertThrows(HarnessClient.HarnessException.class, () -> client.dispatchPlan("p1", "hash-1"));
    }

    // ---------------------------------------------------------------- ARC-12
    /** The harness's status for each refusal code (server._PLANE_REFUSALS). */
    private static final java.util.Map<String, Integer> STATUS = java.util.Map.ofEntries(
            java.util.Map.entry("unknown_plan", 404),
            java.util.Map.entry("not_dispatched", 409), java.util.Map.entry("dispatch_nonce_mismatch", 409),
            java.util.Map.entry("duplicate_submission", 409), java.util.Map.entry("plan_terminal", 409),
            java.util.Map.entry("dispatch_nonce_required", 422), java.util.Map.entry("wrong_execution_plane", 422),
            java.util.Map.entry("binding_mismatch", 422), java.util.Map.entry("executor_mismatch", 422),
            java.util.Map.entry("capability_cannot_confirm", 422), java.util.Map.entry("confirmed_status_invalid", 422));

    private void refuseWith(String reason) {
        status = STATUS.get(reason);
        reply = "{\"detail\": {\"reason\": \"" + reason + "\", \"message\": \"server wording\"}}";
    }

    private static ValidationSubmission result() {
        ValidationSubmission v = new ValidationSubmission();
        v.plan_id = "p1"; v.status = "rejected"; v.executor = "burp:x"; v.dispatch_nonce = NONCE;
        return v;
    }

    /** The refusal reached the caller as its code, in the kind, the getter and the message. */
    private static void checkSurfaced(HarnessClient.HarnessException e, String reason) {
        assertEquals("refused", e.getFailureKind(), e.getMessage());
        assertEquals(reason, e.getRefusalReason());
        assertTrue(e.getMessage().contains(reason) && e.getMessage().contains("HTTP " + STATUS.get(reason)),
                e.getMessage());
    }

    @Test
    @DisplayName("every refusal code the harness returns is surfaced, for the dispatch and for the result")
    void everyRefusalReasonIsSurfaced() {
        assertEquals(STATUS.keySet(), HarnessClient.PLANE_REFUSALS.keySet());
        for (String reason : STATUS.keySet()) {
            refuseWith(reason);
            checkSurfaced(assertThrows(HarnessClient.HarnessException.class,
                    () -> client.dispatchPlan("p1", "hash-1")), reason);
            checkSurfaced(assertThrows(HarnessClient.HarnessException.class,
                    () -> client.submitValidationResult(result())), reason);
        }
    }

    @Test
    @DisplayName("an unlisted code, a string detail or another status is withheld, not echoed")
    void unlistedRefusalsAreWithheld() {
        String[][] cases = {
                {"409", "{\"detail\": {\"reason\": \"<b>owned</b>\", \"message\": \"x\"}}"},
                {"409", "{\"detail\": \"duplicate_submission\"}"},
                {"422", "{\"detail\": [{\"loc\": [\"body\", \"status\"], \"msg\": \"bad\"}]}"},
                {"500", "{\"detail\": {\"reason\": \"plan_terminal\"}}"},
                {"409", "not json"},
        };
        for (String[] c : cases) {
            status = Integer.parseInt(c[0]);
            reply = c[1];
            var e = assertThrows(HarnessClient.HarnessException.class, () -> client.submitValidationResult(result()));
            assertEquals(null, e.getRefusalReason(), c[1]);
            assertFalse(e.getMessage().contains("owned"), e.getMessage());
            assertTrue(e.getMessage().contains("HTTP " + c[0]), e.getMessage());
        }
    }

    @Test
    @DisplayName("a dispatch 404 without a code points at a harness that predates dispatch")
    void routeless404HintsAtVersionSkew() {
        status = 404;
        reply = "{\"detail\": \"Not Found\"}";
        var e = assertThrows(HarnessClient.HarnessException.class, () -> client.dispatchPlan("p1", "hash-1"));
        assertTrue(e.getMessage().contains("predate plan dispatch"), e.getMessage());
        refuseWith("unknown_plan");
        e = assertThrows(HarnessClient.HarnessException.class, () -> client.dispatchPlan("p1", "hash-1"));
        assertFalse(e.getMessage().contains("predate"), e.getMessage());
        checkSurfaced(e, "unknown_plan");
    }

    @Test
    @DisplayName("control: the pre-ARC-12 failure (status only) does not surface the reason")
    void controlStatusOnlyFailureLosesTheReason() {
        assertThrows(AssertionError.class, () -> checkSurfaced(HarnessClient.httpFailure(409), "plan_terminal"));
        checkSurfaced(HarnessClient.refused("result", "plan_terminal", 409), "plan_terminal");
    }

    @Test
    @DisplayName("a reply without a usable nonce is malformed")
    void noNonceIsMalformed() {
        for (String body : new String[]{"{}", "{\"dispatch_nonce\": 7}", "{\"dispatch_nonce\": \"short\"}",
                "{\"dispatch_nonce\": \"has spaces in it, not a token\"}"}) {
            var e = assertThrows(HarnessClient.HarnessException.class, () -> HarnessClient.parseDispatch(json(body)));
            assertEquals("malformed", e.getFailureKind(), body);
        }
    }

    @Test
    @DisplayName("the policy flags are true only as JSON booleans; a missing policy is all off")
    void flagsAreStrict() throws Exception {
        var quoted = HarnessClient.parseDispatch(json("{\"dispatch_nonce\": \"" + NONCE + "\","
                + " \"policy\": {\"active_enabled\": \"true\", \"allow_mutating_replay\": 1}, \"request_budget\": null}"));
        assertFalse(quoted.policy.activeEnabled());
        assertFalse(quoted.policy.allowMutatingReplay());
        var missing = HarnessClient.parseDispatch(json("{\"dispatch_nonce\": \"" + NONCE + "\", \"request_budget\": null}"));
        assertFalse(missing.policy.activeEnabled());
        assertFalse(missing.policy.allowMutatingReplay());
    }

    @Test
    @DisplayName("the budget: null is no ceiling; missing, fractional or non-numeric is zero; negative clamps")
    void budgetFailsClosed() throws Exception {
        String head = "{\"dispatch_nonce\": \"" + NONCE + "\"";
        assertEquals(PlanePolicy.NO_BUDGET,
                HarnessClient.parseDispatch(json(head + ", \"request_budget\": null}")).policy.requestBudget());
        for (String budget : new String[]{"", ", \"request_budget\": 2.5", ", \"request_budget\": \"9\"",
                ", \"request_budget\": -4", ", \"request_budget\": [1]"}) {
            assertEquals(0, HarnessClient.parseDispatch(json(head + budget + "}")).policy.requestBudget(), budget);
        }
        assertEquals(Integer.MAX_VALUE, HarnessClient.parseDispatch(
                json(head + ", \"request_budget\": 99999999999}")).policy.requestBudget());
    }
}
