package com.harness.llm;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.internal.MontoyaObjectFactory;
import burp.api.montoya.internal.ObjectFactoryLocator;
import com.harness.llm.FakeMontoya.Reply;
import com.harness.llm.FakeMontoya.Run;
import com.harness.llm.logic.PlanePolicy;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;
import java.util.regex.Pattern;

import static com.harness.llm.FakeMontoya.executeUnder;
import static com.harness.llm.FakeMontoya.headers;
import static com.harness.llm.FakeMontoya.policy;
import static com.harness.llm.FakeMontoya.request;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ARC-4, through the public ValidationExecutor.execute() path: the plane asks
 * the harness to dispatch the plan, runs it under the live policy it gets
 * back, and carries the dispatch nonce on its one submission.
 *
 * The case is the mass-assignment positive control (a PATCH that persists
 * role=admin, with GET read-backs), so a run that ignored the policy would
 * send the PATCH and report a confirmation.
 */
final class ValidationExecutorPlanePolicyTest {
    private static final Pattern ROLE_ADMIN = Pattern.compile("\"role\"\\s*:\\s*\"admin\"");
    private MontoyaObjectFactory previousFactory;

    @BeforeEach void installFactory() { previousFactory = FakeMontoya.installParameterFactory(); }
    @AfterEach void restoreFactory() { ObjectFactoryLocator.FACTORY = previousFactory; }

    private static HttpRequest profileWrite() {
        return request("PATCH", "/profile", "{\"name\":\"sample\"}",
                headers("Content-Type", "application/json", "Cookie", "session=synthetic"));
    }

    private static Function<HttpRequest, Reply> persistingTarget() {
        AtomicReference<String> role = new AtomicReference<>("user");
        return r -> {
            if (r.method().equals("PATCH") && ROLE_ADMIN.matcher(r.bodyToString()).find()) role.set("admin");
            return Reply.of(200, "{\"name\":\"sample\",\"role\":\"" + role.get() + "\"}");
        };
    }

    private static Run massAssignment(FakeMontoya.Dispatcher dispatcher) throws Exception {
        return executeUnder(dispatcher, "api_security_validation", profileWrite(),
                Reply.of(200, "{\"name\":\"sample\"}"), persistingTarget());
    }

    /** No mutating request reached the target, and the run reported the refusal, not a verdict. */
    private static void checkMutatingArmRefused(Run run) {
        for (HttpRequest r : run.sent()) {
            assertTrue(PlanePolicy.isSafeMethod(r.method()), "a " + r.method() + " reached the target");
        }
        assertEquals(1, run.submissions());
        assertEquals("error", run.status(), run.submission().summary);
        assertFalse(run.confirmed());
        assertTrue(run.submission().summary.contains("mutating replay is off"), run.submission().summary);
        assertEquals("REFUSED", run.outcome());
        assertEquals(FakeMontoya.NONCE, run.submission().dispatch_nonce);
    }

    @Test
    @DisplayName("allow_mutating_replay=false: the mutating arm sends no write and reports the refusal")
    void mutatingArmRefusedWhileMutatingReplayIsOff() throws Exception {
        checkMutatingArmRefused(massAssignment(policy(true, false, PlanePolicy.NO_BUDGET)));
    }

    @Test
    @DisplayName("active_enabled=false: the mutating arm is refused too")
    void mutatingArmRefusedWhileActiveIsOff() throws Exception {
        checkMutatingArmRefused(massAssignment(policy(false, true, PlanePolicy.NO_BUDGET)));
    }

    @Test
    @DisplayName("control: with both flags on the same case sends the PATCH and confirms, under the nonce")
    void bothFlagsOnRunsTheArm() throws Exception {
        Run run = massAssignment(policy(true, true, PlanePolicy.NO_BUDGET));
        assertTrue(run.confirmed(), run.status() + " " + run.submission().summary);
        assertTrue(run.sent().stream().anyMatch(r -> r.method().equals("PATCH")));
        assertEquals(FakeMontoya.NONCE, run.submission().dispatch_nonce);
        // The refusal check detects a run that sent the write: it is not vacuous.
        assertThrows(AssertionError.class, () -> checkMutatingArmRefused(run));
    }

    @Test
    @DisplayName("the server's request budget stops the run and the plane reports it")
    void budgetStopsTheRun() throws Exception {
        Run run = massAssignment(policy(true, true, 1));
        assertEquals(1, run.sent().size(), "one send, then the budget refuses");
        assertEquals("error", run.status());
        assertFalse(run.confirmed());
        assertTrue(run.submission().summary.contains("request budget of 1"), run.submission().summary);
    }

    @Test
    @DisplayName("no dispatch from the harness: nothing is sent and nothing is submitted")
    void undispatchedPlanSendsNothing() throws Exception {
        Run run = massAssignment((planId, hash) -> {
            throw new HarnessClient.HarnessException("Harness request unsuccessful (HTTP 409).");
        });
        assertTrue(run.sent().isEmpty());
        assertEquals(0, run.submissions());
        assertNull(run.submission());
        assertEquals("ERROR", run.outcome());
        assertTrue(run.outcomeDetail().contains("did not dispatch"), run.outcomeDetail());
    }

    @Test
    @DisplayName("a passive arm still runs with both flags off (only mutating sends need them)")
    void passiveArmRunsWithFlagsOff() throws Exception {
        Run run = executeUnder(policy(false, false, PlanePolicy.NO_BUDGET), "cors_misconfiguration_detection",
                request("GET", "/account", "", headers("Cookie", "session=synthetic")),
                Reply.of(200, "{}"),
                r -> new Reply(200, "{}", headers("Access-Control-Allow-Origin", "https://evil.example",
                        "Access-Control-Allow-Credentials", "true")));
        assertEquals(1, run.submissions());
        assertTrue(!run.sent().isEmpty() && run.sent().stream().allMatch(r -> r.method().equals("GET")));
        assertFalse("error".equals(run.status()), run.submission().summary);
        assertEquals(FakeMontoya.NONCE, run.submission().dispatch_nonce);
    }
}
