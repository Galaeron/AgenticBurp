package com.harness.llm.logic;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** ARC-4: the Burp plane's per-dispatch policy, mirroring the Python SafetyGate. */
final class PlanePolicyTest {

    @Test
    @DisplayName("safe methods are sent with both flags off")
    void safeMethodsNeedNoFlags() {
        PlanePolicy policy = new PlanePolicy(false, false, PlanePolicy.NO_BUDGET);
        for (String method : new String[]{"GET", "head", "OPTIONS", " TRACE "}) {
            assertNull(policy.authorize(method), method);
        }
        assertEquals(4, policy.sent());
        assertNull(policy.refusal());
    }

    @Test
    @DisplayName("a mutating or unknown method is refused unless both flags are on")
    void mutatingNeedsBothFlags() {
        boolean[][] partial = {{false, false}, {true, false}, {false, true}};
        for (boolean[] flags : partial) {
            for (String method : new String[]{"POST", "PUT", "PATCH", "DELETE", "PROPFIND", "", null}) {
                PlanePolicy policy = new PlanePolicy(flags[0], flags[1], PlanePolicy.NO_BUDGET);
                String refusal = policy.authorize(method);
                assertNotNull(refusal, method + " active=" + flags[0] + " mutating=" + flags[1]);
                assertTrue(refusal.contains("mutating replay is off"), refusal);
                assertEquals(0, policy.sent(), "a refused send is not counted");
            }
        }
    }

    @Test
    @DisplayName("control: with active_enabled and allow_mutating_replay on, a mutating method is sent")
    void bothFlagsAllowMutating() {
        PlanePolicy policy = new PlanePolicy(true, true, PlanePolicy.NO_BUDGET);
        assertNull(policy.authorize("POST"));
        assertNull(policy.authorize("DELETE"));
        assertNull(policy.refusal());
    }

    @Test
    @DisplayName("the request budget stops the run at its ceiling")
    void budgetIsACeiling() {
        PlanePolicy policy = new PlanePolicy(false, false, 2);
        assertNull(policy.authorize("GET"));
        assertNull(policy.authorize("GET"));
        String refusal = policy.authorize("GET");
        assertNotNull(refusal);
        assertTrue(refusal.contains("budget of 2"), refusal);
        assertEquals(2, policy.sent());
        assertNotNull(new PlanePolicy(false, false, 0).authorize("GET"), "a zero budget sends nothing");
    }

    @Test
    @DisplayName("the first refusal is sticky: a later safe send is refused with it")
    void refusalIsSticky() {
        PlanePolicy policy = new PlanePolicy(false, false, PlanePolicy.NO_BUDGET);
        String first = policy.authorize("POST");
        assertEquals(first, policy.authorize("GET"));
        assertEquals(first, policy.refusal());
        assertEquals(0, policy.sent());
    }
}
