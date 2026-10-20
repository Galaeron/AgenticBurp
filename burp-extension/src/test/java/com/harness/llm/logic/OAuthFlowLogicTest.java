package com.harness.llm.logic;

import org.junit.jupiter.api.Test;

import static com.harness.llm.logic.OAuthFlowLogic.*;
import static org.junit.jupiter.api.Assertions.*;

public final class OAuthFlowLogicTest {

    private static final String ATTACKER = "https://harness-oauth-probe.example/cb";

    @Test
    void noRedirectUriParamIsInvalid() {
        assertEquals(Verdict.INVALID, evaluate(false, true, ATTACKER, -1, null).verdict());
    }

    @Test
    void honouredTamperedRedirectIsConfirmed() {
        Evidence ev = evaluate(true, true, ATTACKER, 302, ATTACKER + "?code=xyz");
        assertEquals(Verdict.CONFIRMED, ev.verdict());
        assertTrue(ev.confirmed());
    }

    @Test
    void notHonouredButMissingStateIsSupported() {
        assertEquals(Verdict.SUPPORTED, evaluate(true, false, ATTACKER, 302, "https://legit.example/cb").verdict());
    }

    @Test
    void notHonouredWithStateIsRejected() {
        assertEquals(Verdict.REJECTED, evaluate(true, true, ATTACKER, 400, null).verdict());
    }

    @Test
    void sameOriginErrorNamingTheAttackerUriIsNotConfirmed() {
        // Code review 02 R31: the rejected URI in the query string of a local
        // error page is not a redirect to the attacker.
        Evidence ev = evaluate(true, true, ATTACKER, 302, "/error?rejected_redirect_uri=" + ATTACKER);
        assertFalse(ev.confirmed());
        assertEquals(Verdict.REJECTED, ev.verdict());
    }

    @Test
    void absoluteSameOriginErrorNamingTheAttackerUriIsNotConfirmed() {
        assertFalse(evaluate(true, true, ATTACKER, 302,
                "https://auth.example/error?redirect_uri=" + ATTACKER).confirmed());
    }

    @Test
    void attackerHostAsUserinfoIsNotConfirmed() {
        // The browser goes to the host after '@', not to the userinfo.
        assertFalse(evaluate(true, true, ATTACKER, 302,
                "https://harness-oauth-probe.example@auth.example/cb").confirmed());
    }

    @Test
    void schemeRelativeAndCaseVariantAttackerRedirectIsConfirmed() {
        assertTrue(evaluate(true, true, ATTACKER, 302, "//HARNESS-OAUTH-PROBE.example/cb?code=xyz").confirmed());
    }

    @Test
    void attackerLocationWithoutRedirectStatusIsNotConfirmed() {
        assertFalse(evaluate(true, true, ATTACKER, 200, ATTACKER + "?code=xyz").confirmed());
    }

    @Test
    void locationWithUnencodedSpaceStillResolvesToItsHost() {
        assertTrue(evaluate(true, true, ATTACKER, 302, ATTACKER + "?code=a b").confirmed());
        assertFalse(evaluate(true, true, ATTACKER, 302, "/error?uri=" + ATTACKER + "&x=a b").confirmed());
    }

    @Test
    void locationWithNoHostIsNotConfirmed() {
        assertFalse(evaluate(true, true, ATTACKER, 302, "https://").confirmed());
        assertFalse(evaluate(true, true, ATTACKER, 302, "").confirmed());
    }
}
