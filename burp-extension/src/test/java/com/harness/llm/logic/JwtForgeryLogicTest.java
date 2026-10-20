package com.harness.llm.logic;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static com.harness.llm.logic.JwtForgeryLogic.*;
import static org.junit.jupiter.api.Assertions.*;

public final class JwtForgeryLogicTest {

    private static String b64(String s) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(s.getBytes(StandardCharsets.UTF_8));
    }

    private static String realToken() {
        String header = b64("{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
        String payload = b64("{\"user_id\":1,\"role\":\"user\"}");
        return header + "." + payload + ".realsignaturebytes";
    }

    // --- shape detection ---

    @Test
    @DisplayName("a real three-segment token looks like a JWT")
    void realTokenLooksLikeJwt() {
        assertTrue(looksLikeJwt(realToken()));
    }

    @Test
    @DisplayName("an opaque non-JWT token does not look like a JWT")
    void opaqueTokenDoesNotLookLikeJwt() {
        assertFalse(looksLikeJwt("opaque-api-key-12345"));
    }

    @Test
    @DisplayName("null and malformed tokens do not look like a JWT")
    void nullAndMalformedAreNotJwt() {
        assertFalse(looksLikeJwt(null));
        assertFalse(looksLikeJwt("only.two"));
        assertFalse(looksLikeJwt(""));
    }

    // --- forging ---

    @Test
    @DisplayName("forgeAlgNone rewrites the header to alg:none, keeps the original payload untouched, empties the signature")
    void forgeAlgNoneRewritesHeaderOnly() {
        String original = realToken();
        String forged = forgeAlgNone(original);
        assertNotNull(forged);
        String[] parts = forged.split("\\.", -1);
        assertEquals(3, parts.length);
        String decodedHeader = new String(Base64.getUrlDecoder().decode(pad(parts[0])), StandardCharsets.UTF_8);
        assertTrue(decodedHeader.contains("\"alg\":\"none\""));
        // payload must be byte-for-byte unchanged -- this probes signature
        // verification, not claim tampering
        assertEquals(original.split("\\.", -1)[1], parts[1]);
        assertEquals("", parts[2]);
    }

    @Test
    @DisplayName("forgeAlgNone returns null for a non-JWT-shaped token")
    void forgeAlgNoneRejectsNonJwt() {
        assertNull(forgeAlgNone("not-a-jwt"));
    }

    @Test
    @DisplayName("forgeGarbledSignature keeps header and payload, replaces only the signature")
    void forgeGarbledSignatureKeepsHeaderAndPayload() {
        String original = realToken();
        String forged = forgeGarbledSignature(original);
        String[] originalParts = original.split("\\.", -1);
        String[] forgedParts = forged.split("\\.", -1);
        assertEquals(originalParts[0], forgedParts[0]);
        assertEquals(originalParts[1], forgedParts[1]);
        assertNotEquals(originalParts[2], forgedParts[2]);
    }

    private static String pad(String s) {
        int rem = s.length() % 4;
        return rem == 0 ? s : s + "=".repeat(4 - rem);
    }

    // --- classification ---

    @Test
    @DisplayName("forged token accepted with same status and similar body shape, no-token control refused -> confirmed")
    void acceptedWithSimilarShapeIsConfirmed() {
        Evidence e = evaluate("alg:none", 200, 200, 100, 105, 401);
        assertEquals(Verdict.CONFIRMED, e.verdict());
        assertTrue(e.confirmed());
    }

    @Test
    @DisplayName("forged token accepted (2xx) but very different body shape -> supported, not confirmed")
    void acceptedButDifferentShapeIsSupported() {
        Evidence e = evaluate("alg:none", 200, 200, 1000, 5, 401);
        assertEquals(Verdict.SUPPORTED, e.verdict());
        assertFalse(e.confirmed());
    }

    @Test
    @DisplayName("forged token rejected -> rejected")
    void rejectedForgedTokenIsRejected() {
        Evidence e = evaluate("alg:none", 200, 401, 100, 20, -1);
        assertEquals(Verdict.REJECTED, e.verdict());
    }

    @Test
    @DisplayName("forged token gets a different 2xx-adjacent redirect/etc -- still not confirmed without matching shape")
    void differentStatusEntirelyIsNotConfirmed() {
        Evidence e = evaluate("garbled signature", 200, 403, 100, 20, -1);
        assertEquals(Verdict.REJECTED, e.verdict());
    }

    @Test
    @DisplayName("R26: a public resource answering the forged token and no token alike is not a bypass")
    void publicResourceIsNotConfirmed() {
        Evidence e = evaluate("alg:none", 200, 200, 21, 21, 200);
        assertEquals(Verdict.REJECTED, e.verdict());
        assertFalse(e.confirmed());
    }

    @Test
    @DisplayName("R26: forged token accepted but the no-token control not run -> supported only")
    void acceptedWithoutControlIsSupported() {
        Evidence e = evaluate("alg:none", 200, 200, 100, 105, -1);
        assertEquals(Verdict.SUPPORTED, e.verdict());
        assertFalse(e.confirmed());
    }

    @Test
    @DisplayName("R26: a no-token control that errors is not a clean refusal -> supported only")
    void controlServerErrorIsSupported() {
        Evidence e = evaluate("alg:none", 200, 200, 100, 105, 502);
        assertEquals(Verdict.SUPPORTED, e.verdict());
        assertFalse(e.confirmed());
    }
}
