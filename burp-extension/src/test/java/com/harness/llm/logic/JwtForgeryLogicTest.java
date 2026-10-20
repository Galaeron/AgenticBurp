package com.harness.llm.logic;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;

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

    // ---------------------------------------------------------------- RV-N N2
    private static final String RVN_JWT = "eyJhbGciOiJIUzI1NiJ9.e30.c2ln";

    private static List<Map.Entry<String, String>> hs(String... nameValuePairs) {
        List<Map.Entry<String, String>> h = new java.util.ArrayList<>();
        for (int i = 0; i < nameValuePairs.length; i += 2) h.add(Map.entry(nameValuePairs[i], nameValuePairs[i + 1]));
        return h;
    }

    @Test
    @DisplayName("N2: a JWT is found in Authorization first, then another header, then a cookie")
    void carrierFoundWhereverTheTokenIs() {
        Carrier auth = findCarrier(hs("Cookie", "token=" + RVN_JWT, "Authorization", "Bearer " + RVN_JWT));
        assertEquals("header Authorization", auth.describe());
        assertEquals("Bearer x", auth.headerValue("x"));

        Carrier header = findCarrier(hs("Cookie", "token=" + RVN_JWT, "X-Access-Token", RVN_JWT));
        assertEquals("header X-Access-Token", header.describe());
        assertEquals("x", header.headerValue("x"));

        Carrier bearer = findCarrier(hs("X-Auth", "Bearer " + RVN_JWT));
        assertEquals("Bearer x", bearer.headerValue("x"));

        Carrier cookie = findCarrier(hs("Cookie", "theme=dark; token=\"" + RVN_JWT + "\""));
        assertTrue(cookie.cookie());
        assertEquals(RVN_JWT, cookie.token());
        assertEquals("Cookie", cookie.headerName());
        assertEquals("token=x", cookie.headerValue("x"));
    }

    @Test
    @DisplayName("N2: a dotted value outside Authorization must decode as a JWT header to count")
    void dottedValuesAreNotTokens() {
        assertNull(findCarrier(hs("Cookie", "host=www.shop.example; v=1.2.3")));
        assertNull(findCarrier(hs("X-Version", "1.2.3", "X-Host", "www.shop.example")));
        assertNull(findCarrier(hs("Accept", "text/html")));
        assertTrue(isDecodableJwt(RVN_JWT));
        assertFalse(isDecodableJwt("www.shop.example"));
        assertFalse(isDecodableJwt("e30.e30.c2ln"));
        assertFalse(isDecodableJwt(null));
    }

    @Test
    @DisplayName("N2: credential headers are recognized by name or by value")
    void credentialHeadersRecognized() {
        for (String name : new String[] {"Cookie", "Authorization", "Proxy-Authorization", "X-Auth-Token",
                "X-Api-Key", "X-API_KEY", "X-Session-Id", "X-Client-Secret", "X-JWT"}) {
            assertTrue(isCredentialHeader(name, "v"), name);
        }
        assertTrue(isCredentialHeader("X-Custom", "Basic dXNlcjpwYXNz"));
        assertTrue(isCredentialHeader("X-Custom", RVN_JWT));
        for (String name : new String[] {"Accept", "User-Agent", "X-Requested-With", "Content-Type", "Referer"}) {
            assertFalse(isCredentialHeader(name, "text/html"), name);
        }
        assertFalse(isCredentialHeader(null, "Bearer x"));
    }

    @Test
    @DisplayName("N2: a refused forged token is rejected only if the original token alone is accepted")
    void refusalCountsOnlyIfTokenAloneAccepted() {
        Evidence refused = evaluate("garbled signature", 200, 401, 100, 20, -1);
        assertEquals(Verdict.REJECTED, refused.verdict());
        assertEquals(Verdict.REJECTED, requireTokenAloneAccepted(refused, 200).verdict());
        Evidence notIsolated = requireTokenAloneAccepted(refused, 401);
        assertEquals(Verdict.INCONCLUSIVE, notIsolated.verdict());
        assertFalse(notIsolated.confirmed());
        assertTrue(notIsolated.detail().contains("original token alone status=401"), notIsolated.detail());
        Evidence confirmed = new Evidence(Verdict.CONFIRMED, 0.9, true, "s", "d");
        assertEquals(confirmed, requireTokenAloneAccepted(confirmed, 401), "only a rejection is qualified");
    }
}
