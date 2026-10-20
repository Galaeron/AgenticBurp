package com.harness.llm.logic;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Forgery + classification logic for jwt_validation. Montoya-free --
 * base64url and a narrow regex substitution on the header segment only
 * (never touching the payload or attempting to forge a valid signature),
 * no JSON library needed for this narrow a task. Ties directly to the
 * alg:none finding worked through by hand earlier this project (see
 * testing/test-target/) -- this is that same check, now something the
 * harness can run deterministically instead of a human reasoning through
 * it.
 */
public final class JwtForgeryLogic {

    public enum Verdict { CONFIRMED, SUPPORTED, INVALID, REJECTED, INCONCLUSIVE }

    public record Evidence(Verdict verdict, double confidence, boolean confirmed, String summary, String detail) {}

    private static final Pattern ALG_FIELD = Pattern.compile("\"alg\"\\s*:\\s*\"[^\"]*\"");

    /**
     * Header names that carry a credential: the standard ones, the cookie
     * (the browser's ambient credential), and custom names such as
     * X-Auth-Token, X-Api-Key or X-Session-Id.
     */
    private static final Pattern CREDENTIAL_HEADER_NAME = Pattern.compile(
            "(?i)^(authorization|proxy-authorization|cookie)$|auth|token|api[-_]?key|session|secret|credential|jwt|bearer");
    private static final Pattern SCHEME_CREDENTIAL_VALUE = Pattern.compile("(?i)^\\s*(bearer|basic|digest|token)\\s+\\S");

    private JwtForgeryLogic() {}

    /** True if `token` has the three dot-separated segments a JWT needs.
     * Doesn't verify anything about validity, just shape -- deliberately
     * permissive about the signature segment being empty, since that's
     * exactly what an alg:none forgery looks like. */
    public static boolean looksLikeJwt(String token) {
        if (token == null) return false;
        String[] parts = token.split("\\.", -1);
        return parts.length == 3 && !parts[0].isEmpty() && !parts[1].isEmpty();
    }

    private static String b64UrlDecode(String s) {
        return new String(Base64.getUrlDecoder().decode(pad(s)), StandardCharsets.UTF_8);
    }

    private static String b64UrlEncode(String s) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(s.getBytes(StandardCharsets.UTF_8));
    }

    private static String pad(String s) {
        int rem = s.length() % 4;
        return rem == 0 ? s : s + "=".repeat(4 - rem);
    }

    /**
     * Forges an alg:none token carrying the ORIGINAL, unmodified payload
     * -- this probes whether signature verification is enforced at all,
     * not whether claims can be tampered with; a server accepting this
     * is vulnerable either way, and leaving the payload untouched keeps
     * the probe from also being a (separate, not-yet-proven) privilege
     * escalation attempt. Returns null if the token isn't JWT-shaped or
     * the header segment doesn't decode as UTF-8/valid base64url.
     */
    public static String forgeAlgNone(String originalToken) {
        if (!looksLikeJwt(originalToken)) return null;
        String[] parts = originalToken.split("\\.", -1);
        try {
            String headerJson = b64UrlDecode(parts[0]);
            var matcher = ALG_FIELD.matcher(headerJson);
            String forgedHeaderJson = matcher.find() ? matcher.replaceFirst("\"alg\":\"none\"") : headerJson;
            String forgedHeader = b64UrlEncode(forgedHeaderJson);
            return forgedHeader + "." + parts[1] + ".";
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Forges a token with the same header/payload but a garbled
     * signature -- a second, independent probe of whether the signature
     * is checked at all (distinct from the alg:none-specific bypass
     * above; a server could reject alg:none but still fail to verify a
     * garbled-but-present signature under its normal algorithm).
     */
    public static String forgeGarbledSignature(String originalToken) {
        if (!looksLikeJwt(originalToken)) return null;
        String[] parts = originalToken.split("\\.", -1);
        return parts[0] + "." + parts[1] + ".AAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    }

    /** True for a 2xx status: the server served the request. */
    public static boolean isSuccess(int status) {
        return status >= 200 && status < 300;
    }

    /**
     * True if `token` is JWT-shaped and its header segment decodes to JSON
     * naming an "alg" -- stricter than {@link #looksLikeJwt}, for values
     * outside the Authorization header, where a dotted value such as a host
     * name or a version string must not be taken for a token.
     */
    public static boolean isDecodableJwt(String token) {
        if (!looksLikeJwt(token)) return false;
        try {
            String headerJson = b64UrlDecode(token.split("\\.", -1)[0]);
            return headerJson.trim().startsWith("{") && ALG_FIELD.matcher(headerJson).find();
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Where a request carries its JWT (code review 02 RV-J residual N2): a
     * header, whose value is {@code prefix + token}, or a cookie.
     */
    public record Carrier(boolean cookie, String name, String prefix, String token) {
        /** The header name a probe sends the token in. */
        public String headerName() { return cookie ? "Cookie" : name; }
        /** The header value carrying {@code token} in place of the original. */
        public String headerValue(String token) { return cookie ? name + "=" + token : prefix + token; }
        public String describe() { return (cookie ? "cookie " : "header ") + name; }
    }

    /**
     * Finds the JWT a request authenticates with: an Authorization Bearer
     * token first (JWT-shaped, as before), then another header whose value is
     * a decodable JWT or "Bearer " and one, then a cookie whose value is a
     * decodable JWT. Returns null if there is none.
     *
     * @param headers the request's headers, in order, as name/value pairs
     */
    public static Carrier findCarrier(List<Map.Entry<String, String>> headers) {
        for (Map.Entry<String, String> h : headers) {
            String value = h.getValue();
            if ("authorization".equalsIgnoreCase(h.getKey()) && value != null
                    && value.regionMatches(true, 0, "Bearer ", 0, 7)) {
                String token = value.substring(7).trim();
                if (looksLikeJwt(token)) return new Carrier(false, h.getKey(), "Bearer ", token);
            }
        }
        for (Map.Entry<String, String> h : headers) {
            String name = h.getKey();
            String value = h.getValue() == null ? "" : h.getValue().trim();
            if (name == null || "cookie".equalsIgnoreCase(name)) continue;
            if (isDecodableJwt(value)) return new Carrier(false, name, "", value);
            if (value.regionMatches(true, 0, "Bearer ", 0, 7) && isDecodableJwt(value.substring(7).trim())) {
                return new Carrier(false, name, "Bearer ", value.substring(7).trim());
            }
        }
        for (Map.Entry<String, String> h : headers) {
            if (!"cookie".equalsIgnoreCase(h.getKey()) || h.getValue() == null) continue;
            for (String pair : h.getValue().split(";")) {
                int eq = pair.indexOf('=');
                if (eq <= 0) continue;
                String name = pair.substring(0, eq).trim();
                String value = pair.substring(eq + 1).trim();
                if (value.length() >= 2 && value.startsWith("\"") && value.endsWith("\"")) value = value.substring(1, value.length() - 1);
                if (!name.isEmpty() && isDecodableJwt(value)) return new Carrier(true, name, "", value);
            }
        }
        return null;
    }

    /**
     * True if this header carries a credential, so the probes must not keep
     * it: a credential-named header, or a value that is a scheme credential
     * ("Bearer ...", "Basic ...") or a decodable JWT. The forged and the
     * no-token requests carry no credential but the token under test --
     * otherwise a session cookie or a second token header authenticates them
     * and the forged token is never what the server checked.
     */
    public static boolean isCredentialHeader(String name, String value) {
        if (name == null) return false;
        if (CREDENTIAL_HEADER_NAME.matcher(name.trim()).find()) return true;
        if (value == null) return false;
        return SCHEME_CREDENTIAL_VALUE.matcher(value).find() || isDecodableJwt(value.trim());
    }

    /**
     * A forged token proves a signature bypass only on a resource that is
     * actually token-gated, so a confirmation needs the unauthenticated
     * control -- the same request with no token at all -- to have been
     * refused. A public resource answers a forged token, a garbled token
     * and no token alike; accepting one there says nothing about signature
     * verification.
     *
     * @param forgedVariant which forgery was attempted, for the summary text
     * @param originalStatus status code of the original, legitimately-signed request
     * @param forgedStatus status code of the forged-token request
     * @param originalBodyLength length of the original response body, for a coarse shape comparison
     * @param forgedBodyLength length of the forged-token response body
     * @param unauthenticatedStatus status of the same request with no token, or -1 if that control was not sent
     */
    public static Evidence evaluate(String forgedVariant, int originalStatus, int forgedStatus,
                                     int originalBodyLength, int forgedBodyLength, int unauthenticatedStatus) {
        boolean sameStatus = originalStatus == forgedStatus;
        boolean statusLooksAuthenticated = isSuccess(forgedStatus);
        boolean similarBodyShape = originalBodyLength > 0
                && Math.abs(originalBodyLength - forgedBodyLength) < Math.max(20, originalBodyLength / 10);
        String detail = "original status=" + originalStatus + " len=" + originalBodyLength
                + " | forged status=" + forgedStatus + " len=" + forgedBodyLength
                + " | no token status=" + unauthenticatedStatus;

        if (!statusLooksAuthenticated) {
            return new Evidence(Verdict.REJECTED, 0.8, false,
                    "The forged token (" + forgedVariant + ") was rejected (status " + forgedStatus
                            + ") -- signature verification appears to be enforced for this bypass attempt.",
                    detail);
        }
        if (unauthenticatedStatus < 0) {
            return new Evidence(Verdict.SUPPORTED, 0.5, false,
                    "A forged token (" + forgedVariant + ") received a 2xx status, but the no-token control "
                            + "was not run, so this cannot be told apart from a resource that is simply public.",
                    detail);
        }
        if (isSuccess(unauthenticatedStatus)) {
            return new Evidence(Verdict.REJECTED, 0.7, false,
                    "The resource also answers with no token at all (status " + unauthenticatedStatus
                            + ") -- it is not token-gated, so the forged token (" + forgedVariant + ") being "
                            + "accepted says nothing about signature verification.",
                    detail);
        }
        if (unauthenticatedStatus < 300 || unauthenticatedStatus >= 500) {
            return new Evidence(Verdict.SUPPORTED, 0.5, false,
                    "A forged token (" + forgedVariant + ") received a 2xx status, but the no-token control "
                            + "returned " + unauthenticatedStatus + ", which is not a clean authentication "
                            + "refusal -- worth a manual check rather than treating this as confirmed.",
                    detail);
        }
        if (sameStatus && similarBodyShape) {
            return new Evidence(Verdict.CONFIRMED, 0.9, true,
                    "A forged token (" + forgedVariant + ") was accepted with the same status code ("
                            + forgedStatus + ") and a similarly-shaped response body as the original, "
                            + "legitimately-signed request, while the same request with no token was refused "
                            + "(status " + unauthenticatedStatus + ") -- the server is not verifying the "
                            + "token's signature.",
                    detail);
        }
        return new Evidence(Verdict.SUPPORTED, 0.55, false,
                "A forged token (" + forgedVariant + ") received a 2xx status on a token-gated resource, but "
                        + "the response shape differs enough from the original that this may be a different "
                        + "code path -- worth a manual comparison rather than treating this as confirmed.",
                detail);
    }

    /**
     * A refused forged token shows the signature is checked only if the
     * original token alone is accepted -- sent in its carrier with the
     * request's other credentials removed, exactly as the probes are (code
     * review 02 RV-N, N2). If that is refused too, the request needs more
     * than the token (a session cookie, a second credential header), and the
     * forged token's refusal says nothing about signature verification.
     *
     * @param refused the evaluation of a forged token that was refused
     * @param tokenAloneStatus status of the original token alone
     */
    public static Evidence requireTokenAloneAccepted(Evidence refused, int tokenAloneStatus) {
        if (refused.verdict() != Verdict.REJECTED || isSuccess(tokenAloneStatus)) return refused;
        return new Evidence(Verdict.INCONCLUSIVE, 0.3, false,
                "The forged token was refused, but so was the original token alone (status " + tokenAloneStatus
                        + ") once the request's other credentials were removed -- the request needs more than "
                        + "the token, so the refusal does not show that the signature is verified.",
                refused.detail() + " | original token alone status=" + tokenAloneStatus);
    }
}
