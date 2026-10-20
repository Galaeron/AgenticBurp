package com.harness.llm.logic;

import java.util.regex.Pattern;

/**
 * Classification logic for csrf_validation. Montoya-free.
 *
 * Scope, stated explicitly because it's easy to over-claim here: this
 * only evaluates classic, cookie-based session CSRF on state-changing
 * requests. A request authenticated purely by a Bearer token or a
 * custom API key isn't meaningfully exposed to cross-site request
 * forgery the same way -- browsers don't auto-attach those headers to
 * a cross-origin request the way they do cookies, so REJECTED there
 * means "not applicable", not "definitely safe" (a CORS misconfiguration
 * could still expose it a different way -- that's
 * cors_misconfiguration_detection's job, not this one's).
 */
public final class CsrfLogic {

    public enum Verdict { CONFIRMED, SUPPORTED, REJECTED, INVALID }

    public record Evidence(Verdict verdict, double confidence, boolean confirmed, String summary, String detail) {}

    private static final Pattern SAFE_METHOD = Pattern.compile("^(GET|HEAD|OPTIONS)$", Pattern.CASE_INSENSITIVE);
    private static final Pattern CSRF_TOKEN_NAME = Pattern.compile(
            "(?i)^(csrf[_-]?token|x[_-]?csrf[_-]?token|xsrf[_-]?token|x[_-]?xsrf[_-]?token|"
                    + "authenticity_token|csrfmiddlewaretoken|__requestverificationtoken|_csrf)$");

    private CsrfLogic() {}

    public static boolean isSafeMethod(String method) {
        return method != null && SAFE_METHOD.matcher(method.trim()).matches();
    }

    public static boolean looksLikeCsrfTokenName(String name) {
        return name != null && CSRF_TOKEN_NAME.matcher(name.trim()).matches();
    }

    /** True for a 2xx status: the server performed the request. */
    public static boolean isSuccess(int status) {
        return status >= 200 && status < 300;
    }

    /**
     * Cookie CSRF is confirmed only when all of these hold: the method
     * changes state; the request is authenticated by an ambient cookie (the
     * one credential a browser attaches to a cross-site request by itself);
     * the captured request succeeded; the forged request -- token removed or
     * invalidated, non-ambient credentials such as Authorization removed,
     * cookie kept -- still succeeded; and the same forged request with no
     * cookie either was refused, so that success is owed to the session
     * cookie and not to the action being open to anyone. A status that
     * merely repeats (403 before and after) is never a success.
     *
     * @param method the request method
     * @param cookieAuthPresent true if the request carries a non-empty Cookie header
     * @param tokenFound true if a CSRF-token-shaped header or body/form parameter was found
     * @param originalStatus status of the captured request (with the real token), or -1 if unknown
     * @param forgedStatus status of the forged request (cookie only, no valid token), or -1 if not sent
     * @param anonymousStatus status of the forged request without the cookie too, or -1 if not sent
     */
    public static Evidence evaluate(String method, boolean cookieAuthPresent, boolean tokenFound,
                                     int originalStatus, int forgedStatus, int anonymousStatus) {
        if (isSafeMethod(method)) {
            return new Evidence(Verdict.INVALID, 0.0, false,
                    "Method " + method + " is a safe/idempotent method -- CSRF protection is conventionally "
                            + "not expected here (a state change performed on GET/HEAD/OPTIONS would be a "
                            + "separate, more unusual finding in its own right).", "");
        }
        if (!cookieAuthPresent) {
            return new Evidence(Verdict.REJECTED, 0.7, false,
                    "This request is not cookie-authenticated -- classic CSRF (relying on a browser "
                            + "auto-attaching session credentials to a cross-site request) does not apply the "
                            + "same way to Bearer-token/API-key authentication. Not evidence the endpoint is "
                            + "safe from every cross-origin issue, just that this specific check doesn't apply.",
                    "");
        }
        if (!tokenFound) {
            return new Evidence(Verdict.SUPPORTED, 0.5, false,
                    "This is a cookie-authenticated, state-changing request with no CSRF-token-shaped header "
                            + "or form field observed -- a passive signal, not a proven exploit. The application "
                            + "could still be protected by a mechanism this check doesn't see (e.g. a strict "
                            + "SameSite cookie attribute, or a custom header check this name pattern doesn't "
                            + "recognize).", "");
        }
        String detail = "original status=" + originalStatus + " | cookie only, token removed=" + forgedStatus
                + " | no cookie, no token=" + anonymousStatus;
        if (!isSuccess(originalStatus)) {
            return new Evidence(Verdict.INVALID, 0.0, false,
                    "The captured request did not succeed (status " + originalStatus + "), so there is no "
                            + "performed action to reproduce without the token -- a repeated refusal is not a "
                            + "cross-site state change.", detail);
        }
        if (forgedStatus < 0) {
            return new Evidence(Verdict.SUPPORTED, 0.4, false,
                    "A CSRF-token-shaped field was found but the removal probe was not run -- presence "
                            + "of a token field doesn't by itself prove it's actually validated.", detail);
        }
        if (!isSuccess(forgedStatus)) {
            return new Evidence(Verdict.REJECTED, 0.85, false,
                    "The request was refused (status " + forgedStatus + ", was " + originalStatus
                            + " with the real token) once the CSRF token was removed and only the session "
                            + "cookie was left -- the token appears to be genuinely validated.", detail);
        }
        if (anonymousStatus < 0) {
            return new Evidence(Verdict.SUPPORTED, 0.5, false,
                    "The request still succeeded (status " + forgedStatus + ") with the CSRF token removed, "
                            + "but the no-cookie control was not run, so the success cannot be attributed to "
                            + "the ambient session cookie.", detail);
        }
        if (isSuccess(anonymousStatus)) {
            return new Evidence(Verdict.REJECTED, 0.6, false,
                    "The request also succeeded with no session cookie and no token (status " + anonymousStatus
                            + ") -- the action is not gated on the session, so a cross-site request gains "
                            + "nothing from the victim's cookie. Any unauthenticated state change here is a "
                            + "different finding, not CSRF.", detail);
        }
        if (anonymousStatus < 300 || anonymousStatus >= 500) {
            return new Evidence(Verdict.SUPPORTED, 0.5, false,
                    "The request still succeeded (status " + forgedStatus + ") with only the session cookie "
                            + "and no token, but the no-cookie control returned " + anonymousStatus
                            + ", which is not a clean authentication refusal.", detail);
        }
        return new Evidence(Verdict.CONFIRMED, 0.88, true,
                "The request still succeeded (status " + forgedStatus + ") carrying only the ambient session "
                        + "cookie, with the CSRF token removed/invalidated and no other credential, while the "
                        + "same request without the cookie was refused (status " + anonymousStatus + ") -- "
                        + "the token is not enforced and the session cookie alone authorizes the action.",
                detail);
    }
}
