package com.harness.llm.logic;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Random;
import java.util.Set;
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

    /**
     * Request headers a cross-site page can make a victim's browser send:
     * those the browser sets itself, and the CORS-safelisted ones a form or a
     * no-cors fetch may carry. Any other header on a captured request was set
     * by the application's own script (a token header, Authorization, a
     * custom credential such as X-Auth-Token) and needs a preflight the
     * attacker's origin cannot pass.
     */
    private static final Set<String> CROSS_SITE_SENDABLE_HEADERS = Set.of(
            "host", "cookie", "content-type", "content-length", "content-language", "accept",
            "accept-language", "accept-encoding", "user-agent", "connection", "keep-alive", "origin",
            "referer", "cache-control", "pragma", "upgrade-insecure-requests", "dnt", "te", "priority");

    /**
     * The host of the foreign page a forged request is sent from: a reserved
     * name (RFC 6761: .invalid never resolves), so it is no real site's origin.
     */
    public static final String CROSS_SITE_PAGE_HOST = "csrf-probe.invalid";

    /** The enctypes a form can submit; a body of any other type is not a CORS simple request. */
    private static final Set<String> FORM_ENCTYPES = Set.of(
            "application/x-www-form-urlencoded", "multipart/form-data", "text/plain");

    /**
     * Fields the change marker is never appended to: credentials, contact
     * details and links the account depends on, and identifiers. Matched
     * anywhere in the name, so it errs towards not marking.
     */
    private static final Pattern UNMARKABLE_FIELD = Pattern.compile(
            "(?i)pass|pwd|secret|token|key|otp|pin|code|captcha|user|login|account|mail|phone|url|uri|link|redirect|"
                    + "return|next|callback|(^|[_-])id$|^id");
    private static final Pattern BOOLEAN_LIKE = Pattern.compile("(?i)true|false|on|off|yes|no");

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

    /** True if a cross-site page can make the victim's browser send this header (see the allowlist above). */
    public static boolean isCrossSiteSendableHeader(String name) {
        if (name == null) return false;
        String n = name.trim().toLowerCase(Locale.ROOT);
        return n.startsWith(":") || n.startsWith("sec-fetch-") || n.startsWith("sec-ch-") || n.equals("sec-gpc")
                || CROSS_SITE_SENDABLE_HEADERS.contains(n);
    }

    /**
     * The browser-set headers of the forged request (batch RV-Q item Q1). The
     * captured request carries the application's own Origin, Referer and
     * Sec-Fetch-Site; the browser sets those from the page that sends the
     * request, so a cross-site page cannot keep them, and a server that checks
     * them refuses the real attack. The forged request is modelled as a POST
     * form with rel="noreferrer" on a foreign page of the target's scheme --
     * a request a browser does send: Origin is that page's origin, Referer is
     * absent (so a Referer check that only applies when the header is present
     * does not stop it), and Fetch Metadata says cross-site navigation with no
     * user activation. Browsers send Fetch Metadata to an https target; to an
     * http one only where they did so on the captured request.
     *
     * @param targetUrl the captured request's URL (its scheme is the foreign page's)
     * @param capturedFetchMetadata true if the captured request carried a Sec-Fetch-* header
     * @return header name to value, in order; a null value means the header is removed
     */
    public static Map<String, String> crossSiteBrowserHeaders(String targetUrl, boolean capturedFetchMetadata) {
        boolean http = targetUrl != null && targetUrl.regionMatches(true, 0, "http://", 0, 7);
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Origin", (http ? "http://" : "https://") + CROSS_SITE_PAGE_HOST);
        headers.put("Referer", null);
        boolean fetchMetadata = !http || capturedFetchMetadata;
        headers.put("Sec-Fetch-Site", fetchMetadata ? "cross-site" : null);
        headers.put("Sec-Fetch-Mode", fetchMetadata ? "navigate" : null);
        headers.put("Sec-Fetch-Dest", fetchMetadata ? "document" : null);
        headers.put("Sec-Fetch-User", null);
        return headers;
    }

    /**
     * Why a cross-site page cannot make the browser send this request without
     * a CORS preflight (batch RV-Q item Q2), or null if it can. A form sends
     * only GET and POST, with a form enctype; a fetch() with any other method
     * or Content-Type is not a CORS simple request, so the browser first asks
     * the target with an OPTIONS preflight and sends nothing unless the
     * target's CORS policy approves the foreign origin with credentials. A
     * header a page cannot set is never sent (see isCrossSiteSendableHeader),
     * so it is not a reason here.
     */
    public static String preflightReason(String method, String contentType) {
        String m = method == null ? "" : method.trim().toUpperCase(Locale.ROOT);
        if (isSafeMethod(m)) return null;
        if (!m.isEmpty() && !m.equals("POST")) {
            return "a form cannot send " + m + ", and a cross-site fetch() with it needs a CORS preflight";
        }
        String essence = contentTypeEssence(contentType);
        if (essence == null || FORM_ENCTYPES.contains(essence)) return null;
        return "a form cannot send Content-Type " + essence + ", and a cross-site fetch() with it needs a CORS preflight";
    }

    private static String contentTypeEssence(String contentType) {
        if (contentType == null) return null;
        int semi = contentType.indexOf(';');
        String essence = (semi < 0 ? contentType : contentType.substring(0, semi)).trim().toLowerCase(Locale.ROOT);
        return essence.isEmpty() ? null : essence;
    }

    /**
     * True if the request needs a preflight only for its Content-Type, so the
     * same body can go as text/plain: a no-cors fetch() sends that cross-site
     * with the victim's cookies and no preflight, and a server that reads the
     * body whatever its declared type is exposed to it.
     */
    public static boolean canSendAsTextPlain(String method, String contentType) {
        return method != null && method.trim().equalsIgnoreCase("POST") && preflightReason(method, contentType) != null;
    }

    /**
     * The headers that make the forged request that no-cors fetch(): the body
     * as text/plain and, where Fetch Metadata is sent (see
     * {@link #crossSiteBrowserHeaders}), a no-cors request for no document.
     * Sent with referrer "" the fetch keeps the foreign Origin and no Referer.
     */
    public static Map<String, String> textPlainFetchHeaders(Map<String, String> crossSite) {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Content-Type", "text/plain;charset=UTF-8");
        if (crossSite != null && crossSite.get("Sec-Fetch-Mode") != null) {
            headers.put("Sec-Fetch-Mode", "no-cors");
            headers.put("Sec-Fetch-Dest", "empty");
        }
        return headers;
    }

    /**
     * True if the change marker may be appended to this submitted field: a
     * free-text-looking value (it has a letter and is not an e-mail address,
     * a link or a boolean) in a field whose name is not a credential, a
     * contact detail, a link or an identifier -- so the marked value is
     * likely to pass validation, and the probe never rewrites a password, an
     * address the account depends on or a redirect target.
     */
    public static boolean isMarkableField(String name, String value) {
        if (name == null || value == null || looksLikeCsrfTokenName(name)) return false;
        if (UNMARKABLE_FIELD.matcher(name).find()) return false;
        String v = value.trim();
        if (v.isEmpty() || v.length() > 200 || v.indexOf('@') >= 0 || v.contains("://")) return false;
        if (BOOLEAN_LIKE.matcher(v).matches()) return false;
        return v.chars().anyMatch(Character::isLetter);
    }

    /** A unique, letters-only marker, so it survives most text validation and needs no escaping. */
    public static String newChangeMarker(Random random) {
        StringBuilder marker = new StringBuilder("csrfmark");
        for (int i = 0; i < 10; i++) marker.append((char) ('a' + random.nextInt(26)));
        return marker.toString();
    }

    /**
     * What independent reads showed about the forged request's effect (code
     * review 02 RV-J residual N1). A 2xx is not a state change: an error page,
     * an "invalid token" page or a re-rendered form all return 200.
     */
    public record ReadBack(boolean showsChange, String description) {
        public static ReadBack notRun(String why) {
            return new ReadBack(false, "read-back not run: " + why);
        }
    }

    /**
     * The forged request appended a unique marker to one submitted field.
     * The change is shown only if a read of the page that displays that
     * state, made before the forged request, succeeded without the marker,
     * and two reads after it both succeeded with it -- two, so a one-shot
     * re-render of the submitted input (a form flashed back after an
     * "invalid token" error) does not pass for stored state.
     */
    public static ReadBack readBack(String target, String field, String marker,
                                    int beforeStatus, String beforeBody,
                                    int afterStatus, String afterBody,
                                    int againStatus, String againBody) {
        boolean markerBefore = carries(beforeBody, marker);
        boolean markerAfter = carries(afterBody, marker);
        boolean markerAgain = carries(againBody, marker);
        boolean shows = marker != null && !marker.isEmpty()
                && isSuccess(beforeStatus) && !markerBefore
                && isSuccess(afterStatus) && markerAfter
                && isSuccess(againStatus) && markerAgain;
        String description = "read-back GET " + target + " for the marker on field '" + field + "': before status="
                + beforeStatus + (markerBefore ? " (marker already present)" : "")
                + ", after status=" + afterStatus + (markerAfter ? " (marker shown)" : " (marker absent)")
                + ", again status=" + againStatus + (markerAgain ? " (marker shown)" : " (marker absent)");
        return new ReadBack(shows, description);
    }

    private static boolean carries(String body, String marker) {
        return body != null && marker != null && !marker.isEmpty() && body.contains(marker);
    }

    /**
     * Cookie CSRF is confirmed only when all of these hold: the method
     * changes state; the request is authenticated by an ambient cookie (the
     * one credential a browser attaches to a cross-site request by itself);
     * the captured request succeeded; the forged request -- token removed or
     * invalidated, every header a cross-site page cannot send removed (so
     * no Authorization or custom credential header), Origin, Referer and
     * Fetch Metadata those of a foreign page (see
     * {@link #crossSiteBrowserHeaders}), cookie kept -- still
     * succeeded; the same forged request with no cookie either was refused,
     * so that success is owed to the session cookie and not to the action
     * being open to anyone; and an independent read-back shows the forged
     * request changed state (see {@link #readBack}), since a 2xx can be an
     * error or "invalid token" page. A status that merely repeats (403
     * before and after) is never a success.
     *
     * @param method the request method
     * @param cookieAuthPresent true if the request carries a non-empty Cookie header
     * @param tokenFound true if a CSRF-token-shaped header or body/form parameter was found
     * @param originalStatus status of the captured request (with the real token), or -1 if unknown
     * @param forgedStatus status of the forged request (cookie only, no valid token), or -1 if not sent
     * @param anonymousStatus status of the forged request without the cookie too, or -1 if not sent
     * @param readBack what reads of the state before and after the forged request showed; null if none were made
     */
    public static Evidence evaluate(String method, boolean cookieAuthPresent, boolean tokenFound,
                                     int originalStatus, int forgedStatus, int anonymousStatus, ReadBack readBack) {
        if (readBack == null) readBack = ReadBack.notRun("no read of the state was made");
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
                + " | no cookie, no token=" + anonymousStatus + " | " + readBack.description();
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
                            + " with the real token) once the CSRF token was removed, only the session "
                            + "cookie was left and it was sent as a foreign page would send it -- the token "
                            + "or the request's cross-site origin is checked.", detail);
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
        if (!readBack.showsChange()) {
            return new Evidence(Verdict.SUPPORTED, 0.55, false,
                    "The request returned " + forgedStatus + " carrying only the ambient session cookie, with "
                            + "the CSRF token removed/invalidated and no other credential, and the same request "
                            + "without the cookie was refused (status " + anonymousStatus + ") -- but no "
                            + "independent read-back showed that the forged request changed anything. A 2xx "
                            + "alone is not a state change: an error page, an \"invalid token\" page or a "
                            + "re-rendered form also return 200.", detail);
        }
        return new Evidence(Verdict.CONFIRMED, 0.88, true,
                "The request still succeeded (status " + forgedStatus + ") carrying only the ambient session "
                        + "cookie, with the CSRF token removed/invalidated and no other credential, the same "
                        + "request without the cookie was refused (status " + anonymousStatus + "), and fresh "
                        + "reads of the state show the marker the forged request submitted -- the token is not "
                        + "enforced and the session cookie alone performs the action.",
                detail);
    }

    /**
     * As above, for a request sent as it needs a CORS preflight from a foreign
     * page ({@code preflightReason} non-null, see {@link #preflightReason}):
     * at most SUPPORTED, naming the preflight, since a forged request that
     * succeeds from Burp shows nothing about what a browser sends from a
     * foreign page before the target approves it.
     */
    public static Evidence evaluate(String method, boolean cookieAuthPresent, boolean tokenFound,
                                     int originalStatus, int forgedStatus, int anonymousStatus, ReadBack readBack,
                                     String preflightReason) {
        Evidence ev = evaluate(method, cookieAuthPresent, tokenFound, originalStatus, forgedStatus, anonymousStatus, readBack);
        if (preflightReason == null || (ev.verdict() != Verdict.CONFIRMED && ev.verdict() != Verdict.SUPPORTED)) return ev;
        String note = "preflight needed: " + preflightReason;
        return new Evidence(Verdict.SUPPORTED, Math.min(ev.confidence(), 0.5), false,
                "Not CSRF as sent: " + preflightReason + " -- the browser sends it only if the target's CORS "
                        + "policy approves the foreign origin with credentials (cors_misconfiguration_detection's "
                        + "question). What the probe saw: " + ev.summary(),
                ev.detail() == null || ev.detail().isEmpty() ? note : ev.detail() + " | " + note);
    }

    /** As above with no read-back made, so it can never confirm. */
    public static Evidence evaluate(String method, boolean cookieAuthPresent, boolean tokenFound,
                                     int originalStatus, int forgedStatus, int anonymousStatus) {
        return evaluate(method, cookieAuthPresent, tokenFound, originalStatus, forgedStatus, anonymousStatus, null);
    }
}
