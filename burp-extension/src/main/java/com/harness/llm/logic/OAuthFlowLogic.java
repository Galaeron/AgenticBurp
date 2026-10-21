package com.harness.llm.logic;

import java.net.URI;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Classification logic for oauth_flow_validation. Montoya-free. Targets the two
 * highest-value, testable OAuth authorization-request weaknesses: a missing
 * {@code state} parameter (CSRF on the redirect/callback) and a tamperable
 * {@code redirect_uri} (open redirect / code exfiltration). The executor resends
 * the authorize request with an attacker-controlled redirect_uri and hands over
 * the resulting status + Location, plus whether the original carried state.
 *
 * NOTE: authored without a JDK (hazard #6); compiled/unit-run at gradle build.
 */
public final class OAuthFlowLogic {

    public enum Verdict { CONFIRMED, SUPPORTED, REJECTED, INVALID }

    public record Evidence(Verdict verdict, double confidence, boolean confirmed, String summary, String detail) {}

    /** Authority of an absolute or scheme-relative URI reference; a relative path has none. */
    private static final Pattern AUTHORITY = Pattern.compile("^(?:[A-Za-z][A-Za-z0-9+.-]*:)?//([^/?#]*)");

    private OAuthFlowLogic() {}

    /**
     * True if the Location sends the browser to the attacker's host. The
     * Location is parsed, not searched (code review 02 R31): a same-origin
     * path that merely names the rejected URI, such as
     * /error?rejected_redirect_uri=https://attacker.example/cb, keeps the
     * browser on the authorization server and exfiltrates nothing.
     */
    static boolean redirectsTo(String location, String attackerUri) {
        if (location == null || attackerUri == null) return false;
        String attackerHost = hostOf(attackerUri.trim());
        String destinationHost = hostOf(location.trim());
        return attackerHost != null && attackerHost.equals(destinationHost);
    }

    /** The lower-cased host a URI reference points at, or null for a relative or unparseable one. */
    private static String hostOf(String uriReference) {
        String host = null;
        try {
            host = new URI(uriReference).getHost();
        } catch (Exception e) {
            // e.g. an unencoded space in the query, which a browser still follows
        }
        if (host == null) {
            // Authority java.net.URI would not split (underscore in the host,
            // illegal characters elsewhere): drop userinfo and port by hand.
            Matcher m = AUTHORITY.matcher(uriReference);
            if (!m.find()) return null;
            String authority = m.group(1);
            authority = authority.substring(authority.lastIndexOf('@') + 1);
            int colon = authority.lastIndexOf(':');
            host = colon >= 0 && !authority.endsWith("]") ? authority.substring(0, colon) : authority;
        }
        if (host.isEmpty()) return null;
        host = host.toLowerCase(Locale.ROOT);
        return host.endsWith(".") ? host.substring(0, host.length() - 1) : host;
    }

    /**
     * @param hadRedirectUriParam whether the request actually carried a redirect_uri to tamper with
     * @param hasStateParam       whether the authorize request carried a state parameter
     * @param attackerRedirectUri the tampered redirect_uri value the executor injected
     * @param redirectStatus      status of the tampered request (-1 if none)
     * @param locationHeader      Location response header of the tampered request (may be null)
     */
    public static Evidence evaluate(boolean hadRedirectUriParam, boolean hasStateParam,
                                    String attackerRedirectUri, int redirectStatus, String locationHeader) {
        if (!hadRedirectUriParam) {
            return new Evidence(Verdict.INVALID, 0, false,
                    "This request carries no redirect_uri parameter -- oauth_flow_validation's redirect_uri "
                            + "tampering probe does not apply. (Not an OAuth authorize request?)", "");
        }
        boolean followedAttacker = (redirectStatus >= 300 && redirectStatus < 400)
                && redirectsTo(locationHeader, attackerRedirectUri);
        if (followedAttacker) {
            return new Evidence(Verdict.CONFIRMED, 0.9, true,
                    "The authorization endpoint honoured a tampered redirect_uri and issued a redirect to an "
                            + "attacker-controlled host -- an authorization code / token can be exfiltrated to the "
                            + "attacker (open redirect in the OAuth flow)."
                            + (hasStateParam ? "" : " No state parameter was present, so the callback is also CSRF-able."),
                    "redirectStatus=" + redirectStatus + " location=" + locationHeader);
        }
        if (!hasStateParam) {
            return new Evidence(Verdict.SUPPORTED, 0.55, false,
                    "The redirect_uri was not honoured to an attacker host, but the authorize request carries "
                            + "no state parameter -- the OAuth callback is exposed to CSRF (login/authorization "
                            + "fixation). Confirm the callback does not otherwise bind the session.",
                    "redirectStatus=" + redirectStatus);
        }
        return new Evidence(Verdict.REJECTED, 0.7, false,
                "The authorization endpoint rejected the tampered redirect_uri and a state parameter is "
                        + "present -- neither redirect_uri tampering nor CSRF demonstrated here.",
                "redirectStatus=" + redirectStatus);
    }
}
