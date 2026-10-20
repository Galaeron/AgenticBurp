package com.harness.llm.logic;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Passive clickjacking-protection check for csp_clickjacking_validation.
 * Montoya-free, like the other *Logic classes -- takes plain strings the
 * caller already has from the already-captured exchange, no new request
 * needed. This is deliberately narrow: it checks specifically for framing
 * protection (X-Frame-Options / CSP frame-ancestors), not a general CSP
 * quality audit -- that's a different, broader question than the
 * capability name asks.
 *
 * The CSP is parsed, not searched (code review 02 R32): policies are split
 * on ',' and directives on ';', the directive name is the first token, and
 * only a frame-ancestors directive's source list counts. A source list that
 * admits any origin ('*', a scheme-only source such as https:, or a host of
 * '*') is not framing protection, and a "frame-ancestors" substring inside
 * another directive's value (report-uri /frame-ancestors/report) is not a
 * directive at all.
 */
public final class CspClickjackingLogic {

    public enum Verdict { CONFIRMED, SUPPORTED, INVALID, REJECTED }

    public record Evidence(Verdict verdict, double confidence, boolean confirmed, String summary, String detail) {}

    private static final Pattern SCHEME_ONLY_SOURCE = Pattern.compile("^[a-z][a-z0-9+.-]*:$");
    private static final Pattern HOST_SOURCE = Pattern.compile("^(?:[a-z][a-z0-9+.-]*://)?([^/:]*)(?::[0-9*]+)?(?:/.*)?$");
    private static final Pattern VALID_XFO = Pattern.compile("^\\s*(DENY|SAMEORIGIN)\\s*$", Pattern.CASE_INSENSITIVE);

    private CspClickjackingLogic() {}

    /**
     * The source list of each policy's frame-ancestors directive, one entry
     * per comma-separated policy that has one (the first occurrence in a
     * policy wins, as in browsers). Sources are lower-cased.
     */
    static List<List<String>> frameAncestorsSourceLists(String csp) {
        List<List<String>> lists = new ArrayList<>();
        if (csp == null) return lists;
        for (String policy : csp.split(",")) {
            for (String directive : policy.split(";")) {
                String[] tokens = directive.trim().toLowerCase(Locale.ROOT).split("\\s+");
                if (tokens.length == 0 || !tokens[0].equals("frame-ancestors")) continue;
                List<String> sources = new ArrayList<>();
                for (int i = 1; i < tokens.length; i++) if (!tokens[i].isEmpty()) sources.add(tokens[i]);
                lists.add(sources);
                break;
            }
        }
        return lists;
    }

    /**
     * True if a frame-ancestors source list lets any origin frame the page:
     * '*', a scheme-only source (https:, http:, data: ...), or a host-source
     * whose host is '*'. An empty list or 'none' blocks framing; 'self' and
     * named hosts restrict it.
     */
    static boolean admitsAnyOrigin(List<String> sources) {
        for (String source : sources) {
            if (source.startsWith("'")) continue;  // 'self', 'none' and other keywords
            if (source.equals("*") || SCHEME_ONLY_SOURCE.matcher(source).matches()) return true;
            var host = HOST_SOURCE.matcher(source);
            if (host.matches() && host.group(1).equals("*")) return true;
        }
        return false;
    }

    /**
     * @param contentType   the response's Content-Type header value, or null
     * @param xFrameOptions the response's X-Frame-Options header value, or null if absent
     * @param csp           the response's Content-Security-Policy header value, or null if absent
     */
    public static Evidence evaluate(String contentType, String xFrameOptions, String csp) {
        boolean rendersInBrowser = contentType != null && contentType.toLowerCase().contains("text/html");
        if (!rendersInBrowser) {
            return new Evidence(Verdict.INVALID, 0.0, false,
                    "Response Content-Type is not text/html -- clickjacking framing protection is not "
                            + "a meaningful question for a response that isn't rendered as a page.", "");
        }

        // Every enforced policy applies, so one restrictive frame-ancestors is enough.
        List<List<String>> frameAncestors = frameAncestorsSourceLists(csp);
        for (List<String> sources : frameAncestors) {
            if (!admitsAnyOrigin(sources)) {
                return new Evidence(Verdict.REJECTED, 0.85, false,
                        "Content-Security-Policy declares a restrictive frame-ancestors ("
                                + (sources.isEmpty() ? "empty source list, i.e. 'none'" : String.join(" ", sources))
                                + "), which takes precedence over X-Frame-Options in browsers that support it "
                                + "-- framing is restricted.",
                        "CSP: " + csp);
            }
        }
        if (!frameAncestors.isEmpty()) {
            return new Evidence(Verdict.SUPPORTED, 0.7, false,
                    "Content-Security-Policy declares frame-ancestors, but its source list admits any origin ("
                            + String.join(" ", frameAncestors.get(0)) + ") -- that is not framing protection, "
                            + "and browsers that enforce frame-ancestors ignore X-Frame-Options"
                            + (xFrameOptions == null ? "" : " (present here: " + xFrameOptions + ")")
                            + ", so the page can be framed by another origin. This is a passive header check, "
                            + "not proof a framed click can do harm.",
                    "CSP: " + csp + (xFrameOptions == null ? "" : " | X-Frame-Options: " + xFrameOptions));
        }

        boolean hasValidXfo = xFrameOptions != null && VALID_XFO.matcher(xFrameOptions).matches();
        if (hasValidXfo) {
            return new Evidence(Verdict.REJECTED, 0.8, false,
                    "X-Frame-Options is present with a recognized value -- framing is restricted in "
                            + "browsers that honor it (older/non-Chromium browsers may not support "
                            + "frame-ancestors, so this header still matters even where CSP is also set).",
                    "X-Frame-Options: " + xFrameOptions);
        }

        boolean hasMalformedXfo = xFrameOptions != null;
        if (hasMalformedXfo) {
            return new Evidence(Verdict.SUPPORTED, 0.6, false,
                    "X-Frame-Options is present but its value is not a recognized directive (DENY/"
                            + "SAMEORIGIN) -- browsers may ignore it entirely, leaving the page framable.",
                    "X-Frame-Options: " + xFrameOptions);
        }

        return new Evidence(Verdict.SUPPORTED, 0.75, false,
                "This HTML response has neither a CSP frame-ancestors directive nor an X-Frame-Options "
                        + "header -- nothing observed here prevents the page from being framed by another "
                        + "origin. This is a passive header check, not proof the page is exploitable via "
                        + "clickjacking (that also depends on what a framed click could actually do).", "");
    }
}
