package com.harness.llm.logic;

/**
 * Classification logic for subdomain_takeover_detection. Montoya-free and
 * passive -- no new request. The executor hands over the captured response's
 * status and body; this class matches them against the well-known "dangling
 * service" fingerprints third-party hosts return when a CNAME points at an
 * unclaimed resource. A fingerprint match is a lead (SUPPORTED) only:
 * the body text alone cannot show who owns the host's DNS or the
 * provider resource, so this class never confirms a takeover.
 *
 * NOTE: authored without a JDK (hazard #6); compiled/unit-run at gradle build.
 */
public final class SubdomainTakeoverLogic {

    public enum Verdict { CONFIRMED, SUPPORTED, REJECTED }

    public record Evidence(Verdict verdict, double confidence, boolean confirmed, String summary, String detail) {}

    private SubdomainTakeoverLogic() {}

    // Distinctive strings served by unclaimed third-party resources. Matched
    // case-insensitively; each is specific to a takeover-prone provider.
    private static final String[][] FINGERPRINTS = {
            {"there isn't a github pages site here", "GitHub Pages"},
            {"no such app", "Heroku"},
            {"nosuchbucket", "Amazon S3"},
            {"the specified bucket does not exist", "Amazon S3"},
            {"fastly error: unknown domain", "Fastly"},
            {"do not know how to serve", "Fastly"},
            {"the request could not be satisfied", "CloudFront/S3"},
            {"herokucdn.com/error-pages/no-such-app.html", "Heroku"},
            {"repository not found", "GitHub/Bitbucket"},
            {"project not found", "Surge.sh"},
            {"this domain is not configured", "Netlify/Vercel"},
            {"backend not found", "Shopify"},
            {"we could not find what you're looking for", "Help Scout"},
            {"unrecognized domain", "Zendesk/Tumblr"},
    };

    /**
     * @param statusCode captured response status
     * @param body       captured response body (may be null)
     */
    public static Evidence evaluate(int statusCode, String body) {
        if (body == null || body.isBlank()) {
            return new Evidence(Verdict.REJECTED, 0.6, false,
                    "No response body to match against subdomain-takeover fingerprints.", "");
        }
        String low = body.toLowerCase();
        for (String[] fp : FINGERPRINTS) {
            if (low.contains(fp[0])) {
                // A lead, never a confirmation: an application's own "not
                // found" page can carry the same words (code review 02 R29).
                // Takeover needs DNS/provider ownership evidence this passive
                // check does not have.
                return new Evidence(Verdict.SUPPORTED, 0.6, false,
                        "The response body carries the '" + fp[1] + "' unclaimed-resource fingerprint -- a "
                                + "takeover lead, not proof: an application's own not-found page can use the same "
                                + "words. Confirming it needs DNS/provider ownership evidence: the host's CNAME "
                                + "points at " + fp[1] + " and the target resource there is unclaimed and "
                                + "claimable.",
                        "provider=" + fp[1] + " status=" + statusCode);
            }
        }
        // A 404 with no fingerprint isn't proof, but on a host reached via a CNAME
        // it's worth a manual DNS check.
        if (statusCode == 404) {
            return new Evidence(Verdict.SUPPORTED, 0.35, false,
                    "The endpoint returns 404 with no known takeover fingerprint -- inconclusive on its own; "
                            + "check whether this host's CNAME points at an unclaimed provider resource.",
                    "status=404");
        }
        return new Evidence(Verdict.REJECTED, 0.7, false,
                "No dangling-service fingerprint matched in the response.", "status=" + statusCode);
    }
}
