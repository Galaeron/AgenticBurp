package com.harness.llm;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.collaborator.CollaboratorPayload;
import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.collaborator.InteractionFilter;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.harness.llm.logic.CommandInjectionTimingLogic;
import com.harness.llm.logic.CorsMisconfigLogic;
import com.harness.llm.logic.CryptoTransportLogic;
import com.harness.llm.logic.CspClickjackingLogic;
import com.harness.llm.logic.CsrfLogic;
import com.harness.llm.logic.DeserializationFormatLogic;
import com.harness.llm.logic.NoSqlInjectionLogic;
import com.harness.llm.logic.OAuthFlowLogic;
import com.harness.llm.logic.RequestSmugglingLogic;
import com.harness.llm.logic.SqlInjectionLogic;
import com.harness.llm.logic.SubdomainTakeoverLogic;
import com.harness.llm.logic.WebCachePoisoningLogic;
import com.harness.llm.logic.WebsocketCswshLogic;
import com.harness.llm.logic.ExchangeFingerprint;
import com.harness.llm.logic.FileUploadLogic;
import com.harness.llm.logic.HeaderInjectionLogic;
import com.harness.llm.logic.IdentityCandidateResolver;
import com.harness.llm.logic.IdentityCompareLogic;
import com.harness.llm.logic.IdentityLabelResolver;
import com.harness.llm.logic.InfoDisclosureLogic;
import com.harness.llm.logic.JwtForgeryLogic;
import com.harness.llm.logic.MassAssignmentLogic;
import com.harness.llm.logic.OpenRedirectLogic;
import com.harness.llm.logic.PoolCandidateResolver;
import com.harness.llm.logic.RaceConditionLogic;
import com.harness.llm.logic.SessionLifecycleLogic;
import com.harness.llm.logic.SsrfCallbackLogic;
import com.harness.llm.logic.SstiPayloadLogic;
import com.harness.llm.logic.UrlIdentifierDiff;
import com.harness.llm.logic.WorkflowReplayLogic;
import com.harness.llm.logic.XssPayloadLogic;
import com.harness.llm.logic.XxeCollaboratorLogic;
import com.harness.llm.model.AnalysisModels.TestPlan;
import com.harness.llm.model.AnalysisModels.ValidationSubmission;

import javax.swing.*;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.function.BiConsumer;

/**
 * Typed, policy-aware Burp execution plane. Each capability has its own
 * narrowly-scoped executor; there is deliberately no generic "mutate this
 * request" path controlled by model output.
 */
public final class ValidationExecutor {
    private static final int MAX_BURST = 5;
    private final MontoyaApi api;
    private final HarnessClient client;
    private final Map<String, HttpRequestResponse> sources = new ConcurrentHashMap<>();
    private final Map<String, HttpRequestResponse> exchangePool = new ConcurrentHashMap<>();

    public ValidationExecutor(MontoyaApi api, HarnessClient client) {
        this.api = api;
        this.client = client;
    }

    public void registerExchange(HttpRequestResponse rr) {
        if (rr == null) return;
        try { exchangePool.put(exchangeFingerprint(rr), rr); } catch (Exception ignored) {}
    }

    public void registerSources(HttpRequestResponse rr, Iterable<TestPlan> plans) {
        registerExchange(rr);
        for (TestPlan plan : plans) if (plan != null && plan.id != null) sources.put(plan.id, rr);
    }

    public void execute(TestPlan plan, BiConsumer<String, String> onComplete) {
        if (plan == null || plan.id == null) { onComplete.accept("ERROR", "No test plan supplied."); return; }
        HttpRequestResponse source = sources.get(plan.id);
        if (source == null) { onComplete.accept("ERROR", "Captured exchange is no longer available."); return; }
        if (!"burp".equalsIgnoreCase(plan.execution_plane)) { onComplete.accept("ERROR", "Plan is not assigned to Burp."); return; }
        if (!source.request().isInScope()) { submit(plan, source, "rejected", 0, false, "Request is outside Burp's configured scope.", ""); onComplete.accept("REJECTED", "Out-of-scope request refused."); return; }
        if (!exchangeFingerprint(source).equals(plan.source_exchange_hash)) { onComplete.accept("REJECTED", "Source request fingerprint does not match the plan."); return; }

        new SwingWorker<Void, Void>() {
            @Override protected Void doInBackground() {
                try {
                    switch (plan.capability) {
                        case "reflection_context_validation" -> reflection(plan, source);
                        case "bounded_rate_limit_probe" -> rateLimit(plan, source);
                        case "workflow_replay_compare" -> workflowReplay(plan, source);
                        case "authorization_boundary_compare", "cross_identity_compare" -> identityCompare(plan, source);
                        case "controlled_callback_probe" -> controlledCallbackProbe(plan, source);
                        case "session_fixation_compare" -> sessionFixationCompare(plan, source);
                        case "logout_invalidation_compare" -> logoutInvalidationCompare(plan, source);
                        case "csp_clickjacking_validation" -> cspClickjacking(plan, source);
                        case "info_disclosure_scan" -> infoDisclosureScan(plan, source);
                        case "cors_misconfiguration_detection" -> corsMisconfig(plan, source);
                        case "open_redirect_validation" -> openRedirect(plan, source);
                        case "jwt_validation" -> jwtForgery(plan, source);
                        case "xxe_validation" -> xxeValidation(plan, source);
                        case "csrf_validation" -> csrfValidation(plan, source);
                        case "ssti_validation" -> sstiValidation(plan, source);
                        case "deserialization_format_confirmation" -> deserializationFormatScan(plan, source);
                        case "command_injection_validation" -> commandInjectionTiming(plan, source);
                        case "race_condition_validation" -> raceConditionBurst(plan, source);
                        case "header_injection_validation" -> headerInjection(plan, source);
                        case "api_security_validation" -> apiSecurityMassAssignment(plan, source);
                        case "file_upload_validation" -> fileUploadEicarProbe(plan, source);
                        case "crypto_transport_validation" -> cryptoTransport(plan, source);
                        case "http_request_smuggling_detection" -> httpRequestSmuggling(plan, source);
                        case "nosql_validation" -> nosqlInjection(plan, source);
                        case "oauth_flow_validation" -> oauthFlow(plan, source);
                        case "sql_injection_validation" -> sqlInjection(plan, source);
                        case "subdomain_takeover_detection" -> subdomainTakeover(plan, source);
                        case "web_cache_poisoning_detection" -> webCachePoisoning(plan, source);
                        case "websocket_cswsh_validation" -> websocketCswsh(plan, source);
                        default -> submit(plan, source, "inconclusive", 0, false, "No typed executor exists for capability '"+plan.capability+"'.", "");
                    }
                } catch (Exception e) {
                    Outcome o=new Outcome(); o.status="error"; o.detail="Validation failed: "+e.getMessage();
                    outcomes.put(plan.id, o);
                    submit(plan, source, o.status, 0, false, o.detail, "");
                }
                return null;
            }
            @Override protected void done() { Outcome o=outcomes.remove(plan.id); if(o==null)o=new Outcome(); onComplete.accept(o.status.toUpperCase(Locale.ROOT), o.detail); }
        }.execute();
    }

    /**
     * v4.11. Was a single fixed alnum canary checked for bare substring
     * presence -- proved only that text echoes, never that HTML/JS-
     * breaking characters survive unescaped (a response that safely
     * HTML-encodes everything could still report "supported, 0.86").
     * Now loops through XssPayloadLogic.PAYLOADS (weakest-signal-last),
     * per mutable parameter, stopping at the first CONFIRMED result --
     * this is the retry-with-a-new-payload loop, bounded by the payload
     * library's own size (4) times the number of mutable parameters, so
     * there's no unbounded retry risk. No LLM is in this loop at all
     * (unlike the Python-side retry_policy.py this mirrors), so there is
     * no "escalate to a stronger model" step here -- each retry is a live
     * HTTP probe, not a judgment call, which is a stronger kind of check
     * to begin with; the closest analog to "handover" is that a SUPPORTED
     * (partial signal: something echoed, breakout didn't survive) is
     * exactly the caveat-attached status an analyst should look at
     * manually, same as before.
     */
    private void reflection(TestPlan plan, HttpRequestResponse source) {
        HttpRequest req = source.request();
        List<HttpParameter> targets = new ArrayList<>();
        for (var p : req.parameters()) {
            if (p.type() == HttpParameterType.COOKIE) continue;
            targets.add(p);
        }
        if (targets.isEmpty()) {
            submit(plan, source, "inconclusive", 0, false,
                    "No mutable URL/body parameter was available for reflection validation.", "");
            return;
        }

        XssPayloadLogic.Verdict best = XssPayloadLogic.Verdict.REJECTED;
        String bestDetail = "";
        HttpParameter bestParam = null;
        XssPayloadLogic.Payload bestPayload = null;

        outer:
        for (HttpParameter param : targets) {
            List<String> tried = new ArrayList<>();
            XssPayloadLogic.Payload payload;
            while ((payload = XssPayloadLogic.nextPayload(tried)) != null) {
                tried.add(payload.template());
                String canary = "LLMHARNESS_" + UUID.randomUUID().toString().replace("-", "").substring(0, 12);
                String rendered = payload.render(canary);
                var rr = api.http().sendRequest(req.withParameter(HttpParameter.parameter(param.name(), rendered, param.type())));
                String body = rr.response() == null ? "" : rr.response().bodyToString();
                XssPayloadLogic.Verdict v = XssPayloadLogic.classify(payload, canary, body);
                if (v == XssPayloadLogic.Verdict.CONFIRMED) {
                    best = v; bestParam = param; bestPayload = payload;
                    bestDetail = "param=" + param.name() + " payload=" + payload.template();
                    break outer;
                }
                if (v == XssPayloadLogic.Verdict.SUPPORTED && best != XssPayloadLogic.Verdict.SUPPORTED) {
                    best = v; bestParam = param; bestPayload = payload;
                    bestDetail = "param=" + param.name() + " payload=" + payload.template();
                    // keep trying other payloads on this param, and other params -- a SUPPORTED here
                    // doesn't stop the search for a CONFIRMED elsewhere, unlike CONFIRMED itself.
                }
            }
        }

        switch (best) {
            case CONFIRMED -> statusFor(plan, source, "confirmed", 0.9, true,
                    "The injected payload, unique canary included, came back unescaped where it executes ("
                            + bestPayload.context() + ") for parameter '" + bestParam.name() + "'.",
                    bestDetail);
            case SUPPORTED -> statusFor(plan, source, "supported", 0.6, false,
                    "Content was reflected for parameter '" + bestParam.name() + "' but no breakout payload came back "
                            + "unescaped in an executable context across " + XssPayloadLogic.PAYLOADS.size() + " tried -- this does not by itself "
                            + "prove executable XSS.", bestDetail);
            default -> statusFor(plan, source, "rejected", 0.72, false,
                    "No reflection was observed for any of " + XssPayloadLogic.PAYLOADS.size()
                            + " payloads across " + targets.size() + " parameter(s).", "");
        }
    }

    private void rateLimit(TestPlan plan, HttpRequestResponse source) {
        long start=System.nanoTime(); int throttled=0; List<Integer> statuses=new ArrayList<>();
        for(int i=0;i<MAX_BURST;i++) {
            var rr=api.http().sendRequest(source.request());
            int code=rr.response()==null?0:rr.response().statusCode(); statuses.add(code);
            if(code==429 || code==503) throttled++;
        }
        double sec=(System.nanoTime()-start)/1_000_000_000.0;
        if(throttled>0) statusFor(plan,source,"supported",0.82,false,"The bounded probe triggered throttling on "+throttled+"/"+MAX_BURST+" requests.","statuses="+statuses+", duration="+String.format(Locale.ROOT,"%.2fs",sec));
        else statusFor(plan,source,"inconclusive",0.55,false,"No throttling response was observed in the bounded probe.","Absence of throttling in five requests is not proof of a rate-limit vulnerability.");
    }

    /**
     * v4.1 correction. The v4 version of this method confirmed IDOR/authz
     * findings whenever two different captured identities received a
     * similar response for the *same URL* -- which cannot distinguish a
     * real authorization failure from a resource that is simply public
     * (a homepage, a public listing). See IdentityCompareLogic's class
     * doc for the full rationale; this method's job is only to gather
     * the four HTTP observations that logic needs and hand off the
     * decision to it, rather than deciding here.
     *
     * For "cross_identity_compare" (object-level IDOR), the candidate
     * must reference a *different* object identifier than the source
     * (found via UrlIdentifierDiff) and the "attempt" is identity A's
     * session replayed with that identifier swapped in. For
     * "authorization_boundary_compare" (no identifier to swap -- e.g.
     * a low-privilege user hitting an admin-only URL) the candidate
     * must share the *same* URL, and the "attempt" is simply identity
     * A's own request replayed as-is.
     */
    private void identityCompare(TestPlan plan, HttpRequestResponse source) {
        identityCompareInternal(plan, source, null);
    }

    /**
     * Headless entry point: resolve the candidate by fingerprint instead of
     * prompting. A null fingerprint falls through to the dialog (identical
     * to identityCompare(plan, source) above); a non-null fingerprint with
     * no exchangePool match is its own distinct "inconclusive" outcome, not
     * silently treated as "no explicit candidate supplied".
     */
    public void identityCompare(TestPlan plan, HttpRequestResponse source, String candidateFingerprint) {
        if (candidateFingerprint == null) { identityCompareInternal(plan, source, null); return; }
        HttpRequestResponse explicit = exchangePool.get(candidateFingerprint);
        if (explicit == null) {
            statusFor(plan, source, "inconclusive", 0, false,
                    "No captured exchange in the pool matches the supplied candidate fingerprint '" + candidateFingerprint + "'.", "");
            return;
        }
        identityCompareInternal(plan, source, explicit);
    }

    /** Headless entry point for a caller that already holds the candidate HttpRequestResponse. */
    public void identityCompare(TestPlan plan, HttpRequestResponse source, HttpRequestResponse explicitCandidate) {
        identityCompareInternal(plan, source, explicitCandidate);
    }

    private void identityCompareInternal(TestPlan plan, HttpRequestResponse source, HttpRequestResponse explicitCandidate) {
        boolean isIdor = "cross_identity_compare".equals(plan.capability);

        IdentityCandidateResolver.Resolution r =
                IdentityCandidateResolver.resolve(source, exchangePool, isIdor, explicitCandidate);

        HttpRequestResponse candidate;
        UrlIdentifierDiff.Diff diff;
        switch (r.outcome) {
            case NO_CANDIDATES -> {
                String need = isIdor
                        ? "No second captured request referencing a different object identifier for the same endpoint shape is available. Capture the same operation for a second identity with a different object id and retry."
                        : "No second captured request for the same URL from a different identity is available. Capture the same operation as a second identity and retry.";
                statusFor(plan, source, "inconclusive", 0, false, need, "");
                return;
            }
            case NEEDS_PICKER -> {
                List<HttpRequestResponse> candidates = r.pickerCandidates;
                List<UrlIdentifierDiff.Diff> diffs = r.pickerDiffs;

                String host = netloc(source.request().url());
                Map<String, String> sessionLabelsByFingerprint = fetchSessionLookup(host);

                String[] labels = new String[candidates.size()];
                for (int i = 0; i < candidates.size(); i++) {
                    HttpRequestResponse rr = candidates.get(i);
                    String fullFingerprint = exchangeFingerprint(rr);
                    labels[i] = IdentityLabelResolver.labelFor(
                            rr.request().method(), rr.request().url(), fullFingerprint.substring(0, 8),
                            fullFingerprint, sessionLabelsByFingerprint);
                }
                final int[] selected = {-1};
                try {
                    selected[0] = JOptionPane.showOptionDialog(null,
                            "Select the captured request made as the comparison identity (identity B).\n\n" +
                                    "This assertion is analyst-controlled; the harness will not invent credentials or session state.",
                            "Select comparison identity", JOptionPane.DEFAULT_OPTION, JOptionPane.PLAIN_MESSAGE, null, labels, labels[0]);
                } catch (Exception e) {
                    statusFor(plan, source, "inconclusive", 0, false, "No comparison identity was selected.", "");
                    return;
                }
                if (selected[0] < 0) { statusFor(plan, source, "inconclusive", 0, false, "Comparison cancelled.", ""); return; }

                candidate = candidates.get(selected[0]);
                diff = diffs.get(selected[0]);
            }
            default -> { // RESOLVED
                candidate = r.candidate;
                diff = r.diff;
            }
        }

        var sourceReplay = api.http().sendRequest(source.request());
        var candidateReplay = api.http().sendRequest(candidate.request());
        if (sourceReplay.response() == null || candidateReplay.response() == null) {
            statusFor(plan, source, "inconclusive", 0, false, "One baseline request returned no response.", "");
            return;
        }

        HttpRequest attemptReq = (isIdor && diff != null) ? applyIdentifierSwap(source.request(), diff) : source.request();
        var attemptResp = api.http().sendRequest(attemptReq);
        if (attemptResp.response() == null) {
            statusFor(plan, source, "inconclusive", 0, false, "The cross-identity attempt request returned no response.", "");
            return;
        }

        HttpRequestResponse anonResp = null;
        try {
            HttpRequest anonReq = stripIdentityHeaders(attemptReq);
            anonResp = api.http().sendRequest(anonReq);
        } catch (Exception ignored) {}

        IdentityCompareLogic.Probe sourceProbe = toProbe(sourceReplay);
        IdentityCompareLogic.Probe candidateProbe = toProbe(candidateReplay);
        IdentityCompareLogic.Probe attemptProbe = toProbe(attemptResp);
        IdentityCompareLogic.Probe anonProbe = (anonResp == null || anonResp.response() == null) ? null : toProbe(anonResp);

        boolean identifierChanged = !isIdor || diff != null;
        IdentityCompareLogic.Evidence ev = IdentityCompareLogic.evaluate(
                plan.capability, identifierChanged, sourceProbe, candidateProbe, attemptProbe, anonProbe);

        String status = ev.confirmed ? "confirmed" : ev.verdict.name().toLowerCase(Locale.ROOT);
        statusFor(plan, source, status, ev.confidence, ev.confirmed, ev.summary, ev.detail);
    }

    /**
     * Session fixation: compares a session cookie's value across a
     * pre-login and post-login exchange picked from the exchange pool.
     * No live replay needed -- both observations are already-captured
     * responses, so this is a pure comparison, unlike the other
     * capabilities in this file which send fresh requests.
     *
     * Cookie-name matching is a heuristic: common session-cookie name
     * patterns are tried first (session/sid/token/auth-shaped names,
     * plus the well-known framework defaults), falling back to any
     * cookie name present in both exchanges' Set-Cookie headers if no
     * pattern match is found. This can pick the wrong cookie on an
     * app with multiple stateful cookies -- the plan's raw detail
     * output includes which cookie name was actually compared, so a
     * wrong pick is visible and correctable, not silently wrong.
     */
    private void sessionFixationCompare(TestPlan plan, HttpRequestResponse source) {
        sessionFixationCompareInternal(plan, source, null);
    }

    /** Headless entry point: resolve the candidate by fingerprint instead of
     * prompting. Null falls through to the dialog; a non-null fingerprint
     * with no exchangePool match is its own distinct "inconclusive". */
    public void sessionFixationCompare(TestPlan plan, HttpRequestResponse source, String candidateFingerprint) {
        if (candidateFingerprint == null) { sessionFixationCompareInternal(plan, source, null); return; }
        HttpRequestResponse explicit = exchangePool.get(candidateFingerprint);
        if (explicit == null) {
            statusFor(plan, source, "inconclusive", 0, false,
                    "No captured exchange in the pool matches the supplied candidate fingerprint '" + candidateFingerprint + "'.", "");
            return;
        }
        sessionFixationCompareInternal(plan, source, explicit);
    }

    private void sessionFixationCompareInternal(TestPlan plan, HttpRequestResponse source, HttpRequestResponse explicitCandidate) {
        PoolCandidateResolver.Resolution r = PoolCandidateResolver.resolve(
                source, exchangePool,
                rr -> { try { return !extractSetCookiePairs(rr).isEmpty(); } catch (Exception e) { return false; } },
                explicitCandidate);

        HttpRequestResponse candidate;
        switch (r.outcome) {
            case NO_CANDIDATES -> {
                statusFor(plan, source, "inconclusive", 0, false,
                        "No other captured exchange with a Set-Cookie header is available to compare against. "
                                + "Capture the pre-login response (the one that first sets the session cookie) and retry.", "");
                return;
            }
            case NEEDS_PICKER -> {
                List<HttpRequestResponse> candidates = r.pickerCandidates;
                String[] labels = new String[candidates.size()];
                for (int i = 0; i < candidates.size(); i++) {
                    HttpRequestResponse rr = candidates.get(i);
                    labels[i] = rr.request().method() + " " + rr.request().url() + " [" + exchangeFingerprint(rr).substring(0, 8) + "]";
                }
                int selected;
                try {
                    selected = JOptionPane.showOptionDialog(null,
                            "Select the OTHER captured exchange to compare session cookies against\n"
                                    + "(pick the pre-login response if 'source' is post-login, or vice versa).\n\n"
                                    + "This assertion is analyst-controlled; the harness will not guess which is which.",
                            "Select comparison exchange", JOptionPane.DEFAULT_OPTION, JOptionPane.PLAIN_MESSAGE, null, labels, labels[0]);
                } catch (Exception e) {
                    statusFor(plan, source, "inconclusive", 0, false, "No comparison exchange was selected.", "");
                    return;
                }
                if (selected < 0) { statusFor(plan, source, "inconclusive", 0, false, "Comparison cancelled.", ""); return; }
                candidate = candidates.get(selected);
            }
            default -> candidate = r.candidate; // RESOLVED
        }

        Map<String, String> sourceCookies = extractSetCookiePairs(source);
        Map<String, String> otherCookies = extractSetCookiePairs(candidate);
        String cookieName = pickSessionCookieName(sourceCookies.keySet(), otherCookies.keySet());
        if (cookieName == null) {
            statusFor(plan, source, "inconclusive", 0, false,
                    "Neither exchange's Set-Cookie headers share a common cookie name to compare.", "");
            return;
        }

        SessionLifecycleLogic.Evidence ev = SessionLifecycleLogic.evaluateSessionFixation(
                sourceCookies.get(cookieName), otherCookies.get(cookieName));
        String fixationStatus = ev.confirmed ? "confirmed" : ev.verdict.name().toLowerCase(Locale.ROOT);
        statusFor(plan, source, fixationStatus, ev.confidence, ev.confirmed, ev.summary,
                "cookieCompared=" + cookieName + " " + ev.detail);
    }

    /**
     * Logout invalidation: the analyst picks the protected-resource
     * exchange (made using the session BEFORE logout) from the pool;
     * this method replays that SAME request (same cookie, unmodified)
     * now that the logout captured in `source` has already happened,
     * and checks whether the old session still works.
     */
    private void logoutInvalidationCompare(TestPlan plan, HttpRequestResponse source) {
        logoutInvalidationCompareInternal(plan, source, null);
    }

    /** Headless entry point: resolve the candidate by fingerprint instead of
     * prompting. Null falls through to the dialog; a non-null fingerprint
     * with no exchangePool match is its own distinct "inconclusive". */
    public void logoutInvalidationCompare(TestPlan plan, HttpRequestResponse source, String candidateFingerprint) {
        if (candidateFingerprint == null) { logoutInvalidationCompareInternal(plan, source, null); return; }
        HttpRequestResponse explicit = exchangePool.get(candidateFingerprint);
        if (explicit == null) {
            statusFor(plan, source, "inconclusive", 0, false,
                    "No captured exchange in the pool matches the supplied candidate fingerprint '" + candidateFingerprint + "'.", "");
            return;
        }
        logoutInvalidationCompareInternal(plan, source, explicit);
    }

    private void logoutInvalidationCompareInternal(TestPlan plan, HttpRequestResponse source, HttpRequestResponse explicitCandidate) {
        PoolCandidateResolver.Resolution r = PoolCandidateResolver.resolve(
                source, exchangePool, rr -> true, explicitCandidate);

        HttpRequestResponse protectedResource;
        switch (r.outcome) {
            case NO_CANDIDATES -> {
                statusFor(plan, source, "inconclusive", 0, false,
                        "No other captured exchange is available. Capture a request to a protected resource "
                                + "made BEFORE this logout, using the same session, and retry.", "");
                return;
            }
            case NEEDS_PICKER -> {
                List<HttpRequestResponse> candidates = r.pickerCandidates;
                String[] labels = new String[candidates.size()];
                for (int i = 0; i < candidates.size(); i++) {
                    HttpRequestResponse rr = candidates.get(i);
                    labels[i] = rr.request().method() + " " + rr.request().url() + " [" + exchangeFingerprint(rr).substring(0, 8) + "]";
                }
                int selected;
                try {
                    selected = JOptionPane.showOptionDialog(null,
                            "Select the pre-logout request to a PROTECTED resource, made with the SAME session "
                                    + "as the logout request being validated.\n\n"
                                    + "This assertion is analyst-controlled; the harness will not guess which request that is.",
                            "Select pre-logout protected request", JOptionPane.DEFAULT_OPTION, JOptionPane.PLAIN_MESSAGE, null, labels, labels[0]);
                } catch (Exception e) {
                    statusFor(plan, source, "inconclusive", 0, false, "No comparison exchange was selected.", "");
                    return;
                }
                if (selected < 0) { statusFor(plan, source, "inconclusive", 0, false, "Comparison cancelled.", ""); return; }
                protectedResource = candidates.get(selected);
            }
            default -> protectedResource = r.candidate; // RESOLVED
        }

        var reuseReplay = api.http().sendRequest(protectedResource.request());
        if (reuseReplay.response() == null) {
            statusFor(plan, source, "inconclusive", 0, false,
                    "Replaying the old session against the protected resource returned no response.", "");
            return;
        }

        HttpRequestResponse anonResp = null;
        try {
            HttpRequest anonReq = stripIdentityHeaders(protectedResource.request());
            anonResp = api.http().sendRequest(anonReq);
        } catch (Exception ignored) {}

        SessionLifecycleLogic.Probe preLogoutProbe =
                new SessionLifecycleLogic.Probe(protectedResource.response().statusCode(), protectedResource.response().bodyToString());
        SessionLifecycleLogic.Probe postLogoutProbe = toSessionProbe(reuseReplay);
        SessionLifecycleLogic.Probe anonProbe = (anonResp == null || anonResp.response() == null) ? null : toSessionProbe(anonResp);

        SessionLifecycleLogic.Evidence ev = SessionLifecycleLogic.evaluateLogoutInvalidation(preLogoutProbe, postLogoutProbe, anonProbe);
        String logoutStatus = ev.confirmed ? "confirmed" : ev.verdict.name().toLowerCase(Locale.ROOT);
        statusFor(plan, source, logoutStatus, ev.confidence, ev.confirmed, ev.summary, ev.detail);
    }

    private static SessionLifecycleLogic.Probe toSessionProbe(HttpRequestResponse rr) {
        int status = rr.response() == null ? 0 : rr.response().statusCode();
        String body = rr.response() == null ? "" : rr.response().bodyToString();
        return new SessionLifecycleLogic.Probe(status, body);
    }

    private static final String[] SESSION_COOKIE_NAME_HINTS = {
            "session", "sess", "sid", "token", "auth",
            "phpsessid", "jsessionid", "connect.sid", "asp.net_sessionid",
    };

    /** Prefer a cookie name matching common session-cookie conventions; fall back to any shared name. */
    private static String pickSessionCookieName(Set<String> namesA, Set<String> namesB) {
        Set<String> shared = new HashSet<>(namesA);
        shared.retainAll(namesB);
        if (shared.isEmpty()) return null;
        for (String hint : SESSION_COOKIE_NAME_HINTS) {
            for (String name : shared) {
                if (name.toLowerCase(Locale.ROOT).contains(hint)) return name;
            }
        }
        return shared.iterator().next();
    }

    /** Parses Set-Cookie response headers into {@code name -> value}, first occurrence wins per name. */
    private static Map<String, String> extractSetCookiePairs(HttpRequestResponse rr) {
        Map<String, String> pairs = new LinkedHashMap<>();
        if (rr == null || rr.response() == null) return pairs;
        for (var header : rr.response().headers()) {
            if (!"Set-Cookie".equalsIgnoreCase(header.name())) continue;
            String value = header.value();
            int semi = value.indexOf(';');
            String nameValue = semi >= 0 ? value.substring(0, semi) : value;
            int eq = nameValue.indexOf('=');
            if (eq <= 0) continue;
            String name = nameValue.substring(0, eq).trim();
            String val = nameValue.substring(eq + 1).trim();
            pairs.putIfAbsent(name, val);
        }
        return pairs;
    }

    private static IdentityCompareLogic.Probe toProbe(HttpRequestResponse rr) {
        int status = rr.response() == null ? 0 : rr.response().statusCode();
        String body = rr.response() == null ? "" : rr.response().bodyToString();
        return new IdentityCompareLogic.Probe(status, body);
    }

    /**
     * Swap the differing identifier (path segment or query value) into
     * {@code req}, keeping req's own headers/cookies/session -- i.e.
     * identity A's own credentials, pointed at identity B's object.
     * Verified against the Montoya API interface source
     * (HttpRequest.withPath / .withParameter) -- these are the same
     * primitives already used elsewhere in this file for the reflection
     * canary (withParameter) -- withPath is new to this method.
     */
    private static HttpRequest applyIdentifierSwap(HttpRequest req, UrlIdentifierDiff.Diff diff) {
        if (diff.isPathDiff()) {
            String path = req.path(); // path including query, per Montoya's HttpRequest#path()
            String query = "";
            int qIdx = path.indexOf('?');
            if (qIdx >= 0) { query = path.substring(qIdx); path = path.substring(0, qIdx); }
            String[] segments = path.split("/", -1);
            int seen = -1;
            for (int i = 0; i < segments.length; i++) {
                if (segments[i].isEmpty()) continue;
                seen++;
                if (seen == diff.pathSegmentIndex) { segments[i] = diff.valueB; break; }
            }
            return req.withPath(String.join("/", segments) + query);
        }
        return req.withParameter(HttpParameter.parameter(diff.queryKey, diff.valueB, HttpParameterType.URL));
    }

    /** Strip session-identifying headers to build an unauthenticated baseline probe. */
    private static HttpRequest stripIdentityHeaders(HttpRequest req) {
        return req.withRemovedHeader("Cookie").withRemovedHeader("Authorization");
    }

    /**
     * v4.9. Replaces the previous placeholder, which called baselineCompare()
     * and always returned "inconclusive" regardless of what happened --
     * see WorkflowReplayLogic's class doc for the full rationale and scope
     * disclosure. This method's job is only to gather the three HTTP
     * observations that logic needs (baseline / boundary / malformed) and
     * hand off the decision to it, matching identityCompare()'s pattern.
     *
     * Targets the first numeric business-logic-shaped parameter found
     * (price/amount/quantity/qty/discount/count/total/balance/value --
     * see WorkflowReplayLogic.isNumericBoundaryCandidateParam). Cookies
     * are skipped, same reasoning as reflection(): mutating session state
     * isn't the point here and risks breaking the request entirely.
     */
    private void workflowReplay(TestPlan plan, HttpRequestResponse source) {
        HttpRequest req = source.request();
        HttpParameter target = null;
        for (var p : req.parameters()) {
            if (p.type() == HttpParameterType.COOKIE) continue;
            if (WorkflowReplayLogic.isNumericBoundaryCandidateParam(p.name()) && isNumeric(p.value())) {
                target = p;
                break;
            }
        }
        if (target == null) {
            statusFor(plan, source, "inconclusive", 0, false,
                    "No numeric business-logic-shaped parameter (price/amount/quantity/qty/discount/count/total/"
                            + "balance/value) with a numeric value was available on this request for "
                            + "workflow_replay_compare.", "");
            return;
        }

        String originalValue = target.value();
        String boundaryValue = boundaryViolationValue(originalValue);
        String malformedValue = "not_a_number";

        var baselineResp = api.http().sendRequest(req);
        var boundaryResp = api.http().sendRequest(
                req.withParameter(HttpParameter.parameter(target.name(), boundaryValue, target.type())));
        var malformedResp = api.http().sendRequest(
                req.withParameter(HttpParameter.parameter(target.name(), malformedValue, target.type())));

        IdentityCompareLogic.Probe baselineProbe = baselineResp.response() == null ? null : toProbe(baselineResp);
        IdentityCompareLogic.Probe boundaryProbe = boundaryResp.response() == null ? null : toProbe(boundaryResp);
        IdentityCompareLogic.Probe malformedProbe = malformedResp.response() == null ? null : toProbe(malformedResp);

        WorkflowReplayLogic.Evidence ev = WorkflowReplayLogic.evaluate(
                target.name(), originalValue, boundaryValue, baselineProbe, boundaryProbe, malformedProbe);

        String status = ev.confirmed ? "confirmed" : ev.verdict.name().toLowerCase(Locale.ROOT);
        statusFor(plan, source, status, ev.confidence, ev.confirmed, ev.summary, ev.detail);
    }

    private static boolean isNumeric(String s) {
        if (s == null) return false;
        try { Double.parseDouble(s.trim()); return true; } catch (Exception e) { return false; }
    }

    /**
     * Builds a value that WorkflowReplayLogic.isGenuineBoundaryViolation
     * will accept as a real boundary case: negate non-negative values
     * (scaled up so a zero/near-zero original doesn't produce -0.0, which
     * is not "< 0" in Java -- see the isGenuineBoundaryViolation test for
     * this exact edge case), or jump three orders of magnitude for values
     * that are already negative.
     */
    private static String boundaryViolationValue(String originalValue) {
        double v = Double.parseDouble(originalValue.trim());
        double boundary = (v >= 0) ? -Math.max(Math.abs(v), 1.0) * 100 : v * 1000.0;
        if (!Double.isInfinite(boundary) && boundary == Math.rint(boundary) && Math.abs(boundary) < 1e15) {
            return Long.toString((long) boundary);
        }
        return Double.toString(boundary);
    }

    /**
     * v4.9. New capability -- the v4.6 handover explicitly flagged this as
     * having zero case in the switch statement despite planner.py already
     * generating plans for it. See SsrfCallbackLogic's class doc for the
     * full design rationale (why Collaborator, why no weaker fallback).
     *
     * Requires Burp Suite Professional with a Collaborator server
     * configured; degrades to an honest "inconclusive, here's why" status
     * rather than a crash or a fabricated result when it isn't available.
     */
    private void controlledCallbackProbe(TestPlan plan, HttpRequestResponse source) {
        HttpRequest req = source.request();
        List<HttpParameter> candidates = new ArrayList<>();
        for (var p : req.parameters()) {
            if (p.type() == HttpParameterType.COOKIE) continue;
            if (SsrfCallbackLogic.isCallbackCandidateParam(p.name())) {
                candidates.add(p);
                if (candidates.size() >= 3) break; // bounded, same spirit as MAX_BURST elsewhere in this file
            }
        }
        if (candidates.isEmpty()) {
            SsrfCallbackLogic.Evidence ev = SsrfCallbackLogic.evaluate(List.of());
            statusFor(plan, source, ev.verdict.name().toLowerCase(Locale.ROOT), ev.confidence, ev.confirmed, ev.summary, ev.detail);
            return;
        }

        CollaboratorClient client;
        List<CollaboratorPayload> payloads = new ArrayList<>();
        try {
            client = api.collaborator().createClient();
            // generatePayload() is documented to throw IllegalStateException
            // if Collaborator is disabled -- this is the real availability
            // check, not createClient() itself.
            for (int i = 0; i < candidates.size(); i++) payloads.add(client.generatePayload());
        } catch (IllegalStateException e) {
            statusFor(plan, source, "inconclusive", 0, false,
                    "Burp Collaborator is unavailable (requires Burp Suite Professional with a Collaborator server "
                            + "configured) -- controlled_callback_probe cannot run. " + e.getMessage(), "");
            return;
        } catch (Exception e) {
            statusFor(plan, source, "error", 0, false, "Could not initialize Burp Collaborator: " + e.getMessage(), "");
            return;
        }

        for (int i = 0; i < candidates.size(); i++) {
            HttpParameter p = candidates.get(i);
            String calloutUrl = "http://" + payloads.get(i) + "/";
            try {
                api.http().sendRequest(req.withParameter(HttpParameter.parameter(p.name(), calloutUrl, p.type())));
            } catch (Exception ignored) {}
        }

        // Bounded poll -- interactions can take a few seconds to register
        // server-side, so a single immediate check (the pattern used
        // elsewhere in this file, e.g. rateLimit()) would produce false
        // negatives here specifically. Polls up to ~10s total, exits as
        // soon as any candidate has a hit.
        List<SsrfCallbackLogic.CallbackAttempt> attempts = buildAttempts(candidates, payloads, client);
        for (int round = 0; round < 5 && attempts.stream().noneMatch(a -> !a.interactionTypes.isEmpty()); round++) {
            try { Thread.sleep(2000); } catch (InterruptedException ie) { Thread.currentThread().interrupt(); break; }
            attempts = buildAttempts(candidates, payloads, client);
        }

        SsrfCallbackLogic.Evidence ev = SsrfCallbackLogic.evaluate(attempts);
        String status = ev.confirmed ? "confirmed" : ev.verdict.name().toLowerCase(Locale.ROOT);
        statusFor(plan, source, status, ev.confidence, ev.confirmed, ev.summary, ev.detail);
    }

    private static List<SsrfCallbackLogic.CallbackAttempt> buildAttempts(
            List<HttpParameter> candidates, List<CollaboratorPayload> payloads, CollaboratorClient client) {
        List<SsrfCallbackLogic.CallbackAttempt> out = new ArrayList<>();
        for (int i = 0; i < candidates.size(); i++) {
            String token = payloads.get(i).toString();
            out.add(new SsrfCallbackLogic.CallbackAttempt(candidates.get(i).name(), token, interactionTypesFor(client, token)));
        }
        return out;
    }

    /** The one-line "get interaction types for this token" computation shared
     * by every Collaborator-based capability -- extracted so it's stated once,
     * not copy-pasted, even though each caller's own retry/poll SHAPE differs
     * (SSRF polls across several candidate tokens per round; XXE below polls
     * a single token). */
    private static List<String> interactionTypesFor(CollaboratorClient client, String token) {
        return client.getInteractions(InteractionFilter.interactionPayloadFilter(token))
                .stream().map(h -> h.type().name()).distinct().toList();
    }

    /** Bounded poll for a single Collaborator payload token -- same reasoning
     * and same 5x2s bound as controlledCallbackProbe's own poll above
     * (interactions can take a few seconds to register server-side, so a
     * single immediate check produces false negatives). Found live: xxeValidation
     * originally checked exactly once with zero wait, unlike this identical
     * underlying mechanism used for SSRF -- a likely source of false
     * INCONCLUSIVE verdicts for XXE specifically. */
    private static List<String> pollInteractionTypes(CollaboratorClient client, String token) {
        List<String> types = interactionTypesFor(client, token);
        for (int round = 0; round < 5 && types.isEmpty(); round++) {
            try { Thread.sleep(2000); } catch (InterruptedException ie) { Thread.currentThread().interrupt(); break; }
            types = interactionTypesFor(client, token);
        }
        return types;
    }

    private static final class Outcome { String status="inconclusive"; String detail=""; }
    private final Map<String, Outcome> outcomes = new ConcurrentHashMap<>();
    private void statusFor(TestPlan p,HttpRequestResponse s,String st,double conf,boolean confirmed,String summary,String evidence){ Outcome o=new Outcome(); o.status=st; o.detail=summary; outcomes.put(p.id,o); submit(p,s,st,conf,confirmed,summary,evidence); }

    // ---------------------------------------------------------------
    // csp_clickjacking_validation -- passive, no new request. Classifies
    // the response Burp already captured; see CspClickjackingLogic.
    // ---------------------------------------------------------------
    private void cspClickjacking(TestPlan plan, HttpRequestResponse source) {
        var resp = source.response();
        if (resp == null) {
            statusFor(plan, source, "inconclusive", 0, false, "No response was captured for this exchange.", "");
            return;
        }
        String contentType = resp.headerValue("Content-Type");
        String xfo = resp.headerValue("X-Frame-Options");
        String csp = resp.headerValue("Content-Security-Policy");
        CspClickjackingLogic.Evidence ev = CspClickjackingLogic.evaluate(contentType, xfo, csp);
        statusFor(plan, source, ev.verdict().name().toLowerCase(Locale.ROOT), ev.confidence(), ev.confirmed(), ev.summary(), ev.detail());
    }

    // ---------------------------------------------------------------
    // info_disclosure_scan -- passive, no new request. Classifies the
    // response body Burp already captured; see InfoDisclosureLogic.
    // ---------------------------------------------------------------
    private void infoDisclosureScan(TestPlan plan, HttpRequestResponse source) {
        var resp = source.response();
        String body = resp == null ? null : resp.bodyToString();
        InfoDisclosureLogic.Evidence ev = InfoDisclosureLogic.evaluate(body);
        statusFor(plan, source, ev.verdict().name().toLowerCase(Locale.ROOT), ev.confidence(), ev.confirmed(), ev.summary(), ev.detail());
    }

    // ---------------------------------------------------------------
    // cors_misconfiguration_detection -- adds a foreign Origin header to
    // the captured request and resends once; see CorsMisconfigLogic.
    // ---------------------------------------------------------------
    private static final String CORS_PROBE_ORIGIN = "https://evil-harness-probe.example";

    private void corsMisconfig(TestPlan plan, HttpRequestResponse source) {
        HttpRequest req = source.request();
        HttpRequest probeReq = req.withUpdatedHeader("Origin", CORS_PROBE_ORIGIN);
        var rr = api.http().sendRequest(probeReq);
        var resp = rr.response();
        if (resp == null) {
            statusFor(plan, source, "inconclusive", 0, false, "No response was received for the CORS probe request.", "");
            return;
        }
        String acao = resp.headerValue("Access-Control-Allow-Origin");
        String acac = resp.headerValue("Access-Control-Allow-Credentials");
        CorsMisconfigLogic.Evidence ev = CorsMisconfigLogic.evaluate(CORS_PROBE_ORIGIN, acao, acac);
        statusFor(plan, source, ev.verdict().name().toLowerCase(Locale.ROOT), ev.confidence(), ev.confirmed(), ev.summary(), ev.detail());
    }

    // ---------------------------------------------------------------
    // open_redirect_validation -- reuses SsrfCallbackLogic's URL/redirect
    // -shaped parameter name heuristic (SSRF and open redirect target
    // near-identically-named parameters) rather than duplicating it.
    // See OpenRedirectLogic.
    // ---------------------------------------------------------------
    private static final String OPEN_REDIRECT_PROBE_URL = "https://harness-redirect-probe.example/proof";

    private void openRedirect(TestPlan plan, HttpRequestResponse source) {
        HttpRequest req = source.request();
        HttpParameter target = null;
        for (var p : req.parameters()) {
            if (p.type() == HttpParameterType.COOKIE) continue;
            if (SsrfCallbackLogic.isCallbackCandidateParam(p.name())) { target = p; break; }
        }
        if (target == null) {
            statusFor(plan, source, "invalid", 0, false,
                    "No URL/redirect-shaped parameter was available on this request for open_redirect_validation to target.", "");
            return;
        }
        var rr = api.http().sendRequest(req.withParameter(HttpParameter.parameter(target.name(), OPEN_REDIRECT_PROBE_URL, target.type())));
        var resp = rr.response();
        if (resp == null) {
            statusFor(plan, source, "inconclusive", 0, false, "No response was received for the open redirect probe request.", "");
            return;
        }
        String location = resp.headerValue("Location");
        OpenRedirectLogic.Evidence ev = OpenRedirectLogic.evaluate(OPEN_REDIRECT_PROBE_URL, resp.statusCode(), location, target.name());
        statusFor(plan, source, ev.verdict().name().toLowerCase(Locale.ROOT), ev.confidence(), ev.confirmed(), ev.summary(), ev.detail());
    }

    // ---------------------------------------------------------------
    // header_injection_validation -- CRLF/HTTP response-header
    // injection. Appends %0d%0a (the transport-safe ENCODED form -- a
    // literal \r\n placed directly into an HttpParameter's value would
    // either get percent-encoded by Montoya before it ever reaches the
    // wire, or break the request Burp sends outright; real attackers
    // send the encoded form for exactly this reason, relying on the
    // TARGET SERVER's own decode-then-reflect code to be what
    // reintroduces the raw newline unsanitized) plus a harness-chosen
    // marker header to the same URL/redirect-shaped parameter
    // open_redirect_validation targets -- see HeaderInjectionLogic's
    // class doc for why that heuristic is reused rather than duplicated.
    // ---------------------------------------------------------------
    private static final String HEADER_INJECTION_MARKER_NAME = "X-Harness-Crlf-Test";
    private static final String HEADER_INJECTION_MARKER_VALUE = "injected-12345";

    private void headerInjection(TestPlan plan, HttpRequestResponse source) {
        HttpRequest req = source.request();
        HttpParameter target = null;
        for (var p : req.parameters()) {
            if (p.type() == HttpParameterType.COOKIE) continue;
            if (SsrfCallbackLogic.isCallbackCandidateParam(p.name())) { target = p; break; }
        }
        if (target == null) {
            statusFor(plan, source, "invalid", 0, false,
                    "No URL/redirect-shaped parameter was available on this request for header_injection_validation to target.", "");
            return;
        }
        boolean baselineHasMarker = source.response() != null && source.response().headerValue(HEADER_INJECTION_MARKER_NAME) != null;
        String payloadValue = HeaderInjectionLogic.buildPayload(target.value(), HEADER_INJECTION_MARKER_NAME, HEADER_INJECTION_MARKER_VALUE);
        var rr = api.http().sendRequest(req.withParameter(HttpParameter.parameter(target.name(), payloadValue, target.type())));
        var resp = rr.response();
        if (resp == null) {
            statusFor(plan, source, "inconclusive", 0, false, "No response was received for the header injection probe request.", "");
            return;
        }
        String mutatedMarkerValue = resp.headerValue(HEADER_INJECTION_MARKER_NAME);
        HeaderInjectionLogic.Evidence ev = HeaderInjectionLogic.evaluate(
                target.name(), HEADER_INJECTION_MARKER_NAME, HEADER_INJECTION_MARKER_VALUE, baselineHasMarker, mutatedMarkerValue);
        statusFor(plan, source, ev.verdict().name().toLowerCase(Locale.ROOT), ev.confidence(), ev.confirmed(), ev.summary(), ev.detail());
    }

    // ---------------------------------------------------------------
    // api_security_validation -- mass-assignment probe. Directly
    // implements the api_security agent's own suggested_test: resend a
    // create/update request with an extra unrequested field ("role":
    // "admin") added to the JSON body, then read the resource back to
    // see whether the field was stored. See MassAssignmentLogic.
    // ---------------------------------------------------------------
    private static final String MASS_ASSIGNMENT_FIELD_NAME = "role";
    private static final String MASS_ASSIGNMENT_FIELD_VALUE_JSON = "\"admin\"";

    private void apiSecurityMassAssignment(TestPlan plan, HttpRequestResponse source) {
        HttpRequest req = source.request();
        String method = req.method();
        if (!"POST".equalsIgnoreCase(method) && !"PUT".equalsIgnoreCase(method) && !"PATCH".equalsIgnoreCase(method)) {
            statusFor(plan, source, "invalid", 0, false,
                    "api_security_validation's mass-assignment probe only applies to create/update requests "
                            + "(POST/PUT/PATCH); this request is " + method + ".", "");
            return;
        }
        String originalBody = req.bodyToString();
        boolean fieldAlreadyPresent = originalBody != null && originalBody.contains("\"" + MASS_ASSIGNMENT_FIELD_NAME + "\"");
        String mutatedBody = MassAssignmentLogic.injectField(originalBody, MASS_ASSIGNMENT_FIELD_NAME, MASS_ASSIGNMENT_FIELD_VALUE_JSON);
        if (mutatedBody == null) {
            statusFor(plan, source, "invalid", 0, false,
                    "Request body is not a JSON object ({...}) -- api_security_validation's mass-assignment "
                            + "probe requires an object-shaped body to inject a field into.", "");
            return;
        }
        // Persistence evidence: read the resource before and after the write.
        // An echo of the request in the write's own response proves nothing
        // about what was stored. A create-style write (a POST whose captured
        // response names the object it created, same-origin and not the
        // write path itself) is read back from the created object, not from
        // the collection it was posted to (RV-J residual N3): before, the
        // object the captured request created; after, the one the probe did.
        String writePath = pathOnly(req.path());
        String capturedObject = null;
        if ("POST".equalsIgnoreCase(method) && source.response() != null
                && MassAssignmentLogic.isSuccess(source.response().statusCode())) {
            capturedObject = sameOriginPath(req.url(), MassAssignmentLogic.createdObjectReference(
                    writePath, source.response().headerValue("Location"), source.response().bodyToString()));
            if (capturedObject != null && pathOnly(capturedObject).equals(writePath)) capturedObject = null;
        }
        HttpRequestResponse before = null;
        boolean createStyle = false;
        if (capturedObject != null) {
            before = api.http().sendRequest(readRequest(req, capturedObject));
            createStyle = MassAssignmentLogic.isSuccess(status(before));
        }
        if (!createStyle) before = api.http().sendRequest(readRequest(req, req.path()));
        var rr = api.http().sendRequest(req.withBody(mutatedBody));
        var resp = rr.response();
        if (resp == null) {
            statusFor(plan, source, "inconclusive", 0, false, "No response was received for the mass-assignment probe request.", "");
            return;
        }
        String afterPath = null;
        if (MassAssignmentLogic.isSuccess(resp.statusCode())) {
            afterPath = createStyle
                    ? sameOriginPath(req.url(), MassAssignmentLogic.createdObjectReference(
                            writePath, resp.headerValue("Location"), resp.bodyToString()))
                    : req.path();
        }
        var after = afterPath == null ? null : api.http().sendRequest(readRequest(req, afterPath));
        String readTargets = createStyle
                ? "create-style: read before GET " + capturedObject + " (object the captured request created), read after "
                        + (afterPath == null ? "not sent (the probe's response named no same-origin object)"
                                             : "GET " + afterPath + " (object the probe created)")
                : "read before/after GET " + req.path();
        String baselineResponseBody = source.response() == null ? null : source.response().bodyToString();
        MassAssignmentLogic.Evidence ev = MassAssignmentLogic.evaluate(
                MASS_ASSIGNMENT_FIELD_NAME, MASS_ASSIGNMENT_FIELD_VALUE_JSON, fieldAlreadyPresent,
                baselineResponseBody, resp.statusCode(), resp.bodyToString(),
                status(before), responseBody(before), status(after), responseBody(after), readTargets);
        statusFor(plan, source, ev.verdict().name().toLowerCase(Locale.ROOT), ev.confidence(), ev.confirmed(), ev.summary(), ev.detail());
    }

    // ===============================================================
    // Executors added blind (no JDK on the authoring machine -- hazard #6):
    // these follow the existing "probe (if any) -> pure *Logic.evaluate ->
    // statusFor" pattern exactly, but are UNCOMPILED and UNIT-UNRUN until the
    // maintainer's `gradle shadowJar`. Each delegates its verdict to a
    // Montoya-free Logic class (unit-tested at build time). Safe by
    // construction: no destructive sends; they default to inconclusive/
    // supported/rejected rather than a false CONFIRMED.
    // ===============================================================

    /** Read a request header by name from headers() (request-side headerValue
     * is not used elsewhere in this class, so we avoid depending on it). */
    private static String reqHeader(HttpRequest req, String name) {
        for (HttpHeader h : req.headers()) {
            if (h.name() != null && h.name().equalsIgnoreCase(name)) return h.value();
        }
        return null;
    }

    /** A plain GET of {@code path} with the original request's session
     * headers but none of its body or body-describing headers -- for
     * reading back what a write stored, without repeating the write. */
    private static HttpRequest readRequest(HttpRequest base, String path) {
        return base.withMethod("GET").withPath(path).withBody("")
                .withRemovedHeader("Content-Type").withRemovedHeader("Content-Length");
    }

    /**
     * The path (and query) {@code candidate} names, resolved against
     * {@code requestUrl}, if it is on the same origin -- scheme, host and
     * effective port -- else null. Keeps every read-back on the target the
     * captured request went to.
     */
    static String sameOriginPath(String requestUrl, String candidate) {
        if (requestUrl == null || candidate == null || candidate.isBlank()) return null;
        try {
            URI base = new URI(requestUrl);
            URI target = base.resolve(new URI(candidate.trim()));
            if (base.getHost() == null || target.getHost() == null || target.getScheme() == null) return null;
            if (!target.getScheme().equalsIgnoreCase(base.getScheme())
                    || !target.getHost().equalsIgnoreCase(base.getHost())
                    || effectivePort(target) != effectivePort(base)) return null;
            String path = target.getRawPath() == null || target.getRawPath().isEmpty() ? "/" : target.getRawPath();
            return target.getRawQuery() == null ? path : path + "?" + target.getRawQuery();
        } catch (java.net.URISyntaxException | IllegalArgumentException e) {
            return null;
        }
    }

    private static int effectivePort(URI uri) {
        if (uri.getPort() >= 0) return uri.getPort();
        if ("https".equalsIgnoreCase(uri.getScheme())) return 443;
        if ("http".equalsIgnoreCase(uri.getScheme())) return 80;
        return -1;
    }

    private static String pathOnly(String path) {
        if (path == null) return "";
        int query = path.indexOf('?');
        return query < 0 ? path : path.substring(0, query);
    }

    private static int bodyLen(HttpRequestResponse rr) {
        if (rr == null || rr.response() == null) return 0;
        String b = rr.response().bodyToString();
        return b == null ? 0 : b.length();
    }

    private static int status(HttpRequestResponse rr) {
        return (rr == null || rr.response() == null) ? -1 : rr.response().statusCode();
    }

    private static String responseBody(HttpRequestResponse rr) {
        return (rr == null || rr.response() == null) ? null : rr.response().bodyToString();
    }

    // crypto_transport_validation -- passive; classifies the captured exchange's
    // transport posture (TLS, HSTS, cookie Secure flag). See CryptoTransportLogic.
    private void cryptoTransport(TestPlan plan, HttpRequestResponse source) {
        HttpRequest req = source.request();
        var resp = source.response();
        if (resp == null) {
            statusFor(plan, source, "inconclusive", 0, false, "No response was captured for this exchange.", "");
            return;
        }
        String url = req.url();
        boolean isHttps = url != null && url.toLowerCase(Locale.ROOT).startsWith("https:");
        String hsts = resp.headerValue("Strict-Transport-Security");
        List<String> setCookies = new ArrayList<>();
        for (HttpHeader h : resp.headers()) {
            if (h.name() != null && h.name().equalsIgnoreCase("Set-Cookie")) setCookies.add(h.value());
        }
        boolean carriesAuth = reqHeader(req, "Authorization") != null || reqHeader(req, "Cookie") != null;
        CryptoTransportLogic.Evidence ev = CryptoTransportLogic.evaluate(isHttps, hsts, setCookies, carriesAuth);
        statusFor(plan, source, ev.verdict().name().toLowerCase(Locale.ROOT), ev.confidence(), ev.confirmed(), ev.summary(), ev.detail());
    }

    // http_request_smuggling_detection -- one NON-destructive framing-hygiene
    // probe (adds Transfer-Encoding alongside the existing Content-Length) and
    // reports how the server framed it. See RequestSmugglingLogic.
    private void httpRequestSmuggling(TestPlan plan, HttpRequestResponse source) {
        HttpRequest req = source.request();
        int baseline = status(source);
        int probeStatus;
        boolean errored = false;
        try {
            var rr = api.http().sendRequest(req.withUpdatedHeader("Transfer-Encoding", "chunked"));
            probeStatus = status(rr);
        } catch (Exception e) {
            probeStatus = -1;
            errored = true;
        }
        RequestSmugglingLogic.Evidence ev = RequestSmugglingLogic.evaluate(baseline, probeStatus, errored);
        statusFor(plan, source, ev.verdict().name().toLowerCase(Locale.ROOT), ev.confidence(), ev.confirmed(), ev.summary(), ev.detail());
    }

    // nosql_validation -- inject a NoSQL operator value into a candidate
    // parameter and check for a driver error or an auth/logic flip. See
    // NoSqlInjectionLogic.
    private static final String NOSQL_PAYLOAD = "{\"$ne\":null}";

    private void nosqlInjection(TestPlan plan, HttpRequestResponse source) {
        HttpRequest req = source.request();
        HttpParameter target = null;
        for (var p : req.parameters()) {
            if (p.type() == HttpParameterType.COOKIE) continue;
            target = p;
            break;
        }
        if (target == null) {
            statusFor(plan, source, "invalid", 0, false,
                    "No non-cookie parameter was available for nosql_validation to inject an operator into.", "");
            return;
        }
        int baseline = status(source);
        var rr = api.http().sendRequest(req.withParameter(HttpParameter.parameter(target.name(), NOSQL_PAYLOAD, target.type())));
        var resp = rr.response();
        String injBody = resp == null ? null : resp.bodyToString();
        NoSqlInjectionLogic.Evidence ev = NoSqlInjectionLogic.evaluate(baseline, status(rr), injBody);
        statusFor(plan, source, ev.verdict().name().toLowerCase(Locale.ROOT), ev.confidence(), ev.confirmed(), ev.summary(), ev.detail());
    }

    // oauth_flow_validation -- tamper redirect_uri to an attacker host and check
    // whether the authorize endpoint honours it; also flags a missing state
    // parameter (CSRF). See OAuthFlowLogic.
    private static final String OAUTH_ATTACKER_REDIRECT = "https://harness-oauth-probe.example/cb";

    private void oauthFlow(TestPlan plan, HttpRequestResponse source) {
        HttpRequest req = source.request();
        HttpParameter redirectParam = null;
        boolean hasState = false;
        for (var p : req.parameters()) {
            if (p.type() == HttpParameterType.COOKIE) continue;
            String n = p.name() == null ? "" : p.name().toLowerCase(Locale.ROOT);
            if (n.equals("redirect_uri") || n.equals("redirecturi") || n.equals("redirect")) redirectParam = p;
            if (n.equals("state")) hasState = true;
        }
        if (redirectParam == null) {
            OAuthFlowLogic.Evidence ev = OAuthFlowLogic.evaluate(false, hasState, OAUTH_ATTACKER_REDIRECT, -1, null);
            statusFor(plan, source, ev.verdict().name().toLowerCase(Locale.ROOT), ev.confidence(), ev.confirmed(), ev.summary(), ev.detail());
            return;
        }
        var rr = api.http().sendRequest(req.withParameter(
                HttpParameter.parameter(redirectParam.name(), OAUTH_ATTACKER_REDIRECT, redirectParam.type())));
        var resp = rr.response();
        String loc = resp == null ? null : resp.headerValue("Location");
        OAuthFlowLogic.Evidence ev = OAuthFlowLogic.evaluate(true, hasState, OAUTH_ATTACKER_REDIRECT, status(rr), loc);
        statusFor(plan, source, ev.verdict().name().toLowerCase(Locale.ROOT), ev.confidence(), ev.confirmed(), ev.summary(), ev.detail());
    }

    // sql_injection_validation -- bounded Burp-plane confirmer (sqlmap runs
    // harness-side): a quote error-probe plus an AND 1=1 / AND 1=2 boolean pair.
    // See SqlInjectionLogic.
    private void sqlInjection(TestPlan plan, HttpRequestResponse source) {
        HttpRequest req = source.request();
        HttpParameter target = null;
        for (var p : req.parameters()) {
            if (p.type() == HttpParameterType.COOKIE) continue;
            target = p;
            break;
        }
        if (target == null) {
            statusFor(plan, source, "invalid", 0, false,
                    "No non-cookie parameter was available for sql_injection_validation to target.", "");
            return;
        }
        String base = target.value() == null ? "" : target.value();
        var quoteRr = api.http().sendRequest(req.withParameter(
                HttpParameter.parameter(target.name(), base + "'", target.type())));
        String quoteBody = quoteRr.response() == null ? null : quoteRr.response().bodyToString();
        var trueRr = api.http().sendRequest(req.withParameter(
                HttpParameter.parameter(target.name(), base + "' AND '1'='1", target.type())));
        var falseRr = api.http().sendRequest(req.withParameter(
                HttpParameter.parameter(target.name(), base + "' AND '1'='2", target.type())));
        SqlInjectionLogic.Evidence ev = SqlInjectionLogic.evaluate(
                quoteBody, status(trueRr), bodyLen(trueRr), status(falseRr), bodyLen(falseRr));
        statusFor(plan, source, ev.verdict().name().toLowerCase(Locale.ROOT), ev.confidence(), ev.confirmed(), ev.summary(), ev.detail());
    }

    // subdomain_takeover_detection -- passive; matches the captured response body
    // against unclaimed-third-party-resource fingerprints. See SubdomainTakeoverLogic.
    private void subdomainTakeover(TestPlan plan, HttpRequestResponse source) {
        var resp = source.response();
        String body = resp == null ? null : resp.bodyToString();
        SubdomainTakeoverLogic.Evidence ev = SubdomainTakeoverLogic.evaluate(status(source), body);
        statusFor(plan, source, ev.verdict().name().toLowerCase(Locale.ROOT), ev.confidence(), ev.confirmed(), ev.summary(), ev.detail());
    }

    // web_cache_poisoning_detection -- send an unkeyed-header (X-Forwarded-Host)
    // probe, then a CLEAN follow-up, and check whether the attacker marker was
    // cached and served back. See WebCachePoisoningLogic.
    private static final String CACHE_POISON_HOST = "harness-cache-probe.example";

    private void webCachePoisoning(TestPlan plan, HttpRequestResponse source) {
        HttpRequest req = source.request();
        // 1) poison attempt with an unkeyed header.
        api.http().sendRequest(req.withUpdatedHeader("X-Forwarded-Host", CACHE_POISON_HOST));
        // 2) clean follow-up (does NOT carry the header) -- did the marker persist?
        var rr = api.http().sendRequest(req);
        var resp = rr.response();
        if (resp == null) {
            statusFor(plan, source, "inconclusive", 0, false, "No response was received for the cache-poisoning follow-up.", "");
            return;
        }
        String body = resp.bodyToString();
        boolean reflects = body != null && body.contains(CACHE_POISON_HOST);
        if (!reflects) {
            String loc = resp.headerValue("Location");
            reflects = loc != null && loc.contains(CACHE_POISON_HOST);
        }
        String cacheStatus = resp.headerValue("X-Cache");
        if (cacheStatus == null) cacheStatus = resp.headerValue("CF-Cache-Status");
        String age = resp.headerValue("Age");
        WebCachePoisoningLogic.Evidence ev = WebCachePoisoningLogic.evaluate(
                CACHE_POISON_HOST, reflects, false, cacheStatus, age);
        statusFor(plan, source, ev.verdict().name().toLowerCase(Locale.ROOT), ev.confidence(), ev.confirmed(), ev.summary(), ev.detail());
    }

    // websocket_cswsh_validation -- replay a WebSocket handshake with a foreign
    // Origin; a completed handshake (101) on an authenticated connection is
    // Cross-Site WebSocket Hijacking. See WebsocketCswshLogic.
    private static final String WS_FOREIGN_ORIGIN = "https://evil-harness-probe.example";

    private void websocketCswsh(TestPlan plan, HttpRequestResponse source) {
        HttpRequest req = source.request();
        String upgrade = reqHeader(req, "Upgrade");
        boolean isWs = upgrade != null && upgrade.toLowerCase(Locale.ROOT).contains("websocket");
        if (!isWs) {
            WebsocketCswshLogic.Evidence ev = WebsocketCswshLogic.evaluate(false, false, -1);
            statusFor(plan, source, ev.verdict().name().toLowerCase(Locale.ROOT), ev.confidence(), ev.confirmed(), ev.summary(), ev.detail());
            return;
        }
        boolean carriesAuth = reqHeader(req, "Authorization") != null || reqHeader(req, "Cookie") != null;
        int st;
        try {
            var rr = api.http().sendRequest(req.withUpdatedHeader("Origin", WS_FOREIGN_ORIGIN));
            st = status(rr);
        } catch (Exception e) {
            st = -1;
        }
        WebsocketCswshLogic.Evidence ev = WebsocketCswshLogic.evaluate(true, carriesAuth, st);
        statusFor(plan, source, ev.verdict().name().toLowerCase(Locale.ROOT), ev.confidence(), ev.confirmed(), ev.summary(), ev.detail());
    }

    // ---------------------------------------------------------------
    // jwt_validation -- forges an alg:none variant and a garbled-
    // signature variant of the Authorization bearer token (if present
    // and JWT-shaped) and resends each once, comparing against the
    // original response. See JwtForgeryLogic. Ties directly to the
    // alg:none finding worked through by hand in testing/test-target/
    // earlier this project -- this is that same check, now
    // deterministic instead of requiring a human to reason through it.
    // ---------------------------------------------------------------
    private void jwtForgery(TestPlan plan, HttpRequestResponse source) {
        HttpRequest req = source.request();
        List<Map.Entry<String, String>> headerList = new ArrayList<>();
        for (HttpHeader h : req.headers()) headerList.add(Map.entry(h.name(), h.value() == null ? "" : h.value()));
        JwtForgeryLogic.Carrier carrier = JwtForgeryLogic.findCarrier(headerList);
        if (carrier == null) {
            statusFor(plan, source, "invalid", 0, false,
                    "No JWT was found on this request for jwt_validation to target -- not as an Authorization "
                            + "bearer token, in another header, or in a cookie. jwt_validation only applies to "
                            + "JWTs, not opaque tokens.", "");
            return;
        }
        String originalToken = carrier.token();

        // The probes carry no credential but the token under test, in the
        // carrier it came in (RV-J residual N2): every credential header and
        // the cookie are removed first. Otherwise a session cookie or a
        // second token authenticates the request, and a "forged token
        // accepted" or a "no token" control says nothing about the JWT.
        HttpRequest bare = req;
        Set<String> removed = new LinkedHashSet<>();
        for (HttpHeader h : req.headers()) {
            if (JwtForgeryLogic.isCredentialHeader(h.name(), h.value()) && removed.add(h.name().toLowerCase(Locale.ROOT))) {
                bare = bare.withRemovedHeader(h.name());
            }
        }
        String carried = "token carrier=" + carrier.describe() + " | removed from the probes: "
                + (removed.isEmpty() ? "none" : String.join(", ", removed));

        var originalResp = source.response();
        int originalStatus = originalResp == null ? 0 : originalResp.statusCode();
        int originalLen = originalResp == null ? 0 : originalResp.bodyToString().length();

        // Control, sent at most once and only after a forged token got a 2xx:
        // the same request with no credential at all. If that is answered
        // too, the resource is public and a forged token proves nothing.
        int unauthenticatedStatus = -1;
        boolean controlSent = false;

        String algNone = JwtForgeryLogic.forgeAlgNone(originalToken);
        if (algNone != null) {
            var rr = api.http().sendRequest(bare.withAddedHeader(carrier.headerName(), carrier.headerValue(algNone)));
            var resp = rr.response();
            if (resp != null) {
                if (JwtForgeryLogic.isSuccess(resp.statusCode())) {
                    unauthenticatedStatus = status(api.http().sendRequest(bare));
                    controlSent = true;
                }
                JwtForgeryLogic.Evidence ev = JwtForgeryLogic.evaluate("alg:none", originalStatus, resp.statusCode(), originalLen, resp.bodyToString().length(), unauthenticatedStatus);
                if (ev.verdict() == JwtForgeryLogic.Verdict.CONFIRMED || ev.verdict() == JwtForgeryLogic.Verdict.SUPPORTED
                        || JwtForgeryLogic.isSuccess(unauthenticatedStatus)) {
                    statusFor(plan, source, ev.verdict().name().toLowerCase(Locale.ROOT), ev.confidence(), ev.confirmed(), ev.summary(), ev.detail() + " | " + carried);
                    return;
                }
            }
        }

        String garbled = JwtForgeryLogic.forgeGarbledSignature(originalToken);
        var rr2 = api.http().sendRequest(bare.withAddedHeader(carrier.headerName(), carrier.headerValue(garbled)));
        var resp2 = rr2.response();
        if (resp2 == null) {
            statusFor(plan, source, "inconclusive", 0, false, "No response was received for the garbled-signature probe.", carried);
            return;
        }
        if (JwtForgeryLogic.isSuccess(resp2.statusCode()) && !controlSent) {
            unauthenticatedStatus = status(api.http().sendRequest(bare));
        }
        JwtForgeryLogic.Evidence ev2 = JwtForgeryLogic.evaluate("garbled signature", originalStatus, resp2.statusCode(), originalLen, resp2.bodyToString().length(), unauthenticatedStatus);
        if (!JwtForgeryLogic.isSuccess(resp2.statusCode())) {
            // The probes carried no other credential, so a refusal is about
            // the token only if the original token alone is accepted. That
            // request is the captured one unless other credentials were removed.
            HttpRequest tokenAlone = bare.withAddedHeader(carrier.headerName(), carrier.headerValue(originalToken));
            int tokenAloneStatus = sameHeaders(tokenAlone, req) ? originalStatus : status(api.http().sendRequest(tokenAlone));
            ev2 = JwtForgeryLogic.requireTokenAloneAccepted(ev2, tokenAloneStatus);
        }
        statusFor(plan, source, ev2.verdict().name().toLowerCase(Locale.ROOT), ev2.confidence(), ev2.confirmed(), ev2.summary(), ev2.detail() + " | " + carried);
    }

    /** True if both requests carry the same headers and values, in any order and any name case. */
    private static boolean sameHeaders(HttpRequest a, HttpRequest b) {
        return headerSet(a).equals(headerSet(b));
    }

    private static List<String> headerSet(HttpRequest r) {
        List<String> out = new ArrayList<>();
        for (HttpHeader h : r.headers()) out.add(h.name().toLowerCase(Locale.ROOT) + ": " + h.value());
        java.util.Collections.sort(out);
        return out;
    }

    // ---------------------------------------------------------------
    // xxe_validation -- reuses the Collaborator infrastructure already
    // built for controlled_callback_probe; the mechanism (an out-of-
    // band interaction) is identical, only the injection point differs
    // (an XML external entity in the body, not a URL-shaped parameter).
    // See XxeCollaboratorLogic.
    // ---------------------------------------------------------------
    private void xxeValidation(TestPlan plan, HttpRequestResponse source) {
        HttpRequest req = source.request();
        String contentType = null;
        for (HttpHeader h : req.headers()) {
            if (h.name().equalsIgnoreCase("Content-Type")) { contentType = h.value(); break; }
        }
        boolean isXml = XxeCollaboratorLogic.isXmlLike(contentType, req.bodyToString());
        if (!isXml) {
            XxeCollaboratorLogic.Evidence ev = XxeCollaboratorLogic.evaluate(false, List.of());
            statusFor(plan, source, ev.verdict().name().toLowerCase(Locale.ROOT), ev.confidence(), ev.confirmed(), ev.summary(), ev.detail());
            return;
        }

        CollaboratorClient client;
        CollaboratorPayload payload;
        try {
            client = api.collaborator().createClient();
            payload = client.generatePayload();
        } catch (IllegalStateException e) {
            statusFor(plan, source, "inconclusive", 0, false,
                    "Burp Collaborator is unavailable (requires Burp Suite Professional with a Collaborator "
                            + "server configured) -- xxe_validation cannot run. " + e.getMessage(), "");
            return;
        }

        String payloadBody = XxeCollaboratorLogic.buildPayload(payload.toString());
        api.http().sendRequest(req.withBody(payloadBody));
        List<String> types = pollInteractionTypes(client, payload.toString());
        XxeCollaboratorLogic.Evidence ev = XxeCollaboratorLogic.evaluate(true, types);
        statusFor(plan, source, ev.verdict().name().toLowerCase(Locale.ROOT), ev.confidence(), ev.confirmed(), ev.summary(), ev.detail());
    }

    // ---------------------------------------------------------------
    // csrf_validation -- if a CSRF-token-shaped header or body/form
    // parameter is found, removes it and resends once, comparing
    // status codes; if none is found, reports the passive signal
    // without an extra request. See CsrfLogic for the full scope note
    // (this only evaluates classic cookie-based session CSRF).
    // ---------------------------------------------------------------
    private void csrfValidation(TestPlan plan, HttpRequestResponse source) {
        HttpRequest req = source.request();
        // Only the cookie is ambient: a browser attaches it to a cross-site
        // request by itself, but never an Authorization header.
        String cookie = reqHeader(req, "Cookie");
        boolean cookieAuthPresent = cookie != null && !cookie.isBlank();

        // The forged request starts as the captured one without a valid token:
        // a token header is removed, a token parameter is invalidated.
        HttpRequest forged = null;
        for (HttpHeader h : req.headers()) {
            if (CsrfLogic.looksLikeCsrfTokenName(h.name())) { forged = req.withRemovedHeader(h.name()); break; }
        }
        if (forged == null) {
            for (var p : req.parameters()) {
                if (p.type() == HttpParameterType.COOKIE) continue;
                if (CsrfLogic.looksLikeCsrfTokenName(p.name())) {
                    forged = req.withParameter(HttpParameter.parameter(p.name(), "invalidated-by-harness", p.type()));
                    break;
                }
            }
        }
        boolean tokenFound = forged != null;
        int originalStatus = status(source);
        int forgedStatus = -1;
        int anonymousStatus = -1;
        if (tokenFound && cookieAuthPresent && !CsrfLogic.isSafeMethod(req.method())
                && CsrfLogic.isSuccess(originalStatus)) {
            // What a cross-site page can make the browser send: the session
            // cookie, no valid token, no non-ambient credential.
            forged = forged.withRemovedHeader("Authorization");
            forgedStatus = status(api.http().sendRequest(forged));
            if (CsrfLogic.isSuccess(forgedStatus)) {
                // Control: the same request without the cookie either. If it
                // also succeeds, the action is not gated on the session.
                anonymousStatus = status(api.http().sendRequest(forged.withRemovedHeader("Cookie")));
            }
        }
        CsrfLogic.Evidence ev = CsrfLogic.evaluate(req.method(), cookieAuthPresent, tokenFound,
                originalStatus, forgedStatus, anonymousStatus);
        statusFor(plan, source, ev.verdict().name().toLowerCase(Locale.ROOT), ev.confidence(), ev.confirmed(), ev.summary(), ev.detail());
    }

    // ---------------------------------------------------------------
    // ssti_validation -- mirrors reflection()'s (XSS) candidate/payload
    // iteration exactly: all non-cookie parameters, cycling payloads
    // until CONFIRMED or exhausted. See SstiPayloadLogic.
    // ---------------------------------------------------------------
    private void sstiValidation(TestPlan plan, HttpRequestResponse source) {
        HttpRequest req = source.request();
        List<HttpParameter> targets = new ArrayList<>();
        for (var p : req.parameters()) {
            if (p.type() == HttpParameterType.COOKIE) continue;
            targets.add(p);
        }
        if (targets.isEmpty()) {
            statusFor(plan, source, "invalid", 0, false,
                    "No mutable URL/body parameter was available for ssti_validation to target.", "");
            return;
        }

        String baselineBody = source.response() == null ? null : source.response().bodyToString();
        SstiPayloadLogic.Verdict best = SstiPayloadLogic.Verdict.REJECTED;
        String bestDetail = "";
        HttpParameter bestParam = null;

        outer:
        for (HttpParameter param : targets) {
            List<String> tried = new ArrayList<>();
            SstiPayloadLogic.Payload payload;
            while ((payload = SstiPayloadLogic.nextPayload(tried)) != null) {
                tried.add(payload.template());
                var rr = api.http().sendRequest(req.withParameter(HttpParameter.parameter(param.name(), payload.template(), param.type())));
                String mutatedBody = rr.response() == null ? null : rr.response().bodyToString();
                SstiPayloadLogic.Evidence ev = SstiPayloadLogic.classify(payload, baselineBody, mutatedBody);
                if (ev.verdict() == SstiPayloadLogic.Verdict.CONFIRMED) {
                    best = ev.verdict(); bestParam = param; bestDetail = "param=" + param.name() + " | " + ev.detail();
                    break outer;
                }
                if (ev.verdict() == SstiPayloadLogic.Verdict.SUPPORTED && best != SstiPayloadLogic.Verdict.SUPPORTED) {
                    best = ev.verdict(); bestParam = param; bestDetail = "param=" + param.name() + " | " + ev.detail();
                }
            }
        }

        switch (best) {
            case CONFIRMED -> statusFor(plan, source, "confirmed", 0.88, true,
                    "A template expression was evaluated server-side for parameter '" + bestParam.name() + "'.", bestDetail);
            case SUPPORTED -> statusFor(plan, source, "supported", 0.5, false,
                    "A partial SSTI signal was observed for parameter '" + bestParam.name()
                            + "' across " + SstiPayloadLogic.PAYLOADS.size() + " engine payloads tried -- not confirmed.", bestDetail);
            default -> statusFor(plan, source, "rejected", 0.72, false,
                    "No template evaluation was observed for any of " + SstiPayloadLogic.PAYLOADS.size()
                            + " engine payloads across " + targets.size() + " parameter(s).", "");
        }
    }

    // ---------------------------------------------------------------
    // deserialization_format_confirmation -- passive, no new request.
    // Classifies the request body Burp already captured. See
    // DeserializationFormatLogic for why this is scoped to pure-ASCII
    // signatures only (no raw magic bytes).
    // ---------------------------------------------------------------
    private void deserializationFormatScan(TestPlan plan, HttpRequestResponse source) {
        String body = source.request().bodyToString();
        DeserializationFormatLogic.Evidence ev = DeserializationFormatLogic.evaluate(body);
        statusFor(plan, source, ev.verdict().name().toLowerCase(Locale.ROOT), ev.confidence(), ev.confirmed(), ev.summary(), ev.detail());
    }

    // ---------------------------------------------------------------
    // command_injection_validation -- differential timing probe. See
    // CommandInjectionTimingLogic for why two different injected delays
    // are compared against each other rather than one delay against a
    // noisy baseline. Deliberately bounded to ONE candidate parameter
    // and 2 payload templates (unlike reflection()/sstiValidation(),
    // which try every parameter and payload) -- each attempt here costs
    // several real seconds of wall-clock wait time (SHORT_SECONDS +
    // LONG_SECONDS of actual sleep, if the injection works), so the
    // same "try everything" approach that's cheap for XSS/SSTI would
    // make an analyst wait a genuinely long time for one click.
    // ---------------------------------------------------------------
    private static final int COMMAND_INJECTION_MAX_PAYLOADS = 2;

    private void commandInjectionTiming(TestPlan plan, HttpRequestResponse source) {
        HttpRequest req = source.request();
        List<HttpParameter> targets = new ArrayList<>();
        for (var p : req.parameters()) {
            if (p.type() == HttpParameterType.COOKIE) continue;
            targets.add(p);
        }
        if (targets.isEmpty()) {
            statusFor(plan, source, "invalid", 0, false,
                    "No mutable URL/body parameter was available for command_injection_validation to target.", "");
            return;
        }
        HttpParameter target = targets.get(0);

        long baselineStart = System.nanoTime();
        api.http().sendRequest(req);
        long baselineMs = (System.nanoTime() - baselineStart) / 1_000_000;

        CommandInjectionTimingLogic.Verdict best = CommandInjectionTimingLogic.Verdict.REJECTED;
        String bestDetail = "";
        int attempts = 0;
        for (CommandInjectionTimingLogic.Payload payload : CommandInjectionTimingLogic.PAYLOADS) {
            if (attempts >= COMMAND_INJECTION_MAX_PAYLOADS) break;
            attempts++;

            String shortPayload = payload.render(CommandInjectionTimingLogic.SHORT_SECONDS);
            long shortStart = System.nanoTime();
            api.http().sendRequest(req.withParameter(HttpParameter.parameter(target.name(), shortPayload, target.type())));
            long shortMs = (System.nanoTime() - shortStart) / 1_000_000;

            String longPayload = payload.render(CommandInjectionTimingLogic.LONG_SECONDS);
            long longStart = System.nanoTime();
            api.http().sendRequest(req.withParameter(HttpParameter.parameter(target.name(), longPayload, target.type())));
            long longMs = (System.nanoTime() - longStart) / 1_000_000;

            CommandInjectionTimingLogic.Evidence ev = CommandInjectionTimingLogic.evaluate(payload, baselineMs, shortMs, longMs);
            if (ev.verdict() == CommandInjectionTimingLogic.Verdict.CONFIRMED) {
                statusFor(plan, source, "confirmed", ev.confidence(), true,
                        "Command injection timing signal for parameter '" + target.name() + "'.",
                        "param=" + target.name() + " | " + ev.detail());
                return;
            }
            if (ev.verdict() == CommandInjectionTimingLogic.Verdict.SUPPORTED && best != CommandInjectionTimingLogic.Verdict.SUPPORTED) {
                best = ev.verdict();
                bestDetail = "param=" + target.name() + " | " + ev.detail();
            }
        }

        if (best == CommandInjectionTimingLogic.Verdict.SUPPORTED) {
            statusFor(plan, source, "supported", 0.4, false,
                    "Partial timing signal for parameter '" + target.name() + "' across " + attempts
                            + " payload(s) tried -- not confirmed.", bestDetail);
        } else {
            statusFor(plan, source, "rejected", 0.7, false,
                    "No timing evidence of command injection for parameter '" + target.name() + "' across "
                            + attempts + " payload(s) tried.", "");
        }
    }

    // ---------------------------------------------------------------
    // race_condition_validation -- the ONE executor in this file that
    // needs genuine concurrent dispatch, not sequential replay. Every
    // other method's sendRequest() calls happen one after another
    // (appropriately -- none of them depend on overlapping in time).
    // A check-then-act race only opens if multiple requests are
    // actually in flight against the server simultaneously, so this
    // uses a real thread pool plus a two-latch start barrier: every
    // worker thread signals "ready" and then blocks on "go", so none of
    // them fires until all of them are lined up to fire together,
    // rather than however the JVM happens to schedule a simple loop.
    // See RaceConditionLogic for how the resulting status codes are
    // interpreted.
    // ---------------------------------------------------------------
    private void raceConditionBurst(TestPlan plan, HttpRequestResponse source) {
        HttpRequest req = source.request();
        int n = MAX_BURST;
        ExecutorService pool = Executors.newFixedThreadPool(n);
        CountDownLatch ready = new CountDownLatch(n);
        CountDownLatch go = new CountDownLatch(1);
        List<Future<Integer>> futures = new ArrayList<>();
        try {
            for (int i = 0; i < n; i++) {
                futures.add(pool.submit(() -> {
                    ready.countDown();
                    try { go.await(); } catch (InterruptedException ie) { Thread.currentThread().interrupt(); }
                    var rr = api.http().sendRequest(req);
                    return rr.response() == null ? 0 : (int) rr.response().statusCode();
                }));
            }
            try { ready.await(2, TimeUnit.SECONDS); } catch (InterruptedException ignored) {}
            go.countDown();

            List<RaceConditionLogic.AttemptResult> results = new ArrayList<>();
            for (Future<Integer> f : futures) {
                try { results.add(new RaceConditionLogic.AttemptResult(f.get(30, TimeUnit.SECONDS))); }
                catch (Exception e) { results.add(new RaceConditionLogic.AttemptResult(0)); }
            }

            RaceConditionLogic.Evidence ev = RaceConditionLogic.evaluate(results);
            String status = switch (ev.verdict()) {
                case CONFIRMED -> "confirmed";
                case SUPPORTED -> "supported";
                case REJECTED -> "rejected";
            };
            statusFor(plan, source, status, ev.confidence(), ev.confirmed(), ev.summary(), ev.detail());
        } finally {
            pool.shutdownNow();
        }
    }

    // ---------------------------------------------------------------
    // file_upload_validation -- EICAR probe. Replaces the content of an
    // existing multipart file part with the industry-standard EICAR
    // antivirus test string (see FileUploadLogic's own doc comment for
    // why EICAR specifically, and why this is deliberately narrower
    // than the specialist agent's own suggested_test payloads), resends,
    // then attempts to fetch the file back from a URL/path found in the
    // upload response to confirm it's stored unscanned and accessible.
    // ---------------------------------------------------------------
    private void fileUploadEicarProbe(TestPlan plan, HttpRequestResponse source) {
        HttpRequest req = source.request();
        String contentType = null;
        for (HttpHeader h : req.headers()) {
            if (h.name().equalsIgnoreCase("Content-Type")) { contentType = h.value(); break; }
        }
        String boundary = FileUploadLogic.extractBoundary(contentType);
        if (boundary == null) {
            statusFor(plan, source, "invalid", 0, false,
                    "This request is not a multipart/form-data upload -- file_upload_validation requires "
                            + "an existing file-upload request to target.", "");
            return;
        }
        String mutatedBody = FileUploadLogic.replaceFileContent(req.bodyToString(), boundary, FileUploadLogic.EICAR_STRING);
        if (mutatedBody == null) {
            statusFor(plan, source, "invalid", 0, false,
                    "No file part (a Content-Disposition with filename=) was found in this multipart body to replace.", "");
            return;
        }

        var rr = api.http().sendRequest(req.withBody(mutatedBody));
        var resp = rr.response();
        if (resp == null) {
            statusFor(plan, source, "inconclusive", 0, false, "No response was received for the file-upload probe request.", "");
            return;
        }
        int uploadStatus = resp.statusCode();
        String extractedUrl = FileUploadLogic.extractUrl(resp.bodyToString());

        int fetchStatus = -1;
        boolean fetchedContainsEicar = false;
        if (extractedUrl != null) {
            try {
                String path = extractedUrl.startsWith("http")
                        ? java.net.URI.create(extractedUrl).getRawPath()
                        : extractedUrl;
                if (path != null && !path.isEmpty()) {
                    var fetchRr = api.http().sendRequest(readRequest(req, path));
                    if (fetchRr.response() != null) {
                        fetchStatus = fetchRr.response().statusCode();
                        fetchedContainsEicar = fetchRr.response().bodyToString().contains(FileUploadLogic.EICAR_STRING);
                    }
                }
            } catch (Exception ignored) {
                // best-effort fetch-back only; evaluate() below already
                // reports SUPPORTED (not CONFIRMED) when this stays inconclusive
            }
        }

        FileUploadLogic.Evidence ev = FileUploadLogic.evaluate(uploadStatus, extractedUrl, fetchStatus, fetchedContainsEicar);
        statusFor(plan, source, ev.verdict().name().toLowerCase(Locale.ROOT), ev.confidence(), ev.confirmed(), ev.summary(), ev.detail());
    }

    private void submit(TestPlan p,HttpRequestResponse source,String status,double confidence,boolean confirmed,String summary,String evidence){
        ValidationSubmission v=new ValidationSubmission(); v.plan_id=p.id; v.status=status; v.confidence=confidence; v.confirmed=confirmed;
        v.summary=summary; v.evidence=evidence; v.executor="burp:"+p.capability; v.source_exchange_hash=exchangeFingerprint(source);
        try{
            client.submitValidationResult(v);
        }catch(HarnessClient.HarnessException e){
            api.logging().logToError("Validation submission failed: "+e.getMessage());
            // Found live: statusFor() already stored this plan's Outcome (with a
            // "CONFIRMED"-shaped detail string) in `outcomes` BEFORE calling this
            // method -- so if the server-side POST above is rejected (most
            // commonly: this capability isn't yet on store.py's
            // confirmation_capabilities allowlist, so a locally-computed
            // confirmed=true verdict is never durably recorded in
            // validation_runs), the analyst would otherwise see "CONFIRMED" in
            // the panel with zero indication that nothing was actually
            // persisted -- the rejection only ever reached Burp's separate
            // Output/error log above, which the analyst watching the harness
            // panel has no reason to be looking at. Mutating the same Outcome
            // object here works because submit() always runs to completion
            // before SwingWorker.done() reads it back out of the map.
            Outcome o = outcomes.get(p.id);
            if (o != null) { o.detail = o.detail + " (NOT PERSISTED: " + e.getMessage() + ")"; }
        }
    }

    /**
     * Must produce byte-for-byte the same string material that
     * harness/planner.py's exchange_fingerprint() hashes -- that
     * function fingerprints the exchange as the Python server actually
     * received it, which went through headersToMap() (HarnessContextMenu.java)
     * on the way there. headersToMap() merges duplicate header names
     * (e.g. two Cookie headers) into one entry joined by "\n", since the
     * wire format is a plain string map that can't represent duplicate
     * JSON keys. This method used to iterate Burp's raw, non-deduplicated
     * header list directly instead -- meaning ANY request with even one
     * duplicate header name would compute a different hash here than the
     * one computed at plan-creation time, and every validation attempt
     * against it would be rejected with "fingerprint does not match",
     * regardless of the request being byte-identical. Deduplicating the
     * same way here, before sorting and hashing, is what makes the two
     * sides agree.
     */
    public static String exchangeFingerprint(HttpRequestResponse rr){
        // Delegates to logic.ExchangeFingerprint so IdentityCandidateResolver
        // (Montoya-stub-only, headlessly testable) can share this exact
        // algorithm without pulling in this class (needs HarnessClient/Gson
        // to compile) -- see that class own doc comment.
        return ExchangeFingerprint.compute(rr);
    }

    /**
     * Extracts host[:port] from a URL the same way harness/store.py's
     * host_of() does (urlparse(url).netloc) -- needed because
     * sessions_for_host() is keyed on that exact string, and this
     * project has no shared code between the Java and Python sides to
     * guarantee the two stay in sync by construction. If Python's
     * host_of() ever changes its normalization (e.g. starts
     * lowercasing, or stripping default ports), this must be updated
     * to match or session lookups will silently stop matching -- there
     * is no test that could catch that kind of cross-language drift
     * automatically, which is worth naming rather than pretending this
     * pairing is more robust than it is.
     */
    /**
     * Extracts host[:port] from a URL the same way harness/store.py's
     * host_of() does (urlparse(url).netloc) -- needed because
     * sessions_for_host() is keyed on that exact string, and this
     * project has no shared code between the Java and Python sides to
     * guarantee the two stay in sync by construction. If Python's
     * host_of() ever changes its normalization (e.g. starts
     * lowercasing, or stripping default ports), this must be updated
     * to match or session lookups will silently stop matching -- there
     * is no test that could catch that kind of cross-language drift
     * automatically, which is worth naming rather than pretending this
     * pairing is more robust than it is.
     *
     * Public (not private) so HarnessContextMenu's session-registration
     * action can reuse it rather than holding its own copy -- exactly
     * the kind of small duplicated helper that silently drifts apart
     * over time, per this project's own documented history of that
     * exact failure mode (see exchange_text.py's harness-side
     * equivalent fix from an earlier session).
     */
    public static String netloc(String url) {
        try {
            URI uri = URI.create(url);
            String host = uri.getHost();
            if (host == null) return url; // unparseable -- fall back to the raw string rather than throwing
            int port = uri.getPort();
            return port == -1 ? host : host + ":" + port;
        } catch (Exception e) {
            return url;
        }
    }

    /**
     * Fetches sessions for `host` and adapts them into the
     * exchange_hash -> "name (role)" lookup IdentityLabelResolver.labelFor()
     * expects. Never throws -- a harness-server hiccup (not running,
     * network blip, auth misconfigured) must degrade the picker back to
     * its original unlabeled format, not break the identity-compare
     * capability entirely. This is a deliberate fail-open-to-the-OLD-
     * behavior choice, not a safety-relevant fail-closed one: unlike
     * safety_gate.py/safety_proxy_addon.py, nothing here authorizes a
     * mutating action -- worst case on failure is a less-informative
     * picker label, exactly what existed before this feature.
     */
    private Map<String, String> fetchSessionLookup(String host) {
        try {
            var sessions = client.sessionsForHost(host);
            List<IdentityLabelResolver.SessionEntry> entries = new ArrayList<>();
            for (var s : sessions) {
                entries.add(new IdentityLabelResolver.SessionEntry(s.exchange_hash, s.identity_name, s.identity_role));
            }
            return IdentityLabelResolver.buildLookup(entries);
        } catch (Exception e) {
            api.logging().logToError("Could not fetch sessions for " + host + " (picker will show unlabeled candidates): " + e.getMessage());
            return Map.of();
        }
    }
}
