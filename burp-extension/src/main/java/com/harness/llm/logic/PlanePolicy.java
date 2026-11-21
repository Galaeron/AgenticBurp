package com.harness.llm.logic;

import java.util.Locale;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/**
 * ARC-4: the live policy one dispatched plan runs under on the Burp plane.
 *
 * The harness hands it out per dispatch (POST /test-plans/{id}/dispatch), so
 * the plane follows the same two flags as the Python SafetyGate: GET, HEAD,
 * OPTIONS and TRACE may be sent; any other method (or an unknown one) only
 * when active_enabled AND allow_mutating_replay are both on. Every send also
 * counts against the request budget. The first refusal is kept: an executor
 * arm that swallows the refused send's exception still cannot report a
 * verdict, because the plane reports the refusal instead.
 *
 * Montoya-free, so it is tested without the Burp API.
 */
public final class PlanePolicy {
    /** No send ceiling (the harness sent request_budget: null). */
    public static final int NO_BUDGET = -1;

    private static final Set<String> SAFE_METHODS = Set.of("GET", "HEAD", "OPTIONS", "TRACE");

    private final boolean activeEnabled;
    private final boolean allowMutatingReplay;
    private final int requestBudget;
    private final AtomicInteger sent = new AtomicInteger();
    private final AtomicReference<String> refusal = new AtomicReference<>();

    public PlanePolicy(boolean activeEnabled, boolean allowMutatingReplay, int requestBudget) {
        this.activeEnabled = activeEnabled;
        this.allowMutatingReplay = allowMutatingReplay;
        // Only NO_BUDGET itself lifts the ceiling; any other negative is zero.
        this.requestBudget = requestBudget == NO_BUDGET ? NO_BUDGET : Math.max(0, requestBudget);
    }

    public boolean activeEnabled() { return activeEnabled; }
    public boolean allowMutatingReplay() { return allowMutatingReplay; }
    public int requestBudget() { return requestBudget; }
    public int sent() { return sent.get(); }

    public static boolean isSafeMethod(String method) {
        return method != null && SAFE_METHODS.contains(method.trim().toUpperCase(Locale.ROOT));
    }

    /**
     * Decide one send. Returns null when it may go out (and counts it), or
     * the refusal reason. After any refusal every later send is refused too.
     */
    public String authorize(String method) {
        String earlier = refusal.get();
        if (earlier != null) return earlier;
        if (!isSafeMethod(method) && !(activeEnabled && allowMutatingReplay)) {
            String shown = method == null || method.isBlank() ? "(none)" : method.trim().toUpperCase(Locale.ROOT);
            return refuse("mutating replay is off: " + shown + " needs active_enabled and "
                    + "allow_mutating_replay (active_enabled=" + activeEnabled
                    + ", allow_mutating_replay=" + allowMutatingReplay + ")");
        }
        if (requestBudget != NO_BUDGET) {
            int prior;
            do {
                prior = sent.get();
                if (prior >= requestBudget) {
                    return refuse("request budget of " + requestBudget + " sends is spent");
                }
            } while (!sent.compareAndSet(prior, prior + 1));
            return null;
        }
        sent.incrementAndGet();
        return null;
    }

    /** The first refusal, or null when nothing was refused. */
    public String refusal() { return refusal.get(); }

    private String refuse(String reason) {
        refusal.compareAndSet(null, reason);
        return refusal.get();
    }
}
