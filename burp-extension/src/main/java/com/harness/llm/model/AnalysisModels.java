package com.harness.llm.model;

import java.util.List;
import java.util.Map;

/**
 * Wire-format POJOs. Field names must match the JSON keys the Python
 * harness (models.py) actually produces/consumes -- these two files are
 * the narrow interface between the two halves of this system and have
 * to be kept in sync by hand, since there's no shared schema.
 */
public class AnalysisModels {

    public static class HttpExchange {
        public String url;
        public String method;
        public Map<String, String> request_headers;
        public String request_body;
        public Integer response_status; // nullable
        public Map<String, String> response_headers;
        public String response_body;
        public String analyst_note;
    }

    public static class AnalysisRequest {
        public HttpExchange exchange;
        public List<String> force_agents;
        public boolean attempt_rediscovery;
    }

    public static class Finding {
        public String vulnerability_class;
        public double confidence;
        public String severity;        // "info"|"low"|"medium"|"high"|"critical"
        public String owasp_category;  // nullable
        public String summary;
        public String evidence;
        public String suggested_test;
        public String basis;
        public Double original_confidence; // nullable
        public String review_verdict;      // nullable
        public String review_note;         // nullable
        public boolean confirmed;
        // P1.9 (Astra oracle + T01/T06 case/proof identity) -- WRITE-ONLY /
        // SELF-REVIEWED addition: this repo has no JDK to compile or test the
        // Burp extension (see CLAUDE.md hazard #6), so these fields are added
        // to keep the wire format in sync with harness/models.py's Finding but
        // are UNBUILT/UNVERIFIED. Before this change, a Finding crossing into
        // the Burp panel silently DROPPED all seven of these -- Gson leaves an
        // unmapped Java field at its default (false/"" ) rather than erroring,
        // so the panel always showed an unconfirmed, non-oracle-verified,
        // case/proof-less finding regardless of what the harness actually sent.
        public String case_id;             // nullable/"" -- T01 case identity
        public String proof_id;            // nullable/"" -- T01 proof identity
        public String confirmed_by_leg;    // nullable/"" -- the confirming validator's name
        public boolean oracle_verified;    // oracle_framework.py's N-of-N + negative-control verdict
        public String verification_state;  // "candidate" | "verified"
        public String oracle_capsule_id;   // nullable/"" -- ProofCapsule.capsule_id()
        public String oracle_reason;       // nullable/"" -- human-readable oracle verdict reason
    }

    public static class AgentReport {
        public String agent;
        public String model;
        public List<Finding> findings;
        public String raw_error; // nullable
    }

    public static class TestPlan {
        public String id;
        public String capability;
        public String finding_class;
        public String category; // nullable -- canonicalized category, see harness/categories.py
        public String source_exchange_url;
        public Map<String, String> mutation;
        public List<String> success_signals;
        public boolean requires_approval;
        public String execution_plane;
        public String rationale;
        public String source_exchange_hash;
        public String schema_version;
    }

    public static class ValidationSubmission {
        public String plan_id;
        public String status;
        public double confidence;
        public boolean confirmed;
        public String summary;
        public String evidence;
        public String executor;
        public String source_exchange_hash;
    }

    public static class AnalysisResponse {
        public String coordinator_model;
        public List<String> dispatched_agents;
        public List<AgentReport> agent_reports;
        public String summary;
        public Finding highest_confidence_finding; // nullable
        public int findings_reviewed;
        public int findings_rejected;
        public List<TestPlan> test_plans;
        public int effort_spent_tokens;
        public Integer effort_budget_remaining; // nullable -- null means no cap configured
        public String effort_budget_warning;    // "" when nothing to report
        public List<ToolRec> tool_recommendations; // A3 -- may be null on older servers
    }

    public static class UrlEstimateItem {
        public String url;
        public Double risk_score; // nullable, 0.0-1.0
        public String category;   // nullable
    }

    public static class EstimateRequest {
        public List<UrlEstimateItem> urls;
    }

    public static class EstimateResponse {
        public int urls_total;
        public int urls_scored;
        public int urls_unscored;
        public int urls_high_risk;
        public long estimated_total_tokens;
        public boolean calibrated_from_real_calls;
        public Map<String, Long> breakdown;
        public Map<String, Double> assumptions;
    }

    /** Mirrors harness/models.py's PrioritizeRequestItem -- structure
     * only (method/URL/param names), no request/response bodies. See
     * server.py's POST /prioritize and surface_prioritizer.py. */
    public static class PrioritizeRequestItem {
        public String method;
        public String url;
        public List<String> param_names;
    }

    public static class PrioritizeRequest {
        public List<PrioritizeRequestItem> items;
    }

    public static class PrioritizeResultItem {
        public String method;
        public String url;
        public String ai_priority; // "critical" | "high" | "medium" | "low" | "unscored"
        public double ai_score;    // 0.0-1.0
        public String reasoning;
    }

    public static class PrioritizeResponse {
        public List<PrioritizeResultItem> results;
    }

    public static class EffortStatus {
        public String mode;
        public Integer total_tokens; // nullable
        public int spent_tokens;
        public Integer remaining_tokens; // nullable
        public boolean exhausted;
        public Map<String, Long> breakdown;
    }

    /** Mirrors harness/server.py's GET /identities response shape (see identity.Identity). */
    public static class IdentityInfo {
        public String id;
        public String name;
        public String role;
        public String notes;
    }

    /**
     * Mirrors harness/store.py's sessions_for_host() response shape --
     * NOT identity.Session's raw fields. sessions_for_host() already
     * JOINs against the identities table and returns identity_name/
     * identity_role directly, precisely so a caller (this one) doesn't
     * need a second round-trip to /identities just to label a session.
     * Field names matter here -- verified against store.py's actual
     * SELECT/dict-construction, not assumed from identity.Session's
     * dataclass fields, which don't match (that class has no
     * identity_name/identity_role -- only identity_id).
     */
    public static class SessionInfo {
        public String session_id;
        public String identity_id;
        public String identity_name;
        public String identity_role;
        public String host;
        public String exchange_hash;
        public String label;
    }

    public static class ErrorBody {
        public String error;
    }

    // --- Session-3 additions: model selection, discovery, active testing,
    // resource governance, tool recommendations, and the live activity feed.
    // Deep/dynamic responses (active-probe, retry-agents, plan-allocation,
    // missing-auth, confidential scan) are handled as raw JsonObject in the
    // client rather than mirrored field-by-field here -- only the shapes that
    // drive a specific widget get a typed POJO. ---

    /** GET /models -- feeds the coordinator/agent model dropdowns. */
    public static class ModelsInfo {
        public List<String> local;
        public List<String> cloud;
        public List<String> all;
        public String coordinator_model;
        public List<String> agent_models;
    }

    /** POST /models/select body. Any field left null/blank is unchanged. */
    public static class SelectModelRequest {
        public String coordinator;
        public String agent_model;
        public String agent;
    }

    /** One event from GET /activity (the live agent-activity feed, V1). */
    public static class ActivityEvent {
        public long seq;
        public double ts;
        public String kind;
        public String message;
        public String agent;
        public String level;   // info | warn | error
        public Map<String, Object> detail;
    }

    /** GET /activity response: a window of events plus the latest seq seen. */
    public static class ActivitySnapshot {
        public long latest_seq;
        public int dropped;
        public List<ActivityEvent> events;
    }

    /** One tool recommendation from POST /tools/recommend / an analysis
     * response's tool_recommendations. */
    public static class ToolRec {
        public String tool;
        public String category;
        public String reason;
        public String command;
        public String url;
        public String kind;
        public String for_finding;
        public String target_url;
    }
}
