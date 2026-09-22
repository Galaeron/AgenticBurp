from __future__ import annotations
from typing import Optional
from pydantic import BaseModel, Field


class HttpExchange(BaseModel):
    """One captured request/response pair, as sent by the Burp extension."""
    url: str
    method: str
    request_headers: dict[str, str] = Field(default_factory=dict)
    request_body: str = ""
    response_status: Optional[int] = None
    response_headers: dict[str, str] = Field(default_factory=dict)
    response_body: str = ""
    # Free-text notes the analyst typed in Burp before sending, if any.
    analyst_note: str = ""


class ComponentCandidate(BaseModel):
    """
    A software component + version an agent noticed in an exchange --
    e.g. from a Server header, a JS library banner, or an exposed
    dependency manifest. This is a candidate for the orchestrator's
    deterministic known-vulnerability lookup, not a vulnerability claim
    on its own: agents extract candidates, they do not decide whether a
    version is vulnerable (see base_agent's common rules).
    """
    ecosystem: str  # e.g. "npm", "PyPI", "Maven", "RubyGems", "Go", "generic"
    name: str
    version: Optional[str] = None
    source: str = ""  # where it was seen, e.g. "Server header" or "package.json body"
    observed_in_exchange: bool = False  # independently verified against raw exchange text
    verification_note: str = ""


class Finding(BaseModel):
    """One structured claim made by a specialist agent."""
    vulnerability_class: str
    confidence: float = Field(ge=0.0, le=1.0)
    summary: str
    evidence: str
    suggested_test: str
    basis: str  # "derived" | "recalled" | "assumed" -- see agent prompts

    # Severity/taxonomy fields -- added after reviewing how comparable
    # tools (Strix, Xalgorix) report findings. Confidence answers "how
    # sure are we this is real"; severity answers "how much would it
    # matter if it is" -- two different axes a reader needs separately.
    severity: str = "info"  # "info" | "low" | "medium" | "high" | "critical"
    owasp_category: Optional[str] = None  # e.g. "A01:2021-Broken Access Control"

    # Populated by the orchestrator's critique pass (§6-style adversarial
    # review), not by the specialist agent itself. None until reviewed.
    original_confidence: Optional[float] = None
    review_verdict: Optional[str] = None  # "survived" | "downgraded" | "rejected"
    review_note: Optional[str] = None
    # Pre-cap severity, set by header_noise_gate when it demotes a header/config
    # observer finding below the medium operating point. None until capped.
    original_severity: Optional[str] = None

    # Set by attribution.py (Phase 3.5). `original_vulnerability_class` records the
    # pre-relabel class when a confirming leg overrides the agent's label;
    # `shape_inconsistent` flags an unconfirmed label that contradicts the
    # endpoint's shape. These are real (serialized) fields so the annotation
    # survives model_dump() into the report and the recall benchmark -- without
    # them, setting the attribute on this pydantic model raises (the attribution
    # passes run on Finding objects in analyze(), not the dicts the unit tests use).
    original_vulnerability_class: Optional[str] = None
    shape_inconsistent: bool = False

    # True only when the harness has actually performed the suggested
    # confirming action (or another explicit verification path). LLM
    # reasoning alone never sets this.
    confirmed: bool = False
    validation_hints: list[str] = Field(default_factory=list)

    # 2026-09-17 coverage-recovery plan, Step 4: the NAME of the deterministic
    # leg that set `confirmed=True` (e.g. "cross_identity", "sqlmap",
    # "jwt_forge"), stamped by _validate_findings/coverage_confirmation_finding
    # at the SAME moment as proof_id/case_id. Before this field existed, the
    # only way to recover which leg (if any) confirmed a finding was to regex
    # -parse its free-text evidence string for a "<leg> CONFIRMED" stamp
    # (recall_benchmark.confirmation_leg_of) -- fragile, and silently empty for
    # any confirmation path that phrased its evidence differently. Empty means
    # no leg is known to have proved it, structurally, not by string luck.
    confirmed_by_leg: str = ""

    # Originating-case coordinates (T01).  Producers may supply authoritative
    # values; the orchestrator derives a stable invocation-local finding_id when
    # legacy findings omit one.  proof_id/case_id are populated only after the
    # exact finding's proof is durably persisted.
    finding_id: str = ""
    principal_id: str = ""
    request_template_id: str = ""
    parameter_location: str = ""
    parameter_name: str = ""
    workflow_state_id: str = ""
    proof_id: str = ""
    case_id: str = ""

    # Oracle-verification axis (precision item #1/#2), orthogonal to `confirmed`.
    # `confirmed` means a leg fired at least once; `oracle_verified` is the higher
    # bar -- the oracle_framework reproduced it N-of-N AND (for non-self-controlling
    # legs) a paired negative control stayed clean. `verification_state` is the
    # operator-facing label derived from it ("verified" vs "candidate"), and
    # `oracle_capsule_id`/`oracle_reason` point at the auditable proof capsule.
    # Set only by oracle_framework.stamp_finding; agents can never assert them.
    oracle_verified: bool = False
    verification_state: str = "candidate"
    oracle_capsule_id: str = ""
    oracle_reason: str = ""


# R02: fields this harness's own deterministic pipeline owns -- the
# orchestrator's confirmation/proof linkage (orchestrator_confirm.py), its
# critique pass, and attribution.py's relabeling. A specialist agent's raw
# JSON is untrusted model output; if it echoes any of these key names (all
# appear throughout this harness's own prompts, docs, and prior findings
# shown back to the model), that must never become a persisted authority
# claim with no harness-side origin. Every call site that builds a Finding
# from raw parsed agent JSON must route it through sanitize_agent_finding
# first -- see harness/agents/base_agent.py, harness/iterative_agent.py,
# harness/orchestrator_detect.py's _attempt_rediscovery.
AGENT_AUTHORITY_FIELDS = frozenset({
    "confirmed", "proof_id", "case_id", "review_verdict", "review_note",
    "original_confidence", "original_severity", "original_vulnerability_class",
    "shape_inconsistent", "confirmed_by_leg",
    "oracle_verified", "verification_state", "oracle_capsule_id", "oracle_reason",
})


def sanitize_agent_finding(raw: dict) -> dict:
    """Strip every harness-owned authority field (R02) from one raw finding
    dict parsed from an agent's JSON output, before it is passed to
    Finding(**...). Pydantic silently ignores unrecognized keys rather than
    rejecting them, so an unlisted field the model invents is harmless on
    its own; this only removes the specific REAL fields that would
    otherwise grant unearned authority."""
    return {k: v for k, v in raw.items() if k not in AGENT_AUTHORITY_FIELDS}


class AgentReport(BaseModel):
    agent: str
    model: str
    findings: list[Finding] = Field(default_factory=list)
    components: list[ComponentCandidate] = Field(default_factory=list)
    raw_error: Optional[str] = None
    # Short hash of the exact system prompt used for this run (see
    # base_agent._prompt_version) -- lets a stored finding be traced back
    # to precisely which prompt version produced it, without hand-
    # maintained version numbers going stale the moment a prompt changes.
    prompt_version: str = ""
    # P1.14 -- short hash of the agent's tactical_guide text (base_agent.
    # _guide_version), "" when the agent carries no guide. Lets a stored
    # finding/report show which tactical-guide version was loaded for this
    # dispatch, independent of the broader prompt_version hash above.
    guide_version: str = ""


class AnalysisRequest(BaseModel):
    exchange: HttpExchange
    # If empty, the coordinator picks agents itself. If set, caller forces
    # a specific subset (e.g. user right-clicked "Test for SQLi only").
    force_agents: list[str] = Field(default_factory=list)
    # Default is False: when a component matches a known, disclosed
    # vulnerability, the harness stops there rather than spending an
    # additional model call trying to independently re-derive something
    # already established (see the top-level "known vs rediscover"
    # design). Set True to explicitly ask the harness to attempt
    # independent analysis anyway -- e.g. to look for exchange-specific
    # exploitability evidence beyond the generic advisory text. This is
    # the analyst's call to make, not a default the harness assumes.
    attempt_rediscovery: bool = False


class TestPlan(BaseModel):
    """A declarative request for independent verification.

    Plans contain capabilities and constrained mutation instructions, never
    shell commands or model-generated destination URLs. The Burp extension
    is the preferred execution plane for stateful/identity-aware plans.
    """
    id: str
    capability: str
    finding_class: str
    # Canonicalized category (see categories.py), distinct from
    # finding_class: finding_class is the LLM's original free-text label
    # (kept for display/traceability), category is the normalized key
    # everything downstream -- the coverage ledger, capability planning --
    # should actually join/group on. None when the free text didn't match
    # any known category (surfaced as such, not silently dropped).
    category: Optional[str] = None
    source_exchange_url: str
    mutation: dict[str, str] = Field(default_factory=dict)
    success_signals: list[str] = Field(default_factory=list)
    requires_approval: bool = True
    execution_plane: str = "burp"  # burp | local_tool
    rationale: str = ""
    source_exchange_hash: str = ""
    schema_version: str = "1"
    # The ORIGINAL finding's severity/confidence, captured at plan-creation
    # time -- not the validator's own confidence. Needed by retry_policy's
    # is_suspicious() check (a HANDOVER_MANUAL for an unconfirmed
    # high-severity/high-confidence original hypothesis vs. a silent
    # STOP_INCONCLUSIVE for a low-stakes one), which has no other way to
    # see the original finding once only plan_id comes back on a
    # ValidationSubmission. Left at the default ("", 0.0) by every
    # construction site that doesn't populate it -- safe, since that just
    # means is_suspicious()'s high_prior branch never fires for that plan,
    # not a crash or a wrong retry decision.
    severity: str = ""
    confidence: float = 0.0
    escalated: bool = False


class ValidationSubmission(BaseModel):
    plan_id: str
    status: str
    confidence: float = Field(ge=0.0, le=1.0, default=0.0)
    confirmed: bool = False
    summary: str = ""
    evidence: str = ""
    executor: str = ""
    source_exchange_hash: str = ""
    # Optional hint from the execution plane about where the payload
    # landed (e.g. "html_attribute", "js_string") -- see payload_library's
    # context-aware selection. Empty is always safe: next_candidate()
    # degrades to trying context-agnostic payloads first.
    context_tags: list[str] = Field(default_factory=list)


class ValidationReport(BaseModel):
    validator: str
    status: str
    finding_class: str
    confidence: float = 0.0
    confirmed: bool = False
    summary: str = ""
    evidence: str = ""


class AnalysisResponse(BaseModel):
    coordinator_model: str
    dispatched_agents: list[str]
    agent_reports: list[AgentReport]
    summary: str
    highest_confidence_finding: Optional[Finding] = None
    # How many findings were sent through the adversarial critique pass,
    # and how many survived/were downgraded/rejected -- a reader-visible
    # signal that review happened, distinct from just claiming it did.
    findings_reviewed: int = 0
    findings_rejected: int = 0
    validation_reports: list[ValidationReport] = Field(default_factory=list)
    test_plans: list[TestPlan] = Field(default_factory=list)
    # Real cumulative token spend for this assessment (across all
    # exchanges analyzed so far in this orchestrator's lifetime, not just
    # this one call) -- see effort.EffortBudget. budget_remaining is None
    # when no cap is configured (tracked but never blocking).
    effort_spent_tokens: int = 0
    effort_budget_remaining: Optional[int] = None
    effort_budget_warning: str = ""
    # Tools the harness recommends the tester reach for to confirm/exploit these
    # findings -- the "an agent needs a tool, return it to the user" path
    # (tool_catalog.py). Deterministic mapping from finding class to catalog
    # tools, each with a command templated to this exchange's URL.
    tool_recommendations: list[dict] = Field(default_factory=list)
    telemetry: dict = Field(default_factory=dict)
    # P0.9: True when agent routing for this exchange failed open (the
    # coordinator errored or returned no valid targets, so a fallback set --
    # curated or all-agents, per coordinator.fail_open_mode -- was dispatched
    # instead of a real routing decision). Surfaces coordinator._record_fail_open's
    # reason string as a structured flag on the response itself, not just in
    # `telemetry`'s process-wide counters or the logs.
    coordinator_fallback: bool = False
    # B2-1: True when the shared ollama circuit breaker (harness.circuit_breaker
    # .get_ollama_circuit_breaker("ollama")) was OPEN during this analysis --
    # agent/critique calls short-circuited without hitting the model, so this
    # result is degraded/false-negative-shaped rather than a clean miss.
    # Observability only: does not change breaker trip/reset behavior.
    agents_circuit_open: bool = False
    # Astra T01: case-bound structured proof records for this analysis, one per
    # validator attempt (evidence.ProofRecord.to_dict()). This is the API/report
    # surface for structured, verdict-honest evidence -- distinct from the
    # free-text validation_reports compatibility view above. Empty when no
    # validator ran.
    proof_records: list[dict] = Field(default_factory=list)


class UrlEstimateItem(BaseModel):
    url: str
    # 0.0-1.0 triage/risk score if already scored (e.g. Burp's PathScorer
    # tier normalized, or a prior agent's confidence). None if the URL is
    # only known from spidering, not yet walked through.
    risk_score: Optional[float] = None
    category: Optional[str] = None


class EstimateRequest(BaseModel):
    urls: list[UrlEstimateItem]


class PrioritizeRequestItem(BaseModel):
    """Structure only -- method, URL, and parameter names -- deliberately
    no request/response bodies. This is a triage/ranking pass over a
    potentially large batch of endpoints (see surface_prioritizer.py),
    not a per-exchange vulnerability analysis; sending full bodies for
    every scanned row would defeat the point of keeping this bounded to
    a handful of LLM calls."""
    method: str
    url: str
    param_names: list[str] = Field(default_factory=list)


class PrioritizeRequest(BaseModel):
    items: list[PrioritizeRequestItem]


class PrioritizeResultItem(BaseModel):
    method: str
    url: str
    ai_priority: str  # "critical" | "high" | "medium" | "low" | "unscored"
    ai_score: float = Field(ge=0.0, le=1.0)
    reasoning: str


class PrioritizeResponse(BaseModel):
    results: list[PrioritizeResultItem]


class EffortStatus(BaseModel):
    mode: str
    total_tokens: Optional[int] = None
    spent_tokens: int = 0
    remaining_tokens: Optional[int] = None
    exhausted: bool = False
    breakdown: dict[str, int] = Field(default_factory=dict)


class IdentityCreateRequest(BaseModel):
    name: str
    role: str = "user"  # anonymous | user | admin | service
    notes: str = ""


class SessionCreateRequest(BaseModel):
    identity_id: str
    host: str
    exchange_hash: str
    label: str = ""


class SuppressFindingRequest(BaseModel):
    fingerprint: str
    reason: str = ""
