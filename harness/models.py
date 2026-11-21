from __future__ import annotations
from typing import Literal, Optional
from pydantic import BaseModel, Field, computed_field


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
    # Trusted transport identifier set by the capture driver (eval harness /
    # Burp extension), NOT agent-authored JSON. Additive/optional for
    # back-compat: empty for older callers, which fall back to a content
    # hash of the exchange (see cache.ExchangeCache.compute_exchange_hash).
    capture_id: str = ""
    # I02-C / I07 shared capture contract. All optional: an absent value means
    # unknown and is never fabricated. `captured_at` is when the exchange was
    # captured (epoch seconds), kept apart from when the harness ingested it;
    # `state_version` is a supplied application state/version label, never
    # inferred from the body; `completeness` says whether the bodies are whole.
    # Unset values are left out of model_dump(), so an exchange without them
    # dumps exactly as before (several plan ids hash the dump).
    captured_at: Optional[float] = Field(default=None, ge=0, allow_inf_nan=False,
                                         exclude_if=lambda v: v is None)
    capture_source: str = Field(default="", max_length=128, exclude_if=lambda v: v == "")
    completeness: Literal["complete", "truncated", "binary_unsupported", "unknown"] = Field(
        default="unknown", exclude_if=lambda v: v == "unknown")
    state_version: Optional[str] = Field(default=None, max_length=128,
                                         exclude_if=lambda v: v is None)


# Marker a crawler puts in `analyst_note` when the request body it sent was a
# guess (no schema, no form): its field names are not known parameters of the
# endpoint. Prompts must not present such a body as the endpoint's inputs, or
# the model names the guessed keys as vulnerable parameters (r7).
PLACEHOLDER_BODY_NOTE = "request body is a harness-guessed placeholder, not the endpoint's known parameters"


def body_is_placeholder(body: str) -> bool:
    """True when `body` is one the role crawler guesses (role_crawl._synthesize_body);
    such a body also reaches worklist templates, which carry no analyst note."""
    from harness.role_crawl import synthesized_bodies  # (cycle: it imports us)
    return bool((body or "").strip()) and body.strip() in synthesized_bodies()


def request_body_is_placeholder(exchange) -> bool:
    """True when `exchange`'s request body was guessed by the harness."""
    body = getattr(exchange, "request_body", "") or ""
    return bool(body) and (PLACEHOLDER_BODY_NOTE in (getattr(exchange, "analyst_note", "") or "")
                           or body_is_placeholder(body))


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

    # Originating-case coordinates (T01).  Harness producers may supply
    # authoritative values; the orchestrator derives a stable invocation-local
    # finding_id when a finding has none.  An agent's JSON never sets
    # finding_id, request_template_id or workflow_state_id, and its principal_id
    # stands only when it names a session principal of the run (ARC-5,
    # sanitize_agent_finding).  proof_id/case_id are populated only after the
    # exact finding's proof is durably persisted.
    finding_id: str = ""
    principal_id: str = ""
    request_template_id: str = ""
    parameter_location: str = ""
    parameter_name: str = ""
    # Set only by the coverage case driver: the leg tests the named parameter and
    # nothing else, so its negative is bound to that parameter (never by a model).
    parameter_only: bool = False
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
    # I04: harness-owned guidance for a candidate that needs a manual check
    # (copy-ready steps). Not confirmation; agents can never set it.
    manual_verification: str = ""
    # E2: header_fingerprint of the response-header policy a csp/cors finding was
    # decided from, set by the harness (never an agent). Findings of one host-wide
    # policy share it; routes with different policies do not.
    header_fingerprint: str = ""

    @computed_field
    @property
    def evidence_maturity(self) -> str:
        from harness.confirmation_gate import finding_triage
        return finding_triage(self)["evidence_maturity"]

    @computed_field
    @property
    def triage_priority(self) -> str:
        from harness.confirmation_gate import finding_triage
        return finding_triage(self)["triage_priority"]

    @computed_field
    @property
    def impact_severity(self) -> str:
        return self.original_severity or self.severity


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
    "evidence_maturity", "triage_priority", "impact_severity",
    "confirmed", "proof_id", "case_id", "review_verdict", "review_note",
    "original_confidence", "original_severity", "original_vulnerability_class",
    "shape_inconsistent", "confirmed_by_leg",
    "oracle_verified", "verification_state", "oracle_capsule_id", "oracle_reason",
    "manual_verification", "parameter_only",
})


# ARC-5: the only fields an agent's JSON may set -- its hypothesis. Everything
# else on Finding is the harness's: the R02 authority fields above, and the case
# identity (finding_id, request_template_id, workflow_state_id) that keys case
# refs and proofs. An allowlist, so a field added to Finding later stays the
# harness's until it is listed here. principal_id is listed but stands only when
# it names a session principal of the run (session_principal_ids), because it
# keys the stored fingerprint that tester suppressions match.
AGENT_SETTABLE_FIELDS = frozenset({
    "vulnerability_class", "confidence", "summary", "evidence", "suggested_test",
    "basis", "severity", "owasp_category", "validation_hints",
    "parameter_location", "parameter_name", "principal_id",
})
assert not AGENT_SETTABLE_FIELDS & AGENT_AUTHORITY_FIELDS


def session_principal_ids(run_context=None) -> frozenset[str]:
    """The principals of the run's sessions (default: the run whose `async with`
    encloses this call). Empty when there is no run: then no agent-named
    principal stands."""
    if run_context is None:
        from harness.run_context import current_run_context
        run_context = current_run_context()
    try:
        return frozenset(s.principal_id for s in run_context.sessions.all() if s.principal_id)
    except Exception:
        return frozenset()


def sanitize_agent_finding(raw: dict, *, principals: frozenset[str] | None = None) -> dict:
    """Keep only the fields an agent may set (AGENT_SETTABLE_FIELDS, ARC-5) of one
    raw finding dict parsed from an agent's JSON output, before it is passed to
    Finding(**...). Every harness-owned field is dropped: the R02 authority
    fields (confirmed, proof_id, ...) and the case identity (finding_id,
    request_template_id, workflow_state_id), so a model can neither mint a
    confirmation nor choose the id two findings share a case under. A
    principal_id stands only when it is one of `principals` (default: the
    current run's session principals); otherwise it is dropped, before the
    finding is ever fingerprinted."""
    clean = {k: v for k, v in raw.items() if k in AGENT_SETTABLE_FIELDS}
    if "principal_id" in clean:
        allowed = session_principal_ids() if principals is None else principals
        if not (isinstance(clean["principal_id"], str) and clean["principal_id"] in allowed):
            del clean["principal_id"]
    # The parameter a finding names steers which injection point a leg tests
    # first. A model writing null or a non-string there must not fail the whole
    # report on Finding's str type, so anything unusable becomes "unnamed".
    for key in ("parameter_location", "parameter_name"):
        if key in clean:
            value = clean[key]
            clean[key] = value.strip()[:200] if isinstance(value, str) else ""
    return clean


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
    # E8 -- body-character budget this agent's prompt actually used, recorded
    # ONLY when it was lowered below the shared max_body_chars (a header-only
    # agent such as cors/csp). None means the agent saw the normal budget, so
    # a reviewer can tell a shortened body from a full one.
    input_body_chars: Optional[int] = None
    # Context-window fit (harness/prompt_budget.py): None when the prompt was sent
    # as built (no budget configured, or it fitted). Otherwise the budget, the
    # estimated tokens before/after, `fits`, and `elided`: each part left out or
    # shortened (methodology notes, shared rules, specialty sections or text,
    # prior findings, request/response body with original and kept characters).
    prompt_fit: Optional[dict] = None


class ObservationAttribution(BaseModel):
    """Analyst-declared labels for a supplied capture (I02-C). An unverified
    operator assertion, never derived from credentials; an absent field stays
    unknown. Labels that look like credentials are rejected by the store."""
    principal_ref: Optional[str] = Field(default=None, max_length=64)
    role: Optional[str] = Field(default=None, max_length=64)
    tenant: Optional[str] = Field(default=None, max_length=64)
    session_ref: Optional[str] = Field(default=None, max_length=64)


class AnalysisRequest(BaseModel):
    exchange: HttpExchange
    # Explicit snapshot partition. Omitted calls use their fresh run identity.
    engagement_id: str = Field(default="", max_length=128)
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
    # I02-C: optional analyst-declared attribution for this capture (who/which
    # tenant it belongs to). Stored as revision 1 of the observation's
    # attribution; correct it later with POST /observations/{id}/attribution.
    observation_attribution: Optional[ObservationAttribution] = None


class ObservationAttributionCorrection(ObservationAttribution):
    """Body of POST /observations/{id}/attribution: a complete new revision."""
    engagement_id: str = Field(default="", max_length=128)
    expected_revision: int = Field(ge=1)
    reason: str = Field(default="", max_length=200)


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


# ARC-4: the statuses an execution plane may report over POST /validation-results.
# The in-process harness path (orchestrator_confirm) still builds the base
# ValidationSubmission with its validators' own status words; only the HTTP
# boundary is closed, so an unknown status from the plane is a 422, never stored.
PlaneResultStatus = Literal["confirmed", "supported", "rejected", "not_confirmed",
                            "inconclusive", "invalid", "error"]


class PlaneValidationSubmission(ValidationSubmission):
    """A result from the Burp execution plane. `dispatch_nonce` is the single-use
    value POST /test-plans/{plan_id}/dispatch issued for this run of the plan."""
    status: PlaneResultStatus
    dispatch_nonce: str = Field(default="", max_length=128)


class PlanDispatchRequest(BaseModel):
    """POST /test-plans/{plan_id}/dispatch: the exchange binding the plane holds
    for the plan, checked against the stored plan before a nonce is issued."""
    source_exchange_hash: str = Field(default="", max_length=128)


class ValidationReport(BaseModel):
    validator: str
    status: str
    finding_class: str
    confidence: float = 0.0
    confirmed: bool = False
    summary: str = ""
    evidence: str = ""
    # FR-5 (F09): case-identity coordinates for this validation attempt, so a
    # controlled negative can be bound to the SAME case (parameter) it actually
    # tested rather than just its class. Optional/default-empty for backward
    # compatibility -- every pre-existing constructor call and serialized form
    # stays valid; an empty `parameter` is treated as a class-level (not
    # parameter-scoped) negative by confirmation_gate.apply_confirmation_suppression.
    url: str = ""
    method: str = ""
    parameter: str = ""
    # SC-3: the principal (identity) this validation attempt ran under, so a
    # controlled negative recorded under one principal cannot refute a finding
    # discovered under a DIFFERENT principal of the same class/parameter.
    # Optional/default-empty for backward compatibility.
    principal_id: str = ""
    # R2/RA-7/EFF-1: carried from ValidationResult.control_outcome (values in
    # harness/control_outcome.py). Only "control_held" = genuine held control,
    # which the suppression gate may count as a refutation. Empty (the validator
    # did not say), "control_failed", "not_run", "inconclusive" and the
    # "named_parameter_untested" / "partial_coverage" markers
    # (validators/injection_targets.py) all leave the finding unverified.
    control_outcome: str = ""
    # I04: manual-check guidance carried from ValidationResult (empty if none).
    manual_verification: str = ""


class StageOutcome(BaseModel):
    """Typed health outcome for one pipeline stage (e.g. the critique pass).

    R08/PR-7: before this existed, AnalysisPipeline._critique() returned a bare
    (0, 0) tuple on THREE different situations -- critique disabled by config,
    a genuinely healthy pass that reviewed 0 candidates (none met the
    confidence threshold), and a FAILED pass where the model call raised
    (OllamaError or any other Exception), so every candidate finding shipped
    UNREVIEWED. All three looked identical to a caller, and a circuit breaker
    that had not tripped was not enough to tell them apart (a single transient
    error is invisible to the breaker's threshold). `status` makes the three
    cases distinguishable; `attempted`/`completed`/`failed` and
    `affected_finding_ids` say exactly what happened and to which findings,
    instead of a silent, indistinguishable 0.

    `status`:
      - "completed": the stage ran to completion (including legitimately
        having nothing to do, e.g. 0 candidates above threshold).
      - "failed": the stage raised/errored; its output (if any) was shipped
        anyway, unreviewed -- see `affected_finding_ids`.
      - "skipped": the stage was bypassed for a reason other than config
        (e.g. an earlier stage's result made it moot).
      - "disabled": the stage is turned off in config.
    """
    name: str
    status: Literal["completed", "failed", "skipped", "disabled"]
    attempted: int = 0
    completed: int = 0
    failed: int = 0
    reason: Optional[str] = None
    affected_finding_ids: list[str] = Field(default_factory=list)
    # Context-window fit of this stage's prompt, as AgentReport.prompt_fit.
    prompt_fit: Optional[dict] = None


class AnalysisResponse(BaseModel):
    engagement_id: str = ""
    captured_principal_id: str = ""
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
    # Compatibility scalar above is a known lower bound when False; None means
    # an older/uninstrumented response supplied no completeness declaration.
    effort_usage_complete: bool | None = None
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
    # R08/PR-7: the typed per-stage health record(s) for this analysis (currently
    # just critique -- one StageOutcome per run_full_analysis call this exchange
    # made, e.g. one for the first dispatch batch and one for the early-termination
    # remainder). See StageOutcome above for what distinguishes "completed with 0
    # reviewed", "disabled" and "failed". Additive/default-empty: a caller that
    # predates this field simply sees an empty list, exactly as before.
    stage_outcomes: list[StageOutcome] = Field(default_factory=list)
    # R08/PR-7: True when this result is degraded -- some stage FAILED (see
    # stage_outcomes) and shipped its input unreviewed, OR the shared ollama
    # circuit breaker was open (agents_circuit_open, B2-1). Deliberately reuses
    # agents_circuit_open rather than duplicating its semantics: `degraded` is
    # the single OR of every known health signal, so a reader only has to check
    # one field to know "was this run's output fully trustworthy". Findings are
    # NEVER dropped because of degradation -- they still ship, just flagged.
    # Default False so a healthy run (the overwhelming common case) is
    # byte-for-byte unchanged from before this field existed.
    degraded: bool = False
    # X08: True when SOME, but not all, dispatched model agents failed. Such a
    # run is also `degraded`; this distinguishes it from a total model outage
    # (every model agent failed, which leads the summary with a warning).
    # Deterministic/rule-based reports never count as model agents here.
    partial_inference: bool = False
    # Top-level, structured mirror of every dispatched agent's raw_error ("<agent>:
    # <error>"). Previously an agent failure (e.g. the model backend being down)
    # was recorded ONLY in the per-agent raw_error buried inside agent_reports, so
    # a run where every LLM agent failed still returned a normal-looking 200 with
    # a few deterministic hits. This surfaces the failures where a caller/UI can
    # see them without walking agent_reports; empty on a clean run. When any
    # dispatched model agent errored, `degraded` is also True and the summary
    # leads with an explicit warning (all failed, or `partial_inference`).
    agent_errors: list[str] = Field(default_factory=list)
    # I02-C: what earlier observations this analysis was given and whether this
    # capture was retained: {status, write, selected [{observation_id, reason,
    # order_basis}], unavailable, excluded_counts, digest}. Empty for callers
    # that do not retain observations (engagement- and discovery-driven runs).
    observation_context: dict = Field(default_factory=dict)


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
    engagement_id: str = Field(default="", max_length=128)
    items: list[PrioritizeRequestItem]


class PrioritizeResultItem(BaseModel):
    method: str
    url: str
    ai_priority: str  # "critical" | "high" | "medium" | "low" | "unscored"
    ai_score: float = Field(ge=0.0, le=1.0)
    reasoning: str


class PrioritizeResponse(BaseModel):
    engagement_id: str = ""
    results: list[PrioritizeResultItem]


class EffortStatus(BaseModel):
    mode: str
    total_tokens: Optional[int] = None
    spent_tokens: int = 0
    remaining_tokens: Optional[int] = None
    exhausted: bool = False
    breakdown: dict[str, int] = Field(default_factory=dict)
    # spent_tokens/breakdown are known lower bounds when any count is missing.
    usage_complete: bool = True
    tokens_lower_bound: bool = False
    pending_admission_tokens: int = 0
    unmeasured_admission_tokens: int = 0
    call_counts: dict[str, int] = Field(default_factory=dict)


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
