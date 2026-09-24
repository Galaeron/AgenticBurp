"""orchestrator_helpers.py -- shared imports, module constants, and free helper
functions lifted out of orchestrator.py (W-15 decomposition).

LEAF MODULE: it imports only external / sibling modules, never the mixin modules
or the Orchestrator class, so orchestrator_detect/confirm/chain/report and
orchestrator.py can each `from orchestrator_helpers import *` with no import cycle.
The trailing __all__ re-exports every top-level name (including underscore-prefixed
helpers/constants and the imported sibling modules) so that star-import reconstitutes
the exact namespace orchestrator.py used to expose -- keeping existing
`from orchestrator import <helper>` and `orchestrator.<helper>` call sites working.
"""
from __future__ import annotations
import asyncio
import logging
import re
from urllib.parse import urlparse, urlsplit

import httpx
from harness import global_throttle
from harness import host_dep_dedup

from harness.ollama_client import OllamaClient, OllamaError
from harness.models import (
    HttpExchange,
    AnalysisResponse,
    AgentReport,
    Finding,
    UrlEstimateItem,
    EffortStatus,
    ComponentCandidate,
    StageOutcome,
)
from harness import store
from harness import evidence
from harness import chaining
from harness import planner
from harness import effort
from harness.effort import BudgetMode, CallKind, EffortBudget
from harness import security
from harness import cache
from harness import fast_path
from harness import scope_discovery
from harness import credential_endpoint_detector
from harness.agent_manager import AgentManager
from harness import coordinator
from harness.coordinator import Coordinator
from harness.analysis_pipeline import AnalysisPipeline
from harness.github_advisories import GitHubAdvisoryClient
from harness.package_registry_checks import PackageRegistryClient
from harness.kev_check import KevClient
from harness.validators import ValidatorRegistry
from harness.models import ValidationReport, ValidationSubmission

log = logging.getLogger("harness.orchestrator")

# Confidence an access-control finding is capped to when an ACTIVE cross-identity
# probe deterministically rejected it (control held). Same value/rationale as
# access_control_gate._CAPPED_CONFIDENCE: below the reporting/critique gate (0.5),
# non-zero so the observation is retained for audit.
_CROSS_IDENTITY_REJECT_CAP = 0.15


# This is the coordinator's only real lever: which specialists even get a
# look at this exchange. Get it wrong and a finding is dropped before any
# agent sees it, silently -- so the prompt encodes what's actually shifted
# in reported vulnerability data over 2021-2025 (HackerOne's Hacker-Powered
# Security Report, Intigriti trend data, CWE/CVE frequency stats), not just
# "here are eight categories, guess." None of this replaces judgment on the
# specific exchange -- it's a prior, not a rule.
_ROUTING_SYSTEM_PROMPT = """
You are the coordinator in a security-testing harness. You are shown one
HTTP request/response pair and a list of available specialist agents.
Decide which specialists are worth dispatching -- i.e. which vulnerability
classes this specific exchange plausibly touches. Do not dispatch a
specialist just because it exists; dispatching all of them on every
exchange wastes the analyst's time and buries real findings in noise.
Do not dispatch a specialist just because its category is currently
trending industry-wide if nothing in THIS exchange suggests it applies.

Background on where reported vulnerabilities have actually concentrated
in bug bounty and CVE data over the past several years -- use this to
break ties and catch categories that are easy to overlook, not to
override what the exchange itself shows:
- Access control issues (broken object/function-level authorization,
  IDOR variations, missing authorization / CWE-862) and security
  misconfiguration have both been rising and now outrank classic
  payload-based bugs in reported volume for many programs. They are
  also the easiest categories to miss, because there's no single
  "signature" to pattern-match the way there is for XSS/SQLi -- any
  endpoint that reads or mutates a specific resource, or that exposes
  config/debug/admin surface, is a candidate.
- Cross-site scripting and SQL injection remain common (CWE-79 and
  CWE-89 are still at or near the top of CWE frequency lists) but have
  declined somewhat from their peak as frameworks increasingly
  auto-escape and parameterize by default -- still worth checking
  whenever there's reflected input or a query-shaped parameter, just
  not the automatic first guess anymore.
- Business logic and workflow-level flaws (multi-step processes, client-
  supplied state/price/role fields, race-condition-prone actions like
  redemption or transfers) are increasingly where the highest-severity
  findings come from, precisely because they require understanding what
  the flow is supposed to enforce rather than recognizing a payload.
- AI/LLM-feature vulnerabilities (prompt injection, insecure handling of
  model output, excessive agency) are the fastest-growing category by a
  wide margin where an exchange touches a chat/assistant/completion-
  style feature -- but irrelevant, and should not be dispatched, for
  exchanges that clearly don't.
- SSRF risk concentrates around any parameter that looks like it holds a
  URL, hostname, or callback address, especially given how much
  infrastructure now sits behind cloud metadata endpoints.
- Supply-chain/dependency exposure (version banners, exposed lockfiles/
  manifests, exposed CI/CD config including GitHub Actions workflows) is
  worth dispatching whenever a response looks like it might reveal a
  component version or serve a config/manifest file directly -- this
  agent also feeds a deterministic, non-LLM lookup against the GitHub
  Advisory Database, so dispatching it costs little even when the
  exchange turns out not to touch this category.

Respond with ONLY a JSON object of this shape, no prose outside it:
{"dispatch": ["sqli", "xss"], "reason": "one sentence why these and not the others"}

Only use agent names from the provided list.
"""

# NOTE: this module used to also define _CRITIQUE_SYSTEM_PROMPT,
# _CRITIQUE_CONFIDENCE_THRESHOLD, and _MAX_FINDINGS_TO_CRITIQUE here,
# backing an Orchestrator._critique() method -- removed as confirmed
# dead code (grep for "self._critique(" across the whole harness/
# directory returns zero call sites). The critique pass that actually
# runs in the real analyze() flow is AnalysisPipeline._critique() in
# analysis_pipeline.py, which has its own separate copy of this same
# system prompt and thresholds. Found while fixing a live bug in the
# critique prompt itself (see analysis_pipeline.py's _critique) --
# editing THIS file's now-deleted copy would have had zero effect on
# the real bug, exactly the kind of trap this note exists to prevent
# for whoever touches critique logic next.


_REDISCOVERY_SYSTEM_PROMPT = """
You are performing an OPT-IN independent re-analysis. The analyst has
already been shown that a component in this exchange matches a known,
disclosed vulnerability (a real GHSA/CVE advisory, looked up
deterministically -- not something you need to verify exists). They have
explicitly chosen to spend extra effort having you look deeper anyway,
rather than stopping at "known, confirmed."

Your job is NOT to re-confirm the advisory exists -- that's already
established with more certainty than you could add. Your job is to look
at THIS SPECIFIC exchange for anything the generic advisory text
wouldn't tell the analyst:
- Evidence in the response that the vulnerable code path is actually
  reachable/exercised here, not just that the version is present.
- Any sign the version banner might be misleading (a common mitigation
  is patching without bumping the reported version string -- if you see
  anything suggesting that, say so).
- Anything specific to this application's configuration that would
  change how exploitable the known issue actually is here (compared to
  a generic deployment).

If you find nothing beyond what the advisory already says, say that
plainly -- "no additional exchange-specific evidence beyond the known
advisory" is a complete, honest, useful answer, not a failure to find
something. Do not manufacture exploitability detail that isn't visible
in what you're shown.

Respond with ONLY JSON:
{"findings": [
  {"vulnerability_class": "...", "confidence": 0.0-1.0, "severity": "info|low|medium|high|critical",
   "owasp_category": null, "summary": "...", "evidence": "...",
   "suggested_test": "...", "basis": "derived|recalled|assumed"}
]}
Return an empty findings list if you found nothing beyond the known advisory.
"""


def _exchange_text(exchange: HttpExchange) -> str:
    from harness.exchange_text import exchange_text
    return exchange_text(exchange)


def _verify_component_observation(component: ComponentCandidate, exchange: HttpExchange) -> ComponentCandidate:
    """Reject the dangerous LLM-only premise before any external lookup.

    A real advisory match is authoritative about the package, but not about
    whether that package/version exists in this target. Require the extracted
    identity to be literally observable in the captured exchange.
    """
    text = _exchange_text(exchange).lower()
    name = component.name.strip().lower()
    version = (component.version or "").strip().lower()
    name_ok = bool(name) and name in text
    version_ok = not version or version in text
    component.observed_in_exchange = name_ok and version_ok
    if component.observed_in_exchange:
        component.verification_note = "component name/version literally observed in captured exchange"
    else:
        missing = []
        if not name_ok:
            missing.append("name")
        if version and not version_ok:
            missing.append("version")
        component.verification_note = "not independently verified; missing literal " + ", ".join(missing)
    return component


# --- proactive, precondition-driven confirmation-leg routing (HANDOVER_6 §4) ----
# The coupling fix: which confirmation legs an ENDPOINT'S SHAPE warrants, chosen
# independently of whether an agent flagged that class. Module-level + pure so the
# routing is unit-testable without a live model (the historical "green tests, dead
# pipeline" failure mode lived exactly in code like this that no test exercised).
_JWT_HDR_RE = re.compile(r"\beyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*")
_URL_PARAM_RE = re.compile(r"https?://|%2f%2f", re.IGNORECASE)


def _carries_jwt(headers: dict | None) -> bool:
    return any(_JWT_HDR_RE.search(v or "") for v in (headers or {}).values())


def _jwt_identity(node: dict, roles):
    """The lowest-trust reachable identity carrying a JWT (a broken verifier proven
    from the weakest role is the stronger result), or None. Falls back to any
    JWT-carrying identity when the node lists no reachable roles."""
    from harness import worklist_investigator
    reach = node.get("reachable_roles") or []
    reachable = sorted((r for r in roles if r.role in reach),
                       key=lambda r: worklist_investigator._trust(r.role))
    for r in (reachable or list(roles)):
        if _carries_jwt(r.headers):
            return r
    return None


def _is_state_changing(exchange: HttpExchange) -> bool:
    return (exchange.method or "GET").upper() in ("POST", "PUT", "PATCH", "DELETE")


def _lacks_csrf_token(exchange: HttpExchange) -> bool:
    """True when a state-changing request carries no recognisable CSRF token."""
    if not _is_state_changing(exchange):
        return False
    import re
    _csrf_re = re.compile(
        r"(csrf|xsrf|_token|authenticity_token|__RequestVerificationToken"
        r"|csrfmiddlewaretoken|_csrf_token|anti.?forgery|nonce)", re.I)
    body = exchange.request_body or ""
    url = exchange.url or ""
    headers = exchange.request_headers or {}
    for source in (body, url):
        if _csrf_re.search(source):
            return False
    for name in headers:
        if _csrf_re.search(name):
            return False
    return True


def _has_settable_body(exchange: HttpExchange) -> bool:
    """POST/PUT/PATCH with a JSON object or form body — mass-assignment target."""
    if (exchange.method or "GET").upper() not in ("POST", "PUT", "PATCH"):
        return False
    body = (exchange.request_body or "").strip()
    if not body:
        return False
    if body.startswith("{"):
        return True
    if "=" in body and not body.startswith(("<", "[")):
        return True
    return False


def _identity_signature(request_headers: dict | None) -> str:
    """A stable fingerprint of the PRINCIPAL a request authenticates as -- its
    Authorization value plus its Cookie header. Part of the confirmation cache key
    so the same URL/body probed AS DIFFERENT identities does not collide (R03)."""
    import hashlib
    hdrs = request_headers or {}
    auth = "".join(f"{(k or '').lower()}={v};" for k, v in hdrs.items()
                   if (k or "").lower() in ("authorization", "cookie"))
    return hashlib.md5(auth.encode("utf-8", errors="replace")).hexdigest()


def confirmation_cache_key(validator_name: str, exchange: HttpExchange,
                           finding_class: str | None = None) -> tuple:
    """The within-run memoisation key for a confirmation leg (R03).

    Includes the IDENTITY (auth headers) and the finding CLASS/subtype, not just
    (validator, method, url, body): different cookies/bearer tokens, and different
    hypothesised subclasses, are DIFFERENT cases. Keying only on url/body replayed
    an administrator's confirmation into another identity's cell, or a skip into a
    valid request."""
    import hashlib
    method = (exchange.method or "GET").upper()
    url = exchange.url or ""
    body = exchange.request_body or ""
    body_hash = hashlib.md5(body.encode("utf-8", errors="replace")).hexdigest()
    identity_sig = _identity_signature(exchange.request_headers)
    fc = (finding_class or "").lower()
    return (validator_name, method, url, body_hash, identity_sig, fc)


async def bounded_gather(coros, limit: int, *, return_exceptions: bool = True):
    """asyncio.gather with a concurrency CAP (R29): at most `limit` coroutines run
    at once. Preserves input order in the results, like gather."""
    sem = asyncio.Semaphore(max(1, int(limit)))

    async def _one(c):
        async with sem:
            return await c
    return await asyncio.gather(*[_one(c) for c in coros], return_exceptions=return_exceptions)


def second_order_identities(roles) -> tuple[dict, dict | None]:
    """Pick the (planter, other) identities for a second-order confirmation (R13).

    The planter is the first AUTHENTICATED role -- the attacker/owner that PLANTS
    the stored value (anonymously planting is not a valid authenticated workflow);
    `other` is a DISTINCT authenticated role for the cross-identity IDOR read (None
    when only one authenticated identity exists, in which case the IDOR leg must
    not run a self-comparison). Returns (planter_headers, other_headers)."""
    authed = [r for r in (roles or [])
              if (getattr(r, "role", "") or "").lower() != "anonymous" and getattr(r, "headers", None)]
    planter = dict(authed[0].headers) if authed else {}
    other = None
    for r in authed[1:]:
        # distinct principal by credentials
        if dict(r.headers) != planter:
            other = dict(r.headers)
            break
    return planter, other


def coverage_confirmation_finding(res, check, url: str, identity: str) -> dict | None:
    """Map a CONFIRMED coverage-driven ValidationResult to a finding dict for the
    NORMAL ingestion path (R06). Returns None unless the result is a confirmation.

    A coverage-driven leg that confirms must reach state/worklist/report/persistence
    like any other confirmed finding -- recording only a matrix cell left a
    matrix-confirmed vulnerability invisible to the analyst's confirmed findings."""
    if res is None or not getattr(res, "confirmed", False):
        return None
    return {
        "vulnerability_class": getattr(res, "finding_class", None) or check.vulnerability_class,
        "confirmed": True,
        "confidence": getattr(res, "confidence", None) or 0.9,
        "severity": "high",
        "summary": (getattr(res, "summary", "") or
                    f"Coverage-driven {check.confirmation} leg confirmed on {url}"),
        "evidence": getattr(res, "evidence", "") or "",
        "confirmation_method": getattr(res, "validator", None) or check.confirmation,
        # Step 4 (2026-09-17 coverage-recovery plan): the SAME structured field
        # name the graph-driven path (_validate_findings) stamps, so a
        # confirmation's provenance is identical shape regardless of which
        # dispatcher produced it -- a coverage-driven confirm previously only
        # carried this leg name under confirmation_method, a key the graph
        # path never wrote, so a single provenance reader had to know which
        # path produced a given finding.
        "confirmed_by_leg": getattr(res, "validator", None) or check.confirmation,
        "url": url,
        "identity": identity,
        "basis": "derived",
    }


def _accepts_xml(exchange: HttpExchange) -> bool:
    ctype = " ".join(v for k, v in (exchange.request_headers or {}).items()
                     if k.lower() == "content-type").lower()
    body = (exchange.request_body or "").lstrip()[:64].lower()
    return "xml" in ctype or body.startswith("<?xml") or body.startswith("<!doctype")


def _has_url_param(exchange: HttpExchange) -> bool:
    blob = (urlsplit(exchange.url).query or "") + " " + (exchange.request_body or "")
    return bool(_URL_PARAM_RE.search(blob))


def _has_injectable_param(exchange: HttpExchange) -> bool:
    """Any query/body parameter to inject a shell/template payload into."""
    from harness.validators.injection_targets import param_targets
    return bool(param_targets(exchange))


def _has_file_shape(exchange: HttpExchange) -> bool:
    """A file/path-shaped parameter, or a file-ish path segment (e.g. /uploads/<id>).
    Reuses the path-traversal validator's own detectors so the routing decision and
    the leg's own targeting never drift."""
    from harness.validators.path_traversal_validator import _file_shaped, _fileish_segment
    return bool(_file_shaped(exchange)) or _fileish_segment(exchange.url)


def _has_redirect_param(exchange: HttpExchange) -> bool:
    """A redirect-shaped parameter to point off-origin."""
    from harness.validators.open_redirect_validator import _redirect_params
    return bool(_redirect_params(exchange))


def _has_pickle_shape(exchange: HttpExchange) -> bool:
    """A cookie/param whose value base64-decodes to pickle bytes -- a
    deserialization sink. Reuses the deser leg's own detector so routing and the
    leg never drift."""
    from harness.validators.deserialization_oob_validator import DeserializationOobValidator
    return bool(DeserializationOobValidator()._sink_candidates(exchange))


def shape_precondition_legs(node: dict, exchange: HttpExchange, roles, base_url: str,
                            id_fill: str = "1") -> list[tuple[str, HttpExchange]]:
    """The proactive confirmation legs an endpoint's shape warrants, as
    (vulnerability_class, seed_exchange) pairs to run REGARDLESS of agent labels:

      - object-scoped GET            -> cross-identity replay (idor)
      - JWT-carrying protected GET   -> jwt-forge (seeded from a JWT-bearing role)
      - XML-accepting request body   -> xxe (OOB)
      - URL-shaped param present      -> ssrf (OOB)
      - settable JSON/form body on a mutating method -> mass-assignment
        (write-then-re-read differential, sequence validator)

    The xxe/ssrf/mass-assignment legs need a real body/param, which route-
    discovery seeds don't carry, so they fire only on a captured exchange that
    actually has that shape (real Burp use) -- never as a blind guess from a
    bare route. Mass-assignment was previously only reachable through
    `shape_precondition_findings` (the analyze()/captured-exchange path) -- a
    settable-body node the graph loop investigated on its own (e.g.
    /api/account/profile, /api/register) got NO shape-driven confirmation leg
    at all unless an agent happened to label it `mass_assignment` itself,
    reproducing the exact detection->confirmation coupling this module exists
    to remove for every other class (2026-09-17 coverage-recovery plan, Step 3)."""
    from harness import worklist_investigator
    method = (node.get("method") or "GET").upper()
    legs: list[tuple[str, HttpExchange]] = []
    if node.get("object_scoped") and method == "GET":
        legs.append(("idor", exchange))
    jid = _jwt_identity(node, roles)
    if jid is not None and method == "GET":
        legs.append(("jwt", worklist_investigator._seed_exchange(
            base_url, node, dict(jid.headers or {}), id_fill)))
    if _accepts_xml(exchange):
        legs.append(("xxe", exchange))
    if _has_url_param(exchange):
        legs.append(("ssrf", exchange))
    # Injection legs need a real captured param/body to mutate (like xxe/ssrf), so
    # they fire only on an exchange that actually carries one -- never on a bare
    # route seed. Confirmation is kept only where the leg CONFIRMS, so breadth here
    # adds no unconfirmed noise, just cost.
    if _has_injectable_param(exchange):
        legs.append(("command_injection", exchange))
        legs.append(("ssti", exchange))
    if _has_file_shape(exchange):
        legs.append(("path_traversal", exchange))
    if _has_redirect_param(exchange):
        legs.append(("open_redirect", exchange))
    if _has_pickle_shape(exchange):
        legs.append(("deserialization", exchange))
    if _has_settable_body(exchange):
        legs.append(("mass_assignment", exchange))
    return legs


# Agent name carried by the synthetic report that holds analyze()'s proactive,
# shape-driven confirmation legs. Used to find and prune them after validation.
_SHAPE_LEG_AGENT = "shape_precondition"


def shape_precondition_findings(exchange: HttpExchange) -> list[Finding]:
    """The proactive confirmation legs a CAPTURED exchange's own shape warrants,
    as synthetic low-confidence Findings -- the analyze() analogue of
    `shape_precondition_legs` for the graph path. Appended to the reports BEFORE
    validation so the active validator runs REGARDLESS of whether an agent
    flagged that class (decoupling confirmation from detection), then kept ONLY
    where a validator confirmed (see analyze()), so shape is a reason to TRY a
    leg, never a source of unconfirmed noise.

    Only the legs that need a real captured body/param belong here: XXE (an
    XML-accepting body) and SSRF (a URL-shaped param). idor/jwt shape-routing
    lives in the graph path (`shape_precondition_legs`) where the seed
    identities needed to replay/forge are known; analyze() has just the one
    captured request and identity."""
    out: list[Finding] = []
    if _accepts_xml(exchange):
        out.append(Finding(
            vulnerability_class="xxe", confidence=0.3, severity="high",
            summary=f"XXE precondition: {exchange.url} accepts an XML request body",
            evidence="", suggested_test="", basis="derived"))
    if _has_url_param(exchange):
        out.append(Finding(
            vulnerability_class="ssrf", confidence=0.3, severity="high",
            summary=f"SSRF precondition: URL-shaped parameter on {exchange.url}",
            evidence="", suggested_test="", basis="derived"))
    # Injection legs: a captured param/body is enough shape to TRY them; kept only
    # if the validator confirms (analyze() prunes shape legs to confirmed-only).
    if _has_injectable_param(exchange):
        out.append(Finding(
            vulnerability_class="command_injection", confidence=0.3, severity="high",
            summary=f"Command-injection precondition: injectable parameter on {exchange.url}",
            evidence="", suggested_test="", basis="derived"))
        out.append(Finding(
            vulnerability_class="ssti", confidence=0.3, severity="high",
            summary=f"SSTI precondition: injectable parameter on {exchange.url}",
            evidence="", suggested_test="", basis="derived"))
    if _has_file_shape(exchange):
        out.append(Finding(
            vulnerability_class="path_traversal", confidence=0.3, severity="high",
            summary=f"Path-traversal precondition: file/path-shaped target on {exchange.url}",
            evidence="", suggested_test="", basis="derived"))
    if _has_redirect_param(exchange):
        out.append(Finding(
            vulnerability_class="open_redirect", confidence=0.3, severity="medium",
            summary=f"Open-redirect precondition: redirect-shaped parameter on {exchange.url}",
            evidence="", suggested_test="", basis="derived"))
    if _has_pickle_shape(exchange):
        out.append(Finding(
            vulnerability_class="deserialization", confidence=0.3, severity="critical",
            summary=f"Deserialization precondition: base64-pickle value on {exchange.url}",
            evidence="", suggested_test="", basis="derived"))
    if _lacks_csrf_token(exchange):
        out.append(Finding(
            vulnerability_class="csrf", confidence=0.3, severity="medium",
            summary=f"CSRF precondition: state-changing {(exchange.method or 'POST').upper()} without anti-CSRF token on {exchange.url}",
            evidence="", suggested_test="", basis="derived"))
    if _has_settable_body(exchange):
        out.append(Finding(
            vulnerability_class="mass_assignment", confidence=0.3, severity="high",
            summary=f"Mass-assignment precondition: settable JSON/form body on {(exchange.method or 'POST').upper()} {exchange.url}",
            evidence="", suggested_test="", basis="derived"))
    return out


async def review_captured_exchanges(orch, state, captured, *, max_reviews: int = 200,
                                    run_context=None) -> int:
    """Phase 0.1: route every substantive 2xx captured during discovery through
    full content-level review and fold its findings into `state`.

    `role_crawl` fetches these response bodies but the access-matrix lens only
    asks "does this differ across identities?". A response correctly scoped to
    its authorized identity that itself leaks (a secret, PII, an internal path)
    produced NO signal there and was dropped without ever becoming an analyzable
    exchange -- a recall hole independent of what any one response contains. Here
    each capture goes through the full `analyze()` pipeline (agents + the
    deterministic confidential-info scan + validators), the same content review a
    captured Burp exchange gets, and its findings fold into the engagement state.

    `_from_discovery=True`: a capture is itself a discovery product, so its own
    analysis must not cascade into another scope-discovery pass (that guard also
    keeps this bounded -- one analyze per capture, not a recursive fan-out).

    Returns the count of captured exchanges that yielded >=1 finding."""
    produced = 0
    reviewed = 0
    for cap in list(captured or [])[:max_reviews]:
        try:
            ex = cap if isinstance(cap, HttpExchange) else HttpExchange(**cap)
        except Exception:
            continue
        reviewed += 1
        # R05: record the captured request template on its endpoint so the graph +
        # coverage replay the real body/query/content-type/object-id, not an empty
        # fabricated shape. Cheap and additive; failure must not sink the review.
        try:
            state.record_template(ex.url, ex.method, ex)
        except Exception:
            pass
        try:
            resp = await orch.analyze(ex, _from_discovery=True, run_context=run_context)
        except Exception as e:  # one capture's failure must not sink the rest
            log.debug("review_captured_exchanges: analyze failed on %s: %s",
                      getattr(ex, "url", "?"), e)
            continue
        findings = [f.model_dump() for r in resp.agent_reports for f in r.findings]
        if findings:
            state.ingest_findings(ex.url, ex.method, findings)
            produced += 1
    if reviewed:
        log.info("review_captured_exchanges: reviewed %d captured 2xx exchanges, "
                 "%d produced findings", reviewed, produced)
    return produced


async def universal_header_audit(orch, state, captured, *, max_exchanges: int = 200) -> int:
    """Universal header audit: run CORS, CSP, and verbose-error validators
    against EVERY captured exchange regardless of agent findings. This closes
    the passive analysis gap where header-level issues (CORS misconfiguration,
    missing CSP/X-Frame-Options, verbose errors) are missed because no LLM
    agent labelled the matching vulnerability class.

    Also scans verbose-error responses for disclosed paths and feeds them
    back into the engagement state for re-discovery.

    Returns the count of exchanges that produced at least one confirmed finding."""
    if not hasattr(orch, 'validator_registry') or orch.validator_registry is None:
        return 0

    audit_validators = orch.validator_registry.header_audit_validators()
    if not audit_validators:
        return 0

    from harness.validators.verbose_error_validator import (
        findings_from_exchange as _ve_findings,
        extract_disclosed_paths,
    )

    produced = 0
    for cap in list(captured or [])[:max_exchanges]:
        try:
            ex = cap if isinstance(cap, HttpExchange) else HttpExchange(**cap)
        except Exception:
            continue

        exchange_findings = []

        # Run the verbose-error detector (passive, no network)
        ve = _ve_findings(ex)
        if ve:
            exchange_findings.extend(ve)

        # Run active header-audit validators (CORS, CSP) if active mode is on
        for v in audit_validators:
            if v.name == "verbose_error_validator":
                continue  # already ran above
            try:
                dummy_finding = Finding(
                    vulnerability_class=next(iter(v.finding_classes)),
                    severity="medium", confidence=0.5,
                    summary=f"Universal header audit: {v.name}",
                    evidence="", suggested_test="", basis="derived",
                )
                result = await v.validate(dummy_finding, ex)
                if result.confirmed:
                    exchange_findings.append(Finding(
                        vulnerability_class=result.finding_class,
                        severity="medium",
                        confidence=result.confidence,
                        summary=result.summary,
                        evidence=result.evidence,
                        suggested_test="",
                        basis="derived",
                        confirmed=True,
                        confirmation_method=v.get_name(),
                    ))
            except Exception as e:
                log.debug("universal_header_audit: %s failed on %s: %s",
                          v.get_name(), getattr(ex, "url", "?"), e)

        if exchange_findings:
            state.ingest_findings(
                ex.url, ex.method,
                [f.model_dump() for f in exchange_findings])
            produced += 1

        # Feed disclosed paths from verbose errors back into discovery
        disclosed = extract_disclosed_paths(ex)
        if disclosed:
            import harness.engagement as _eng
            for p in disclosed:
                state._ep("GET", _eng.normalize_path(p))

    if produced:
        log.info("universal_header_audit: %d of %d exchanges produced header/error findings",
                 produced, min(len(captured or []), max_exchanges))
    return produced


# Re-export EVERY top-level name so `from orchestrator_helpers import *` gives the
# full namespace (star-import honours __all__, so underscore names come through too).
__all__ = [_n for _n in list(globals()) if not _n.startswith("__")]
