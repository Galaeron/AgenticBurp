"""orchestrator_helpers.py -- shared module constants and free helper functions
lifted out of orchestrator.py (W-15 decomposition).

LEAF MODULE: it imports only external / sibling modules, never the mixin modules or
the Orchestrator class, so orchestrator_detect/confirm/chain*/report and orchestrator.py
can import from it with no import cycle. ARC-9: every consumer imports the names it uses
explicitly (the old star-import namespace is gone); the capture-review passes now live in
orchestrator_review.py.
"""
from __future__ import annotations

import asyncio
import logging
import re
from urllib.parse import urlsplit

from harness.models import ComponentCandidate, Finding, HttpExchange


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
    from harness.engagement import principal_reached
    from harness.coverage_tracker import _principal_of
    # Each session is matched by its own principal cell (WL-02), so a same-role
    # principal that was denied is not chosen because another one reached.
    cells = node.get("access_by_principal") or {}
    reach = node.get("reachable_roles") or []
    reachable = sorted((r for r in roles
                        if principal_reached(cells, reach, _principal_of(r), r.role)),
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


def _browser_form_csrf_candidate(exchange: HttpExchange) -> bool:
    """Whether a captured write is a browser-form CSRF confirmation target.

    A present token is not proof of protection: applications sometimes validate
    it only for one HTTP method. Cookie-backed, form-shaped writes therefore
    warrant a bounded method-bypass check even when the original request carries
    a token. Bearer/JSON APIs stay out because a cross-site navigation cannot
    supply their Authorization header or JSON body.
    """
    if not _is_state_changing(exchange):
        return False
    headers = {str(k).lower(): str(v) for k, v in (exchange.request_headers or {}).items()}
    if "cookie" not in headers or "authorization" in headers:
        return False
    ctype = headers.get("content-type", "").lower()
    body = exchange.request_body or ""
    return "application/x-www-form-urlencoded" in ctype or ("=" in body and not body.lstrip().startswith("{"))


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


def _read_body_mass_assignment(exchange: HttpExchange) -> bool:
    """R11-6: a PUT/PATCH of one object with NO captured body (seen only through its
    route or GET). The sequence leg builds its body from the object's own read, so
    it gets a mass-assignment leg too (a guessed body already passes
    `_has_settable_body` and is routed to the same read-built path)."""
    from harness.validators.sequence_validator import needs_read_body
    return not _has_settable_body(exchange) and needs_read_body(exchange)


def _nosql_login_candidate(exchange: HttpExchange) -> bool:
    """A captured form login whose credential fields can carry Mongo operators."""
    if (exchange.method or "GET").upper() != "POST":
        return False
    if "login" not in (urlsplit(exchange.url or "").path or "").lower():
        return False
    ctype = " ".join(str(v) for k, v in (exchange.request_headers or {}).items()
                     if str(k).lower() == "content-type").lower()
    if not any(t in ctype for t in ("application/x-www-form-urlencoded", "application/json")):
        return False
    from harness.validators.nosql_validator import _credential_names
    return all(_credential_names(exchange.request_body or ""))


def _nosql_json_write_candidate(exchange: HttpExchange, gate=None) -> bool:
    """A captured JSON update (PUT/PATCH) with scalar fields of its own, where the
    run's write gates already admit the operator differential's replays.

    r11: the nosql leg reached JSON write bodies only when an agent labelled them,
    so an injectable `id` in a review PATCH was never tried. Shape now opens the
    leg, but only where the run would send it anyway: validators.active_enabled,
    validators.allow_mutating_replay, and a per-finding write ceiling for nosql
    (validators.mutating_ceiling_by_check.nosql) that pays for one verdict. The
    default ceiling of 1 opens no leg, so no default widens. POST creates are left
    out (`json_write_fields`): nothing here can delete what they would make."""
    from harness.validators.nosql_validator import _SENDS_PER_VERDICT, json_write_fields
    if not json_write_fields(exchange):
        return False
    if gate is None:
        from harness.safety_gate import get_default_gate
        gate = get_default_gate()
    cfg = getattr(gate, "config", None)
    if not (getattr(cfg, "active_enabled", False) and getattr(cfg, "allow_mutating_replay", False)):
        return False
    try:
        _, _, ceiling = gate.mutating_headroom(None, "nosql")
    except Exception:
        return False
    return ceiling >= _SENDS_PER_VERDICT


def _email_change_race_candidate(exchange: HttpExchange) -> bool:
    """A mutating form request with a settable email address.

    Shape only warrants trying the race leg.  The validator still requires an
    operator-declared target address, a controlled mailbox, and target-address
    account readback before it can confirm anything.
    """
    if (exchange.method or "GET").upper() not in ("POST", "PUT", "PATCH"):
        return False
    from urllib.parse import parse_qsl
    return any(k.lower() == "email" for k, _ in parse_qsl(
        exchange.request_body or "", keep_blank_values=True))


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
                           finding_class: str | None = None,
                           parameter: tuple[str, str] = ("", "")) -> tuple:
    """The within-run memoisation key for a confirmation leg (R03).

    Includes the IDENTITY (auth headers) and the finding CLASS/subtype, not just
    (validator, method, url, body): different cookies/bearer tokens, and different
    hypothesised subclasses, are DIFFERENT cases. Keying only on url/body replayed
    an administrator's confirmation into another identity's cell, or a skip into a
    valid request. The named (location, parameter) is part of the case too: a leg
    tests a named parameter first, so one parameter's result is not another's."""
    import hashlib
    from harness.volatile_params import stable_url
    method = (exchange.method or "GET").upper()
    # Cache-buster query parameters (an epoch, a random token, a date-time) are
    # not part of the case: two captures differing only there are one check.
    url = stable_url(exchange.url or "")
    body = exchange.request_body or ""
    body_hash = hashlib.md5(body.encode("utf-8", errors="replace")).hexdigest()
    identity_sig = _identity_signature(exchange.request_headers)
    fc = (finding_class or "").lower()
    return (validator_name, method, url, body_hash, identity_sig, fc, tuple(parameter))


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
        "severity": getattr(res, "severity", "") or "high",
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
        "header_fingerprint": getattr(res, "header_fingerprint", "") or "",   # E2: issue grouping
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


def _has_object_id_param(exchange: HttpExchange) -> bool:
    """A GET that references an object through an id-like QUERY parameter
    (?id=, ?user=, ?account=...). Path-segment ids are already `object_scoped`;
    this catches the query-param form so query-keyed IDOR is testable too."""
    from harness.validators.idor_read_validator import _locate_id
    loc = _locate_id(exchange)
    return loc is not None and loc[0] == "query"


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


def _has_client_trust_shape(exchange: HttpExchange) -> bool:
    """A mutating request whose body carries a server-owned field: a price/amount/
    total, a payment source, a plan/tier, a quantity, a currency, a coupon or a
    role/status flag. Reuses ClientTrustValidator's own predicate (applies()) so
    the routing decision and the leg's own targeting never drift."""
    from harness.validators.client_trust_validator import has_trust_shape
    return has_trust_shape(exchange)


def _has_2fa_step_shape(exchange: HttpExchange) -> bool:
    """A login-shaped POST/PUT (username/password fields) whose CAPTURED response
    already landed on a second-factor step. Reuses AuthSequenceValidator's own
    login-shape predicate (applies()) plus its MFA-marker check (_check_mfa_bypass)
    so the routing decision and the leg's own targeting never drift."""
    from harness.validators.auth_sequence_validator import (
        _parse_body, _find_key, _USER_KEYS, _PASS_KEYS, _MFA_MARKERS,
    )
    if (exchange.method or "").upper() not in ("POST", "PUT"):
        return False
    fields, _ = _parse_body(exchange)
    if _find_key(fields, _PASS_KEYS) is None and _find_key(fields, _USER_KEYS) is None:
        return False
    loc = (exchange.response_headers or {}).get("location", "") or ""
    body = (exchange.response_body or "")[:2000]
    return bool(_MFA_MARKERS.search(loc) or _MFA_MARKERS.search(body))


def shape_precondition_legs(node: dict, exchange: HttpExchange, roles, base_url: str,
                            id_fill: str = "1", *, gate=None) -> list[tuple[str, HttpExchange]]:
    """The proactive confirmation legs an endpoint's shape warrants, as
    (vulnerability_class, seed_exchange) pairs to run REGARDLESS of agent labels:

      - object-scoped GET            -> cross-identity replay (idor)
      - JWT-carrying protected GET   -> jwt-forge (seeded from a JWT-bearing role)
      - XML-accepting request body   -> xxe (OOB)
      - URL-shaped param present      -> ssrf (OOB)
      - query/body parameter present -> SQL injection plus other injection legs
      - settable JSON/form body on a mutating method -> mass-assignment
        (write-then-re-read differential, sequence validator)
      - form/JSON login, or a JSON PUT/PATCH with scalar fields whose writes
        the gate admits -> nosql operator differential (`gate` defaults to the
        run's ambient gate)

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
    # A privileged-looking read that the anonymous role already reached is the
    # exact precondition for a missing-authentication check. Keep this separate
    # from IDOR: it needs no second identity and the independent confirmation is
    # a credential-stripped replay of the observed request.
    from harness.engagement import _looks_privileged
    if (method == "GET" and "anonymous" in (node.get("reachable_roles") or [])
            and _looks_privileged(node.get("path") or "")):
        legs.append(("auth_bypass", exchange))
    if node.get("object_scoped") and method == "GET":
        legs.append(("idor", exchange))
    elif method == "GET" and _has_object_id_param(exchange):
        # A GET that references an object via an id-like QUERY param
        # (/my-account?id=wiener, /invoice?num=42) is object-scoped too, even
        # though the id is not a path segment. Dispatch the IDOR leg so the
        # read-differential validator can attempt a safe cross-object read.
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
        legs.append(("sqli", exchange))
        legs.append(("command_injection", exchange))
        legs.append(("ssti", exchange))
        legs.append(("xss", exchange))
    if _has_file_shape(exchange):
        legs.append(("path_traversal", exchange))
    if _has_redirect_param(exchange):
        legs.append(("open_redirect", exchange))
    if _has_pickle_shape(exchange):
        legs.append(("deserialization", exchange))
    if _has_settable_body(exchange):
        legs.append(("mass_assignment", exchange))
    # One nosql leg per request template: a login's credential fields, or a JSON
    # update's own fields when the write gates admit its replays.
    if _nosql_login_candidate(exchange) or _nosql_json_write_candidate(exchange, gate):
        legs.append(("nosql", exchange))
    if _email_change_race_candidate(exchange):
        legs.append(("race_condition", exchange))
    if _lacks_csrf_token(exchange) or _browser_form_csrf_candidate(exchange):
        legs.append(("csrf", exchange))
    if _has_client_trust_shape(exchange):
        legs.append(("client_trust", exchange))
    if _has_2fa_step_shape(exchange):
        legs.append(("2fa_bypass", exchange))
    if _read_body_mass_assignment(exchange):
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
    XML-accepting body) and SSRF (a URL-shaped param). idor shape-routing lives
    in the graph path (`shape_precondition_legs`) where the seed identities
    needed to replay are known; analyze() has just the one captured request and
    identity. The jwt leg needs only that one request: a captured GET carrying a
    JWT is forged from its own token (DET-JWT-SCOPE). The graph path seeds from
    supplied roles and never replays a capture's own headers, so this is also
    the route for a JWT that only a capture carries (capture review runs each
    capture through analyze()). GET only: the forge leg replays the request
    several times, and on a write that is several writes."""
    out: list[Finding] = []
    # Capture-level exposure sweep: a captured GET whose response holds an
    # unmasked allowlisted credential-secret field is tried against the exposure
    # oracle even when no agent raised a finding on it (kept only if confirmed).
    from harness.validators.api_security_validator import exposure_evidence
    if exposure_evidence(None, exchange):
        out.append(Finding(
            vulnerability_class="excessive data exposure", confidence=0.3, severity="high",
            summary=f"Exposure precondition: the captured GET {exchange.url} returns an "
                    f"unmasked credential-secret field",
            evidence="", suggested_test="", basis="derived"))
    if (exchange.method or "GET").upper() == "GET" and _carries_jwt(exchange.request_headers):
        out.append(Finding(
            vulnerability_class="jwt", confidence=0.3, severity="high",
            summary=f"JWT precondition: the captured request to {exchange.url} carries a JWT",
            evidence="", suggested_test="", basis="derived"))
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
            vulnerability_class="sqli", confidence=0.3, severity="high",
            summary=f"SQL-injection precondition: injectable parameter on {exchange.url}",
            evidence="", suggested_test="", basis="derived"))
        out.append(Finding(
            vulnerability_class="command_injection", confidence=0.3, severity="high",
            summary=f"Command-injection precondition: injectable parameter on {exchange.url}",
            evidence="", suggested_test="", basis="derived"))
        out.append(Finding(
            vulnerability_class="ssti", confidence=0.3, severity="high",
            summary=f"SSTI precondition: injectable parameter on {exchange.url}",
            evidence="", suggested_test="", basis="derived"))
        out.append(Finding(
            vulnerability_class="xss", confidence=0.3, severity="high",
            summary=f"XSS precondition: injectable parameter on {exchange.url}",
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
    if _lacks_csrf_token(exchange) or _browser_form_csrf_candidate(exchange):
        out.append(Finding(
            vulnerability_class="csrf", confidence=0.3, severity="medium",
            summary=f"CSRF precondition: browser-form {(exchange.method or 'POST').upper()} requires token-validation checks on {exchange.url}",
            evidence="", suggested_test="", basis="derived"))
    if _has_settable_body(exchange):
        out.append(Finding(
            vulnerability_class="mass_assignment", confidence=0.3, severity="high",
            summary=f"Mass-assignment precondition: settable JSON/form body on {(exchange.method or 'POST').upper()} {exchange.url}",
            evidence="", suggested_test="", basis="derived"))
    if _nosql_login_candidate(exchange):
        out.append(Finding(
            vulnerability_class="nosql", confidence=0.3, severity="critical",
            summary=f"NoSQL precondition: operator-capable credential form on {exchange.url}",
            evidence="", suggested_test="", basis="derived"))
    if _email_change_race_candidate(exchange):
        out.append(Finding(
            vulnerability_class="race_condition", confidence=0.3, severity="high",
            summary=f"Race-condition precondition: settable email transition on {exchange.url}",
            evidence="", suggested_test="", basis="derived"))
    out.extend(_r11_detection_shapes(exchange))
    return out


def _r11_detection_shapes(exchange: HttpExchange) -> list[Finding]:
    """R11-8 (c): the three legs r11 never opened. A challenge-shaped JSON GET
    (challenge_echo reads the captured pairs; it sends nothing by default), a GET
    lookup naming an account in its query (username enumeration), and a
    reset/recovery-answer write (wrong-answer rate limit). Each leg records a
    lead until its confirm key is on."""
    from harness.validators.auth_sequence_validator import RECOVERY_LOOKUP_SHAPE, _query_identifier
    from harness.validators.challenge_echo_validator import is_challenge_shape
    from harness.validators.rate_limit_validator import reset_answer_shape
    method = (exchange.method or "GET").upper()
    shapes = []
    if is_challenge_shape(exchange):
        shapes.append(("challenge_echo", "medium", "challenge-shaped JSON response"))
    if method == "GET" and _query_identifier(exchange) is not None:
        shapes.append(("username_enumeration", "medium", RECOVERY_LOOKUP_SHAPE))
    if reset_answer_shape(exchange) is not None:
        shapes.append(("rate_limit", "medium", "reset/recovery-answer write"))
    return [Finding(vulnerability_class=cls, confidence=0.3, severity=sev,
                    summary=f"Shape precondition ({why}) on {exchange.url.split('?', 1)[0]}",
                    evidence="", suggested_test="", basis="derived")
            for cls, sev, why in shapes]


# Agent name for the deterministic reflected-parameter hypotheses. Unlike the
# shape legs these are kept unconfirmed (capped by the confirmation gate): a
# reflection is an observed fact, and it is what gets an XSS plan planned.
_REFLECTION_AGENT = "reflection_detector"


# Shorter values reflect by coincidence ("1", "en", "id").
_REFLECTION_MIN_VALUE = 3


def reflected_parameter_findings(exchange: HttpExchange) -> list[Finding]:
    """One low-confidence XSS hypothesis per query parameter whose captured value
    appears verbatim in the captured response body. Passive: it reads the one
    exchange and sends nothing. The browser_xss validator (or the planner's
    reflection_context_validation plan) is what tests it."""
    from urllib.parse import parse_qsl, urlsplit as _split
    body = exchange.response_body or ""
    if not body:
        return []
    out: list[Finding] = []
    seen: set[str] = set()
    for name, value in parse_qsl(_split(exchange.url).query, keep_blank_values=False):
        value = value.strip()
        if name in seen or len(value) < _REFLECTION_MIN_VALUE or value not in body:
            continue
        seen.add(name)
        out.append(Finding(
            vulnerability_class="xss", confidence=0.3, severity="medium",
            summary=(f"Reflected parameter: the value of query parameter {name!r} is "
                     f"echoed in the response from {exchange.url.split('?', 1)[0]}"),
            evidence=f"query parameter {name!r} value reflected in the response body",
            suggested_test="Run a browser execution check on this parameter",
            basis="derived", parameter_location="query", parameter_name=name))
    return out


def per_run_gate_config(config: dict | None, registry=None) -> dict:
    """Gate POLICY for a freshly-created per-run RunContext on the standalone
    analysis path.

    RunContext.create() builds a fresh SafetyGate per run (per-run budget
    isolation), but its policy flags -- active_enabled / allow_mutating_replay /
    max_burst_size -- must still match the server the operator configured.
    Without this, the per-run gate defaults both safety flags to False and
    BLOCKS a mutating send that validators using the process-global gate are
    allowed to make (the reproduced "blocked: active_enabled off" on a POST
    SQL-injection in a run configured active=true). active_enabled additionally
    reflects the live runtime toggle (ValidatorRegistry.set_active_enabled),
    which arms the registry without rewriting `config`. Returns the
    `validators:` subconfig with active_enabled overridden by the registry's
    live value when a registry is supplied.
    """
    cfg = dict((config or {}).get("validators", {}) or {})
    if registry is not None:
        cfg["active_enabled"] = getattr(registry, "active_enabled", cfg.get("active_enabled", False))
    return cfg
