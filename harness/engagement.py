"""
Engagement state -- the shared spine the discrete capabilities hang off.

Every other module here is a leaf: it takes an input and returns a result and
forgets. That makes a good toolbox and a bad agent -- nothing lets a crawl, an
access matrix, an LLM rating, and a finding inform ONE picture of the target so
the next action can be chosen from all of them at once. This module is that
picture.

An `EngagementState` is a per-host graph of:
  - SURFACE: every known endpoint, carrying whatever signals we've gathered
    about it -- a static path tier (PathScorer, from Burp), an LLM structure
    rating (surface_prioritizer), the per-role access matrix (role_crawl), and
    any findings the agents/validators produced for it.
  - IDENTITIES: the roles/credentials in play and HOW each was obtained (seeded
    by the tester vs. derived from a finding) -- the substrate the closed loop
    (slice 2) will re-crawl from.

Its one job today is FUSION: collapse those separate, currently-disjoint signals
into a single, auditable "test-next" ranking, so the worklist reflects
everything known -- "reachable by anonymous but shaped like admin" outranks "a
static high tier with nothing else behind it," and an endpoint already validated
drops down the list. The score is a transparent weighted sum with per-endpoint
reasons (same discipline as resource_governor), never an opaque number.

Pure and deterministic: ingest_* mutate the state, fusion is arithmetic, no LLM
call and no network. Persistence is a JSON snapshot per host (see store).
"""
from __future__ import annotations
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

try:
    from harness.categories import canonicalize as _canon
except Exception:  # pragma: no cover - categories is always present in the harness
    def _canon(x):  # type: ignore
        return (x or "").lower().strip() or None

_SEV_W = {"critical": 1.0, "high": 0.75, "medium": 0.5, "low": 0.25, "info": 0.1}
_TIER_W = {"critical": 1.0, "high": 0.75, "medium": 0.5, "low": 0.25, "info": 0.1, "unscored": 0.1}

# Path shapes that read as privileged/sensitive -- used to flag the high-value
# anomaly "a low-trust role can reach something that looks admin-only".
_PRIVILEGED = re.compile(
    r"/(admin|administrator|manage|management|config|configuration|settings|internal|debug|"
    r"actuator|console|dashboard|billing|payment|invoice|account|users?|profile|report|export|"
    r"backup|token|secret|key|password|role|permission|privilege)(s)?(/|$)",
    re.IGNORECASE,
)

_NUM_SEG = re.compile(r"/\d+(?=/|$)")
_HEXISH = re.compile(r"/[0-9a-fA-F]{12,}(?=/|$)")

# 2026-09-17 coverage-recovery plan, Step 2: a percent-encoded byte surviving
# INTO the normalized path is a discovery artifact (an encoded traversal probe,
# a doubly-encoded fuzz payload), not a distinct real route -- a legitimate
# captured path is decoded before it ever reaches here. Left unscored, one of
# these can still out-rank a real endpoint just by containing a privileged
# keyword substring (e.g. "/admin%2f..") or a high path_tier/LLM rating, which
# is exactly how a max-coverage run's worklist got crowded with them.
_PERCENT_ENCODED = re.compile(r"%[0-9a-fA-F]{2}")


def _looks_malformed_or_encoded(path: str) -> bool:
    return bool(_PERCENT_ENCODED.search(path or ""))


def normalize_path(url_or_path: str) -> str:
    """A stable key that aligns a crawl's normalized path with a finding's
    concrete URL: strip scheme/host/query, collapse numeric and long-hex
    segments to {id} (so /orders/42 and /orders/{id} map together)."""
    s = url_or_path or ""
    if "://" in s:
        parts = urlsplit(s)
        s = parts.path or "/"
    else:
        s = s.split("?", 1)[0].split("#", 1)[0]
    s = _HEXISH.sub("/{id}", s)
    s = _NUM_SEG.sub("/{id}", s)
    if len(s) > 1 and s.endswith("/"):
        s = s[:-1]
    return s or "/"


def _looks_privileged(path: str) -> bool:
    return bool(_PRIVILEGED.search(path or ""))


def template_from_exchange(ex) -> dict:
    """A compact, replayable request TEMPLATE captured from a real exchange (R05):
    method, query string, request body, content-type, and the observed leaf object
    id -- the detail the graph otherwise fabricates away (empty body, {id}->1, query
    stripped). Accepts an HttpExchange or a dict."""
    if isinstance(ex, dict):
        get = lambda k, d=None: ex.get(k, d)
    else:
        get = lambda k, d=None: getattr(ex, k, d)
    url = get("url", "") or ""
    method = (get("method", "GET") or "GET").upper()
    headers = dict(get("request_headers", {}) or {})
    body = get("request_body", "") or ""
    parts = urlsplit(url)
    ctype = next((v for k, v in headers.items() if (k or "").lower() == "content-type"), "")
    obj_id = None
    for seg in [s for s in (parts.path or "").split("/") if s]:
        if re.fullmatch(r"\d+|[0-9a-fA-F-]{8,}", seg):
            obj_id = seg  # keep the LAST matching segment -> the leaf object id
    return {"method": method, "query": parts.query or "", "body": body,
            "content_type": ctype or "", "object_id": obj_id}


@dataclass
class SurfaceEndpoint:
    method: str
    path: str                         # normalized key path
    path_tier: str | None = None      # PathScorer tier (from Burp)
    llm_priority: str | None = None   # surface_prioritizer ai_priority
    llm_score: float | None = None    # surface_prioritizer ai_score 0..1
    access: dict = field(default_factory=dict)          # role -> status
    reachable_roles: list = field(default_factory=list)  # substantive 2xx
    object_scoped: bool = False
    findings: list = field(default_factory=list)         # [{class, severity, confidence, confirmed}]
    status: str = "discovered"        # discovered | analyzed | validated
    # Captured request TEMPLATE (R05): the real query/body/content-type/object-id
    # observed for this endpoint, so the graph + coverage replay its actual shape
    # instead of fabricating an empty body, a stripped query, and id=1. None until
    # a capture is recorded (record_template); replay falls back to fabrication.
    template: dict | None = None

    @property
    def key(self) -> str:
        return f"{self.method.upper()} {self.path}"

    def is_malformed_or_encoded(self) -> bool:
        """A discovery artifact (residual percent-encoding), not a distinct
        real route to test -- Step 2 of the 2026-09-17 coverage-recovery plan."""
        return _looks_malformed_or_encoded(self.path)

    def is_repeat_5xx_artifact(self) -> bool:
        """Every role that was probed got a server error (or no substantive
        response at all) and none reached it -- a dead/broken discovery
        artifact, not a real endpoint worth a bounded agent investigation."""
        if not self.access or self.reachable_roles:
            return False
        return all(v is None or (isinstance(v, int) and v >= 500) for v in self.access.values())

    def is_input_bearing(self) -> bool:
        """A concrete, replayable shape exists to probe with -- a captured
        body/query TEMPLATE, or a live object id to enumerate -- rather than a
        bare path the graph would have to fabricate a probe for."""
        tmpl = self.template or {}
        return bool(tmpl.get("body") or tmpl.get("query") or self.object_scoped)

    def best_finding(self) -> dict | None:
        if not self.findings:
            return None
        return max(self.findings, key=lambda f: (
            1 if f.get("confirmed") else 0, _SEV_W.get((f.get("severity") or "info").lower(), 0.1),
            f.get("confidence", 0.0)))

    def add_finding(self, f: dict) -> None:
        """Attach a finding, de-duped by vulnerability_class, MONOTONICALLY (R07).

        A CONFIRMED finding is proof. It is never overwritten or downgraded by a
        later UNCONFIRMED hypothesis, whatever the hypothesis's model confidence
        (the reproduced bug: confirmed@0.9 replaced by unconfirmed@0.99). A
        hypothesis is superseded only by a stronger hypothesis or by a
        confirmation. Proof/context fields (evidence, summary, url, validator,
        identity, basis) are PRESERVED rather than dropped to a 4-key slim, and
        every superseded entry is retained under `_superseded` so the history and
        the proof that backed a finding are never silently lost."""
        # Step 4 (2026-09-17 coverage-recovery plan): reject an active-class
        # confirmation with no leg proof behind it -- the honesty backstop, not
        # the primary path (see confirmation_gate.active_confirmation_is_unproven's
        # docstring for exactly what this does and does not police).
        from harness import confirmation_gate
        confirmed = bool(f.get("confirmed", False))
        if confirmed and confirmation_gate.active_confirmation_is_unproven(f):
            confirmed = False
        slim = {
            "vulnerability_class": f.get("vulnerability_class", ""),
            "severity": f.get("severity", "info"),
            "confidence": f.get("confidence", 0.0),
            "confirmed": confirmed,
        }
        # Carry proof/context when present -- never fabricate empty keys.
        # (T04: proof_id/case_id link a finding to its case-bound structured proof so
        # the link survives ingestion into state and the report projection.)
        for k in ("evidence", "summary", "url", "confirmation_method",
                  "validator", "identity", "basis", "proof_id", "case_id",
                  "confirmed_by_leg"):
            if f.get(k):
                slim[k] = f[k]

        def _sev(x) -> float:
            return _SEV_W.get((x or "info").lower(), 0.1)

        for existing in self.findings:
            if existing["vulnerability_class"] != slim["vulnerability_class"]:
                continue
            ex_conf = bool(existing.get("confirmed"))
            new_conf = slim["confirmed"]
            # A proof is never downgraded by an unconfirmed hypothesis (R07).
            if ex_conf and not new_conf:
                return
            stronger = (
                (new_conf and not ex_conf)                       # confirmation beats hypothesis
                or (new_conf == ex_conf and (                    # same tier: stronger sev/conf wins
                    _sev(slim["severity"]) > _sev(existing.get("severity"))
                    or slim["confidence"] >= existing.get("confidence", 0.0)))
            )
            if stronger:
                history = existing.get("_superseded", [])
                prior = {k: v for k, v in existing.items() if k != "_superseded"}
                existing.clear()
                existing.update(slim)
                existing["_superseded"] = history + [prior]
            return
        self.findings.append(slim)

    def fused_score(self) -> tuple[float, list[str]]:
        """Collapse every signal into one 'worth testing next' value with the
        reasons that drove it. Higher = attack value still on the table."""
        score = 0.0
        reasons: list[str] = []

        bf = self.best_finding()
        if bf:
            sev = _SEV_W.get((bf.get("severity") or "info").lower(), 0.1)
            if bf.get("confirmed"):
                score += 1.0 * sev
                reasons.append(f"confirmed {bf.get('vulnerability_class', 'finding')} (sev {bf.get('severity')})")
            else:
                score += 0.6 * sev * float(bf.get("confidence", 0.0) or 0.0)
                reasons.append(f"unconfirmed {bf.get('vulnerability_class', 'finding')} @ {bf.get('confidence', 0):.2f}")

        if self.llm_score is not None:
            score += 0.4 * float(self.llm_score)
            reasons.append(f"LLM rating {self.llm_priority or ''} {self.llm_score:.2f}".strip())

        if self.path_tier:
            score += 0.3 * _TIER_W.get(self.path_tier.lower(), 0.1)
            reasons.append(f"path tier {self.path_tier}")

        # Access-matrix anomalies -- the highest-signal cross-source insight.
        low_trust_reaches = any(r.lower() in ("anonymous", "user") for r in self.reachable_roles)
        if low_trust_reaches and _looks_privileged(self.path):
            score += 0.7
            reasons.append("low-trust role reaches a privileged-looking path (authz gap)")
        if self.object_scoped and any(r.lower() not in ("anonymous",) for r in self.reachable_roles):
            score += 0.3
            reasons.append("object-scoped endpoint reachable by an identity (IDOR candidate)")
        if _looks_privileged(self.path) and not self.findings and not self.reachable_roles:
            score += 0.15
            reasons.append("privileged-looking path, not yet tested")

        # Step 2 (2026-09-17 coverage-recovery plan): a concrete, replayable
        # shape (a captured body/query, or a live object id) means a real probe
        # can be built, not a fabricated one -- rank it above a bare path with
        # the same other signals.
        if self.is_input_bearing():
            score += 0.2
            reasons.append("input-bearing route (body/query/object-id) -- concrete probe available")

        # Already validated -> mostly done; keep a little so it stays visible.
        if self.status == "validated":
            score *= 0.3
            reasons.append("already validated (deprioritized)")

        # A discovery artifact competing on borrowed signal (a privileged
        # keyword substring inside an encoded probe, a path_tier/LLM score that
        # doesn't know the route is dead) must not out-rank a real endpoint --
        # multiplicative, so it demotes regardless of which additive signal fired.
        if self.is_malformed_or_encoded():
            score *= 0.05
            reasons.append("malformed/encoded discovery artifact (deprioritized)")
        if self.is_repeat_5xx_artifact():
            score *= 0.05
            reasons.append("every probed role got a server error here -- dead endpoint (deprioritized)")

        return round(score, 4), reasons

    def to_dict(self) -> dict:
        s, reasons = self.fused_score()
        return {
            "method": self.method, "path": self.path, "status": self.status,
            "path_tier": self.path_tier, "llm_priority": self.llm_priority, "llm_score": self.llm_score,
            "access": self.access, "reachable_roles": self.reachable_roles,
            "object_scoped": self.object_scoped, "findings": self.findings,
            "template": self.template,
            "score": s, "reasons": reasons,
            # Step 2/3 (2026-09-17 coverage-recovery plan): surfaced so a
            # dict-based consumer (investigate_worklist) can preserve a bounded
            # per-run budget (max_precondition_legs) for real, live endpoints
            # instead of spending it on a discovery artifact that already
            # proved dead or malformed.
            "dead_endpoint": self.is_repeat_5xx_artifact(),
            "malformed_or_encoded": self.is_malformed_or_encoded(),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "SurfaceEndpoint":
        return cls(
            method=d.get("method", "GET"), path=d.get("path", "/"),
            path_tier=d.get("path_tier"), llm_priority=d.get("llm_priority"), llm_score=d.get("llm_score"),
            access=d.get("access", {}) or {}, reachable_roles=d.get("reachable_roles", []) or [],
            object_scoped=bool(d.get("object_scoped", False)), findings=d.get("findings", []) or [],
            status=d.get("status", "discovered"), template=d.get("template"),
        )


# --- capability detection (slice 2: the closed loop) ------------------------
# Access-control finding classes that, once real, mean a new part of the surface
# just became reachable and is worth re-testing (possibly as a new identity).
_REACHABLE_CLASSES = {"idor", "auth", "missing_authentication", "broken_access_control",
                      "access_control", "session_fixation"}

# A JWT anywhere in a response is a directly-usable bearer credential.
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_\-]{6,}\.eyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}\b")
# Session-ish cookie names worth replaying as an identity.
_SESSION_COOKIE = re.compile(
    r"\b(session|sess|sid|sessionid|jsessionid|phpsessid|connect\.sid|auth|token|jwt)=([^;,\s]+)",
    re.IGNORECASE)
# Token fields in a JSON body.
_JSON_TOKEN = re.compile(
    r"""["'](?:access_?token|auth_?token|id_?token|jwt|token)["']\s*:\s*["']([^"']{12,})["']""",
    re.IGNORECASE)


def _extract_credential(resp_headers: dict | None, resp_body: str | None) -> dict | None:
    """A directly-replayable credential the harness just observed in a response,
    as {"kind","headers"} -- an Authorization bearer or a Cookie header a
    re-crawl can send as a new identity. None when nothing usable is present.

    This is the ONE place the harness holds a learned credential; it is passed to
    an in-process re-crawl and never persisted (see EngagementState -- the queue
    stores the fact 'a credential was learned here', never the value)."""
    body = resp_body or ""
    headers = resp_headers or {}
    set_cookie = " ; ".join(v for k, v in headers.items() if k.lower() == "set-cookie")
    # 1. JWT (in a Set-Cookie, an Authorization echo, or the body) -> bearer.
    for source in (set_cookie, body):
        m = _JWT_RE.search(source or "")
        if m:
            return {"kind": "bearer", "headers": {"Authorization": f"Bearer {m.group(0)}"}}
    # 2. JSON token field -> bearer.
    m = _JSON_TOKEN.search(body)
    if m:
        return {"kind": "bearer", "headers": {"Authorization": f"Bearer {m.group(1)}"}}
    # 3. Session cookie -> Cookie header.
    m = _SESSION_COOKIE.search(set_cookie)
    if m:
        return {"kind": "cookie", "headers": {"Cookie": f"{m.group(1)}={m.group(2)}"}}
    return None


# Business-logic hand-off (AppSecSanta 2026: ~70% of critical web vulns are
# business logic, and no autonomous agent detects them reliably -- it requires
# understanding what the app is SUPPOSED to do. So instead of letting an agent
# fake-confirm these, we flag the surface for a human and stop there.
_BUSINESS_LOGIC_CLASSES = {"business_logic", "business_logic_enhanced", "workflow",
                          "race_condition"}
_BUSINESS_LOGIC_PATH = re.compile(
    r"/(checkout|cart|basket|order|orders|payment|pay|purchase|transfer|coupon|discount|promo|"
    r"voucher|balance|refund|reward|loyalty|subscription|plan|quantity|qty|price|amount|wallet|"
    r"credit|invoice|withdraw|deposit)(s)?(/|$)",
    re.IGNORECASE)


def business_logic_review(finding_class: str, url: str) -> dict | None:
    """Whether an endpoint warrants human business-logic review -- either the
    finding's class is a business-logic one, or the path shape is (checkout,
    transfer, coupon, ...). Returns a review-task spec (blocked on human
    judgment) or None. This is deliberately a HAND-OFF, not a confirmation: the
    harness flags it and lets the tester reason about intent."""
    canon = _canon(finding_class or "") or (finding_class or "").lower()
    path = normalize_path(url)
    is_bl_class = canon in _BUSINESS_LOGIC_CLASSES
    is_bl_path = bool(_BUSINESS_LOGIC_PATH.search(path))
    if not (is_bl_class or is_bl_path):
        return None
    why = ("finding class is business-logic" if is_bl_class
           else "endpoint shape suggests a business-logic flow (value/quantity/workflow)")
    return {"target": path, "reason": f"needs human business-logic review -- {why}. "
                                      f"Automated agents don't reliably detect intent-level flaws "
                                      f"(price/quantity tampering, workflow bypass, race conditions).",
            "needs": "human judgment (business logic)"}


def needs_human_review(finding_class: str, url: str) -> dict | None:
    """Whether a finding's class has NO automated confirmation leg at all, so the
    only honest disposition is a HUMAN verification hand-off -- never a fabricated
    confirmation. This is the general guard the operator asked for on the classes
    with no leg (V2/V37 and any other no-leg class): the harness must flag them for
    a tester, not let an agent's guess masquerade as confirmed and not silently
    drop them. Business-logic classes are handled by their own richer hand-off
    (business_logic_review), so this defers to that and covers everything else.

    Returns a review-task spec (blocked on human judgment) or None. Deterministic;
    keyed off the leg-tier table (confirmation_gate), not free text."""
    # business logic has its own, more specific hand-off -- don't double-flag.
    if business_logic_review(finding_class, url) is not None:
        return None
    try:
        from harness.confirmation_gate import leg_tier
        tier = leg_tier(finding_class)
    except Exception:  # pragma: no cover - confirmation_gate always importable
        tier = "none"
    if tier != "none":
        return None  # a leg exists (live or provisional) -> confirmation path owns it
    path = normalize_path(url)
    return {"target": path,
            "reason": (f"finding class {finding_class!r} has no automated confirmation leg in this "
                       f"harness -- it is reported UNCONFIRMED and flagged for human verification. "
                       f"The harness never fabricates confirmation for a class it cannot actually test."),
            "needs": "human verification (no automated leg for this class)"}


def detect_capabilities(finding: dict, resp_headers: dict | None, resp_body: str | None,
                        url: str) -> list[dict]:
    """What new access, if any, a finding grants -- the trigger for the closed
    loop. Two kinds:

      - "credential": a directly-replayable token/cookie was observed. Carries
        `headers` (ephemeral -- used by an in-process re-crawl, never persisted).
      - "reachable_area": an access-control finding means this area is reachable
        (perhaps as a role we should re-crawl as); persisted as a queued action.

    Deterministic; keyed off the finding's class + the raw response, no LLM."""
    caps: list[dict] = []
    canon = _canon(finding.get("vulnerability_class", "")) or (finding.get("vulnerability_class", "") or "").lower()
    confirmed = bool(finding.get("confirmed"))
    conf = float(finding.get("confidence", 0.0) or 0.0)

    # A credential is only interesting from an auth-relevant or confirmed finding
    # (a token echoed in some unrelated benign response isn't a capability gain).
    if canon in ("auth", "jwt", "session_fixation", "missing_authentication") or confirmed or conf >= 0.7:
        cred = _extract_credential(resp_headers, resp_body)
        if cred:
            caps.append({"type": "credential", "kind": cred["kind"], "headers": cred["headers"],
                         "source_url": url,
                         "reason": f"a replayable {cred['kind']} credential was observed in the response"})

    if canon in _REACHABLE_CLASSES and (confirmed or conf >= 0.5):
        caps.append({"type": "reachable_area", "area": normalize_path(url), "source_url": url,
                     "finding_class": finding.get("vulnerability_class", ""),
                     "reason": f"{finding.get('vulnerability_class', 'access-control')} makes this area "
                               f"reachable -- re-crawl/re-test it, possibly as a new identity"})
    return caps


@dataclass
class EngagementState:
    host: str
    endpoints: dict = field(default_factory=dict)   # key "METHOD path" -> SurfaceEndpoint
    identities: list = field(default_factory=list)  # [{name, role, source, obtained_from}]
    # The work model: a dependency graph of escalation tasks (task_graph.py),
    # replacing the old flat queue. Never holds a credential value -- only the
    # fact one was learned and where.
    graph: "object" = None

    def __post_init__(self):
        from harness import task_graph
        if self.graph is None:
            self.graph = task_graph.TaskGraph()

    # --- ingest: every source writes into the SAME model ---

    def _ep(self, method: str, path: str) -> SurfaceEndpoint:
        key = f"{method.upper()} {path}"
        ep = self.endpoints.get(key)
        if ep is None:
            ep = SurfaceEndpoint(method=method.upper(), path=path)
            self.endpoints[key] = ep
        return ep

    def ingest_endpoints(self, paths, method: str = "GET") -> int:
        """From a plain /crawl: add discovered paths as GET endpoints."""
        n = 0
        for p in paths or []:
            self._ep(method, normalize_path(p))
            n += 1
        return n

    def merge_from(self, other: "EngagementState") -> int:
        """Fold another engagement's discoveries into this one (R19).

        The closed-loop re-crawl builds a SEPARATE state (`st2`) as a newly-leaked
        identity; without merging, the surface and findings reachable only as that
        identity never reach the primary state's summary/worklist/report. This
        merges the other state's endpoints (adding new ones, unioning findings via
        the monotonic add_finding, unioning reachable roles, adopting a template
        where we lack one) and its identities. Returns the count of NEW endpoints
        added."""
        added = 0
        for key, ep in (other.endpoints or {}).items():
            mine = self.endpoints.get(key)
            if mine is None:
                self.endpoints[key] = ep
                added += 1
                continue
            for f in ep.findings or []:
                mine.add_finding(f)
            for r in ep.reachable_roles or []:
                if r not in mine.reachable_roles:
                    mine.reachable_roles.append(r)
            if ep.template and not mine.template:
                mine.template = ep.template
            # a proven endpoint status propagates upward, never downward
            if ep.status == "validated":
                mine.status = "validated"
        for ident in getattr(other, "identities", []) or []:
            if not any(i.get("name") == ident.get("name") for i in self.identities):
                self.identities.append(ident)
        return added

    def ingest_role_crawl(self, result: dict) -> int:
        """From /crawl-roles: the access matrix + object-scoping per endpoint,
        plus the derived IDOR findings."""
        n = 0
        for e in result.get("endpoints", []) or []:
            ep = self._ep(e.get("method", "GET"), normalize_path(e.get("path", "/")))
            ep.access = e.get("by_role", {}) or {}
            ep.reachable_roles = e.get("reachable_roles", []) or []
            ep.object_scoped = bool(e.get("object_scoped", False))
            n += 1
        for f in result.get("idor_findings", []) or []:
            # idor_findings carry a validation_hint "cross_identity_compare:<path>"
            for hint in f.get("validation_hints", []) or []:
                if hint.startswith("cross_identity_compare:"):
                    path = normalize_path(hint.split(":", 1)[1])
                    self._ep("GET", path).add_finding(f)
        return n

    def ingest_prioritization(self, items) -> int:
        """From /prioritize (surface_prioritizer LLM ratings)."""
        n = 0
        for it in items or []:
            method = it.get("method", "GET")
            path = normalize_path(it.get("url", "/"))
            ep = self._ep(method, path)
            ep.llm_priority = it.get("ai_priority")
            try:
                ep.llm_score = float(it.get("ai_score")) if it.get("ai_score") is not None else None
            except (TypeError, ValueError):
                ep.llm_score = None
            n += 1
        return n

    def record_template(self, url: str, method: str, exchange) -> None:
        """Attach the captured request TEMPLATE to the endpoint so the graph and
        coverage replay its real shape instead of fabricating (R05). When several
        captures map to one endpoint, keep the most informative (a body/query/
        object-id beats an empty one)."""
        ep = self._ep(method, normalize_path(url))
        tmpl = template_from_exchange(exchange)

        def _richness(t: dict | None) -> int:
            if not t:
                return -1
            return ((1 if t.get("body") else 0) + (1 if t.get("query") else 0)
                    + (1 if t.get("object_id") else 0))

        if _richness(tmpl) > _richness(ep.template):
            ep.template = tmpl

    def ingest_findings(self, url: str, method: str, findings) -> int:
        """From /analyze (agents + validators): attach findings to the endpoint,
        promoting its status."""
        ep = self._ep(method, normalize_path(url))
        n = 0
        for f in findings or []:
            ep.add_finding(f if isinstance(f, dict) else _finding_to_dict(f))
            n += 1
        if any(fd.get("confirmed") for fd in ep.findings):
            ep.status = "validated"
        elif ep.findings:
            ep.status = "analyzed"
        return n

    def ingest_identity(self, name: str, role: str, source: str = "seed", obtained_from: str = "") -> None:
        if any(i["name"] == name for i in self.identities):
            return
        self.identities.append({"name": name, "role": role, "source": source, "obtained_from": obtained_from})

    def enqueue_action(self, kind: str, target: str, reason: str, source: str = "",
                       auto_runnable: bool = False, depends_on: list | None = None,
                       needs: str = "") -> None:
        """Add an escalation task to the graph, de-duped by (kind, target). Never
        carries a credential value -- only the pointer to what to do. BLOCKED
        automatically when it has unmet dependencies or a human `needs`."""
        self.graph.add(kind, target, reason=reason, source=source,
                       depends_on=depends_on or [], needs=needs,
                       meta={"auto_runnable": auto_runnable})

    def apply_capabilities(self, caps: list, url: str) -> list:
        """Fold detected capabilities into the task graph as a DEPENDENCY chain.
        Returns the subset that are `credential` type (carrying ephemeral headers)
        so the caller can act on them in-process -- these are NOT stored."""
        from harness import task_graph
        credential_caps: list = []
        for cap in caps or []:
            if cap.get("type") == "credential":
                # obtain(DONE) -> recrawl_as_derived(READY): the re-crawl depends on
                # having obtained the credential, which we just did. This is the
                # smallest real edge in the DAG. The identity is label-only; the
                # header value travels with the returned cap, never into the graph.
                name = f"derived:{cap.get('kind', 'cred')}@{normalize_path(url)}"
                self.ingest_identity(name, role="derived", source="finding", obtained_from=url)
                obtain = self.graph.add("obtain", name, reason="credential observed in a response",
                                        source=url)
                self.graph.mark(obtain.id, task_graph.DONE)
                self.graph.add("recrawl_as_derived", name,
                               reason=cap.get("reason", "credential learned -- re-crawl as this identity"),
                               source=url, depends_on=[obtain.id], meta={"auto_runnable": True})
                credential_caps.append(cap)
            elif cap.get("type") == "reachable_area":
                area = cap.get("area", normalize_path(url))
                self.graph.add("recrawl_area", area,
                               reason=cap.get("reason", "access-control finding -- re-test this area"),
                               source=url, meta={"auto_runnable": False})
                # If a privileged area is only reachable anonymously, the deeper
                # move needs a privileged session -- a human/credential input.
                # Model it as a BLOCKED task so the operator sees what would
                # unlock it rather than it silently not happening.
                if _looks_privileged(area):
                    obtain = self.graph.add("obtain", f"privileged-session@{area}",
                                            reason="a privileged session for this area",
                                            needs="privileged credentials (human)", source=url)
                    self.graph.add("recrawl_as_privileged", area,
                                   reason="re-crawl this privileged area as a privileged identity",
                                   source=url, depends_on=[obtain.id])
        return credential_caps

    def resolve_action(self, kind: str, target: str) -> None:
        from harness import task_graph
        self.graph.mark_by(kind, target, task_graph.DONE)

    def flag_business_logic(self, finding_class: str, url: str) -> bool:
        """If this finding/endpoint warrants human business-logic review, add a
        BLOCKED 'review' task (needs=human judgment) so it's surfaced to the
        tester rather than auto-tested or fake-confirmed. Returns whether one was
        added."""
        spec = business_logic_review(finding_class, url)
        if spec is None:
            return False
        self.graph.add("review", spec["target"], reason=spec["reason"],
                       needs=spec["needs"], source=url)
        return True

    def flag_unconfirmable(self, finding_class: str, url: str) -> bool:
        """If this finding's class has NO automated confirmation leg, add a BLOCKED
        'verify' task (needs=human verification) so it is surfaced to the tester as
        reported-not-verified rather than fake-confirmed or dropped. Returns whether
        one was added. De-duped by (kind, target) via the task graph."""
        spec = needs_human_review(finding_class, url)
        if spec is None:
            return False
        self.graph.add("verify", spec["target"], reason=spec["reason"],
                       needs=spec["needs"], source=url)
        return True

    # --- the fused output ---

    def worklist(self, limit: int = 25) -> list:
        ranked = sorted(self.endpoints.values(), key=lambda e: e.fused_score()[0], reverse=True)
        return [e.to_dict() for e in ranked[:limit]]

    def pending(self) -> list:
        """Ready-to-act tasks (all prerequisites satisfied)."""
        return [t.to_dict() for t in self.graph.ready()]

    def blocked(self) -> list:
        """Tasks waiting on a prerequisite -- each names what would unlock it."""
        return [t.to_dict() for t in self.graph.blocked()]

    def summary(self) -> dict:
        by_status: dict[str, int] = {}
        for e in self.endpoints.values():
            by_status[e.status] = by_status.get(e.status, 0) + 1
        return {"host": self.host, "endpoint_count": len(self.endpoints),
                "by_status": by_status, "identities": self.identities,
                "ready_task_count": len(self.graph.ready()),
                "blocked_task_count": len(self.graph.blocked())}

    def to_dict(self) -> dict:
        return {"host": self.host,
                "endpoints": {k: v.to_dict() for k, v in self.endpoints.items()},
                "identities": self.identities,
                "task_graph": self.graph.to_dict()}

    @classmethod
    def from_dict(cls, d: dict) -> "EngagementState":
        from harness import task_graph
        st = cls(host=d.get("host", ""))
        for k, v in (d.get("endpoints", {}) or {}).items():
            st.endpoints[k] = SurfaceEndpoint.from_dict(v)
        st.identities = d.get("identities", []) or []
        if d.get("task_graph"):
            st.graph = task_graph.TaskGraph.from_dict(d["task_graph"])
        return st


def _finding_to_dict(f) -> dict:
    return {
        "vulnerability_class": getattr(f, "vulnerability_class", ""),
        "severity": getattr(f, "severity", "info"),
        "confidence": getattr(f, "confidence", 0.0),
        "confirmed": getattr(f, "confirmed", False),
    }
