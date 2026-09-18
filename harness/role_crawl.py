"""
Role-aware crawl -> access matrix.

A plain crawl finds an application's endpoint surface. It doesn't tell you WHO
can reach each endpoint -- and that is exactly the question broken-access-control
testing turns on. This module crawls the same target once per supplied role
(using that role's real captured session headers), unions the discovered
surface, then probes every endpoint with every role and records the result as an
ACCESS MATRIX: endpoint -> {role: status}. From that matrix two high-value
candidate sets fall out deterministically:

  - auth-bypass / missing-auth: an endpoint the ANONYMOUS role reaches with
    substantive 2xx content, or one a lower-trust role reaches that a
    higher-trust one doesn't -- a function-level access-control gap (BFLA).
  - IDOR / BOLA: an object-scoped endpoint (a path carrying an {id}) reachable
    by more than one authenticated identity -- the precise target the existing
    cross-identity compare needs (same object, two identities).

Credentials are never stored here. Each role's headers arrive per call from the
caller (Burp, which holds the real captured session) exactly like the plain
crawl and missing-auth probe -- the harness's standing rule that sessions record
fingerprints, not secrets, is preserved. Scope-gated to allowed_hosts and paced
by the global request throttle throughout.
"""
from __future__ import annotations
import hashlib
import logging
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import httpx

from harness import crawler
from harness import global_throttle
import harness.missing_auth_probe as map_
from harness.models import Finding, HttpExchange

log = logging.getLogger("harness.role_crawl")

# A pure-digit path segment is an object id -> template it to {id} so the same
# object-scoped endpoint (tickets/1, tickets/2 ...) collapses to one row the
# access matrix probes once per role and the IDOR machinery recognises.
_NUM_SEG = re.compile(r"/\d+(?=/|$)")


def _template_ids(path: str) -> str:
    return _NUM_SEG.sub("/{id}", path)


# Probe only these declared write methods, in stable order. DELETE needs a
# purpose-built confirmation flow and is excluded from speculative crawl.
_NON_GET_PREFERENCE = ("POST", "PUT", "PATCH")

# No OpenAPI spec and no HTML form means no schema to build a body from --
# guess a minimal, generically-plausible one from common field-name
# conventions in the path, rather than sending an empty body that trips a
# uniform error across every identity and gets a real POST/PUT-only endpoint
# misread as unreachable.
_BODY_HEURISTICS: tuple[tuple[tuple[str, ...], str], ...] = (
    (("login", "signin", "sign-in", "authenticate"),
     '{"username": "probe_user", "password": "ProbeUser123!"}'),
    (("regist", "signup", "sign-up"),
     '{"username": "probe_user", "password": "ProbeUser123!", "email": "probe@example.com"}'),
    (("password", "reset"),
     '{"password": "ProbeUser123!", "new_password": "ProbeUser123!"}'),
    (("profile", "account", "settings", "/me"),
     '{"name": "Probe User", "email": "probe@example.com"}'),
)
_GENERIC_JSON_BODY = '{"name": "probe", "value": "probe"}'

# Endpoints whose own path names them as a search/filter/query surface but
# were discovered with no captured query string -- probe with a plausible
# parameter rather than an empty query that returns default/no results and
# exercises no input-handling code at all.
_QUERY_KEYWORDS = ("search", "query", "find", "filter")


def _synthesize_body(method: str, path: str) -> tuple[str, str]:
    """Guess a minimal JSON body for a POST/PUT/PATCH endpoint with no
    captured template. Returns (body, content_type); ("", "") for GET."""
    if method == "GET":
        return "", ""
    low = path.lower()
    for keywords, body in _BODY_HEURISTICS:
        if any(k in low for k in keywords):
            return body, "application/json"
    return _GENERIC_JSON_BODY, "application/json"


def _synthesize_query(path: str) -> str:
    """Guess a plausible query string for a GET endpoint that looks like a
    search/filter surface but was discovered with no captured query."""
    low = path.lower()
    if "?" in path:
        return ""
    if any(k in low for k in _QUERY_KEYWORDS):
        return "q=test"
    return ""


def _resolve_probe_methods(methods: set[str] | None) -> tuple[str, ...]:
    """Pick bounded operations to exercise for one discovered path.
    `methods` are the REAL accepted verbs from discovery (an Allow header),
    not a guess. A path can have both GET and PUT operations; collapsing it
    to one method hides the write shape. None/empty defaults to GET."""
    if not methods:
        return ("GET",)
    selected = (("GET",) if "GET" in methods else ()) + tuple(
        m for m in _NON_GET_PREFERENCE if m in methods)
    if selected:
        return selected
    # DELETE and unusual protocol verbs are never chosen for speculative
    # access-matrix probing. They require a purpose-built confirmation leg.
    return ()


def _resolve_probe_method(methods: set[str] | None) -> str | None:
    """Legacy one-method helper for callers needing a representative verb."""
    selected = _resolve_probe_methods(methods)
    return selected[0] if selected else None

# Trust ordering for the built-in identity roles (identity.IdentityRole). A role
# reaching something a STRICTLY higher-trust role also reaches is normal; a
# lower-trust role reaching something a higher one can't is the interesting
# (privilege) direction. Unknown/custom role labels sort as mid-trust.
_TRUST = {"anonymous": 0, "user": 1, "service": 2, "admin": 3}


def _trust(role: str) -> int:
    return _TRUST.get((role or "").lower(), 1)


# Role "feature" words used to de-duplicate discovery sweeps by the feature-set a
# role plausibly unlocks (not by trust -- custom labels like "carol-agent-org1"
# all default to trust 1 yet gate DIFFERENT features). Distinct roles differing
# only by tenant/instance (two "user" accounts) collapse to one sweep.
_ROLE_WORDS = ("admin", "administrator", "superuser", "root", "manager", "supervisor",
               "agent", "operator", "staff", "moderator", "support", "service",
               "editor", "author", "reviewer", "auditor", "billing", "finance",
               "user", "member", "customer", "guest")


def _feature_key(role: str) -> str:
    low = (role or "").lower()
    for w in _ROLE_WORDS:
        if w in low:
            return w
    return low


def _distinct_discovery_roles(roles: list, cap: int = 6) -> list:
    """Authenticated roles to run the discovery sweep AS, one per distinct feature
    key -- so an agent-only / manager-only endpoint (404 or 403 for other roles)
    is reached by sweeping as that role. Falls back to the highest-trust role, or
    anonymous, when no authenticated role is present. Highest-trust always kept."""
    authed = [r for r in roles if r.norm_headers()]
    if not authed:
        return [max(roles, key=lambda r: _trust(r.role))] if roles else []
    top = max(authed, key=lambda r: _trust(r.role))
    picked: dict[str, object] = {_feature_key(top.role): top}
    for r in authed:
        picked.setdefault(_feature_key(r.role), r)
    out = list(picked.values())
    # keep the highest-trust first, then stable order; cap the fan-out.
    out.sort(key=lambda r: (r is not top, r.role))
    return out[:cap]


@dataclass
class RoleSession:
    role: str                 # "anonymous" | "user" | "admin" | "service" | free label
    headers: dict             # real captured session headers; empty/none for anonymous
    name: str | None = None   # explicit principal id (username) when the tester supplies one
    # T02/R27: operator-declared identity metadata, kept distinct from the
    # credential. tenant is never inferred from a URL or role label, and
    # expected_permissions are declared by the tester/fixture, never role rank.
    tenant: str | None = None
    expected_permissions: frozenset = frozenset()

    def norm_headers(self) -> dict:
        return dict(self.headers or {})

    def principal_id(self) -> str:
        """A STABLE, DISTINCT identifier for this principal (R10). Two sessions
        with the SAME role but different credentials are different principals and
        must not collapse to one identity/matrix column. Uses the explicit `name`
        when supplied, else the role plus a short hash of the credentials (so
        alice@user and bob@user stay distinct); anonymous (no credentials) keeps
        its role label."""
        if self.name:
            return self.name
        cred = "".join(f"{k.lower()}={v};" for k, v in (self.headers or {}).items()
                       if (k or "").lower() in ("authorization", "cookie"))
        if not cred:
            return self.role or "anonymous"
        import hashlib
        return f"{self.role}#{hashlib.sha256(cred.encode()).hexdigest()[:8]}"

    def to_principal(self):
        """Adapt this session to a durable principals.Principal (T02). The id is
        stable across credential renewal (it uses the explicit name, or the role
        for anonymous, never the current cookie/token); an id that could only be
        derived from a credential hash is flagged `provisional` so callers do not
        treat it as an authoritative account or merge/split people on it."""
        from harness import principals
        provisional = not self.name and bool(self.headers)  # id came from a credential hash
        trust = principals.TRUST_BY_ROLE.get((self.role or "").lower(), 1)
        return principals.Principal(
            id=self.principal_id(), role=self.role or "user", trust=trust, tenant=self.tenant,
            expected_permissions=frozenset(self.expected_permissions or ()),
            provisional=provisional, label=self.name or self.role or "")


@dataclass
class EndpointAccess:
    method: str
    path: str                 # normalized (may contain {id})
    by_role: dict = field(default_factory=dict)   # role -> status (int) or None on error
    reachable_roles: list = field(default_factory=list)  # roles that got substantive 2xx
    # role -> {"len": int, "hash": str|None} for the SAME probed object id, so
    # the same object's response can be compared ACROSS identities (BOLA test).
    fingerprints: dict = field(default_factory=dict)

    @property
    def object_scoped(self) -> bool:
        return "{id}" in self.path

    def to_dict(self) -> dict:
        return {"method": self.method, "path": self.path, "by_role": self.by_role,
                "reachable_roles": self.reachable_roles, "object_scoped": self.object_scoped,
                "fingerprints": self.fingerprints}


def _body_fp(body: str) -> str:
    return hashlib.sha1((body or "")[:4000].encode("utf-8", "ignore")).hexdigest()[:16]


@dataclass
class RoleCrawlResult:
    base_url: str
    roles: list = field(default_factory=list)
    endpoints: list = field(default_factory=list)          # EndpointAccess
    auth_bypass_candidates: list = field(default_factory=list)  # dicts
    idor_candidates: list = field(default_factory=list)         # dicts
    # Findings from the same-object cross-identity comparison (Finding.model_dump()).
    idor_findings: list = field(default_factory=list)
    # Every substantive 2xx encountered during discovery, retained as an
    # analyzable HttpExchange (model_dump dict) so content-level review can reach
    # it. The access-matrix lens above only asks "does this differ across
    # identities?"; a body correctly scoped to its authorized identity that
    # itself leaks (a secret, PII, an internal path) yields no signal there and
    # would otherwise be dropped without ever becoming reviewable. Deduped by
    # response content, so identical bodies across roles collapse to one.
    captured: list = field(default_factory=list)
    sensitive_file_hits: list = field(default_factory=list)
    errors: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "base_url": self.base_url,
            "roles": self.roles,
            "endpoint_count": len(self.endpoints),
            "endpoints": [e.to_dict() for e in self.endpoints],
            "auth_bypass_candidates": self.auth_bypass_candidates,
            "idor_candidates": self.idor_candidates,
            "idor_findings": self.idor_findings,
            "captured": self.captured,
            "errors": self.errors,
        }


async def _probe(method: str, url: str, headers: dict, timeout: float, *,
                 run_context=None, session_ref: str | None = None,
                 body: str = "", content_type: str = "") -> tuple[int | None, str, dict]:
    if not method:
        method = "GET"
    if run_context is None and method not in ("GET", "HEAD", "OPTIONS"):
        return None, "mutating role crawl requires a gated run context", {}
    req_headers = dict(headers or {})
    if content_type and not any((k or "").lower() == "content-type" for k in req_headers):
        req_headers["Content-Type"] = content_type
    try:
        if run_context is not None:
            from harness.run_context import TypedRequest
            outcome = await run_context.executor().execute(
                TypedRequest(method=method, url=url, body=body or None,
                            headers={"Content-Type": content_type} if content_type else {}),
                capability="role_crawl", session_ref=session_ref)
            if not outcome.ok:
                return None, f"request {outcome.outcome}: {outcome.error}", {}
            return outcome.status, outcome.body or "", dict(outcome.headers or {})
        await global_throttle.acquire()
        # `content` is only passed when there is a body; older test doubles
        # and bodyless GET/HEAD/OPTIONS calls do not require the keyword.
        request_kwargs = {"headers": req_headers or None}
        if body:
            request_kwargs["content"] = body.encode("utf-8")
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
            resp = await client.request(method, url, **request_kwargs)
        # getattr guard: test stubs return a minimal response object with no
        # .headers -- capture must degrade to empty headers, not crash.
        return resp.status_code, (resp.text or ""), dict(getattr(resp, "headers", None) or {})
    except httpx.HTTPError as e:
        return None, f"request failed: {e.__class__.__name__}", {}


async def crawl_roles(
    base_url: str,
    roles: list[RoleSession],
    *,
    allowed_hosts: list[str] | None = None,
    max_pages: int = 40,
    max_endpoints: int = 150,
    id_fill: str = "1",
    timeout: float = 15.0,
    active_discovery: bool = False,
    discovery_max_probes: int = 6000,
    max_captured: int = 200,
    run_context=None,
    session_refs: list[str | None] | None = None,
) -> RoleCrawlResult:
    """Crawl `base_url` once per role, union the surface, probe every endpoint
    with every role, and derive auth-bypass + IDOR candidates from the matrix.

    `roles` is a list of RoleSession; include an anonymous role (empty headers)
    to detect auth bypass. Probing is bounded by `max_endpoints` method+path
    operations so a large surface cannot fan out without limit.

    `active_discovery` augments the JS-mined surface with black-box API discovery
    (api_surface_discovery) -- essential on a headless API where the JS crawler
    finds nothing. The engagement builder turns active discovery on."""
    result = RoleCrawlResult(base_url=base_url, roles=[r.role for r in roles])
    if not roles:
        result.errors.append("no roles supplied")
        return result
    if run_context is not None and (session_refs is None or len(session_refs) != len(roles)):
        result.errors.append("run_context requires one explicit session reference per role")
        return result

    # 1. Discover the surface, per role (authenticated pages/JS may reveal more).
    discovered: set[str] = set()
    # path -> real accepted HTTP verbs, from active discovery's Allow-header
    # introspection. A path with no entry here came from the passive JS/HTML
    # crawl only, which carries no method signal -- default GET for those.
    path_methods: dict[str, set[str]] = {}
    for role_index, r in enumerate(roles):
        try:
            cr = await crawler.crawl(base_url, headers=r.norm_headers(),
                                     allowed_hosts=allowed_hosts, max_pages=max_pages,
                                     run_context=run_context,
                                     session_ref=(session_refs[role_index]
                                                  if session_refs is not None else None))
            discovered |= cr.endpoints
            result.errors.extend(f"[{r.role}] {e}" for e in cr.errors)
        except Exception as e:  # a bad role's crawl must not sink the whole run
            result.errors.append(f"[{r.role}] crawl failed: {e.__class__.__name__}")

    # 1b. Active black-box API discovery (opt-in). Runs ONCE as the most-trusted
    # role -- route EXISTENCE is ~role-independent (a 401 still proves the route);
    # per-role ACCESS is the probe step below. Concrete ids are templated to {id}.
    if active_discovery:
        try:
            from harness.api_surface_discovery import SurfaceDiscovery
            # Sweep discovery AS each distinct-feature authenticated role, not just
            # the single highest-trust one: role feature-sets differ (an agent-only
            # integrations/webhook endpoint is 404/403 for admin), so a one-identity
            # sweep structurally misses them. Union the routes; split the probe
            # budget across the sweeps so the total stays within discovery_max_probes.
            sweep_roles = _distinct_discovery_roles(roles)
            # Each sweep gets the FULL budget, not a split share: the wordlist needs
            # the whole budget to complete, and discovery probes are cheap HTTP GETs
            # (the iterative agent, not discovery, dominates wall time). Splitting it
            # (budget // n) truncated the wordlist and REGRESSED coverage below the
            # single-sweep baseline (session-13 re-run: 21 -> 17 endpoints). Full
            # budget per sweep can only ADD role-gated routes, never subtract.
            per_budget = discovery_max_probes
            total_routes, total_probes = 0, 0
            for sr in sweep_roles:
                try:
                    # Feed the crawler's HTML/JS-mined links (and routes found by an
                    # earlier sweep) in as seed paths so active discovery derives the
                    # namespaces they reveal (Phase 0.2(a)) and later sweeps benefit.
                    disc = SurfaceDiscovery(base_url, headers=sr.norm_headers(),
                                            allowed_hosts=allowed_hosts, max_probes=per_budget,
                                            seed_paths=sorted(discovered),
                                            run_context=run_context,
                                            session_ref=(session_refs[roles.index(sr)]
                                                         if session_refs is not None else None))
                    sres = await disc.discover()
                    for rt in sres.routes:
                        tp = _template_ids(rt.path)
                        discovered.add(tp)
                        if rt.methods:
                            path_methods.setdefault(tp, set()).update(
                                m.upper() for m in rt.methods if m.upper() != "OPTIONS")
                    total_routes += len(sres.routes); total_probes += sres.probes_sent
                    result.sensitive_file_hits.extend(sres.sensitive_file_hits)
                    if sres.spec_found:
                        result.errors.append(f"[discovery] used spec {sres.spec_found}")
                except Exception as e:
                    result.errors.append(f"[discovery] sweep as {sr.role!r} failed: {e.__class__.__name__}")
            log.info("role_crawl: active discovery swept %d role(s) -> %d routes (%d probes), "
                     "%d unique paths", len(sweep_roles), total_routes, total_probes, len(discovered))
        except Exception as e:
            result.errors.append(f"[discovery] failed: {e.__class__.__name__}")

    operations = [(path, method) for path in sorted(discovered)
                  for method in _resolve_probe_methods(path_methods.get(path))]
    if len(operations) > max_endpoints:
        result.errors.append(f"surface truncated to {max_endpoints} of {len(operations)} "
                             "endpoint operations for probing")

    # 2. Probe each endpoint with each role -> access matrix.
    captured_keys: set[tuple] = set()   # (method, path, body-fp) -> dedup captures
    for path, probe_method in operations[:max_endpoints]:
        # Use the endpoint's REAL accepted method (from discovery's Allow-header
        # introspection) rather than always GET -- a POST/PUT-only endpoint
        # probed with GET returns a uniform wrong-method error to every role
        # and is misread as unreachable/dead, never exercising the endpoint's
        # actual logic. No method info (passive JS/HTML crawl only) -> GET.
        req_body, req_ctype = _synthesize_body(probe_method, path)
        query = _synthesize_query(path) if probe_method == "GET" else ""
        url = map_._build_url(base_url, path, id_fill)
        if query:
            url = f"{url}?{query}"
        if not map_._host_allowed(url, allowed_hosts):
            continue
        access = EndpointAccess(method=probe_method, path=path)
        for role_index, r in enumerate(roles):
            status, body, resp_headers = await _probe(
                probe_method, url, r.norm_headers(), timeout, run_context=run_context,
                session_ref=session_refs[role_index] if session_refs is not None else None,
                body=req_body, content_type=req_ctype)
            access.by_role[r.role] = status
            substantive = map_._substantive(status, body)
            if substantive:
                access.reachable_roles.append(r.role)
                # Phase 0.1: retain the substantive 2xx as an analyzable exchange
                # so full content-level review reaches it, AND (R05) so the
                # request body/query the harness actually used to reach it
                # survives as this endpoint's replay template -- not an empty
                # fabrication -- via record_template downstream. Dedup by
                # response content -- identical bodies returned to several
                # roles are one exchange for content purposes (the
                # cross-identity lens already owns the "same body to two
                # identities" signal separately).
                cap_key = (access.method, path, _body_fp(body))
                if cap_key not in captured_keys and len(result.captured) < max_captured:
                    captured_keys.add(cap_key)
                    req_headers = dict(r.norm_headers())
                    if req_ctype and not any((k or "").lower() == "content-type" for k in req_headers):
                        req_headers["Content-Type"] = req_ctype
                    result.captured.append(HttpExchange(
                        url=url, method=access.method,
                        request_headers=req_headers, request_body=req_body,
                        response_status=status, response_headers=resp_headers,
                        response_body=body,
                        analyst_note=f"role_crawl discovery capture as '{r.role}' (HTTP {status})",
                    ).model_dump())
            # Record a body fingerprint for object-scoped endpoints so the SAME
            # object's response can be compared across identities below.
            if access.object_scoped:
                access.fingerprints[r.role] = {
                    "len": len((body or "").strip()),
                    "hash": _body_fp(body) if substantive else None,
                }
        result.endpoints.append(access)

    _derive_candidates(result, roles)
    _compare_identities(result, roles, id_fill)
    log.info("role_crawl: %s -- %d endpoints, %d auth-bypass, %d idor candidates, "
             "%d idor findings, %d captured exchanges",
             base_url, len(result.endpoints), len(result.auth_bypass_candidates),
             len(result.idor_candidates), len(result.idor_findings), len(result.captured))
    return result


def _compare_identities(result: RoleCrawlResult, roles: list[RoleSession], id_fill: str) -> None:
    """The queued same-object comparison, run deterministically: for each
    object-scoped endpoint, group the AUTHENTICATED identities that reached it by
    their response fingerprint. When the SAME object id returns byte-identical
    substantive content to two or more DISTINCT identities, the endpoint isn't
    scoping the object per-identity -- either it's a shared/public object or it's
    a broken object-level authorization (BOLA/IDOR). That distinction needs a
    human (is object {id} meant to be private?), so this ships as an unconfirmed,
    moderate-confidence finding, not a confirmation."""
    authed = {r.role for r in roles if _trust(r.role) > 0}
    for e in result.endpoints:
        if not e.object_scoped:
            continue
        by_hash: dict[str, list[str]] = {}
        for role in e.reachable_roles:
            if role not in authed:
                continue
            h = e.fingerprints.get(role, {}).get("hash")
            if h:
                by_hash.setdefault(h, []).append(role)
        for _hash, sharing in by_hash.items():
            distinct = sorted(set(sharing))
            if len(distinct) < 2:
                continue
            url_shown = e.path.replace("{id}", id_fill)
            result.idor_findings.append(Finding(
                vulnerability_class="idor",
                confidence=0.65,
                summary=(f"Object-scoped endpoint {e.method} {e.path} returns identical content "
                         f"for object id={id_fill} to distinct identities ({', '.join(distinct)}) "
                         f"-- object-level authorization is not enforced per-identity."),
                evidence=(f"Same request ({e.method} {url_shown}) sent as each identity returned "
                          f"byte-identical substantive responses across {', '.join(distinct)}. "
                          f"If object id={id_fill} is meant to be private to one identity, this is "
                          f"BOLA/IDOR; if it is a shared/public object it is benign -- confirm ownership."),
                suggested_test=(f"Fetch an object that belongs to one identity, then request the SAME "
                                f"object id as another identity; a proper control returns 403/404 or that "
                                f"identity's own object, not the first identity's data."),
                basis="derived",
                severity="high",
                owasp_category="A01:2021-Broken Access Control",
                confirmed=False,
                validation_hints=[f"cross_identity_compare:{e.path}"],
            ).model_dump())


def _derive_candidates(result: RoleCrawlResult, roles: list[RoleSession]) -> None:
    anon_roles = {r.role for r in roles if _trust(r.role) == 0}
    for e in result.endpoints:
        reachable = set(e.reachable_roles)
        if not reachable:
            continue

        # Auth bypass: reachable anonymously at all -> served without credentials.
        anon_reach = reachable & anon_roles
        if anon_reach:
            result.auth_bypass_candidates.append({
                "path": e.path, "method": e.method, "reached_by": sorted(reachable),
                "reason": "reachable with no authentication (anonymous role got substantive 2xx)",
                "severity": "high", "class": "missing_authentication",
                "by_role": e.by_role,
            })
        else:
            # Function-level authz gap: a lower-trust role reaches something a
            # strictly higher-trust role in this run does NOT -- the privilege
            # direction is inverted from what RBAC would produce.
            reached_trust = min(_trust(x) for x in reachable)
            higher_absent = sorted(r.role for r in roles
                                   if r.role not in reachable and _trust(r.role) > reached_trust)
            if higher_absent and reached_trust > 0:
                result.auth_bypass_candidates.append({
                    "path": e.path, "method": e.method, "reached_by": sorted(reachable),
                    "reason": f"reachable by lower-trust role(s) but not higher-trust role(s) "
                              f"{higher_absent} -- inverted privilege direction, a broken "
                              f"function-level authorization candidate",
                    "severity": "medium", "class": "authz",
                    "by_role": e.by_role,
                })

        # IDOR/BOLA: an object-scoped endpoint reachable by >=1 authenticated
        # identity -- the target for a same-object cross-identity comparison.
        authed_reach = sorted(x for x in reachable if _trust(x) > 0)
        if e.object_scoped and authed_reach:
            result.idor_candidates.append({
                "path": e.path, "method": e.method, "reached_by": authed_reach,
                "reason": "object-scoped endpoint ({id} in path) reachable by an authenticated "
                          "identity -- test same object id across identities for IDOR/BOLA",
                "severity": "high", "class": "idor",
                "by_role": e.by_role,
            })
