"""
Cross-identity (Autorize-style) access-control validator.

The single-exchange idor/auth/api agents can only GUESS at broken access control:
one captured request cannot distinguish "a 200 returning my own data" (secure)
from "a 200 returning someone else's data" (IDOR). The only way to tell is the
Autorize move -- replay the SAME request as a DIFFERENT identity (and
unauthenticated) and compare -- which needs credentials the harness deliberately
never stores.

This validator does exactly that, tester-fed: it reads other identities' session
headers from identity_headers (in-memory, never persisted -- the tester supplies
them, like configuring Autorize's low-priv cookie), replays the request as each,
plus an anonymous baseline, and runs the already-proven identity_compare decision
logic (authorization_boundary_compare):

  - CONFIRMED  -> another identity reached the owner's protected resource while
                 anon was denied: a real broken-access-control finding. Sets
                 finding.confirmed and boosts confidence (via _validate_findings).
  - not_confirmed (deterministic REJECT) -> every other identity AND anon were
                 denied: the control held. The orchestrator downgrades the
                 single-exchange hypothesis (mirroring access_control_gate).
  - skipped    -> no identities configured, out of scope, or non-GET (safe by
                 default; mutating replay is intentionally not attempted here).

Off by default: gated by validators.cross_identity.enabled AND
validators.active_enabled (it sends live requests), and scoped to
server.allowed_hosts. GET-only.
"""
from __future__ import annotations
import re
from urllib.parse import urlparse, parse_qs

import httpx

import access_control_gate
import identity_compare
import identity_headers
from models import Finding, HttpExchange
from .base import Validator, ValidationResult

# A path segment that looks like an OBJECT IDENTIFIER (the thing an IDOR swaps):
# all-digits (/orders/1), a long hex/uuid (/tickets/a1b2c3d4-...), or a long hash.
_ID_SEGMENT = re.compile(r'^(\d+|[0-9a-fA-F]{8,}|[0-9a-fA-F]{8}-[0-9a-fA-F-]{4,})$')
# Query params that carry an object reference.
_ID_QUERY_KEYS = {"id", "user", "user_id", "userid", "uid", "order", "order_id",
                  "account", "account_id", "oid", "object", "resource", "doc", "file"}

# Collection nouns that, when a NON-numeric slug directly follows them
# (/users/alice, /tickets/support-42), mark that slug as a specific object an
# IDOR could swap -- the case _ID_SEGMENT can't catch because the id is a name
# rather than a number/hash. A closed allowlist (singular + plural) keeps this
# conservative: only after one of these is a bare slug treated as an object.
_COLLECTION_NOUNS = frozenset({
    "users", "user", "accounts", "account", "orders", "order", "tickets", "ticket",
    "invoices", "invoice", "customers", "customer", "clients", "client",
    "documents", "document", "docs", "doc", "files", "file", "profiles",
    "posts", "post", "items", "item", "products", "product", "projects", "project",
    "reports", "report", "records", "record", "messages", "message",
    "comments", "comment", "notes", "note", "transactions", "transaction",
    "payments", "payment", "subscriptions", "subscription", "groups", "group",
    "teams", "team", "organizations", "orgs", "org", "companies", "company",
    "employees", "employee", "members", "member", "articles", "article",
    "images", "image", "photos", "photo", "videos", "video", "carts", "cart",
    "addresses", "address", "bookings", "booking", "reservations", "reservation",
    "appointments", "appointment", "events", "event", "folders", "folder",
    "resources", "resource", "entities", "entity",
    # relationship / sub-collection nouns -- a collection following a collection
    # (/products/reviews) is a nested list, not one object; listing them here
    # lets the nested-collection guard in _looks_like_object_slug skip them.
    "reviews", "review", "likes", "like", "tags", "tag", "roles", "role",
    "permissions", "permission", "followers", "following", "notifications",
    "notification", "replies", "reply", "ratings", "rating", "attachments",
    "attachment", "versions", "version", "revisions", "revision", "favorites",
    "favorite", "tokens", "token",
})
# Words that, even when they follow a collection noun, are NOT an object id:
# self-references (/users/me returns the caller's OWN data -- the TN3 FP) and
# route verbs / non-object views (/users/search, /orders/export). Denylisting
# biases toward SKIPPING (a miss, never a false positive) -- the safe direction.
_RESERVED_SLUGS = frozenset({
    # self-reference
    "me", "self", "current", "mine", "my", "own",
    # profile / meta views
    "profile", "account", "dashboard", "settings", "preferences", "home",
    "overview", "index", "default", "none", "null", "undefined",
    # CRUD / action / list verbs
    "new", "create", "add", "edit", "update", "delete", "remove", "save",
    "search", "filter", "query", "list", "all", "export", "import", "upload",
    "download", "bulk", "batch", "count", "stats", "summary", "history",
    "activity", "feed", "latest", "recent",
})


# An ADMIN/privilege-namespaced FUNCTION path: the namespace itself declares the
# intended boundary (admin-only), so reaching it as a non-admin identity while
# anonymous is denied is a broken FUNCTION-level authorization (BFLA) -- distinct
# from BOLA (object swap), which needs an object id. Kept narrow (only unambiguous
# admin namespaces) to avoid the /account, /profile, /reports false positives.
_ADMIN_NAMESPACE = re.compile(
    r"/(admin|administrator|manage|management|internal|console|backoffice|"
    r"back-office|sysadmin|superuser|moderation|moderator)(/|$)", re.IGNORECASE)
# A role label that is itself privileged -- an admin reaching an admin function is
# expected, not a bypass, so such identities are excluded from the BFLA test.
_PRIVILEGED_ROLE = re.compile(
    r"admin|administrator|superuser|root|manager|supervisor|staff|operator|"
    r"moderator|sysadmin", re.IGNORECASE)


def is_admin_namespaced(url: str) -> bool:
    """True iff the path lives under an unambiguously admin/privilege namespace."""
    return bool(_ADMIN_NAMESPACE.search(urlparse(url).path or ""))


def _looks_like_object_slug(prev: str, seg: str) -> bool:
    """A non-numeric slug counts as an object identifier only when it directly
    follows a known collection noun and is not itself a self-reference/verb/
    sub-collection keyword -- so /users/alice matches, but /users/me,
    /users/search and /products/reviews do not. Deliberately conservative: when
    unsure it returns False (skip, no cross-identity), which is the safe
    direction -- a miss, never the /users/me-style false positive the
    object-identifier gate exists to prevent (TN3)."""
    if prev.lower() not in _COLLECTION_NOUNS:
        return False
    base = seg.split(".", 1)[0].lower()  # strip a trailing .json/.xml before matching
    if not base or base in _RESERVED_SLUGS:
        return False
    # A collection noun following a collection noun is a nested sub-collection
    # (/products/reviews), not a single object -- don't treat it as an id.
    return base not in _COLLECTION_NOUNS


def has_object_identifier(url: str) -> bool:
    """True iff the URL references a SPECIFIC object an IDOR could swap. A
    token-relative endpoint (/users/me, /profile, /account, /dashboard) has no
    such identifier -- it returns each identity's OWN data, so a cross-identity
    'match' there is two different self-profiles that merely share a JSON shape,
    not an access-control bug. This is the fix for the /api/users/me false
    positive (TN3). A numeric/hash id (/orders/1) is caught by _ID_SEGMENT; a
    named-slug id (/users/alice) by the collection-noun rule in
    _looks_like_object_slug."""
    p = urlparse(url)
    segments = [s for s in p.path.split("/") if s]
    if any(_ID_SEGMENT.match(s) for s in segments):
        return True
    if any(_looks_like_object_slug(prev, seg) for prev, seg in zip(segments, segments[1:])):
        return True
    return any(k.lower() in _ID_QUERY_KEYS for k in parse_qs(p.query))


def _auth_signature(headers: dict | None) -> tuple:
    """A normalized fingerprint of the PRINCIPAL a set of request headers
    authenticates as: its Authorization value plus its Cookie header. Two header
    sets with the same signature are the SAME principal -- replaying one against
    the other is self-comparison, never a cross-identity test (R10). An empty
    signature (no auth material) means an anonymous/unknown principal, for which
    no self-exclusion is possible."""
    headers = headers or {}
    auth = ""
    cookie = ""
    for k, v in headers.items():
        lk = (k or "").lower()
        if lk == "authorization":
            auth = (v or "").strip()
        elif lk == "cookie":
            cookie = (v or "").strip()
    if not auth and not cookie:
        return ()
    return (auth, cookie)


def _distinct_other_principals(idents: list, source_sig: tuple) -> list:
    """The configured identities that are DISTINCT principals from the source
    (R10): drop any whose credentials equal the source request's, and collapse
    duplicate credentials so one principal supplied twice is not counted twice.
    Two accounts with the SAME role but different credentials are kept -- that is
    exactly the same-role cross-user case the test must exercise."""
    out: list = []
    seen: set = set()
    for i in idents:
        sig = _auth_signature(i.get("headers"))
        if source_sig and sig == source_sig:
            continue  # this identity IS the source principal
        if sig and sig in seen:
            continue  # duplicate credential -> same principal already counted
        if sig:
            seen.add(sig)
        out.append(i)
    return out


class CrossIdentityValidator(Validator):
    name = "cross_identity"
    active = True  # sends live requests; only runs when validators.active_enabled

    def __init__(self, allowed_hosts: list[str] | None = None,
                 timeout: float = 10.0, max_identities: int = 3, ownership=None,
                 run_context=None):
        self.allowed_hosts = set(allowed_hosts or [])
        self.timeout = timeout
        self.max_identities = max_identities
        # T02: an optional principals.OwnershipLedger. When supplied, a would-be
        # BOLA confirmation is checked against observed ownership first, so the
        # object's owner, an explicitly-shared principal, or a public object is NOT
        # reported as a boundary crossing. Default None keeps pre-T02 behavior.
        self.ownership = ownership
        # T03: an optional run_context.RunContext. When supplied, every probe is sent
        # through its Executor -- one gate/scope/budget decision with redirects
        # re-checked per hop -- instead of a bespoke httpx client. Default None keeps
        # the legacy direct path, so registry construction is unchanged until a run
        # supplies a context.
        self.run_context = run_context

    def _object_ref(self, url: str) -> str:
        """The object identity used to look up ownership facts. The URL path is a
        stable per-object key; the ownership-recording side uses the same convention."""
        return urlparse(url).path or url

    def applies(self, finding: Finding, exchange: HttpExchange) -> bool:
        # Reuse the access-control gate's markers so the two never drift.
        return access_control_gate._is_access_control_class(finding.vulnerability_class)

    async def _probe(self, url: str, headers: dict,
                     session_ref: str | None = None) -> identity_compare.Probe:
        """Live GET. A method seam so unit tests can replace it with a canned
        responder and never touch the network. When a RunContext is configured (T03)
        the send goes through its Executor -- one policy path (scope + gate + budget,
        redirects re-checked per hop); a policy-declined send is reported as
        'not reached' (status 0), never a crash."""
        if self.run_context is not None:
            from run_context import TypedRequest
            out = await self.run_context.executor().execute(
                TypedRequest("GET", url, headers=dict(headers or {})),
                capability=self.name, session_ref=session_ref)
            if out.outcome == "error":
                raise RuntimeError(out.error or "probe transport error")
            if not out.executed:   # out_of_scope / blocked / budget / cancelled -> not reached
                return identity_compare.Probe(0, "")
            return identity_compare.Probe(out.status or 0, out.body or "")
        import global_throttle
        await global_throttle.acquire()
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=False, verify=False) as client:
            resp = await client.get(url, headers=headers or None)
        return identity_compare.Probe(resp.status_code, resp.text)

    def _run_identities(self, host: str) -> list[dict]:
        if self.run_context is None:
            return identity_headers.identities_for_host(host)
        return [{"name": s.name or s.principal_id, "role": s.role,
                 "headers": dict(s.headers), "session_ref": s.session_id,
                 "principal_id": s.principal_id}
                for s in self.run_context.sessions.all()
                if s.principal_id != "anonymous"]

    def _anonymous_session_ref(self) -> str | None:
        if self.run_context is None:
            return None
        for session in self.run_context.sessions.all():
            if session.principal_id == "anonymous":
                return session.session_id
        return None

    async def _probe_identity(self, url: str, ident: dict) -> identity_compare.Probe:
        session_ref = ident.get("session_ref")
        if session_ref is None:
            return await self._probe(url, ident["headers"])
        return await self._probe(url, ident["headers"], session_ref)

    def _skip(self, fc: str, why: str) -> ValidationResult:
        return ValidationResult(validator=self.name, status="skipped", finding_class=fc, summary=why)

    @staticmethod
    def _reached(probe: "identity_compare.Probe") -> bool:
        """A substantive success: 2xx with a non-trivial body (not an empty/error
        stub). Used by the function-level test to tell 'served the admin function'
        from 'denied'."""
        return 200 <= (probe.status or 0) < 300 and len((probe.body or "").strip()) > 20

    async def _confirm_bfla(self, fc: str, exchange: HttpExchange, idents: list,
                            anon: "identity_compare.Probe") -> ValidationResult:
        """Function-level authorization (BFLA) confirmation for an admin-namespaced
        endpoint: a NON-privileged identity reaching it (substantive 2xx) while the
        anonymous baseline is denied is a real bypass. An admin-role identity is
        excluded (an admin reaching an admin function is expected). Confirms only
        that unambiguous case; if every non-admin identity is denied, the control
        held (not_confirmed)."""
        if self._reached(anon):
            return self._skip(fc, "the admin-namespaced endpoint is reachable ANONYMOUSLY -- that is a "
                                  "missing-authentication issue (auth_bypass), not a function-level "
                                  "authorization bypass; not this leg's confirmation")
        # R11: an admin namespace is a LEAD, not an entitlement specification. A
        # non-admin getting a 2xx there may be a legitimate delegated/read-only view.
        # To CONFIRM we need a privileged-DATA oracle: the non-admin must see the
        # SAME privileged content an ADMIN sees. Establish the admin baseline first.
        admin_probe = None
        for ident in idents:
            if _PRIVILEGED_ROLE.search(ident.get("role", "") or ""):
                try:
                    admin_probe = await self._probe_identity(exchange.url, ident)
                except Exception:
                    admin_probe = None
                if admin_probe is not None:
                    break
        have_admin_baseline = admin_probe is not None and self._reached(admin_probe)

        considered = 0
        rejects = 0
        reached_unproven = None
        for ident in idents[:self.max_identities]:
            if _PRIVILEGED_ROLE.search(ident.get("role", "") or ""):
                continue  # an admin reaching an admin function is expected, not a bypass
            try:
                attempt = await self._probe_identity(exchange.url, ident)
            except Exception:
                continue
            considered += 1
            if self._reached(attempt):
                # Confirm ONLY when the non-admin's response materially MATCHES the
                # admin's -- i.e. it returned the same privileged data, not merely a
                # 2xx on an admin-looking path.
                if have_admin_baseline and identity_compare.similarity(
                        attempt.body, admin_probe.body) >= identity_compare.MATCH_THRESHOLD:
                    return ValidationResult(
                        validator=self.name, status="confirmed", finding_class=fc,
                        confidence=0.85, confirmed=True,
                        summary=f"Broken function-level authorization: non-privileged identity "
                                f"{ident['name']!r} (role {ident.get('role','?')!r}) obtained the same "
                                f"privileged response an admin sees at {exchange.url} while anonymous was denied.",
                        evidence=f"Anonymous -> HTTP {anon.status} (denied); {ident['name']!r} -> HTTP "
                                 f"{attempt.status} returning content materially matching the admin baseline "
                                 f"(similarity >= {identity_compare.MATCH_THRESHOLD}). A non-admin obtained "
                                 f"the admin function's privileged data.")
                reached_unproven = ident  # reached, but not proven to be a real bypass
            else:
                rejects += 1
        if considered == 0:
            return self._skip(fc, "only privileged-role identities are configured -- cannot test a "
                                  "function-level bypass (an admin reaching an admin function is expected). "
                                  "Supply a lower-privilege identity's session to test BFLA")
        if reached_unproven is not None:
            return ValidationResult(
                validator=self.name, status="not_confirmed", finding_class=fc, confidence=0.4, confirmed=False,
                summary=f"OBSERVATION (not confirmed): non-privileged identity {reached_unproven['name']!r} "
                        f"reached the admin-namespaced function {exchange.url}, but this leg could not "
                        f"establish it returned the same PRIVILEGED data an admin sees "
                        f"({'no admin baseline configured' if not have_admin_baseline else 'the responses differed'}). "
                        f"An admin namespace is a lead, not proof -- delegated/read-only access may be legitimate.",
                evidence=f"Supply an admin session for a privileged-data comparison, or verify the returned "
                         f"content is genuinely admin-only, before treating this as a confirmed BFLA.")
        if rejects == considered:
            return ValidationResult(
                validator=self.name, status="not_confirmed", finding_class=fc, confidence=0.8, confirmed=False,
                summary="Function-level authorization holds: every non-privileged identity was denied "
                        "this admin-namespaced function (and anonymous too).",
                evidence=f"{considered} non-privileged identity/identities tested against {exchange.url}; "
                         f"all denied.")
        return self._skip(fc, "function-level comparison inconclusive")

    async def validate(self, finding: Finding, exchange: HttpExchange) -> ValidationResult:
        fc = finding.vulnerability_class
        if (exchange.method or "GET").upper() != "GET":
            return self._skip(fc, "cross-identity replay is GET-only (safe); a mutating request is not replayed here")
        host = urlparse(exchange.url).hostname or ""
        if self.run_context is not None and not self.run_context.scope.in_scope(exchange.url):
            return self._skip(fc, f"host {host!r} is outside the run scope")
        if self.run_context is None and self.allowed_hosts and host not in self.allowed_hosts:
            return self._skip(fc, f"host {host!r} is outside server.allowed_hosts scope")
        object_scoped = has_object_identifier(exchange.url)
        function_level = not object_scoped and is_admin_namespaced(exchange.url)
        if not object_scoped and not function_level:
            return self._skip(fc, "no object identifier in the path/query -- a token-relative "
                                  "endpoint (e.g. /users/me, /profile, /dashboard) returns each "
                                  "identity's OWN data and is not an IDOR candidate; and the path is "
                                  "not admin-namespaced, so it is not a function-level (BFLA) "
                                  "candidate either; cross-identity needs an object reference to swap "
                                  "or an admin-namespaced function to reach")
        idents = self._run_identities(host)
        if not idents:
            return self._skip(fc, "no identities configured for this host -- supply another identity's "
                                  "session headers via POST /identities/session-headers (Autorize-style)")

        # R10: reject SELF-COMPARISON. The captured request was made by some
        # principal (its Authorization/Cookie). Replaying it "as another identity"
        # that is really the SAME principal proves nothing -- a principal reaching
        # its own resource is not an access-control failure. Exclude the source
        # principal and collapse duplicate credentials to DISTINCT principals.
        source_sig = _auth_signature(exchange.request_headers)
        idents_distinct = _distinct_other_principals(idents, source_sig)
        if not idents_distinct:
            return self._skip(fc, "only the source principal's own credentials are configured -- "
                                  "cross-identity needs a DISTINCT principal (a different account, even "
                                  "with the same role) to replay as; a principal reaching its own resource "
                                  "is not evidence of IDOR/BFLA (R10 self-comparison guard)")

        candidate = identity_compare.Probe(exchange.response_status or 0, exchange.response_body or "")
        try:
            anon_ref = self._anonymous_session_ref()
            if self.run_context is not None and anon_ref is None:
                return self._skip(fc, "run has no explicit anonymous session")
            anon = (await self._probe(exchange.url, {}, anon_ref)
                    if anon_ref is not None else await self._probe(exchange.url, {}))
        except Exception as e:  # network/scope error -- degrade, never crash the pipeline
            return ValidationResult(validator=self.name, status="error", finding_class=fc,
                                    summary=f"anonymous baseline probe failed: {e}")

        # Function-level authorization (BFLA): an admin-namespaced function reached
        # by a NON-privileged identity while anonymous is denied. The namespace
        # declares the intended admin-only boundary; a non-admin role crossing it
        # is a real bypass. Distinct from the BOLA object-swap path below.
        if function_level:
            return await self._confirm_bfla(fc, exchange, idents_distinct, anon)

        considered = 0
        rejects = 0
        for ident in idents_distinct[:self.max_identities]:
            try:
                attempt = await self._probe_identity(exchange.url, ident)
            except Exception:
                continue
            considered += 1
            ev = identity_compare.evaluate(
                "authorization_boundary_compare", False, candidate, candidate, attempt, anon)
            if ev.verdict == identity_compare.Verdict.CONFIRMED:
                # T02 ownership gate: reaching another identity's object is only a
                # crossing if that identity was NOT entitled to it. If observed
                # ownership shows AUTHORIZED access (own / explicitly shared /
                # public), this is authorized sharing, not BOLA -> observation, not
                # a confirmation. UNKNOWN ownership falls through to the existing
                # response-similarity verdict (it neither invents nor suppresses).
                if self.ownership is not None:
                    import principals as _pr
                    accessor = _pr.Principal(
                        id=ident.get("name") or ident.get("role") or "unknown",
                        role=ident.get("role", "user"),
                        trust=_pr.TRUST_BY_ROLE.get((ident.get("role") or "").lower(), 1))
                    if self.ownership.authorization(accessor, self._object_ref(exchange.url)) \
                            == _pr.AuthzDecision.AUTHORIZED:
                        return ValidationResult(
                            validator=self.name, status="not_confirmed", finding_class=fc,
                            confidence=0.3, confirmed=False,
                            summary=f"OBSERVATION (not confirmed): {ident['name']!r} reached "
                                    f"{exchange.url}, but ownership provenance shows this access is "
                                    f"AUTHORIZED (own / shared / public object) -- authorized sharing is "
                                    f"not a broken-object-authorization crossing.",
                            evidence=f"OwnershipLedger: {ident.get('name')!r} is entitled to "
                                     f"{self._object_ref(exchange.url)!r}; a cross-identity 2xx here is "
                                     f"expected, not a bug.")
                return ValidationResult(
                    validator=self.name, status="confirmed", finding_class=fc,
                    confidence=ev.confidence, confirmed=True,
                    summary=f"Cross-identity ({ident['name']}): {ev.summary}", evidence=ev.detail)
            if ev.verdict == identity_compare.Verdict.REJECTED:
                rejects += 1

        if considered == 0:
            return self._skip(fc, "no configured identity probe could be sent")
        if rejects == considered:
            return ValidationResult(
                validator=self.name, status="not_confirmed", finding_class=fc, confidence=0.8, confirmed=False,
                summary="Access correctly restricted: every configured other identity, and the anonymous "
                        "baseline, were denied this resource -- the single-exchange access-control hypothesis "
                        "is contradicted by an active cross-identity test.",
                evidence=f"{considered} identity/identities tested against {exchange.url}; all rejected")
        return self._skip(fc, "cross-identity comparison inconclusive (no confirmation, and not every "
                              "identity was cleanly rejected)")
