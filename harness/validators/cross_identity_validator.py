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
                 anon was denied AND declared ownership says that identity is not
                 entitled to it: a real broken-access-control finding. Sets
                 finding.confirmed and boosts confidence (via _validate_findings).
  - supported  -> the same response match, but ownership of the object was NOT
                 declared (WL-04, RETIRED (review 2026-10-21): a resource shared
                 with every logged-in user matches identically, so similarity
                 alone cannot tell a crossing from authorized sharing). A lead
                 with manual-verification guidance; never a confirmation and
                 never a negative.
  - not_confirmed (deterministic REJECT) -> every other identity AND anon were
                 denied: the control held. The orchestrator downgrades the
                 single-exchange hypothesis (mirroring access_control_gate).
  - skipped    -> no identities configured, out of scope, or a write while
                 mutating replay is off.

Write leg (B1-T2, PUT/PATCH/DELETE): only with validators.allow_mutating_replay
and the run's safety gate. Owner baseline read, one write as a non-privileged
other principal changing one field to a unique marker, owner read-back, then a
MANDATORY restore check (in `finally`): a restore is sent only when a write went
out and no owner read shows the object unchanged (a denied write sends none),
PATCH restores only the changed field, and the restore is verified against the
whole object minus volatile keys (timestamps, versions). A baseline with masked
values is refused before any full-object write. One per-object lock spans
baseline to verification. A failed restore is a logged `error`. Confirmed only
when the marker persisted on an object declared to another principal; an
undeclared/shared object is a `supported` lead. Not restored: a server that
scopes the write to the SESSION user changes the writer's own record, which this
leg cannot locate; that case is reported in the not_confirmed summary.

Off by default: gated by validators.cross_identity.enabled AND
validators.active_enabled (it sends live requests), and scoped to
server.allowed_hosts. Reads are GET-only; writes need the mutating gate.
"""
from __future__ import annotations
from harness import scope_lock
import re
import asyncio
import json
import logging
import secrets
import weakref
from dataclasses import dataclass
from urllib.parse import urlparse, parse_qs

log = logging.getLogger(__name__)

import httpx

from harness import access_control_gate
from harness import identity_compare
from harness import identity_headers
from harness.models import Finding, HttpExchange
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


@dataclass
class _UnsentProbe(identity_compare.Probe):
    """A probe the executor refused or never sent (budget, safety gate, scope,
    cancellation). It still reads as status 0 / empty body, the 'policy-declined ->
    not reached' contract of ``_probe``, but carries why, so a caller can tell it
    from a response (R10)."""
    outcome: str = ""


def _not_reached(probe) -> bool:
    """True when no HTTP response was obtained for this probe. A request that was
    refused or never sent is neither a denial nor an authorization verdict: it must
    never be compared as if the target had answered (R10). A real response never has
    status 0."""
    return isinstance(probe, _UnsentProbe) or (getattr(probe, "status", 0) or 0) <= 0


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


# Ids the harness derives from a CREDENTIAL rather than from an account name:
# role_crawl.RoleSession.principal_id() with no name ("<role>#<8 hex>") and the R05
# captured-session id store.captured_principal_id() mints ("captured:<hmac>"). Such
# an id names a credential, not an account, so it cannot be matched against a
# declared owner: the owner's own second session would read as "not the owner".
_CREDENTIAL_ALIAS = re.compile(r"(?:#[0-9a-fA-F]{8}$|^captured:)")


def _principal_for(ident: dict):
    """The durable principal an identity entry authenticates as. A Principal carried
    by the run session is authoritative; otherwise one is built from the entry's
    name/role, marked provisional when the name is only a credential alias."""
    import harness.principals as _pr
    principal = ident.get("principal")
    if principal is not None:
        return principal
    pid = ident.get("principal_id") or ident.get("name") or ident.get("role") or "unknown"
    return _pr.Principal(
        id=pid, role=ident.get("role", "user"),
        trust=_pr.TRUST_BY_ROLE.get((ident.get("role") or "").lower(), 1),
        provisional=bool(_CREDENTIAL_ALIAS.search(pid)) or pid == "unknown")


def _source_identity(idents: list, source_sig: tuple) -> dict | None:
    """The configured identity whose credentials made the captured request, if it
    is registered (WL-04: the capture may itself be the crossing, so its principal
    must be resolvable to apply a declaration to it)."""
    if not source_sig:
        return None
    for i in idents:
        if _auth_signature(i.get("headers")) == source_sig:
            return i
    return None


from contextvars import ContextVar
_ownership_method = ContextVar("ownership_method", default="GET")
_WRITE_METHODS = frozenset({"PUT", "PATCH", "DELETE"})

# A value a read MASKS rather than returns ("****", bullet runs, "[REDACTED]"). Sending
# it back in a full-object write would overwrite the real value with the mask, so
# a baseline holding one is not safely round-trippable.
_MASKED_VALUE = re.compile(
    r"\*{3,}|\u2022{3,}|\u25cf{3,}|^\s*[\[<({]?\s*(redacted|masked|hidden|filtered|"
    r"removed|omitted|withheld|censored|sensitive)\s*[\]>)}]?\s*$", re.IGNORECASE)
# Keys the server rewrites on every save (timestamps, versions, etags). Restore
# verification ignores them; every other key must match the baseline.
_VOLATILE_KEY = re.compile(
    r"^(?:(?:created|changed|deleted|last(?:login|seen|access(?:ed)?)?)"
    r"(?:at|on|date|time|timestamp|ts)|last(?:modified|updated|changed)\w*|modified\w*|"
    r"updated\w*|timestamp|ts|version|etag|rev|revision|lockversion|v)$")


def _masked_paths(obj, prefix: str = "") -> list[str]:
    """Paths of string values in `obj` that look masked or redacted."""
    if isinstance(obj, dict):
        return [p for k, v in obj.items() for p in _masked_paths(v, f"{prefix}{k}.")]
    if isinstance(obj, list):
        return [p for i, v in enumerate(obj) for p in _masked_paths(v, f"{prefix}{i}.")]
    return [prefix.rstrip(".")] if isinstance(obj, str) and _MASKED_VALUE.search(obj) else []


def _stable(obj):
    """`obj` without volatile (server-rewritten) keys, recursively."""
    if isinstance(obj, dict):
        return {k: _stable(v) for k, v in obj.items()
                if not _VOLATILE_KEY.match(re.sub(r"[^a-z0-9]", "", str(k).lower()))}
    if isinstance(obj, list):
        return [_stable(v) for v in obj]
    return obj


def _object_lock_key(url: str) -> str:
    """One key per target object: scheme, host, effective port, the path with
    duplicate/trailing slashes collapsed, and the query in sorted order."""
    from urllib.parse import unquote, urlsplit
    parts = urlsplit(url)
    scheme = (parts.scheme or "http").lower()
    try:
        port = parts.port
    except ValueError:
        port = None
    port = port or {"http": 80, "https": 443}.get(scheme)
    path = re.sub(r"/+", "/", unquote(parts.path or "/")).rstrip("/") or "/"
    query = "&".join(sorted(parts.query.split("&"))) if parts.query else ""
    return f"{scheme}://{(parts.hostname or '').lower()}:{port}{path}?{query}"


# Per event loop, one lock per target object: two write cases on the same object
# (registry dispatch and the engagement chain's own validator instance) must not
# interleave, or the second takes the first's marker as its "original" and
# restores to it.
_OBJECT_LOCKS: "weakref.WeakKeyDictionary" = weakref.WeakKeyDictionary()


def _object_lock(url: str) -> asyncio.Lock:
    locks = _OBJECT_LOCKS.setdefault(asyncio.get_running_loop(), {})
    return locks.setdefault(_object_lock_key(url), asyncio.Lock())


class CrossIdentityValidator(Validator):
    name = "cross_identity"
    active = True  # sends live requests; only runs when validators.active_enabled

    def __init__(self, allowed_hosts: list[str] | None = None,
                 timeout: float = 10.0, max_identities: int = 3, ownership=None,
                 run_context=None, delete_restore_method: str = "",
                 allow_writes: bool = False):
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
        # DELETE cannot be reversed generically. An operator must explicitly
        # declare that PUT recreates the exact resource before this leg deletes it.
        self.delete_restore_method = (delete_restore_method or "").upper()
        # B1-T2: whether this registry's config permits mutating replay
        # (validators.allow_mutating_replay). Off, a captured write never arms the
        # leg -- reads stay GET-only. On, the run's own safety gate still decides
        # every send (validate re-checks it before writing anything).
        self.allow_writes = bool(allow_writes)

    def _object_ref(self, url: str) -> str:
        from harness import principals
        run_id = self.run_context.run_id if self.run_context is not None else ""
        return principals.object_reference(url, run_id=run_id)

    def applies(self, finding: Finding, exchange: HttpExchange) -> bool:
        # Reuse the access-control gate's markers so the two never drift.
        if not access_control_gate._is_access_control_class(finding.vulnerability_class):
            return False
        return self.shape_applies(exchange) and self.write_admitted(exchange.method)

    def write_admitted(self, method: str | None) -> bool:
        """Whether this leg may be armed for `method`: GET always; PUT/PATCH only
        with mutating replay permitted; DELETE additionally needs the operator's
        delete_restore_method=PUT recreation contract."""
        method = (method or "GET").upper()
        if method == "GET":
            return True
        if method not in _WRITE_METHODS or not self.allow_writes:
            return False
        return method != "DELETE" or self.delete_restore_method == "PUT"

    @staticmethod
    def shape_applies(exchange: HttpExchange) -> bool:
        """The request shapes this leg can test: a GET, or an object write (PUT/
        PATCH/DELETE, B1-T2), that names an object to swap or reaches an
        admin-namespaced function. Any other shape (a login POST, a collection read
        like /rest/memories/) is never sent here, so the leg's own "skipped" is not
        recorded as having tested it (r5). Whether a write may arm the leg is a
        policy question answered by write_admitted, not by shape."""
        if (exchange.method or "GET").upper() not in {"GET", *_WRITE_METHODS}:
            return False
        return has_object_identifier(exchange.url) or is_admin_namespaced(exchange.url)

    async def _probe(self, url: str, headers: dict,
                     session_ref: str | None = None) -> identity_compare.Probe:
        """Live GET. A method seam so unit tests can replace it with a canned
        responder and never touch the network. When a RunContext is configured (T03)
        the send goes through its Executor -- one policy path (scope + gate + budget,
        redirects re-checked per hop); a policy-declined send is reported as
        'not reached' (status 0, an ``_UnsentProbe``), never a crash."""
        if self.run_context is not None:
            from harness.run_context import TypedRequest
            out = await self.run_context.executor().execute(
                TypedRequest("GET", url, headers=dict(headers or {})),
                capability=self.name, session_ref=session_ref)
            if out.outcome == "error":
                raise RuntimeError(out.error or "probe transport error")
            if not out.executed:   # out_of_scope / blocked / budget / cancelled -> not reached
                return _UnsentProbe(0, "", outcome=out.outcome or "not sent")
            return identity_compare.Probe(out.status or 0, out.body or "", artifact_id=out.artifact_id)
        from harness import global_throttle
        await global_throttle.acquire()
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=False, verify=False) as client:
            resp = await client.get(url, headers=headers or None)
        return identity_compare.Probe(resp.status_code, resp.text)

    def _run_identities(self, host: str) -> list[dict]:
        if self.run_context is None:
            return identity_headers.identities_for_host(host)
        return [{"name": s.name or s.principal_id, "role": s.role,
                 "headers": dict(s.headers), "session_ref": s.session_id,
                 "principal_id": s.principal_id, "principal": s.principal}
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

    async def _matching_replay(self, url: str, ident: dict | None,
                               against: "identity_compare.Probe"):
        """`ident`'s own read of `url`, replayed, when it was reached and materially
        matches `against`: the exchange a crossing's proof is audited against
        (Ticket 6). None otherwise, so the proof names no exchange that does not
        show what the verdict says. Outside a run it would name nothing: not sent."""
        if ident is None or self.run_context is None:
            return None
        try:
            probe = await self._probe_identity(url, ident)
        except Exception:
            return None
        if _not_reached(probe) or identity_compare.similarity(
                probe.body, against.body) < identity_compare.MATCH_THRESHOLD:
            return None
        return probe

    def _skip(self, fc: str, why: str) -> ValidationResult:
        return ValidationResult(validator=self.name, status="skipped", finding_class=fc, summary=why)

    def _blocked(self, fc: str, why: str, evidence: str = "") -> ValidationResult:
        """The access-control check was refused or never sent (R10). Not a negative:
        no control_outcome, so it is never read as a held control."""
        return ValidationResult(validator=self.name, status="blocked", finding_class=fc,
                                confidence=0.0, confirmed=False, summary=why, evidence=evidence)

    def _ownership_decision(self, principal, url: str):
        """WL-04 ownership gate: what the declared/observed ownership of the object
        at `url` says about `principal` reaching it. UNKNOWN when no ownership
        source is configured, when nothing is known about this object, or when the
        principal's id is only a credential alias (it cannot be compared with a
        declared owner, so "not the owner" cannot be asserted for it)."""
        import harness.principals as _pr
        if self.ownership is None:
            return _pr.AuthzDecision.UNKNOWN
        ref, method = self._object_ref(url), _ownership_method.get()
        source = "declared"
        if hasattr(self.ownership, "authorization_source"):
            decision, source, _ = self.ownership.authorization_source(principal, ref, method)
        else:
            decision = self.ownership.authorization(principal, ref, method)
        # A self-observed decision already required the owner and this principal to
        # be shown to be different ACCOUNTS (self_ownership.py), so a credential
        # alias does not make it unknown; against a declared owner it does.
        if decision == _pr.AuthzDecision.UNAUTHORIZED and getattr(principal, "provisional", False) \
                and source != "self_observed":
            return _pr.AuthzDecision.UNKNOWN
        return decision

    def _ownership_provenance(self, exchange):
        fact = self.ownership.lookup(self._object_ref(exchange.url), exchange.method) if self.ownership else None
        if fact is None and getattr(self.ownership, "self_observed", None) is not None:
            hit = self.ownership.self_observed.fact_for(exchange.url)
            if hit is not None:
                return hit[1]
        return fact.provenance if fact else "no ownership provenance"

    def _ownership_kind(self, exchange) -> str:
        if getattr(self.ownership, "self_observed", None) is not None \
                and not self.ownership.has_declaration(self._object_ref(exchange.url), exchange.method):
            return "Self-observed"
        return "Declared"

    def _undeclared_lead(self, fc: str, exchange: HttpExchange, ident: dict, detail: str,
                         function_level: bool = False) -> ValidationResult:
        """RETIRED (review 2026-10-21, WL-04): a response match with anonymous
        denied used to confirm on its own. A resource legitimately shared with every
        authenticated user (a team announcement, a shared catalogue) produces the
        same match, so without declared ownership this is a LEAD, not a
        confirmation -- and not a negative either: status `supported` is neither a
        controlled negative (confirmation_gate) nor tested coverage
        (coverage_tracker), and carries the analyst's next step."""
        ref = self._object_ref(exchange.url)
        kind = "function" if function_level else "object"
        who = f"{ident.get('name')!r} (role {ident.get('role', '?')!r})"
        guidance = (
            f"Establish ownership before treating this as broken access control. "
            f"Identity {who} received materially the same response as the source "
            f"principal at {exchange.url} while the anonymous request was denied, but "
            f"nothing declares who may reach this {kind}. (1) Identify the owning "
            f"principal, e.g. the account that created the {kind} or the owner field in "
            f"its response. (2) Check whether {ident.get('name')!r} is entitled to it: "
            f"explicit sharing, team/organisation membership, or visibility to every "
            f"authenticated user -- any of those is authorized sharing, not BOLA/BFLA. "
            f"(3) Declare the result (owner principal plus the explicitly entitled "
            f"principals, or public) as an ownership fact for this {kind} and re-run the "
            f"cross-identity check; it confirms only when the declaration says the "
            f"accessor is not entitled.")
        return ValidationResult(
            validator=self.name, status="supported", finding_class=fc,
            confidence=0.55, confirmed=False,
            summary=f"LEAD (not confirmed): cross-identity read by {ident.get('name')} matched the "
                    f"source principal's response at {exchange.url} with anonymous denied, but "
                    f"ownership of the {kind} was not declared -- authorized sharing (e.g. a "
                    f"resource visible to every logged-in user) cannot be ruled out.",
            evidence=f"Ownership NOT declared for {ref!r}: no owner, share or public fact is "
                     f"known for this {kind}, so the response match is not a confirmed "
                     f"boundary crossing. {detail}",
            control_outcome="inconclusive", manual_verification=guidance)

    @staticmethod
    def _unsent_reason(probe) -> str:
        return getattr(probe, "outcome", "") or "not sent"

    @staticmethod
    def _incomplete_detail(errored: int, unsent: int, unsent_why: str) -> str:
        parts = []
        if errored:
            parts.append(f"{errored} errored")
        if unsent:
            parts.append(f"{unsent} not sent: {unsent_why}")
        return ", ".join(parts)

    @staticmethod
    def _last_error_note(errored: int, last_error) -> str:
        return f" (last error: {last_error})" if errored else ""

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
                if admin_probe is not None and _not_reached(admin_probe):
                    admin_probe = None   # refused/unsent: no baseline, not a denial (R10)
                if admin_probe is not None:
                    break
        have_admin_baseline = admin_probe is not None and self._reached(admin_probe)

        import harness.principals as _pr
        considered = 0
        rejects = 0
        authorized = 0
        undeclared = None   # first (identity, detail) admin-data match with no declaration
        errored = 0
        unsent = 0
        unsent_why = ""
        last_error = None
        reached_unproven = None
        for ident in idents[:self.max_identities]:
            if _PRIVILEGED_ROLE.search(ident.get("role", "") or ""):
                continue  # an admin reaching an admin function is expected, not a bypass
            try:
                attempt = await self._probe_identity(exchange.url, ident)
            except Exception as e:
                errored += 1       # an errored probe is an UNKNOWN, not a denial
                last_error = e
                continue
            if _not_reached(attempt):
                unsent += 1        # a refused/unsent probe is an UNKNOWN too (R10)
                unsent_why = self._unsent_reason(attempt)
                continue
            considered += 1
            if self._reached(attempt):
                # Confirm ONLY when the non-admin's response materially MATCHES the
                # admin's -- i.e. it returned the same privileged data, not merely a
                # 2xx on an admin-looking path -- AND a declaration says this identity
                # is not entitled to the function (WL-04). The admin namespace is a
                # path-name lead, not a declaration of who may reach the function
                # (RV-M M1: a label never declares a route protected); a management
                # view shared with all staff matches the admin's response identically.
                sim = identity_compare.similarity(attempt.body, admin_probe.body) \
                    if have_admin_baseline else 0.0
                if have_admin_baseline and sim >= identity_compare.MATCH_THRESHOLD:
                    detail = (f"Anonymous -> HTTP {anon.status} (denied); {ident['name']!r} -> HTTP "
                              f"{attempt.status} returning content materially matching the admin "
                              f"baseline (similarity {sim:.3f} >= {identity_compare.MATCH_THRESHOLD}).")
                    accessor = _principal_for(ident)
                    decision = self._ownership_decision(accessor, exchange.url)
                    if decision == _pr.AuthzDecision.UNAUTHORIZED:
                        return ValidationResult(
                            validator=self.name, status="confirmed", finding_class=fc,
                            confidence=0.85, confirmed=True,
                            summary=f"Broken function-level authorization: non-privileged identity "
                                    f"{ident['name']!r} (role {ident.get('role','?')!r}) obtained the same "
                                    f"privileged response an admin sees at {exchange.url} while anonymous was denied.",
                            evidence=f"{detail} The declared entitlement for "
                                     f"{self._object_ref(exchange.url)!r} does not include "
                                     f"{accessor.id!r}: a non-admin obtained the admin function's "
                                     f"privileged data. {self._ownership_provenance(exchange)}"
                        ).with_artifacts(baseline=admin_probe, attack=attempt, controls=[anon])
                    if decision == _pr.AuthzDecision.AUTHORIZED:
                        authorized += 1
                        continue
                    if undeclared is None:
                        undeclared = (ident, detail)
                    continue
                reached_unproven = ident  # reached, but not proven to be a real bypass
            else:
                rejects += 1
        if undeclared is not None:
            return self._undeclared_lead(fc, exchange, *undeclared, function_level=True)
        if authorized:
            return ValidationResult(
                validator=self.name, status="not_confirmed", finding_class=fc,
                confidence=0.3, confirmed=False,
                summary=f"OBSERVATION (not confirmed): {authorized} principal(s) declared entitled "
                        f"to {exchange.url} reached it; authorized access to the function, not a "
                        f"bypass. All {considered} configured non-privileged principals were evaluated.",
                evidence=f"Declared entitlement authorized {authorized} of {considered} tested "
                         f"principal(s) for {self._object_ref(exchange.url)!r}.",
                control_outcome="inconclusive")
        if considered == 0:
            if unsent:
                return self._blocked(
                    fc, f"function-level authorization NOT tested: {unsent} non-privileged identity "
                        f"request(s) were not sent ({unsent_why}); a refused request is not evidence "
                        f"that the control held",
                    evidence=f"No response was obtained for {exchange.url}; this is not a negative result.")
            if errored:
                return self._skip(fc, f"could not test a function-level bypass: every non-privileged probe "
                                      f"errored ({errored}; last: {last_error}) -- an errored probe is an "
                                      f"unknown, never evidence that the control held")
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
                         f"content is genuinely admin-only, before treating this as a confirmed BFLA.",
                control_outcome="inconclusive")
        if errored or unsent:
            # An errored or unsent probe is an UNKNOWN, not a denial. Without this guard it
            # silently drops out of `considered`, so a single remaining denial
            # satisfies rejects==considered and the leg reports "authorization
            # holds" at 0.8 with control_outcome="control_held" -- which the
            # downgrade block in orchestrator_confirm treats as a refutation,
            # turning a network/scope failure into a confident clean bill of
            # health against a real BFLA lead. Report inconclusive, never held.
            return ValidationResult(
                validator=self.name, status="not_confirmed", finding_class=fc, confidence=0.0, confirmed=False,
                summary=f"Function-level authorization test INCONCLUSIVE: {rejects} non-privileged "
                        f"identity/identities were denied, but {errored + unsent} probe(s) "
                        f"({self._incomplete_detail(errored, unsent, unsent_why)}) could not be "
                        f"evaluated -- 'every non-privileged identity was denied' cannot be asserted.",
                evidence=f"{considered} non-privileged identity/identities tested against {exchange.url} "
                         f"({rejects} denied); {self._incomplete_detail(errored, unsent, unsent_why)}"
                         f"{self._last_error_note(errored, last_error)}. An errored or unsent probe "
                         f"is an unknown, not a denial, so this is NOT reported as a held control.",
                control_outcome="inconclusive")
        if rejects == considered:
            return ValidationResult(
                validator=self.name, status="not_confirmed", finding_class=fc, confidence=0.8, confirmed=False,
                summary="Function-level authorization holds: every non-privileged identity was denied "
                        "this admin-namespaced function (and anonymous too).",
                evidence=f"{considered} non-privileged identity/identities tested against {exchange.url}; "
                         f"all denied.",
                control_outcome="control_held")
        return self._skip(fc, "function-level comparison inconclusive")

    async def _validate_write(self, finding, exchange):
        from harness.principals import AuthzDecision
        from harness.run_context import TypedRequest
        from harness.security import is_identity_credential_header

        fc, method, run = finding.vulnerability_class, exchange.method.upper(), self.run_context
        if not self.write_admitted(method):
            # The construction-time policy (validators.allow_mutating_replay and
            # the DELETE recreation contract) binds every caller, including
            # those that call validate() without applies().
            return self._skip(fc, "Write authorization skipped: this validator was not built with "
                                  "mutating replay permission (validators.allow_mutating_replay) "
                                  "or, for DELETE, a delete_restore_method=PUT contract")
        if run is None:
            return self._skip(fc, "Write authorization requires a run transport and registered sessions")
        if not run.gate.config.active_enabled or not run.gate.config.allow_mutating_replay:
            return self._skip(fc, "Write authorization skipped: mutating replay permission is off")
        if not run.scope.in_scope(exchange.url) or not self.shape_applies(exchange):
            return self._skip(fc, "Write authorization requires an in-scope object reference")
        # Refuse before changing anything when known ceilings cannot pay for undo.
        case_ref = finding.finding_id or finding.case_id or "write-authz-" + secrets.token_hex(8)
        headroom, _, _ = run.gate.mutating_headroom(case_ref, self.name)
        if headroom < 2 or (run.budget.remaining is not None and run.budget.remaining < 6):
            return self._skip(fc, "Write and verified restore need two mutating sends for this case "
                                  "(validators.mutating_ceiling_by_check.cross_identity >= 2) and "
                                  "six request slots; nothing was written")
        idents = self._run_identities(urlparse(exchange.url).hostname or "")
        source = _source_identity(idents, _auth_signature(exchange.request_headers))
        fact = self.ownership.lookup(self._object_ref(exchange.url), method) if self.ownership else None
        owner_id = fact.owner_principal_id if fact else ""
        owner = next((i for i in idents if _principal_for(i).id == owner_id), None) if owner_id else source
        if owner is None or not owner.get("session_ref"):
            return self._skip(fc, "No registered owner/baseline session is available for restoration")
        others = _distinct_other_principals(idents, _auth_signature(owner["headers"]))
        others = [i for i in others if not _PRIVILEGED_ROLE.search(i.get("role", ""))
                  and not _principal_for(i).provisional
                  and self._ownership_decision(_principal_for(i), exchange.url) != AuthzDecision.AUTHORIZED]
        if not others:
            return self._skip(fc, "No distinct non-privileged principal available to test the write")
        # Held from the baseline read through restore verification, so a second
        # write case on the same object never reads this case's marker as its
        # original (and restores the target to it).
        async with _object_lock(exchange.url):
            return await self._write_locked(finding, exchange, case_ref, owner, others[0],
                                            AuthzDecision, TypedRequest, is_identity_credential_header)

    async def _write_locked(self, finding, exchange, case_ref, owner, other,
                            AuthzDecision, TypedRequest, is_identity_credential_header):
        fc, method, run = finding.vulnerability_class, exchange.method.upper(), self.run_context
        # One controlled attempt per dispatch; no repeated mutation of the object.
        headers = {k: v for k, v in exchange.request_headers.items()
                   if not is_identity_credential_header(k) and k.lower() not in
                   {"host", "content-length", "if-match", "if-none-match"}}
        headers["Content-Type"] = "application/json"

        async def send(verb, ident, body=None, cleanup=False):
            return await run.executor().execute(
                TypedRequest(verb, exchange.url, headers=headers,
                             body=json.dumps(body) if body is not None else None),
                capability=self.name, session_ref=ident["session_ref"],
                case_ref=case_ref, allow_cancelled_cleanup=cleanup)

        def object_body(answer):
            if answer is None or not answer.ok or not 200 <= (answer.status or 0) < 300:
                return None
            try:
                obj = json.loads(answer.body)
            except (ValueError, TypeError):
                return None
            for _ in range(3):
                if isinstance(obj, dict) and len(obj) == 1 and isinstance(
                        next(iter(obj.values())), dict):
                    obj = next(iter(obj.values()))
                else:
                    break
            return obj if isinstance(obj, dict) and obj else None

        baseline = await send("GET", owner)
        original = object_body(baseline)
        if original is None:
            return self._skip(fc, "Owner baseline did not return a restorable JSON object")
        try:
            captured = json.loads(exchange.request_body or "{}")
        except ValueError:
            captured = {}
        if not isinstance(captured, dict):
            captured = {}
        forbidden = {"id", "owner", "ownerid", "userid", "role", "password", "token",
                     "email", "username", "apikey", "sessiontoken", "totpsecret"}
        field = next((k for k in captured if isinstance(original.get(k), str)
                      and re.sub(r"[^a-z0-9]", "", k.lower()) not in forbidden
                      and not _VOLATILE_KEY.match(re.sub(r"[^a-z0-9]", "", k.lower()))), None)
        if method != "DELETE" and field is None:
            return self._skip(fc, "No existing non-credential string field in the captured write to restore")
        # A full-object write (the PUT attack, its restore, and the DELETE
        # recreation PUT) sends the owner's GET body back. A read that masks a
        # value would turn that into an overwrite with the mask, so refuse the
        # leg before any write. PATCH sends only `field`, so only it must be real.
        # NOT covered: a field the read OMITS entirely (server-computed, write-only)
        # is invisible here; a full PUT can still drop it, and verification cannot
        # see it either. Operators should arm PUT only on round-trippable objects.
        masked = _masked_paths(original if method in {"PUT", "DELETE"} else {field: original[field]})
        if masked:
            return self._skip(fc, "Owner baseline is not safely round-trippable (masked/redacted "
                                  "value at " + ", ".join(masked[:5]) + "); nothing was written")
        marker = "harness_authz_" + secrets.token_hex(12)
        attack_body = ({**original, field: marker} if method == "PUT" else {field: marker})
        # Minimal restore: PATCH sends back only the changed field; PUT (and the
        # DELETE recreation PUT) must carry the whole object.
        restore_body = original if method in {"PUT", "DELETE"} else {field: original[field]}
        # DELETE is undone by the operator-declared recreation verb (only PUT is admitted).
        restore_method = self.delete_restore_method if method == "DELETE" else method
        # Preflight both payloads through the same gate before attempting a write.
        for verb, body in ((method, None if method == "DELETE" else attack_body),
                           (restore_method, restore_body)):
            decision = run.gate.authorize(validator_name=self.name, method=verb,
                                          url=exchange.url, body=json.dumps(body))
            if not decision.allowed:
                return self._skip(fc, "Write/restore preflight refused: " + decision.reason)

        def matches_original(obj) -> bool:
            # The whole object minus volatile keys (timestamps, versions, etags the
            # server rewrites on every save), and no trace of the marker.
            return (obj is not None and marker not in json.dumps(obj)
                    and _stable(obj) == _stable(original))

        def changed(observed):
            """True: the object differs from the baseline (marker present, other
            values changed, or -- for DELETE -- gone). False: an owner read shows
            it unchanged (still present, for DELETE). None: unknown."""
            if observed is None or not observed.ok:
                return None
            if method == "DELETE" and observed.status in {404, 410}:
                return True
            obj = object_body(observed)
            if obj is None:
                return None
            if method == "DELETE":
                return False   # still present: nothing to recreate
            return not matches_original(obj)

        attack_sent = False

        def restore_needed(observed) -> bool | None:
            state = changed(observed)
            if state is not None:
                return state
            if not attack_sent or (attack is not None and not attack.executed):
                return False   # no write ever left: nothing to undo
            if attack is not None and attack.ok and 400 <= (attack.status or 0) < 500:
                return False   # denied (401/403/4xx), and no read shows a change
            return None        # a write may have committed and no read says otherwise

        async def restore():
            """Undo only what may have changed. Returns (undo, check, sent)."""
            need = restore_needed(after)
            check = after
            if need is None:
                # Look before writing: a fresh owner read decides.
                check = await send("GET", owner, cleanup=True)
                need = changed(check)
                if need is None:
                    need = True   # the attack may have committed; undo it
            if not need:
                return None, check, False
            undo = await send(restore_method, owner, restore_body, cleanup=True)
            check = await send("GET", owner, cleanup=True)
            return undo, check, True

        attack = after = undo = restored = None
        restore_sent = False
        failure, cancelled = "", False
        try:
            attack_sent = True
            attack = await send(method, other, None if method == "DELETE" else attack_body)
            after = await send("GET", owner)
        except asyncio.CancelledError:
            cancelled = True
        except Exception as exc:  # a timeout can follow a committed write
            failure = f"probe raised {type(exc).__name__}: {exc}"
        finally:
            # MANDATORY undo check, as the owner, even after an exception or run
            # cancellation (cleanup sends bypass the cancel token). A restore is
            # SENT only when a write went out and was not shown unchanged by an
            # owner read. Shielded so a second cancellation cannot abandon it.
            task = asyncio.ensure_future(restore())
            try:
                try:
                    undo, restored, restore_sent = await asyncio.shield(task)
                except asyncio.CancelledError:
                    cancelled = True
                    undo, restored, restore_sent = await task
            except Exception as exc:
                restore_sent = True   # unknown: report it as a failed restore
                failure += f"; restore raised {type(exc).__name__}: {exc}"
        if restore_sent:
            restore_ok = (undo is not None and undo.ok and 200 <= (undo.status or 0) < 300
                          and matches_original(object_body(restored)))
        else:
            restore_ok = True
        evidence = (f"object={exchange.url}; owner/baseline={_principal_for(owner).id}; "
                    f"writer={_principal_for(other).id}; method={method}; "
                    f"field={field or '[deleted object]'}; marker={marker}; "
                    f"attack_status={getattr(attack, 'status', None)}; "
                    f"restore={'sent' if restore_sent else 'not_needed'}; "
                    f"restore_status={getattr(undo, 'status', None)}; "
                    f"restore_succeeded={str(restore_ok).lower()}")
        if not restore_ok:
            # Loud: the target may still hold the marker (or lack the object).
            message = ("RESTORE FAILED: the original state of " + exchange.url + " could not be "
                       "restored and verified; the target may still hold " + marker
                       + " -- restore it manually. " + evidence + (" " + failure if failure else ""))
            log.error(message)
            if cancelled:
                raise asyncio.CancelledError(message)
            return ValidationResult(self.name, "error", fc, summary=message, evidence=evidence)
        if cancelled:
            raise asyncio.CancelledError
        undone = "original restored" if restore_sent else "object unchanged, no restore needed"
        controls = [after] + ([restored] if restore_sent else [])
        if failure or attack is None or after is None or not attack.ok or not after.ok:
            return ValidationResult(self.name, "error", fc,
                                    summary=f"Write probe incomplete; {undone}. " + failure,
                                    evidence=evidence)
        if attack.status in {401, 403}:
            return ValidationResult(self.name, "not_confirmed", fc,
                                    summary=f"Other principal's {method} was denied "
                                            f"(HTTP {attack.status}); {undone}",
                                    evidence=evidence, control_outcome="control_held"
                                    ).with_artifacts(baseline=baseline, attack=attack,
                                                     controls=controls)
        persisted = ((after.status in {404, 410}) if method == "DELETE" else
                     (object_body(after) or {}).get(field) == marker)
        if not 200 <= (attack.status or 0) < 300 or not persisted:
            note = ""
            if 200 <= (attack.status or 0) < 300 and method != "DELETE":
                # NOT restored: a server that scopes the write to the SESSION user
                # applies it to the writer's own record, which this leg cannot
                # locate generically. Surface it so the operator can check.
                note = (f" The server accepted the write without changing this object; if it "
                        f"scopes writes to the session user, {_principal_for(other).id!r}'s own "
                        f"record may now hold {marker} in {field!r} -- check and restore it manually.")
                log.warning("cross_identity write accepted but not applied to %s; the writer's "
                            "own record may hold %s", exchange.url, marker)
            return ValidationResult(self.name, "not_confirmed", fc,
                                    summary=f"{method} as another principal returned HTTP "
                                            f"{attack.status} but the owner read-back did not show "
                                            f"the change; {undone}.{note}",
                                    evidence=evidence).with_artifacts(
                                        baseline=baseline, attack=attack, controls=controls)
        # Confirmed only against a DECLARED boundary: a known owner who is not the
        # writer, or an object declared to a privileged principal (admin-only).
        # Undeclared/shared (catalogue) objects stay a lead.
        denied = self._ownership_decision(_principal_for(other), exchange.url) == AuthzDecision.UNAUTHORIZED
        return ValidationResult(
            self.name, "confirmed" if denied else "supported", fc,
            confirmed=denied, confidence=0.9 if denied else 0.4,
            summary=(f"Broken object-level write authorization: {_principal_for(other).id!r} "
                     f"{method} persisted on an object declared to another principal; original restored"
                     if denied else
                     f"LEAD: a low-privilege {method} persisted on an object with no declared "
                     f"owner or access expectation; original restored. Verify whether this "
                     f"principal may modify it."),
            evidence=evidence + "; " + self._ownership_provenance(exchange),
        ).with_artifacts(baseline=baseline, attack=attack, controls=controls)

    async def validate(self, finding: Finding, exchange: HttpExchange) -> ValidationResult:
        token = _ownership_method.set(exchange.method)
        try:
            return await self._validate_with_ownership_method(finding, exchange)
        finally:
            _ownership_method.reset(token)

    async def _validate_with_ownership_method(self, finding: Finding, exchange: HttpExchange) -> ValidationResult:
        fc = finding.vulnerability_class
        if (exchange.method or "GET").upper() in _WRITE_METHODS:
            return await self._validate_write(finding, exchange)
        if (exchange.method or "GET").upper() != "GET":
            return self._skip(fc, "cross-identity replay is GET-only (safe); a mutating request is not replayed here")
        host = urlparse(exchange.url).hostname or ""
        if self.run_context is not None and not self.run_context.scope.in_scope(exchange.url):
            return self._skip(fc, f"host {host!r} is outside the run scope")
        if self.run_context is None and self.allowed_hosts and not scope_lock.host_in_scope(exchange.url, self.allowed_hosts):
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
        if _not_reached(anon):
            # R10: the baseline was refused (budget, gate, scope, cancellation) or never
            # sent. Comparing an identity against an empty "denial" would claim a held
            # control the target never exercised.
            return self._blocked(
                fc, f"cross-identity access control NOT tested: the anonymous baseline request was "
                    f"not sent ({self._unsent_reason(anon)}); a refused request is not evidence "
                    f"that the control held",
                evidence=f"No response was obtained for {exchange.url}; this is not a negative result.")

        # Function-level authorization (BFLA): an admin-namespaced function reached
        # by a NON-privileged identity while anonymous is denied. The namespace
        # declares the intended admin-only boundary; a non-admin role crossing it
        # is a real bypass. Distinct from the BOLA object-swap path below.
        if function_level:
            return await self._confirm_bfla(fc, exchange, idents_distinct, anon)

        import harness.principals as _pr
        considered = 0
        rejects = 0
        authorized = 0
        undeclared = None   # first (identity, evidence) crossing with no ownership declared
        errored = 0
        unsent = 0
        unsent_why = ""
        last_error = None
        for ident in idents_distinct[:self.max_identities]:
            try:
                attempt = await self._probe_identity(exchange.url, ident)
            except Exception as e:
                errored += 1       # an errored probe is an UNKNOWN, not a denial
                last_error = e
                continue
            if _not_reached(attempt):
                unsent += 1        # a refused/unsent probe is an UNKNOWN too (R10)
                unsent_why = self._unsent_reason(attempt)
                continue
            considered += 1
            ev = identity_compare.evaluate(
                "authorization_boundary_compare", False, candidate, candidate, attempt, anon)
            if ev.verdict == identity_compare.Verdict.CONFIRMED:
                # WL-04 ownership gate (T02 made strict): a response match with
                # anonymous denied is a boundary crossing ONLY when declared ownership
                # says the principal that received it was not entitled to it.
                #   UNAUTHORIZED accessor -> confirmed (the other identity crossed).
                #   AUTHORIZED accessor (owner / shared / public): the owner's own
                #     replay matching the capture shows the content is the protected
                #     object, so if the SOURCE principal is declared not entitled, the
                #     capture itself is the crossing -> confirmed; otherwise this is
                #     authorized sharing -> observation.
                #   UNKNOWN (no ownership source, nothing declared for this object,
                #     or a credential-alias id) -> a `supported` lead, never a
                #     confirmation (a resource shared with every authenticated user
                #     matches identically) and never a negative.
                accessor = _principal_for(ident)
                decision = self._ownership_decision(accessor, exchange.url)
                if decision == _pr.AuthzDecision.UNAUTHORIZED:
                    # Baseline: the source principal's own read, replayed live (the
                    # comparison above used the captured response, not a run send).
                    source_read = await self._matching_replay(
                        exchange.url, _source_identity(idents, source_sig), attempt)
                    return ValidationResult(
                        validator=self.name, status="confirmed", finding_class=fc,
                        confidence=ev.confidence, confirmed=True,
                        summary=f"Cross-identity ({ident['name']}): {ev.summary}",
                        evidence=f"{self._ownership_kind(exchange)} ownership of {self._object_ref(exchange.url)!r} does not "
                                 f"entitle {accessor.id!r} to it. {self._ownership_provenance(exchange)}. {ev.detail}"
                    ).with_artifacts(baseline=source_read, attack=attempt, controls=[anon])
                if decision == _pr.AuthzDecision.AUTHORIZED:
                    source_ident = _source_identity(idents, source_sig)
                    source = _principal_for(source_ident) if source_ident is not None else None
                    if source is not None and self._ownership_decision(source, exchange.url) \
                            == _pr.AuthzDecision.UNAUTHORIZED:
                        # The crossing is the capture itself: the attack exchange is
                        # the source principal's read replayed live, the entitled
                        # principal's read its baseline.
                        source_read = await self._matching_replay(exchange.url, source_ident, attempt)
                        return ValidationResult(
                            validator=self.name, status="confirmed", finding_class=fc,
                            confidence=ev.confidence, confirmed=True,
                            summary=f"Cross-identity ({source.id}): the captured read by "
                                    f"{source.id!r} returned the protected object that the entitled "
                                    f"principal {accessor.id!r} sees, while anonymous was denied.",
                            evidence=f"{self._ownership_kind(exchange)} ownership of {self._object_ref(exchange.url)!r} does "
                                     f"not entitle the source principal {source.id!r}; the entitled "
                                     f"principal's replay matched its captured response. {self._ownership_provenance(exchange)}. {ev.detail}"
                        ).with_artifacts(baseline=attempt, attack=source_read, controls=[anon])
                    authorized += 1
                    continue
                if undeclared is None:
                    undeclared = (ident, ev.detail)
                continue
            if ev.verdict == identity_compare.Verdict.REJECTED:
                rejects += 1

        if considered == 0:
            if unsent:
                return self._blocked(
                    fc, f"cross-identity access control NOT tested: {unsent} identity request(s) were "
                        f"not sent ({unsent_why}); a refused request is not evidence that the control held",
                    evidence=f"No response was obtained for {exchange.url}; this is not a negative result.")
            if errored:
                return self._skip(fc, f"no configured identity probe completed: every probe errored "
                                      f"({errored}; last: {last_error}) -- cannot test access control")
            return self._skip(fc, "no configured identity probe could be sent")
        if undeclared is not None:
            # A crossing-shaped match with no ownership declared outranks the other
            # non-confirmations: it is the lead the analyst must resolve.
            return self._undeclared_lead(fc, exchange, *undeclared)
        if authorized:
            return ValidationResult(
                validator=self.name, status="not_confirmed", finding_class=fc,
                confidence=0.3, confirmed=False,
                summary=f"OBSERVATION (not confirmed): {authorized} authorized principal(s) reached "
                        f"{exchange.url} with explicit ownership/share/public permission; "
                        f"all {considered} configured principals were still evaluated.",
                evidence=f"OwnershipLedger authorized {authorized} of {considered} tested "
                         f"principal(s) for {self._object_ref(exchange.url)!r}.",
                control_outcome="inconclusive")
        if errored or unsent:
            # An errored or unsent probe is an UNKNOWN, not a denial. Without this guard it
            # silently drops out of `considered`, so a single remaining denial
            # satisfies rejects==considered and the leg reports "access correctly
            # restricted" at 0.8 with control_outcome="control_held" -- which the
            # downgrade block in orchestrator_confirm treats as a refutation,
            # turning a network/scope failure into a confident clean bill of
            # health against a real IDOR/BOLA lead. Report inconclusive, never held.
            return ValidationResult(
                validator=self.name, status="not_confirmed", finding_class=fc, confidence=0.0, confirmed=False,
                summary=f"Cross-identity access-control test INCONCLUSIVE: {rejects} identity/identities "
                        f"were denied, but {errored + unsent} probe(s) "
                        f"({self._incomplete_detail(errored, unsent, unsent_why)}) could not be "
                        f"evaluated -- 'every other identity was denied' cannot be asserted.",
                evidence=f"{considered} identity/identities evaluated against {exchange.url} "
                         f"({rejects} rejected); {self._incomplete_detail(errored, unsent, unsent_why)}"
                         f"{self._last_error_note(errored, last_error)}. An errored or unsent "
                         f"probe is an unknown, not a denial, so this is NOT reported as a "
                         f"restricted/held control.",
                control_outcome="inconclusive")
        if rejects == considered:
            return ValidationResult(
                validator=self.name, status="not_confirmed", finding_class=fc, confidence=0.8, confirmed=False,
                summary="Access correctly restricted: every configured other identity, and the anonymous "
                        "baseline, were denied this resource -- the single-exchange access-control hypothesis "
                        "is contradicted by an active cross-identity test.",
                evidence=f"{considered} identity/identities tested against {exchange.url}; all rejected",
                control_outcome="control_held")
        return self._skip(fc, "cross-identity comparison inconclusive (no confirmation, and not every "
                              "identity was cleanly rejected)")
