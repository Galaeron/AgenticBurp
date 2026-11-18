"""
Write-integrity leg: business-logic and cross-identity WRITE flaws, each
confirmed by reading the object back, every write restored afterwards.

The existing legs either read (cross_identity's read leg), modify an existing
object (cross_identity's write leg, verb_tamper), or write without undoing it
(sequence's mass-assignment write, client_trust's price tamper). None of them
creates an object, reads it back and deletes it again. This leg covers the five
write classes that need that:

  cross_identity_write    A creates an object that references B's object (an
                          owned foreign key in the body, or B's container id in
                          the path).
  forged_authorship       A creates an object whose author/owner/user field names
                          someone other than A.
  business_rule_tamper    a negative quantity, rating, price or total is stored,
                          on a create or on an update of A's own object.
  mass_assignment_create  a role/admin field sent on a create is stored.
  create_validation       a create with every string field empty, or a duplicate
                          of a unique create (same email/username), is accepted.

Every case follows one order:

  1. refuse before writing when anything below cannot be paid for: the run's
     active/write gate (validators.active_enabled + allow_mutating_replay), the
     per-case mutating ceiling (validators.mutating_ceiling_by_check.write_integrity),
     a restore path (a known DELETE route for the created object, or the captured
     update route itself), and a preflight of every payload through the gate;
  2. positive control: the legitimate write (the captured create with unique
     values, or an in-range update) succeeds and reads back;
  3. for a create, the control object is deleted and the deletion verified BEFORE
     any attack is sent, so a restore path that does not work costs one object,
     never the attack's;
  4. the attack write, then a read-back of what the server stored;
  5. restore in ``finally`` (shielded from cancellation, inside
     run_handoff.restore_scope): DELETE each created object and verify it is gone,
     or write the snapshot value back and verify the object matches it; the
     outcome is recorded on the run's change log (run_handoff.mark_restore) and in
     the evidence (restore=..., restore_succeeded=...). A failed restore is a loud
     ``error`` result naming what to clean up by hand.

Confirmation always rests on the read-back, never on a status code alone. The
negative controls are the server's own answers: a refused or session-bound
reference (ownership enforced), a refused or normalized value (bounds enforced),
a role field the stored object does not carry (field ignored).

Nothing here is application-specific: fields are recognised by generic names
(``*Id`` references, author/owner/user, quantity/rating/price/total, email/
username) and other principals' objects come from the run's ownership facts
(operator declarations, or self-observed ownership when enabled).
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
import secrets
from dataclasses import dataclass, field as dc_field
from urllib.parse import quote, urljoin, urlsplit, urlunsplit

from harness import naming
from harness.models import Finding, HttpExchange
from .base import ValidationResult, Validator
from .cross_identity_validator import (
    _PRIVILEGED_ROLE, _auth_signature, _distinct_other_principals, _masked_paths,
    _object_lock, _principal_for, _source_identity, _stable, _unwrap_envelope)
from .sequence_validator import _AUTHORITY_RE, _PRIV_FIELDS, _is_priv, _present_privileged

log = logging.getLogger(__name__)

CROSS_IDENTITY_WRITE = "cross_identity_write"
FORGED_AUTHORSHIP = "forged_authorship"
BUSINESS_RULE_TAMPER = "business_rule_tamper"
MASS_ASSIGNMENT_CREATE = "mass_assignment_create"
CREATE_VALIDATION = "create_validation"
# R11-5: an update of one object sent by a principal who should not be able to
# make it (anonymous, or the capture's own non-owner session), read back as the
# object's owner or an admin, and written back.
UNAUTHORIZED_UPDATE = "unauthorized_update"
KINDS = (CROSS_IDENTITY_WRITE, FORGED_AUTHORSHIP, BUSINESS_RULE_TAMPER,
         MASS_ASSIGNMENT_CREATE, CREATE_VALIDATION, UNAUTHORIZED_UPDATE)

_KIND_ALIASES = {
    CROSS_IDENTITY_WRITE: {"cross_identity_write", "cross_identity_create", "cross_user_write",
                           "bola_write", "idor_write", "foreign_reference_write"},
    FORGED_AUTHORSHIP: {"forged_authorship", "authorship_forgery", "author_spoofing",
                        "forged_owner", "owner_spoofing", "impersonated_write"},
    BUSINESS_RULE_TAMPER: {"business_rule_tamper", "business_rule_bypass", "numeric_tamper",
                           "negative_quantity", "quantity_tampering", "rating_tampering",
                           "out_of_bounds_value", "negative_total"},
    MASS_ASSIGNMENT_CREATE: {"mass_assignment_create", "mass_assignment_at_create",
                             "registration_mass_assignment"},
    CREATE_VALIDATION: {"create_validation", "weak_create_validation", "duplicate_registration",
                        "empty_required_fields", "missing_required_field_validation"},
    UNAUTHORIZED_UPDATE: {"unauthorized_update", "unauthorized_write", "unauthenticated_write",
                          "missing_write_authorization", "write_authorization_bypass"},
}
FINDING_CLASSES = {a for aliases in _KIND_ALIASES.values() for a in aliases} | {
    "write_integrity", "business_logic", "business logic", "mass_assignment", "mass assignment"}

# An identifier segment in a path: a number, a long hex string or a uuid.
_ID_SEGMENT = re.compile(r"^(\d+|[0-9a-fA-F]{8,}|[0-9a-fA-F]{8}-[0-9a-fA-F-]{4,})$")
_ID_SUFFIX = re.compile(r"(?:_id|-id|Id|ID|id)$")
_ID_KEYS = frozenset({"id", "_id", "uuid", "guid"})
# A reference to a person (forged_authorship), never an owned-object reference.
_PERSON_STEMS = frozenset({
    "user", "owner", "author", "customer", "account", "member", "creator", "poster",
    "sender", "reviewer", "createdby", "postedby", "submittedby", "writtenby", "authoredby"})
_QUANTITY = re.compile(r"^(qty|quantity|quantities|count|units|pieces|itemcount|numitems)$")
_RATING = re.compile(r"^(rating|ratings|stars?|score|grade)$")
_MONEY = re.compile(r"^(price|unitprice|cost|total|subtotal|amount|ordertotal|grandtotal)$")
_TEXT_KEY = re.compile(r"^(comment|message|description|title|text|body|content|note|notes|"
                       r"subject|review|name)$")
_UNIQUE_KEY = re.compile(r"^(e?mail|emailaddress|username|login|handle|nick|nickname)$")
_EMAILISH = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_TAMPER_VALUE = -1   # out of bounds for any quantity, rating, price or total


def _flat(key) -> str:
    return re.sub(r"[^a-z0-9]", "", str(key).lower())


def _kind_of(finding: Finding, exchange: HttpExchange) -> str | None:
    """The sub-check a finding asks for, or None when this leg has nothing to test."""
    return kind_for(finding.vulnerability_class, exchange)


def kind_for(vulnerability_class: str, exchange: HttpExchange) -> str | None:
    """The sub-check a vulnerability class names for this capture, or None."""
    from harness.categories import canonicalize
    raw = re.sub(r"[\s-]+", "_", (vulnerability_class or "").strip().lower())
    for kind, aliases in _KIND_ALIASES.items():
        if raw in aliases:
            return kind
    if "mass_assign" in raw and _is_create(exchange):
        return MASS_ASSIGNMENT_CREATE   # a create is this leg's; updates stay sequence's
    if canonicalize(vulnerability_class or "") == "business_logic" or raw == "write_integrity":
        return BUSINESS_RULE_TAMPER
    return None


def chain_routes(vulnerability_class: str, exchange: HttpExchange) -> bool:
    """The chain's routing rule: does a finding of this class on this capture go to
    this leg rather than its keyword-matched neighbour? An explicit write-integrity
    class always does; a mass-assignment finding on a create does (sequence could
    not undo it); a business-logic finding does only when the capture carries a
    quantity/rating/price/total this leg tampers with and no integer value field
    client_trust owns."""
    kind = kind_for(vulnerability_class, exchange)
    if kind is None or (exchange.method or "").upper() not in ("POST", "PUT", "PATCH"):
        return False
    body = _json_object(exchange.request_body)
    if body is None:
        return False
    raw = re.sub(r"[\s-]+", "_", (vulnerability_class or "").strip().lower())
    if any(raw in aliases for aliases in _KIND_ALIASES.values()) or kind == MASS_ASSIGNMENT_CREATE:
        return True
    from .client_trust_validator import _value_field
    return _value_field(body) is None and bool(WriteIntegrityValidator._tamper_field(body)[0])


def _ends_with_id(url: str) -> bool:
    segments = [s for s in urlsplit(url or "").path.split("/") if s]
    return bool(segments) and bool(_ID_SEGMENT.match(segments[-1]))


def _is_create(exchange: HttpExchange) -> bool:
    return (exchange.method or "").upper() == "POST" and not _ends_with_id(exchange.url)


def _json_object(text):
    try:
        obj = json.loads(text) if isinstance(text, str) else None
    except (TypeError, ValueError):
        return None
    return obj if isinstance(obj, dict) else None


def _ref_stem(key) -> str:
    """The object type a reference field names ("BasketId" -> "basket"), else ""."""
    key = str(key)
    if _flat(key) in _ID_KEYS or not _ID_SUFFIX.search(key):
        return ""
    base = _ID_SUFFIX.sub("", key).rstrip("_-")
    return naming.object_key(base) if base else ""


def _number(value):
    return value if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def _same_value(a, b) -> bool:
    if _number(a) is not None and _number(b) is not None:
        return float(a) == float(b)
    return a is not None and b is not None and str(a) == str(b)


def _field_of(obj, key):
    """`obj[key]`, matched case- and separator-insensitively; (found, value)."""
    if not isinstance(obj, dict):
        return False, None
    if key in obj:
        return True, obj[key]
    want = _flat(key)
    for k, v in obj.items():
        if _flat(k) == want:
            return True, v
    return False, None


def _uniquify(body: dict, tag: str) -> tuple[dict, str]:
    """A copy of a create body that cannot collide with an existing object (unique
    email/username values get the tag) and carries the tag in a free-text field
    so the created object can be found again. Returns (body, marker)."""
    out, marker = dict(body), ""
    for k, v in body.items():
        if not isinstance(v, str) or not v:
            continue
        flat = _flat(k)
        if _UNIQUE_KEY.match(flat):
            if "@" in v:
                local, domain = v.rsplit("@", 1)
                out[k] = f"wi{tag}.{local[:24]}@{domain}"
            else:
                out[k] = f"{v[:24]}_wi{tag}"
            marker = marker or out[k]
        elif _TEXT_KEY.match(flat):
            out[k] = f"{v[:80]} wi{tag}"
            marker = marker or f"wi{tag}"
    return out, marker


def _unique_keys(body: dict) -> list[str]:
    return [k for k, v in body.items() if isinstance(v, str) and v and _UNIQUE_KEY.match(_flat(k))]


def _created_id(outcome) -> str:
    """The id of the object a create answered with: from the (enveloped) JSON
    body, else from the Location header. "" when neither names one."""
    try:
        doc = json.loads(outcome.body or "")
    except (TypeError, ValueError):
        doc = None
    obj = _unwrap_envelope(doc) if isinstance(doc, dict) else None
    if isinstance(doc, dict) and isinstance(doc.get("data"), dict):
        obj = doc["data"]
    if isinstance(obj, dict):
        for k, v in obj.items():
            if _flat(k) in _ID_KEYS and isinstance(v, (int, str)) and not isinstance(v, bool) and str(v):
                return str(v)
    headers = {str(k).lower(): v for k, v in (getattr(outcome, "headers", None) or {}).items()}
    location = headers.get("location") or ""
    last = [s for s in urlsplit(location).path.split("/") if s]
    return last[-1] if last and _ID_SEGMENT.match(last[-1]) else ""


def route_set(routes) -> set[tuple[str, str]]:
    """("METHOD", "/template") pairs from route strings such as
    "DELETE /api/things/{id}" (the route inventory and restore_routes form)."""
    known = set()
    for route in routes or ():
        parts = str(route).split(None, 1)
        if len(parts) == 2:
            known.add((parts[0].upper(), parts[1].strip().rstrip("/").lower()))
    return known


def _item_url(collection_url: str, oid: str) -> str:
    parts = urlsplit(collection_url)
    return urlunsplit((parts.scheme, parts.netloc,
                       parts.path.rstrip("/") + "/" + quote(str(oid), safe=""), "", ""))


def _object_of(outcome):
    if outcome is None or not outcome.ok or not 200 <= (outcome.status or 0) < 300:
        return None
    try:
        doc = json.loads(outcome.body or "")
    except (TypeError, ValueError):
        return None
    if isinstance(doc, dict) and isinstance(doc.get("data"), dict):
        doc = doc["data"]
    obj = _unwrap_envelope(doc) if isinstance(doc, dict) else None
    return obj if isinstance(obj, dict) and obj else None


def _absent(outcome) -> bool:
    """A verification read shows the object is gone."""
    if outcome is None or not outcome.ok:
        return False
    if outcome.status in (404, 410):
        return True
    if 200 <= (outcome.status or 0) < 300:
        text = (outcome.body or "").strip()
        if text in ("", "null", "{}", "[]"):
            return True
        doc = _json_object(text)
        return isinstance(doc, dict) and "data" in doc and doc["data"] in (None, {}, [])
    return False


def _ok2xx(outcome) -> bool:
    return outcome is not None and outcome.ok and 200 <= (outcome.status or 0) < 300


def _refused(outcome) -> bool:
    return outcome is not None and outcome.ok and 400 <= (outcome.status or 0) < 500


@dataclass
class _Made:
    """One create this case sent, and what became of it."""
    label: str
    url: str
    body: dict
    marker: str = ""
    sent: object = None
    item: str = ""
    read: object = None
    obj: dict | None = None
    undo: object = None
    check: object = None
    restored: bool | None = None   # None: nothing was created, nothing to undo
    done: bool = False
    # The exact body text when it is not json.dumps(body): a duplicate-key body.
    raw: str | None = None
    left: bool = False             # created and deliberately left in place (opt-in)
    # Login read-back of a self-service sign-up (opt-in path only): the login body
    # with the credentials this create submits, the before/after/wrong-password
    # login outcomes, and what they showed: "stored" (fails before, succeeds after,
    # a wrong password fails), "existing" (already logs in before the create),
    # "not_stored" (fails before and after), "unsure" (with `login_why`).
    login: dict | None = None
    logins: dict = dc_field(default_factory=dict)
    login_result: str = ""
    login_why: str = ""
    account: str = ""              # how a stored account with no object URL is named

    @property
    def status(self):
        return getattr(self.sent, "status", None)


@dataclass
class _Case:
    finding: Finding
    exchange: HttpExchange
    kind: str
    case_ref: str
    actor: dict | None
    idents: list
    headers: dict
    body: dict
    others: list = dc_field(default_factory=list)
    # A self-service create with no DELETE route, run only under the owner's opt-in
    # (validators.write_integrity.allow_unrestorable_self_service_creates).
    unrestorable: bool = False


@dataclass
class _Plan:
    control: _Made
    attacks: list
    field: str = ""
    detail: str = ""
    forged: object = None
    own: object = None
    other: dict | None = None
    # cross_identity_write: parameter-pollution forms of the attack, each sent only
    # when no earlier attack landed and the case's mutating headroom still pays for
    # it and the deletes it may need. `sent` lists those sent, `unsent` why not.
    variants: list = dc_field(default_factory=list)
    sent: list = dc_field(default_factory=list)
    unsent: list = dc_field(default_factory=list)
    # create_validation on the opt-in path: the observed login a refused or
    # unreadable sign-up is read back through, or why none was used.
    login_url: str = ""
    login_source: str = ""
    login_note: str = ""
    login_keys: tuple = ()         # (identifier key, password key) of the login body


# A login among the routes a run observed (the route inventory or a captured
# exchange); a path is never guessed. Registration and logout paths are not logins.
_LOGIN_PATH = re.compile(r"(?:^|/)(?:log[-_]?in|sign[-_]?in|log[-_]?on|authenticate|sessions?)(?:/|$|\.)",
                         re.I)
_NOT_LOGIN_PATH = re.compile(r"regist|sign[-_]?up|log[-_]?out|sign[-_]?out|reset|forgot|change", re.I)
_LOGIN_SENDS = 3   # before the create, after it, and the wrong-password control


def _login_session(outcome) -> str:
    """What a 2xx login issued -- "a token in the JSON field 'token'", "a session
    cookie (sid)" -- or "" when it issued neither. Never the value."""
    if not _ok2xx(outcome):
        return ""
    from types import SimpleNamespace
    from .auth_sequence_validator import _SESSION_COOKIE_RE, _login_token
    headers = {str(k).lower(): v for k, v in (getattr(outcome, "headers", None) or {}).items()}
    minted = _login_token(SimpleNamespace(text=outcome.body or "", headers=headers))
    if minted is not None:
        return "a token in " + minted[0].removeprefix("the ")
    names = re.findall(r"(?:^|,\s*|\n)([^=;,\s]+)=", str(headers.get("set-cookie") or ""))
    session = [n for n in names if _SESSION_COOKIE_RE.search(n)]
    return f"a session cookie ({', '.join(session)})" if session else ""


def _login_refused(outcome) -> bool:
    """An answered login that issued no session or token (a 5xx or no answer is
    not a refusal: it says nothing about the credentials)."""
    return (outcome is not None and outcome.ok and outcome.status is not None
            and outcome.status < 500 and not _login_session(outcome))


_VARIANT_WORDS = {
    "dup-own-first": "a duplicate key (the writer's value first, the foreign value last)",
    "dup-foreign-first": "a duplicate key (the foreign value first, the writer's value last)",
    "array": "an array holding both values",
}
_PASSWORD_KEY = re.compile(r"^(password|passwd|pwd|passphrase|pass|newpassword)$")


def _polluted(body: dict, key: str, first, last) -> str:
    """`body` as JSON text carrying `key` twice: `first` in the key's own place and
    `last` appended as the final member. json.dumps cannot write a duplicate key,
    so the second member is spliced in as text; the result is valid JSON whose
    meaning depends on which duplicate the server's parser (and its checks) keep."""
    head = json.dumps({**body, key: first})
    tail = f"{json.dumps(key)}: {json.dumps(last)}"
    return head[:-1] + (", " if len(head) > 2 else "") + tail + "}"


def _run_identities(run) -> list[dict]:
    return [{"name": s.name or s.principal_id, "role": s.role, "headers": dict(s.headers),
             "session_ref": s.session_id, "principal_id": s.principal_id, "principal": s.principal}
            for s in run.sessions.identities() if s.principal_id != "anonymous"]


def _pid(ident: dict | None) -> str:
    return _principal_for(ident).id if ident else "anonymous"


class WriteIntegrityValidator(Validator):
    name = "write_integrity"
    finding_classes = FINDING_CLASSES
    active = True
    mechanism_version = "1"

    def __init__(self, *, allowed_hosts: list[str] | None = None, run_context=None,
                 restore_routes=(), route_inventory=None, allow_writes: bool = False):
        self.allowed_hosts = list(allowed_hosts or [])
        self.run_context = run_context
        # The validators.allow_mutating_replay policy frozen at construction (as
        # cross_identity's): off, this leg is never dispatched and never writes.
        self.allow_writes = bool(allow_writes)
        # Operator-declared undo routes ("DELETE /api/things/{id}"), plus a callable
        # the chain supplies that returns the routes this engagement observed.
        self.restore_routes = tuple(restore_routes or ())
        self.route_inventory = route_inventory
        self.ownership = None

    # -- dispatch --------------------------------------------------------------

    def applies(self, finding: Finding, exchange: HttpExchange) -> bool:
        return (self.allow_writes and (exchange.method or "").upper() in ("POST", "PUT", "PATCH")
                and _kind_of(finding, exchange) is not None
                and _json_object(exchange.request_body) is not None)

    def _result(self, status: str, fc: str, summary: str, **kw) -> ValidationResult:
        return ValidationResult(self.name, status, fc, summary=summary, **kw)

    def _skip(self, fc: str, why: str) -> ValidationResult:
        return self._result("skipped", fc, why)

    async def validate(self, finding: Finding, exchange: HttpExchange) -> ValidationResult:
        fc = finding.vulnerability_class
        kind = _kind_of(finding, exchange)
        run = self.run_context
        if kind is None:
            return self._skip(fc, "write_integrity: no write-integrity class in this finding")
        if kind == UNAUTHORIZED_UPDATE:
            return await self.unauthorized_update(finding, exchange)
        if run is None:
            return self._skip(fc, "write_integrity needs a run transport and registered sessions; "
                                  "nothing was written")
        if (not self.allow_writes or not run.gate.config.active_enabled
                or not run.gate.config.allow_mutating_replay):
            return self._skip(fc, "write_integrity runs only with validators.active_enabled and "
                                  "validators.allow_mutating_replay on; nothing was written")
        if not run.scope.in_scope(exchange.url):
            return self._skip(fc, "write_integrity: target is out of scope; nothing was written")
        body = _json_object(exchange.request_body)
        if body is None:
            return self._skip(fc, "write_integrity needs a JSON object request body; nothing was written")
        from harness.security import is_identity_credential_header
        idents = _run_identities(run)
        signature = _auth_signature(exchange.request_headers)
        actor = _source_identity(idents, signature)
        if signature and actor is None:
            return self._skip(fc, "write_integrity: the capture's credentials belong to no registered "
                                  "session, so its writes could not be restored as their owner")
        headers = {k: v for k, v in (exchange.request_headers or {}).items()
                   if not is_identity_credential_header(k)
                   and k.lower() not in {"host", "content-length", "if-match", "if-none-match"}}
        headers["Content-Type"] = "application/json"
        case_ref = finding.finding_id or finding.case_id or "write-integrity-" + secrets.token_hex(8)
        others = [i for i in _distinct_other_principals(idents, _auth_signature(actor["headers"]) if actor else ())
                  if not _PRIVILEGED_ROLE.search(i.get("role") or "") and not _principal_for(i).provisional
                  and (actor is None or _pid(i) != _pid(actor))]
        case = _Case(finding, exchange, kind, case_ref, actor, idents, headers, body, others)
        method = (exchange.method or "").upper()
        if kind == BUSINESS_RULE_TAMPER and method in ("PUT", "PATCH") and _ends_with_id(exchange.url):
            async with _object_lock(exchange.url):
                return await self._update_tamper(case)
        if kind == FORGED_AUTHORSHIP and method in ("PUT", "PATCH"):
            if not _ends_with_id(exchange.url):
                return self._skip(fc, self._no_update_object(case))
            async with _object_lock(exchange.url):
                return await self._update_authorship(case)
        if not _is_create(exchange):
            return self._skip(fc, f"write_integrity {kind} needs a POST create to a collection "
                                  f"(got {method} {urlsplit(exchange.url).path}); nothing was written")
        planner = {CROSS_IDENTITY_WRITE: self._plan_cross_identity,
                   FORGED_AUTHORSHIP: self._plan_authorship,
                   BUSINESS_RULE_TAMPER: self._plan_tamper,
                   MASS_ASSIGNMENT_CREATE: self._plan_mass_assignment,
                   CREATE_VALIDATION: self._plan_validation}[kind]
        # The owner's opt-in (off by default): a self-service registration with no
        # DELETE route may run and leave its throwaway accounts in place, named.
        case.unrestorable = (self._self_service(case) and self._allows_unrestorable()
                             and not self._restore_route(exchange.url))
        plan = planner(case)
        if isinstance(plan, str):
            return self._skip(fc, f"write_integrity {kind}: {plan}; nothing was written")
        refusal = self._refusal(case, plan)
        if refusal:
            return self._skip(fc, f"write_integrity {kind}: {refusal}; nothing was written")
        if case.unrestorable and kind == CREATE_VALIDATION:
            self._plan_logins(case, plan)
        return await self._run_creates(case, plan)

    # -- what may be written -----------------------------------------------------

    def _route_entries(self) -> list:
        routes = list(self.restore_routes)
        if callable(self.route_inventory):
            try:
                routes += list(self.route_inventory() or ())
            except Exception:
                log.debug("write_integrity: route inventory failed", exc_info=True)
        return routes

    def _known_routes(self) -> set[tuple[str, str]]:
        return route_set(self._route_entries())

    def _restore_route(self, url: str) -> str:
        """The DELETE route that undoes a create at `url`, if one is known; ""."""
        from harness.engagement import normalize_path
        template = normalize_path(_item_url(url, "1"))
        return template if ("DELETE", template.rstrip("/").lower()) in self._known_routes() else ""

    def _refusal(self, case: _Case, plan: _Plan) -> str:
        """Why this plan must not start, or ""."""
        run, creates = self.run_context, 1 + len(plan.attacks)
        urls = {plan.control.url} | {m.url for m in plan.attacks}
        for url in urls if not case.unrestorable else ():
            if not self._restore_route(url):
                from harness.engagement import normalize_path
                hint = ("; a self-service registration with no DELETE route is left in place only "
                        "under the owner's opt-in validators.write_integrity."
                        "allow_unrestorable_self_service_creates (off by default)"
                        if self._self_service(case) else "")
                return (f"no restore path known for objects created at {urlsplit(url).path} "
                        f"(needs DELETE {normalize_path(_item_url(url, '1'))} in the route inventory or "
                        f"validators.write_integrity.restore_routes){hint}")
        need = creates if case.unrestorable else 2 * creates
        headroom, _, ceiling = run.gate.mutating_headroom(case.case_ref, self.name)
        if headroom < need:
            return (f"{creates} create(s) and their verified deletes need {need} mutating sends "
                    f"for this case (validators.mutating_ceiling_by_check.write_integrity >= {need}; "
                    f"ceiling is {ceiling})")
        if run.budget.remaining is not None and run.budget.remaining < 4 * creates + 2:
            return f"the run's request budget cannot pay for {creates} create(s), read-backs and deletes"
        for made in [plan.control] + plan.attacks:
            decision = run.gate.authorize(validator_name=self.name, method="POST", url=made.url,
                                          body=made.raw if made.raw is not None else json.dumps(made.body))
            if not decision.allowed:
                return "write preflight refused: " + decision.reason
        # An optional variant the gate refuses is dropped, never the whole plan.
        for made in list(plan.variants):
            decision = run.gate.authorize(validator_name=self.name, method="POST", url=made.url,
                                          body=made.raw if made.raw is not None else json.dumps(made.body))
            if not decision.allowed:
                plan.variants.remove(made)
                plan.unsent.append(f"{made.label} (preflight refused: {decision.reason})")
        if case.unrestorable:
            return ""
        decision = run.gate.authorize(validator_name=self.name, method="DELETE",
                                      url=_item_url(plan.control.url, "1"))
        if not decision.allowed:
            return "restore preflight refused: " + decision.reason
        return ""

    def _self_service(self, case: _Case) -> bool:
        """An anonymous registration-shaped create: a unique email/username and a
        password, sent with no session (a throwaway account anyone may make)."""
        return (case.actor is None and case.kind in (MASS_ASSIGNMENT_CREATE, CREATE_VALIDATION)
                and bool(_unique_keys(case.body))
                and any(_PASSWORD_KEY.match(_flat(k)) for k in case.body))

    def _allows_unrestorable(self) -> bool:
        """The owner's opt-in to leave self-service throwaway accounts in place when no
        DELETE route exists. Off unless the run's config sets it to true."""
        cfg = getattr(self.run_context, "config", None) or {}
        wi = ((cfg.get("validators") or {}).get("write_integrity") or {}) if isinstance(cfg, dict) else {}
        return wi.get("allow_unrestorable_self_service_creates", False) is True

    # -- login read-back of a self-service sign-up (opt-in path only) ----------------
    # A sign-up the server answers 4xx (or 2xx with nothing readable) may still have
    # stored the account. Logging in with the credentials that create submitted reads
    # it back: it must fail before the create, succeed after it with a session or a
    # token, and a wrong password must still fail.

    @staticmethod
    def _login_keys(body: dict) -> tuple[str, str]:
        """(identifier key, password key) of a login or sign-up body ("" when absent)."""
        ident = next((k for k in body if _UNIQUE_KEY.match(_flat(k))), "")
        password = next((k for k in body if _PASSWORD_KEY.match(_flat(k))), "")
        return ident, password

    def _login_target(self, case: _Case) -> tuple[str, dict | None, str]:
        """(url, captured login body or None, where it was observed) of a login the
        run observed on the sign-up's origin: a captured login exchange first, then a
        POST route in the route inventory. ("", None, "") when it observed none."""
        parts = urlsplit(case.exchange.url)
        origin = f"{parts.scheme}://{parts.netloc}"

        def is_login(path: str) -> bool:
            return bool(_LOGIN_PATH.search(path)) and not _NOT_LOGIN_PATH.search(path)

        context = getattr(self.run_context, "experiment_context", None)
        captured = (context.get("captured") if isinstance(context, dict) else None) or ()
        for item in list(captured)[:500]:
            def get(key, _item=item):
                return _item.get(key) if isinstance(_item, dict) else getattr(_item, key, None)
            p = urlsplit(str(get("url") or ""))
            if (str(get("method") or "").upper() != "POST" or f"{p.scheme}://{p.netloc}" != origin
                    or not is_login(p.path)):
                continue
            body = _json_object(get("request_body"))
            if body and all(self._login_keys(body)):
                return (urlunsplit((p.scheme, p.netloc, p.path, p.query, "")), body,
                        f"a captured login (POST {p.path})")
        for route in self._route_entries():
            bits = str(route).split(None, 1)
            if len(bits) != 2 or bits[0].upper() != "POST":
                continue
            path = bits[1].strip()
            if path.lower().startswith(("http://", "https://")):
                p = urlsplit(path)
                if f"{p.scheme}://{p.netloc}" != origin:
                    continue
                path = p.path
            if path.startswith("/") and "{" not in path and is_login(path):
                return origin + path, None, f"the route inventory (POST {path})"
        return "", None, ""

    def _plan_logins(self, case: _Case, plan: _Plan) -> None:
        """Arm the login read-back for each attack whose credential pair no other create
        of this case submits (a login cannot tell two creates with one pair apart),
        while the case's mutating headroom pays for every create plus three logins each."""
        url, template, source = self._login_target(case)
        id_key, pw_key = self._login_keys(case.body)
        if not url or not id_key or not pw_key:
            plan.login_note = ("a refused or unreadable sign-up was not read back by logging in: the "
                               "run observed no login route (none in the route inventory or its "
                               "captured exchanges)" if not url else
                               "a refused or unreadable sign-up was not read back by logging in: the "
                               "sign-up has no identifier and password pair to log in with")
            return
        plan.login_url, plan.login_source = url, source
        plan.login_keys = self._login_keys(template) if template else (id_key, pw_key)
        t_id, t_pw = plan.login_keys
        everyone = [plan.control] + plan.attacks

        def pair(m):
            return m.body.get(id_key), m.body.get(pw_key)

        run, armed = self.run_context, 0
        headroom, _, ceiling = run.gate.mutating_headroom(case.case_ref, self.name)
        for m in plan.attacks:
            if sum(pair(x) == pair(m) for x in everyone) > 1:
                m.login_why = ("it submits the same credentials as another create of this case, so a "
                               "login cannot tell which of them stored the account")
                continue
            if not all(isinstance(v, str) for v in pair(m)):
                continue
            need = len(everyone) + _LOGIN_SENDS * (armed + 1)
            if headroom < need or (run.budget.remaining is not None
                                   and run.budget.remaining < 4 * len(everyone) + 2 + _LOGIN_SENDS * (armed + 1)):
                m.login_why = (f"its login read-back needs {need} mutating sends for this case "
                               f"(validators.mutating_ceiling_by_check.write_integrity; ceiling is {ceiling})")
                continue
            body = {**(template or {}), t_id: m.body[id_key], t_pw: m.body[pw_key]}
            decision = run.gate.authorize(validator_name=self.name, method="POST", url=url,
                                          body=json.dumps(body))
            if not decision.allowed:
                m.login_why = "its login read-back was refused by the preflight: " + decision.reason
                continue
            m.login = body
            armed += 1

    async def _login(self, case: _Case, plan: _Plan, body: dict):
        """One login through a fresh ephemeral session: its own cookie jar, never one
        of the run's identities, so a session it is issued reaches no other send."""
        sid = "wi-login-" + secrets.token_hex(6)
        p = urlsplit(plan.login_url)
        self.run_context.sessions.register(sid, sid, {}, allowed_origins=[f"{p.scheme}://{p.netloc}"],
                                           role="negative-control", ephemeral=True)
        return await self._send(case, "POST", plan.login_url, body, ident={"session_ref": sid})

    async def _login_before(self, case: _Case, plan: _Plan, m: _Made) -> None:
        if m.login is None:
            return
        m.logins["before"] = before = await self._login(case, plan, m.login)
        issued = _login_session(before)
        if issued:
            m.login_result = "existing"
            m.login_why = (f"a login with the credentials it submits already succeeded before the "
                           f"create (HTTP {before.status}, {issued}), so an account with them exists")
        elif not _login_refused(before):
            m.login_result = "unsure"
            m.login_why = f"the login before the create got no usable answer (HTTP {before.status})"

    async def _login_after(self, case: _Case, plan: _Plan, m: _Made) -> None:
        if (m.login is None or m.login_result or m.sent is None or not m.sent.ok
                or m.sent.status is None or (_ok2xx(m.sent) and m.obj is not None)):
            return   # not armed, settled before the create, unanswered, or read back directly
        before = m.logins["before"]
        m.logins["after"] = after = await self._login(case, plan, m.login)
        issued = _login_session(after)
        if not issued:
            m.login_result = "not_stored" if _login_refused(after) else "unsure"
            m.login_why = (f"a login with the credentials it submitted failed before (HTTP "
                           f"{before.status}) and after it (HTTP {after.status})"
                           if m.login_result == "not_stored" else
                           f"the login after the create got no usable answer (HTTP {after.status})")
            return
        t_id, t_pw = plan.login_keys
        m.logins["wrong"] = wrong = await self._login(
            case, plan, {**m.login, t_pw: "wi-wrong-" + secrets.token_hex(8)})
        if not _login_refused(wrong):
            m.login_result = "unsure"
            m.login_why = (f"a login with its credentials succeeded after the create, but the "
                           f"wrong-password control did not fail (HTTP {wrong.status}), so that login "
                           f"does not show the credentials were checked")
            return
        m.login_result, m.left = "stored", True
        m.account = (f"the account {t_id}={m.login[t_id]!r} (logs in at POST "
                     f"{urlsplit(plan.login_url).path})")
        m.login_why = (f"a login with the credentials it submitted failed before the create (HTTP "
                       f"{before.status}) and succeeded after it (HTTP {after.status}, {issued}), "
                       f"while a wrong password was refused (HTTP {wrong.status})")

    # -- per-class plans ---------------------------------------------------------

    def _others_refs(self, principal_id: str) -> dict[str, list[str]]:
        """{object type: [ids]} of the objects the run knows `principal_id` owns:
        operator declarations first, then self-observed ownership."""
        refs: dict[str, list[str]] = {}
        ledger = self.ownership
        if ledger is not None and hasattr(ledger, "owned_objects"):
            for collection, oid in ledger.owned_objects(principal_id):
                refs.setdefault(naming.object_key(collection), []).append(oid)
        observed = getattr(self.run_context, "self_ownership", None)
        if observed is not None and hasattr(observed, "owned_objects"):
            for stem, oid in observed.owned_objects(principal_id):
                if oid not in refs.setdefault(stem, []):
                    refs[stem].append(oid)
        return refs

    def _account_ids(self, principal_id: str) -> list[str]:
        ids = list(self._others_refs(principal_id).get("user", []))
        observed = getattr(self.run_context, "self_ownership", None)
        if observed is not None and hasattr(observed, "account_ids"):
            ids += [i for i in observed.account_ids(principal_id) if i not in ids]
        return ids

    def _plan_cross_identity(self, case: _Case):
        if case.actor is None:
            return "needs the capture to be an authenticated, registered session"
        if not case.others:
            return "no distinct non-privileged principal is registered"
        own = self._others_refs(_pid(case.actor))
        url = case.exchange.url
        for other in case.others:
            theirs = self._others_refs(_pid(other))
            for key, value in case.body.items():
                stem = _ref_stem(key)
                if not stem or stem in _PERSON_STEMS or not isinstance(value, (int, str)) or isinstance(value, bool):
                    continue
                candidates = [o for o in theirs.get(stem, ()) if str(o) != str(value)
                              and str(o) not in own.get(stem, ())]
                if not candidates:
                    continue
                forged = int(candidates[0]) if isinstance(value, int) and candidates[0].isdigit() else candidates[0]
                ctl_body, ctl_marker = _uniquify(case.body, "c" + secrets.token_hex(4))
                atk_body, atk_marker = _uniquify(case.body, "a" + secrets.token_hex(4))
                atk_body[key] = forged
                # Parameter pollution: an ownership check and the code that stores the
                # reference may read different members of a duplicate key, or one
                # element of an array, so the same foreign reference is also tried
                # alongside the writer's own one, in both orders.
                variants = []
                for label, first, last in (("dup-own-first", value, forged),
                                           ("dup-foreign-first", forged, value)):
                    v_body, v_marker = _uniquify(case.body, "v" + secrets.token_hex(4))
                    raw = _polluted(v_body, key, first, last)
                    variants.append(_Made(label, url, json.loads(raw), v_marker, raw=raw))
                v_body, v_marker = _uniquify(case.body, "v" + secrets.token_hex(4))
                variants.append(_Made("array", url, {**v_body, key: [value, forged]}, v_marker))
                return _Plan(_Made("control", url, ctl_body, ctl_marker),
                             [_Made("attack", url, atk_body, atk_marker)], field=key,
                             forged=forged, own=value, other=other, variants=variants,
                             detail=f"{key}: {value!r} -> {_pid(other)}'s {stem} {forged!r}")
            parts = urlsplit(url)
            segments = parts.path.split("/")
            for i in range(1, len(segments)):
                if not _ID_SEGMENT.match(segments[i] or "") or not segments[i - 1]:
                    continue
                stem = naming.object_key(segments[i - 1])
                candidates = [o for o in theirs.get(stem, ()) if str(o) != segments[i]
                              and str(o) not in own.get(stem, ())]
                if not candidates:
                    continue
                swapped = urlunsplit((parts.scheme, parts.netloc,
                                      "/".join(segments[:i] + [candidates[0]] + segments[i + 1:]),
                                      parts.query, ""))
                ctl_body, ctl_marker = _uniquify(case.body, "c" + secrets.token_hex(4))
                atk_body, atk_marker = _uniquify(case.body, "a" + secrets.token_hex(4))
                return _Plan(_Made("control", url, ctl_body, ctl_marker),
                             [_Made("attack", swapped, atk_body, atk_marker)],
                             field=stem + "Id", forged=candidates[0], own=segments[i], other=other,
                             detail=f"path {segments[i - 1]}/{segments[i]} -> "
                                    f"{_pid(other)}'s {stem} {candidates[0]}")
        return ("the create carries no reference to an object type another registered principal "
                "is known to own (declare ownership, or enable authz.self_observed_ownership)")

    def _plan_authorship(self, case: _Case):
        if case.actor is None:
            return "needs the capture to be an authenticated, registered session"
        for key, value in case.body.items():
            forged, whose = self._forge_author(case, key, value)
            if forged is None:
                continue
            ctl_body, ctl_marker = _uniquify(case.body, "c" + secrets.token_hex(4))
            atk_body, atk_marker = _uniquify(case.body, "a" + secrets.token_hex(4))
            atk_body[key] = forged
            return _Plan(_Made("control", case.exchange.url, ctl_body, ctl_marker),
                         [_Made("attack", case.exchange.url, atk_body, atk_marker)], field=key,
                         forged=forged, own=value,
                         detail=f"{key}: {value!r} -> {forged!r} ({whose})")
        return ("the create carries no author/owner/user field whose value can be replaced by "
                "another principal's known identifier")

    def _forge_author(self, case: _Case, key, value):
        """(forged value, whose) for an author/owner/user field `key`, or (None, "")
        when `key` is not one or no other identity's value is known."""
        base = _flat(_ID_SUFFIX.sub("", str(key)) if _ref_stem(key) else key)
        if base not in _PERSON_STEMS or value in (None, "") or isinstance(value, bool):
            return None, ""
        forged, whose = None, ""
        if _number(value) is not None or (isinstance(value, str) and value.isdigit()):
            for other in case.others:
                ids = [i for i in self._account_ids(_pid(other)) if str(i) != str(value)]
                if ids:
                    forged = int(ids[0]) if isinstance(value, int) and ids[0].isdigit() else ids[0]
                    whose = _pid(other)
                    break
        elif isinstance(value, str):
            other = case.others[0] if case.others else None
            name = (other or {}).get("name") or ""
            if _EMAILISH.match(value):
                forged = name if _EMAILISH.match(name) else f"wi-{secrets.token_hex(4)}@example.com"
            else:
                forged = name if name and name != value else f"wi-{secrets.token_hex(4)}"
            whose = _pid(other) if forged == name else "a fabricated identity"
        if forged is None or _same_value(forged, value):
            return None, ""
        return forged, whose

    @staticmethod
    def _tamper_field(obj: dict) -> tuple[str, str]:
        """(field, kind) of the business number to tamper with, or ("", "")."""
        for regex, label in ((_QUANTITY, "quantity"), (_RATING, "rating"), (_MONEY, "price/total")):
            for key, value in obj.items():
                if regex.match(_flat(key)) and (_number(value) or 0) > 0:
                    return key, label
        return "", ""

    def _plan_tamper(self, case: _Case):
        key, label = self._tamper_field(case.body)
        if not key:
            return ("no positive quantity, rating, price or total field in the create "
                    "(discount-code reuse and expiry are not attempted: they need an "
                    "operator-declared spent code)")
        ctl_body, ctl_marker = _uniquify(case.body, "c" + secrets.token_hex(4))
        atk_body, atk_marker = _uniquify(case.body, "a" + secrets.token_hex(4))
        atk_body[key] = _TAMPER_VALUE
        return _Plan(_Made("control", case.exchange.url, ctl_body, ctl_marker),
                     [_Made("attack", case.exchange.url, atk_body, atk_marker)], field=key,
                     forged=_TAMPER_VALUE, own=case.body[key],
                     detail=f"{label} {key}: {case.body[key]!r} -> {_TAMPER_VALUE}")

    def _plan_mass_assignment(self, case: _Case):
        fields = {f: v for f, v in _PRIV_FIELDS.items()
                  if _field_of(case.body, f)[0] is False}
        if not fields:
            return "the create already sets every privileged field this check would add"
        ctl_body, ctl_marker = _uniquify(case.body, "c" + secrets.token_hex(4))
        atk_body, atk_marker = _uniquify(case.body, "a" + secrets.token_hex(4))
        atk_body.update(fields)
        return _Plan(_Made("control", case.exchange.url, ctl_body, ctl_marker),
                     [_Made("attack", case.exchange.url, atk_body, atk_marker)],
                     field=",".join(sorted(fields)), forged=fields,
                     detail="added " + ", ".join(sorted(fields)))

    def _plan_validation(self, case: _Case):
        url = case.exchange.url
        unique = _unique_keys(case.body)
        texts = [k for k, v in case.body.items() if isinstance(v, str) and v]
        if not texts:
            return "the create has no non-empty string field to empty and no unique field to duplicate"
        ctl_body, ctl_marker = _uniquify(case.body, "c" + secrets.token_hex(4))
        attacks = []
        if unique:
            tag = "d" + secrets.token_hex(4)
            dup_body, dup_marker = _uniquify(case.body, tag)
            attacks += [_Made("duplicate-first", url, dup_body, dup_marker),
                        _Made("duplicate-second", url, dict(dup_body), dup_marker)]
        empty = {k: ("" if isinstance(v, str) else v) for k, v in case.body.items()}
        attacks.append(_Made("empty", url, empty, ""))
        return _Plan(_Made("control", url, ctl_body, ctl_marker), attacks,
                     field=",".join(texts),
                     detail=(f"duplicate on {', '.join(unique)}; " if unique else "")
                            + f"emptied {', '.join(texts)}")

    # -- the create engine ---------------------------------------------------------

    async def _send(self, case: _Case, verb: str, url: str, body=None, *, ident="actor",
                    cleanup: bool = False, raw: str | None = None):
        from harness.run_context import TypedRequest
        who = case.actor if ident == "actor" else ident
        text = raw if raw is not None else json.dumps(body) if body is not None else None
        return await self.run_context.executor().execute(
            TypedRequest(verb, url, headers=dict(case.headers), body=text),
            capability=self.name, session_ref=(who or {}).get("session_ref"),
            case_ref=case.case_ref, allow_cancelled_cleanup=cleanup)

    def _readers(self, case: _Case) -> list:
        """Who may read back or delete what this case created: the writer first,
        then every other registered identity (a created account is often readable
        and deletable only by an administrator)."""
        out, seen = [case.actor], {(case.actor or {}).get("session_ref")}
        for ident in case.idents:
            if ident.get("session_ref") not in seen:
                seen.add(ident.get("session_ref"))
                out.append(ident)
        return out

    async def _find_by_marker(self, case: _Case, made: _Made, *, cleanup: bool) -> str:
        if not made.marker:
            return ""
        listing = await self._send(case, "GET", made.url, cleanup=cleanup)
        if not _ok2xx(listing):
            return ""
        try:
            doc = json.loads(listing.body or "")
        except (TypeError, ValueError):
            return ""
        items = doc if isinstance(doc, list) else next(
            (v for v in (doc or {}).values() if isinstance(v, list)), []) if isinstance(doc, dict) else []
        for item in items:
            if isinstance(item, dict) and made.marker in json.dumps(item):
                oid = next((str(v) for k, v in item.items() if _flat(k) in _ID_KEYS and str(v)), "")
                if oid:
                    return _item_url(made.url, oid)
        return ""

    async def _create(self, case: _Case, made: _Made) -> None:
        made.sent = await self._send(case, "POST", made.url, made.body, raw=made.raw)
        if not _ok2xx(made.sent):
            return
        oid = _created_id(made.sent)
        made.item = _item_url(made.url, oid) if oid else await self._find_by_marker(case, made, cleanup=False)
        if not made.item:
            return
        for reader in self._readers(case):
            made.read = await self._send(case, "GET", made.item, ident=reader)
            made.obj = _object_of(made.read)
            if made.obj is not None:
                return

    async def _undo(self, case: _Case, made: _Made, first: dict | None = None) -> None:
        """Delete what `made` created and verify it is gone. Leaves `restored` None
        when nothing was created, True when a read shows it gone, False otherwise.
        With `first` (the principal the read-back shows owns the object), that
        principal's sessions delete first, and a principal whose delete was refused
        is not asked again through its other sessions: at most one delete per
        principal, which is what the variant headroom check reserves."""
        if made.done:
            return
        made.done = True
        sent = made.sent
        if sent is None or not getattr(sent, "executed", False) or _refused(sent):
            return   # never sent, or the server refused it: nothing was created
        if case.unrestorable:
            # The owner's opt-in: a self-service create with no DELETE route stays.
            made.left = _ok2xx(sent)
            return
        if not made.item:
            made.item = await self._find_by_marker(case, made, cleanup=True)
        if not made.item:
            # A 2xx create nobody can locate cannot be undone; a 5xx or an
            # exception without a trace in the listing is taken as not created.
            made.restored = False if _ok2xx(sent) else None
            return
        from harness import run_handoff
        made.restored = False
        order = self._readers(case)
        if first is not None:
            lead = _pid(first)
            order = [i for i in order if _pid(i) == lead] + [i for i in order if _pid(i) != lead]
        denied: set[str] = set()
        for who in order:
            if first is not None and _pid(who) in denied:
                continue
            with run_handoff.restore_scope(f"{case.case_ref}:write_integrity_restore"):
                made.undo = await self._send(case, "DELETE", made.item, ident=who, cleanup=True)
                made.check = await self._send(case, "GET", made.item, ident=who, cleanup=True)
            if _absent(made.check):
                made.restored = True
                return
            if not _refused(made.undo) and getattr(made.undo, "executed", False) is False:
                return   # refused by the gate or the ceiling: no other deleter will fare better
            if _refused(made.undo):
                denied.add(_pid(who))

    def _record(self, case: _Case, made: _Made) -> None:
        artifact = getattr(made.sent, "artifact_id", "") if made.sent is not None else ""
        if not artifact or made.restored is None:
            return
        detail = (f"write_integrity {made.label} create deleted and verified gone ({made.item})"
                  if made.restored else
                  f"write_integrity {made.label} create NOT removed: {made.item or made.url} "
                  f"(delete HTTP {getattr(made.undo, 'status', None)})")
        try:
            from harness import run_handoff
            run_handoff.mark_restore(self.run_context, [artifact], ok=bool(made.restored), detail=detail)
        except Exception:
            log.debug("write_integrity: mark_restore failed", exc_info=True)

    async def _run_creates(self, case: _Case, plan: _Plan) -> ValidationResult:
        made: list[_Made] = []
        failure, cancelled = "", False

        async def attempt():
            made.append(plan.control)
            await self._create(case, plan.control)
            if not _ok2xx(plan.control.sent):
                return
            if not case.unrestorable:
                # Prove the restore path on the control before any attack is sent.
                await self._undo(case, plan.control)
                if plan.control.restored is not True:
                    return
            for leg in plan.attacks:
                made.append(leg)
                await self._login_before(case, plan, leg)
                await self._create(case, leg)
                await self._login_after(case, plan, leg)
            if plan.variants and not any(self._landed(plan, m) for m in plan.attacks):
                await self._send_variants(case, plan, made)

        async def cleanup():
            for m in made:
                await self._undo(case, m, first=self._deleter(case, plan, m))

        try:
            await attempt()
        except asyncio.CancelledError:
            cancelled = True
        except Exception as exc:
            failure = f"probe raised {type(exc).__name__}: {exc}"
        finally:
            task = asyncio.ensure_future(cleanup())
            try:
                try:
                    await asyncio.shield(task)
                except asyncio.CancelledError:
                    cancelled = True
                    await task
            except Exception as exc:
                failure += f"; restore raised {type(exc).__name__}: {exc}"
                for m in made:
                    if m.restored is None and _ok2xx(m.sent):
                        m.restored = False
        for m in made:
            self._record(case, m)
        restore_ok = all(m.restored is not False for m in made)
        sent_restores = [m for m in made if m.restored is not None]
        left = [m for m in made if m.left]
        evidence = (f"kind={case.kind}; target=POST {case.exchange.url}; writer={_pid(case.actor)}; "
                    + (f"other={_pid(plan.other)}; " if plan.other else "")
                    + f"change={plan.detail}; legs="
                    + ",".join(f"{m.label}:{m.status}" for m in made)
                    + (f"; variants_unsent={' | '.join(plan.unsent)}" if plan.unsent else "")
                    + (f"; login={plan.login_source}" if plan.login_url else "")
                    + "".join(f"; login_{m.label}=" + ",".join(f"{k}:{getattr(v, 'status', None)}"
                                                              for k, v in m.logins.items())
                              + f"->{m.login_result or 'unread'}" for m in made if m.logins)
                    + f"; restore={'sent' if sent_restores else 'left_in_place' if left else 'not_needed'}; restored="
                    + ",".join(f"{m.label}:{'ok' if m.restored else 'FAILED'}" for m in sent_restores)
                    + (f"; left_in_place={' | '.join(m.item or m.account or m.label for m in left)}"
                       if left else "")
                    + f"; restore_succeeded={str(restore_ok).lower()}")
        if left:
            log.warning("write_integrity: %d self-service create(s) left in place by the owner's opt-in "
                        "(validators.write_integrity.allow_unrestorable_self_service_creates): %s",
                        len(left), ", ".join(m.item or m.account or m.url for m in left))
        fc = case.finding.vulnerability_class
        if not restore_ok:
            left = [m.item or f"an object created at {m.url} (not located)" for m in made if m.restored is False]
            message = ("RESTORE FAILED: write_integrity could not delete and verify the removal of "
                       + "; ".join(left) + " -- remove it manually. " + evidence
                       + (" " + failure if failure else ""))
            log.error(message)
            if cancelled:
                raise asyncio.CancelledError(message)
            return self._result("error", fc, message, evidence=evidence)
        if cancelled:
            raise asyncio.CancelledError
        control = plan.control
        if failure:
            return self._result("error", fc, "write_integrity probe incomplete; every created object "
                                             "was deleted. " + failure, evidence=evidence)
        if not _ok2xx(control.sent):
            return self._result("inconclusive", fc,
                                f"Positive control failed: the legitimate create returned HTTP "
                                f"{control.status}; no attack was sent", evidence=evidence)
        undone = " Every created object was deleted and its removal verified."
        if left:
            undone = (f" {len(left)} throwaway account(s) were created and NOT deleted (no DELETE route; "
                      f"validators.write_integrity.allow_unrestorable_self_service_creates is on): "
                      + ", ".join(m.item or m.account or f"an object created at {urlsplit(m.url).path}"
                                  for m in left)
                      + ".")
        if control.obj is None:
            return self._result("inconclusive", fc,
                                "Positive control created an object that could not be read back; no "
                                "attack was sent." + undone, evidence=evidence)
        judge = {CROSS_IDENTITY_WRITE: self._judge_cross_identity, FORGED_AUTHORSHIP: self._judge_reference,
                 BUSINESS_RULE_TAMPER: self._judge_reference,
                 MASS_ASSIGNMENT_CREATE: self._judge_mass_assignment,
                 CREATE_VALIDATION: self._judge_validation}[case.kind]
        status, summary, control_outcome = judge(case, plan)
        tried = plan.attacks + plan.sent
        controls = [control.read, control.check] + [x for m in tried for x in (m.read, m.check)]
        landed = next((m for m in tried if case.kind == CROSS_IDENTITY_WRITE and self._landed(plan, m)), None)
        attack = landed.sent if landed is not None else next(
            (m.sent for m in tried if _ok2xx(m.sent)), plan.attacks[0].sent)
        return self._result(status, fc, summary + undone, evidence=evidence,
                            confirmed=status == "confirmed",
                            confidence=0.9 if status == "confirmed" else 0.4 if status == "supported" else 0.0,
                            control_outcome=control_outcome
                            ).with_artifacts(baseline=control.sent, attack=attack,
                                             controls=[c for c in controls if c is not None])

    # -- cross-identity parameter pollution ------------------------------------------

    @staticmethod
    def _stored_ref(plan: _Plan, obj: dict):
        """(found, value) of the reference field `plan` forged, in a read-back."""
        found, stored = _field_of(obj, plan.field)
        if not found:
            stem = naming.object_key(_ID_SUFFIX.sub("", plan.field) or plan.field)
            found, stored = next(((True, v) for k, v in obj.items() if _ref_stem(k) == stem),
                                 (False, None))
        return found, stored

    def _landed(self, plan: _Plan, made: _Made) -> bool:
        """The read-back of `made` stores the foreign reference: the object landed on
        the other principal's object (the only confirmation a variant gets)."""
        if made.obj is None or plan.other is None:
            return False
        found, stored = self._stored_ref(plan, made.obj)
        return bool(found) and _same_value(stored, plan.forged)

    def _deleter(self, case: _Case, plan: _Plan, made: _Made):
        """Whose sessions delete `made` first: the other principal when the object
        landed on its object, the writer for a variant, else the default order."""
        if case.kind == CROSS_IDENTITY_WRITE and self._landed(plan, made):
            return plan.other
        return case.actor if any(made is v for v in plan.sent) else None

    async def _send_variants(self, case: _Case, plan: _Plan, made: list) -> None:
        """Send the pollution variants one at a time, each only while the case's
        mutating headroom pays for its create and one delete per principal, deleting
        each one that did not land before the next (a unique rule would refuse it)."""
        for m in plan.attacks:   # the plain attack's object, bound to the writer's own
            await self._undo(case, m, first=case.actor)
            if m.restored is False:
                plan.unsent += [f"{v.label} (an earlier create could not be removed)" for v in plan.variants]
                return
        need = 1 + len({_pid(r) for r in self._readers(case)})
        for i, v in enumerate(plan.variants):
            headroom, _, ceiling = self.run_context.gate.mutating_headroom(case.case_ref, self.name)
            if headroom < need:
                plan.unsent += [f"{x.label} (mutating headroom {headroom} < {need}; ceiling {ceiling})"
                                for x in plan.variants[i:]]
                return
            made.append(v)
            plan.sent.append(v)
            await self._create(case, v)
            if self._landed(plan, v):
                return
            await self._undo(case, v, first=case.actor)
            if v.restored is False:
                plan.unsent += [f"{x.label} (an earlier create could not be removed)"
                                for x in plan.variants[i + 1:]]
                return

    def _judge_cross_identity(self, case: _Case, plan: _Plan):
        status, summary, outcome = self._judge_reference(case, plan)
        if status == "confirmed" or not (plan.sent or plan.unsent):
            return status, summary, outcome
        plain = plan.attacks[0]
        landed = next((v for v in plan.sent if self._landed(plan, v)), None)
        if landed is not None:
            _, stored = self._stored_ref(plan, landed.obj)
            how = (f"refused (HTTP {plain.status})" if _refused(plain.sent) else
                   "bound to the writer's own object" if _ok2xx(plain.sent) else
                   f"answered HTTP {plain.status}")
            return ("confirmed", f"Cross-identity write by parameter pollution: {_pid(case.actor)!r} "
                                 f"created an object bound to {_pid(plan.other)!r}'s object by sending "
                                 f"{_VARIANT_WORDS.get(landed.label, landed.label)} ({plan.detail}; "
                                 f"HTTP {landed.status}); the read-back stores {plan.field}={stored!r}, "
                                 f"while the plain foreign reference was {how}", "")
        notes = []
        if plan.sent:
            notes.append("parameter-pollution variants did not land ("
                         + ", ".join(f"{v.label}: HTTP {v.status}" for v in plan.sent) + ")")
        if plan.unsent:
            notes.append("not sent: " + "; ".join(plan.unsent))
        lead = next((v for v in plan.sent if _ok2xx(v.sent) and v.obj is None), None)
        if lead is not None:
            return ("supported", f"LEAD: the server accepted {_VARIANT_WORDS.get(lead.label, lead.label)} "
                                 f"carrying {_pid(plan.other)!r}'s reference ({plan.detail}) but the "
                                 f"created object could not be read back; " + "; ".join(notes), "")
        # The plain reference's verdict stands; the summary names what else was tried
        # and what the headroom could not pay for.
        return status, summary + "; " + "; ".join(notes), outcome

    # -- verdicts --------------------------------------------------------------------

    def _judge_reference(self, case: _Case, plan: _Plan):
        """cross_identity_write, forged_authorship, business_rule_tamper: the attack
        sent one forged value; the verdict is what the server stored for it."""
        attack = plan.attacks[0]
        what = {CROSS_IDENTITY_WRITE: "a reference to another principal's object",
                FORGED_AUTHORSHIP: "an author/owner value that is not the writer's",
                BUSINESS_RULE_TAMPER: "an out-of-range value"}[case.kind]
        if _refused(attack.sent):
            return ("not_confirmed", f"The server refused a create carrying {what} "
                                     f"(HTTP {attack.status}; {plan.detail}) while the legitimate "
                                     f"create succeeded", "control_held")
        if not _ok2xx(attack.sent):
            return "inconclusive", f"The attack create returned HTTP {attack.status}", ""
        if attack.obj is None:
            return ("supported", f"LEAD: the server accepted a create carrying {what} "
                                 f"({plan.detail}) but the created object could not be read back", "")
        found, stored = _field_of(attack.obj, plan.field)
        if not found and case.kind == CROSS_IDENTITY_WRITE:
            stem = naming.object_key(_ID_SUFFIX.sub("", plan.field) or plan.field)
            found, stored = next(((True, v) for k, v in attack.obj.items() if _ref_stem(k) == stem),
                                 (False, None))
        if not found:
            return ("supported", f"LEAD: the server accepted a create carrying {what} "
                                 f"({plan.detail}); the read-back does not show {plan.field!r}", "")
        if _same_value(stored, plan.forged):
            summary = {
                CROSS_IDENTITY_WRITE: f"Cross-identity write: {_pid(case.actor)!r} created an object "
                                      f"bound to {_pid(plan.other)!r}'s object ({plan.detail}); the "
                                      f"read-back stores {plan.field}={stored!r}",
                FORGED_AUTHORSHIP: f"Forged authorship: {_pid(case.actor)!r} created an object whose "
                                   f"{plan.field} reads back as {stored!r}, not the writer "
                                   f"({plan.detail})",
                BUSINESS_RULE_TAMPER: f"Business-rule tampering: the server stored {plan.field}="
                                      f"{stored!r} ({plan.detail}); the legitimate create stored "
                                      f"{_field_of(plan.control.obj, plan.field)[1]!r}",
            }[case.kind]
            return "confirmed", summary, ""
        held = {CROSS_IDENTITY_WRITE: "the server bound the reference to the writer's own object",
                FORGED_AUTHORSHIP: "the server bound authorship to the session",
                BUSINESS_RULE_TAMPER: "the server normalized the value"}[case.kind]
        return ("not_confirmed", f"The server accepted the create but {held}: the read-back stores "
                                 f"{plan.field}={stored!r}, not {plan.forged!r}", "control_held")

    def _judge_mass_assignment(self, case: _Case, plan: _Plan):
        attack = plan.attacks[0]
        if _refused(attack.sent):
            return ("not_confirmed", f"The server refused a create carrying privileged fields "
                                     f"(HTTP {attack.status}) while the plain create succeeded",
                    "control_held")
        if not _ok2xx(attack.sent):
            return "inconclusive", f"The attack create returned HTTP {attack.status}", ""
        if attack.obj is None:
            return ("supported", "LEAD: the server accepted a create carrying privileged fields but "
                                 "the created object could not be read back", "")
        stored = sorted(f for f, v in plan.forged.items()
                        if _present_privileged(attack.obj, f, v)
                        and not _present_privileged(plan.control.obj, f, v))
        # A privileged value the server set on an authority-named field the plain
        # create did not have also counts (e.g. role -> "admin" under another key).
        if not stored:
            for k, v in attack.obj.items():
                if isinstance(k, str) and _AUTHORITY_RE.search(k) and not _same_value(
                        v, _field_of(plan.control.obj, k)[1]) and (_is_priv(v, "admin") or v is True):
                    stored.append(k)
        if stored:
            return ("confirmed", f"Mass assignment at create: the read-back of the created object "
                                 f"carries {', '.join(stored)} with the privileged value sent, which "
                                 f"the plain create did not get", "")
        return ("not_confirmed", "The server accepted the create but ignored the privileged fields: the "
                                 "read-back carries none of them", "control_held")

    def _judge_validation(self, case: _Case, plan: _Plan):
        notes, accepted, lead = [], [], []
        dups = [m for m in plan.attacks if m.label.startswith("duplicate")]
        if dups:
            first, second = dups
            if _ok2xx(first.sent) and _ok2xx(second.sent) and first.item and second.item \
                    and first.item != second.item:
                (accepted if first.obj is not None and second.obj is not None else lead).append(
                    f"a duplicate of a unique create was stored as a second object ({second.item})")
            elif _ok2xx(first.sent):
                notes.append(f"the duplicate was refused (HTTP {second.status})"
                             + (f" (not read back by logging in: {second.login_why})"
                                if plan.login_url and second.login_why else ""))
        empty = next(m for m in plan.attacks if m.label == "empty")
        unsettled = []
        if _ok2xx(empty.sent):
            if empty.obj is not None:
                # Only a field the read-back returns as "" counts: a field it never
                # returns (a password) says nothing about what was stored.
                blanks = [k for k in plan.field.split(",") if _field_of(empty.obj, k) == (True, "")]
                (accepted if blanks else lead).append(
                    f"a create with every string field empty was stored"
                    + (f" (read-back: {', '.join(blanks)} empty)" if blanks else ""))
            elif empty.login_result == "stored":
                accepted.append(f"a create with every string field empty was stored although its "
                                f"HTTP {empty.status} answer named no readable object: {empty.login_why}")
            else:
                lead.append("a create with every string field empty was accepted (HTTP "
                            f"{empty.status}) but could not be read back"
                            + (f" ({empty.login_why})" if empty.login_why else ""))
        elif empty.sent is not None:
            if empty.login_result == "stored":
                accepted.append(f"a create with every string field empty was stored despite HTTP "
                                f"{empty.status}: {empty.login_why}")
            elif empty.login_result in ("existing", "unsure"):
                unsettled.append(f"the empty create's HTTP {empty.status} cannot be counted as a refusal: "
                                 f"{empty.login_why}")
            else:
                notes.append(f"the empty create was refused (HTTP {empty.status})"
                             + (f" and {empty.login_why}" if empty.login_result == "not_stored" else
                                f" (not read back by logging in: {empty.login_why})" if empty.login_why
                                else ""))
        if accepted:
            return "confirmed", "Weak create validation: " + "; ".join(accepted + lead), ""
        if lead:
            return "supported", "LEAD: " + "; ".join(lead), ""
        if unsettled:
            return "inconclusive", "Create validation not settled: " + "; ".join(unsettled + notes), ""
        return ("not_confirmed", "The server enforces create validation: " + "; ".join(notes)
                + (f"; {plan.login_note}" if plan.login_note else ""), "control_held")

    # -- update tamper (business_rule_tamper on PUT/PATCH) --------------------------------

    async def _update_tamper(self, case: _Case) -> ValidationResult:
        fc, run, url = case.finding.vulnerability_class, self.run_context, case.exchange.url
        method = (case.exchange.method or "").upper()
        key, label = self._tamper_field(case.body)
        if not key:
            return self._skip(fc, "write_integrity business_rule_tamper: no positive quantity, rating, "
                                  "price or total field in the update; nothing was written")
        headroom, _, ceiling = run.gate.mutating_headroom(case.case_ref, self.name)
        if headroom < 3 or (run.budget.remaining is not None and run.budget.remaining < 8):
            return self._skip(fc, "write_integrity business_rule_tamper: an in-range control, the "
                                  "tamper and the restore need 3 mutating sends "
                                  f"(validators.mutating_ceiling_by_check.write_integrity >= 3; "
                                  f"ceiling is {ceiling}); nothing was written")
        snapshot = await self._send(case, "GET", url)
        original = _object_of(snapshot)
        found, before = _field_of(original, key)
        if original is None or not found or _number(before) is None:
            return self._skip(fc, f"write_integrity business_rule_tamper: the object's read does not "
                                  f"return a numeric {key!r} to restore; nothing was written")
        if method == "PUT" and _masked_paths(original):
            return self._skip(fc, "write_integrity business_rule_tamper: the object's read is not "
                                  "safely round-trippable (masked value); nothing was written")
        # A different, still-valid value: one more, or one less for a rating already at 5.
        in_range = before - 1 if _RATING.match(_flat(key)) and before >= 5 else before + 1
        stored_key = next((k for k in original if _flat(k) == _flat(key)), key)

        def payload(value):
            return {**original, stored_key: value} if method == "PUT" else {key: value}

        restore_body = original if method == "PUT" else {key: before}
        for value, body in ((in_range, payload(in_range)), (_TAMPER_VALUE, payload(_TAMPER_VALUE)),
                            (before, restore_body)):
            decision = run.gate.authorize(validator_name=self.name, method=method, url=url,
                                          body=json.dumps(body))
            if not decision.allowed:
                return self._skip(fc, "write_integrity business_rule_tamper: write/restore preflight "
                                      "refused: " + decision.reason)
        control = control_read = attack = attack_read = undo = check = None
        failure, cancelled = "", False

        async def restore():
            nonlocal undo, check
            from harness import run_handoff
            with run_handoff.restore_scope(f"{case.case_ref}:write_integrity_restore"):
                undo = await self._send(case, method, url, restore_body, cleanup=True)
            check = await self._send(case, "GET", url, cleanup=True)

        try:
            control = await self._send(case, method, url, payload(in_range))
            control_read = await self._send(case, "GET", url)
            if _ok2xx(control) and _same_value(_field_of(_object_of(control_read), key)[1], in_range):
                attack = await self._send(case, method, url, payload(_TAMPER_VALUE))
                attack_read = await self._send(case, "GET", url)
        except asyncio.CancelledError:
            cancelled = True
        except Exception as exc:
            failure = f"probe raised {type(exc).__name__}: {exc}"
        finally:
            sent_any = any(getattr(x, "executed", False) for x in (control, attack))
            if sent_any:
                task = asyncio.ensure_future(restore())
                try:
                    try:
                        await asyncio.shield(task)
                    except asyncio.CancelledError:
                        cancelled = True
                        await task
                except Exception as exc:
                    failure += f"; restore raised {type(exc).__name__}: {exc}"
        restore_sent = undo is not None
        restore_ok = (not restore_sent and not any(getattr(x, "executed", False) for x in (control, attack))) or (
            _ok2xx(undo) and _object_of(check) is not None
            and _stable(_object_of(check)) == _stable(original))
        detail = (f"write_integrity restore {'verified' if restore_ok else 'NOT verified'} "
                  f"(restore HTTP {getattr(undo, 'status', None)}) on {url}")
        try:
            from harness import run_handoff
            ids = [getattr(x, "artifact_id", "") for x in (control, attack) if x is not None]
            run_handoff.mark_restore(run, [i for i in ids if i], ok=restore_ok, detail=detail)
        except Exception:
            log.debug("write_integrity: mark_restore failed", exc_info=True)
        stored = _field_of(_object_of(attack_read), key)[1] if attack_read is not None else None
        evidence = (f"kind={case.kind}; target={method} {url}; writer={_pid(case.actor)}; "
                    f"change={label} {key}: {before!r} -> control {in_range!r}, attack {_TAMPER_VALUE}; "
                    f"control_status={getattr(control, 'status', None)}; "
                    f"attack_status={getattr(attack, 'status', None)}; stored={stored!r}; "
                    f"restore={'sent' if restore_sent else 'not_needed'}; "
                    f"restore_status={getattr(undo, 'status', None)}; "
                    f"restore_succeeded={str(restore_ok).lower()}")
        if not restore_ok:
            message = (f"RESTORE FAILED: write_integrity could not restore {key}={before!r} on {url} "
                       f"and verify it -- restore it manually. " + evidence
                       + (" " + failure if failure else ""))
            log.error(message)
            if cancelled:
                raise asyncio.CancelledError(message)
            return self._result("error", fc, message, evidence=evidence)
        if cancelled:
            raise asyncio.CancelledError
        undone = " Original value restored and verified." if restore_sent else ""
        if failure:
            return self._result("error", fc, "write_integrity probe incomplete." + undone + " " + failure,
                                evidence=evidence)
        artifacts = dict(baseline=control, attack=attack,
                         controls=[c for c in (snapshot, control_read, attack_read, check) if c is not None])
        if attack is None:
            return self._result("inconclusive", fc,
                                f"Positive control failed: an in-range {method} of {key} returned HTTP "
                                f"{getattr(control, 'status', None)} and did not read back; no tamper "
                                f"was sent." + undone, evidence=evidence)
        if _refused(attack):
            return self._result("not_confirmed", fc,
                                f"The server refused {key}={_TAMPER_VALUE} (HTTP {attack.status}) after "
                                f"accepting an in-range value." + undone, evidence=evidence,
                                control_outcome="control_held").with_artifacts(**artifacts)
        if _ok2xx(attack) and _same_value(stored, _TAMPER_VALUE):
            return self._result("confirmed", fc,
                                f"Business-rule tampering: an update stored {key}={stored!r} "
                                f"({label}; an in-range value {in_range!r} was the control)." + undone,
                                evidence=evidence, confirmed=True, confidence=0.9).with_artifacts(**artifacts)
        return self._result("not_confirmed", fc,
                            f"The tamper returned HTTP {attack.status} but the read-back stores "
                            f"{key}={stored!r}, not {_TAMPER_VALUE}." + undone, evidence=evidence,
                            control_outcome="control_held" if _ok2xx(attack) else ""
                            ).with_artifacts(**artifacts)

    # -- forged authorship on an update (PUT/PATCH of one object) --------------------

    def _no_update_object(self, case: _Case) -> str:
        """Why an author-carrying PUT/PATCH with no object id in its path cannot run."""
        ex = case.exchange
        method = (ex.method or "").upper()
        path = urlsplit(ex.url).path or "/"
        status = ex.response_status
        from types import SimpleNamespace
        oid = _created_id(SimpleNamespace(body=ex.response_body or "", headers=ex.response_headers or {}))
        if oid:
            answer = (f" (its answer names object {oid}, but a {method} to the collection adds an "
                      f"object rather than updating one)")
        else:
            answer = f" and its answer (HTTP {status}) names none" if status is not None else " and names none"
        adds = ""
        if status == 201 or oid:
            if not self._restore_route(ex.url):
                from harness.engagement import normalize_path
                adds = (f", and no DELETE route is known for what it adds (DELETE "
                        f"{normalize_path(_item_url(ex.url, '1'))})")
        return (f"write_integrity forged_authorship: the {method} to {path} does not end in an "
                f"object id{answer}, so there is no object to snapshot, read back or write back"
                f"{adds}; nothing was written")

    async def _update_authorship(self, case: _Case) -> ValidationResult:
        """Snapshot one object, re-write its author/owner field with the writer's own
        value (control), then with another identity's, read it back, and write the
        snapshot back (as the forged identity too if the writer can no longer)."""
        fc, run, url = case.finding.vulnerability_class, self.run_context, case.exchange.url
        method = (case.exchange.method or "").upper()
        tag = "write_integrity forged_authorship"
        if case.actor is None:
            return self._skip(fc, f"{tag}: needs the capture to be an authenticated, registered "
                                  f"session; nothing was written")
        key = forged = None
        whose = ""
        for k, v in case.body.items():
            f, w = self._forge_author(case, k, v)
            if f is not None:
                key, forged, whose = k, f, w
                break
        if key is None:
            return self._skip(fc, f"{tag}: the update carries no author/owner/user field whose value "
                                  f"can be replaced by another principal's known identifier; nothing "
                                  f"was written")
        headroom, _, ceiling = run.gate.mutating_headroom(case.case_ref, self.name)
        if headroom < 3 or (run.budget.remaining is not None and run.budget.remaining < 10):
            return self._skip(fc, f"{tag}: the control, the forged update and the write-back need 3 "
                                  f"mutating sends (validators.mutating_ceiling_by_check.write_integrity "
                                  f">= 3; ceiling is {ceiling}); nothing was written")
        snapshot = await self._send(case, "GET", url)
        original = _object_of(snapshot)
        if original is None:
            return self._skip(fc, f"{tag}: a read of {urlsplit(url).path} returned no object (HTTP "
                                  f"{getattr(snapshot, 'status', None)}) to snapshot, so nothing could be "
                                  f"read back or written back; nothing was written")
        found, before = _field_of(original, key)
        if not found:
            return self._skip(fc, f"{tag}: the object's read does not return {key!r}, so a forged value "
                                  f"could not be read back; nothing was written")
        if _same_value(before, forged):
            return self._skip(fc, f"{tag}: the object's {key} already reads {before!r}; nothing was written")
        if method == "PUT" and _masked_paths(original):
            return self._skip(fc, f"{tag}: the object's read is not safely round-trippable (masked "
                                  f"value); nothing was written")
        stored_key = next((k for k in original if _flat(k) == _flat(key)), key)

        def payload(value):
            return {**original, stored_key: value} if method == "PUT" else {key: value}

        restore_body = original if method == "PUT" else {key: before}
        for body in (payload(before), payload(forged), restore_body):
            decision = run.gate.authorize(validator_name=self.name, method=method, url=url,
                                          body=json.dumps(body))
            if not decision.allowed:
                return self._skip(fc, f"{tag}: write/restore preflight refused: " + decision.reason)
        other = next((o for o in case.others if _pid(o) == whose), None)
        control = control_read = attack = attack_read = undo = check = None
        restorer = ""
        failure, cancelled = "", False

        def restored() -> bool:
            obj = _object_of(check)
            return _ok2xx(undo) and obj is not None and _stable(obj) == _stable(original)

        async def restore():
            nonlocal undo, check, restorer
            from harness import run_handoff
            with run_handoff.restore_scope(f"{case.case_ref}:write_integrity_restore"):
                undo = await self._send(case, method, url, restore_body, cleanup=True)
            check = await self._send(case, "GET", url, cleanup=True)
            restorer = _pid(case.actor)
            if restored() or other is None or not _ok2xx(attack):
                return
            # The forged author may own the object now: write it back as that identity.
            if run.gate.mutating_headroom(case.case_ref, self.name)[0] < 1:
                return
            with run_handoff.restore_scope(f"{case.case_ref}:write_integrity_restore"):
                undo = await self._send(case, method, url, restore_body, ident=other, cleanup=True)
            check = await self._send(case, "GET", url, ident=other, cleanup=True)
            restorer = _pid(other)

        try:
            control = await self._send(case, method, url, payload(before))
            control_read = await self._send(case, "GET", url)
            if _ok2xx(control) and _object_of(control_read) is not None:
                attack = await self._send(case, method, url, payload(forged))
                attack_read = await self._send(case, "GET", url)
                if _object_of(attack_read) is None and other is not None:
                    attack_read = await self._send(case, "GET", url, ident=other)
        except asyncio.CancelledError:
            cancelled = True
        except Exception as exc:
            failure = f"probe raised {type(exc).__name__}: {exc}"
        finally:
            if any(getattr(x, "executed", False) for x in (control, attack)):
                task = asyncio.ensure_future(restore())
                try:
                    try:
                        await asyncio.shield(task)
                    except asyncio.CancelledError:
                        cancelled = True
                        await task
                except Exception as exc:
                    failure += f"; restore raised {type(exc).__name__}: {exc}"
        restore_sent = undo is not None
        restore_ok = (not restore_sent and not any(getattr(x, "executed", False) for x in (control, attack))) \
            or restored()
        detail = (f"write_integrity restore {'verified' if restore_ok else 'NOT verified'} "
                  f"(restore HTTP {getattr(undo, 'status', None)} as {restorer or 'nobody'}) on {url}")
        try:
            from harness import run_handoff
            ids = [getattr(x, "artifact_id", "") for x in (control, attack) if x is not None]
            run_handoff.mark_restore(run, [i for i in ids if i], ok=restore_ok, detail=detail)
        except Exception:
            log.debug("write_integrity: mark_restore failed", exc_info=True)
        stored = _field_of(_object_of(attack_read), key)[1] if attack_read is not None else None
        evidence = (f"kind={case.kind}; target={method} {url}; writer={_pid(case.actor)}; "
                    f"change={key}: {before!r} -> {forged!r} ({whose}); "
                    f"control_status={getattr(control, 'status', None)}; "
                    f"attack_status={getattr(attack, 'status', None)}; stored={stored!r}; "
                    f"restore={'sent' if restore_sent else 'not_needed'}; "
                    f"restore_status={getattr(undo, 'status', None)}; restored_by={restorer or '-'}; "
                    f"restore_succeeded={str(restore_ok).lower()}")
        if not restore_ok:
            message = (f"RESTORE FAILED: write_integrity could not write {key}={before!r} back on {url} "
                       f"and verify it -- restore it manually. " + evidence
                       + (" " + failure if failure else ""))
            log.error(message)
            if cancelled:
                raise asyncio.CancelledError(message)
            return self._result("error", fc, message, evidence=evidence)
        if cancelled:
            raise asyncio.CancelledError
        undone = " The snapshot was written back and verified." if restore_sent else ""
        if failure:
            return self._result("error", fc, "write_integrity probe incomplete." + undone + " " + failure,
                                evidence=evidence)
        artifacts = dict(baseline=control, attack=attack,
                         controls=[c for c in (snapshot, control_read, attack_read, check) if c is not None])
        if attack is None:
            return self._result("inconclusive", fc,
                                f"Positive control failed: re-writing the object's own {key}={before!r} "
                                f"returned HTTP {getattr(control, 'status', None)} and did not read back; "
                                f"no forged value was sent." + undone, evidence=evidence)
        if _refused(attack):
            return self._result("not_confirmed", fc,
                                f"The server refused an update setting {key} to {forged!r} ({whose}) "
                                f"(HTTP {attack.status}) after accepting the object's own value."
                                + undone, evidence=evidence,
                                control_outcome="control_held").with_artifacts(**artifacts)
        if _ok2xx(attack) and _same_value(stored, forged):
            return self._result("confirmed", fc,
                                f"Forged authorship on update: {_pid(case.actor)!r} rewrote {key} of "
                                f"{urlsplit(url).path} to {stored!r} ({whose}), not the writer; the "
                                f"read-back stores it (it was {before!r})." + undone,
                                evidence=evidence, confirmed=True, confidence=0.9).with_artifacts(**artifacts)
        return self._result("not_confirmed", fc,
                            f"The update returned HTTP {attack.status} but the server kept authorship "
                            f"bound: the read-back stores {key}={stored!r}, not {forged!r}." + undone,
                            evidence=evidence, control_outcome="control_held" if _ok2xx(attack) else ""
                            ).with_artifacts(**artifacts)

    # -- unauthorized update: write as someone else, read back as owner/admin (R11-5) --

    def _object_ref(self, url: str) -> str:
        from harness import principals
        return principals.object_reference(url, run_id=getattr(self.run_context, "run_id", "") or "")

    def _owner_fact(self, url: str, method: str):
        """The ownership fact for the object at `url` (the write's verb first, then
        GET), and whether it is an operator declaration; (None, False) when none."""
        if self.ownership is None:
            return None, False
        ref = self._object_ref(url)
        for verb in dict.fromkeys((method, "GET")):
            fact = self.ownership.lookup(ref, verb)
            if fact is not None:
                return fact, bool(self.ownership.has_declaration(ref, verb))
        return None, False

    def _update_reader(self, url: str, method: str, idents: list) -> tuple[dict | None, str]:
        """Who reads the object back and writes it back: its owner (an ownership
        fact naming a registered identity), else a registered admin.
        (identity, "owner"|"admin"), or (None, why there is none)."""
        fact, _ = self._owner_fact(url, method)
        owner_id = getattr(fact, "owner_principal_id", "") or ""
        if owner_id:
            owner = next((i for i in idents if _pid(i) == owner_id and i.get("session_ref")), None)
            if owner is not None:
                return owner, "owner"
        admin = next((i for i in idents if _PRIVILEGED_ROLE.search(i.get("role") or "")
                      and i.get("session_ref")), None)
        if admin is not None:
            return admin, "admin"
        return None, (f"its owner {owner_id!r} has no registered session and no admin session is "
                      f"registered" if owner_id else
                      "no owner is known for it and no admin session is registered")

    def _declared_boundary(self, writer, url: str, method: str) -> str:
        """Why a change `writer` (None: anonymous) made to the object at `url`
        crosses a boundary the operator declared, or "": an anonymous write to a
        route on authz.protected_paths, or an authz.owners declaration that does not
        entitle the writer. Self-observed ownership is not a declaration."""
        if writer is None:
            try:
                from harness import protected_routes
                hit = protected_routes.ProtectedRoutes.for_target(
                    getattr(self.run_context, "config", None) or {}, url).match(method, url)
            except Exception:
                log.debug("write_integrity: protected routes failed", exc_info=True)
                hit = None
            if hit is not None:
                return f"an anonymous {method} to a route declared protected ({hit.describe()})"
        fact, declared = self._owner_fact(url, method)
        if fact is None or not declared:
            return ""
        from harness import principals
        principal = principals.Principal.anonymous() if writer is None else _principal_for(writer)
        ref = self._object_ref(url)
        decision = next((self.ownership.authorization(principal, ref, verb)
                         for verb in dict.fromkeys((method, "GET"))
                         if self.ownership.has_declaration(ref, verb)), None)
        if decision != principals.AuthzDecision.UNAUTHORIZED:
            return ""
        owner = getattr(fact, "owner_principal_id", "") or "another principal"
        return (f"authz.owners declares the object to {owner!r}, which does not entitle "
                f"{principal.id!r} ({fact.provenance})")

    async def unauthorized_update(self, finding: Finding, exchange: HttpExchange) -> ValidationResult:
        """R11-5. Snapshot one object as its owner (or an admin), change one
        restorable scalar field of it as anonymous -- and, when anonymous is
        refused, as the capture's own non-owner session -- read it back as the
        reader, and write the snapshot back as the reader (as the writer if the
        reader cannot), verified equal.

        The field and the body come from the reader's snapshot, never from the
        captured body alone: a capture whose body the crawler guessed ({name,
        value}) still gets a write of a field the object really has. A changed
        object is confirmed only against a declared boundary (_declared_boundary);
        otherwise it is a labelled LEAD. A 2xx that leaves the object unchanged is
        not_confirmed. Nothing is sent unless validators.active_enabled and
        allow_mutating_replay are on and the per-case ceiling pays for the write
        and the write-back (a second writer only when it also pays for that)."""
        from harness.security import is_identity_credential_header
        fc, run, url = finding.vulnerability_class, self.run_context, exchange.url
        method = (exchange.method or "").upper()
        tag = "write_integrity unauthorized_update"
        if run is None:
            return self._skip(fc, f"{tag} needs a run transport and registered sessions; nothing was written")
        if (not self.allow_writes or not run.gate.config.active_enabled
                or not run.gate.config.allow_mutating_replay):
            return self._skip(fc, f"{tag} runs only with validators.active_enabled and "
                                  f"validators.allow_mutating_replay on; nothing was written")
        if not run.scope.in_scope(url):
            return self._skip(fc, f"{tag}: target is out of scope; nothing was written")
        if method not in ("PUT", "PATCH") or not _ends_with_id(url):
            return self._skip(fc, f"{tag} needs a PUT/PATCH of one object (a path ending in its id); "
                                  f"got {method} {urlsplit(url).path}; nothing was written")
        idents = _run_identities(run)
        signature = _auth_signature(exchange.request_headers)
        actor = _source_identity(idents, signature)
        if signature and actor is None:
            return self._skip(fc, f"{tag}: the capture's credentials belong to no registered session; "
                                  f"nothing was written")
        headers = {k: v for k, v in (exchange.request_headers or {}).items()
                   if not is_identity_credential_header(k)
                   and k.lower() not in {"host", "content-length", "if-match", "if-none-match"}}
        headers["Content-Type"] = "application/json"
        case_ref = finding.finding_id or finding.case_id or "write-integrity-" + secrets.token_hex(8)
        captured = _json_object(exchange.request_body) or {}
        case = _Case(finding, exchange, UNAUTHORIZED_UPDATE, case_ref, None, idents, headers, captured)
        reader, reader_kind = self._update_reader(url, method, idents)
        if reader is None:
            return self._skip(fc, f"{tag}: nobody can read {urlsplit(url).path} back: {reader_kind}; "
                                  f"nothing was written")
        # Writers: anonymous first; then the capture's own session, only when it is
        # a registered, non-privileged identity other than the reader.
        writers = [None]
        if (actor is not None and not _PRIVILEGED_ROLE.search(actor.get("role") or "")
                and _pid(actor) != _pid(reader)):
            writers.append(actor)
        headroom, _, ceiling = run.gate.mutating_headroom(case_ref, self.name)
        if headroom < 2 or (run.budget.remaining is not None and run.budget.remaining < 6):
            return self._skip(fc, f"{tag}: the write and its write-back need 2 mutating sends "
                                  f"(validators.mutating_ceiling_by_check.write_integrity >= 2; ceiling "
                                  f"is {ceiling}); nothing was written")
        if headroom < 3:
            writers = writers[:1]
        async with _object_lock(url):
            return await self._unauthorized_update_locked(case, reader, reader_kind, writers, captured)

    async def _unauthorized_update_locked(self, case: _Case, reader: dict, reader_kind: str,
                                          writers: list, captured: dict) -> ValidationResult:
        from .cross_identity_validator import _choose_write_field, _mutation_for
        fc, run, url = case.finding.vulnerability_class, self.run_context, case.exchange.url
        method = (case.exchange.method or "").upper()
        tag = "write_integrity unauthorized_update"
        path = urlsplit(url).path
        snapshot = await self._send(case, "GET", url, ident=reader)
        original = _object_of(snapshot)
        if original is None:
            return self._skip(fc, f"{tag}: the {reader_kind}'s read of {path} returned no object (HTTP "
                                  f"{getattr(snapshot, 'status', None)}) to snapshot; nothing was written")
        # A captured key the object really has, else any field of the snapshot.
        field, source = _choose_write_field(captured, original), "captured"
        if field is None:
            field, source = _choose_write_field(original, original), "snapshot"
        if field is None:
            return self._skip(fc, f"{tag}: the object has no string, number or boolean field outside the "
                                  f"fixed denylist (identifiers, owner/user references, roles, "
                                  f"credentials) to change and restore; nothing was written")
        if _masked_paths(original if method == "PUT" else {field: original[field]}):
            return self._skip(fc, f"{tag}: the object's read is not safely round-trippable (masked "
                                  f"value); nothing was written")
        before = original[field]
        marker = _mutation_for(before)
        if marker is None or _same_value(marker, before):
            return self._skip(fc, f"{tag}: {field!r} has no distinct value of its type to write; "
                                  f"nothing was written")
        attack_body = {**original, field: marker} if method == "PUT" else {field: marker}
        restore_body = original if method == "PUT" else {field: before}
        for body in (attack_body, restore_body):
            decision = run.gate.authorize(validator_name=self.name, method=method, url=url,
                                          body=json.dumps(body))
            if not decision.allowed:
                return self._skip(fc, f"{tag}: write/restore preflight refused: " + decision.reason)

        def changed(outcome):
            """True: the object differs from the snapshot; False: it reads back
            unchanged; None: the read says nothing."""
            obj = _object_of(outcome)
            if obj is None:
                return None
            return not (_stable(obj) == _stable(original)
                        and not (isinstance(marker, str) and marker in json.dumps(obj)))

        def may_have_changed() -> bool:
            return any(changed(r) is not False for _, a, r in attempts
                       if getattr(a, "executed", False) and not _refused(a))

        attempts = []          # (writer, write outcome, read-back outcome)
        undo = check = None
        restorer = ""
        failure, cancelled = "", False

        async def restore():
            nonlocal undo, check, restorer
            if not may_have_changed():
                return
            from harness import run_handoff
            for who in [reader] + [w for w, a, _ in attempts if _ok2xx(a)]:
                if run.gate.mutating_headroom(case.case_ref, self.name)[0] < 1:
                    return
                with run_handoff.restore_scope(f"{case.case_ref}:write_integrity_restore"):
                    undo = await self._send(case, method, url, restore_body, ident=who, cleanup=True)
                check = await self._send(case, "GET", url, ident=reader, cleanup=True)
                restorer = "anonymous" if who is None else _pid(who)
                if changed(check) is False:
                    return

        try:
            for writer in writers:
                attack = await self._send(case, method, url, attack_body, ident=writer)
                read = await self._send(case, "GET", url, ident=reader)
                attempts.append((writer, attack, read))
                if not _refused(attack) or changed(read):
                    break   # only a refused write earns the next writer a try
        except asyncio.CancelledError:
            cancelled = True
        except Exception as exc:
            failure = f"probe raised {type(exc).__name__}: {exc}"
        finally:
            if any(getattr(a, "executed", False) for _, a, _ in attempts):
                task = asyncio.ensure_future(restore())
                try:
                    try:
                        await asyncio.shield(task)
                    except asyncio.CancelledError:
                        cancelled = True
                        await task
                except Exception as exc:
                    failure += f"; restore raised {type(exc).__name__}: {exc}"
        restore_sent = undo is not None
        restore_ok = changed(check) is False if restore_sent else not may_have_changed()
        detail = (f"write_integrity restore {'verified' if restore_ok else 'NOT verified'} "
                  f"(restore HTTP {getattr(undo, 'status', None)} as {restorer or 'nobody'}) on {url}")
        try:
            from harness import run_handoff
            ids = [getattr(a, "artifact_id", "") for _, a, _ in attempts]
            run_handoff.mark_restore(run, [i for i in ids if i], ok=restore_ok, detail=detail)
        except Exception:
            log.debug("write_integrity: mark_restore failed", exc_info=True)

        def state(read) -> str:
            return {True: "changed", False: "unchanged"}.get(changed(read), "unread")

        tried = "; ".join(f"{'anonymous' if w is None else _pid(w)} -> HTTP {getattr(a, 'status', None)}, "
                          f"{state(r)}" for w, a, r in attempts)
        evidence = (f"kind={UNAUTHORIZED_UPDATE}; target={method} {url}; reader={_pid(reader)} "
                    f"({reader_kind}); field={field} (from the {source} body); writes=[{tried}]; "
                    f"restore={'sent' if restore_sent else 'not_needed'}; "
                    f"restore_status={getattr(undo, 'status', None)}; restored_by={restorer or '-'}; "
                    f"restore_succeeded={str(restore_ok).lower()}")
        if not restore_ok:
            message = (f"RESTORE FAILED: write_integrity could not write {field}={before!r} back on {url} "
                       f"and verify it -- restore it manually. " + evidence
                       + (" " + failure if failure else ""))
            log.error(message)
            if cancelled:
                raise asyncio.CancelledError(message)
            return self._result("error", fc, message, evidence=evidence)
        if cancelled:
            raise asyncio.CancelledError
        undone = " The snapshot was written back and verified." if restore_sent else ""
        if failure or not attempts:
            return self._result("error", fc, f"{tag} probe incomplete." + undone + " " + failure,
                                evidence=evidence)
        hit = next(((w, a, r) for w, a, r in attempts if changed(r)), None)
        last = attempts[-1][1]
        artifacts = dict(baseline=snapshot, attack=hit[1] if hit else last,
                         controls=[r for _, _, r in attempts if r is not None] + ([check] if check else []))
        if hit is None:
            unsent = [a for _, a, _ in attempts if not getattr(a, "executed", False)]
            if unsent:
                return self._result("blocked", fc,
                                    f"{tag}: a write was not sent ({getattr(unsent[0], 'outcome', '') or 'not sent'}); "
                                    f"a refused send is not evidence the control held." + undone,
                                    evidence=evidence)
            if all(_refused(a) for _, a, _ in attempts):
                statuses = ", ".join(str(getattr(a, "status", None)) for _, a, _ in attempts)
                return self._result("not_confirmed", fc,
                                    f"Every writer was refused (HTTP {statuses}) and the {reader_kind}'s "
                                    f"read-back of {path} is unchanged." + undone, evidence=evidence,
                                    control_outcome="control_held").with_artifacts(**artifacts)
            if any(changed(r) is None for _, _, r in attempts):
                return self._result("inconclusive", fc,
                                    f"The {reader_kind}'s read-back of {path} returned no object, so the "
                                    f"write's effect is unknown." + undone,
                                    evidence=evidence).with_artifacts(**artifacts)
            return self._result("not_confirmed", fc,
                                f"The write returned HTTP {getattr(last, 'status', None)} but the "
                                f"{reader_kind}'s read-back of {path} is unchanged ({field} still "
                                f"{before!r})." + undone, evidence=evidence).with_artifacts(**artifacts)
        writer, attack, _ = hit
        who = "anonymous" if writer is None else repr(_pid(writer))
        boundary = self._declared_boundary(writer, url, method)
        if boundary:
            result = self._result(
                "confirmed", fc,
                f"Unauthorized update: {who} changed {field} of {path} (HTTP {attack.status}) and the "
                f"{reader_kind}'s read-back shows it; {boundary}." + undone,
                evidence=evidence + f"; boundary={boundary}", confirmed=True, confidence=0.9)
            # R11-1: name what this proves; an anonymous write is also missing authentication.
            result.mechanism_classes = (("broken_access_control", "missing_authentication")
                                        if writer is None else ("broken_access_control",))
            return result.with_artifacts(**artifacts)
        return self._result(
            "supported", fc,
            f"LEAD: {who} changed {field} of {path} (HTTP {attack.status}) and the {reader_kind}'s "
            f"read-back shows it, but the route is not on authz.protected_paths and authz.owners "
            f"declares no owner it violates, so whether {who} may modify it is an owner decision. "
            f"Declare the route or its owner to confirm." + undone,
            evidence=evidence + "; boundary=undeclared", confidence=0.4).with_artifacts(**artifacts)
