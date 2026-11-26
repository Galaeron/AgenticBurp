"""Write-integrity constants, field heuristics, case/plan records and login helpers: moved
verbatim out of write_integrity_validator.py (ARC-9). Nothing here sends a request."""

from __future__ import annotations

import logging
import json
import logging
import re
from dataclasses import dataclass, field as dc_field
from urllib.parse import quote, urlsplit, urlunsplit

from .cross_identity_validator import _principal_for, _unwrap_envelope
from harness import naming
from harness.models import Finding, HttpExchange


log = logging.getLogger("harness.validators.write_integrity_validator")


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


def _ends_with_id(url: str) -> bool:
    segments = [s for s in urlsplit(url or "").path.split("/") if s]
    return bool(segments) and bool(_ID_SEGMENT.match(segments[-1]))


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
