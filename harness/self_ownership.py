"""
self_ownership.py -- ownership the harness observed for its OWN test principals.

The ownership ledger (principals.py) decides a cross-principal read only from
operator declarations, so a run whose operator declared nothing never confirms an
IDOR -- even when the harness itself logged two accounts in and saw which objects
the application handed each of them. This module records those observations as
`self_observed` ownership facts and answers the same AUTHORIZED / UNAUTHORIZED /
UNKNOWN question, one priority BELOW any operator declaration (the ledger only
consults it when nothing is declared for the object).

What counts as an observation (an exchange the harness itself sent or captured --
`observe()` refuses any other source, so a model's claim can never become one):

  - a self-scoped read (`/whoami`, `/me`, `/userinfo` ...) answered 2xx with an
    account `id` / `email`: binds the requesting principal to that account, and the
    account owns the `users/{id}` object;
  - a login answered 2xx with a basket id next to the account's email (`bid` /
    `basketId` ...): the account owns `basket/{bid}`;
  - an authenticated POST answered 2xx with a JSON `id`: the creating principal
    owns `<collection>/{id}`.

On top of those rules, an agent (the local model) may classify an unknown route
as self-scoped, naming only a kind and a JSON pointer; the harness uses it only
after its own exchanges corroborate it (see `classify_pending`). The model never
names an owner or an id, so no fact comes from its claim.

A decision needs more than a differing credential: two credentials can be two
sessions of ONE account. UNAUTHORIZED therefore needs the owner and the reader to
be shown to be DIFFERENT accounts -- both bound to an account of the same kind
(id or email) that differs, or two distinct operator-named (non-provisional)
principals. An object two different accounts were both served is ambiguous and
stays UNKNOWN. Emails are kept only as a hash.

Pure/deterministic and in-memory; persistence to `ownership_facts` is an audit
copy that nothing loads back as a declaration.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from harness.principals import ANON, AuthzDecision, OwnershipFact

log = logging.getLogger(__name__)

SELF_OBSERVED = "self_observed"
# The only producers of an observation: the run's transport (a send the harness
# made under a registered session) and an analysed capture (an exchange the proxy
# or capture driver recorded). Anything else -- a model, an agent's text -- is refused.
HARNESS_SOURCES = frozenset({"transport", "capture"})

_WHOAMI = re.compile(r"^(whoami|me|current[-_]?user|userinfo|self)$", re.IGNORECASE)
_LOGIN = re.compile(r"(log[-_]?in|sign[-_]?in|authenticate|oauth2?/token|sessions?)$", re.IGNORECASE)
_ID_SEGMENT = re.compile(r"^(\d+|[0-9a-fA-F]{8,}|[0-9a-fA-F]{8}-[0-9a-fA-F-]{4,})$")
_COLLECTION = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,40}$")
_BASKET_KEYS = ("bid", "basketid", "basket_id")
MAX_CANDIDATE_ROUTES = 50
MAX_SAMPLES = 4
MAX_AGENT_CALLS = 20

ROUTE_CLASSIFIER_PROMPT = """You classify one HTTP route of a web application under test.
You see the method, the route template ({id} marks an id segment) and the SHAPE of a JSON
response (keys and value types, no values). Decide whether the route returns, to whoever
calls it, an identifier of the CALLER'S OWN account or of an object the caller owns
(e.g. "my profile", "my cart", "the order I just created").
Answer JSON only:
{"self_scoped": true|false, "kind": "account"|"own_object",
 "id_pointer": "<JSON pointer to that identifier, e.g. /data/id>",
 "collection": "<the path segment under which that object is addressed, e.g. users, baskets>"}
Say self_scoped=false when unsure. Your answer is a hypothesis: the harness verifies it
against the responses it observed before using it."""
_EMAIL_KEYS = ("email", "umail", "mail")


def _stem(segment: str) -> str:
    s = re.sub(r"[^a-z0-9]", "", segment.lower())
    return s[:-1] if s.endswith("s") and len(s) > 1 else s


def _scalar(value) -> str:
    if isinstance(value, bool) or value is None:
        return ""
    if isinstance(value, (int, str)) and str(value).strip():
        return str(value).strip()
    return ""


def _email_key(value) -> str:
    v = _scalar(value).lower()
    return "email:" + hashlib.sha256(v.encode()).hexdigest()[:16] if "@" in v else ""


def _json(body: str):
    try:
        return json.loads(body or "")
    except (ValueError, TypeError):
        return None


def _dicts(doc, depth: int = 3):
    """`doc` and its nested mappings (not lists: a list is a collection, whose
    members are not the requester's own object)."""
    if not isinstance(doc, dict) or depth < 0:
        return
    yield doc
    for v in doc.values():
        yield from _dicts(v, depth - 1)


def _find(doc, keys) -> str:
    for d in _dicts(doc):
        for k, v in d.items():
            if k.lower() in keys and _scalar(v):
                return _scalar(v)
    return ""


def _at(doc, pointer) -> str | None:
    """The non-empty scalar at a JSON pointer, else None."""
    if not isinstance(pointer, str) or not pointer.startswith("/"):
        return None
    cur = doc
    try:
        for token in pointer[1:].split("/"):
            token = token.replace("~1", "/").replace("~0", "~")
            cur = cur[int(token)] if isinstance(cur, list) else cur[token]
    except (ValueError, TypeError, KeyError, IndexError):
        return None
    return _scalar(cur) or None


def _skeleton(doc, depth: int = 4):
    """Keys and value types of a JSON document, no values (what the agent may see)."""
    if isinstance(doc, dict) and depth > 0:
        return {str(k)[:60]: _skeleton(v, depth - 1) for k, v in list(doc.items())[:40]}
    if isinstance(doc, list) and depth > 0:
        return [_skeleton(doc[0], depth - 1)] if doc else []
    return type(doc).__name__


def ollama_route_classifier(ollama, model: str):
    """The production classifier: the run's local agent model asked for JSON."""
    async def classify(payload: dict) -> dict:
        from harness.ollama_client import model_stage
        with model_stage("self_ownership"):
            return await ollama.chat_json(model, ROUTE_CLASSIFIER_PROMPT,
                                          json.dumps(payload)[:6000], temperature=0.0)
    return classify


@dataclass(frozen=True)
class _Owner:
    principal: str = ""             # a run principal id, or "" for an account-owned object
    account: frozenset = frozenset()  # account keys ("id:23", "email:<hash>")

    @property
    def label(self) -> str:
        return self.principal or "account:" + ",".join(sorted(self.account))


class SelfOwnership:
    """The run's self-observed facts: per-principal account bindings and owned
    objects keyed by (collection stem, id)."""

    def __init__(self, *, run_id: str = "", persist: bool = True) -> None:
        self.run_id = run_id
        self.persist = persist
        self._accounts: dict[str, set] = {}
        self._objects: dict[tuple, tuple] = {}   # (stem, id) -> (_Owner | None, provenance)
        self.rejected = 0
        # Agent-classified routes: (origin, method, template) -> verified rule, or
        # None once refused; samples wait in memory only (never logged or persisted).
        self._routes: dict[tuple, dict | None] = {}
        self._samples: dict[tuple, list] = {}
        self._agent_calls = 0

    # -- recording ---------------------------------------------------------------

    def observe(self, *, source: str, principal_id: str, method: str, url: str,
                status, response_body: str) -> list[str]:
        """Record what one harness-observed exchange says about ownership. Returns
        the facts recorded (provenance strings); [] when it says nothing."""
        if source not in HARNESS_SOURCES:
            self.rejected += 1
            log.warning("self_ownership: refused an observation from %r (only harness exchanges count)",
                        source)
            return []
        if not isinstance(status, int) or not 200 <= status < 300:
            return []
        method = (method or "GET").upper()
        parts = urlsplit(url or "")
        segments = [s for s in parts.path.split("/") if s]
        if not segments:
            return []
        doc = _json(response_body)
        if not isinstance(doc, dict):
            return []
        principal = principal_id if principal_id and principal_id != ANON else ""
        origin = f"{parts.scheme}://{parts.netloc}"
        recorded = []
        last = segments[-1]
        if method == "GET" and _WHOAMI.match(last) and principal:
            uid = _find(doc, ("id",))
            email = _email_key(_find(doc, _EMAIL_KEYS))
            account = {k for k in (f"id:{uid}" if uid else "", email) if k}
            if account:
                self._accounts.setdefault(principal, set()).update(account)
                recorded.append(f"{SELF_OBSERVED}; principal={principal}; account bound via GET {parts.path}")
                if uid:
                    recorded += self._own(origin, "users", uid, _Owner(account=frozenset(account)),
                                          f"served as own account via GET {parts.path}")
        elif method == "POST" and _LOGIN.search(parts.path):
            bid, email = _find(doc, _BASKET_KEYS), _email_key(_find(doc, _EMAIL_KEYS))
            if bid and email:
                recorded += self._own(origin, "basket", bid, _Owner(account=frozenset({email})),
                                      f"basket id returned at login via POST {parts.path}")
        elif method == "POST" and principal and not _ID_SEGMENT.match(last):
            top = doc.get("data") if isinstance(doc.get("data"), dict) else doc
            oid = _scalar(top.get("id"))
            if oid:
                recorded += self._own(origin, last, oid, _Owner(principal=principal),
                                      f"id returned by POST {parts.path} as {principal}",
                                      route=f"{parts.path.rstrip('/')}/{{id}}")
        if not recorded and method in ("GET", "POST"):
            recorded = self._agent_route(origin, method, segments, principal, doc)
        return recorded

    # -- agent-classified routes ---------------------------------------------------
    #
    # On top of the deterministic rules above, an agent may classify a route the
    # rules do not know as self-scoped. It names only a KIND and a JSON POINTER for
    # a route template; it never names an owner or an id. The harness accepts the
    # classification only when its own exchanges corroborate it: the pointer
    # resolves to a scalar in every sample, at least two distinct authenticated
    # principals were served the route with DIFFERENT values there (the route
    # answers per principal), and no anonymous request was served the route. Facts
    # then come from the observed bodies, as with the deterministic rules.

    def _agent_route(self, origin: str, method: str, segments: list, principal: str, doc) -> list[str]:
        key = (origin, method, "/" + "/".join("{id}" if _ID_SEGMENT.match(s) else s for s in segments))
        rule = self._routes.get(key)
        if rule is not None:
            return self._apply_rule(key, rule, principal, doc) if rule and principal else []
        samples = self._samples.get(key)
        if samples is None:
            if len(self._samples) >= MAX_CANDIDATE_ROUTES:
                return []
            samples = self._samples[key] = []
        if not principal:
            samples.append(("", doc))      # an anonymous answer is kept only to refuse the route
        elif len(samples) < MAX_SAMPLES and not any(p == principal for p, _ in samples):
            samples.append((principal, doc))
        return []

    def pending_routes(self) -> list:
        """Route keys the agent has not classified yet and the harness could verify:
        at least two distinct authenticated principals were served them."""
        return [k for k, s in self._samples.items()
                if k not in self._routes and len({p for p, _ in s if p}) >= 2]

    async def classify_pending(self, classify_fn, *, limit: int = 3) -> list[str]:
        """Ask `classify_fn` (async, payload -> dict) about up to `limit` pending
        routes; verify and apply what it proposes. The payload carries the route
        template and the JSON key skeleton only -- never a value from a body."""
        recorded = []
        for key in self.pending_routes()[:limit]:
            if self._agent_calls >= MAX_AGENT_CALLS:
                break
            self._agent_calls += 1
            origin, method, template = key
            payload = {"method": method, "route": template,
                       "response_shape": _skeleton(self._samples[key][0][1])}
            try:
                proposal = await classify_fn(payload)
            except Exception as exc:   # a model failure classifies nothing
                log.info("self_ownership: route classifier failed for %s %s: %s", method, template,
                         type(exc).__name__)
                self._routes[key] = None
                continue
            rule, why = self._verify(key, proposal)
            self._routes[key] = rule
            if rule is None:
                log.info("self_ownership: agent route proposal for %s %s refused: %s", method, template, why)
                continue
            for principal, doc in self._samples.pop(key, []):
                if principal:
                    recorded += self._apply_rule(key, rule, principal, doc)
        return recorded

    def _verify(self, key, proposal) -> tuple[dict | None, str]:
        if not isinstance(proposal, dict) or proposal.get("self_scoped") is not True:
            return None, "not proposed as self-scoped"
        kind, pointer = proposal.get("kind"), proposal.get("id_pointer")
        collection = proposal.get("collection")
        if kind not in ("account", "own_object"):
            return None, "unknown kind"
        if not isinstance(collection, str) or not _COLLECTION.match(collection):
            return None, "collection is not a plain path segment"
        samples = self._samples.get(key, [])
        if any(not p for p, _ in samples):
            return None, "an anonymous request was served this route"
        values = {}
        for principal, doc in samples:
            value = _at(doc, pointer)
            if value is None:
                return None, "the pointer does not resolve to a scalar in every observed response"
            values.setdefault(principal, set()).add(value)
        if len(values) < 2:
            return None, "fewer than two principals observed"
        seen = [v for vals in values.values() for v in vals]
        if len(seen) != len(set(seen)):
            return None, "two principals were served the same value (not per-principal)"
        return {"kind": kind, "pointer": pointer, "collection": collection,
                "corroboration": f"{len(values)} principals, distinct values"}, ""

    def _apply_rule(self, key, rule: dict, principal: str, doc) -> list[str]:
        origin, method, template = key
        value = _at(doc, rule["pointer"])
        if value is None:
            return []
        how = (f"agent-classified route {method} {template} (pointer {rule['pointer']}; harness-verified: "
               f"{rule['corroboration']})")
        if rule["kind"] == "account":
            # An account id is an account key only within its route's collection.
            account = f"id@{_stem(rule['collection'])}:{value}"
            self._accounts.setdefault(principal, set()).add(account)
            return self._own(origin, rule["collection"], value,
                             _Owner(account=frozenset({account})), how)
        return self._own(origin, rule["collection"], value, _Owner(principal=principal), how)

    def _own(self, origin: str, collection: str, oid: str, owner: _Owner, how: str,
             *, route: str = "") -> list[str]:
        key = (_stem(collection), oid)
        route = route or f"*/{collection}/{{id}}"
        provenance = f"{SELF_OBSERVED}; owner={owner.label}; object={collection}/{oid}; route={route}; {how}"
        prior = self._objects.get(key)
        if prior is not None:
            if prior[0] is not None and (prior[0] == owner or self._same_owner(prior[0], owner) is True):
                return []
            if prior[0] is not None:
                # Two owners for one object: shared, or the observation is wrong. Unknown.
                self._objects[key] = (None, f"{SELF_OBSERVED}; ambiguous: {prior[1]} | {provenance}")
            return []
        self._objects[key] = (owner, provenance)
        self._persist(origin, route.replace("{id}", oid), owner, provenance)
        return [provenance]

    def _persist(self, origin: str, resource: str, owner: _Owner, provenance: str) -> None:
        if not self.persist:
            return
        try:
            from harness import store
            store.save_ownership_fact(OwnershipFact(
                object_ref=f"run:{self.run_id or 'legacy'}|app:{origin}|tenant:?|resource:{resource}",
                owner_principal_id=owner.label, provenance=provenance))
        except Exception as exc:   # an audit copy; never fail a send over it
            log.debug("self_ownership: audit persist failed: %s", exc)

    # -- deciding ----------------------------------------------------------------

    def fact_for(self, url: str):
        """(owner, provenance) for the object a URL addresses, or None."""
        segments = [s for s in urlsplit(url or "").path.split("/") if s]
        for i in range(len(segments) - 1, 0, -1):
            hit = self._objects.get((_stem(segments[i - 1]), segments[i]))
            if hit is not None:
                return hit
        return None

    def _account(self, principal) -> set:
        return set(self._accounts.get(getattr(principal, "id", ""), ()))

    def _same_owner(self, owner: _Owner, other: _Owner):
        """True same account, False shown different, None unknown."""
        if owner.principal and owner.principal == other.principal:
            return True
        a = set(owner.account) | (self._accounts.get(owner.principal, set()) if owner.principal else set())
        b = set(other.account) | (self._accounts.get(other.principal, set()) if other.principal else set())
        if a & b:
            return True
        # Keys of one kind ("id", "email", or an agent route's "id@<collection>")
        # on both sides and none shared: different accounts.
        if {k.split(":", 1)[0] for k in a} & {k.split(":", 1)[0] for k in b}:
            return False
        return None

    def authorization(self, principal, url: str) -> tuple[AuthzDecision, str]:
        """What self-observed ownership says about `principal` reading the object at
        `url`, with its provenance. UNKNOWN unless the owner and the reader are shown
        to be the same account (AUTHORIZED) or different accounts (UNAUTHORIZED)."""
        hit = self.fact_for(url)
        if hit is None or hit[0] is None:
            return AuthzDecision.UNKNOWN, (hit[1] if hit else "")
        owner, provenance = hit
        pid = getattr(principal, "id", "") or ""
        if not pid or getattr(principal, "is_anonymous", pid == ANON):
            return AuthzDecision.UNKNOWN, provenance
        same = self._same_owner(owner, _Owner(principal=pid))
        if same is None and owner.principal and owner.principal != pid:
            # Two distinct operator-NAMED principals are distinct accounts by
            # declaration; credential-alias ids (provisional) are not.
            owner_alias = bool(re.search(r"(?:#[0-9a-fA-F]{8}$|^captured:|ephemeral)", owner.principal))
            if not owner_alias and not getattr(principal, "provisional", True):
                same = False
        if same is True:
            return AuthzDecision.AUTHORIZED, provenance
        if same is False:
            return AuthzDecision.UNAUTHORIZED, provenance
        return AuthzDecision.UNKNOWN, provenance


def enabled(config: dict | None) -> bool:
    """`authz.self_observed_ownership` (absent = off, the shipped default)."""
    authz = (config or {}).get("authz", {})
    return isinstance(authz, dict) and authz.get("self_observed_ownership", False) is True
