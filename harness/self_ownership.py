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
_BASKET_KEYS = ("bid", "basketid", "basket_id")
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
        return recorded

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
        for kind in ("id:", "email:"):
            ka, kb = {k for k in a if k.startswith(kind)}, {k for k in b if k.startswith(kind)}
            if ka and kb:
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
