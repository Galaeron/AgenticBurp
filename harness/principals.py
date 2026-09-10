"""
principals.py -- explicit principal / session / ownership model (Astra T02, R27).

The harness has conflated three different things behind "identity":

  - the DURABLE actor (a user account -- Alice),
  - the RENEWABLE credential that authenticates it right now (a cookie/token that
    expires and is refreshed), and
  - WHO OWNS a given object (the fact that decides whether Alice reaching object 7
    is normal or a broken-object-authorization bug).

Collapsing them causes real defects: a refreshed cookie reads as a NEW principal
(so Alice stops being Alice), two different people with the same role collapse into
one matrix column, and "another identity reached this object" is treated as a BOLA
even when the object is public or was legitimately shared.

This module separates them, additively (it does not replace identity.py / role_crawl
-- RoleSession stays as an adapter via `RoleSession.to_principal()`):

  - `Principal`  -- a stable id that survives credential renewal, plus role, an
    explicit trust level, tenant membership, and OPERATOR-DECLARED expected
    permissions (never inferred from role rank or URL spelling).
  - `Session`    -- the renewable credential material; `renew()` bumps a generation
    but keeps the same principal_id, so a re-login leaves the principal stable. The
    actual headers live here, never in a finding/issue (findings carry a session
    reference).
  - `OwnershipFact` -- an OBSERVED fact about who owns / can reach an object, with
    provenance. Unknown ownership stays UNKNOWN; it is never guessed.
  - `OwnershipLedger.authorization()` -- the decision a confirmation leg consults:
    AUTHORIZED (own object / shared / public / declared permission -> not a bug),
    UNAUTHORIZED (a real boundary crossing), or UNKNOWN (ownership not established
    -> never a confirmation on its own).

Pure/deterministic; no network, no model call.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlsplit

ANON = "anonymous"


def object_reference(url: str, *, run_id: str = "", tenant: str | None = None) -> str:
    """Namespace a concrete object selection by run and application origin.

    The raw query is retained so repeated parameters and their order remain part
    of the selected object identity. Fragments are client-side and excluded.
    """
    parsed = urlsplit(url)
    scheme = (parsed.scheme or "").lower()
    host = (parsed.hostname or "").lower()
    port_value = parsed.port
    port = "" if (scheme == "http" and port_value in (None, 80)) or \
        (scheme == "https" and port_value in (None, 443)) else f":{port_value}"
    origin = f"{scheme}://{host}{port}" if scheme and host else "unknown-app"
    resource = parsed.path or "/"
    if parsed.query:
        resource += "?" + parsed.query
    return f"run:{run_id or 'legacy'}|app:{origin}|tenant:{tenant or '?'}|resource:{resource}"

# Coarse trust levels. Deliberately explicit integers, not a role-name lookup, so
# modules stop disagreeing on ordering. A higher number is MORE privileged, but
# trust rank NEVER by itself authorizes access to an object -- only a declared
# permission or an ownership/share fact does (see OwnershipLedger.authorization).
TRUST_BY_ROLE = {"anonymous": 0, "guest": 0, "user": 1, "member": 1,
                 "service": 2, "staff": 2, "manager": 3, "admin": 3, "administrator": 3}


class AuthzDecision(str, Enum):
    AUTHORIZED = "authorized"       # the principal is entitled to this object -> not a crossing
    UNAUTHORIZED = "unauthorized"   # a real boundary crossing
    UNKNOWN = "unknown"             # ownership/entitlement not established -> never a confirmation


@dataclass(frozen=True)
class Principal:
    """A durable actor identity, distinct from the session that authenticates it.

    `id` is stable across credential renewal -- it is NOT derived from the current
    cookie/token. `provisional=True` marks an id that could only be derived from a
    credential hash (no explicit account name was supplied), so callers know not to
    treat it as an authoritative account identity or to merge/split people on it."""
    id: str
    role: str = "user"
    trust: int = 1
    tenant: str | None = None                       # None = unknown; never inferred from URL/role
    expected_permissions: frozenset = frozenset()   # operator/fixture-declared, never role-rank-derived
    provisional: bool = False
    label: str = ""

    @property
    def is_anonymous(self) -> bool:
        return self.id == ANON or self.trust <= 0

    def has_permission(self, perm: str) -> bool:
        return perm in self.expected_permissions

    @classmethod
    def anonymous(cls) -> "Principal":
        return cls(id=ANON, role="anonymous", trust=0)

    def to_dict(self) -> dict:
        return {"id": self.id, "role": self.role, "trust": self.trust, "tenant": self.tenant,
                "expected_permissions": sorted(self.expected_permissions),
                "provisional": self.provisional, "label": self.label}

    @classmethod
    def from_dict(cls, d: dict) -> "Principal":
        return cls(id=d.get("id", ""), role=d.get("role", "user"), trust=int(d.get("trust", 1)),
                   tenant=d.get("tenant"),
                   expected_permissions=frozenset(d.get("expected_permissions", []) or []),
                   provisional=bool(d.get("provisional", False)), label=d.get("label", ""))


@dataclass
class Session:
    """Renewable credential material authenticating a principal.

    Refreshing bumps `generation` but NEVER changes `principal_id`, so a re-login or
    token refresh leaves the principal's identity stable. The actual auth headers
    live here (for local replay), never in a finding/issue -- those carry only the
    session id. `redacted_view()` is the export-safe projection."""
    id: str
    principal_id: str
    headers: dict = field(default_factory=dict)
    generation: int = 0
    healthy: bool = True
    created_at: float = field(default_factory=time.time)
    last_used_at: float = 0.0

    def renew(self, headers: dict) -> "Session":
        """A refreshed session: SAME principal, new credentials, next generation."""
        return Session(id=self.id, principal_id=self.principal_id, headers=dict(headers or {}),
                       generation=self.generation + 1, healthy=True,
                       created_at=self.created_at, last_used_at=time.time())

    def redacted_view(self) -> dict:
        return {"id": self.id, "principal_id": self.principal_id, "generation": self.generation,
                "healthy": self.healthy}

    def to_dict(self) -> dict:
        return {"id": self.id, "principal_id": self.principal_id, "headers": dict(self.headers or {}),
                "generation": self.generation, "healthy": self.healthy,
                "created_at": self.created_at, "last_used_at": self.last_used_at}

    @classmethod
    def from_dict(cls, d: dict) -> "Session":
        return cls(id=d.get("id", ""), principal_id=d.get("principal_id", ""),
                   headers=dict(d.get("headers", {}) or {}), generation=int(d.get("generation", 0)),
                   healthy=bool(d.get("healthy", True)), created_at=d.get("created_at", 0.0),
                   last_used_at=d.get("last_used_at", 0.0))


@dataclass(frozen=True)
class OwnershipFact:
    """An OBSERVED fact about who owns / can reach an object, with provenance.

    Unknown ownership stays unknown: an empty owner with no share/public flag makes
    `known` False, and the ledger returns UNKNOWN for it -- the harness never
    guesses an owner from a URL or a role label."""
    object_ref: str
    owner_principal_id: str = ""            # "" = unknown owner
    tenant: str | None = None              # None = unknown tenant
    shared_with: frozenset = frozenset()    # principals explicitly granted access
    public: bool = False
    provenance: str = ""                    # how observed, e.g. "created-as:alice via POST /items"
    observed_at: float = field(default_factory=time.time)

    @property
    def known(self) -> bool:
        return bool(self.owner_principal_id) or self.public or bool(self.shared_with)

    def to_dict(self) -> dict:
        return {"object_ref": self.object_ref, "owner_principal_id": self.owner_principal_id,
                "tenant": self.tenant, "shared_with": sorted(self.shared_with),
                "public": self.public, "provenance": self.provenance, "observed_at": self.observed_at}

    @classmethod
    def from_dict(cls, d: dict) -> "OwnershipFact":
        return cls(object_ref=d.get("object_ref", ""), owner_principal_id=d.get("owner_principal_id", ""),
                   tenant=d.get("tenant"), shared_with=frozenset(d.get("shared_with", []) or []),
                   public=bool(d.get("public", False)), provenance=d.get("provenance", ""),
                   observed_at=d.get("observed_at", 0.0))


class OwnershipLedger:
    """Observed ownership facts + the authorization decision a leg consults.

    Conservative by construction: unknown ownership is UNKNOWN (never a confirmed
    crossing), and only an own-object / explicit-share / public / operator-declared
    permission yields AUTHORIZED. Everything else with KNOWN ownership is a real
    UNAUTHORIZED crossing."""

    def __init__(self) -> None:
        self._by_ref: dict[str, OwnershipFact] = {}

    def record(self, fact: OwnershipFact) -> OwnershipFact:
        self._by_ref[fact.object_ref] = fact
        return fact

    def owner_of(self, object_ref: str) -> OwnershipFact | None:
        return self._by_ref.get(object_ref)

    def authorization(self, principal: Principal, object_ref: str) -> AuthzDecision:
        fact = self._by_ref.get(object_ref)
        if fact is None or not fact.known:
            return AuthzDecision.UNKNOWN            # ownership not established -> never a crossing
        pid = principal.id
        if fact.public:
            return AuthzDecision.AUTHORIZED
        if pid and pid == fact.owner_principal_id:
            return AuthzDecision.AUTHORIZED         # own object
        if pid in fact.shared_with:
            return AuthzDecision.AUTHORIZED         # explicitly shared with this principal
        # An OPERATOR-DECLARED permission over this object (never inferred from role
        # rank): the fixture states "carol may read object 7" as expected_permissions.
        if object_ref in principal.expected_permissions or f"read:{object_ref}" in principal.expected_permissions:
            return AuthzDecision.AUTHORIZED
        # Known owner, and this principal is not it / not shared / no declared
        # permission -> a real boundary crossing. Same-tenant does NOT authorize
        # (a colleague is still not entitled to your object); cross-tenant is the
        # same verdict, only more clearly so.
        return AuthzDecision.UNAUTHORIZED
