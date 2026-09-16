"""
Safety Gate -- the harness's single, mandatory checkpoint for any active
test that sends a mutating (state-changing) HTTP method or amplifies a
request via repetition/concurrency.

Why this exists (read before touching finding_classes or validators/):
--------------------------------------------------------------------
An earlier version of this harness had 13 validators that blindly
reused the CAPTURED exchange's HTTP method when sending a live probe,
regardless of what technique they were actually testing. A cache-
poisoning check, a CORS check, an OAuth redirect_uri check -- none of
these need to replay a POST/PUT/DELETE to work; they were only doing
it because "reuse the original method" was the path of least resistance
when each validator was written independently. If the originally
captured exchange was itself a mutating request (a real "delete
account," "transfer funds," "redeem coupon" action), those validators
would have silently replayed it live against the target while testing
something completely unrelated.

The fix applied alongside this file: every validator whose technique
doesn't inherently require a mutating method now hardcodes a safe one
(GET, or a fixed method appropriate to its technique) -- removing the
capability entirely is a stronger guarantee than gating it, since code
that cannot send a DELETE cannot accidentally send one regardless of
config, bugs, or later edits.

This module exists for the two remaining techniques where mutating
replay is the ACTUAL POINT of the test and can't be designed away:
- API security's mass-assignment probe (must POST/PUT/PATCH to test
  request-body binding)
- The race-condition validator's concurrent burst (must fire the real
  mutating operation multiple times to observe a check-then-act race)

Everything that passes through here is logged, fails closed on
ambiguity, and is bounded by hard ceilings baked into this file that
CANNOT be raised by config -- only the operator's config can make
things MORE restrictive than these ceilings, never less.
"""

from __future__ import annotations
import logging
import re
import time
import urllib.parse
from dataclasses import dataclass, field
from enum import Enum

log = logging.getLogger("harness.safety_gate")

# Methods that are safe by default: no expected server-side state change.
_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})

# Methods this gate treats as mutating and therefore gated.
_MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

# Hard ceilings. These are Python module-level constants, not config
# values -- there is deliberately no config key that can raise them.
# A misconfigured or malicious config.yaml can only lower the
# effective limit (via SafetyGateConfig fields below), never exceed
# these numbers, because the gate takes the min() of the two at
# authorization time (see SafetyGate.authorize_burst).
HARD_MAX_BURST_SIZE = 20
HARD_MAX_MUTATING_REQUESTS_PER_FINDING = 20

# Patterns the harness must never itself send in a body/URL it
# constructs, regardless of any config flag. This is defense in depth
# for the case where a future validator (or a bug in an existing one)
# tries to build a payload containing one of these -- it is NOT a
# claim that these strings can't appear in a captured exchange's own,
# unmodified content (a legitimately captured request/response can
# contain the word "DROP" in a product description; this check only
# ever runs against content the harness is about to SEND as part of a
# probe it constructed, never against passively-observed content).
_HARD_DENY_PATTERNS: tuple[re.Pattern, ...] = (
    re.compile(r'\bDROP\s+TABLE\b', re.IGNORECASE),
    re.compile(r'\bDROP\s+DATABASE\b', re.IGNORECASE),
    re.compile(r'\bTRUNCATE\s+TABLE\b', re.IGNORECASE),
    re.compile(r'\bALTER\s+TABLE\b.*\bDROP\b', re.IGNORECASE),
    re.compile(r'\bDELETE\s+FROM\s+\w+\s*(;|$)', re.IGNORECASE),  # DELETE with no WHERE clause
    re.compile(r'\bUPDATE\s+\w+\s+SET\b(?!.*\bWHERE\b)', re.IGNORECASE),  # UPDATE with no WHERE clause
    re.compile(r'\bshutdown\s*/[rs]\b', re.IGNORECASE),
    re.compile(r'\brm\s+-rf\s+/', re.IGNORECASE),
    re.compile(r'\bformat\s+[a-z]:', re.IGNORECASE),
    re.compile(r'\bxp_cmdshell\b', re.IGNORECASE),
)


class ActionRiskTier(str, Enum):
    SAFE = "safe"                    # GET/HEAD/OPTIONS/TRACE
    MUTATING = "mutating"             # POST/PUT/PATCH/DELETE
    HARD_DENIED = "hard_denied"       # matched a _HARD_DENY_PATTERNS entry -- never allowed, no override


@dataclass(frozen=True)
class AuthorizationDecision:
    allowed: bool
    tier: ActionRiskTier
    reason: str
    allowed_burst_size: int = 1


@dataclass
class SafetyGateConfig:
    """
    Operator-controlled settings. Every field here can only make the
    gate MORE restrictive than the hard ceilings above -- there is no
    field that can exceed HARD_MAX_BURST_SIZE or
    HARD_MAX_MUTATING_REQUESTS_PER_FINDING, enforced by min() at
    authorization time, not by trusting the config to behave.
    """
    active_enabled: bool = False
    allow_mutating_replay: bool = False  # separate, stricter flag from active_enabled
    max_burst_size: int = 1
    max_mutating_requests_per_finding: int = 1

    @classmethod
    def from_dict(cls, cfg: dict) -> "SafetyGateConfig":
        # R01: active_enabled/allow_mutating_replay are safety-critical -- route
        # them through config_schema's strict bool coercion, not Python's naive
        # bool(value) (bool("false") is True). See parse_validators_flags's
        # docstring for the exact defect this closes.
        from harness.config_schema import parse_validators_flags
        flags = parse_validators_flags(cfg)
        return cls(
            active_enabled=flags["active_enabled"],
            allow_mutating_replay=flags["allow_mutating_replay"],
            max_burst_size=int(cfg.get("max_burst_size", 1)),
            max_mutating_requests_per_finding=int(cfg.get("max_mutating_requests_per_finding", 1)),
        )


@dataclass
class AuditLogEntry:
    timestamp: float
    validator_name: str
    method: str
    url: str
    tier: str
    allowed: bool
    reason: str
    burst_size: int = 1


class SafetyGate:
    """
    The mandatory checkpoint. A validator that needs to send a
    mutating method, or repeat/amplify any request, must call
    `authorize()` (or `authorize_burst()` for repeated requests)
    before sending and must not send if `allowed` is False.

    This class cannot force a validator to call it -- see
    test_safety_gate.py's `test_no_validator_bypasses_the_gate`,
    which greps every validator file for direct mutating-method
    construction outside this module, so a validator that tries to
    route around this gate fails the test suite, not just a code
    review someone might skip.
    """

    def __init__(self, config: SafetyGateConfig | None = None):
        self.config = config or SafetyGateConfig()
        self.audit_log: list[AuditLogEntry] = []
        # Per-finding mutating-request accounting (R16): finding_id -> count of
        # mutating sends already reserved this run. Enforced against
        # min(config.max_mutating_requests_per_finding, HARD ceiling).
        self._mutating_counts: dict[str, int] = {}

    def _mutating_ceiling(self) -> int:
        return min(self.config.max_mutating_requests_per_finding,
                   HARD_MAX_MUTATING_REQUESTS_PER_FINDING)

    def _reserve_mutating(self, finding_id: str | None, n: int) -> tuple[bool, int, int]:
        """Atomically reserve `n` mutating sends against a finding's budget (R16).
        Returns (ok, used_before, ceiling). A no-op that always succeeds when no
        finding_id is supplied (accounting is opt-in per call, so existing callers
        are unaffected) or n<=0."""
        if not finding_id or n <= 0:
            return True, 0, 0
        ceiling = self._mutating_ceiling()
        used = self._mutating_counts.get(finding_id, 0)
        if used + n > ceiling:
            return False, used, ceiling
        self._mutating_counts[finding_id] = used + n
        return True, used, ceiling

    def reset_finding_budget(self, finding_id: str | None = None) -> None:
        """Clear the mutating-request budget for one finding, or all of them."""
        if finding_id is None:
            self._mutating_counts.clear()
        else:
            self._mutating_counts.pop(finding_id, None)

    def classify(self, method: str, body: str | None = None, url: str | None = None) -> ActionRiskTier:
        # Check both the raw string AND a URL-decoded version of it.
        # Found via the safety_proxy_addon test suite, not a prior audit:
        # a destructive pattern with its spaces percent-encoded (%20) or
        # plus-encoded (+, the application/x-www-form-urlencoded space
        # convention) never matched the hard-deny regexes below, because
        # none of them tolerate anything but a literal space between
        # words -- "rm+-rf+/" and "rm%20-rf%20/" both classified as SAFE
        # where "rm -rf /" correctly classified as HARD_DENIED. This
        # matters because a URL is exactly the kind of string that
        # arrives percent-encoded as a matter of course, not as an
        # attempt to evade this specific check -- and the target server
        # will decode it before acting on it regardless of what this
        # gate saw. Decoding once before matching closes that gap for
        # both hex percent-encoding and +-as-space; deliberately a
        # single decode pass, not a loop hunting for double-encoding,
        # to keep this bounded and its behavior predictable -- see
        # test_safety_gate.py's tests for exactly what is and isn't
        # covered.
        candidates = [c for c in (body, url) if c]
        decoded_candidates = [urllib.parse.unquote_plus(c) for c in candidates]
        for text in candidates + decoded_candidates:
            for pattern in _HARD_DENY_PATTERNS:
                if pattern.search(text):
                    return ActionRiskTier.HARD_DENIED

        method_upper = (method or "").upper()
        if method_upper in _SAFE_METHODS:
            return ActionRiskTier.SAFE
        if method_upper in _MUTATING_METHODS:
            return ActionRiskTier.MUTATING
        # Fail closed: an unrecognized method (not in either known set)
        # is treated as mutating, the stricter tier, not safe.
        return ActionRiskTier.MUTATING

    def authorize(self, *, validator_name: str, method: str, url: str,
                  body: str | None = None, finding_id: str | None = None,
                  count: int = 1) -> AuthorizationDecision:
        """Authorize a single (non-repeated) request.

        When `finding_id` is supplied, a MUTATING request is also counted against
        that finding's mutating-request budget (R16): once
        max_mutating_requests_per_finding (capped by the hard ceiling) sends have
        been authorized for the finding, further mutating sends are denied. `count`
        is how many sends this authorization represents (>1 for a burst)."""
        tier = self.classify(method, body=body, url=url)

        if tier == ActionRiskTier.HARD_DENIED:
            decision = AuthorizationDecision(
                allowed=False, tier=tier,
                reason="Request content matches a hard-denied destructive pattern "
                       "(e.g. DROP TABLE, DELETE without WHERE, rm -rf). This is never "
                       "allowed regardless of configuration.",
            )
        elif tier == ActionRiskTier.SAFE:
            decision = AuthorizationDecision(allowed=True, tier=tier, reason="Safe method, no gating required.")
        else:  # MUTATING
            if not self.config.active_enabled:
                decision = AuthorizationDecision(
                    allowed=False, tier=tier,
                    reason="Mutating method requires active testing to be enabled "
                           "(validators.active_enabled), which is off.",
                )
            elif not self.config.allow_mutating_replay:
                decision = AuthorizationDecision(
                    allowed=False, tier=tier,
                    reason="Mutating method requires validators.allow_mutating_replay, "
                           "a separate, stricter opt-in from active_enabled, which is off. "
                           "This flag exists specifically because a mutating replay can cause "
                           "real side effects (a real purchase, a real account change) on the "
                           "live target, distinct from ordinary read-only active probing.",
                )
            else:
                # Enforce the per-finding mutating-request ceiling (R16) when a
                # finding_id is supplied -- previously this ceiling was declared in
                # config but never counted, so N separate POSTs all passed.
                ok, used, ceiling = self._reserve_mutating(finding_id, count)
                if not ok:
                    decision = AuthorizationDecision(
                        allowed=False, tier=tier,
                        reason=f"Per-finding mutating-request ceiling reached: {used}/{ceiling} "
                               f"mutating send(s) already authorized for finding {finding_id!r} "
                               f"(max_mutating_requests_per_finding, capped at "
                               f"{HARD_MAX_MUTATING_REQUESTS_PER_FINDING}). Refusing further "
                               f"mutating replay for this finding.")
                else:
                    decision = AuthorizationDecision(allowed=True, tier=tier,
                                                      reason="Mutating method explicitly authorized.")

        self._log(validator_name, method, url, decision)
        return decision

    def authorize_burst(self, *, validator_name: str, method: str, url: str,
                         requested_burst_size: int, body: str | None = None,
                         finding_id: str | None = None) -> AuthorizationDecision:
        """
        Authorize a repeated/concurrent burst of the same request.
        The effective burst size is the minimum of what was requested,
        the operator's configured ceiling, and the hard ceiling in
        this file -- in that order, so a generous config can never
        exceed HARD_MAX_BURST_SIZE, and a validator's own requested
        size can never exceed what the operator configured.

        When `finding_id` is supplied and the request is mutating, the WHOLE
        effective burst is reserved against that finding's mutating budget (R16),
        atomically -- a burst that would exceed the remaining budget is denied.
        """
        # Base tier/enablement check only -- reserve the budget as a single
        # atomic unit below (not one-per-authorize), so pass no finding_id here.
        base = self.authorize(validator_name=validator_name, method=method, url=url, body=body)
        if not base.allowed:
            return base

        effective_burst = min(requested_burst_size, self.config.max_burst_size, HARD_MAX_BURST_SIZE)
        if effective_burst < 1:
            decision = AuthorizationDecision(
                allowed=False, tier=base.tier,
                reason="Configured max_burst_size is below 1 -- bursts are disabled.",
            )
        else:
            reserve_ok, used, ceiling = (
                self._reserve_mutating(finding_id, effective_burst)
                if base.tier == ActionRiskTier.MUTATING else (True, 0, 0))
            if not reserve_ok:
                decision = AuthorizationDecision(
                    allowed=False, tier=base.tier,
                    reason=f"Per-finding mutating budget exhausted: {used}/{ceiling} already used "
                           f"for finding {finding_id!r}; a burst of {effective_burst} would exceed it (R16).")
            else:
                decision = AuthorizationDecision(
                    allowed=True, tier=base.tier,
                    reason=f"Burst authorized at {effective_burst} (requested {requested_burst_size}, "
                           f"operator ceiling {self.config.max_burst_size}, hard ceiling {HARD_MAX_BURST_SIZE}).",
                    allowed_burst_size=effective_burst,
                )
        self._log(validator_name, method, url, decision, burst_size=decision.allowed_burst_size)
        return decision

    def _log(self, validator_name: str, method: str, url: str,
              decision: AuthorizationDecision, burst_size: int = 1) -> None:
        entry = AuditLogEntry(
            timestamp=time.time(), validator_name=validator_name, method=method, url=url,
            tier=decision.tier.value, allowed=decision.allowed, reason=decision.reason,
            burst_size=burst_size,
        )
        self.audit_log.append(entry)
        level = logging.INFO if decision.allowed else logging.WARNING
        log.log(level, f"[safety_gate] {validator_name} {method} {url[:120]} "
                        f"-> {'ALLOWED' if decision.allowed else 'BLOCKED'} ({decision.reason})")


class SafetyGateBlocked(Exception):
    """Raised by GatedAsyncClient when a request is denied by the gate."""
    def __init__(self, decision: AuthorizationDecision):
        self.decision = decision
        super().__init__(decision.reason)


class GatedAsyncClient:
    """
    Drop-in async-context-manager wrapper around httpx.AsyncClient that
    routes every request through SafetyGate.authorize() first. Only
    needed by validators that legitimately send mutating methods
    (api_security's mass-assignment probe today); everything else was
    fixed to never need a mutating method at all, so it uses plain
    httpx.AsyncClient directly and never needs this wrapper.
    """

    def __init__(self, gate: SafetyGate, validator_name: str, **httpx_kwargs):
        import httpx
        self._client = httpx.AsyncClient(**httpx_kwargs)
        self._gate = gate
        self._validator_name = validator_name

    async def __aenter__(self) -> "GatedAsyncClient":
        await self._client.__aenter__()
        return self

    async def __aexit__(self, *exc):
        return await self._client.__aexit__(*exc)

    async def request(self, method: str, url: str, *, content=None, headers=None, **kwargs):
        decision = self._gate.authorize(
            validator_name=self._validator_name, method=method, url=url,
            body=content if isinstance(content, str) else None,
        )
        if not decision.allowed:
            raise SafetyGateBlocked(decision)
        return await self._client.request(method, url, content=content, headers=headers, **kwargs)


_default_gate: SafetyGate | None = None


def get_default_gate(config: dict | None = None) -> SafetyGate:
    """
    Process-wide default gate, initialized from the validators config
    block on first call. Subsequent calls ignore `config` and return
    the same instance, so the audit log accumulates across a whole
    run rather than resetting per validator.
    """
    global _default_gate
    if _default_gate is None:
        _default_gate = SafetyGate(SafetyGateConfig.from_dict(config or {}))
    return _default_gate


def reset_default_gate() -> None:
    """Test-only: clears the process-wide gate so tests don't leak state into each other."""
    global _default_gate
    _default_gate = None
