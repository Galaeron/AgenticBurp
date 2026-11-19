"""
Multi-step business flows (R11-7, HU-4 scope): checkout/payment tamper at the
settlement step, coupon/voucher misuse, and disabling 2FA without the step-up
secret.

Every check starts from the run's own captured flow, never from knowledge of the
target application: the settlement capture and the cart writes the same identity
made before it, the coupon write, the 2FA-disable request, and the captured GETs
that read the resulting state back (an order history, a balance, a basket, a 2FA
status). Operators may add read-backs in `validators.business_flow.read_backs`.

Owner decision (2026-11-19): these checks may drive multi-step writes on
run-owned accounts, restoring what they can and naming in the finding what they
could not. So:

- only a run-owned identity acts: the capture's credentials must belong to a
  session the run registered (never an ephemeral or foreign credential), and
  every send goes through `RunContext.executor()` as that session;
- every check needs `validators.active_enabled`, `validators.allow_mutating_replay`
  and an explicit `validators.mutating_ceiling_by_check.business_flow` entry that
  pays for the plan's writes before the first one is sent; the committed config
  sets none of them, so a default run sends nothing;
- no DELETE is ever sent (owner policy): a placed order cannot be undone and is
  named `LEFT IN PLACE`; a coupon is cleared by re-sending the write with the
  code emptied (or the earlier code put back); 2FA is re-enabled by replaying the
  run's own captured enable request, else named `LEFT DISABLED`;
- a verdict rests on a read-back of the resulting state, never on a 2xx alone.

Kinds (the finding class the coverage drive hands the leg):

  payment_tamper      a client-chosen amount, quantity or delivery value at the
                      settlement step (or in a cart write before it) makes the
                      server settle for less than the untampered control flow;
                      or a settlement with its payment field dropped or forged
                      grants a standing (membership, tier) without a debit.
  coupon_misuse       a forged code, an expired code or another identity's code
                      earns a discount the read-back shows.
  mfa_disable_stepup  a captured 2FA-disable request with its password/TOTP field
                      missing or wrong turns 2FA off on the status read-back.
"""
from __future__ import annotations

import json
import logging
import re
import secrets
import string
from dataclasses import dataclass, field as dc_field
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

from harness.models import Finding, HttpExchange
from .base import Validator, ValidationResult
from .client_trust_validator import (_COUPON, _PAYMENT, _QUANTITY, _authority_state, _discounts,
                                     _elevations, _flat, _flatten, _json, _money)
from .cross_identity_validator import _auth_signature, _object_lock

log = logging.getLogger(__name__)

PAYMENT_TAMPER = "payment_tamper"
COUPON_MISUSE = "coupon_misuse"
MFA_DISABLE = "mfa_disable_stepup"
KINDS = (MFA_DISABLE, COUPON_MISUSE, PAYMENT_TAMPER)

_CLASS_TOKENS = {
    PAYMENT_TAMPER: ("payment_tamper", "payment tamper", "payment_tampering", "payment tampering",
                     "checkout_tamper", "checkout tampering", "settlement_tamper", "payment_bypass",
                     "payment bypass", "payment_skip", "order_total_tamper", "wallet_payment_skip"),
    COUPON_MISUSE: ("coupon_misuse", "coupon misuse", "coupon_forgery", "coupon forgery",
                    "coupon_reuse", "expired_coupon", "voucher_misuse", "promo_code_abuse",
                    "discount_code_abuse", "cross_user_coupon"),
    MFA_DISABLE: ("mfa_disable_stepup", "mfa disable stepup", "2fa_disable", "2fa disable",
                  "mfa_disable", "two_factor_disable", "mfa_step_up_bypass",
                  "2fa_disable_without_password"),
}
# A business-logic finding reaches this leg too, but only on a shape the
# client_trust leg (single-request tamper) does not already own.
_GENERIC_CLASSES = ("business_logic", "business logic", "logic_flaw", "logic flaw")
FINDING_CLASSES = {t for toks in _CLASS_TOKENS.values() for t in toks} | set(_GENERIC_CLASSES)

_WRITE_METHODS = ("POST", "PUT", "PATCH")
_SETTLE_PATH = re.compile(
    r"(?:^|/)(?:checkout|check-out|place[-_]?order|orders?|purchase|payments?|pay|buy|settle|"
    r"complete[-_]?order|submit[-_]?order|membership|deluxe[-_]?\w*|premium|subscribe|"
    r"subscriptions?|upgrade|top[-_]?up|deposit)(?:/|$)", re.I)
_CART_PATH = re.compile(r"(?:^|/)(?:carts?|baskets?|bags?|basket[-_]?items?|cart[-_]?items?|"
                        r"line[-_]?items?|items?)(?:/|$)", re.I)
_AUTH_PATH = re.compile(r"log[-_]?in|sign[-_]?in|log[-_]?out|regist|sign[-_]?up|password|2fa|mfa|"
                        r"totp|otp", re.I)
_COUPON_PATH = re.compile(r"(?:^|/)(?:coupons?|vouchers?|promos?|promo[-_]?codes?|discounts?|"
                          r"redeem)(?:/|$)", re.I)
_COUPON_FIELD = re.compile(f"(?:{_COUPON.pattern})|^(?:coupon|voucher|promo)(?:data|value|id)$")
_MONEY_KEYS = re.compile(r"^(?:price|amount|cost|total|subtotal|unitprice|fee|payamount|"
                         r"paymentamount|deliveryprice|deliverycost|shippingcost|shippingprice)$")
_DELIVERY = re.compile(r"^(?:delivery|shipping|shipment)(?:method|option|type|speed|mode)?(?:id)?$")
_MFA_PATH = re.compile(r"(?:^|/|[-_])(?:2fa|two[-_]?factor|mfa|totp|otp|authenticator)(?:/|$|[-_.])",
                       re.I)
_MFA_OFF_PATH = re.compile(r"disable|deactivate|remove|turn[-_]?off|(?:^|/)off(?:/|$)", re.I)
_MFA_ON_PATH = re.compile(r"setup|set[-_]?up|enable|activate|turn[-_]?on|verify|(?:^|/)on(?:/|$)", re.I)
_STEP_UP = re.compile(r"^(?:password|currentpassword|oldpassword|passwd|pwd|pass|passphrase|totp|otp|"
                      r"code|token|totptoken|otptoken|totpcode|otpcode|verificationcode|mfacode|"
                      r"2facode|twofactorcode|pin|secret)$")
_MFA_STATUS = re.compile(r"^(?:setup|enabled|active|status|isenabled|configured|twofactorenabled|"
                         r"mfaenabled|totpenabled|otpenabled|twofactor|mfa|totp)$")
_TOTAL_ORDER = ("grandtotal", "ordertotal", "totalprice", "totalamount", "total", "amountdue", "due",
                "amount", "price", "cost", "subtotal", "balance")
_ID_KEYS = frozenset({"id", "uuid", "guid", "orderid", "ordernumber", "number", "reference"})
_MAX_PREREQS = 3
_MAX_READS = 4
_MAX_AMOUNT_VARIANTS = 2
_MAX_CAPTURED = 600


# -- body and capture helpers ------------------------------------------------------

def _parse(body: str):
    """(fields, kind) for a JSON object or urlencoded body; kind 'json' | 'form' | ''."""
    text = (body or "").strip()
    if text.startswith("{"):
        doc = _json(text)
        if isinstance(doc, dict):
            return doc, "json"
        return {}, ""
    if text and "=" in text:
        return dict(parse_qsl(text, keep_blank_values=True)), "form"
    return {}, ""


def _encode(fields: dict, kind: str) -> str:
    return json.dumps(fields) if kind == "json" else urlencode(fields)


def _leaves(obj, prefix=(), depth=0):
    """(path tuple, value) of every non-container leaf in nested dicts (depth <= 3)."""
    if isinstance(obj, dict) and depth <= 3:
        for k, v in obj.items():
            if isinstance(v, dict):
                yield from _leaves(v, prefix + (k,), depth + 1)
            elif not isinstance(v, list):
                yield prefix + (k,), v


def _with(fields: dict, path: tuple, value, *, drop: bool = False) -> dict:
    out = json.loads(json.dumps(fields))
    target = out
    for p in path[:-1]:
        target = target[p]
    if drop:
        target.pop(path[-1], None)
    else:
        target[path[-1]] = value
    return out


def _number(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, str) and re.fullmatch(r"-?\d{1,9}(?:\.\d{1,4})?", value.strip()):
        return float(value) if "." in value else int(value)
    return None


def _like(original, number):
    return str(number) if isinstance(original, str) else number


def _get(item, key):
    return item.get(key) if isinstance(item, dict) else getattr(item, key, None)


def _origin(url: str) -> str:
    p = urlsplit(url or "")
    return f"{p.scheme}://{p.netloc}".lower()


def _path(url: str) -> str:
    return (urlsplit(url or "").path or "/").rstrip("/") or "/"


def _norm(path: str) -> str:
    """A path with id-like segments folded, so a captured URL matches a template."""
    segs = [("{id}" if re.fullmatch(r"\d+|[0-9a-fA-F-]{8,}", s) else s.lower())
            for s in (path or "/").split("/") if s]
    return "/" + "/".join(segs)


def _ok(outcome) -> bool:
    return outcome is not None and getattr(outcome, "ok", False) and \
        outcome.status is not None and 200 <= outcome.status < 300


def _refused(outcome) -> bool:
    return outcome is not None and getattr(outcome, "ok", False) and \
        outcome.status is not None and 400 <= outcome.status < 500


def _doc(outcome):
    return _json(outcome.body) if _ok(outcome) else None


def _top(doc):
    if isinstance(doc, dict) and "data" in doc and len(doc) <= 4:
        return doc["data"]
    return doc


# -- shapes ----------------------------------------------------------------------------

@dataclass
class _Tamper:
    """One tampered value in one step of the flow."""
    step: int            # -1 = the settlement itself; else the prerequisite's index
    path: tuple
    family: str          # amount | quantity | delivery | payment | coupon
    original: object
    value: object = None
    drop: bool = False

    def describe(self) -> str:
        where = "settlement" if self.step < 0 else f"cart step {self.step + 1}"
        key = ".".join(str(p) for p in self.path)
        return f"{where} {key}: dropped" if self.drop else \
            f"{where} {key}={self.original!r} -> {self.value!r}"


def _amount_tampers(fields: dict, step: int) -> list[_Tamper]:
    out = []
    for path, value in _leaves(fields):
        flat = _flat(path[-1])
        n = _number(value)
        if n is not None and _MONEY_KEYS.match(flat) and n > 0:
            low = 0.01 if isinstance(n, float) else 1
            if n > low:
                out.append(_Tamper(step, path, "amount", value, _like(value, low)))
        elif n is not None and _QUANTITY.match(flat) and n > 0:
            out.append(_Tamper(step, path, "quantity", value, _like(value, -1)))
        elif _DELIVERY.match(flat) and value not in (None, ""):
            fake = _like(value, 987654321) if n is not None else "x" + secrets.token_hex(4)
            out.append(_Tamper(step, path, "delivery", value, fake))
    order = {"amount": 0, "quantity": 1, "delivery": 2}
    return sorted(out, key=lambda t: order[t.family])


def _payment_fields(fields: dict) -> list[tuple]:
    return [(path, value) for path, value in _leaves(fields)
            if _PAYMENT.match(_flat(path[-1])) or _PAYMENT.match("".join(_flat(p) for p in path))]


def coupon_location(method: str, url: str, body: str):
    """("body", path, code) | ("path", segment index, code) | None."""
    fields, _kind = _parse(body or "")
    for path, value in _leaves(fields):
        if _COUPON_FIELD.match(_flat(path[-1])) and isinstance(value, (str, int)) \
                and not isinstance(value, bool):
            return ("body", path, str(value))
    segs = [s for s in (urlsplit(url or "").path or "").split("/")]
    for i, s in enumerate(segs[:-1]):
        if _COUPON_PATH.search("/" + s + "/") and segs[i + 1]:
            return ("path", i + 1, segs[i + 1])
    return None


def flow_kind(method: str, url: str, body: str) -> str | None:
    """The business-flow kind a captured write has the shape of, or None. Pure."""
    method = (method or "").upper()
    if method not in _WRITE_METHODS:
        return None
    path = urlsplit(url or "").path or "/"
    fields, _kind = _parse(body or "")
    if _MFA_PATH.search(path) and (_MFA_OFF_PATH.search(path) or any(
            v is False or str(v).lower() == "false" for p, v in _leaves(fields)
            if _MFA_STATUS.match(_flat(p[-1])))):
        if any(_STEP_UP.match(_flat(p[-1])) for p, _ in _leaves(fields)):
            return MFA_DISABLE
        return None
    if _AUTH_PATH.search(path):
        return None
    if coupon_location(method, url, body) is not None:
        return COUPON_MISUSE
    if _SETTLE_PATH.search(path) and (_amount_tampers(fields, -1) or _payment_fields(fields)
                                      or _kind == "json"):
        return PAYMENT_TAMPER
    return None


def endpoint_flow_kind(endpoint: dict) -> str | None:
    """flow_kind of a coverage endpoint (its methods, path and captured template)."""
    template = endpoint.get("template") or {}
    methods = [m for m in (endpoint.get("methods") or ()) if m in _WRITE_METHODS]
    method = (template.get("method") or (methods[0] if methods else "")).upper()
    if method not in _WRITE_METHODS:
        return None
    return flow_kind(method, "http://x" + (endpoint.get("path") or "/"), template.get("body") or "")


def kind_for(vulnerability_class: str, exchange: HttpExchange) -> str | None:
    """The kind this leg runs for a finding class on a capture, or None."""
    cls = (vulnerability_class or "").strip().lower()
    shape = flow_kind(exchange.method, exchange.url, exchange.request_body or "")
    for kind, tokens in _CLASS_TOKENS.items():
        if cls in tokens:
            return kind if shape == kind else None
    if cls in _GENERIC_CLASSES:
        # client_trust owns a plain cart tamper; this leg takes the multi-step shapes.
        return shape
    return None


def _claimed_kind(vulnerability_class: str) -> str | None:
    cls = (vulnerability_class or "").strip().lower()
    for kind, tokens in _CLASS_TOKENS.items():
        if cls in tokens:
            return kind
    return None


# -- read-back state ---------------------------------------------------------------------

def _sig(rec: dict) -> str:
    for k, v in rec.items():
        if _flat(k) in _ID_KEYS and isinstance(v, (int, str)) and not isinstance(v, bool) and str(v):
            return f"{_flat(k)}={v}"
    return json.dumps(rec, sort_keys=True, default=str)


def _record_amount(rec: dict):
    best = None
    for path, v in _flatten(rec):
        leaf = _flat(path.rsplit(".", 1)[-1])
        if leaf in _TOTAL_ORDER and isinstance(v, (int, float)) and not isinstance(v, bool):
            rank = (_TOTAL_ORDER.index(leaf), path.count("."))
            if best is None or rank < best[0]:
                best = (rank, v, path)
    return (best[1], best[2]) if best else None


@dataclass
class _ReadState:
    records: dict = dc_field(default_factory=dict)
    scalars: dict = dc_field(default_factory=dict)
    standing: dict = dc_field(default_factory=dict)
    discounts: dict = dc_field(default_factory=dict)
    codes: dict = dc_field(default_factory=dict)
    mfa: object = None


def _read_state(doc) -> _ReadState | None:
    if doc is None:
        return None
    top = _top(doc)
    state = _ReadState()
    lists = [top] if isinstance(top, list) else (
        [v for v in top.values() if isinstance(v, list)] if isinstance(top, dict) else [])
    for lst in lists:
        for rec in lst:
            if isinstance(rec, dict):
                state.records[_sig(rec)] = rec
    if isinstance(top, (int, float)) and not isinstance(top, bool):
        state.scalars["data"] = top
    elif isinstance(top, dict):
        state.scalars = dict(_money(top))
        state.standing = _authority_state(top)
        state.discounts = dict(_discounts(top))
        state.codes = {p: v for p, v in _flatten(top)
                       if _COUPON_FIELD.match(_flat(p.rsplit(".", 1)[-1])) and v not in (None, "")}
        state.mfa = _mfa_flag(top)
    return state


def _mfa_flag(obj):
    for path, v in _flatten(obj if isinstance(obj, dict) else {}):
        if not _MFA_STATUS.match(_flat(path.rsplit(".", 1)[-1])):
            continue
        if isinstance(v, bool):
            return v
        if isinstance(v, str) and v.strip().lower() in ("enabled", "on", "active", "true"):
            return True
        if isinstance(v, str) and v.strip().lower() in ("disabled", "off", "inactive", "false"):
            return False
    return None


@dataclass
class _Effect:
    """What one flow changed in the read-backs."""
    new: list = dc_field(default_factory=list)       # (read url, amount, field path)
    deltas: dict = dc_field(default_factory=dict)    # "url field" -> after - before
    elevated: list = dc_field(default_factory=list)
    unread: list = dc_field(default_factory=list)

    @property
    def traced(self) -> bool:
        return bool(self.new or self.deltas or self.elevated)

    def amounts(self) -> dict:
        out = {}
        for url, amount, path in self.new:
            out.setdefault((url, path), []).append(amount)
        return {k: min(v) for k, v in out.items()}


def _effect(before: dict, after: dict) -> _Effect:
    eff = _Effect()
    for url, b in before.items():
        a = after.get(url)
        if b is None or a is None:
            eff.unread.append(url)
            continue
        for key, rec in a.records.items():
            if key not in b.records:
                got = _record_amount(rec)
                if got is not None:
                    eff.new.append((url, got[0], got[1]))
                else:
                    eff.new.append((url, None, ""))
        for path, v in a.scalars.items():
            if path in b.scalars and v != b.scalars[path]:
                eff.deltas[f"{url} {path}"] = v - b.scalars[path]
        eff.elevated += [f"{_path(url)} {e}" for e in _elevations(b.standing, a.standing)]
    return eff


# -- the leg ------------------------------------------------------------------------------

@dataclass
class _Case:
    finding: Finding
    exchange: HttpExchange
    kind: str
    case_ref: str
    actor: object                     # the run's ManagedSession
    headers: dict
    fields: dict
    body_kind: str
    prereqs: list = dc_field(default_factory=list)   # (method, url, headers, fields, kind)
    reads: list = dc_field(default_factory=list)     # read-back urls
    sent: list = dc_field(default_factory=list)      # every write outcome, for the change log
    left: list = dc_field(default_factory=list)      # residue the leg could not restore
    notes: list = dc_field(default_factory=list)


class BusinessFlowValidator(Validator):
    name = "business_flow"
    finding_classes = FINDING_CLASSES
    active = True
    mechanism_version = "1"

    def __init__(self, *, allowed_hosts: list[str] | None = None, run_context=None,
                 allow_writes: bool = False, read_backs=(), coupons: dict | None = None,
                 mfa_status_reads=()):
        self.allowed_hosts = list(allowed_hosts or [])
        self.run_context = run_context
        # validators.allow_mutating_replay frozen at construction (as write_integrity's).
        self.allow_writes = bool(allow_writes)
        self.read_backs = tuple(read_backs or ())
        self.coupons = dict(coupons or {})
        self.mfa_status_reads = tuple(mfa_status_reads or ())

    # -- dispatch ----------------------------------------------------------------------

    def applies(self, finding: Finding, exchange: HttpExchange) -> bool:
        return self.allow_writes and kind_for(finding.vulnerability_class, exchange) is not None

    def claims_class(self, finding: Finding, exchange: HttpExchange | None = None) -> bool:
        cls = (finding.vulnerability_class or "").strip().lower()
        return cls in FINDING_CLASSES

    def _result(self, status: str, case_or_fc, summary: str, **kw) -> ValidationResult:
        if isinstance(case_or_fc, _Case):
            fc, kind = case_or_fc.finding.vulnerability_class, case_or_fc.kind
        else:
            fc, kind = case_or_fc, _claimed_kind(case_or_fc) or ""
        res = ValidationResult(self.name, status, fc, summary=summary,
                               confirmed=status == "confirmed", **kw)
        if kind:
            res.mechanism_classes = (kind,)
        if status not in ("confirmed", "not_confirmed"):
            res.limitation = summary[:400]
        return res

    def _skip(self, fc: str, why: str) -> ValidationResult:
        return self._result("skipped", fc, f"business_flow: {why}; nothing was sent")

    def _refusal(self, finding: Finding, exchange: HttpExchange):
        """(kind, actor) or a skip result. Sends nothing."""
        fc = finding.vulnerability_class
        run = self.run_context
        kind = kind_for(fc, exchange)
        if kind is None:
            return self._skip(fc, "the capture has no checkout, coupon or 2FA-disable shape "
                                  "for this finding class")
        if run is None:
            return self._skip(fc, "it needs the run's transport and registered sessions")
        gate = run.gate.config
        if not self.allow_writes or not gate.active_enabled or not gate.allow_mutating_replay:
            return self._skip(fc, "it runs only with validators.active_enabled and "
                                  "validators.allow_mutating_replay on")
        if self.name not in (gate.mutating_ceiling_by_check or {}):
            return self._skip(fc, "it needs an explicit validators.mutating_ceiling_by_check."
                                  "business_flow entry (each flow is several writes)")
        if not run.scope.in_scope(exchange.url):
            return self._skip(fc, "the target is out of scope")
        if self.allowed_hosts:
            from harness import scope_lock
            if not scope_lock.host_in_scope(exchange.url, self.allowed_hosts):
                return self._skip(fc, "the host is outside server.allowed_hosts")
        signature = _auth_signature(exchange.request_headers)
        actor = next((s for s in run.sessions.identities()
                      if s.principal_id != "anonymous" and s.health != "expired"
                      and _auth_signature(s.headers) == signature), None) if signature else None
        if actor is None:
            return self._skip(fc, "the capture's credentials belong to no identity the run "
                                  "registered, so the flow would not act on a run-owned account")
        return kind, actor

    async def validate(self, finding: Finding, exchange: HttpExchange) -> ValidationResult:
        got = self._refusal(finding, exchange)
        if isinstance(got, ValidationResult):
            return got
        kind, actor = got
        from harness.security import is_identity_credential_header
        headers = {k: v for k, v in (exchange.request_headers or {}).items()
                   if not is_identity_credential_header(k)
                   and k.lower() not in {"host", "content-length", "if-match", "if-none-match"}}
        fields, body_kind = _parse(exchange.request_body or "")
        case_ref = finding.finding_id or finding.case_id or "business-flow-" + secrets.token_hex(8)
        case = _Case(finding, exchange, kind, case_ref, actor, headers, fields, body_kind)
        # One flow at a time per run-owned account: two flows on one basket or one
        # 2FA setting would read each other's effects.
        async with _object_lock(_origin(exchange.url) + "/__business_flow__/" + actor.session_id):
            try:
                if kind == MFA_DISABLE:
                    return await self._mfa(case)
                if kind == COUPON_MISUSE:
                    return await self._coupon(case)
                return await self._settlement(case)
            finally:
                self._record_residue(case)

    # -- sending ------------------------------------------------------------------------

    async def _send(self, case: _Case, method: str, url: str, body: str | None = None,
                    headers: dict | None = None, *, cleanup: bool = False):
        from harness.run_context import TypedRequest
        method = (method or "GET").upper()
        if method == "DELETE":
            raise ValueError("business_flow never sends DELETE (owner policy)")
        hdrs = dict(case.headers if headers is None else headers)
        if method == "GET":
            hdrs = {k: v for k, v in hdrs.items() if k.lower() != "content-type"}
        outcome = await self.run_context.executor().execute(
            TypedRequest(method, url, headers=hdrs, body=body),
            capability=self.name, session_ref=case.actor.session_id, case_ref=case.case_ref,
            allow_cancelled_cleanup=cleanup)
        if method != "GET" and getattr(outcome, "executed", False):
            case.sent.append(outcome)
        return outcome

    def _headroom(self, case: _Case) -> int:
        remaining, _used, _ceiling = self.run_context.gate.mutating_headroom(case.case_ref, self.name)
        return remaining

    def _record_residue(self, case: _Case) -> None:
        """Name every write the leg could not undo in the run's change log."""
        if not case.left:
            return
        from harness import run_handoff
        ids = [getattr(o, "artifact_id", "") for o in case.sent]
        try:
            run_handoff.mark_restore(self.run_context, ids, ok=False,
                                     detail="business_flow LEFT IN PLACE: " + " | ".join(case.left))
        except Exception:
            log.debug("business_flow: mark_restore failed", exc_info=True)

    def _restored(self, outcomes, detail: str) -> None:
        from harness import run_handoff
        try:
            run_handoff.mark_restore(self.run_context, [getattr(o, "artifact_id", "") for o in outcomes],
                                     ok=True, detail=detail)
        except Exception:
            log.debug("business_flow: mark_restore failed", exc_info=True)

    # -- the run's captured flow ----------------------------------------------------------

    def _captured(self) -> list:
        context = getattr(self.run_context, "experiment_context", None)
        return list(((context.get("captured") if isinstance(context, dict) else None) or ()))[:_MAX_CAPTURED]

    def _mine(self, case: _Case, item) -> bool:
        return (_origin(str(_get(item, "url") or "")) == _origin(case.exchange.url)
                and _auth_signature(_get(item, "request_headers") or {})
                == _auth_signature(case.actor.headers))

    def _plan_reads(self, case: _Case, want) -> list[str]:
        """Read-back URLs: declared ones first, then the actor's captured 2xx JSON GETs
        whose answer `want` accepts, those sharing most of the write's path first."""
        origin = _origin(case.exchange.url)
        out = []
        for entry in self.read_backs:
            bits = str(entry).split(None, 1)
            path = bits[-1].strip()
            if len(bits) == 2 and bits[0].upper() != "GET":
                continue
            out.append(path if path.lower().startswith("http") else origin + path)
        here = [s for s in _path(case.exchange.url).lower().split("/") if s]
        found = []
        for item in self._captured():
            url = str(_get(item, "url") or "")
            status = _get(item, "response_status")
            if (str(_get(item, "method") or "GET").upper() != "GET" or not self._mine(case, item)
                    or status is None or not 200 <= int(status) < 300):
                continue
            doc = _json(_get(item, "response_body"))
            if doc is None or not want(url, doc):
                continue
            segs = [s for s in _path(url).lower().split("/") if s]
            shared = next((i for i, (a, b) in enumerate(zip(segs, here)) if a != b), min(len(segs), len(here)))
            found.append((-shared, len(found), url))
        out += [u for _, _, u in sorted(found)]
        return list(dict.fromkeys(u for u in out if _origin(u) == origin))[:_MAX_READS]

    def _plan_prereqs(self, case: _Case) -> list:
        """The actor's captured cart writes made before the settlement capture (the
        steps that fill the basket the settlement consumes), at most three."""
        target = (case.exchange.method.upper(), _norm(_path(case.exchange.url)))
        captured = self._captured()
        upto = next((i for i, item in enumerate(captured)
                     if (str(_get(item, "method") or "").upper(), _norm(_path(str(_get(item, "url") or ""))))
                     == target), len(captured))
        steps = []
        for item in captured[:upto]:
            method = str(_get(item, "method") or "").upper()
            url = str(_get(item, "url") or "")
            path = _path(url)
            status = _get(item, "response_status")
            if (method not in _WRITE_METHODS or not self._mine(case, item) or not _CART_PATH.search(path)
                    or _SETTLE_PATH.search(path) or _AUTH_PATH.search(path) or _COUPON_PATH.search(path)
                    or status is None or not 200 <= int(status) < 300):
                continue
            fields, kind = _parse(_get(item, "request_body") or "")
            if not kind:
                continue
            from harness.security import is_identity_credential_header
            hdrs = {k: v for k, v in (_get(item, "request_headers") or {}).items()
                    if not is_identity_credential_header(k) and k.lower() not in {"host", "content-length"}}
            steps.append((method, url, hdrs, fields, kind))
        return steps[-_MAX_PREREQS:]

    async def _snapshot(self, case: _Case, reads) -> dict:
        out = {}
        for url in reads:
            outcome = await self._send(case, "GET", url)
            out[url] = _read_state(_doc(outcome))
        return out

    # -- 1. checkout / payment tamper ---------------------------------------------------------

    async def _flow(self, case: _Case, tamper: _Tamper | None, settle_fields=None):
        """Replay the prerequisites and the settlement (one tamper applied). Returns
        (settlement outcome or None, refused step label or "")."""
        for i, (method, url, hdrs, fields, kind) in enumerate(case.prereqs):
            body = fields
            if tamper is not None and tamper.step == i:
                body = _with(fields, tamper.path, tamper.value, drop=tamper.drop)
            outcome = await self._send(case, method, url, _encode(body, kind), hdrs)
            if tamper is not None and tamper.step == i and not _ok(outcome):
                return None, f"the tampered cart step answered HTTP {getattr(outcome, 'status', None)}"
            if not getattr(outcome, "executed", False):
                return None, f"a cart step was not sent ({outcome.outcome})"
        body = settle_fields if settle_fields is not None else case.fields
        if tamper is not None and tamper.step < 0:
            body = _with(body, tamper.path, tamper.value, drop=tamper.drop)
        outcome = await self._send(case, case.exchange.method, case.exchange.url,
                                   _encode(body, case.body_kind) if case.body_kind else
                                   (case.exchange.request_body or None))
        return outcome, ""

    def _wants_money(self, url, doc) -> bool:
        state = _read_state(doc)
        return bool(state and (state.scalars or state.standing or any(
            _record_amount(r) for r in state.records.values())))

    async def _settlement(self, case: _Case) -> ValidationResult:
        case.prereqs = self._plan_prereqs(case)
        case.reads = self._plan_reads(case, self._wants_money)
        if not case.reads:
            return self._skip(case.finding.vulnerability_class,
                              "no read-back of the settled state (an order history, a balance) was "
                              "captured for this identity or declared in validators.business_flow."
                              "read_backs, so a settlement could not be judged")
        tampers = list(_amount_tampers(case.fields, -1))
        for i, (_m, _u, _h, fields, _k) in enumerate(case.prereqs):
            tampers += [t for t in _amount_tampers(fields, i) if t.family in ("amount", "quantity")]
        # Amounts first, wherever they sit; a delivery tamper is tried last because a
        # refused settlement can leave the cart steps' items behind (see _amount_flows).
        rank = {"amount": 0, "quantity": 1, "delivery": 2}
        tampers = sorted(tampers, key=lambda t: rank[t.family])[:_MAX_AMOUNT_VARIANTS]
        flow_writes = len(case.prereqs) + 1
        if tampers:
            return await self._amount_flows(case, tampers, flow_writes)
        payments = _payment_fields(case.fields)
        if not payments:
            return self._skip(case.finding.vulnerability_class,
                              "the settlement carries no amount, quantity, delivery or payment field "
                              "to tamper")
        return await self._payment_skip(case, payments, flow_writes)

    def _left_orders(self, case: _Case, label: str, eff: _Effect | None) -> None:
        new = [f"{_path(u)} (+1 entry{'' if a is None else f', {p}={a}'})" for u, a, p in (eff.new if eff else [])]
        moved = [f"{k.split(' ', 1)[0] and _path(k.split(' ', 1)[0])} {k.split(' ', 1)[1]} {v:+}"
                 for k, v in (eff.deltas.items() if eff else [])]
        what = "; ".join(new + moved + list(eff.elevated if eff else [])) or "no read-back showed its trace"
        case.left.append(f"{label} settlement {case.exchange.method.upper()} "
                         f"{_path(case.exchange.url)} placed by the run-owned identity "
                         f"{case.actor.name or case.actor.principal_id} ({what}); no DELETE is "
                         f"sent (owner policy), so it stays")

    async def _amount_flows(self, case: _Case, tampers: list[_Tamper], flow_writes: int):
        if self._headroom(case) < 2 * flow_writes:
            return self._skip(case.finding.vulnerability_class,
                              f"the business_flow ceiling does not pay for an untampered control flow "
                              f"and one tampered flow ({2 * flow_writes} writes)")
        before = await self._snapshot(case, case.reads)
        if all(v is None for v in before.values()):
            return self._result("inconclusive", case, "business_flow incomplete: no read-back answered "
                                                      "before the flow; nothing was written")
        control, why = await self._flow(case, None)
        mid = await self._snapshot(case, case.reads)
        ctl_eff = _effect(before, mid)
        if control is not None and _ok(control):
            self._left_orders(case, "the untampered control", ctl_eff)
        if control is None or not _ok(control):
            return self._result("inconclusive", case,
                                f"business_flow not decided: the untampered control flow did not settle "
                                f"({why or 'HTTP ' + str(getattr(control, 'status', None))}), so a refused "
                                f"tamper would prove nothing" + self._residue_text(case))
        if not ctl_eff.traced or not (ctl_eff.amounts() or ctl_eff.deltas):
            return self._result("inconclusive", case,
                                "business_flow not decided: the untampered control settled (HTTP "
                                f"{control.status}) but no read-back showed what it settled, so a "
                                "tamper could not be compared" + self._residue_text(case))
        tried, hit, prev = [], None, mid
        for tamper in tampers:
            if self._headroom(case) < flow_writes:
                case.notes.append(f"{tamper.describe()} not sent: the ceiling is spent")
                break
            outcome, why = await self._flow(case, tamper)
            after = await self._snapshot(case, case.reads)
            eff = _effect(prev, after)
            prev = after
            if outcome is not None and _ok(outcome):
                self._left_orders(case, f"the tampered ({tamper.describe()})", eff)
            verdict = self._compare(ctl_eff, eff)
            tried.append((tamper, outcome, why, eff, verdict))
            if verdict[0] == "strong" and outcome is not None and _ok(outcome):
                hit = tried[-1]
                break
            if outcome is not None and not _ok(outcome) and case.prereqs:
                # The cart steps went in but the settlement did not consume them, so a
                # further flow would settle a fuller basket than the control's.
                case.notes.append("later variants not sent: a refused settlement may have left "
                                  "this flow's cart items in place")
                break
        return self._amount_verdict(case, control, ctl_eff, tried, hit)

    @staticmethod
    def _compare(ctl: _Effect, eff: _Effect):
        """("strong", why) when the tampered flow settled for less than the control."""
        c_amounts, v_amounts = ctl.amounts(), eff.amounts()
        for key, v in v_amounts.items():
            if v is None:
                continue
            c = c_amounts.get(key)
            if v < 0:
                return "strong", f"{_path(key[0])} shows a new entry with {key[1]}={v} (negative)"
            if c is not None and v < c:
                return "strong", (f"{_path(key[0])} shows a new entry with {key[1]}={v}, the untampered "
                                  f"control's was {c}")
        for key, v in eff.deltas.items():
            c = ctl.deltas.get(key)
            url, path = key.split(" ", 1)
            if c is not None and c < 0 and v > c:
                return "strong", (f"{_path(url)} {path} moved by {v:+} where the control's moved by "
                                  f"{c:+} (less was charged)")
            if (c is None or c == 0) and v > 0:
                return "strong", f"{_path(url)} {path} rose by {v:+} (the settlement credited the account)"
        if not eff.traced:
            return "untraced", ""
        return "same", ""

    def _residue_text(self, case: _Case) -> str:
        return (" LEFT IN PLACE: " + " | ".join(case.left) + ".") if case.left else ""

    def _amount_verdict(self, case, control, ctl_eff, tried, hit) -> ValidationResult:
        sent = [f"control -> HTTP {control.status}"] + [
            f"{t.describe()} -> " + (f"HTTP {o.status}" if o is not None and o.status is not None
                                     else why or "not sent") for t, o, why, _e, _v in tried]
        evidence = (f"{case.exchange.method.upper()} {_path(case.exchange.url)} after "
                    f"{len(case.prereqs)} captured cart step(s); read back from "
                    f"{', '.join(_path(u) for u in case.reads)}: " + "; ".join(sent) + "."
                    + (" " + "; ".join(case.notes) if case.notes else ""))
        reads = [o for o in case.sent]
        art = dict(baseline=control, controls=[o for o in reads if o is not control][:3])
        if hit is not None:
            tamper, outcome, _why, _eff, (_s, how) = hit
            return self._result(
                "confirmed", case,
                f"Checkout tamper confirmed: the settlement accepted a client-chosen value "
                f"({tamper.describe()}, HTTP {outcome.status}) and the read-back shows it took effect: "
                f"{how}." + self._residue_text(case), confidence=0.9,
                evidence=evidence).with_artifacts(attack=outcome, **art)
        if not tried:
            return self._result("inconclusive", case, "business_flow incomplete: no tampered flow was "
                                                      "sent" + self._residue_text(case), evidence=evidence)
        accepted = [x for x in tried if x[1] is not None and _ok(x[1])]
        if accepted and all(x[4][0] == "untraced" for x in accepted):
            return self._result("inconclusive", case,
                                "business_flow not decided: a tampered settlement was accepted but no "
                                "read-back showed what it settled" + self._residue_text(case),
                                evidence=evidence).with_artifacts(attack=accepted[0][1], **art)
        held = ("every tampered step or settlement was refused" if not accepted else
                "the tampered flows settled for the same amount as the control (the server "
                "re-derives its own price)")
        return self._result("not_confirmed", case,
                            f"The settlement enforces its own amounts: {held}." + self._residue_text(case),
                            evidence=evidence).with_artifacts(
            attack=(accepted or tried)[0][1], **art)

    async def _payment_skip(self, case: _Case, payments, flow_writes: int) -> ValidationResult:
        """A settlement with its payment field dropped, then forged: confirmed when the
        read-back grants a standing (or an entry) with no debit."""
        path, original = payments[0]
        tampers = [_Tamper(-1, path, "payment", original, drop=True)]
        n = _number(original)
        tampers.append(_Tamper(-1, path, "payment", original,
                               _like(original, 987654321) if n is not None else "x" + secrets.token_hex(4)))
        if self._headroom(case) < flow_writes:
            return self._skip(case.finding.vulnerability_class,
                              f"the business_flow ceiling does not pay for one flow ({flow_writes} writes)")
        prev = await self._snapshot(case, case.reads)
        if all(v is None for v in prev.values()):
            return self._result("inconclusive", case, "business_flow incomplete: no read-back answered "
                                                      "before the flow; nothing was written")
        tried, hit, lead = [], None, None
        for tamper in tampers:
            if self._headroom(case) < flow_writes:
                case.notes.append(f"{tamper.describe()} not sent: the ceiling is spent")
                break
            outcome, why = await self._flow(case, tamper)
            after = await self._snapshot(case, case.reads)
            eff = _effect(prev, after)
            prev = after
            tried.append((tamper, outcome, why, eff))
            if outcome is None or not _ok(outcome):
                continue
            self._left_orders(case, f"the unpaid ({tamper.describe()})", eff)
            charged = [k for k, v in eff.deltas.items() if v < 0]
            if eff.elevated and not charged:
                hit = tried[-1]
                case.left.append(f"the standing it granted ({'; '.join(eff.elevated[:2])}) is not undone")
                break
            if eff.new and not charged and lead is None:
                lead = tried[-1]
        sent = "; ".join(f"{t.describe()} -> " + (f"HTTP {o.status}" if o is not None and o.status is not None
                                                  else why or "not sent") for t, o, why, _e in tried)
        evidence = (f"{case.exchange.method.upper()} {_path(case.exchange.url)}; read back from "
                    f"{', '.join(_path(u) for u in case.reads)}: {sent}.")
        if hit is not None:
            tamper, outcome, _why, eff = hit
            return self._result(
                "confirmed", case,
                f"Payment skip confirmed: the settlement with {tamper.describe()} was accepted (HTTP "
                f"{outcome.status}) and the read-back shows a granted standing "
                f"({'; '.join(eff.elevated[:2])}) with no debit on any balance read."
                + self._residue_text(case), confidence=0.85,
                evidence=evidence).with_artifacts(attack=outcome, controls=case.sent[:3])
        if lead is not None:
            tamper, outcome, _why, eff = lead
            return self._result(
                "supported", case,
                f"LEAD: the settlement with {tamper.describe()} was accepted (HTTP {outcome.status}) and "
                f"added an entry with no debit on a balance read; the server may have charged a saved "
                f"instrument, so this is not confirmed." + self._residue_text(case),
                confidence=0.4, evidence=evidence).with_artifacts(attack=outcome)
        if tried and all(o is not None and _refused(o) for _t, o, _w, _e in tried):
            return self._result("not_confirmed", case, "The settlement requires its payment: every "
                                                       "dropped or forged payment was refused.",
                                evidence=evidence).with_artifacts(attack=tried[0][1])
        return self._result("inconclusive", case,
                            "business_flow not decided: no unpaid settlement both settled and showed a "
                            "standing or entry on a read-back" + self._residue_text(case),
                            evidence=evidence)

    # -- 2. coupon / voucher misuse -----------------------------------------------------------

    def _codes(self, case: _Case, original: str) -> list[tuple[str, str, bool]]:
        """(label, code, may confirm) to try: a forged code of the captured code's
        shape, then an expired code and another identity's code when the run knows one."""
        alphabet = (string.digits if original.isdigit() else
                    string.ascii_uppercase + string.digits if original.isupper() or not original else
                    string.ascii_letters + string.digits)
        length = min(max(len(original), 8), 40)
        forged = "".join(secrets.choice(alphabet) for _ in range(length))
        out = [("a forged code", forged, True)]
        declared = self.coupons or {}
        expired = [str(c) for c in (declared.get("expired") or ())]
        others = {}
        for name, code in (declared.get("by_identity") or {}).items():
            if str(name) not in (case.actor.name, case.actor.principal_id, case.actor.session_id):
                others[str(code)] = True
        sigs = {_auth_signature(s.headers): s for s in self.run_context.sessions.identities()
                if s.principal_id != "anonymous"}
        mine = _auth_signature(case.actor.headers)
        for item in self._captured():
            loc = coupon_location(str(_get(item, "method") or ""), str(_get(item, "url") or ""),
                                  _get(item, "request_body") or "")
            if loc is None or _origin(str(_get(item, "url") or "")) != _origin(case.exchange.url):
                continue
            status = _get(item, "response_status")
            code, sig = loc[2], _auth_signature(_get(item, "request_headers") or {})
            if status is not None and 400 <= int(status) < 500 and \
                    re.search(r"expir", str(_get(item, "response_body") or ""), re.I):
                expired.append(code)
            elif status is not None and 200 <= int(status) < 300 and sig and sig != mine and sig in sigs:
                others.setdefault(code, False)
        for code in list(dict.fromkeys(expired))[:1]:
            if code != original:
                out.append(("an expired code", code, True))
        for code, declared_own in list(others.items())[:1]:
            if code != original:
                out.append(("another identity's code", code, declared_own))
        return out

    def _wants_coupon_state(self, url, doc) -> bool:
        state = _read_state(doc)
        return bool(state and (state.codes or state.discounts or state.scalars
                               or _CART_PATH.search(_path(url))))

    def _apply(self, case: _Case, loc, code):
        """(method, url, body) of the coupon write carrying `code`."""
        method, url = case.exchange.method.upper(), case.exchange.url
        if loc[0] == "path":
            p = urlsplit(url)
            segs = p.path.split("/")
            segs[loc[1]] = quote(str(code), safe="")
            return method, urlunsplit((p.scheme, p.netloc, "/".join(segs), p.query, "")), \
                case.exchange.request_body or None
        return method, url, _encode(_with(case.fields, loc[1], code), case.body_kind)

    async def _coupon(self, case: _Case) -> ValidationResult:
        loc = coupon_location(case.exchange.method, case.exchange.url, case.exchange.request_body or "")
        if _SETTLE_PATH.search(_path(case.exchange.url)) and loc[0] == "body":
            return await self._coupon_at_settlement(case, loc)
        case.reads = self._plan_reads(case, self._wants_coupon_state)
        if not case.reads:
            return self._skip(case.finding.vulnerability_class,
                              "no read-back of the basket or order the coupon applies to was captured "
                              "for this identity or declared, so a discount could not be read back")
        codes = self._codes(case, loc[2])
        per = 2 if loc[0] == "body" else 1
        if self._headroom(case) < per:
            return self._skip(case.finding.vulnerability_class,
                              f"the business_flow ceiling does not pay for one coupon write and its "
                              f"removal ({per} writes)")
        tried, hit, lead = [], None, None
        for label, code, may_confirm in codes:
            if self._headroom(case) < per:
                case.notes.append(f"{label} not sent: the ceiling is spent")
                break
            base = await self._snapshot(case, case.reads)
            if all(v is None for v in base.values()):
                return self._result("inconclusive", case, "business_flow incomplete: no read-back "
                                                          "answered; nothing more was written")
            method, url, body = self._apply(case, loc, code)
            outcome = await self._send(case, method, url, body)
            after = await self._snapshot(case, case.reads)
            how, weak = self._discount_shown(base, after, code, _doc(outcome))
            tried.append((label, outcome, how or weak))
            if _ok(outcome):
                await self._clear_coupon(case, loc, base, code, label)
            if how and _ok(outcome):
                if may_confirm:
                    hit = (label, outcome, how)
                    break
                lead = lead or (label, outcome, how + " (the code was seen used by another identity "
                                                      "in this run; whether codes are per-account is not "
                                                      "known, so this is a lead)")
            elif weak and _ok(outcome):
                lead = lead or (label, outcome, weak)
        sent = "; ".join(f"{label} -> " + (f"HTTP {o.status}" if o is not None and o.status is not None
                                           else getattr(o, "outcome", "not sent")) for label, o, _ in tried)
        evidence = (f"{case.exchange.method.upper()} {_path(case.exchange.url)}; read back from "
                    f"{', '.join(_path(u) for u in case.reads)}: {sent}."
                    + (" " + "; ".join(case.notes) if case.notes else ""))
        if hit is not None:
            label, outcome, how = hit
            return self._result("confirmed", case,
                                f"Coupon misuse confirmed: {label} was accepted (HTTP {outcome.status}) "
                                f"and the read-back shows the discount: {how}." + self._residue_text(case),
                                confidence=0.9, evidence=evidence).with_artifacts(
                attack=outcome, controls=[o for _l, o, _h in tried if o is not outcome][:3])
        if lead is not None:
            label, outcome, how = lead
            return self._result("supported", case, f"LEAD: {label} was accepted (HTTP {outcome.status}): "
                                                   f"{how}." + self._residue_text(case),
                                confidence=0.4, evidence=evidence).with_artifacts(attack=outcome)
        if tried and all(o is not None and getattr(o, "ok", False) and o.status is not None
                         for _l, o, _h in tried):
            return self._result("not_confirmed", case,
                                "The server enforces its codes: no forged, expired or foreign code earned "
                                "a discount on the read-back." + self._residue_text(case),
                                evidence=evidence).with_artifacts(attack=tried[0][1])
        return self._result("inconclusive", case, "business_flow incomplete: a coupon write got no "
                                                  "answer" + self._residue_text(case), evidence=evidence)

    @staticmethod
    def _discount_shown(base: dict, after: dict, code: str, answer):
        """(strong, weak) evidence that the applied code took effect on a read-back."""
        answer_discount = _discounts(_top(answer) if isinstance(_top(answer), dict) else answer) \
            if isinstance(answer, dict) else {}
        weak = ""
        for url, b in base.items():
            a = after.get(url)
            if a is None or b is None:
                continue
            for p, v in a.discounts.items():
                if v > b.discounts.get(p, 0):
                    return f"{_path(url)} shows {p}={v} (it read {b.discounts.get(p, 0)} before)", ""
            for p, v in a.scalars.items():
                if p in b.scalars and v < b.scalars[p] and _flat(p.rsplit(".", 1)[-1]) != "balance":
                    return f"{_path(url)} {p} fell from {b.scalars[p]} to {v}", ""
            stored = [p for p, v in a.codes.items() if str(v) == str(code)]
            if stored:
                if answer_discount:
                    p, v = next(iter(answer_discount.items()))
                    return (f"{_path(url)} stores the code ({stored[0]}) and the server answered "
                            f"{p}={v}"), ""
                weak = f"{_path(url)} stores the code ({stored[0]}) but no discount was read back"
        if answer_discount and not weak:
            p, v = next(iter(answer_discount.items()))
            weak = f"the answer reported {p}={v} but no read-back showed the discount"
        return "", weak

    async def _clear_coupon(self, case: _Case, loc, base: dict, code: str, label: str) -> None:
        """Take the applied code off again: re-send the write with the code emptied
        (a body field) or with the code the read-back held before (a path code).
        A code that cannot be cleared is named."""
        prior = next((str(v) for s in base.values() if s is not None for v in s.codes.values()), "")
        if loc[0] == "path" and not prior:
            case.left.append(f"{label} stays applied to {_path(case.exchange.url).rsplit('/', 2)[0]}: the "
                             f"code sits in the path and removing it needs a DELETE (owner policy)")
            return
        if self._headroom(case) < 1:
            case.left.append(f"{label} stays applied: the ceiling left no write to remove it")
            return
        undo_code = prior if loc[0] == "path" else (prior or "")
        method, url, body = self._apply(case, loc, undo_code)
        from harness import run_handoff
        with run_handoff.restore_scope(f"{case.case_ref}:business_flow_coupon"):
            undo = await self._send(case, method, url, body, cleanup=True)
            check = await self._snapshot(case, case.reads)
        still = [u for u, s in check.items() if s is not None and (
            any(str(v) == str(code) for v in s.codes.values())
            or any(v > ((base.get(u).discounts.get(p, 0)) if base.get(u) else 0) for p, v in s.discounts.items()))]
        if still or not _ok(undo):
            case.left.append(f"{label} stays applied ({', '.join(_path(u) for u in still) or 'the removal '}"
                             f"{'' if still else 'answered HTTP ' + str(getattr(undo, 'status', None))})")
        else:
            applied = case.sent[-2:] if len(case.sent) >= 2 else case.sent
            self._restored(applied, f"business_flow {label} removed and verified on the read-back")

    async def _coupon_at_settlement(self, case: _Case, loc) -> ValidationResult:
        """A code carried by the settlement itself: the control flow sends it emptied,
        each misuse flow a forged/expired/foreign code; confirmed when the misuse
        flow settles for less than the control."""
        case.prereqs = self._plan_prereqs(case)
        case.reads = self._plan_reads(case, self._wants_money)
        if not case.reads:
            return self._skip(case.finding.vulnerability_class,
                              "no read-back of the settled state was captured or declared")
        codes = self._codes(case, loc[2])
        tampers = [_Tamper(-1, loc[1], "coupon", loc[2], code) for _l, code, ok in codes if ok]
        cleared = _with(case.fields, loc[1], "")
        flow_writes = len(case.prereqs) + 1
        if self._headroom(case) < 2 * flow_writes:
            return self._skip(case.finding.vulnerability_class,
                              f"the business_flow ceiling does not pay for a control flow and one coupon "
                              f"flow ({2 * flow_writes} writes)")
        saved, case.fields = case.fields, cleared
        try:
            return await self._amount_flows(case, tampers[:_MAX_AMOUNT_VARIANTS], flow_writes)
        finally:
            case.fields = saved

    # -- 3. 2FA disable without the step-up secret ----------------------------------------

    def _wants_mfa(self, url, doc) -> bool:
        state = _read_state(doc)
        return bool(_MFA_PATH.search(_path(url)) and state is not None and state.mfa is not None)

    def _mfa_reads(self, case: _Case) -> list[str]:
        origin = _origin(case.exchange.url)
        declared = [p if str(p).lower().startswith("http") else origin + str(p).split(None, 1)[-1]
                    for p in self.mfa_status_reads]
        saved, self.read_backs = self.read_backs, ()
        try:
            return list(dict.fromkeys(declared + self._plan_reads(case, self._wants_mfa)))[:2]
        finally:
            self.read_backs = saved

    async def _mfa_status(self, case: _Case):
        for url in case.reads:
            state = _read_state(_doc(await self._send(case, "GET", url)))
            if state is not None and state.mfa is not None:
                return state.mfa, url
        return None, ""

    def _enable_request(self, case: _Case):
        """The actor's own captured 2FA-enable write that succeeded, or None."""
        for item in reversed(self._captured()):
            method = str(_get(item, "method") or "").upper()
            url = str(_get(item, "url") or "")
            status = _get(item, "response_status")
            if (method in _WRITE_METHODS and self._mine(case, item) and _MFA_PATH.search(_path(url))
                    and _MFA_ON_PATH.search(_path(url)) and not _MFA_OFF_PATH.search(_path(url))
                    and status is not None and 200 <= int(status) < 300):
                return method, url, _get(item, "request_body") or None, _get(item, "request_headers") or {}
        return None

    async def _mfa(self, case: _Case) -> ValidationResult:
        case.reads = self._mfa_reads(case)
        who = case.actor.name or case.actor.principal_id
        if not case.reads:
            return self._skip(case.finding.vulnerability_class,
                              "no 2FA status read was captured for this identity or declared in "
                              "validators.business_flow.mfa_status_reads")
        steps = [p for p, _v in _leaves(case.fields) if _STEP_UP.match(_flat(p[-1]))]
        variants = [("the step-up field(s) " + ", ".join(".".join(map(str, p)) for p in steps) + " dropped",
                     self._without(case.fields, steps, drop=True)),
                    ("wrong step-up value(s)", self._without(case.fields, steps, drop=False))]
        if self._headroom(case) < 2:
            return self._skip(case.finding.vulnerability_class,
                              "the business_flow ceiling does not pay for a disable attempt and its "
                              "re-enable (2 writes)")
        status, read_url = await self._mfa_status(case)
        if status is not True:
            return self._result("inconclusive", case,
                                f"business_flow not decided: the status read does not show 2FA enabled on "
                                f"{who} ({'unreadable' if status is None else 'disabled'}); enabling it "
                                f"needs a secret, so nothing was written")
        tried, hit = [], None
        for label, fields in variants:
            if self._headroom(case) < 2:
                case.notes.append(f"{label} not sent: the ceiling keeps one write for the re-enable")
                break
            outcome = await self._send(case, case.exchange.method, case.exchange.url,
                                       _encode(fields, case.body_kind))
            now, _u = await self._mfa_status(case)
            tried.append((label, outcome, now))
            if now is False:
                hit = (label, outcome)
                break
        restore = ""
        if hit is not None:
            restore = await self._mfa_restore(case, who)
        sent = "; ".join(f"{label} -> " + (f"HTTP {o.status}" if o is not None and o.status is not None
                                           else getattr(o, "outcome", "not sent"))
                         + f", status read {'disabled' if now is False else 'enabled' if now else 'unreadable'}"
                         for label, o, now in tried)
        evidence = (f"{case.exchange.method.upper()} {_path(case.exchange.url)} as {who}; status read "
                    f"{_path(read_url)} showed 2FA enabled first: {sent}."
                    + (" " + "; ".join(case.notes) if case.notes else ""))
        if hit is not None:
            label, outcome = hit
            return self._result("confirmed", case,
                                f"2FA disabled without the step-up secret: the disable request with {label} "
                                f"was accepted (HTTP {outcome.status}) and the status read-back shows 2FA "
                                f"off for {who}. {restore}" + self._residue_text(case), confidence=0.9,
                                evidence=evidence).with_artifacts(attack=outcome)
        if tried and all(now is True for _l, _o, now in tried):
            return self._result("not_confirmed", case,
                                f"The 2FA disable requires its step-up secret: with it dropped or wrong, "
                                f"the status read-back still shows 2FA enabled for {who}.",
                                evidence=evidence).with_artifacts(attack=tried[0][1])
        return self._result("inconclusive", case, "business_flow incomplete: a disable attempt or its "
                                                  "status read got no answer", evidence=evidence)

    @staticmethod
    def _without(fields: dict, steps, *, drop: bool) -> dict:
        out = fields
        for p in steps:
            original = None
            cur = fields
            for k in p:
                cur = cur.get(k) if isinstance(cur, dict) else None
            original = cur
            wrong = ("".join(secrets.choice(string.digits) for _ in range(len(str(original))))
                     if str(original).isdigit() else "wrong-" + secrets.token_hex(4))
            out = _with(out, p, wrong, drop=drop)
        return out

    async def _mfa_restore(self, case: _Case, who: str) -> str:
        enable = self._enable_request(case)
        if enable is None:
            case.left.append(f"2FA LEFT DISABLED on the run-owned identity {who}: the run holds no captured "
                             f"enable request to turn it back on; re-enable it by hand")
            return ""
        if self._headroom(case) < 1:
            case.left.append(f"2FA LEFT DISABLED on {who}: the ceiling left no write for the re-enable")
            return ""
        method, url, body, hdrs = enable
        from harness import run_handoff
        from harness.security import is_identity_credential_header
        headers = {k: v for k, v in hdrs.items()
                   if not is_identity_credential_header(k) and k.lower() not in {"host", "content-length"}}
        with run_handoff.restore_scope(f"{case.case_ref}:business_flow_mfa"):
            outcome = await self._send(case, method, url, body, headers, cleanup=True)
            now, _u = await self._mfa_status(case)
        if now is True:
            self._restored([o for o in case.sent], f"business_flow re-enabled 2FA on {who}, verified on "
                                                   f"the status read")
            case.sent = []
            return "2FA was re-enabled by replaying the run's captured enable request and verified."
        case.left.append(f"2FA LEFT DISABLED on the run-owned identity {who}: the replayed enable request "
                         f"answered HTTP {getattr(outcome, 'status', None)} and the status still reads "
                         f"{'disabled' if now is False else 'unreadable'} (it may need a fresh one-time "
                         f"code); re-enable it by hand")
        return ""
