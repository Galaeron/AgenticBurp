"""Business-flow constants, request/response readers, tamper and effect records, flow
classification: moved verbatim out of business_flow_validator.py (ARC-9). Nothing here sends.
`kind_for` stays in the validator module: it reads the captured request's method."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import struct
import time
from dataclasses import dataclass, field as dc_field
from urllib.parse import parse_qsl, urlencode, urlsplit

from .client_trust_validator import (
    _COUPON,
    _PAYMENT,
    _QUANTITY,
    _authority_state,
    _discounts,
    _elevations,
    _flat,
    _flatten,
    _json,
    _money,
)
from harness.models import Finding, HttpExchange


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
_MAX_AMOUNT_VARIANTS = 2          # the default of validators.business_flow.max_variants
_MAX_VARIANTS_HARD = 4
_MAX_RACE_COPIES = 5
_MAX_CAPTURED = 600
# A one-time-code field in a captured 2FA enable/setup body (its value is 6-8 digits).
_OTP_FIELD = re.compile(r"^(?:totp|otp|code|token|totptoken|otptoken|totpcode|otpcode|verificationcode|"
                        r"mfacode|2facode|twofactorcode|initialtoken|inittoken|onetimecode|"
                        r"onetimepassword|pin)$")
_TOTP_SECRET_KEYS = ("totp_secret", "totpSecret", "mfa_secret", "otp_secret")


def totp_code(secret: str, at: float | None = None, *, digits: int = 6, step: int = 30) -> str:
    """RFC 6238 TOTP (HMAC-SHA1) for a base32 secret. Never logged by callers."""
    clean = re.sub(r"[\s=-]", "", str(secret)).upper()
    key = base64.b32decode(clean + "=" * (-len(clean) % 8))
    counter = int((time.time() if at is None else at) // step)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(value).zfill(digits)


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
