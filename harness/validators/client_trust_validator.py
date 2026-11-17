"""
Excessive-trust-in-client-side-controls confirmation leg (business logic).

A price/amount/total that the SERVER should own is instead taken from a
client-supplied request field (a hidden form input, a JSON value). The bug is
confirmed by TAMPERING that field to a distinctive sentinel value and observing
the server REFLECT it back on an independent read (the cart/order summary), i.e.
the server stored the attacker-chosen amount rather than its own authoritative
price. A server that ignores the client value and re-derives its own price shows
the real amount instead, so the sentinel is absent and this stays un-confirmed.

Safe + non-destructive: the tamper is a normal add-to-cart/update write (gated by
validators.allow_mutating_replay); NO checkout/purchase is performed -- the proof
is that the amount was trusted, read back from the cart, not an order placed.

Beyond a price, the same flaw class covers any field whose value the server
should own or constrain (recognised by key semantics and value shape, never a
per-application key list), each tampered with adversarial values:

  payment   a payment mode/method/source/instrument id -> empty, "none", a
            nonexistent value (or null)
  plan      a plan/tier/membership/subscription name -> a higher tier
  quantity  a quantity/count -> a negative, a zero and a huge value
  currency  a currency code -> another currency (a mismatch)
  coupon    a coupon/voucher/promo code -> a code that does not exist
  authority a role, an approval/verified/paid flag, a lifecycle status -> the
            privileged value

Each runs the untampered request first as a control. A tamper is confirmed only
when the server accepts it AND shows the effect took hold: a read-back of the
created or updated object storing the tampered value, a reissued token whose
role/tier claims changed, a state read that changed, or a changed total. A
payment tamper also needs the untampered control to be refused (the legitimate
payment fails, the unpaid one succeeds); a captured payment that succeeded is
never replayed, so nothing is paid twice. Every object a probe creates is
deleted and its removal verified; an update is written back to its untampered
value. A state change with no undo route (a granted membership) is named in the
result.
"""
from __future__ import annotations
from harness import scope_lock

import base64
import json
import re
import secrets
from dataclasses import dataclass, field as dc_field
from urllib.parse import quote, urljoin, urlsplit, urlunsplit, parse_qsl, urlencode

import httpx

from harness import global_throttle
from harness.models import Finding, HttpExchange
from harness.safety_gate import GatedAsyncClient, get_default_gate, SafetyGateBlocked
from .base import Validator, ValidationResult
from .injection_targets import replay_headers

# Fields whose value the SERVER should own; a client-supplied one is the bug.
_VALUE_KEYS = re.compile(
    r"^(price|amount|cost|total|subtotal|unit[_-]?price|fee|balance|discount|"
    r"pay(?:ment)?_?amount|value)$", re.I)
_CSRF_KEYS = re.compile(r"csrf|xsrf|authenticity|_token|nonce", re.I)
# Re-read targets that commonly render a stored cart/order amount.
_SUMMARY_PATHS = ("/cart", "/basket", "/checkout", "/order", "/orders",
                  "/cart/summary", "/my-account")


def _parse(body: str):
    """(fields, kind) for a urlencoded or JSON body; kind in {'form','json'}."""
    s = (body or "").strip()
    if s.startswith("{"):
        try:
            obj = json.loads(s)
            if isinstance(obj, dict):
                return obj, "json"
        except ValueError:
            pass
    return dict(parse_qsl(body or "", keep_blank_values=True)), "form"


def _encode(fields: dict, kind: str) -> str:
    return json.dumps(fields) if kind == "json" else urlencode(fields)


def _value_field(fields: dict) -> str | None:
    for k, v in fields.items():
        if _VALUE_KEYS.match(str(k)) and re.fullmatch(r"-?\d+", str(v) or ""):
            return k
    return None


def _formats(cents: int) -> list[str]:
    """Distinctive renderings of a cents amount to look for in a summary page."""
    dollars = f"{cents // 100}.{cents % 100:02d}"
    return [dollars, str(cents)]


# -- server-owned and server-constrained fields beyond a price -------------------
# Matched on the key flattened to lowercase letters and digits, and on the value's
# shape, so "payment_mode", "paymentMode" and {"payment": {"mode": ...}} all match.
_PAYMENT = re.compile(r"^(?:payment|pay|billing|funding|charge)(?:mode|method|type|source|option|"
                      r"instrument|provider|channel|gateway|id|token|with|via)?$"
                      r"|^(?:card|wallet|instrument)(?:id|token)$")
_PLAN = re.compile(r"^(?:plan|tier|membership|subscription|package|edition|accounttype|"
                   r"membershiptype|membershiplevel|membershiptier|subscriptiontype|subscriptiontier|"
                   r"subscriptionplan|plantype|planname|tiername|servicelevel)$")
_QUANTITY = re.compile(r"^(?:qty|quantity|quantities|count|units|pieces|itemcount|numitems|nights|"
                       r"seats|tickets|licenses|licences|copies)$")
_CURRENCY = re.compile(r"^(?:currency|currencycode|curr|ccy|currencyiso)$")
_COUPON = re.compile(r"^(?:coupon|couponcode|voucher|vouchercode|promo|promocode|promotion|"
                     r"promotioncode|discountcode|giftcard|giftcode|giftcardcode|redeemcode|"
                     r"redemptioncode|referralcode)$")
_ROLE = re.compile(r"^(?:role|roles|usertype|accesslevel|usergroup|permission|permissions)$")
_FLAG = re.compile(r"^(?:is)?(?:admin|superuser|staff|verified|emailverified|approved|paid|premium|"
                   r"vip|trusted|confirmed)$")
_STATUS = re.compile(r"^(?:status|orderstatus|paymentstatus|accountstatus|approvalstatus|"
                     r"verificationstatus|kycstatus|state)$")
# A status worth promoting: an early lifecycle value, never a free-form one.
_LIFECYCLE = re.compile(r"^(?:new|pending|unpaid|draft|open|created|submitted|unverified|inactive|"
                        r"trial|awaiting[\w-]*|on[_-]?hold|requested|initiated)$", re.I)
_TOP_TIERS = ("enterprise", "premium", "unlimited")
_CHEAP_CURRENCIES = ("IDR", "VND", "JPY", "USD")
_CARD_NUMBER = re.compile(r"^\d[\d \-]{11,}$")
# Claims and state fields that carry a principal's privilege, tier or standing.
_AUTHORITY_CLAIM = re.compile(
    r"^(?:role|roles|tier|plan|membership|membershiptype|membershiplevel|subscription|"
    r"subscriptiontype|subscriptiontier|accounttype|usertype|accesslevel|group|groups|permission|"
    r"permissions|scope|scopes|entitlement|entitlements|privilege|privileges|isadmin|admin|"
    r"premium|ispremium|vip|isvip|paid|ispaid|verified|isverified|status)$")
_MONEY_FIELD = re.compile(r"^(?:total|subtotal|grandtotal|ordertotal|amount|totalamount|price|"
                          r"totalprice|cost|totalcost|balance|due|amountdue)$")
_DISCOUNT_FIELD = re.compile(r"^(?:discount|discountamount|discounttotal|savings|saved|reduction|"
                             r"couponvalue|vouchervalue|promovalue)$")
_JWT = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*")
_ID_SEGMENT = re.compile(r"^(\d+|[0-9a-fA-F]{8,}|[0-9a-fA-F]{8}-[0-9a-fA-F-]{4,})$")
_ID_KEYS = frozenset({"id", "uuid", "guid"})   # flattened: "_id" is "id"
_FAMILY_ORDER = ("payment", "plan", "quantity", "currency", "coupon", "authority")
# Families whose accepted tamper changes a principal's standing: one is enough.
_STATEFUL = frozenset({"payment", "plan", "authority"})
_LABEL = {"payment": "payment source", "plan": "plan/tier", "quantity": "quantity",
          "currency": "currency", "coupon": "discount code", "authority": "privilege/status"}


def _flat(key) -> str:
    return re.sub(r"[^a-z0-9]", "", str(key).lower())


@dataclass
class _Field:
    """One server-owned field of the captured body and the values to try."""
    path: tuple
    family: str
    original: object
    tampers: list

    @property
    def key(self) -> str:
        return ".".join(str(p) for p in self.path)


def _numeric(value):
    """`value` as an int when it is an integer number or numeric string, else None."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and re.fullmatch(r"-?\d{1,9}", value.strip()):
        return int(value)
    return None


def _like(original, number: int):
    """`number` in the captured value's type (a numeric string stays a string)."""
    return str(number) if isinstance(original, str) else number


def _tampers_for(family: str, flat: str, value, kind: str) -> list:
    """The adversarial values for one field, or [] when its value has the wrong shape."""
    if family == "payment":
        if isinstance(value, str) and len(value) <= 64 and not _CARD_NUMBER.match(value):
            out = ["", "none", "x" + secrets.token_hex(4)]
            return [v for v in out if v != value] + ([None] if kind == "json" else [])
        if _numeric(value) is not None and flat.endswith("id"):
            return [_like(value, n) for n in (0, -1, 987654321) if n != _numeric(value)]
        return []
    if family == "plan":
        if isinstance(value, str) and value and len(value) <= 40:
            return [t for t in _TOP_TIERS if t != value.strip().lower()][:2]
        return []
    if family == "quantity":
        n = _numeric(value)
        if n is None or n <= 0:
            return []
        negative = -(secrets.randbelow(80) + 17)
        return [_like(value, v) for v in (negative, 0, 99999) if v != n]
    if family == "currency":
        if isinstance(value, str) and re.fullmatch(r"[A-Za-z]{3}", value):
            pick = next(c for c in _CHEAP_CURRENCIES if c != value.upper())
            return [pick if value.isupper() else pick.lower()]
        return []
    if family == "coupon":
        if isinstance(value, str) and len(value) <= 64:
            return ["WI" + secrets.token_hex(4).upper()]
        return []
    if family == "authority":
        if _ROLE.match(flat):
            if isinstance(value, list):
                return [["admin"]] if "admin" not in [str(v).lower() for v in value] else []
            if isinstance(value, str) and value and value.lower() != "admin":
                return ["admin"]
            return []
        if _FLAG.match(flat):
            if value is False:
                return [True]
            if isinstance(value, str) and value.lower() in ("false", "0", "no", "off"):
                return ["true" if value.lower() == "false" else "1"]
            return []
        if isinstance(value, str) and _LIFECYCLE.match(value):
            return ["paid" if "pay" in flat else "approved", "completed"]
        return []
    return []


def _family_of(flats: tuple) -> str:
    for name, regex in (("payment", _PAYMENT), ("plan", _PLAN), ("quantity", _QUANTITY),
                        ("currency", _CURRENCY), ("coupon", _COUPON)):
        if any(regex.match(f) for f in flats):
            return name
    if any(_ROLE.match(f) or _FLAG.match(f) or _STATUS.match(f) for f in flats):
        return "authority"
    return ""


def _leaves(fields: dict, kind: str):
    """(path, flat names, value) for each top-level field and, in a JSON body, each
    field of a nested object (matched on its own name and on parent+child)."""
    for k, v in fields.items():
        if isinstance(v, dict) and kind == "json":
            for k2, v2 in v.items():
                if not isinstance(v2, dict):
                    yield (k, k2), (_flat(k2), _flat(k) + _flat(k2)), v2
        else:
            yield (k,), (_flat(k),), v


def trust_fields(fields: dict, kind: str = "json") -> list[_Field]:
    """Every server-owned field (beyond an integer price/amount) this leg can
    tamper with, best first: payment, plan, quantity, currency, coupon, authority."""
    found = []
    for path, flats, value in _leaves(fields or {}, kind):
        if _CSRF_KEYS.search(str(path[-1])):
            continue
        family = _family_of(flats)
        if not family:
            continue
        flat = next((f for f in flats if _family_of((f,)) == family), flats[0])
        tampers = _tampers_for(family, flat, value, kind)
        if tampers:
            found.append(_Field(path, family, value, tampers))
    found.sort(key=lambda f: _FAMILY_ORDER.index(f.family))
    return found


def body_trust_fields(body: str) -> list[_Field]:
    """trust_fields of a raw urlencoded or JSON request body (the coverage row's
    applicability test reads a captured template body with it)."""
    return trust_fields(*_parse(body or ""))


def has_trust_shape(exchange: HttpExchange) -> bool:
    """The leg's targeting predicate: a POST/PUT/PATCH whose body carries an integer
    price/amount/total or another server-owned field (payment source, plan/tier,
    quantity, currency, coupon, role/status/verified flag)."""
    if (exchange.method or "").upper() not in ("POST", "PUT", "PATCH"):
        return False
    fields, kind = _parse(exchange.request_body or "")
    return _value_field(fields) is not None or bool(trust_fields(fields, kind))


def _with(fields: dict, path: tuple, value) -> dict:
    out = json.loads(json.dumps(fields))
    target = out
    for p in path[:-1]:
        target = target[p]
    target[path[-1]] = value
    return out


def _json(text):
    try:
        return json.loads(text) if isinstance(text, str) and text.strip() else None
    except ValueError:
        return None


def _unwrap(doc):
    """The object a JSON answer is about: `data` when it wraps one, else the answer."""
    if isinstance(doc, dict) and isinstance(doc.get("data"), dict):
        return doc["data"]
    return doc if isinstance(doc, dict) else None


def _leaf(obj, path: tuple):
    """`obj` at `path`, each key matched case- and separator-insensitively; also the
    leaf name at the top level (a nested field may come back flat). (found, value)."""
    def get(o, key):
        if not isinstance(o, dict):
            return False, None
        if key in o:
            return True, o[key]
        want = _flat(key)
        for k, v in o.items():
            if _flat(k) == want:
                return True, v
        return False, None
    cur, ok = obj, True
    for p in path:
        ok, cur = get(cur, p)
        if not ok:
            break
    if ok:
        return True, cur
    return get(obj, path[-1]) if len(path) > 1 else (False, None)


def _same(a, b) -> bool:
    if a is None or b is None:
        return a is b
    if isinstance(a, (list, dict)) or isinstance(b, (list, dict)):
        return json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)
    return str(a).strip().lower() == str(b).strip().lower()


def _flatten(obj, prefix=""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _flatten(v, f"{prefix}{k}.")
    elif prefix:
        yield prefix[:-1], obj


def _authority_state(obj) -> dict:
    """{dotted path: value} of the privilege/tier fields in `obj`."""
    out = {}
    for path, value in _flatten(obj if isinstance(obj, dict) else {}):
        if not _AUTHORITY_CLAIM.match(_flat(path.rsplit(".", 1)[-1])):
            continue
        if isinstance(value, str) and value.strip().lower() in _ENVELOPE:
            continue   # a response envelope ("status": "success"), not a standing
        out[path] = json.dumps(value, sort_keys=True) if isinstance(value, list) else value
    return out


_ENVELOPE = frozenset({"success", "ok", "error", "fail", "failed", "failure"})


def _by_leaf(state: dict, path: str):
    """`state` at `path`, or at the one entry with the same leaf name: a token claim
    "data.role" and a response field "role" describe the same standing."""
    if path in state:
        return True, state[path]
    leaf = _flat(path.rsplit(".", 1)[-1])
    hits = [v for p, v in state.items() if _flat(p.rsplit(".", 1)[-1]) == leaf]
    return (True, hits[0]) if len(hits) == 1 else (False, None)


def _jwt_claims(token: str) -> dict:
    try:
        part = token.split(".")[1]
        part += "=" * (-len(part) % 4)
        payload = json.loads(base64.urlsafe_b64decode(part.encode()))
    except (ValueError, IndexError, TypeError):
        return {}
    return _authority_state(payload) if isinstance(payload, dict) else {}


def _claims_in(texts) -> dict:
    """The privilege/tier claims of the first decodable JWT among `texts`."""
    for text in texts:
        for token in _JWT.findall(str(text or "")):
            claims = _jwt_claims(token)
            if claims:
                return claims
    return {}


def _elevations(before: dict, after: dict) -> list[str]:
    """Privilege/tier values that changed from `before` to `after` (a new truthy flag
    or an "admin" value also counts). Values only, never a token."""
    out = []
    for path, value in after.items():
        known, prior = _by_leaf(before, path)
        if known:
            if not _same(prior, value):
                out.append(f"{path}: {prior!r} -> {value!r}")
        elif value is True or str(value).lower() == "admin":
            out.append(f"{path}: (absent) -> {value!r}")
    return out


def _money(obj) -> dict:
    return {p: v for p, v in _flatten(obj if isinstance(obj, dict) else {})
            if _MONEY_FIELD.match(_flat(p.rsplit(".", 1)[-1]))
            and isinstance(v, (int, float)) and not isinstance(v, bool)}


def _discounts(obj) -> dict:
    return {p: v for p, v in _flatten(obj if isinstance(obj, dict) else {})
            if _DISCOUNT_FIELD.match(_flat(p.rsplit(".", 1)[-1]))
            and isinstance(v, (int, float)) and not isinstance(v, bool) and v > 0}


def _created_id(obj) -> str:
    if isinstance(obj, dict):
        for k, v in obj.items():
            if _flat(k) in _ID_KEYS and isinstance(v, (int, str)) and not isinstance(v, bool) and str(v):
                return str(v)
    return ""


def _ends_with_id(url: str) -> bool:
    segments = [s for s in urlsplit(url or "").path.split("/") if s]
    return bool(segments) and bool(_ID_SEGMENT.match(segments[-1]))


def _item_url(collection_url: str, oid: str) -> str:
    parts = urlsplit(collection_url)
    return urlunsplit((parts.scheme, parts.netloc,
                       parts.path.rstrip("/") + "/" + quote(str(oid), safe=""), "", ""))


def _gone(resp) -> bool:
    """A verification read shows the object is gone."""
    if resp is None:
        return False
    if resp.status_code in (404, 410):
        return True
    if 200 <= resp.status_code < 300:
        text = (resp.text or "").strip()
        if text in ("", "null", "{}", "[]"):
            return True
        doc = _json(text)
        return isinstance(doc, dict) and "data" in doc and doc["data"] in (None, {}, [])
    return False


@dataclass
class _Obs:
    """One write this probe sent (the control or a tamper) and what it showed."""
    label: str
    value: object = None
    resp: object = None
    status: int | None = None
    echo: dict | None = None
    claims: dict = dc_field(default_factory=dict)
    item: str = ""
    read: object = None
    obj: dict | None = None
    created: bool = False
    removed: bool | None = None
    error: str = ""
    strong: list = dc_field(default_factory=list)   # the effect took hold
    weak: list = dc_field(default_factory=list)     # accepted, echoed, not shown stored

    @property
    def ok(self) -> bool:
        return self.status is not None and 200 <= self.status < 300

    @property
    def refused(self) -> bool:
        return self.status is not None and self.status >= 400


class ClientTrustValidator(Validator):
    name = "client_trust"
    finding_classes = {
        "business_logic", "business logic", "business logic vulnerability",
        "client_side_controls", "client-side controls", "excessive trust",
        "price_manipulation", "price manipulation", "logic_flaw", "logic flaw",
    }
    active = True

    def __init__(self, *, allowed_hosts: list[str] | None = None, timeout: float = 10.0):
        self.allowed_hosts = allowed_hosts or []
        self.timeout = timeout

    def _skip(self, why: str) -> ValidationResult:
        return ValidationResult(self.name, "skipped", "business_logic", summary=why)

    def applies(self, finding: Finding, exchange: HttpExchange) -> bool:
        if not super().applies(finding, exchange):
            return False
        return has_trust_shape(exchange)

    async def _send(self, client, method, url, headers, body):
        await global_throttle.acquire()
        return await client.request(method, url, headers=headers or None, content=body or None)

    def _headers(self, exchange) -> dict:
        return {k: v for k, v in (exchange.request_headers or {}).items()
                if k.lower() not in ("content-length", "host")}

    async def validate(self, finding: Finding, exchange: HttpExchange) -> ValidationResult:
        host = urlsplit(exchange.url).hostname or ""
        if self.allowed_hosts and not scope_lock.host_in_scope(exchange.url, self.allowed_hosts):
            return self._skip(f"host {host!r} out of scope")
        if not get_default_gate().config.allow_mutating_replay:
            return self._skip("client-trust tamper is a mutating write; needs validators.allow_mutating_replay")
        fields, kind = _parse(exchange.request_body or "")
        if _value_field(fields) is not None:
            return await self._validate_value(finding, exchange)
        found = trust_fields(fields, kind)
        status = exchange.response_status
        if status is not None and 200 <= status < 300:
            # A captured payment that went through is never replayed: it would pay again.
            paid = [f for f in found if f.family == "payment"]
            found = [f for f in found if f.family != "payment"]
            if paid and not found:
                return self._skip(
                    f"the captured {(exchange.method or 'POST').upper()} with {paid[0].key}="
                    f"{paid[0].original!r} succeeded (HTTP {status}); replaying a payment that went "
                    f"through would pay again, so no payment-source tamper was sent")
        if not found:
            return self._skip("no server-owned field (price/amount/total, payment source, plan/tier, "
                              "quantity, currency, coupon, role/status flag) in the request body")
        return await self._validate_state(exchange, fields, kind, found[0])

    async def _validate_value(self, finding: Finding, exchange: HttpExchange) -> ValidationResult:
        """The price/amount path: a sentinel amount reflected on a summary read."""
        host = urlsplit(exchange.url).hostname or ""
        if self.allowed_hosts and not scope_lock.host_in_scope(exchange.url, self.allowed_hosts):
            return self._skip(f"host {host!r} out of scope")
        if not get_default_gate().config.allow_mutating_replay:
            return self._skip("client-trust tamper is a mutating write; needs validators.allow_mutating_replay")

        fields, kind = _parse(exchange.request_body or "")
        vkey = _value_field(fields)
        if vkey is None:
            return self._skip("no server-owned value field (price/amount/total) in the request body")
        original = str(fields.get(vkey))
        # A distinctive 5-digit sentinel amount (in cents) -> $DDD.CC, unlikely to
        # appear by chance; kept well below the original so it also demonstrates the
        # "buy for less" exploit direction without any purchase.
        sentinel = secrets.randbelow(90000) + 1000
        if str(sentinel) == original:
            sentinel += 7
        method = (exchange.method or "POST").upper()
        p = urlsplit(exchange.url)
        origin = f"{p.scheme}://{p.netloc}"

        # A read-back or token refresh that got no response is not a negative
        # (RV-P P1): the confirming page may be the one that never answered.
        refresh_failures: list[str] = []
        refused, errors = "", []
        try:
            async with GatedAsyncClient(get_default_gate(), self.name, timeout=self.timeout,
                                        follow_redirects=True, verify=False) as client:
                tampered = dict(fields)
                tampered[vkey] = str(sentinel)
                # Refresh an in-session CSRF token if the write is token-bound.
                ckey = next((k for k in fields if _CSRF_KEYS.search(str(k))), None)
                if ckey is not None:
                    tampered = await self._refresh_csrf(client, exchange, tampered, ckey, kind,
                                                        refresh_failures)
                resp = await self._send(client, method, exchange.url,
                                        self._headers(exchange), _encode(tampered, kind))
                if resp.status_code >= 400 and refresh_failures:
                    return ValidationResult(
                        self.name, "inconclusive", "business_logic", confidence=0.0, confirmed=False,
                        summary=f"Client-trust check incomplete: the in-session CSRF token could not be "
                                f"refreshed ({'; '.join(refresh_failures[:3])}), so the rejected write "
                                f"(HTTP {resp.status_code}) may be the stale token; not a negative result",
                        evidence=f"POST {exchange.url} with {vkey}={sentinel} and the captured {ckey} "
                                 f"→ {resp.status_code}; the source page that mints a fresh {ckey} "
                                 f"never answered.")
                if resp.status_code >= 400:
                    return ValidationResult(
                        self.name, "not_confirmed", "business_logic", confidence=0.0, confirmed=False,
                        summary=f"Tampered {vkey} write rejected (HTTP {resp.status_code}).",
                        evidence=f"POST {exchange.url} with {vkey}={sentinel} → {resp.status_code}.")

                wanted = _formats(sentinel)
                read_headers = {k: v for k, v in self._headers(exchange).items()
                                if k.lower() != "content-type"}
                pages = [resp.text or ""]
                targets = list(dict.fromkeys([str(resp.url)] + [origin + sp for sp in _SUMMARY_PATHS]))
                for t in targets:
                    try:
                        rr = await self._send(client, "GET", t, read_headers, None)
                        pages.append(rr.text or "")
                    except SafetyGateBlocked as e:
                        # Nothing more can send once the gate refuses (budget, scope).
                        refused = e.decision.reason
                        break
                    except httpx.HTTPError as e:
                        errors.append(f"GET {t}: {e.__class__.__name__}")
                        continue
        except SafetyGateBlocked as e:
            return ValidationResult(
                self.name, "blocked", "business_logic", confidence=0.0, confirmed=False,
                summary=f"Client-trust check incomplete: the tampered write was refused by the "
                        f"safety gate ({e.decision.reason}); not a negative result",
                evidence=f"No tampered {vkey} write reached {exchange.url}.")
        except httpx.HTTPError as e:
            return ValidationResult(self.name, "error", "business_logic",
                                    summary=f"request failed: {e.__class__.__name__}")
        for body in pages:
            if wanted[0] in body:  # the $DDD.CC rendering of the sentinel
                return ValidationResult(
                    self.name, "confirmed", "business_logic", confidence=0.9, confirmed=True,
                    summary=(f"Excessive trust in client-side controls confirmed: the server accepted a "
                             f"client-supplied {vkey} and reflected it back on an independent read."),
                    evidence=(f"The captured request set {vkey}={original}; replaying it with "
                              f"{vkey}={sentinel} caused the summary to show the attacker-chosen amount "
                              f"(${wanted[0]}). The server trusts the client value instead of its own "
                              f"authoritative price. No checkout/purchase was performed."))
        answered = len(pages) - 1
        if refused or errors:
            why = "; ".join(([f"refused by the safety gate ({refused})"] if refused else []) + errors[:3])
            return ValidationResult(
                self.name, "inconclusive", "business_logic", confidence=0.0, confirmed=False,
                summary=f"Client-trust check incomplete: {len(targets) - answered} of {len(targets)} "
                        f"read-back(s) got no response ({why}); not a negative result",
                evidence=f"The write with {vkey}={sentinel} was accepted (HTTP {resp.status_code}); "
                         f"{answered} answered read-back(s) did not show ${wanted[0]}, but a page "
                         f"that never answered cannot show it.")
        return ValidationResult(
            self.name, "not_confirmed", "business_logic", confidence=0.0, confirmed=False,
            summary=f"Server did not reflect the tampered {vkey}; it appears to own the value.",
            evidence=f"Set {vkey}={sentinel} but ${wanted[0]} was not shown on re-read -- the server "
                     f"likely re-derives its own authoritative amount.")

    # -- server-owned fields beyond a price ------------------------------------------

    async def _validate_state(self, exchange: HttpExchange, fields: dict, kind: str,
                              cand: _Field) -> ValidationResult:
        """Control, then tamper `cand` with each adversarial value; confirm only on
        an accepted tamper whose effect an independent read or a reissued token shows."""
        method = (exchange.method or "POST").upper()
        url = exchange.url
        headers = self._headers(exchange)
        read_headers = {k: v for k, v in headers.items() if k.lower() != "content-type"}
        label = _LABEL[cand.family]
        stateful = cand.family in _STATEFUL
        on_item = method in ("PUT", "PATCH") or _ends_with_id(url)
        session = _claims_in(v for k, v in headers.items() if k.lower() in ("authorization", "cookie"))
        ckey = next((k for k in fields if _CSRF_KEYS.search(str(k))), None)
        refresh_failures: list[str] = []
        errors: list[str] = []
        leftovers: list[str] = []     # objects a probe created whose removal was not verified
        ctl = _Obs("control", cand.original)
        tries: list[_Obs] = []
        before = after = None
        restored: bool | None = None
        refused_by_gate = ""

        async def read(client, target):
            try:
                rr = await self._send(client, "GET", target, read_headers, None)
            except httpx.HTTPError as e:
                errors.append(f"GET {target}: {e.__class__.__name__}")
                return None, None
            return rr, (_unwrap(_json(rr.text)) if 200 <= rr.status_code < 300 else None)

        async def remove(client, target) -> bool:
            try:
                rd = await self._send(client, "DELETE", target, read_headers, None)
            except httpx.HTTPError as e:
                errors.append(f"DELETE {target}: {e.__class__.__name__}")
                return False
            if rd.status_code >= 400 and rd.status_code not in (404, 410):
                return False
            check, _ = await read(client, target)
            return _gone(check)

        async def write(client, body_fields: dict, obs: _Obs):
            if ckey is not None:
                body_fields = await self._refresh_csrf(client, exchange, body_fields, ckey, kind,
                                                       refresh_failures)
            try:
                resp = await self._send(client, method, url, headers, _encode(body_fields, kind))
            except httpx.HTTPError as e:
                obs.error = f"{method} {url}: {e.__class__.__name__}"
                errors.append(obs.error)
                return
            obs.resp, obs.status = resp, resp.status_code
            obs.echo = _unwrap(_json(resp.text))
            obs.claims = _claims_in([resp.text or ""] + [v for k, v in resp.headers.multi_items()
                                                         if k.lower() in ("set-cookie", "authorization")])
            if not obs.ok:
                return
            if on_item:
                obs.item = url
            elif method == "POST":
                loc, oid = resp.headers.get("location"), _created_id(obs.echo)
                obs.item = urljoin(url, loc) if loc else _item_url(url, oid) if oid else ""
                obs.created = bool(obs.item)
                if not obs.item and resp.status_code == 201:
                    leftovers.append(f"{url} (HTTP 201 named no id to delete it by)")
            if obs.item:
                obs.read, obs.obj = await read(client, obs.item)
            if obs.created:
                obs.removed = await remove(client, obs.item)
                if not obs.removed:
                    leftovers.append(obs.item)

        async def state(client):
            _, obj = await read(client, url)
            return _authority_state(obj) if isinstance(obj, dict) else None

        try:
            async with GatedAsyncClient(get_default_gate(), self.name, timeout=self.timeout,
                                        follow_redirects=True, verify=False) as client:
                await write(client, dict(fields), ctl)
                # A usable baseline: a payment control the server refuses (the legitimate
                # payment fails), any other control it accepts, and nothing left behind
                # that a tamper could collide with. Anything else is reported below.
                usable = (not ctl.error and ctl.status is not None
                          and (ctl.refused if cand.family == "payment" else ctl.ok)
                          and not (ctl.created and not ctl.removed))
                if usable:
                    if stateful and not on_item:
                        before = await state(client)
                    for value in cand.tampers:
                        obs = _Obs("tamper", value)
                        await write(client, _with(fields, cand.path, value), obs)
                        tries.append(obs)
                        if obs.created and not obs.removed:
                            break
                        obs.strong, obs.weak = self._evidence(cand, obs, ctl, session, None, None)
                        if obs.ok and (stateful or obs.strong):
                            break
                    accepted = [t for t in tries if t.ok]
                    if stateful and accepted and not on_item and before is not None:
                        after = await state(client)
                        last = accepted[-1]
                        last.strong, last.weak = self._evidence(cand, last, ctl, session, before, after)
                    if on_item and accepted:
                        restored = await self._write_back(client, write, read, fields, cand, url)
        except SafetyGateBlocked as e:
            refused_by_gate = e.decision.reason
        except httpx.HTTPError as e:
            errors.append(f"{e.__class__.__name__}")
        return self._state_verdict(exchange, cand, label, ctl, tries, leftovers, restored, errors,
                                   refresh_failures, refused_by_gate, stateful, on_item)

    async def _write_back(self, client, write, read, fields, cand, url) -> bool | None:
        """Re-send the untampered body to an updated object; True when the read-back
        shows the original value again, None when nothing could read it."""
        obs = _Obs("restore", cand.original)
        await write(client, dict(fields), obs)
        _, obj = await read(client, url)
        if obj is None:
            return None
        found, stored = _leaf(obj, cand.path)
        return bool(found and _same(stored, cand.original))

    def _evidence(self, cand: _Field, t: _Obs, ctl: _Obs, session: dict, before, after):
        """(strong, weak) evidence that an accepted tamper took hold. Values only."""
        strong: list[str] = []
        weak: list[str] = []
        if not t.ok:
            return strong, weak
        value, key = t.value, cand.key
        leaf = _flat(cand.path[-1])
        own = lambda p: _flat(p.split(":", 1)[0].rsplit(".", 1)[-1]) == leaf   # the tampered key itself
        # A token reissued with changed privilege/tier claims.
        if t.claims:
            el = [e for e in _elevations(ctl.claims or session, t.claims)
                  if e not in _elevations(session, ctl.claims)]
            if el:
                strong.append(f"the response carried a reissued token whose claims changed "
                              f"({'; '.join(el[:3])})")
        # A state read of the write target that changed.
        if before is not None and after is not None:
            el = _elevations(before, after)
            if el:
                strong.append(f"a read of the target changed ({'; '.join(el[:3])})")
        # The response itself showing a privileged state the session did not have.
        if cand.family in _STATEFUL and t.echo is not None:
            base = _authority_state(ctl.echo) if ctl.ok and ctl.echo else session
            el = [e for e in _elevations(base, _authority_state(t.echo)) if not own(e)]
            if el and base:
                strong.append(f"the response shows a changed standing ({'; '.join(el[:3])})")
        # The read-back of the created or updated object.
        if t.obj is not None and cand.family != "payment":
            found, stored = _leaf(t.obj, cand.path)
            c_found, c_stored = _leaf(ctl.obj, cand.path) if ctl.obj is not None else (False, None)
            if found and _same(stored, value) and not (c_found and _same(c_stored, value)):
                said = f"the read-back stores {key}={stored!r} (the control stored {c_stored!r})" \
                    if c_found else f"the read-back stores {key}={stored!r}"
                n = _numeric(value)
                if cand.family == "quantity":
                    (strong if n is not None and n <= 0 else weak).append(said)
                elif cand.family == "currency":
                    m_t, m_c = _money(t.obj), _money(ctl.obj)
                    same = [p for p in m_t if p in m_c and m_t[p] == m_c[p]]
                    if same:
                        strong.append(f"{said} with the same amount(s) as the control "
                                      f"({', '.join(f'{p}={m_t[p]}' for p in same[:3])}): no conversion")
                    elif not m_t:
                        weak.append(said + " (no amount was shown to tell a conversion)")
                elif cand.family == "coupon":
                    weak.append(said)
                else:
                    strong.append(said)
            if cand.family in _STATEFUL and ctl.obj is not None:
                el = [e for e in _elevations(_authority_state(ctl.obj), _authority_state(t.obj))
                      if not own(e)]
                if el:
                    strong.append(f"the read-back shows a changed standing ({'; '.join(el[:3])})")
        # A changed total: a negative amount after a quantity tamper.
        if cand.family == "quantity":
            for src in (t.obj, t.echo):
                neg = {p: v for p, v in _money(src).items() if v < 0}
                if neg:
                    p, v = next(iter(neg.items()))
                    strong.append(f"the server computed a negative amount ({p}={v})")
                    break
        # A discount for a code that does not exist, or a total below the control's.
        if cand.family == "coupon":
            disc = _discounts(t.obj) or _discounts(t.echo)
            if disc and not (_discounts(ctl.obj) or _discounts(ctl.echo)):
                p, v = next(iter(disc.items()))
                strong.append(f"a nonexistent code earned a discount ({p}={v})")
            m_t, m_c = _money(t.obj or t.echo), _money(ctl.obj or ctl.echo)
            lower = [p for p in m_t if p in m_c and m_t[p] < m_c[p]]
            if lower:
                strong.append(f"the total fell below the control's ({lower[0]}: "
                              f"{m_c[lower[0]]} -> {m_t[lower[0]]})")
        if not strong and not weak and cand.family != "payment" and t.echo is not None:
            found, echoed = _leaf(t.echo, cand.path)
            if found and _same(echoed, value):
                weak.append(f"the response echoed {key}={echoed!r}, but no independent read showed it stored")
        return list(dict.fromkeys(strong)), list(dict.fromkeys(weak))

    def _state_verdict(self, exchange, cand, label, ctl, tries, leftovers, restored, errors,
                       refresh_failures, refused_by_gate, stateful, on_item) -> ValidationResult:
        method = (exchange.method or "POST").upper()
        path = urlsplit(exchange.url).path or "/"
        key = cand.key
        fc = "business_logic"
        sent = [f"control {key}={cand.original!r} -> " + (f"HTTP {ctl.status}" if ctl.status is not None
                                                          else ctl.error or "not sent")]
        sent += [f"{key}={t.value!r} -> " + (f"HTTP {t.status}" if t.status is not None else t.error or "no answer")
                 for t in tries]
        # Cleanup: what the probe left behind, never a token.
        made = [o for o in [ctl] + tries if o.created]
        if leftovers:
            cleanup = (f" RESTORE FAILED: {len(leftovers)} object(s) the probe created could not be "
                       f"removed and verified ({'; '.join(leftovers[:3])}).")
        elif made:
            cleanup = f" Every created object ({len(made)}) was deleted and its removal verified."
        else:
            cleanup = ""
        if restored is True:
            cleanup += f" The object was written back to {key}={cand.original!r} and the read-back verified it."
        elif restored is False:
            cleanup += f" RESTORE FAILED: the write-back of {key}={cand.original!r} did not read back."
        elif on_item and any(t.ok for t in tries):
            cleanup += f" The write-back of {key}={cand.original!r} was sent but no read could verify it."
        hit = next((t for t in tries if t.strong), None)
        if hit is not None and stateful and not on_item:
            cleanup += (" The accepted tamper changed the principal's standing and this leg knows no "
                        "route to undo it; an operator must revert it.")
        evidence = f"{method} {path}: " + "; ".join(sent) + "."
        artifacts = dict(baseline=ctl.resp, controls=[o.read for o in [ctl] + tries if o.read is not None])

        def result(status, summary, confidence=0.0, extra="", attack=None):
            return ValidationResult(
                self.name, status, fc, confidence=confidence, confirmed=status == "confirmed",
                summary=summary + cleanup, evidence=evidence + (" " + extra if extra else "")
            ).with_artifacts(attack=attack.resp if attack is not None else None, **artifacts)

        if refused_by_gate and not tries:
            return result("blocked", f"Client-trust check incomplete: the safety gate refused a write "
                                     f"({refused_by_gate}); not a negative result")
        if hit is not None:
            how = "; ".join(hit.strong[:3])
            if cand.family == "payment":
                return result("confirmed",
                              f"Excessive trust in client-side controls: the legitimate {key}="
                              f"{cand.original!r} was refused (HTTP {ctl.status}) but {key}={hit.value!r} "
                              f"was accepted (HTTP {hit.status}) and took effect: {how}.",
                              0.9, attack=hit)
            return result("confirmed",
                          f"Excessive trust in client-side controls: the server accepted a client-chosen "
                          f"{label} field {key}={hit.value!r} (HTTP {hit.status}; the control {key}="
                          f"{cand.original!r} was accepted) and it took effect: {how}.", 0.9, attack=hit)
        if ctl.error or (ctl.status is None and not refused_by_gate):
            return result("inconclusive", f"Client-trust check incomplete: the untampered control got no "
                                          f"response ({ctl.error or 'not sent'}); not a negative result")
        if ctl.created and not ctl.removed:
            return result("inconclusive", "Client-trust check stopped: the untampered control created an "
                                          "object that could not be removed and verified, so a tamper "
                                          "could collide with it; no tamper was sent")
        if cand.family == "payment" and ctl.ok:
            return result("inconclusive",
                          f"Client-trust check not decided: the untampered {key}={cand.original!r} was "
                          f"accepted (HTTP {ctl.status}), so an accepted unpaid {key} would prove nothing; "
                          f"no payment-source tamper was sent")
        if cand.family != "payment" and not ctl.ok:
            why = (f" (the in-session CSRF token could not be refreshed: {'; '.join(refresh_failures[:2])})"
                   if refresh_failures else "")
            return result("inconclusive",
                          f"Client-trust check not decided: the untampered control was refused "
                          f"(HTTP {ctl.status}){why}, so a refused tamper would prove nothing; no tamper "
                          f"was sent")
        if not tries:
            return result("inconclusive", f"Client-trust check not decided: the untampered control "
                                          f"returned HTTP {ctl.status}; no tamper was sent")
        lead = next((t for t in tries if t.weak), None)
        if lead is not None:
            return result("supported",
                          f"LEAD: the server accepted {label} {key}={lead.value!r} (HTTP {lead.status}) "
                          f"but did not show the effect took hold: {'; '.join(lead.weak[:2])}.", 0.4,
                          attack=lead)
        accepted = [t for t in tries if t.ok]
        if refused_by_gate or errors or any(t.status is None for t in tries):
            why = "; ".join(([f"refused by the safety gate ({refused_by_gate})"] if refused_by_gate else [])
                            + errors[:3])
            return result("inconclusive", f"Client-trust check incomplete: {why}; not a negative result")
        if tries and not accepted:
            if refresh_failures:
                return result("inconclusive",
                              f"Client-trust check incomplete: every tamper was refused, but the in-session "
                              f"CSRF token could not be refreshed ({'; '.join(refresh_failures[:2])}); "
                              f"not a negative result")
            held = (f"the legitimate {key}={cand.original!r} and every unpaid value were refused"
                    if cand.family == "payment" else
                    f"the control {key}={cand.original!r} was accepted and every tampered value was refused")
            return result("not_confirmed", f"The server enforces its own {label}: {held}.")
        if accepted and all(t.obj is None and not t.claims for t in accepted) and not on_item and \
                not any(t.created for t in accepted):
            return result("inconclusive",
                          f"Client-trust check not decided: the server accepted {label} "
                          f"{key}={accepted[0].value!r} (HTTP {accepted[0].status}) but no independent read "
                          f"or reissued token could show what it stored; not a negative result")
        return result("not_confirmed",
                      f"The server accepted the tampered {label} but stored or applied its own value: no "
                      f"read-back, token or total showed {key} take effect.")

    async def _refresh_csrf(self, client, exchange, fields: dict, ckey: str, kind: str,
                            failures: list[str]) -> dict:
        """Mint a fresh CSRF token in THIS session from the write's source page.
        A source page that never answered is recorded in `failures`."""
        from harness.validators.source_form import fetch_source_form

        def select(forms):
            for f in forms:
                tok = next((fld.value for fld in f.fields
                            if _CSRF_KEYS.search(fld.name or "") and fld.value), None)
                if tok:
                    return f
            return None

        try:
            found = await fetch_source_form(client, [exchange.url], self._headers(exchange), select,
                                            failures=failures)
            if found is not None:
                tok = next((fld.value for fld in found.form.fields
                            if _CSRF_KEYS.search(fld.name or "") and fld.value), None)
                if tok:
                    out = dict(fields); out[ckey] = tok
                    return out
        except SafetyGateBlocked as e:
            failures.append(f"GET {exchange.url}: refused ({e.decision.reason})")
        except Exception as e:
            failures.append(f"GET {exchange.url}: {e.__class__.__name__}")
        return fields
