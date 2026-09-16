"""
Stateful sequence leg -- Phase 3 (the missing confirmation SHAPE).

Every existing leg confirms by replaying ~one request and diffing the response.
That shape structurally cannot catch a bug whose effect shows up on a LATER,
DIFFERENT request: mass-assignment where a privileged field is silently accepted
(not echoed in the write's own response), self-assignment escalation, or a value
stored now and read back with new authority. The single-shot mass-assignment
probe in api_security even documents its own blind spot -- "a field silently
accepted but not echoed back would not be caught."

This leg is the A->verify-B differential that closes it:
  1. BASELINE read  -- GET the resource, record whether the privileged fields are set.
  2. MUTATE (A)     -- send the write with canonical privileged fields injected.
  3. VERIFY read (B)-- GET the resource AGAIN; if a privileged field is now set that
                       was not set in the baseline, the write both took AND persisted,
                       proven by an INDEPENDENT read -- not the mutation's own echo.

Session-13 generalisation (why it missed on a real target): the original leg only
injected a fixed set of privilege field NAMES and only looked for them at the TOP
LEVEL of the re-read response. Real APIs (a) name the field something outside that
list and (b) nest the object under a wrapper key (`{"user": {...}}`). So this
version also (a) derives AUTHORITY-named candidate fields from the resource's own
baseline schema and (b) detects a flipped field at ANY depth of the re-read
(recursive walk). Precision is preserved: schema-derived candidates are limited to
authority-named fields, and confirmation still requires an independent-read flip
against a baseline that did NOT have it -- the allowlisted control stays silent.

One mutating write (all candidate fields injected at once), bracketed by two
GETs, so it respects max_mutating_requests_per_finding. Scope-gated; the mutating
send is routed through the safety gate (needs validators.allow_mutating_replay).
"""
from __future__ import annotations

import json
import re
from urllib.parse import urlsplit, parse_qsl, urlencode

import httpx

from harness import global_throttle
from harness.models import Finding, HttpExchange
from harness.safety_gate import GatedAsyncClient, get_default_gate, SafetyGateBlocked
from .base import Validator, ValidationResult
from harness.validators.sqlmap import _looks_like_json, _content_type_of

# Canonical privilege/authority fields to inject. value = the privileged value.
_PRIV_FIELDS = {
    "role": "admin", "roles": "admin", "account_type": "admin", "privilege": "admin",
    "is_admin": True, "isAdmin": True, "admin": True, "is_staff": True, "isStaff": True,
    "is_superuser": True, "superuser": True, "verified": True, "isVerified": True,
    "email_verified": True, "approved": True,
}

# A field NAME is "authority-shaped" if it looks like it governs privilege, role,
# ownership, tenancy, plan/tier, or account status -- the class of field a client
# should not be able to set via mass-assignment. Used to derive extra candidate
# fields from the resource's OWN baseline schema (so a target that names its
# escalation field something outside _PRIV_FIELDS is still covered), kept narrow
# to preserve precision.
_AUTHORITY_RE = re.compile(
    r"admin|role|priv|superuser|super_user|staff|owner|tenant|verif|approv|"
    r"activ|enabl|premium|paid|vip|plan|tier|grade|level|access|perm|scope|"
    r"trust|confirm|elevat|is_|_admin|entitl|quota|credit|balance",
    re.I,
)


def _is_priv(value, priv) -> bool:
    """Whether a response value counts as the privileged value we injected --
    tolerant of bool vs "true" string and case."""
    if value is None:
        return False
    if isinstance(priv, bool):
        return value is True or str(value).strip().lower() == "true"
    return str(value).strip().lower() == str(priv).strip().lower()


def _walk(obj):
    """Yield every (key, value) pair in a nested dict/list structure, so a field
    bound one level down (`{"user": {"role": "admin"}}`) is still found."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield k, v
            if isinstance(v, (dict, list)):
                yield from _walk(v)
    elif isinstance(obj, list):
        for item in obj:
            yield from _walk(item)


def _present_privileged(obj, field, priv) -> bool:
    """True if `field` appears anywhere in the (possibly nested) response with the
    privileged value -- the recursive counterpart of a top-level `obj.get(field)`."""
    return any(k == field and _is_priv(v, priv) for k, v in _walk(obj))


class SequenceValidator(Validator):
    name = "sequence"
    finding_classes = {"mass_assignment", "mass assignment", "privilege_escalation",
                       "privilege escalation", "api_security", "api security",
                       "broken_access_control"}
    active = True

    def __init__(self, *, allowed_hosts: list[str] | None = None, timeout: float = 10.0):
        self.allowed_hosts = allowed_hosts or []
        self.timeout = timeout

    def _json_object(self, body: str):
        try:
            obj = json.loads(body)
        except (ValueError, TypeError):
            return None
        return obj if isinstance(obj, dict) else None

    def _form_object(self, body: str):
        """Parse a urlencoded form body into a flat {name: value} dict, or None if
        it doesn't look like one (no '=' pairs)."""
        body = body or ""
        if "=" not in body or (body.lstrip().startswith(("{", "["))):
            return None
        pairs = parse_qsl(body, keep_blank_values=True)
        return dict(pairs) if pairs else None

    def _parse_body(self, exchange: HttpExchange):
        """(kind, dict) for the request body: 'json' for a JSON object, 'form' for
        urlencoded. None when neither -- mass-assignment needs settable fields."""
        body = exchange.request_body or ""
        if _looks_like_json(body, _content_type_of(exchange)):
            obj = self._json_object(body)
            if obj is not None:
                return "json", obj
        form = self._form_object(body)
        if form is not None:
            return "form", form
        return None, None

    def _encode(self, kind: str, fields: dict) -> str:
        return json.dumps(fields) if kind == "json" else urlencode(fields)

    def applies(self, finding: Finding, exchange: HttpExchange) -> bool:
        if not super().applies(finding, exchange):
            return False
        if (exchange.method or "").upper() not in ("POST", "PUT", "PATCH"):
            return False
        kind, _ = self._parse_body(exchange)
        return kind is not None

    def _skip(self, why: str) -> ValidationResult:
        return ValidationResult(self.name, "skipped", "mass_assignment", summary=why)

    def _not_confirmed(self, why: str) -> ValidationResult:
        return ValidationResult(self.name, "not_confirmed", "mass_assignment",
                                confidence=0.0, confirmed=False, summary=why)

    async def _get_json(self, client, url, headers):
        await global_throttle.acquire()
        resp = await client.request("GET", url, headers=headers or None)
        try:
            return resp.status_code, json.loads(resp.text or "")
        except (ValueError, TypeError):
            return resp.status_code, None

    def _schema_candidates(self, baseline: dict, base_body: dict) -> dict:
        """Authority-named fields present in the resource's baseline that the
        request did not itself set -- injectable escalation candidates beyond the
        canonical list. A boolean field currently not-True -> try True; a string
        field not already 'admin' -> try 'admin'. Numbers are skipped (a bigger
        number is not unambiguously 'more privileged')."""
        out: dict = {}
        for k, v in _walk(baseline):
            if k in _PRIV_FIELDS or k in base_body or not isinstance(k, str):
                continue
            if not _AUTHORITY_RE.search(k):
                continue
            if isinstance(v, bool):
                if v is not True:
                    out[k] = True
            elif isinstance(v, str):
                if not _is_priv(v, "admin"):
                    out[k] = "admin"
        return out

    async def validate(self, finding: Finding, exchange: HttpExchange) -> ValidationResult:
        host = urlsplit(exchange.url).hostname or ""
        if self.allowed_hosts and host not in self.allowed_hosts:
            return self._skip(f"host {host!r} out of scope")
        method = (exchange.method or "").upper()
        kind, base_body = self._parse_body(exchange)
        if base_body is None:
            return self._skip("request body is not a JSON object or urlencoded form")
        # Fields not already privileged in the ORIGINAL request body.
        candidates = {f: v for f, v in _PRIV_FIELDS.items() if not _is_priv(base_body.get(f), v)}

        headers = {k: v for k, v in (exchange.request_headers or {}).items()
                   if k.lower() not in ("content-length", "host")}
        headers.setdefault("Content-Type",
                           "application/json" if kind == "json" else "application/x-www-form-urlencoded")
        try:
            async with GatedAsyncClient(get_default_gate(), self.name, timeout=self.timeout,
                                        follow_redirects=False, verify=False) as client:
                # 1. baseline read
                b_status, baseline = await self._get_json(client, exchange.url, headers)
                if not isinstance(baseline, dict):
                    return self._skip(f"resource not readable as a JSON object for a "
                                      f"differential (GET -> {b_status})")
                # Broaden with authority-named fields the resource itself exposes but
                # the request didn't set (covers escalation fields outside the canonical
                # list, e.g. a target-specific `is_premium`/`plan`/`org_owner`).
                candidates.update(self._schema_candidates(baseline, base_body))
                # keep only fields NOT already privileged on the resource (recursive).
                cands = {f: v for f, v in candidates.items()
                         if not _present_privileged(baseline, f, v)}
                if not cands:
                    return self._skip("no non-privileged candidate field to flip "
                                      "(request/resource already carry the privileged fields)")
                # 2. mutate (A): inject all candidate privileged fields in ONE write,
                #    encoded in the SAME format as the captured request (json or form).
                try:
                    await global_throttle.acquire()
                    await client.request(method, exchange.url, headers=headers,
                                         content=self._encode(kind, {**base_body, **cands}))
                except SafetyGateBlocked as e:
                    return self._skip(f"mutating replay not authorized: {e.decision.reason}")
                # 3. verify read (B): independent GET -- did any field persist (at any depth)?
                v_status, after = await self._get_json(client, exchange.url, headers)
                if not isinstance(after, dict):
                    return self._not_confirmed(f"verification read returned no JSON object "
                                               f"(GET -> {v_status})")
                flipped = [f for f, v in cands.items()
                           if _present_privileged(after, f, v) and not _present_privileged(baseline, f, v)]
        except httpx.HTTPError as e:
            return self._skip(f"request failed: {e.__class__.__name__}")

        if flipped:
            return ValidationResult(
                self.name, "confirmed", "mass_assignment", confidence=0.9, confirmed=True,
                summary=f"Mass-assignment / privilege escalation confirmed: field(s) {flipped} "
                        f"became privileged after a write and PERSISTED across an independent re-read.",
                evidence=f"Baseline GET showed {flipped} not privileged; after a {method} with those "
                         f"field(s) injected, a fresh GET shows them set (matched at any nesting depth). "
                         f"Proven by the write->re-read differential -- catching a silent accept the "
                         f"single-shot echo check misses.")
        return self._not_confirmed(
            "no injected privileged field persisted across the write->re-read differential")
