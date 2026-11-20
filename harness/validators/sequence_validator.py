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
from harness import scope_lock

import json
import re
from urllib.parse import urlsplit, parse_qsl, urlencode

import httpx

from harness import global_throttle
from harness.control_outcome import CONTROL_HELD
from harness.models import Finding, HttpExchange, request_body_is_placeholder
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


_HIDES_OBJECT = re.compile(r"delet|remov|ban|block|lock|disabl|suspend|archiv|hidden|expir", re.I)


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


def _lists_a_collection(doc) -> bool:
    """True when a GET answered with a listing envelope ({"data": [{...}, ...]}):
    the URL names a collection, so a POST to it creates rather than updates."""
    if not isinstance(doc, dict) or "id" in doc or any(isinstance(v, dict) for v in doc.values()):
        return False
    return any(str(k).lower() in _LISTING_KEYS and isinstance(v, list)
               and (not v or isinstance(v[0], dict)) for k, v in doc.items())


# An identifier as the last path segment: a number, a long hex string or a uuid.
_ITEM_SEGMENT = re.compile(r"^(\d+|[0-9a-fA-F]{8,}|[0-9a-fA-F]{8}-[0-9a-fA-F-]{4,})$")


def _names_an_item(url: str) -> bool:
    """True when the URL's last path segment is an object id (an update target),
    False for a collection (where a POST creates)."""
    segments = [s for s in urlsplit(url or "").path.split("/") if s]
    return bool(segments) and bool(_ITEM_SEGMENT.match(segments[-1]))


_LISTING_KEYS = frozenset({"data", "items", "results", "records", "rows", "entries", "list",
                           "content", "elements", "hits", "objects"})


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
        if needs_read_body(exchange):
            return True
        kind, _ = self._parse_body(exchange)
        return kind is not None

    def _skip(self, why: str) -> ValidationResult:
        return ValidationResult(self.name, "skipped", "mass_assignment", summary=why)

    def _not_confirmed(self, why: str, control_outcome: str = "") -> ValidationResult:
        # EFF-1: control_outcome stays "" (unknown) unless the caller observed the
        # defence hold against a reference read (see validate_from_read).
        return ValidationResult(self.name, "not_confirmed", "mass_assignment",
                                confidence=0.0, confirmed=False, summary=why,
                                control_outcome=control_outcome)

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
        if self.allowed_hosts and not scope_lock.host_in_scope(exchange.url, self.allowed_hosts):
            return self._skip(f"host {host!r} out of scope")
        method = (exchange.method or "").upper()
        if needs_read_body(exchange):
            return await self.validate_from_read(exchange)
        if request_body_is_placeholder(exchange):
            # R11-6: the crawler's guessed body names no field of the endpoint; a
            # create (POST) has no object to read a body from or restore.
            return self._skip("the request body is a harness-guessed placeholder, not the "
                              "endpoint's parameters, and a create has no object to build a body "
                              "from; nothing was written")
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
                if not 200 <= (b_status or 0) < 300:
                    baseline = None   # an error document ({"error": ...}) is not the resource
                if not isinstance(baseline, dict):
                    if method == "POST" and not _names_an_item(exchange.url):
                        # The GET already carried the capture's own session: a create
                        # (often an anonymous signup) whose collection that session may
                        # not list. There is no object to diff before the write exists.
                        return self._skip(
                            f"POST to a collection is a create the capture's own session cannot "
                            f"read back (GET {urlsplit(exchange.url).path} -> {b_status}): handed to "
                            f"write_integrity (mass_assignment_create, restored by DELETE) and "
                            f"api_security's create check; nothing was written")
                    return self._skip(f"resource not readable as a JSON object for a "
                                      f"differential (GET -> {b_status})")
                if method == "POST" and _lists_a_collection(baseline):
                    # A POST to a collection CREATES an object this leg could never
                    # delete again. write_integrity's mass_assignment_create runs it
                    # with a plain-create control, a read-back and a verified DELETE.
                    return self._skip("POST to a collection is a create: handed to write_integrity "
                                      "(mass_assignment_create, restored by DELETE); nothing was written")
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

    # -- R11-6 (b): an update with no captured body, built from the object's read --

    def _read_candidates(self, fields: dict) -> dict:
        """Authority fields the READ itself holds (top level, settable, not already
        privileged), each with the privileged value to try. Only fields present in
        the read are injected: their snapshot value is what the restore writes back,
        so nothing is stored that the restore could not undo."""
        out: dict = {}
        for key, value in fields.items():
            if not isinstance(key, str) or not (key in _PRIV_FIELDS or _AUTHORITY_RE.search(key)):
                continue
            if _HIDES_OBJECT.search(key):
                continue   # a flag that could hide or lock the object from its own restore
            if isinstance(value, bool):
                if value is not True:
                    out[key] = True
            elif isinstance(value, str) and not isinstance(_PRIV_FIELDS.get(key), bool):
                if not _is_priv(value, "admin"):
                    out[key] = "admin"
        return out

    async def _read(self, client, url, headers):
        await global_throttle.acquire()
        resp = await client.request("GET", url, headers=headers or None)
        try:
            doc = json.loads(resp.text or "")
        except (ValueError, TypeError):
            doc = None
        return resp, (doc if 200 <= resp.status_code < 300 else None)

    async def validate_from_read(self, exchange: HttpExchange) -> ValidationResult:
        """Mass assignment on a PUT/PATCH of one object whose write was never
        captured (or only guessed): GET the object, send its settable fields back
        with the authority fields it holds set privileged, re-read it, then write
        the snapshot back and verify the object equals it (docs/WRITE_CHECKS.md:
        an update is restored to its snapshot and verified equal). The attack and
        its restore are both preflighted before either is sent."""
        import asyncio
        from harness.engagement import normalize_path
        from .base import artifact_id_of
        from .cross_identity_validator import _stable
        from .read_body import body_from_read, read_object, settable_fields
        method, url = (exchange.method or "").upper(), exchange.url
        path = normalize_path(url)
        if self.allowed_hosts and not scope_lock.host_in_scope(url, self.allowed_hosts):
            return self._skip(f"host {urlsplit(url).hostname!r} out of scope")
        gate = get_default_gate()
        _, _, ceiling = gate.mutating_headroom(None, self.name)
        if ceiling < 2:
            return self._skip(f"a write built from the read and its restore need 2 mutating sends "
                              f"(validators.mutating_ceiling_by_check.sequence >= 2; ceiling is {ceiling}); "
                              f"nothing was written")
        headers = {k: v for k, v in (exchange.request_headers or {}).items()
                   if k.lower() not in ("content-length", "host", "content-type")}
        headers["Content-Type"] = "application/json"
        read_headers = {k: v for k, v in headers.items() if k.lower() != "content-type"}
        wrote = after_doc = restored = check_doc = None
        attempted, failure, cancelled = False, "", False
        try:
            async with GatedAsyncClient(gate, self.name, timeout=self.timeout,
                                        follow_redirects=False, verify=False) as client:
                snap_resp, doc = await self._read(client, url, read_headers)
                fields, why = body_from_read(doc) if doc is not None else (
                    None, f"GET -> {snap_resp.status_code}")
                if fields is None:
                    return self._skip(f"no write body could be built from the read of {path} "
                                      f"({why}); nothing was written")
                original = read_object(doc)
                withheld = sorted(k for k in original if k not in fields)
                cands = self._read_candidates(fields)
                if not cands:
                    return self._skip(f"the read of {path} holds no non-privileged authority field "
                                      f"to flip; nothing was written")
                attack_body, restore_body = {**fields, **cands}, dict(fields)
                for body in (attack_body, restore_body):
                    decision = gate.authorize(validator_name=self.name, method=method, url=url,
                                              body=json.dumps(body))
                    if not decision.allowed:
                        return self._skip(f"write/restore preflight refused: {decision.reason}; "
                                          f"nothing was written")

                async def restore():
                    nonlocal restored, check_doc
                    from harness import run_handoff
                    with run_handoff.restore_scope(f"sequence_restore:{path}"):
                        await global_throttle.acquire()
                        restored = await client.request(method, url, headers=headers,
                                                        content=json.dumps(restore_body))
                    _, check_doc = await self._read(client, url, read_headers)

                try:
                    attempted = True
                    await global_throttle.acquire()
                    wrote = await client.request(method, url, headers=headers,
                                                 content=json.dumps(attack_body))
                    _, after_doc = await self._read(client, url, read_headers)
                except SafetyGateBlocked as e:
                    attempted = wrote is not None
                    failure = f"write not authorized: {e.decision.reason}"
                except asyncio.CancelledError:
                    cancelled = True
                except Exception as e:
                    failure = f"write raised {type(e).__name__}"
                finally:
                    if attempted:
                        task = asyncio.ensure_future(restore())
                        try:
                            try:
                                await asyncio.shield(task)
                            except asyncio.CancelledError:
                                cancelled = True
                                await task
                        except Exception as e:
                            failure += f"; restore raised {type(e).__name__}"
        except httpx.HTTPError as e:
            if not attempted:
                return self._skip(f"request failed: {e.__class__.__name__}")
            failure += f"; {e.__class__.__name__}"

        restore_ok = (not attempted) or (
            restored is not None and 200 <= restored.status_code < 300
            and read_object(check_doc) is not None
            and _stable(settable_fields(read_object(check_doc))) == _stable(fields))
        evidence = (f"body_source=read of GET {path}; sent_fields={sorted(fields)}; "
                    f"injected={sorted(cands)}; withheld_read_only={withheld}; "
                    f"write_status={getattr(wrote, 'status_code', None)}; "
                    f"restore={'sent' if restored is not None else 'not_sent'}; "
                    f"restore_status={getattr(restored, 'status_code', None)}; "
                    f"restore_succeeded={str(restore_ok).lower()}")
        try:
            from harness import run_handoff
            from harness.run_context import current_run_context
            ids = [i for i in [artifact_id_of(wrote)] if i]
            run_handoff.mark_restore(current_run_context(), ids, ok=restore_ok,
                                     detail=f"sequence restore {'verified' if restore_ok else 'NOT verified'} "
                                            f"on {path}")
        except Exception:
            pass
        if not restore_ok:
            message = (f"RESTORE FAILED: sequence could not write {path} back to its snapshot and "
                       f"verify it -- restore fields {sorted(cands)} by hand. {evidence}"
                       + (f" {failure}" if failure else ""))
            if cancelled:
                raise asyncio.CancelledError(message)
            return ValidationResult(self.name, "error", "mass_assignment", confidence=0.0,
                                    confirmed=False, summary=message, evidence=evidence)
        if cancelled:
            raise asyncio.CancelledError
        if wrote is None:
            return self._skip(f"mutating replay not authorized ({failure}); nothing was written")
        stored = read_object(after_doc) or {}
        flipped = sorted(f for f, v in cands.items()
                         if _is_priv(stored.get(f), v) and not _is_priv(original.get(f), v))
        if flipped and 200 <= wrote.status_code < 300:
            return ValidationResult(
                self.name, "confirmed", "mass_assignment", confidence=0.9, confirmed=True,
                summary=f"Mass-assignment / privilege escalation confirmed: field(s) {flipped} of "
                        f"{path} became privileged after a {method} built from the object's own "
                        f"read, and persisted across an independent re-read. Snapshot restored "
                        f"and verified.",
                evidence=evidence).with_artifacts(baseline=snap_resp, attack=wrote)
        # EFF-1: the control HELD only when the server accepted the write (2xx) and
        # the independent re-read shows every injected field -- so the read would
        # have revealed a flip, and it shows the field kept its unprivileged value.
        # A refused write or a read that omits the field compared nothing.
        held = (200 <= wrote.status_code < 300 and bool(stored)
                and all(f in stored for f in cands))
        return self._not_confirmed(
            f"no injected authority field persisted after a {method} built from the read of "
            f"{path} (write HTTP {wrote.status_code}); snapshot restored and verified. "
            f"{evidence}" + (f" {failure}" if failure else ""),
            control_outcome=CONTROL_HELD if held else "")


def needs_read_body(exchange: HttpExchange) -> bool:
    """R11-6: a PUT/PATCH of one object (its path ends in an id) whose request body
    is absent or the crawler's guess: the leg builds its body from the object's read."""
    if (exchange.method or "").upper() not in ("PUT", "PATCH") or not _names_an_item(exchange.url):
        return False
    return not (exchange.request_body or "").strip() or request_body_is_placeholder(exchange)
