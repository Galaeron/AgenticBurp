"""
Verb-tampering / HTTP method access-control bypass (V15, WSTG-CONF-06).

Safe subset: read-only method alternates (HEAD, OPTIONS, GET) + method-override
headers (X-HTTP-Method-Override, X-Method-Override, X-HTTP-Method). Confirms a
denial→2xx transition: an endpoint that denies the intended method (401/403) but
serves a substantive 2xx for a different method or override has a method-scoped
authorization hole.

By default does NOT send blind PUT/DELETE. The mutating-method case (the common
high-value shape: GET-protected but PUT/PATCH/DELETE-open) is gated behind an
explicit opt-in `validators.verb_tamper.try_mutating_methods` (off by default),
and even then every mutating send goes through the safety gate + allow_mutating_replay
(triple-gated) per LEG_DECISIONS.md #1. Active; scope-gated.

An override is a POST. A server that ignores the override header executes it as
a POST, and on a collection that creates an object: an answer with a 201, a
Location header, or a JSON body naming an id the URL does not carry. That is a
negative for the bypass, never an observation. The object is named in the result
and in the run's change log; with a known DELETE route (the engagement's route
inventory or `validators.write_integrity.restore_routes`) a 201/Location create
is deleted and verified gone, otherwise it is named as left in place and the
remaining override POSTs are withheld (each would create another). An id named
only by the body is never deleted on that alone: it could be an existing object
the override honoured. Before any override POST, a path where this run already
saw a POST create, with no DELETE route known, gets none at all (the result says
why and is not a negative).
"""
from __future__ import annotations
from harness import scope_lock

import logging
from types import SimpleNamespace
from urllib.parse import urljoin, urlsplit, urlunsplit

from harness import global_throttle
from harness.models import Finding, HttpExchange
from harness.safety_gate import GatedAsyncClient, get_default_gate, SafetyGateBlocked
from .base import Validator, ValidationResult, artifact_id_of
from .injection_targets import replay_headers

log = logging.getLogger(__name__)

_OVERRIDE_HEADERS = ("X-HTTP-Method-Override", "X-Method-Override", "X-HTTP-Method")
_SAFE_METHODS = ("HEAD", "OPTIONS", "GET")
# Only reached under the explicit try_mutating_methods opt-in + allow_mutating_replay.
_MUTATING_METHODS = ("PUT", "PATCH", "DELETE")


def _path_segments(url: str) -> set[str]:
    return {s for s in urlsplit(url).path.split("/") if s}


def _created(url: str, status, headers, body: str) -> dict | None:
    """What a 2xx answer to an override POST shows the server CREATED, or None.

    `strong` (201, or a Location header) is a create beyond doubt; an id named
    only by the JSON body (and not already in the URL) is read as a create too,
    but could be an existing object an honoured override returned."""
    if status is None or not 200 <= status < 300:
        return None
    from .write_integrity_validator import _created_id, _item_url
    lower = {str(k).lower(): v for k, v in (headers or {}).items()}
    location = str(lower.get("location") or "").strip()
    in_path = _path_segments(url)
    body_id = _created_id(SimpleNamespace(body=body, headers={}))
    if body_id in in_path:
        body_id = ""
    item, oid = "", body_id
    if location:
        target = urljoin(url, location)
        parts = urlsplit(target)
        if parts.netloc.lower() == urlsplit(url).netloc.lower():
            item = urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
            last = [s for s in parts.path.split("/") if s]
            oid = oid or (last[-1] if last and last[-1] not in in_path else "")
    if not item and body_id:
        item = _item_url(url, body_id)
    if status == 201 or location:
        why = f"HTTP {status}" + (f", Location: {location[:200]}" if location else "")
        return {"strong": True, "item": item, "id": oid, "why": why}
    if body_id:
        return {"strong": False, "item": item, "id": body_id,
                "why": f"HTTP {status}, the body names id {body_id!r} (no 201 or Location)"}
    return None


class VerbTamperValidator(Validator):
    name = "verb_tamper"
    finding_classes = {"misconfig", "misconfiguration", "verb tamper", "verb_tamper",
                       "method tampering", "http method", "http_method"}
    active = True

    def __init__(self, *, allowed_hosts: list[str] | None = None, timeout: float = 10.0,
                 try_mutating_methods: bool = False, run_context=None,
                 restore_routes=(), route_inventory=None):
        self.allowed_hosts = allowed_hosts or []
        self.timeout = timeout
        # Off by default: sending a blind PUT/DELETE to an endpoint we have not
        # confirmed is safe to mutate can destroy data. When on, still gated by
        # the safety gate (allow_mutating_replay).
        self.try_mutating_methods = bool(try_mutating_methods)
        self.run_context = run_context
        # Where an override POST's create can be undone: declared routes
        # ("DELETE /api/things/{id}") plus a callable route inventory (the drive's
        # engagement endpoints), as write_integrity finds its restore routes.
        self.restore_routes = tuple(restore_routes or ())
        self.route_inventory = route_inventory

    async def _request(self, method: str, url: str, headers: dict, *, cleanup: bool = False):
        if self.run_context is not None:
            from harness.run_context import TypedRequest
            from .transport import bind_session
            session_ref, request_headers = bind_session(self.run_context, headers)
            return await self.run_context.executor().execute(
                TypedRequest(method, url, headers=request_headers),
                capability=self.name, session_ref=session_ref,
                **({"allow_cancelled_cleanup": True} if cleanup else {}))
        await global_throttle.acquire()
        async with GatedAsyncClient(get_default_gate(), self.name, timeout=self.timeout,
                                    follow_redirects=False, verify=False) as client:
            return await client.request(method, url, headers=headers or None)

    def _response_parts(self, response):
        if self.run_context is not None:
            if not response.executed or response.outcome == "error":
                return None, ""
            return response.status, response.body or ""
        return response.status_code, response.text or ""

    def _headers_of(self, response) -> dict:
        if response is None:
            return {}
        return dict(getattr(response, "headers", None) or {})

    # -- restore routes ---------------------------------------------------------

    def _delete_route_known(self, item_url: str) -> bool:
        from harness.engagement import normalize_path
        from .write_integrity_validator import route_set
        routes = list(self.restore_routes)
        if callable(self.route_inventory):
            try:
                routes += list(self.route_inventory() or ())
            except Exception:
                log.debug("verb_tamper: route inventory failed", exc_info=True)
        template = normalize_path(item_url).rstrip("/").lower()
        return ("DELETE", template) in route_set(routes)

    def _observed_create(self, url: str) -> dict | None:
        """A change-log entry showing this run already saw a POST to this path
        create an object (201, or a created id), else None."""
        change_log = getattr(self.run_context, "change_log", None)
        if change_log is None:
            return None
        from harness.engagement import normalize_path
        from harness.run_handoff import RESTORE_SEND
        key, host = normalize_path(url), urlsplit(url).netloc.lower()
        try:
            entries = change_log.entries()
        except Exception:
            return None
        for entry in entries:
            if (entry.get("method") == "POST" and entry.get("host") == host
                    and entry.get("restore_status") != RESTORE_SEND
                    and normalize_path(entry.get("path") or "") == key
                    and (entry.get("status") == 201
                         or str(entry.get("object_ref") or "").startswith("created:"))):
                return entry
        return None

    async def _undo(self, finding: Finding, made: dict, headers: dict) -> bool:
        """DELETE the created item and read it back. True when the read shows it gone."""
        from harness import run_handoff
        from .write_integrity_validator import _absent
        item = made["item"]
        ref = f"{getattr(finding, 'finding_id', '') or self.name}:verb_tamper_restore"
        undo = check = None
        try:
            with run_handoff.restore_scope(ref):
                undo = await self._request("DELETE", item, headers, cleanup=True)
                check = await self._request("GET", item, headers, cleanup=True)
        except Exception as e:
            made["undo_error"] = f"{e.__class__.__name__}: {e}"[:200]
        if self.run_context is None and check is not None:
            check = SimpleNamespace(ok=True, status=check.status_code, body=check.text or "")
        made["undo_status"] = (getattr(undo, "status", None) if self.run_context is not None
                               else getattr(undo, "status_code", None))
        return _absent(check)

    async def _handle_create(self, finding: Finding, made: dict, header: str, resp,
                             headers: dict) -> dict:
        """Record (and, when it can be undone, undo) the object an override POST
        created. Sets made["restore"]: deleted_verified | restore_failed | left_in_place."""
        from harness import run_handoff
        from harness.engagement import normalize_path
        made["header"], made["artifact"] = header, artifact_id_of(resp)
        made["object"] = made["item"] or f"an object created at {urlsplit(made['url']).path}"
        oref = f"created:{made['id']}" if made["id"] else (urlsplit(made["item"]).path if made["item"] else "")
        if not made["strong"]:
            made["restore"] = "left_in_place"
            made["left_why"] = ("only the answer's body names the id; deleting on that alone could "
                                "remove an object that already existed")
        elif not made["item"]:
            made["restore"] = "left_in_place"
            made["left_why"] = "the answer names no object to delete"
        elif not self._delete_route_known(made["item"]):
            made["restore"] = "left_in_place"
            made["left_why"] = (f"no DELETE route is known for {normalize_path(made['item'])} "
                                f"(route inventory or validators.write_integrity.restore_routes)")
        else:
            gone = await self._undo(finding, made, headers)
            made["restore"] = "deleted_verified" if gone else "restore_failed"
        if made["artifact"]:
            if made["restore"] == "left_in_place":
                run_handoff.note_object(self.run_context, [made["artifact"]], object_ref=oref,
                                        detail=f"verb_tamper override POST create LEFT IN PLACE: "
                                               f"{made['object']} ({made['left_why']})")
            else:
                run_handoff.note_object(self.run_context, [made["artifact"]], object_ref=oref)
                run_handoff.mark_restore(
                    self.run_context, [made["artifact"]], ok=made["restore"] == "deleted_verified",
                    detail=(f"verb_tamper override POST create deleted and verified gone ({made['item']})"
                            if made["restore"] == "deleted_verified" else
                            f"verb_tamper override POST create NOT removed: {made['item']} "
                            f"(delete HTTP {made.get('undo_status')})"))
        if made["restore"] == "left_in_place":
            log.warning("verb_tamper: POST + %s was executed as a POST and created %s; "
                        "left in place (%s)", header, made["object"], made["left_why"])
        elif made["restore"] == "restore_failed":
            log.error("RESTORE FAILED: verb_tamper POST + %s created %s; the DELETE did not "
                      "verify it gone -- remove it manually", header, made["item"])
        return made

    @staticmethod
    def _creates_note(creates: list[dict]) -> str:
        if not creates:
            return ""
        parts = []
        for m in creates:
            state = {"deleted_verified": "deleted and verified gone",
                     "restore_failed": "RESTORE FAILED",
                     "left_in_place": f"LEFT IN PLACE ({m.get('left_why', '')})"}[m["restore"]]
            parts.append(f"POST + {m['header']} -> {m['why']}: created {m['object']}"
                         + (f" [artifact {m['artifact']}]" if m.get("artifact") else "")
                         + f", {state}")
        return " Override POST create(s): " + "; ".join(parts) + "."

    def applies(self, finding: Finding, exchange: HttpExchange) -> bool:
        # A denial-bypass test: with no captured denial there is nothing to tamper
        # past, so a "misconfig" finding on a 2xx read (r5: exposed admin
        # configuration data) is never routed here to be "tested" by a skip.
        if (exchange.response_status or 0) not in (401, 403, 405):
            return False
        return super().applies(finding, exchange)

    def _skip(self, why: str) -> ValidationResult:
        return ValidationResult(self.name, "skipped", "misconfig", summary=why)

    async def validate(self, finding: Finding, exchange: HttpExchange) -> ValidationResult:
        host = urlsplit(exchange.url).hostname or ""
        if self.allowed_hosts and not scope_lock.host_in_scope(exchange.url, self.allowed_hosts):
            return self._skip(f"host {host!r} out of scope")
        url = exchange.url
        orig_method = (exchange.method or "GET").upper()
        headers = replay_headers(exchange)
        orig_status = exchange.response_status or 0

        if 200 <= orig_status < 300:
            return self._skip("original request already succeeded (2xx) — no denial to bypass")

        if orig_status not in (401, 403, 405):
            return self._skip(f"original status {orig_status} is not a denial (401/403/405)")

        # Sends that got no response (RV-P P6): an alternate or override that was
        # never answered is not part of a negative. A refusal that ends the run
        # (budget, cancellation) stops the remaining sends.
        refused: list[str] = []
        errors: list[str] = []
        # Override POSTs deliberately not sent (each would create an object that
        # cannot be undone), and answers that cannot tell a create from a read:
        # neither is part of a negative.
        withheld: list[str] = []
        creates: list[dict] = []
        planned = 0
        stopped = False

        async def probe(label: str, method: str, h: dict):
            nonlocal planned, stopped
            planned += 1
            if stopped:
                refused.append(f"{label}: not sent after the run stopped")
                return None, "", None
            try:
                resp = await self._request(method, url, h)
            except SafetyGateBlocked as e:
                refused.append(f"{label}: refused ({e.decision.reason})")
                return None, "", None
            except Exception as e:
                errors.append(f"{label}: {e.__class__.__name__}")
                return None, "", None
            if self.run_context is not None and not resp.ok:
                if not resp.executed:
                    refused.append(f"{label}: refused by the run ({resp.outcome})")
                    stopped = resp.outcome in ("budget_exhausted", "cancelled")
                else:
                    art = getattr(resp, "artifact", None)
                    errors.append(f"{label}: {getattr(art, 'transport_outcome', '') or resp.error}")
                return None, "", None
            status, text = self._response_parts(resp)
            return status, text, resp

        for method in _SAFE_METHODS:
            if method == orig_method:
                continue
            status, text, _ = await probe(method, method, headers)
            if status is not None and 200 <= status < 300 and len(text) > 10:
                # RETIRED (review 2026-09-09): an alternate method returning 2xx where
                # the original was denied is NOT proof of an authz bypass -- it can be
                # ordinary routing (a public GET beside a private POST). It no longer
                # sets confirmed=True. Re-qualify: compare the SAME protected data/
                # action under the SAME unauthorized principal across methods, with a
                # public-GET/private-write control; only then confirmed=True.
                return ValidationResult(
                    self.name, "not_confirmed", "misconfig", confidence=0.4, confirmed=False,
                    summary=f"OBSERVATION (not confirmed): {orig_method} returns {orig_status} but "
                            f"{method} returns {status} with a substantive body -- may be "
                            f"ordinary routing, not an authz bypass; needs a same-principal same-data control.",
                    evidence=f"Original: {orig_method} {url} -> {orig_status}. "
                             f"Alternate: {method} -> {status} ({len(text)} bytes).")

        # A POST here already created objects in this run and nothing can undo one:
        # an override the server ignores would create another, so none is sent.
        from .write_integrity_validator import _item_url
        observed = self._observed_create(url)
        if observed is not None and not self._delete_route_known(_item_url(url, "1")):
            from harness.engagement import normalize_path
            reason = (f"not sent: a POST to {urlsplit(url).path} created an object earlier in this run "
                      f"(change log #{observed.get('seq')}, {observed.get('object_ref') or 'HTTP 201'}) "
                      f"and no DELETE route is known for {normalize_path(_item_url(url, '1'))} to undo "
                      f"another (route inventory or validators.write_integrity.restore_routes)")
            for override_header in _OVERRIDE_HEADERS:
                planned += 1
                withheld.append(f"POST + {override_header}: {reason}")
            override_headers = ()
        else:
            override_headers = _OVERRIDE_HEADERS

        undoable = bool(override_headers) and self._delete_route_known(_item_url(url, "1"))
        for idx, override_header in enumerate(override_headers):
            remaining = (self.run_context.budget.remaining
                         if undoable and self.run_context is not None else None)
            if remaining is not None and remaining < 3:
                # A create here would be deleted and read back: never send a POST
                # whose cleanup the run could not pay for.
                rest = override_headers[idx:]
                planned += len(rest)
                withheld.extend(f"POST + {r}: not sent: the run's request budget ({remaining} left) "
                                f"cannot pay for the POST plus the delete and read-back a create needs"
                                for r in rest)
                break
            h = dict(headers or {})
            h[override_header] = orig_method
            status, text, resp = await probe(f"POST + {override_header}", "POST", h)
            made = _created(url, status, self._headers_of(resp), text)
            if made is not None:
                # The override was ignored: the server executed a POST and created an
                # object. A negative for the bypass -- never an observation.
                made["url"] = url
                await self._handle_create(finding, made, override_header, resp, headers)
                creates.append(made)
                if made["restore"] == "restore_failed":
                    message = (f"RESTORE FAILED: verb_tamper's POST + {override_header}: {orig_method} "
                               f"was executed as a POST and created {made['item']}; the DELETE did "
                               f"not verify it gone -- remove it manually.")
                    return ValidationResult(
                        self.name, "error", "misconfig", confidence=0.0, confirmed=False,
                        summary=message,
                        evidence=f"Original: {orig_method} {url} -> {orig_status}."
                                 + self._creates_note(creates),
                        limitation="An override POST the server ignored created an object that "
                                   "could not be removed and verified gone.")
                if not made["strong"]:
                    withheld.append(f"POST + {override_header}: {made['why']} -- read as a create "
                                    f"(left in place), but it could be the override honoured")
                if made["restore"] != "deleted_verified":
                    rest = override_headers[idx + 1:]
                    planned += len(rest)
                    withheld.extend(
                        f"POST + {r}: not sent: the POST + {override_header} override created "
                        f"{made['object']}, left in place; another would create another" for r in rest)
                    break
                continue
            if status is not None and 200 <= status < 300 and len(text) > 10:
                # RETIRED (review 2026-09-09) -- see the note above; observation only.
                return ValidationResult(
                    self.name, "not_confirmed", "misconfig", confidence=0.4, confirmed=False,
                    summary=f"OBSERVATION (not confirmed): POST with {override_header}: {orig_method} "
                            f"returns {status} (original {orig_method} returns {orig_status}) "
                            f"-- needs a same-principal same-data control to distinguish a real bypass.",
                    evidence=f"Original: {orig_method} {url} -> {orig_status}. "
                             f"Override: POST + {override_header}: {orig_method} -> {status}."
                             + self._creates_note(creates))

        # Opt-in mutating-method variant: the common exploitable shape is a
        # GET/POST-denied endpoint that serves a mutating method. Triple-gated
        # (this flag + active_enabled + allow_mutating_replay via GatedAsyncClient).
        if self.try_mutating_methods:
            for method in _MUTATING_METHODS:
                if method == orig_method:
                    continue
                n_refused = len(refused)
                status, text, _ = await probe(method, method, headers)
                if len(refused) > n_refused:
                    # mutating replay not authorized -- stop trying mutating methods.
                    rest = [m for m in _MUTATING_METHODS[_MUTATING_METHODS.index(method) + 1:]
                            if m != orig_method]
                    refused.extend(f"{m}: not sent after {method} was refused" for m in rest)
                    planned += len(rest)
                    break
                if status is not None and 200 <= status < 300 and len(text) > 10:
                    # RETIRED (review 2026-09-09) -- see the note above; observation only.
                    return ValidationResult(
                        self.name, "not_confirmed", "misconfig", confidence=0.4, confirmed=False,
                        summary=f"OBSERVATION (not confirmed, mutating): {orig_method} returns {orig_status} "
                                f"but {method} returns {status} with a substantive body -- "
                                f"needs a same-principal same-data control to distinguish a real bypass.",
                        evidence=f"Original: {orig_method} {url} -> {orig_status}. "
                                 f"Mutating alternate: {method} -> {status} "
                                 f"({len(text)} bytes). Sent under the try_mutating_methods opt-in "
                                 f"+ allow_mutating_replay." + self._creates_note(creates))

        tried_mut = f" + {len(_MUTATING_METHODS)} mutating methods" if self.try_mutating_methods else ""
        left = [m["object"] for m in creates if m["restore"] == "left_in_place"]
        deleted = sum(1 for m in creates if m["restore"] == "deleted_verified")
        created_note = ""
        if creates:
            created_note = (f" The override was ignored: {len(creates)} override POST(s) were executed "
                            f"as POSTs and created objects; {deleted} deleted and verified gone"
                            + (f"; LEFT IN PLACE: {' | '.join(left)}" if left else "") + ".")
        if refused or errors or withheld:
            unanswered = refused + errors + withheld
            answered = planned - len(refused) - len(errors) - len(withheld)
            what = "got no response" if not withheld else "got no response or were withheld"
            return ValidationResult(
                self.name,
                "blocked" if (refused or withheld) and not errors and not answered else "inconclusive",
                "misconfig", confidence=0.0, confirmed=False,
                summary=f"Verb-tamper check incomplete: {len(unanswered)} of {planned} send(s) {what} "
                        f"({'; '.join(unanswered[:4])}); not a negative result"
                        + ("." + created_note if created_note else ""),
                evidence=f"Original: {orig_method} {url} -> {orig_status}. {answered} answered "
                         f"alternate(s)/override(s) returned no substantive 2xx; the unanswered ones "
                         f"were never tested." + self._creates_note(creates))
        if creates:
            return ValidationResult(
                self.name, "not_confirmed", "misconfig", confidence=0.0, confirmed=False,
                summary="No verb-tamper bypass." + created_note,
                evidence=f"Original: {orig_method} {url} -> {orig_status}. Tried "
                         f"{len(_SAFE_METHODS)-1} safe alternate methods + {len(_OVERRIDE_HEADERS)} "
                         f"override headers{tried_mut}; none returned a substantive 2xx read."
                         + self._creates_note(creates))
        return ValidationResult(
            self.name, "not_confirmed", "misconfig", confidence=0.0, confirmed=False,
            summary="No verb-tamper bypass found with safe methods and override headers"
                    + (" or mutating methods" if self.try_mutating_methods else "") + ".",
            evidence=f"Tried {len(_SAFE_METHODS)-1} safe alternate methods + {len(_OVERRIDE_HEADERS)} "
                     f"override headers{tried_mut}; none returned a substantive 2xx.")
