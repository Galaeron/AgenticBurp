"""Write-integrity verdict judges and record shaping: methods of WriteIntegrityValidator moved
verbatim out of write_integrity_validator.py (ARC-9). Every write, undo and scope check stays
in the validator module; these methods classify what came back."""

from __future__ import annotations

import json
from urllib.parse import urlsplit

from .cross_identity_validator import _PRIVILEGED_ROLE, _principal_for
from harness import naming
from .sequence_validator import _AUTHORITY_RE, _is_priv, _present_privileged
from .write_integrity_support import (
    BUSINESS_RULE_TAMPER, _Case, _created_id, CROSS_IDENTITY_WRITE, _field_of, _flat,
    FORGED_AUTHORSHIP, _ID_KEYS, _ID_SUFFIX, _item_url, log, _Made, _ok2xx, _pid, _Plan, _ref_stem,
    _refused, _same_value, _VARIANT_WORDS,
)


class _JudgingMixin:
    """Judges and record helpers; sends go through the validator's own `_send`."""

    def _readers(self, case: _Case) -> list:
        """Who may read back or delete what this case created: the writer first,
        then every other registered identity (a created account is often readable
        and deletable only by an administrator)."""
        out, seen = [case.actor], {(case.actor or {}).get("session_ref")}
        for ident in case.idents:
            if ident.get("session_ref") not in seen:
                seen.add(ident.get("session_ref"))
                out.append(ident)
        return out

    async def _find_by_marker(self, case: _Case, made: _Made, *, cleanup: bool) -> str:
        if not made.marker:
            return ""
        listing = await self._send(case, "GET", made.url, cleanup=cleanup)
        if not _ok2xx(listing):
            return ""
        try:
            doc = json.loads(listing.body or "")
        except (TypeError, ValueError):
            return ""
        items = doc if isinstance(doc, list) else next(
            (v for v in (doc or {}).values() if isinstance(v, list)), []) if isinstance(doc, dict) else []
        for item in items:
            if isinstance(item, dict) and made.marker in json.dumps(item):
                oid = next((str(v) for k, v in item.items() if _flat(k) in _ID_KEYS and str(v)), "")
                if oid:
                    return _item_url(made.url, oid)
        return ""

    def _record(self, case: _Case, made: _Made) -> None:
        artifact = getattr(made.sent, "artifact_id", "") if made.sent is not None else ""
        if not artifact or made.restored is None:
            return
        detail = (f"write_integrity {made.label} create deleted and verified gone ({made.item})"
                  if made.restored else
                  f"write_integrity {made.label} create NOT removed: {made.item or made.url} "
                  f"(delete HTTP {getattr(made.undo, 'status', None)})")
        try:
            from harness import run_handoff
            run_handoff.mark_restore(self.run_context, [artifact], ok=bool(made.restored), detail=detail)
        except Exception:
            log.debug("write_integrity: mark_restore failed", exc_info=True)

    @staticmethod
    def _stored_ref(plan: _Plan, obj: dict):
        """(found, value) of the reference field `plan` forged, in a read-back."""
        found, stored = _field_of(obj, plan.field)
        if not found:
            stem = naming.object_key(_ID_SUFFIX.sub("", plan.field) or plan.field)
            found, stored = next(((True, v) for k, v in obj.items() if _ref_stem(k) == stem),
                                 (False, None))
        return found, stored

    def _landed(self, plan: _Plan, made: _Made) -> bool:
        """The read-back of `made` stores the foreign reference: the object landed on
        the other principal's object (the only confirmation a variant gets)."""
        if made.obj is None or plan.other is None:
            return False
        found, stored = self._stored_ref(plan, made.obj)
        return bool(found) and _same_value(stored, plan.forged)

    def _deleter(self, case: _Case, plan: _Plan, made: _Made):
        """Whose sessions delete `made` first: the other principal when the object
        landed on its object, the writer for a variant, else the default order."""
        if case.kind == CROSS_IDENTITY_WRITE and self._landed(plan, made):
            return plan.other
        return case.actor if any(made is v for v in plan.sent) else None

    def _judge_cross_identity(self, case: _Case, plan: _Plan):
        status, summary, outcome = self._judge_reference(case, plan)
        if status == "confirmed" or not (plan.sent or plan.unsent):
            return status, summary, outcome
        plain = plan.attacks[0]
        landed = next((v for v in plan.sent if self._landed(plan, v)), None)
        if landed is not None:
            _, stored = self._stored_ref(plan, landed.obj)
            how = (f"refused (HTTP {plain.status})" if _refused(plain.sent) else
                   "bound to the writer's own object" if _ok2xx(plain.sent) else
                   f"answered HTTP {plain.status}")
            return ("confirmed", f"Cross-identity write by parameter pollution: {_pid(case.actor)!r} "
                                 f"created an object bound to {_pid(plan.other)!r}'s object by sending "
                                 f"{_VARIANT_WORDS.get(landed.label, landed.label)} ({plan.detail}; "
                                 f"HTTP {landed.status}); the read-back stores {plan.field}={stored!r}, "
                                 f"while the plain foreign reference was {how}", "")
        notes = []
        if plan.sent:
            notes.append("parameter-pollution variants did not land ("
                         + ", ".join(f"{v.label}: HTTP {v.status}" for v in plan.sent) + ")")
        if plan.unsent:
            notes.append("not sent: " + "; ".join(plan.unsent))
        lead = next((v for v in plan.sent if _ok2xx(v.sent) and v.obj is None), None)
        if lead is not None:
            return ("supported", f"LEAD: the server accepted {_VARIANT_WORDS.get(lead.label, lead.label)} "
                                 f"carrying {_pid(plan.other)!r}'s reference ({plan.detail}) but the "
                                 f"created object could not be read back; " + "; ".join(notes), "")
        # The plain reference's verdict stands; the summary names what else was tried
        # and what the headroom could not pay for.
        return status, summary + "; " + "; ".join(notes), outcome

    # -- verdicts --------------------------------------------------------------------

    def _judge_reference(self, case: _Case, plan: _Plan):
        """cross_identity_write, forged_authorship, business_rule_tamper: the attack
        sent one forged value; the verdict is what the server stored for it."""
        attack = plan.attacks[0]
        what = {CROSS_IDENTITY_WRITE: "a reference to another principal's object",
                FORGED_AUTHORSHIP: "an author/owner value that is not the writer's",
                BUSINESS_RULE_TAMPER: "an out-of-range value"}[case.kind]
        if _refused(attack.sent):
            return ("not_confirmed", f"The server refused a create carrying {what} "
                                     f"(HTTP {attack.status}; {plan.detail}) while the legitimate "
                                     f"create succeeded", "control_held")
        if not _ok2xx(attack.sent):
            return "inconclusive", f"The attack create returned HTTP {attack.status}", ""
        if attack.obj is None:
            return ("supported", f"LEAD: the server accepted a create carrying {what} "
                                 f"({plan.detail}) but the created object could not be read back", "")
        found, stored = _field_of(attack.obj, plan.field)
        if not found and case.kind == CROSS_IDENTITY_WRITE:
            stem = naming.object_key(_ID_SUFFIX.sub("", plan.field) or plan.field)
            found, stored = next(((True, v) for k, v in attack.obj.items() if _ref_stem(k) == stem),
                                 (False, None))
        if not found:
            return ("supported", f"LEAD: the server accepted a create carrying {what} "
                                 f"({plan.detail}); the read-back does not show {plan.field!r}", "")
        if _same_value(stored, plan.forged):
            summary = {
                CROSS_IDENTITY_WRITE: f"Cross-identity write: {_pid(case.actor)!r} created an object "
                                      f"bound to {_pid(plan.other)!r}'s object ({plan.detail}); the "
                                      f"read-back stores {plan.field}={stored!r}",
                FORGED_AUTHORSHIP: f"Forged authorship: {_pid(case.actor)!r} created an object whose "
                                   f"{plan.field} reads back as {stored!r}, not the writer "
                                   f"({plan.detail})",
                BUSINESS_RULE_TAMPER: f"Business-rule tampering: the server stored {plan.field}="
                                      f"{stored!r} ({plan.detail}); the legitimate create stored "
                                      f"{_field_of(plan.control.obj, plan.field)[1]!r}",
            }[case.kind]
            return "confirmed", summary, ""
        held = {CROSS_IDENTITY_WRITE: "the server bound the reference to the writer's own object",
                FORGED_AUTHORSHIP: "the server bound authorship to the session",
                BUSINESS_RULE_TAMPER: "the server normalized the value"}[case.kind]
        return ("not_confirmed", f"The server accepted the create but {held}: the read-back stores "
                                 f"{plan.field}={stored!r}, not {plan.forged!r}", "control_held")

    def _judge_mass_assignment(self, case: _Case, plan: _Plan):
        attack = plan.attacks[0]
        if _refused(attack.sent):
            return ("not_confirmed", f"The server refused a create carrying privileged fields "
                                     f"(HTTP {attack.status}) while the plain create succeeded",
                    "control_held")
        if not _ok2xx(attack.sent):
            return "inconclusive", f"The attack create returned HTTP {attack.status}", ""
        if attack.obj is None:
            return ("supported", "LEAD: the server accepted a create carrying privileged fields but "
                                 "the created object could not be read back", "")
        stored = sorted(f for f, v in plan.forged.items()
                        if _present_privileged(attack.obj, f, v)
                        and not _present_privileged(plan.control.obj, f, v))
        # A privileged value the server set on an authority-named field the plain
        # create did not have also counts (e.g. role -> "admin" under another key).
        if not stored:
            for k, v in attack.obj.items():
                if isinstance(k, str) and _AUTHORITY_RE.search(k) and not _same_value(
                        v, _field_of(plan.control.obj, k)[1]) and (_is_priv(v, "admin") or v is True):
                    stored.append(k)
        if stored:
            return ("confirmed", f"Mass assignment at create: the read-back of the created object "
                                 f"carries {', '.join(stored)} with the privileged value sent, which "
                                 f"the plain create did not get", "")
        return ("not_confirmed", "The server accepted the create but ignored the privileged fields: the "
                                 "read-back carries none of them", "control_held")

    def _judge_validation(self, case: _Case, plan: _Plan):
        notes, accepted, lead = [], [], []
        dups = [m for m in plan.attacks if m.label.startswith("duplicate")]
        if dups:
            first, second = dups
            if _ok2xx(first.sent) and _ok2xx(second.sent) and first.item and second.item \
                    and first.item != second.item:
                (accepted if first.obj is not None and second.obj is not None else lead).append(
                    f"a duplicate of a unique create was stored as a second object ({second.item})")
            elif _ok2xx(first.sent):
                notes.append(f"the duplicate was refused (HTTP {second.status})"
                             + (f" (not read back by logging in: {second.login_why})"
                                if plan.login_url and second.login_why else ""))
        empty = next(m for m in plan.attacks if m.label == "empty")
        unsettled = []
        if _ok2xx(empty.sent):
            if empty.obj is not None:
                # Only a field the read-back returns as "" counts: a field it never
                # returns (a password) says nothing about what was stored.
                blanks = [k for k in plan.field.split(",") if _field_of(empty.obj, k) == (True, "")]
                (accepted if blanks else lead).append(
                    f"a create with every string field empty was stored"
                    + (f" (read-back: {', '.join(blanks)} empty)" if blanks else ""))
            elif empty.login_result == "stored":
                accepted.append(f"a create with every string field empty was stored although its "
                                f"HTTP {empty.status} answer named no readable object: {empty.login_why}")
            else:
                lead.append("a create with every string field empty was accepted (HTTP "
                            f"{empty.status}) but could not be read back"
                            + (f" ({empty.login_why})" if empty.login_why else ""))
        elif empty.sent is not None:
            if empty.login_result == "stored":
                accepted.append(f"a create with every string field empty was stored despite HTTP "
                                f"{empty.status}: {empty.login_why}")
            elif empty.login_result in ("existing", "unsure"):
                unsettled.append(f"the empty create's HTTP {empty.status} cannot be counted as a refusal: "
                                 f"{empty.login_why}")
            else:
                notes.append(f"the empty create was refused (HTTP {empty.status})"
                             + (f" and {empty.login_why}" if empty.login_result == "not_stored" else
                                f" (not read back by logging in: {empty.login_why})" if empty.login_why
                                else ""))
        if accepted:
            return "confirmed", "Weak create validation: " + "; ".join(accepted + lead), ""
        if lead:
            return "supported", "LEAD: " + "; ".join(lead), ""
        if unsettled:
            return "inconclusive", "Create validation not settled: " + "; ".join(unsettled + notes), ""
        return ("not_confirmed", "The server enforces create validation: " + "; ".join(notes)
                + (f"; {plan.login_note}" if plan.login_note else ""), "control_held")

    def _no_update_object(self, case: _Case) -> str:
        """Why an author-carrying PUT/PATCH with no object id in its path cannot run."""
        ex = case.exchange
        method = (ex.method or "").upper()
        path = urlsplit(ex.url).path or "/"
        status = ex.response_status
        from types import SimpleNamespace
        oid = _created_id(SimpleNamespace(body=ex.response_body or "", headers=ex.response_headers or {}))
        if oid:
            answer = (f" (its answer names object {oid}, but a {method} to the collection adds an "
                      f"object rather than updating one)")
        else:
            answer = f" and its answer (HTTP {status}) names none" if status is not None else " and names none"
        adds = ""
        if status == 201 or oid:
            if not self._restore_route(ex.url):
                from harness.engagement import normalize_path
                adds = (f", and no DELETE route is known for what it adds (DELETE "
                        f"{normalize_path(_item_url(ex.url, '1'))})")
        return (f"write_integrity forged_authorship: the {method} to {path} does not end in an "
                f"object id{answer}, so there is no object to snapshot, read back or write back"
                f"{adds}; nothing was written")

    def _object_ref(self, url: str) -> str:
        from harness import principals
        return principals.object_reference(url, run_id=getattr(self.run_context, "run_id", "") or "")

    def _owner_fact(self, url: str, method: str):
        """The ownership fact for the object at `url` (the write's verb first, then
        GET), and whether it is an operator declaration; (None, False) when none."""
        if self.ownership is None:
            return None, False
        ref = self._object_ref(url)
        for verb in dict.fromkeys((method, "GET")):
            fact = self.ownership.lookup(ref, verb)
            if fact is not None:
                return fact, bool(self.ownership.has_declaration(ref, verb))
        return None, False

    def _update_reader(self, url: str, method: str, idents: list) -> tuple[dict | None, str]:
        """Who reads the object back and writes it back: its owner (an ownership
        fact naming a registered identity), else a registered admin.
        (identity, "owner"|"admin"), or (None, why there is none)."""
        fact, _ = self._owner_fact(url, method)
        owner_id = getattr(fact, "owner_principal_id", "") or ""
        if owner_id:
            owner = next((i for i in idents if _pid(i) == owner_id and i.get("session_ref")), None)
            if owner is not None:
                return owner, "owner"
        admin = next((i for i in idents if _PRIVILEGED_ROLE.search(i.get("role") or "")
                      and i.get("session_ref")), None)
        if admin is not None:
            return admin, "admin"
        return None, (f"its owner {owner_id!r} has no registered session and no admin session is "
                      f"registered" if owner_id else
                      "no owner is known for it and no admin session is registered")

    def _declared_boundary(self, writer, url: str, method: str) -> str:
        """Why a change `writer` (None: anonymous) made to the object at `url`
        crosses a boundary the operator declared, or "": an anonymous write to a
        route on authz.protected_paths or the engagement's protected_paths, or an authz.owners declaration that does not
        entitle the writer. Self-observed ownership is not a declaration."""
        if writer is None:
            try:
                from harness import protected_routes
                hit = protected_routes.ProtectedRoutes.for_target(
                    getattr(self.run_context, "config", None) or {}, url,
                    engagement_paths=getattr(self.run_context, "protected_paths", None) or None,
                ).match(method, url)
            except Exception:
                log.debug("write_integrity: protected routes failed", exc_info=True)
                hit = None
            if hit is not None:
                return f"an anonymous {method} to a route declared protected ({hit.describe()})"
        fact, declared = self._owner_fact(url, method)
        if fact is None or not declared:
            return ""
        from harness import principals
        principal = principals.Principal.anonymous() if writer is None else _principal_for(writer)
        ref = self._object_ref(url)
        decision = next((self.ownership.authorization(principal, ref, verb)
                         for verb in dict.fromkeys((method, "GET"))
                         if self.ownership.has_declaration(ref, verb)), None)
        if decision != principals.AuthzDecision.UNAUTHORIZED:
            return ""
        owner = getattr(fact, "owner_principal_id", "") or "another principal"
        return (f"authz.owners declares the object to {owner!r}, which does not entitle "
                f"{principal.id!r} ({fact.provenance})")
