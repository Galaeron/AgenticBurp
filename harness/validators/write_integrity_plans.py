"""Write-integrity plan builders (which identities, which payload variants): the planning methods
of WriteIntegrityValidator, moved verbatim out of write_integrity_validator.py (ARC-9). The
login plan that spends the gate (_plan_logins) stays in the validator module."""

from __future__ import annotations

import json
import secrets
from urllib.parse import urlsplit, urlunsplit

from harness import naming
from .sequence_validator import _PRIV_FIELDS
from .write_integrity_support import (
    _Case, _EMAILISH, _field_of, _flat, _ID_SEGMENT, _ID_SUFFIX, _json_object, _LOGIN_PATH, _Made,
    _MONEY, _NOT_LOGIN_PATH, _number, _PASSWORD_KEY, _PERSON_STEMS, _pid, _Plan, _polluted,
    _QUANTITY, _RATING, _ref_stem, _same_value, _TAMPER_VALUE, _UNIQUE_KEY, _unique_keys,
    _uniquify,
)


class _PlanningMixin:
    """Pure plan builders; every method reads only its arguments and `self`."""

    @staticmethod
    def _login_keys(body: dict) -> tuple[str, str]:
        """(identifier key, password key) of a login or sign-up body ("" when absent)."""
        ident = next((k for k in body if _UNIQUE_KEY.match(_flat(k))), "")
        password = next((k for k in body if _PASSWORD_KEY.match(_flat(k))), "")
        return ident, password

    def _login_target(self, case: _Case) -> tuple[str, dict | None, str]:
        """(url, captured login body or None, where it was observed) of a login the
        run observed on the sign-up's origin: a captured login exchange first, then a
        POST route in the route inventory. ("", None, "") when it observed none."""
        parts = urlsplit(case.exchange.url)
        origin = f"{parts.scheme}://{parts.netloc}"

        def is_login(path: str) -> bool:
            return bool(_LOGIN_PATH.search(path)) and not _NOT_LOGIN_PATH.search(path)

        context = getattr(self.run_context, "experiment_context", None)
        captured = (context.get("captured") if isinstance(context, dict) else None) or ()
        for item in list(captured)[:500]:
            def get(key, _item=item):
                return _item.get(key) if isinstance(_item, dict) else getattr(_item, key, None)
            p = urlsplit(str(get("url") or ""))
            if (str(get("method") or "").upper() != "POST" or f"{p.scheme}://{p.netloc}" != origin
                    or not is_login(p.path)):
                continue
            body = _json_object(get("request_body"))
            if body and all(self._login_keys(body)):
                return (urlunsplit((p.scheme, p.netloc, p.path, p.query, "")), body,
                        f"a captured login (POST {p.path})")
        for route in self._route_entries():
            bits = str(route).split(None, 1)
            if len(bits) != 2 or bits[0].upper() != "POST":
                continue
            path = bits[1].strip()
            if path.lower().startswith(("http://", "https://")):
                p = urlsplit(path)
                if f"{p.scheme}://{p.netloc}" != origin:
                    continue
                path = p.path
            if path.startswith("/") and "{" not in path and is_login(path):
                return origin + path, None, f"the route inventory (POST {path})"
        return "", None, ""

    def _others_refs(self, principal_id: str) -> dict[str, list[str]]:
        """{object type: [ids]} of the objects the run knows `principal_id` owns:
        operator declarations first, then self-observed ownership."""
        refs: dict[str, list[str]] = {}
        ledger = self.ownership
        if ledger is not None and hasattr(ledger, "owned_objects"):
            for collection, oid in ledger.owned_objects(principal_id):
                refs.setdefault(naming.object_key(collection), []).append(oid)
        observed = getattr(self.run_context, "self_ownership", None)
        if observed is not None and hasattr(observed, "owned_objects"):
            for stem, oid in observed.owned_objects(principal_id):
                if oid not in refs.setdefault(stem, []):
                    refs[stem].append(oid)
        return refs

    def _account_ids(self, principal_id: str) -> list[str]:
        ids = list(self._others_refs(principal_id).get("user", []))
        observed = getattr(self.run_context, "self_ownership", None)
        if observed is not None and hasattr(observed, "account_ids"):
            ids += [i for i in observed.account_ids(principal_id) if i not in ids]
        return ids

    def _plan_cross_identity(self, case: _Case):
        if case.actor is None:
            return "needs the capture to be an authenticated, registered session"
        if not case.others:
            return "no distinct non-privileged principal is registered"
        own = self._others_refs(_pid(case.actor))
        url = case.exchange.url
        for other in case.others:
            theirs = self._others_refs(_pid(other))
            for key, value in case.body.items():
                stem = _ref_stem(key)
                if not stem or stem in _PERSON_STEMS or not isinstance(value, (int, str)) or isinstance(value, bool):
                    continue
                candidates = [o for o in theirs.get(stem, ()) if str(o) != str(value)
                              and str(o) not in own.get(stem, ())]
                if not candidates:
                    continue
                forged = int(candidates[0]) if isinstance(value, int) and candidates[0].isdigit() else candidates[0]
                ctl_body, ctl_marker = _uniquify(case.body, "c" + secrets.token_hex(4))
                atk_body, atk_marker = _uniquify(case.body, "a" + secrets.token_hex(4))
                atk_body[key] = forged
                # Parameter pollution: an ownership check and the code that stores the
                # reference may read different members of a duplicate key, or one
                # element of an array, so the same foreign reference is also tried
                # alongside the writer's own one, in both orders.
                variants = []
                for label, first, last in (("dup-own-first", value, forged),
                                           ("dup-foreign-first", forged, value)):
                    v_body, v_marker = _uniquify(case.body, "v" + secrets.token_hex(4))
                    raw = _polluted(v_body, key, first, last)
                    variants.append(_Made(label, url, json.loads(raw), v_marker, raw=raw))
                v_body, v_marker = _uniquify(case.body, "v" + secrets.token_hex(4))
                variants.append(_Made("array", url, {**v_body, key: [value, forged]}, v_marker))
                return _Plan(_Made("control", url, ctl_body, ctl_marker),
                             [_Made("attack", url, atk_body, atk_marker)], field=key,
                             forged=forged, own=value, other=other, variants=variants,
                             detail=f"{key}: {value!r} -> {_pid(other)}'s {stem} {forged!r}")
            parts = urlsplit(url)
            segments = parts.path.split("/")
            for i in range(1, len(segments)):
                if not _ID_SEGMENT.match(segments[i] or "") or not segments[i - 1]:
                    continue
                stem = naming.object_key(segments[i - 1])
                candidates = [o for o in theirs.get(stem, ()) if str(o) != segments[i]
                              and str(o) not in own.get(stem, ())]
                if not candidates:
                    continue
                swapped = urlunsplit((parts.scheme, parts.netloc,
                                      "/".join(segments[:i] + [candidates[0]] + segments[i + 1:]),
                                      parts.query, ""))
                ctl_body, ctl_marker = _uniquify(case.body, "c" + secrets.token_hex(4))
                atk_body, atk_marker = _uniquify(case.body, "a" + secrets.token_hex(4))
                return _Plan(_Made("control", url, ctl_body, ctl_marker),
                             [_Made("attack", swapped, atk_body, atk_marker)],
                             field=stem + "Id", forged=candidates[0], own=segments[i], other=other,
                             detail=f"path {segments[i - 1]}/{segments[i]} -> "
                                    f"{_pid(other)}'s {stem} {candidates[0]}")
        return ("the create carries no reference to an object type another registered principal "
                "is known to own (declare ownership, or enable authz.self_observed_ownership)")

    def _plan_authorship(self, case: _Case):
        if case.actor is None:
            return "needs the capture to be an authenticated, registered session"
        for key, value in case.body.items():
            forged, whose = self._forge_author(case, key, value)
            if forged is None:
                continue
            ctl_body, ctl_marker = _uniquify(case.body, "c" + secrets.token_hex(4))
            atk_body, atk_marker = _uniquify(case.body, "a" + secrets.token_hex(4))
            atk_body[key] = forged
            return _Plan(_Made("control", case.exchange.url, ctl_body, ctl_marker),
                         [_Made("attack", case.exchange.url, atk_body, atk_marker)], field=key,
                         forged=forged, own=value,
                         detail=f"{key}: {value!r} -> {forged!r} ({whose})")
        return ("the create carries no author/owner/user field whose value can be replaced by "
                "another principal's known identifier")

    def _forge_author(self, case: _Case, key, value):
        """(forged value, whose) for an author/owner/user field `key`, or (None, "")
        when `key` is not one or no other identity's value is known."""
        base = _flat(_ID_SUFFIX.sub("", str(key)) if _ref_stem(key) else key)
        if base not in _PERSON_STEMS or value in (None, "") or isinstance(value, bool):
            return None, ""
        forged, whose = None, ""
        if _number(value) is not None or (isinstance(value, str) and value.isdigit()):
            for other in case.others:
                ids = [i for i in self._account_ids(_pid(other)) if str(i) != str(value)]
                if ids:
                    forged = int(ids[0]) if isinstance(value, int) and ids[0].isdigit() else ids[0]
                    whose = _pid(other)
                    break
        elif isinstance(value, str):
            other = case.others[0] if case.others else None
            name = (other or {}).get("name") or ""
            if _EMAILISH.match(value):
                forged = name if _EMAILISH.match(name) else f"wi-{secrets.token_hex(4)}@example.com"
            else:
                forged = name if name and name != value else f"wi-{secrets.token_hex(4)}"
            whose = _pid(other) if forged == name else "a fabricated identity"
        if forged is None or _same_value(forged, value):
            return None, ""
        return forged, whose

    @staticmethod
    def _tamper_field(obj: dict) -> tuple[str, str]:
        """(field, kind) of the business number to tamper with, or ("", "")."""
        for regex, label in ((_QUANTITY, "quantity"), (_RATING, "rating"), (_MONEY, "price/total")):
            for key, value in obj.items():
                if regex.match(_flat(key)) and (_number(value) or 0) > 0:
                    return key, label
        return "", ""

    def _plan_tamper(self, case: _Case):
        key, label = self._tamper_field(case.body)
        if not key:
            return ("no positive quantity, rating, price or total field in the create "
                    "(discount-code reuse and expiry are not attempted: they need an "
                    "operator-declared spent code)")
        ctl_body, ctl_marker = _uniquify(case.body, "c" + secrets.token_hex(4))
        atk_body, atk_marker = _uniquify(case.body, "a" + secrets.token_hex(4))
        atk_body[key] = _TAMPER_VALUE
        return _Plan(_Made("control", case.exchange.url, ctl_body, ctl_marker),
                     [_Made("attack", case.exchange.url, atk_body, atk_marker)], field=key,
                     forged=_TAMPER_VALUE, own=case.body[key],
                     detail=f"{label} {key}: {case.body[key]!r} -> {_TAMPER_VALUE}")

    def _plan_mass_assignment(self, case: _Case):
        fields = {f: v for f, v in _PRIV_FIELDS.items()
                  if _field_of(case.body, f)[0] is False}
        if not fields:
            return "the create already sets every privileged field this check would add"
        ctl_body, ctl_marker = _uniquify(case.body, "c" + secrets.token_hex(4))
        atk_body, atk_marker = _uniquify(case.body, "a" + secrets.token_hex(4))
        atk_body.update(fields)
        return _Plan(_Made("control", case.exchange.url, ctl_body, ctl_marker),
                     [_Made("attack", case.exchange.url, atk_body, atk_marker)],
                     field=",".join(sorted(fields)), forged=fields,
                     detail="added " + ", ".join(sorted(fields)))

    def _plan_validation(self, case: _Case):
        url = case.exchange.url
        unique = _unique_keys(case.body)
        texts = [k for k, v in case.body.items() if isinstance(v, str) and v]
        if not texts:
            return "the create has no non-empty string field to empty and no unique field to duplicate"
        ctl_body, ctl_marker = _uniquify(case.body, "c" + secrets.token_hex(4))
        attacks = []
        if unique:
            tag = "d" + secrets.token_hex(4)
            dup_body, dup_marker = _uniquify(case.body, tag)
            attacks += [_Made("duplicate-first", url, dup_body, dup_marker),
                        _Made("duplicate-second", url, dict(dup_body), dup_marker)]
        empty = {k: ("" if isinstance(v, str) else v) for k, v in case.body.items()}
        attacks.append(_Made("empty", url, empty, ""))
        return _Plan(_Made("control", url, ctl_body, ctl_marker), attacks,
                     field=",".join(texts),
                     detail=(f"duplicate on {', '.join(unique)}; " if unique else "")
                            + f"emptied {', '.join(texts)}")
