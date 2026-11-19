"""
Challenge-echo leg (R11-8 c): a challenge whose issuing response carries its own
answer (WSTG-BUSL-07, anti-automation).

Oracle. A challenge endpoint answers a GET with a JSON object. A later request
passes the challenge by submitting a value. The flaw: a field of the challenge
response holds exactly the value the passing request submitted, under a
DIFFERENT name, while the field the request fills in is also in the challenge
response and shows something else there (the question). So the client is handed
the solution next to the question.

  challenge:  {"challengeId": 7, "question": "3*8+1", "solution": "25"}
  submission: POST {"challengeId": 7, "question": "25", ...}   -> 2xx, accepted

A value echoed under the SAME name (a correlation id, an anti-CSRF token) is
never the oracle: forwarding a handle is how such tokens work.

Nothing here knows an application or a route name. Recognition is by the
captured pair only.

Passive first. The verdict reads the run's captured exchanges
(`run_context.experiment_context["captured"]`): each accepted submission is
paired with the latest earlier answer of the same challenge endpoint. A pair is
the evidence. Two pairs with different echoed values show that the value tracks
the challenge rather than being a constant.

Active only where captures cannot show it (`active_submit`, default off). The
leg GETs the challenge twice and needs fields that change on every call, which a
static resource never does. It submits a captured submission once with a wrong
value (the control, which must be rejected), then once per candidate field with
that field's fresh value. Every submission is a write the leg cannot undo, so it
also needs validators.allow_mutating_replay and stays inside `max_submissions`.

Policy (owner decision 2026-11-19): validators.challenge_echo.confirm is on by
default, so a positive confirms, and then only on two passive pairs or an active
positive with its rejected control. With the key set false a positive is a
labelled LEAD (not_confirmed, manual_verification set).
"""
from __future__ import annotations

import json
import re
import secrets
from urllib.parse import urlsplit

from harness import scope_lock
from harness.models import Finding, HttpExchange
from .base import Validator, ValidationResult

_REJECTION = re.compile(r"\b(wrong|invalid|incorrect|failed|denied|mismatch|not match)", re.I)
_ID_LIKE = re.compile(r"(?:^|_)id$|id$|uuid|token|nonce|csrf|key$", re.I)
_MAX_CANDIDATES = 3


def _doc(text: str):
    try:
        return json.loads(text or "")
    except (ValueError, TypeError):
        return None


def challenge_fields(body: str) -> dict[str, str]:
    """The scalar fields of a JSON object response (and of one nested object
    level), keyed by leaf name; booleans, nulls and empty strings are left out."""
    doc = _doc(body)
    out: dict[str, str] = {}
    if not isinstance(doc, dict):
        return out

    def add(obj):
        for k, v in obj.items():
            if isinstance(v, bool) or v is None:
                continue
            if isinstance(v, (int, float, str)) and str(v).strip() and k not in out:
                out[str(k)] = str(v)

    add(doc)
    for v in doc.values():
        if isinstance(v, dict):
            add(v)
    return out


def submitted_fields(exchange: HttpExchange) -> tuple[dict, str]:
    from .auth_sequence_validator import _parse_body
    fields, kind = _parse_body(exchange)
    return {str(k): v for k, v in fields.items()}, kind


def is_challenge_shape(exchange: HttpExchange) -> bool:
    """A GET answered 2xx with a JSON object of at least two scalar fields: the
    shape a challenge issuer has. The leg decides; this only routes."""
    if (exchange.method or "GET").upper() != "GET":
        return False
    if not 200 <= (exchange.response_status or 0) < 300:
        return False
    return len(challenge_fields(exchange.response_body or "")) >= 2


def _accepted(status, body: str) -> bool:
    return status is not None and 200 <= int(status) < 300 and not _REJECTION.search(body or "")


def echo_match(challenge: dict[str, str], submitted: dict) -> tuple[str, str, str] | None:
    """(answer_field, submitted_field, value) when the submission carries, under
    a name the challenge response ALSO uses for something else, a value the
    challenge response holds under another name. None otherwise."""
    low_challenge = {k.lower(): (k, v) for k, v in challenge.items()}
    for k2, raw in submitted.items():
        if isinstance(raw, (dict, list, bool)) or raw is None:
            continue
        value = str(raw)
        if not value.strip():
            continue
        shown = low_challenge.get(k2.lower())
        if shown is None or shown[1] == value:
            continue      # not a challenge slot, or a same-name echo (a handle)
        for k1, v1 in challenge.items():
            if k1.lower() != k2.lower() and v1 == value:
                return k1, k2, value
    return None


def _captured(run_context) -> list[HttpExchange]:
    context = getattr(run_context, "experiment_context", None)
    raw = (context.get("captured") if isinstance(context, dict) else None) or ()
    out = []
    for item in raw:
        try:
            out.append(item if isinstance(item, HttpExchange) else HttpExchange(**item))
        except Exception:
            continue
    return out


def _route(exchange: HttpExchange) -> tuple[str, str]:
    return (exchange.method or "GET").upper(), urlsplit(exchange.url or "").path


class ChallengeEchoValidator(Validator):
    name = "challenge_echo"
    finding_classes = {
        "challenge_echo", "challenge echo", "captcha bypass", "captcha_bypass",
        "captcha answer disclosure", "challenge answer disclosure",
        "anti-automation bypass", "anti_automation_bypass",
    }
    active = True

    def __init__(self, *, allowed_hosts: list[str] | None = None, timeout: float = 10.0,
                 confirm: bool = True, active_submit: bool = False, max_submissions: int = 4):
        self.allowed_hosts = allowed_hosts or []
        self.timeout = timeout
        self.confirm = bool(confirm)
        self.active_submit = bool(active_submit)
        self.max_submissions = max(2, int(max_submissions))

    def applies(self, finding: Finding, exchange: HttpExchange) -> bool:
        return super().applies(finding, exchange) and is_challenge_shape(exchange)

    def _result(self, status, summary, *, evidence="", confidence=0.0, confirmed=False,
                manual="", limitation=""):
        return ValidationResult(self.name, status, "challenge_echo", confidence=confidence,
                                confirmed=confirmed, summary=summary, evidence=evidence,
                                manual_verification=manual, limitation=limitation)

    def _verdict(self, summary: str, evidence: str, *, strong: bool) -> ValidationResult:
        manual = ("Fetch a fresh challenge, submit the value of the named field as the "
                  "answer, and check that the submission passes.")
        if self.confirm and strong:
            return self._result("confirmed", "Challenge answer disclosed: " + summary,
                                evidence=evidence, confidence=0.8, confirmed=True)
        why = ("validators.challenge_echo.confirm is off (set false in config)"
               if strong else "one pair only: a second pair with another value would show "
                              "the value tracks the challenge")
        return self._result("not_confirmed", f"Lead, not confirmed ({why}): " + summary,
                            evidence=evidence, confidence=0.5 if strong else 0.4,
                            manual=manual, limitation=why)

    async def validate(self, finding: Finding, exchange: HttpExchange) -> ValidationResult:
        if self.allowed_hosts and not scope_lock.host_in_scope(exchange.url, self.allowed_hosts):
            return self._result("skipped", "host out of scope")
        if not is_challenge_shape(exchange):
            return self._result("skipped", "not a JSON challenge-shaped GET response")
        route = _route(exchange)
        captured = _captured(self.run_context)
        pairs = self._passive_pairs(exchange, captured)
        where = f"{route[0]} {route[1]}"
        if pairs:
            values = {p[3] for p in pairs}
            first = pairs[0]
            summary = (f"the {where} response field '{first[0]}' holds the value an accepted "
                       f"{first[2]} submitted as '{first[1]}'")
            evidence = (f"{len(pairs)} captured pair(s), {len(values)} distinct value(s): "
                        + "; ".join(f"{where} '{a}' == {s} '{b}' (accepted)"
                                    for a, b, s, _v in pairs[:3])
                        + ". The submitted field also appears in the challenge response "
                          "with a different value (the question).")
            return self._verdict(summary, evidence, strong=len(values) >= 2)
        submissions = self._submission_templates(exchange, captured)
        if not submissions:
            return self._result("not_confirmed",
                                f"No captured submission echoes a field of {where}; no "
                                f"challenge-echo evidence", confidence=0.0)
        if not self.active_submit:
            return self._result(
                "inconclusive",
                f"Challenge-echo candidate: {submissions[0][0].method.upper()} "
                f"{urlsplit(submissions[0][0].url).path} fills field '{submissions[0][1]}' "
                f"that {where} also returns, but no captured submission was accepted. "
                f"The active check is off (validators.challenge_echo.active_submit).")
            # No manual_verification: a shared field name alone is too common (an
            # object read and its update) to surface as a lead. The proof keeps it.
        return await self._active(exchange, submissions, where)

    def _passive_pairs(self, exchange, captured):
        route = _route(exchange)
        timeline: list[HttpExchange] = []
        if not any(_route(c) == route and c.response_body == exchange.response_body
                   for c in captured):
            timeline.append(exchange)
        timeline.extend(captured)
        latest: dict[str, str] | None = None
        pairs = []
        for ex in timeline:
            if _route(ex) == route:
                fields = challenge_fields(ex.response_body or "")
                if fields:
                    latest = fields
                continue
            if latest is None or (ex.method or "GET").upper() in ("GET", "HEAD", "OPTIONS"):
                continue
            if not _accepted(ex.response_status, ex.response_body or ""):
                continue
            body, _kind = submitted_fields(ex)
            match = echo_match(latest, body)
            if match:
                k1, k2, value = match
                pairs.append((k1, k2, f"{(ex.method or '').upper()} {urlsplit(ex.url).path}", value))
        return pairs

    def _submission_templates(self, exchange, captured):
        """(captured submission, field to fill) for writes to another route that
        fill a field the challenge response also returns. Id-like shared names come
        last: those are handles the submission forwards."""
        route = _route(exchange)
        keys = {k.lower() for k in challenge_fields(exchange.response_body or "")}
        out, seen = [], set()
        for ex in captured:
            method, path = _route(ex)
            if method in ("GET", "HEAD", "OPTIONS") or path == route[1]:
                continue
            if self.allowed_hosts and not scope_lock.host_in_scope(ex.url, self.allowed_hosts):
                continue
            body, _kind = submitted_fields(ex)
            shared = sorted((k for k in body if k.lower() in keys),
                            key=lambda k: (bool(_ID_LIKE.search(k)), k))
            for k in shared[:2]:
                if (method, path, k) not in seen:
                    seen.add((method, path, k))
                    out.append((ex, k))
        return out

    async def _active(self, exchange, submissions, where) -> ValidationResult:
        from harness.run_context import TypedRequest
        from harness.safety_gate import get_default_gate
        from .auth_sequence_validator import _encode
        from .transport import bind_session
        run = self.run_context
        if run is None:
            return self._result("skipped", "the active challenge check needs a run context")
        gate = getattr(run, "gate", None) or get_default_gate()
        if not gate.config.allow_mutating_replay:
            return self._result("skipped", "the active challenge check submits writes; needs "
                                           "validators.allow_mutating_replay")
        executor = run.executor()
        get_headers = {k: v for k, v in (exchange.request_headers or {}).items()
                       if k.lower() not in ("content-length", "host")}

        async def fetch():
            ref, headers = bind_session(run, get_headers)
            result = await executor.execute(TypedRequest("GET", exchange.url, headers=headers),
                                            capability=self.name, session_ref=ref)
            if not result.executed or not result.ok:
                return None
            return challenge_fields(result.body or "")

        first, second = await fetch(), await fetch()
        if not first or not second:
            return self._result("inconclusive", f"could not fetch {where} twice")
        changing = {k for k in first if second.get(k) not in (None, first[k])}
        if len(changing) < 2:
            return self._result("not_confirmed",
                                f"{where} answers with the same fields on every call: a static "
                                f"resource, not an issued challenge", confidence=0.0)
        sent = 0
        for template, slot in submissions:
            if slot not in {k for k in first} and slot.lower() not in {k.lower() for k in first}:
                continue
            body, kind = submitted_fields(template)
            candidates = [k for k in second if k in changing and k.lower() != slot.lower()
                          and k.lower() not in {b.lower() for b in body}][:_MAX_CANDIDATES]
            if not candidates:
                continue
            headers = {k: v for k, v in (template.request_headers or {}).items()
                       if k.lower() not in ("content-length", "host")}
            method = (template.method or "POST").upper()
            target = f"{method} {urlsplit(template.url).path}"

            async def submit(value, fresh):
                nonlocal sent
                fields = dict(body)
                for k in fields:
                    if k != slot and k in fresh:
                        fields[k] = type(fields[k])(fresh[k]) if isinstance(fields[k], int) \
                            and fresh[k].isdigit() else fresh[k]
                fields[slot] = value
                ref, bound = bind_session(run, headers)
                sent += 1
                result = await executor.execute(
                    TypedRequest(method, template.url, headers=bound, body=_encode(fields, kind)),
                    capability=self.name, session_ref=ref)
                if not result.executed:
                    return None
                return result

            fresh = await fetch()
            if not fresh:
                continue
            control = await submit("wrong-" + secrets.token_hex(3), fresh)
            if control is None:
                return self._result("skipped", "the run refused the control submission")
            if _accepted(control.status, control.body or ""):
                return self._result(
                    "not_confirmed",
                    f"{target} accepted a wrong value in '{slot}': the challenge is not "
                    f"enforced there, so an echoed answer proves nothing", confidence=0.0)
            for k1 in candidates:
                if sent >= self.max_submissions:
                    break
                fresh = await fetch()
                if not fresh or k1 not in fresh:
                    continue
                attempt = await submit(fresh[k1], fresh)
                if attempt is None:
                    break
                if _accepted(attempt.status, attempt.body or ""):
                    return self._verdict(
                        f"the {where} response field '{k1}' passes the challenge at {target} "
                        f"when submitted as '{slot}'",
                        f"Control: a wrong '{slot}' -> HTTP {control.status} (rejected). "
                        f"Fresh challenge field '{k1}' as '{slot}' -> HTTP {attempt.status} "
                        f"(accepted). {where} changed fields {sorted(changing)} between calls.",
                        strong=True)
            if sent >= self.max_submissions:
                break
        return self._result("not_confirmed",
                            f"No field of {where} passed the challenge ({sent} submission(s), "
                            f"each control rejected)", confidence=0.0)
