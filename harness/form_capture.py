"""
Forms on fetched HTML documents as request templates (engagement.form_templates).

r9: a server-rendered page the SPA reached was fetched thousands of times, all 200,
yet none of its POST forms ever became a request, so the CSRF and SSRF legs had no
capture for them. The crawler parses forms only on pages it reaches through
`<a href>` (an SPA shell links to none), role_crawl builds its form templates only
from those crawler forms, the browser crawl keeps only XHR/fetch calls, and the
workflow crawl submits marker values on its own short walk.

`mine_templates` closes the gap on the existing capture path: every form on a 2xx
HTML document the run already fetched (role crawl captures, supplied or browser
captures, documents the SPA crawl navigated to) becomes a request template, which
build_engagement adds to the captures and records with `record_template`, so review
and the validators get it like any other capture. A template carries the form's
method, its resolved action and the page's own current values, hidden fields such
as anti-CSRF tokens kept as rendered; its note lists the field names and types.
PASSIVE: nothing is sent. A form with a password field is not templated (a password
value is never stored), and no field value is ever logged.

`submit_baselines` (engagement.form_templates.baseline, off by default) submits a
POST template once, UNCHANGED, as the identity that fetched its page, so the
capture carries the real answer. It is a write. The run's executor applies scope,
the active/mutating gate, the per-finding mutating ceiling (one case per form) and
the budget. Only a fully filled edit form, whose unchanged submit re-saves the state
it shows, is submitted. A create-shaped or button-only form, a file form, a form no
longer on its page, or one the ceiling cannot afford is skipped with the reason.
The page is read just before the submit (fresh token and values) and again after
it: the same values mark the write `restored` in the change log, anything else
marks it `restore_failed` (logged at ERROR) with the reason.
"""
from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from harness import feature_workflow
from harness.models import HttpExchange

log = logging.getLogger("harness.form_capture")

TEMPLATE_SOURCE = "form_template"
BASELINE_SOURCE = "form_baseline"
BASELINE_CAPABILITY = "form_baseline"

# Not carried from the page's request onto the form's: they describe that request.
_PAGE_ONLY_HEADERS = frozenset({"content-type", "content-length", "referer", "origin", "host"})
# Controls that hold no user-editable state.
_NOT_EDITABLE = frozenset({"hidden", "submit", "button", "reset", "image", "file", "password"})
# Editable controls that always submit some value (no evidence of stored state).
_CHOICE = frozenset({"select", "checkbox", "radio"})


@dataclass
class _Mined:
    form: "feature_workflow.FormAction"
    source: HttpExchange
    exchange: HttpExchange

    @property
    def label(self) -> str:
        return f"{(self.form.method or 'GET').upper()} {urlsplit(self.form.action).path or '/'}"


@dataclass
class FormCapture:
    """What mine_templates found: the templates (in `mined`), the forms it did not
    template and why, and what submit_baselines did. Labels are METHOD + path only."""
    mined: list = field(default_factory=list)          # _Mined
    skipped: list = field(default_factory=list)        # {"form", "reason"}
    baselines: list = field(default_factory=list)      # {"form", "outcome", ...}
    documents: int = 0
    forms: int = 0

    @property
    def templates(self) -> list:
        return [m.exchange for m in self.mined]

    def skip(self, label: str, reason: str) -> None:
        self.skipped.append({"form": label, "reason": reason})

    def summary(self) -> dict:
        return {"documents": self.documents, "forms": self.forms,
                "templates": [{"form": m.label, "fields": m.form.field_schema(),
                               "source": urlsplit(m.source.url).path or "/",
                               "capture": m.exchange.capture_source}
                              for m in self.mined],
                "skipped": list(self.skipped), "baselines": list(self.baselines)}


def _as_exchange(item):
    try:
        return item if isinstance(item, HttpExchange) else HttpExchange(**item)
    except (TypeError, ValueError):
        return None


def _is_document(ex: HttpExchange) -> bool:
    return ((ex.method or "GET").upper() == "GET" and ex.response_status is not None
            and 200 <= ex.response_status < 300 and bool(ex.response_body)
            and feature_workflow._looks_html(ex.response_headers, ex.response_body))


def _refusal(form, method: str, origin: str, in_scope) -> str:
    """Why `form` is not templated, or ""."""
    from harness.run_context import ScopePolicy
    if method not in ("GET", "POST"):
        return f"method {method.lower()!r} is not an HTTP submission"
    if ScopePolicy.origin_of(form.action) != origin or (in_scope is not None
                                                         and not in_scope(form.action)):
        return "action outside the engagement origin or scope"
    if feature_workflow._destructive_navigation(form.action):
        return "destructive-looking action"
    if form.has_type("password"):
        return "credential form: a password value is never stored"
    if method == "GET" and not any(f.name for f in form.fields):
        return "no named field"
    return ""


def _template(form, source: HttpExchange) -> HttpExchange:
    url, body, ctype = form.current_request()
    method = (form.method or "GET").upper()
    headers = {k: v for k, v in (source.request_headers or {}).items()
               if (k or "").lower() not in _PAGE_ONLY_HEADERS}
    if ctype:
        headers["Content-Type"] = ctype
    headers["Referer"] = source.url.split("#", 1)[0]
    schema = ", ".join(f"{f['name']}:{f['type']}" for f in form.field_schema()) or "none"
    note = (f"form template: {method} form on {urlsplit(source.url).path or '/'}, fields "
            f"[{schema}]; built from the page's own current values (hidden fields as "
            "rendered), not sent")
    return HttpExchange(url=url, method=method, request_headers=headers, request_body=body,
                        analyst_note=note[:2000], capture_source=TEMPLATE_SOURCE)


def mine_templates(exchanges, *, base_url: str, in_scope=None, max_forms: int = 40) -> FormCapture:
    """Every form on a 2xx HTML document in `exchanges`, on the engagement origin, as
    a request template (see the module doc). One template per form and identity. A
    form whose request an answered capture already holds (the role crawl submitted
    it) is not templated again."""
    from harness.engagement import capture_identity_key
    from harness.run_context import ScopePolicy
    origin = ScopePolicy.origin_of(base_url)
    out = FormCapture()
    parsed = [ex for ex in (_as_exchange(item) for item in exchanges or []) if ex is not None]
    answered = set()
    for ex in parsed:
        parts = urlsplit(ex.url)
        if ex.response_status is not None and (ex.request_body or parts.query):
            answered.add(((ex.method or "GET").upper(), parts.path or "/",
                          capture_identity_key(ex.request_headers)))
    seen = set()
    for ex in parsed:
        if (not _is_document(ex) or ScopePolicy.origin_of(ex.url) != origin
                or (in_scope is not None and not in_scope(ex.url))):
            continue
        forms = feature_workflow.extract_forms(ex.response_body, ex.url)
        if not forms:
            continue
        out.documents += 1
        identity = capture_identity_key(ex.request_headers)
        for form in forms:
            method = (form.method or "GET").upper()
            path = urlsplit(form.action).path or "/"
            key = (method, path, tuple(sorted(f.name for f in form.fields if f.name)), identity)
            if key in seen:
                continue
            seen.add(key)
            out.forms += 1
            label = f"{method} {path}"
            reason = _refusal(form, method, origin, in_scope)
            if not reason and (method, path, identity) in answered:
                reason = "already captured with an answer"
            if not reason and len(out.mined) >= max(0, int(max_forms)):
                reason = f"template cap reached ({max_forms} forms)"
            if reason:
                out.skip(label, reason)
                continue
            out.mined.append(_Mined(form=form, source=ex, exchange=_template(form, ex)))
    return out


# ---------------------------------------------------------------------------
# Baseline submission (a write)
# ---------------------------------------------------------------------------

def _editable(form) -> list:
    return [f for f in form.fields
            if f.name and not f.disabled and (f.type or "text").lower() not in _NOT_EDITABLE]


def _current(f) -> str:
    return f.text if (f.type or "").lower() == "textarea" else (f.value or "")


def _baseline_refusal(form) -> str:
    """Why an unchanged submit of `form` could not be restored, or ""."""
    if form.has_type("file"):
        return "file field: a file form is left to the upload capture"
    editable = _editable(form)
    if not editable:
        return "action form (no editable field): its effect cannot be checked or restored"
    texts = [f for f in editable if (f.type or "text").lower() not in _CHOICE]
    if not texts or any(not _current(f) for f in texts):
        return ("not a filled edit form: an unchanged submit could create rather than "
                "re-save, which cannot be restored")
    return ""


def _values(form) -> dict:
    return {f.name: _current(f) for f in _editable(form)
            if (f.type or "").lower() not in ("checkbox", "radio")} | {
        f.name: str(f.checked) for f in _editable(form)
        if (f.type or "").lower() in ("checkbox", "radio")}


def _same_form(forms, form):
    want = (form.method.upper(), urlsplit(form.action).path,
            tuple(sorted(f.name for f in form.fields if f.name)))
    return next((f for f in forms
                 if (f.method.upper(), urlsplit(f.action).path,
                     tuple(sorted(x.name for x in f.fields if x.name))) == want), None)


async def _read_form(run_context, url: str, session_ref, headers: dict, form):
    """(the form as `url` renders it now, or None, and "" or why the read failed)."""
    from harness.run_context import TypedRequest
    outcome = await run_context.executor().execute(
        TypedRequest("GET", url, headers=headers), capability=BASELINE_CAPABILITY,
        session_ref=session_ref)
    if not outcome.ok or outcome.status is None or not 200 <= outcome.status < 300:
        return None, f"page read failed ({outcome.outcome}, status {outcome.status})"
    return _same_form(feature_workflow.extract_forms(outcome.body or "", url), form), ""


def _case_ref(mined: _Mined) -> str:
    from harness.engagement import capture_identity_key
    key = "\x00".join((mined.label, capture_identity_key(mined.exchange.request_headers)))
    return f"{BASELINE_CAPABILITY}:{hashlib.sha256(key.encode('utf-8', 'replace')).hexdigest()[:12]}"


async def submit_baselines(capture: FormCapture, run_context, *, max_baselines: int = 20) -> None:
    """Submit each POST template once, unchanged, through the run's executor (see the
    module doc). A submitted form's template is replaced by the answered capture.
    Every outcome, skip or restore lands in `capture.baselines`; never a value."""
    from harness import run_handoff
    from harness.role_crawl import mutating_policy_reason
    from harness.run_context import TypedRequest
    from harness.security import is_identity_credential_header
    policy = mutating_policy_reason(run_context)
    sent = 0
    for mined in capture.mined:
        if (mined.form.method or "GET").upper() != "POST":
            continue      # a GET form is a read: its template is replayed as one
        label = mined.label
        case_ref = _case_ref(mined)
        session_ref, extra = run_context.sessions.bind_headers(mined.exchange.request_headers)
        read_headers = {k: v for k, v in extra.items() if k.lower() != "content-type"}
        reason = (f"withheld: writes are off ({policy})" if policy
                  else _baseline_refusal(mined.form))
        if not reason and sent >= max(0, int(max_baselines)):
            reason = f"baseline cap reached ({max_baselines})"
        if not reason and run_context.cancel.cancelled:
            reason = "run cancelled"
        if not reason and session_ref is None and any(
                is_identity_credential_header(k) for k in extra):
            reason = "the page's identity has no registered session"
        if not reason:
            remaining, used, ceiling = run_context.gate.mutating_headroom(
                case_ref, BASELINE_CAPABILITY)
            if remaining < 1:
                reason = f"per-finding mutating ceiling reached ({used}/{ceiling})"
        fresh = None
        if not reason:
            fresh, failed = await _read_form(run_context, mined.source.url, session_ref,
                                             read_headers, mined.form)
            if fresh is None:
                reason = failed or "the form is no longer on its page"
            else:
                reason = _baseline_refusal(fresh)
        if reason:
            capture.baselines.append({"form": label, "outcome": "skipped", "reason": reason})
            continue
        url, body, ctype = fresh.current_request()
        headers = dict(extra)
        headers["Content-Type"] = ctype
        sent += 1
        outcome = await run_context.executor().execute(
            TypedRequest("POST", url, headers=headers, body=body),
            capability=BASELINE_CAPABILITY, session_ref=session_ref, case_ref=case_ref)
        if not outcome.ok:
            capture.baselines.append({"form": label, "outcome": "not_sent",
                                      "reason": outcome.outcome})
            continue
        mined.exchange = HttpExchange(
            url=url, method="POST", request_headers=dict(mined.exchange.request_headers),
            request_body=body, response_status=outcome.status,
            response_headers=dict(outcome.headers or {}), response_body=outcome.body or "",
            analyst_note=mined.exchange.analyst_note.replace(
                ", not sent", f", submitted unchanged once (HTTP {outcome.status})"),
            capture_source=BASELINE_SOURCE)
        if outcome.status is None or not 200 <= outcome.status < 300:
            capture.baselines.append({"form": label, "outcome": "answered",
                                      "status": outcome.status,
                                      "restore": "nothing to restore: the write was not accepted"})
            continue
        after, failed = await _read_form(run_context, mined.source.url, session_ref,
                                         read_headers, fresh)
        if after is None:
            ok, detail = False, f"re-read: {failed or 'the form is no longer on its page'}"
        else:
            before_values, after_values = _values(fresh), _values(after)
            changed = sorted(n for n in before_values | after_values
                             if before_values.get(n) != after_values.get(n))
            ok = not changed
            detail = ("re-read: the form shows the values it was submitted with" if ok
                      else "re-read: field(s) " + ", ".join(changed[:8])
                      + " changed after an unchanged submit")
        run_handoff.mark_restore(run_context, [outcome.artifact_id], ok=ok, detail=detail)
        capture.baselines.append({"form": label, "outcome": "submitted", "status": outcome.status,
                                  "restore": "restored" if ok else "restore_failed",
                                  "detail": detail})
