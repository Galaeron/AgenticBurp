"""File-input helpers (crawl_spa(file_uploads=True)): hold, fill and submit a
form with a benign file, split from browser_driver.py (ARC-9). Import these
names from harness.browser_driver.
"""
from __future__ import annotations

import asyncio


# ---------------------------------------------------------------------------
# File inputs (crawl_spa(file_uploads=True), driver_capture.file_uploads)
# ---------------------------------------------------------------------------

# Methods a held upload attempt lets through to the normal routing: reads.
_HELD_READS = frozenset({"GET", "HEAD", "OPTIONS"})

_FILE_INPUTS_JS = """() => Array.from(document.querySelectorAll('input[type=file]')).map(
  (el, index) => {
    const f = el.form;
    return {index: index, name: el.name || '', accept: el.getAttribute('accept') || '',
            multiple: !!el.multiple, disabled: !!el.disabled,
            form: f ? {action: f.action || '', method: (f.method || 'get').toLowerCase(),
                       enctype: f.enctype || '', novalidate: !!f.noValidate} : null};
  })"""

_SUBMIT_FILE_FORM_JS = """el => {
  const f = el.form;
  if (!f) return 'noform';
  if (!f.noValidate && !f.checkValidity()) return 'invalid';
  if (typeof f.requestSubmit === 'function') f.requestSubmit(); else f.submit();
  return 'submitted';
}"""


# A script-driven form (no POST method: the page uploads from its own submit
# handler, by XHR or fetch): its empty visible text fields get a benign value,
# then its submit control is clicked, as a user would. Never a password field.
_FILLABLE_JS = """el => {
  if (el.disabled || el.readOnly || (el.value || '') !== '' || !el.getClientRects().length) return '';
  const t = el.tagName === 'TEXTAREA' ? 'textarea' : (el.type || 'text').toLowerCase();
  return ['text', 'textarea', 'search', 'email', 'url', 'tel', 'number'].includes(t) ? t : '';
}"""
_BENIGN_FIELD_VALUES = {"email": "upload-check@example.com", "url": "https://example.com/",
                        "tel": "5550100", "number": "1"}
_BENIGN_TEXT = "harness upload check"
_MAX_FILLED_FIELDS = 12
_SUBMIT_CONTROL = "button[type=submit], input[type=submit], button:not([type])"


async def _submit_script_form(handle) -> str:
    """Fill the file input's form and click its submit control (see _FILLABLE_JS).
    Every write the page issues meanwhile stays held. Returns "clicked",
    "noform", "nosubmit", "invalid" (the control stayed disabled) or "failed"."""
    form = await handle.evaluate_handle("el => el.form")
    try:
        if not await form.evaluate("f => !!f"):
            return "noform"
        button = await form.query_selector(_SUBMIT_CONTROL)
        if button is None:
            return "nosubmit"
        for control in (await form.query_selector_all("input, textarea"))[:_MAX_FILLED_FIELDS]:
            kind = await control.evaluate(_FILLABLE_JS)
            if kind:
                await _bd._quietly(control.fill(_BENIGN_FIELD_VALUES.get(kind, _BENIGN_TEXT),
                                            timeout=1000))
        try:
            await button.click(timeout=2000)
        except Exception:
            if not await button.is_enabled():
                return "invalid"
            # Enabled, but the pointer click lands elsewhere: a toast or banner
            # over the control takes it. Activate the control itself instead.
            await button.evaluate("b => b.click()")
        return "clicked"
    except Exception:
        return "failed"
    finally:
        await _bd._quietly(form.dispose())


async def _await_hold(hold: dict, wait_ms: int) -> None:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + max(0.3, min(wait_ms, 10000) / 1000)
    while hold["exchange"] is None and not hold["reason"] and loop.time() < deadline:
        await asyncio.sleep(0.05)


def _upload_refusal(gate, case_ref: str) -> str:
    """Why no file may be attached for this input's capture, or ""."""
    from harness.spa_navigation import UPLOAD_CAPABILITY
    if gate is None:
        return "withheld: no write gate"
    cfg = getattr(gate, "config", None)
    if not getattr(cfg, "active_enabled", False):
        return "withheld: writes are off (active_testing_disabled)"
    if not getattr(cfg, "allow_mutating_replay", False):
        return "withheld: writes are off (mutating_replay_disabled)"
    remaining, used, ceiling = gate.mutating_headroom(case_ref, UPLOAD_CAPABILITY)
    if remaining < 1:
        return f"per-finding mutating ceiling reached ({used}/{ceiling})"
    return ""


async def _upload_file_input(page, router, desc: dict, *, gate, headers: dict | None,
                             wait_ms: int):
    """Try one file input: attach a small benign file its `accept` allows, wait for
    the page's own upload request, and (nothing seen yet) submit its form as the
    page would: a POST form natively, a script-driven form (no POST method) by
    filling its empty text fields with benign values and clicking its submit
    control, as a page that uploads on submit expects. The router HOLDS every
    write meanwhile: the upload is captured as a request template and aborted, never sent (an
    uploaded file cannot be removed generically; the file_upload validator makes
    its own gated upload from the capture). Only with writes on and the input's
    ceiling case open, checked before anything is attached. Returns (exchange
    dict or None, reason)."""
    import secrets
    from harness import upload_files
    from harness.spa_navigation import UPLOAD_CAPABILITY, view_key
    case_ref = str(desc.get("case_ref") or "")
    accept = str(desc.get("accept") or "")
    refusal = _upload_refusal(gate, case_ref)
    if refusal:
        return None, refusal
    made = upload_files.benign_file(accept, secrets.token_hex(6))
    if made is None:
        return None, f"no benign file type matches accept={accept!r}"
    name, mime, data = made
    handles = await page.query_selector_all("input[type=file]")
    index = int(desc.get("index", -1))
    if not 0 <= index < len(handles):
        return None, "the file input is no longer on the view"
    form = desc.get("form") or None
    label = str(desc.get("name") or f"#{index}")
    ext = name.rsplit(".", 1)[-1]
    hold = {"markers": (name.encode(), data), "case_ref": case_ref,
            "capability": UPLOAD_CAPABILITY, "exchange": None, "reason": "", "aborted": [],
            "note": (f"driver_capture: upload request the page issued for file input "
                     f"'{label}' on view {view_key(page.url or '')} with a benign generated "
                     f".{ext} file (accept={accept or 'any'}); held in the browser and "
                     "never sent -- an uploaded file cannot be removed generically")}
    submitted = ""
    router.hold = hold
    try:
        await handles[index].set_input_files({"name": name, "mimeType": mime, "buffer": data})
        await _await_hold(hold, wait_ms)
        if (hold["exchange"] is None and not hold["reason"] and form
                and (form.get("method") or "get") == "post"):
            submitted = str(await handles[index].evaluate(_SUBMIT_FILE_FORM_JS))
            if submitted == "submitted":
                await _await_hold(hold, wait_ms)
        elif hold["exchange"] is None and not hold["reason"] and form:
            submitted = await _submit_script_form(handles[index])
            if submitted == "clicked":
                await _await_hold(hold, wait_ms)
    finally:
        router.hold = None
    others =(f"; {len(hold['aborted'])} other write(s) held and aborted"
              if hold["aborted"] else "")
    if hold["exchange"] is not None:
        return (_bd._with_identity(hold["exchange"], router.run_origin, headers),
                f"held, not sent; benign .{ext} file{others}")
    if hold["reason"]:
        return None, hold["reason"] + others
    if submitted == "invalid":
        return None, "its form needs other fields filled before it submits; not submitted" + others
    if submitted == "nosubmit":
        return None, "no upload request observed; its form has no submit control" + others
    if submitted == "failed":
        return None, "no upload request observed; its submit control could not be clicked" + others
    how = {"submitted": " and submitting its form",
           "clicked": " and clicking its form's submit control"}.get(submitted, "")
    return None, f"no upload request observed after attaching a benign .{ext} file{how}{others}"


# Bound last (browser_driver imports this module): read only at call time.
from harness import browser_driver as _bd  # noqa: E402
