"""
Shared in-session source-form replay primitive (LB-1).

Four validators independently reimplemented the same shape: a crawled write
(POST/PUT/PATCH) was captured with a session- and token-bound body that cannot
simply be replayed as-is -- the CSRF token (and sometimes the real field names/
types) is bound to the ORIGINAL crawl's session, not this validator's own
client. A fresh client replaying the captured body verbatim is rejected
("session does not contain a CSRF token") or clobbers structural fields.

The fix is always the same shape:
  1. GET a candidate "source" page -- the page that renders the form which
     targets this write -- using the CALLER's own client, i.e. IN THE SAME
     SESSION as the write under test.
  2. Extract that page's forms with harness.feature_workflow.extract_forms.
  3. Select the form that matches this write (by action+method, by field
     shape, by carrying a token, ...) -- callers differ here, so selection is
     a caller-supplied predicate, not baked into this helper.
  4. Try the next candidate if this one has no match.

This module only owns steps 1/2/4 (`fetch_source_form`) plus a small shared
CSRF-field-name pattern. Field selection, payload/body construction, and what
to do with a found form stay at each call site, because that is exactly where
the four validators legitimately differ:
  - stored_xss_validator: matches by form action-path + method, then plants a
    payload into every free-text field while preserving structural ones.
  - file_upload_validator: matches by "has a file field" (+ action-path when
    possible), then swaps in the real multipart field names.
  - auth_sequence_validator: the write URL itself is the only candidate
    (the login page IS the source page); only the CSRF field is refreshed,
    the rest of the captured login body is left untouched.
  - client_trust_validator: same single-candidate shape as auth_sequence, but
    its own (subtly different) CSRF-field matching rule -- preserved as-is
    rather than folded into a shared "find the csrf field" helper.

No new network behavior is introduced here: every request this module makes
was already being made, with the same throttle/skip/continue semantics, by
each of the four validators before this refactor.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable

import httpx

from harness import global_throttle
from harness.feature_workflow import FormAction, extract_forms

# Shared anti-forgery-token field-name pattern (identical across the four
# validators before this refactor).
CSRF_FIELD_RE = re.compile(r"csrf|xsrf|authenticity|_token|nonce", re.I)


@dataclass
class SourceForm:
    """A form discovered on an in-session GET of one candidate source page."""
    form: FormAction
    source_url: str


async def fetch_source_form(
    client,
    candidates: list[str],
    headers: dict | None,
    select: Callable[[list[FormAction]], FormAction | None],
) -> SourceForm | None:
    """GET each of `candidates` in turn, in THIS client's session, and return
    the first form a caller's `select` accepts.

    For the first candidate whose response is HTML, `select` is handed that
    page's extracted forms (`feature_workflow.extract_forms`) and may return
    the form to use -- ending the search -- or None, meaning "no acceptable
    form on this page", which moves on to the next candidate. A candidate
    whose GET raises an httpx error, or whose response isn't HTML, is skipped
    the same way. Returns None when no candidate yields a match, so the
    caller can fall back to its own captured-body behavior.

    Each GET is throttled exactly like the write-side requests (one
    `global_throttle.acquire()` per attempt) and is not itself gated here --
    `client` is expected to already be a gated/session-bound client, same as
    before this refactor.
    """
    for url in candidates:
        await global_throttle.acquire()
        try:
            resp = await client.request("GET", url, headers=headers or None)
        except httpx.HTTPError:
            continue
        if "html" not in (resp.headers.get("content-type") or "").lower():
            continue
        forms = extract_forms(resp.text or "", url)
        chosen = select(forms)
        if chosen is not None:
            return SourceForm(form=chosen, source_url=url)
    return None
