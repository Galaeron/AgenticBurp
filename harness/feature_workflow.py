"""
Stateful, authenticated agent-role feature crawling.

Route/vocabulary discovery finds endpoints that EXIST as URLs. It provably cannot
reach an app's real workflow surface (sessions 11/13/15): a ticket is created by
POSTing a form, an integration fires only after that ticket exists, a template is
rendered only at the end of a flow. Those requests never appear until a session
DRIVES the feature. This module is the automated driver: given a role's real
captured session headers, it walks the app the way a user would --

  GET a page -> read its forms and links -> SUBMIT a form (create ticket, use
  integration, trigger webhook) with benign default values -> follow the result
  -> repeat, bounded --

and RETAINS every request/response as an analyzable `HttpExchange`. Because each
send carries the role's session, the captured exchange carries the authenticated
context (the session cookie, the workflow body) the confirmation legs need. It is
the active counterpart to `burp_sitemap` (which imports a human's browsing): both
produce the credential-bearing, workflow-shaped exchanges the crawler can't.

The network seam is an injected `fetch_fn` (like worklist_investigator's
`probe_fn`), so the driver is exercised hermetically against an in-memory app in
tests and against a real, scope-gated, throttled httpx client in production. Form
and link extraction is pure (stdlib HTMLParser + JSON walk), deterministic, and
unit-tested on its own. Bounded by max_steps and max_depth; mutating submits are
opt-in (`submit_forms`) and still pass through the caller's gated client.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit, urlencode

from models import HttpExchange

log = logging.getLogger("harness.feature_workflow")

# Benign default values by input name/type -- enough to pass typical validation
# and actually create the object, never an attack payload (the confirmation legs
# inject payloads later; this leg's job is only to REACH the workflow surface).
_MARKER = "harness-workflow-probe"


@dataclass
class FormField:
    name: str
    type: str = "text"
    value: str = ""


@dataclass
class FormAction:
    method: str
    action: str                       # absolute URL
    fields: list[FormField] = field(default_factory=list)
    enctype: str = "application/x-www-form-urlencoded"

    def signature(self) -> tuple:
        """Dedup key: same target + same field names is the same form."""
        return (self.method, self.action, tuple(sorted(f.name for f in self.fields if f.name)))

    def body(self) -> str:
        """A urlencoded submission with a benign default per field. Hidden fields
        (CSRF tokens, ids) keep their server-supplied value so the submit is
        accepted; visible fields get a type-appropriate default."""
        pairs = []
        for f in self.fields:
            if not f.name:
                continue
            pairs.append((f.name, f.value if f.value else _default_value(f.name, f.type)))
        return urlencode(pairs)


def _default_value(name: str, input_type: str) -> str:
    t = (input_type or "text").lower()
    n = (name or "").lower()
    if t in ("hidden", "submit", "button"):
        return ""  # caller keeps the supplied value; empty only if none was given
    if t == "email" or "email" in n:
        return "probe@example.com"
    if t in ("number", "range") or any(k in n for k in ("qty", "quantity", "amount", "count")):
        return "1"
    if t == "checkbox" or t == "radio":
        return "on"
    if t == "url" or "url" in n or "link" in n:
        return "http://example.com/"
    if t == "date":
        return "2020-01-01"
    if t == "password" or "password" in n:
        return "Probe-Passw0rd!"
    if "subject" in n or "title" in n:
        return f"{_MARKER}-subject"
    if "body" in n or "message" in n or "comment" in n or "description" in n or t == "textarea":
        return f"{_MARKER}-body"
    return f"{_MARKER}"


class _FormParser(HTMLParser):
    """Collects <form>s (with their input/select/textarea fields) and <a href>
    links from an HTML document. Robust to unclosed tags -- fields seen while a
    form is open attach to it; a stray input outside any form is ignored."""

    def __init__(self, base_url: str):
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.forms: list[FormAction] = []
        self.links: list[str] = []
        self._cur: FormAction | None = None
        self._in_textarea_name: str | None = None

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "form":
            method = (a.get("method") or "GET").upper()
            action = urljoin(self.base_url, a.get("action") or self.base_url)
            self._cur = FormAction(method=method, action=action,
                                   enctype=a.get("enctype") or "application/x-www-form-urlencoded")
        elif tag in ("input", "select") and self._cur is not None:
            name = a.get("name") or ""
            if name:
                self._cur.fields.append(FormField(
                    name=name, type=a.get("type") or ("select" if tag == "select" else "text"),
                    value=a.get("value") or ""))
        elif tag == "textarea" and self._cur is not None:
            self._in_textarea_name = a.get("name") or ""
            if self._in_textarea_name:
                self._cur.fields.append(FormField(name=self._in_textarea_name, type="textarea"))
        elif tag == "a":
            href = a.get("href") or ""
            if href and not href.startswith(("#", "javascript:", "mailto:", "tel:")):
                self.links.append(urljoin(self.base_url, href))

    def handle_endtag(self, tag):
        if tag == "form" and self._cur is not None:
            self.forms.append(self._cur)
            self._cur = None
        elif tag == "textarea":
            self._in_textarea_name = None


def extract_forms(html: str, base_url: str) -> list[FormAction]:
    p = _FormParser(base_url)
    try:
        p.feed(html or "")
    except Exception as e:  # a malformed doc must not sink the crawl
        log.debug("feature_workflow: HTML parse error on %s: %s", base_url, e)
    if p._cur is not None:  # an unclosed trailing <form>
        p.forms.append(p._cur)
    return p.forms


def extract_links(html: str, base_url: str) -> list[str]:
    p = _FormParser(base_url)
    try:
        p.feed(html or "")
    except Exception:
        pass
    return p.links


# JSON keys whose string value is a navigable link/action to follow.
_JSON_LINK_KEYS = ("href", "url", "link", "self", "next", "location", "endpoint", "action")


def extract_json_links(body: str, base_url: str) -> list[str]:
    """Same-origin links referenced in a JSON API response (HATEOAS-style
    `_links`/`href`, or a bare `url` field) -- so a JSON app's workflow graph is
    walkable too, not just an HTML one."""
    try:
        obj = json.loads(body or "")
    except (ValueError, TypeError):
        return []
    out: list[str] = []

    def _walk(o):
        if isinstance(o, dict):
            for k, v in o.items():
                if isinstance(v, str) and k.lower() in _JSON_LINK_KEYS and ("/" in v):
                    out.append(urljoin(base_url, v))
                elif isinstance(v, (dict, list)):
                    _walk(v)
        elif isinstance(o, list):
            for item in o:
                _walk(item)

    _walk(obj)
    return out


@dataclass
class FeatureCrawlResult:
    base_url: str
    role: str
    captured: list = field(default_factory=list)   # HttpExchange
    steps: int = 0
    forms_submitted: int = 0
    errors: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"base_url": self.base_url, "role": self.role,
                "captured_count": len(self.captured), "steps": self.steps,
                "forms_submitted": self.forms_submitted, "errors": self.errors}


def _same_origin(url: str, base_url: str) -> bool:
    a, b = urlsplit(url), urlsplit(base_url)
    return (a.netloc or b.netloc) == b.netloc


def _looks_html(headers: dict, body: str) -> bool:
    ctype = " ".join(v for k, v in (headers or {}).items() if k.lower() == "content-type").lower()
    if "html" in ctype:
        return True
    if ctype:  # a declared non-HTML type is authoritative
        return False
    return "<html" in (body or "")[:1000].lower() or "<form" in (body or "")[:2000].lower()


async def crawl_features(
    base_url: str,
    role: str,
    headers: dict,
    *,
    fetch_fn,
    seed_paths: list[str] | None = None,
    allowed_hosts: list[str] | None = None,
    submit_forms: bool = True,
    max_steps: int = 40,
    max_depth: int = 3,
    max_captured: int = 200,
) -> FeatureCrawlResult:
    """Drive the app's workflows as `role`, capturing every exchange.

    `fetch_fn(method, url, headers, body) -> response` is the network seam. The
    response must expose `.status_code`, `.text`, and `.headers` (an httpx
    Response, or a test double). Production passes a scope-gated, throttled,
    optionally-gated client wrapper (see `default_fetch_fn`).

    BFS from `seed_paths` (default `/`): GET a node, extract its forms + links,
    enqueue same-origin links, and -- when `submit_forms` -- submit each new form
    with benign defaults and enqueue the result. Deduped by (method, url) for GETs
    and by form signature for submits. Bounded by max_steps and max_depth so a
    large app can't fan out unbounded."""
    result = FeatureCrawlResult(base_url=base_url, role=role)
    origin = f"{urlsplit(base_url).scheme}://{urlsplit(base_url).netloc}"
    seeds = seed_paths or ["/"]
    # queue items: (url, depth). start with GETs of the seeds.
    queue: list[tuple[str, int]] = [(urljoin(base_url + "/", s.lstrip("/")), 0) for s in seeds]
    seen_get: set[str] = set()
    seen_form: set[tuple] = set()

    async def _do(method, url, body):
        if allowed_hosts and (urlsplit(url).hostname or "") not in allowed_hosts:
            return None
        try:
            return await fetch_fn(method, url, dict(headers or {}), body)
        except Exception as e:  # one bad request must not sink the walk
            result.errors.append(f"{method} {url}: {e.__class__.__name__}")
            return None

    def _capture(method, url, body, resp):
        if len(result.captured) >= max_captured:
            return
        result.captured.append(HttpExchange(
            url=url, method=method, request_headers=dict(headers or {}),
            request_body=body or "",
            response_status=getattr(resp, "status_code", None),
            response_headers=dict(getattr(resp, "headers", {}) or {}),
            response_body=getattr(resp, "text", "") or "",
            analyst_note=f"feature_workflow crawl as '{role}' ({method})",
        ))

    while queue and result.steps < max_steps:
        url, depth = queue.pop(0)
        if url in seen_get or not _same_origin(url, base_url):
            continue
        seen_get.add(url)
        resp = await _do("GET", url, None)
        result.steps += 1
        if resp is None:
            continue
        _capture("GET", url, None, resp)
        body = getattr(resp, "text", "") or ""
        resp_headers = dict(getattr(resp, "headers", {}) or {})

        # Enqueue links (HTML anchors + JSON HATEOAS) for the next depth.
        if depth < max_depth:
            links = extract_links(body, url) if _looks_html(resp_headers, body) else []
            links += extract_json_links(body, url)
            for link in links:
                if link.startswith(origin) and link not in seen_get:
                    queue.append((link, depth + 1))

        # Submit forms found on this page (the workflow-driving step).
        if submit_forms and _looks_html(resp_headers, body):
            for form in extract_forms(body, url):
                sig = form.signature()
                if sig in seen_form:
                    continue
                seen_form.add(sig)
                if form.method == "GET":
                    # a GET form is really a filtered navigation -> enqueue.
                    target = form.action
                    q = form.body()
                    if q:
                        target = target + ("&" if "?" in target else "?") + q
                    if depth < max_depth and target.startswith(origin):
                        queue.append((target, depth + 1))
                    continue
                sub_body = form.body()
                sub_resp = await _do(form.method, form.action, sub_body)
                result.steps += 1
                if sub_resp is None:
                    continue
                result.forms_submitted += 1
                _capture(form.method, form.action, sub_body, sub_resp)
                # follow the result page (a create usually redirects/renders the object)
                loc = _redirect_location(sub_resp, form.action)
                if loc and depth < max_depth and loc.startswith(origin) and loc not in seen_get:
                    queue.append((loc, depth + 1))

    log.info("feature_workflow: crawled %s as %r -- %d steps, %d forms submitted, %d captured",
             base_url, role, result.steps, result.forms_submitted, len(result.captured))
    return result


def _redirect_location(resp, fallback: str) -> str | None:
    status = getattr(resp, "status_code", None)
    headers = getattr(resp, "headers", {}) or {}
    loc = next((v for k, v in headers.items() if k.lower() == "location"), None)
    if status and 300 <= status < 400 and loc:
        return urljoin(fallback, loc)
    return None


def default_fetch_fn(allowed_hosts: list[str] | None = None, *, timeout: float = 15.0,
                     gate=None, validator_name: str = "feature_workflow"):
    """A production `fetch_fn`: scope-gated + globally-throttled. Mutating
    submits route through the safety gate (`GatedAsyncClient`) so the crawl obeys
    the same allow_mutating_replay authorisation as every other active leg; GETs
    use a plain client. Returned as a closure so `crawl_features` stays
    network-agnostic and fully unit-testable with an in-memory double."""
    import global_throttle
    import httpx
    from safety_gate import GatedAsyncClient, get_default_gate

    _gate = gate or get_default_gate()

    async def _fetch(method, url, req_headers, body):
        await global_throttle.acquire()
        m = (method or "GET").upper()
        if m in ("GET", "HEAD", "OPTIONS"):
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=False,
                                         verify=False) as client:
                return await client.request(m, url, headers=req_headers or None)
        async with GatedAsyncClient(_gate, validator_name, timeout=timeout,
                                    follow_redirects=False, verify=False) as client:
            return await client.request(m, url, headers=req_headers or None, content=body or None)

    return _fetch


def run_context_fetch_fn(run_context, session_ref: str | None, *,
                         validator_name: str = "feature_workflow"):
    """Production fetch adapter backed by one invocation's Executor."""
    from types import SimpleNamespace
    from run_context import TypedRequest

    async def _fetch(method, url, req_headers, body):
        safe_headers = {k: v for k, v in (req_headers or {}).items()
                        if k.lower() not in ("authorization", "cookie", "proxy-authorization")}
        outcome = await run_context.executor().execute(
            TypedRequest((method or "GET").upper(), url, headers=safe_headers,
                         body=body or None),
            capability=validator_name, session_ref=session_ref)
        if not outcome.ok:
            raise RuntimeError(f"transport declined: {outcome.outcome}")
        return SimpleNamespace(status_code=outcome.status, text=outcome.body,
                               headers=outcome.headers)

    return _fetch
