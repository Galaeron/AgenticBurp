"""
File-upload extension/content-type bypass leg (V33, WSTG-BUSL-08 Upload of
Unexpected File Types: a benign file of a disallowed type, never a malicious one).

Per LEG_DECISIONS.md: confirm only the SAFE slice — that a file with a
disallowed content-type/extension is stored and retrievable (no execution).
Does NOT attempt RCE via uploaded executables.

Oracle: upload a benign file with a disallowed extension (.html), then
request the stored URL and check if the content is served back. If the
server stores and serves a .html file, the upload filter is bypassable.

Policy lead (oracle gap): an upload the server accepts but never serves back
cannot confirm under the owner rule above, yet the app may DECLARE a policy the
server does not enforce -- a file input's `accept`, or an uploader's allowed
types / maximum size in a same-origin script near the endpoint's path. When the
.html upload was accepted against such a declared type policy, the leg sends one
conforming control file (it must be accepted alike), and against a declared
size limit one conforming file just over it. Acceptance the declared policy
forbids is reported as a clearly labelled LEAD (not_confirmed, control_outcome
"inconclusive"), never a confirmation; with no declared policy the old negative
stands.

Active; the upload is a POST (mutating), gated by allow_mutating_replay.

Bound to a run (`run_context`, set by the registry and the coverage drive), every
send -- the source-form read, the upload, fetch-backs and the policy lead's
control/over-size uploads -- goes through THAT run's executor, so its gate,
scope, budget, cancellation and change log decide, never the process default
gate. Unbound, the leg keeps the default-gate path it always had.
"""
from __future__ import annotations
from harness import scope_lock

import re
import secrets
from urllib.parse import urljoin, urlsplit

import httpx

from harness import global_throttle, upload_files
from harness.models import Finding, HttpExchange
from harness.safety_gate import GatedAsyncClient, get_default_gate, SafetyGateBlocked
from .base import Validator, ValidationResult
from .injection_targets import replay_headers

_NONCE = secrets.token_hex(6)
_BENIGN_HTML = f"<!-- harness-upload-test-{_NONCE} -->"

# A 2xx upload answer that still says no.
_REJECTION_WORDS = re.compile(
    r"\b(?:error|invalid|not allowed|disallowed|rejected|unsupported|denied|forbidden|"
    r"too large|too big|exceed(?:s|ed)?|failed|not permitted)\b", re.I)
# Declared-policy discovery: pages and same-origin scripts read, and the window
# around the endpoint's path in a script where an uploader's config is looked for.
_MAX_POLICY_PAGES = 2
_MAX_POLICY_SCRIPTS = 8
_POLICY_WINDOW = 4000
_SIZE_PROBE_CAP = 2 * 1024 * 1024
_TYPE_LIST_KEYS = (r"allowedMimeTypes?|allowedFileTypes?|allowedTypes|allowedExtensions|"
                   r"acceptedFileTypes|acceptedMimeTypes|allowedContentTypes|acceptedTypes")
_TYPE_LIST = re.compile(r"""(?<![\w$])["'`]?(?:%s)["'`]?\s*[:=]\s*\[([^\]]{0,800})\]"""
                        % _TYPE_LIST_KEYS)
_TYPE_STRING = re.compile(
    r"""(?<![\w$-])["'`]?(acceptedFiles|accept)["'`]?\s*[:=,]\s*["'`]([^"'`<>]{1,200})["'`]""")
_SIZE_VALUE = re.compile(
    r"""(?<![\w$])["'`]?(maxFileSize|fileSizeLimit|maxSize|sizeLimit|maxBytes)["'`]?\s*[:=]\s*"""
    r"""(["'`][0-9.]+\s*(?:[kKmM]i?)?[bB]?["'`]|[0-9][0-9eE.+]*(?:\s*\*\s*[0-9][0-9eE.+]*)*)""")
_SIZE_MB = re.compile(r"""(?<![\w$])["'`]?maxFilesize["'`]?\s*[:=]\s*([0-9]+(?:\.[0-9]+)?)""")
_QUOTED = re.compile(r"""["'`]([^"'`]{1,80})["'`]""")  # backticks: minified template literals
_FILE_INPUT = re.compile(r"<input\b[^>]*\btype\s*=\s*[\"']?file\b[^>]*>", re.I)
_ACCEPT_ATTR = re.compile(r"""\baccept\s*=\s*["']([^"']*)["']""", re.I)
_SCRIPT_SRC = re.compile(r"""<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']""", re.I)
_NOTE_ACCEPT = re.compile(r"\baccept=([^)\s;]+)")
# Keys that name an upload policy outright; a generic one (`accept`, `maxSize`)
# counts only with "file"/"upload" just before it (not an HTTP Accept header).
_SPECIFIC_KEYS = {"acceptedFiles", "maxFileSize", "fileSizeLimit"}
_MIN_DECLARED_SIZE = 1024


def _file_context(text: str, at: int) -> bool:
    return re.search(r"file|upload", text[max(0, at - 300):at], re.I) is not None


def _type_token(raw: str) -> str:
    """An accept-style token (".pdf", "application/pdf", "image/*") for a declared
    type, or "" when it is not one."""
    tok = (raw or "").strip().strip("'\"").lower().split(";", 1)[0].strip()
    if not tok:
        return ""
    if tok in ("*", "*/*") or tok.startswith(".") or re.fullmatch(r"[a-z0-9.+-]+/[a-z0-9.+*-]+", tok):
        return tok
    if re.fullmatch(r"[a-z0-9]{1,8}", tok):
        return "." + tok
    return ""


def _size_bytes(raw: str, unit_mb: bool = False) -> int | None:
    raw = (raw or "").strip().strip("'\"`")
    try:
        if unit_mb:
            value = float(raw) * 1024 * 1024
        else:
            m = re.fullmatch(r"([0-9.]+)\s*([kKmM]i?)?[bB]?", raw)
            if m:
                mult = {"k": 1024, "m": 1024 * 1024}.get((m.group(2) or "")[:1].lower(), 1)
                value = float(m.group(1)) * mult
            else:
                value = 1.0
                for factor in raw.split("*"):
                    value *= float(factor.strip())
    except ValueError:
        return None
    return int(value) if 1 <= value <= 10 ** 10 else None


def declared_policy_in(text: str) -> tuple[list[str], int | None]:
    """(allowed type tokens, max size in bytes) an uploader config or a file
    input declares in `text`."""
    tokens: list[str] = []
    for m in _TYPE_LIST.finditer(text):
        tokens.extend(_type_token(q) for q in _QUOTED.findall(m.group(1)))
    for m in _TYPE_STRING.finditer(text):
        if m.group(1) in _SPECIFIC_KEYS or _file_context(text, m.start()):
            tokens.extend(_type_token(t) for t in m.group(2).split(","))
    for tag in _FILE_INPUT.findall(text):
        attr = _ACCEPT_ATTR.search(tag)
        if attr:
            tokens.extend(_type_token(t) for t in attr.group(1).split(","))
    sizes = [_size_bytes(m.group(2)) for m in _SIZE_VALUE.finditer(text)
             if m.group(1) in _SPECIFIC_KEYS or _file_context(text, m.start())]
    sizes += [_size_bytes(m.group(1), True) for m in _SIZE_MB.finditer(text)]
    sizes = [b for b in sizes if b and b >= _MIN_DECLARED_SIZE]
    seen, out = set(), []
    for t in tokens:
        if t and t not in seen:
            seen.add(t); out.append(t)
    return out, (min(sizes) if sizes else None)


def _accepted(resp) -> bool:
    if resp is None or not 200 <= resp.status_code < 300:
        return False
    return not _REJECTION_WORDS.search((resp.text or "")[:2000])


def _padded(mime: str, data: bytes, size: int) -> bytes:
    pad = size - len(data)
    if pad <= 0:
        return data
    if mime == "application/pdf":
        return data + b"\n%" + b"0" * max(pad - 2, 0)
    if mime.startswith("text/") or mime.endswith(("json", "xml", "csv")):
        return data + b"\n" * pad
    return data + b"\0" * pad


class FileUploadValidator(Validator):
    name = "file_upload"
    finding_classes = {"file_upload", "file upload", "arbitrary file upload",
                       "file upload vulnerability", "unrestricted file upload"}
    active = True

    def __init__(self, *, allowed_hosts: list[str] | None = None, timeout: float = 15.0,
                 run_context=None):
        self.allowed_hosts = allowed_hosts or []
        self.timeout = timeout
        self.run_context = run_context

    def applies(self, finding: Finding, exchange: HttpExchange) -> bool:
        if not super().applies(finding, exchange):
            return False
        method = (exchange.method or "GET").upper()
        return method in ("POST", "PUT", "PATCH")

    def _skip(self, why: str) -> ValidationResult:
        return ValidationResult(self.name, "skipped", "file_upload", summary=why)

    def _source_page_candidates(self, exchange: HttpExchange) -> list[str]:
        """Where the multipart upload form (with its fresh CSRF token and its real
        field names) is most likely rendered. Generic: the Referer, then the parent
        resource carrying each id-shaped body value, then the bare parent."""
        parts = urlsplit(exchange.url)
        base = f"{parts.scheme}://{parts.netloc}"
        cands: list[str] = []
        for k, v in (exchange.request_headers or {}).items():
            if (k or "").lower() == "referer" and v:
                cands.append(v)
        segs = [s for s in parts.path.split("/") if s]
        parent = "/" + "/".join(segs[:-1]) if len(segs) >= 1 else "/"
        from urllib.parse import parse_qsl
        for k, val in parse_qsl(exchange.request_body or "", keep_blank_values=True):
            low = (k or "").lower()
            if val and (low in ("id", "user", "username") or low.endswith("id")):
                cands.append(f"{base}{parent}?id={val}")
        cands.append(f"{base}{parent}")
        seen, out = set(), []
        for u in cands:
            if u and u not in seen:
                seen.add(u); out.append(u)
        return out

    async def _upload_form_from_source(self, client, exchange: HttpExchange, headers: dict,
                                       failures: list[str] | None = None):
        """GET the source page in THIS session and return the multipart upload form
        whose action targets this endpoint: (action_url, file_field, extra_fields
        with a FRESH csrf). None when no matching file form is discoverable, so the
        caller falls back to a bare single-field upload. A candidate page that
        never answered is recorded in `failures`."""
        from harness.validators.source_form import fetch_source_form
        action_path = urlsplit(exchange.url).path

        def select(forms):
            file_forms = [f for f in forms if any((x.type or "").lower() == "file" for x in f.fields)]
            match = [f for f in file_forms if urlsplit(f.action).path == action_path] or file_forms
            return match[0] if match else None

        try:
            found = await fetch_source_form(client, self._source_page_candidates(exchange),
                                            headers, select, failures=failures)
        except SafetyGateBlocked as e:
            if failures is None:
                raise
            failures.append(f"source page: refused ({e.decision.reason})")
            return None
        if found is None:
            return None
        f = found.form
        file_input = next((x for x in f.fields
                           if (x.type or "").lower() == "file" and x.name), None)
        file_field = file_input.name if file_input is not None else "file"
        extra = {x.name: (x.value or "") for x in f.fields
                 if x.name and (x.type or "").lower() != "file"}
        accept = (getattr(file_input, "accept", "") or "") if file_input is not None else ""
        return f.action, file_field, extra, accept

    @staticmethod
    def _captured_multipart(exchange: HttpExchange):
        """(file field, other text fields) of a captured multipart upload -- e.g. one
        a page's script issued with no HTML form to re-read -- or None."""
        import re
        ctype = next((str(v) for k, v in (exchange.request_headers or {}).items()
                      if (k or "").lower() == "content-type"), "")
        boundary = re.search(r'boundary="?([^";]+)"?', ctype, re.I)
        if "multipart/form-data" not in ctype.lower() or not boundary:
            return None
        file_field, extra = None, {}
        for part in (exchange.request_body or "").split("--" + boundary.group(1)):
            head, sep, value = part.partition("\r\n\r\n")
            name = re.search(r'\bname="([^"]*)"', head)
            if not sep or not name or not name.group(1):
                continue
            if re.search(r'\bfilename="', head):
                file_field = file_field or name.group(1)
            else:
                extra.setdefault(name.group(1), value[:-2] if value.endswith("\r\n") else value)
        return (file_field, extra) if file_field else None

    async def validate(self, finding: Finding, exchange: HttpExchange) -> ValidationResult:
        host = urlsplit(exchange.url).hostname or ""
        if self.allowed_hosts and not scope_lock.host_in_scope(exchange.url, self.allowed_hosts):
            return self._skip(f"host {host!r} out of scope")

        method = (exchange.method or "GET").upper()
        if method not in ("POST", "PUT", "PATCH"):
            return self._skip("endpoint does not accept file uploads")
        # The leg's verdict needs the mutating upload, so with mutating replay off it
        # sends nothing at all (not even the read-only source-form fetch).
        # Bound to a run, the RUN's gate decides: an ambient or process-default gate
        # that allows mutating replay must not override a run that does not.
        run = self.run_context
        gate = run.gate if run is not None else get_default_gate()
        if not gate.config.allow_mutating_replay:
            return self._skip("mutating file upload not authorized (set validators.allow_mutating_replay)")

        url = exchange.url
        headers = replay_headers(exchange)

        nonce = secrets.token_hex(8)
        marker = f"<!-- harness-upload-{nonce} -->"
        filename = f"test-{nonce}.html"

        import io
        file_field = "file"
        extra_fields: dict = {}
        form_accept = ""

        try:
            await global_throttle.acquire()
            if run is not None:
                # Every send through the bound run's executor (its gate, scope,
                # budget, cancellation and change log), as verb_tamper's _request.
                client_cm = GatedAsyncClient(run.gate, self.name, run_context=run,
                                             timeout=self.timeout, follow_redirects=True,
                                             verify=False)
            else:
                client_cm = GatedAsyncClient(get_default_gate(), self.name, timeout=self.timeout,
                                             follow_redirects=True, verify=False)
            async with client_cm as client:
                # Multipart uploads are commonly CSRF-token-bound and use a specific
                # file-field name (e.g. `avatar`) alongside hidden fields (csrf,
                # user). Replaying a bare `file` part with no token is rejected, so
                # discover the real form in-session first; the captured token would
                # belong to another session and be refused.
                source_failures: list[str] = []
                found = await self._upload_form_from_source(client, exchange, headers,
                                                             source_failures)
                if found is not None:
                    url, file_field, extra_fields, form_accept = found
                elif (captured := self._captured_multipart(exchange)) is not None:
                    # No form to re-read: the captured upload's own field names.
                    file_field, extra_fields = captured
                read_headers = {k: v for k, v in (headers or {}).items()
                                if (k or "").lower() != "content-type"}
                files_data = {file_field: (filename, io.BytesIO(marker.encode()), "text/html")}
                # GatedAsyncClient exposes only .request() (R04): calling .post()/.get()
                # raised AttributeError before any request was ever sent.
                resp = await client.request(method, url, headers=read_headers or None,
                                            data=extra_fields or None, files=files_data)

                async def upload(name: str, data: bytes, mime: str):
                    await global_throttle.acquire()
                    return await client.request(
                        method, url, headers=read_headers or None, data=extra_fields or None,
                        files={file_field: (name, io.BytesIO(data), mime)})

                policy_ctx = {"exchange": exchange, "form_accept": form_accept,
                              "upload": upload}
                return await self._after_upload(client, resp, url, read_headers, marker, filename,
                                                source_failures, policy_ctx=policy_ctx)
        except SafetyGateBlocked as e:
            if run is not None:
                return self._skip(f"file upload not sent: refused by the run ({e.decision.reason})")
            return self._skip("mutating file upload not authorized (set validators.allow_mutating_replay)")
        except httpx.HTTPError as e:
            return ValidationResult(
                self.name, "error", "file_upload", summary=f"upload HTTP error: {e}")

    async def _after_upload(self, client, resp, url, headers, marker, filename,
                            source_failures: list[str] | None = None, *,
                            policy_ctx: dict | None = None):
        # A send that got no response is not part of a negative (RV-P P9): a
        # rejection may be the token the unread source page would have minted,
        # and a stored copy may sit behind a fetch-back that never answered.
        if resp.status_code >= 400 and source_failures:
            return ValidationResult(
                self.name, "inconclusive", "file_upload", confidence=0.0, confirmed=False,
                summary=f"File-upload check incomplete: the in-session upload form could not be read "
                        f"({'; '.join(source_failures[:3])}), so the rejection (HTTP "
                        f"{resp.status_code}) may be a missing token or field; not a negative result",
                evidence=f"POST {url} with {filename} (text/html) → {resp.status_code} without the "
                         f"source page's fresh form fields.")
        if resp.status_code >= 400:
            return ValidationResult(
                self.name, "not_confirmed", "file_upload", confidence=0.0, confirmed=False,
                summary=f"Upload rejected with status {resp.status_code}.",
                evidence=f"POST {url} with {filename} (text/html) → {resp.status_code}.")

        import re
        p = urlsplit(url)
        origin = f"{p.scheme}://{p.netloc}"

        def _abs(val: str):
            val = (val or "").strip('"\'')
            if val.startswith("/"):
                return f"{origin}{val}"
            if val.startswith("http"):
                return val
            return None

        candidates: list[str] = []
        body = resp.text or ""
        if filename in body:
            m = re.search(r'(?:href|src|url)["\s:=]+([^\s"<>]+' + re.escape(filename) + r')', body)
            if m:
                u = _abs(m.group(1))
                if u:
                    candidates.append(u)
        try:
            resp_json = resp.json()
            for key in ("url", "path", "file_url", "download_url", "location"):
                if isinstance(resp_json.get(key), str):
                    u = _abs(resp_json[key])
                    if u:
                        candidates.append(u)
        except Exception:
            pass
        # Heuristic serving paths: many apps store an upload under a predictable
        # collection (e.g. /files/avatars/<name>) without echoing its URL in the
        # response, so probe the common ones by the exact filename.
        for base_path in ("/files/avatars/", "/files/", "/avatars/", "/uploads/"):
            candidates.append(f"{origin}{base_path}{filename}")

        seen, ordered = set(), []
        for u in candidates:
            if u not in seen:
                seen.add(u); ordered.append(u)

        retrieve, upload_url = None, None
        refused, errors, answered = "", [], 0
        for cand in ordered:
            try:
                await global_throttle.acquire()
                r = await client.request("GET", cand, headers=headers or None)
            except SafetyGateBlocked as e:
                # Nothing more can send once the gate refuses (budget, scope).
                refused = e.decision.reason
                break
            except httpx.HTTPError as e:
                errors.append(f"GET {cand}: {e.__class__.__name__}")
                continue
            answered += 1
            if r.status_code < 400 and marker in (r.text or ""):
                retrieve, upload_url = r, cand
                break

        if retrieve is None and (refused or errors):
            why = "; ".join(([f"refused by the safety gate ({refused})"] if refused else []) + errors[:3])
            return ValidationResult(
                self.name, "inconclusive", "file_upload", confidence=0.0, confirmed=False,
                summary=f"File-upload check incomplete: {len(ordered) - answered} of {len(ordered)} "
                        f"fetch-back(s) got no response ({why}); not a negative result",
                evidence=f"Upload succeeded ({resp.status_code}); {answered} answered candidate "
                         f"serving URL(s) did not return the marker, but a URL that never answered "
                         f"cannot show it.")

        if retrieve is None:
            if policy_ctx is not None:
                lead = await self._policy_lead(client, policy_ctx, resp, url, headers,
                                               filename, len(ordered))
                if lead is not None:
                    return lead
            return ValidationResult(
                self.name, "not_confirmed", "file_upload", confidence=0.3, confirmed=False,
                summary="File accepted but the stored copy was not retrievable with our marker.",
                evidence=f"Upload succeeded ({resp.status_code}) but none of {len(ordered)} candidate "
                         f"serving URL(s) returned the uploaded marker.")

        if marker in (retrieve.text or ""):
            content_type = retrieve.headers.get("content-type", "") or ""
            disposition = (retrieve.headers.get("content-disposition", "") or "").lower()
            ctl = content_type.lower()
            # Oracle tightened (review 2026-09-09): a stored+served .html is only a
            # DANGEROUS bypass when served as an active execution context -- an
            # HTML/script/svg Content-Type and NOT forced as an attachment. Served
            # as text/plain or as an attachment is a benign storage bypass, not a
            # confirmed dangerous upload -> observation.
            served_active = (("html" in ctl or "javascript" in ctl or "xml" in ctl
                              or ctl.startswith("image/svg")) and "attachment" not in disposition)
            if served_active:
                return ValidationResult(
                    self.name, "confirmed", "file_upload", confidence=0.90, confirmed=True,
                    summary=f"File upload bypass confirmed: .html file stored and served as an active "
                            f"context (content-type: {content_type}).",
                    evidence=f"Uploaded {filename} (text/html) -> stored at {upload_url}. Retrieved and "
                             f"found our marker, served as {content_type} (no attachment disposition).")
            return ValidationResult(
                self.name, "not_confirmed", "file_upload", confidence=0.4, confirmed=False,
                summary=f"OBSERVATION (not confirmed): the .html upload was stored and served, but as "
                        f"content-type {content_type!r}"
                        f"{' (attachment)' if 'attachment' in disposition else ''} -- not an active "
                        f"HTML/script execution context, so not a dangerous upload.",
                evidence=f"Uploaded {filename}; retrieved at {upload_url} served as {content_type!r}.")

        return ValidationResult(
            self.name, "not_confirmed", "file_upload", confidence=0.1, confirmed=False,
            summary="Uploaded file retrievable but marker not found — file may have been sanitized.",
            evidence=f"Retrieved {upload_url} but the injected marker was absent.")

    async def _declared_policy(self, client, policy_ctx: dict, url: str, headers: dict):
        """(allowed type tokens, max bytes, where it was declared) the app states
        for this upload, or None. Read in order: the in-session form's file input,
        the capture's driver note, then the Referer / origin page's file inputs and
        its same-origin scripts near the endpoint's path."""
        exchange = policy_ctx.get("exchange")
        accept = (policy_ctx.get("form_accept") or "").strip()
        if accept:
            tokens = [t for t in (_type_token(x) for x in accept.split(",")) if t]
            if tokens:
                return tokens, None, f"the upload form's file input (accept={accept!r})"
        note = _NOTE_ACCEPT.search(getattr(exchange, "analyst_note", "") or "")
        if note and note.group(1).lower() != "any":
            tokens = [t for t in (_type_token(x) for x in note.group(1).split(",")) if t]
            if tokens:
                return tokens, None, f"the captured file input (accept={note.group(1)!r})"
        parts = urlsplit(url)
        origin = f"{parts.scheme}://{parts.netloc}"
        path = parts.path or "/"
        needles = [n for n in (path, path.lstrip("/")) if len(n.strip("/")) >= 4]
        pages = [v for k, v in ((exchange.request_headers or {}).items() if exchange else ())
                 if (k or "").lower() == "referer" and v]
        pages.append(origin + "/")
        tokens: list[str] = []
        size: int | None = None
        where: list[str] = []
        scripts: list[str] = []
        for page in list(dict.fromkeys(pages))[:_MAX_POLICY_PAGES]:
            if urlsplit(page).netloc != parts.netloc:
                continue
            text = await self._read_text(client, page, headers)
            if text is None:
                continue
            found, _ = declared_policy_in("".join(_FILE_INPUT.findall(text)))
            if found:
                tokens.extend(found); where.append(f"a file input on {page}")
            for src in _SCRIPT_SRC.findall(text):
                full = urljoin(page, src)
                if urlsplit(full).netloc == parts.netloc and full not in scripts:
                    scripts.append(full)
        for script in scripts[:_MAX_POLICY_SCRIPTS]:
            text = await self._read_text(client, script, headers)
            if not text:
                continue
            for needle in needles:
                spots = [m.start() for m in re.finditer(re.escape(needle), text)][:5]
                for at in spots:
                    found, limit = declared_policy_in(
                        text[max(0, at - _POLICY_WINDOW):at + _POLICY_WINDOW])
                    if found or limit:
                        tokens.extend(found)
                        size = limit if size is None or (limit and limit < size) else size
                        where.append(f"an uploader config near {needle!r} in {script}")
                if spots:
                    break
        tokens = list(dict.fromkeys(t for t in tokens if t))
        if not tokens and not size:
            return None
        return tokens, size, "; ".join(dict.fromkeys(where))

    async def _read_text(self, client, url: str, headers: dict) -> str | None:
        try:
            await global_throttle.acquire()
            r = await client.request("GET", url, headers=headers or None)
        except (SafetyGateBlocked, httpx.HTTPError):
            return None
        if r.status_code >= 400:
            return None
        return (r.text or "")[:4_000_000]

    async def _policy_lead(self, client, policy_ctx: dict, resp, url: str, headers: dict,
                           filename: str, n_candidates: int):
        """A labelled lead when the server accepted what the app's own declared
        policy forbids; None when no declared policy was found or none was broken."""
        policy = await self._declared_policy(client, policy_ctx, url, headers)
        if policy is None:
            return None
        tokens, max_size, where = policy
        upload = policy_ctx["upload"]
        html_allowed = not tokens or upload_files._allows(tokens, "html", ("htm",), ("text/html",))
        benign = upload_files.benign_file(",".join(tokens), secrets.token_hex(6))
        notes, leads, held = [], [], []

        async def send(name, data, mime):
            try:
                return await upload(name, data, mime), ""
            except SafetyGateBlocked as e:
                return None, f"refused by the safety gate ({e.decision.reason})"
            except httpx.HTTPError as e:
                return None, e.__class__.__name__

        if not html_allowed and _accepted(resp):
            if benign is None:
                notes.append("no benign file type fits the declared policy, so no control "
                             "upload was sent")
                leads.append(f"the server accepted {filename} (text/html, HTTP "
                             f"{resp.status_code}) though only {', '.join(tokens)} is allowed")
            else:
                cname, cmime, cdata = benign
                control, why = await send(cname, cdata, cmime)
                if control is None:
                    notes.append(f"the conforming control upload {cname} was not answered ({why})")
                    leads.append(f"the server accepted {filename} (text/html, HTTP "
                                 f"{resp.status_code}) though only {', '.join(tokens)} is "
                                 f"allowed")
                elif not _accepted(control):
                    return ValidationResult(
                        self.name, "inconclusive", "file_upload", confidence=0.0,
                        confirmed=False,
                        summary=f"File-upload check incomplete: the .html upload was accepted "
                                f"(HTTP {resp.status_code}) but a conforming control file "
                                f"{cname} ({cmime}) was rejected (HTTP {control.status_code}), "
                                f"so acceptance cannot be read against the declared policy",
                        evidence=f"Declared policy: {', '.join(tokens)} ({where}).")
                else:
                    held.append(f"the conforming control {cname} ({cmime}) was accepted alike "
                                f"(HTTP {control.status_code})")
                    leads.append(f"the server accepted {filename} (text/html, HTTP "
                                 f"{resp.status_code}) though only {', '.join(tokens)} is "
                                 f"allowed")
        sized = benign
        if sized is None and html_allowed:
            nonce = secrets.token_hex(6)
            sized = (f"harness-upload-{nonce}.html", "text/html",
                     f"<!-- harness-upload-{nonce} -->".encode())
        if max_size and max_size <= _SIZE_PROBE_CAP and sized is not None:
            cname, cmime, cdata = sized
            over = max_size + max(1024, max_size // 10)
            big, why = await send(cname, _padded(cmime, cdata, over), cmime)
            if big is None:
                notes.append(f"the over-size probe was not answered ({why})")
            elif _accepted(big):
                leads.append(f"the server accepted a conforming {cmime} file of {over} bytes "
                             f"(HTTP {big.status_code}) over the declared {max_size}-byte limit")
            else:
                held.append(f"a conforming {cmime} file of {over} bytes over the declared "
                            f"{max_size}-byte limit was rejected (HTTP {big.status_code})")
        if not leads:
            return None
        detail = "; ".join(leads)
        controls = ("; ".join(held) + ". ") if held else ""
        extra = ("; ".join(notes) + ". ") if notes else ""
        result = ValidationResult(
            self.name, "not_confirmed", "file_upload", confidence=0.5, confirmed=False,
            summary=f"Lead, not confirmed (owner rule: confirmation needs the stored copy served "
                    f"back): {detail}, a policy the app itself declares ({where}).",
            evidence=f"Declared policy: types {', '.join(tokens) or 'any'}"
                     f"{f', max {max_size} bytes' if max_size else ''} ({where}). {controls}"
                     f"{extra}None of {n_candidates} candidate serving URL(s) returned the "
                     f"uploaded marker.")
        result.control_outcome = "inconclusive"
        result.limitation = ("The server accepted an upload its own declared policy forbids, but "
                             "the stored copy could not be fetched back, so the owner rule "
                             "(stored and served) is not met; client-side-only enforcement is a "
                             "lead, not a confirmed upload bypass.")
        result.manual_verification = (
            f"Locate where {url} stores uploads (response, UI or storage) and fetch the "
            f"uploaded file back; check the server enforces the declared policy ({where}).")
        return result
