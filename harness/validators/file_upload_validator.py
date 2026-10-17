"""
File-upload extension/content-type bypass leg (V33, WSTG-BUSL-09).

Per LEG_DECISIONS.md: confirm only the SAFE slice — that a file with a
disallowed content-type/extension is stored and retrievable (no execution).
Does NOT attempt RCE via uploaded executables.

Oracle: upload a benign file with a disallowed extension (.html), then
request the stored URL and check if the content is served back. If the
server stores and serves a .html file, the upload filter is bypassable.

Active; the upload is a POST (mutating), gated by allow_mutating_replay.
"""
from __future__ import annotations

import secrets
from urllib.parse import urlsplit

import httpx

from harness import global_throttle
from harness.models import Finding, HttpExchange
from harness.safety_gate import GatedAsyncClient, get_default_gate, SafetyGateBlocked
from .base import Validator, ValidationResult
from .injection_targets import replay_headers

_NONCE = secrets.token_hex(6)
_BENIGN_HTML = f"<!-- harness-upload-test-{_NONCE} -->"


class FileUploadValidator(Validator):
    name = "file_upload"
    finding_classes = {"file_upload", "file upload", "arbitrary file upload",
                       "file upload vulnerability", "unrestricted file upload"}
    active = True

    def __init__(self, *, allowed_hosts: list[str] | None = None, timeout: float = 15.0):
        self.allowed_hosts = allowed_hosts or []
        self.timeout = timeout

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

    async def _upload_form_from_source(self, client, exchange: HttpExchange, headers: dict):
        """GET the source page in THIS session and return the multipart upload form
        whose action targets this endpoint: (action_url, file_field, extra_fields
        with a FRESH csrf). None when no matching file form is discoverable, so the
        caller falls back to a bare single-field upload."""
        from harness.validators.source_form import fetch_source_form
        action_path = urlsplit(exchange.url).path

        def select(forms):
            file_forms = [f for f in forms if any((x.type or "").lower() == "file" for x in f.fields)]
            match = [f for f in file_forms if urlsplit(f.action).path == action_path] or file_forms
            return match[0] if match else None

        found = await fetch_source_form(client, self._source_page_candidates(exchange),
                                        headers, select)
        if found is None:
            return None
        f = found.form
        file_field = next((x.name for x in f.fields
                           if (x.type or "").lower() == "file" and x.name), "file")
        extra = {x.name: (x.value or "") for x in f.fields
                 if x.name and (x.type or "").lower() != "file"}
        return f.action, file_field, extra

    async def validate(self, finding: Finding, exchange: HttpExchange) -> ValidationResult:
        host = urlsplit(exchange.url).hostname or ""
        if self.allowed_hosts and host not in self.allowed_hosts:
            return self._skip(f"host {host!r} out of scope")

        method = (exchange.method or "GET").upper()
        if method not in ("POST", "PUT", "PATCH"):
            return self._skip("endpoint does not accept file uploads")

        url = exchange.url
        headers = replay_headers(exchange)

        nonce = secrets.token_hex(8)
        marker = f"<!-- harness-upload-{nonce} -->"
        filename = f"test-{nonce}.html"

        import io
        file_field = "file"
        extra_fields: dict = {}

        try:
            await global_throttle.acquire()
            async with GatedAsyncClient(get_default_gate(), self.name, timeout=self.timeout,
                                        follow_redirects=True, verify=False) as client:
                # Multipart uploads are commonly CSRF-token-bound and use a specific
                # file-field name (e.g. `avatar`) alongside hidden fields (csrf,
                # user). Replaying a bare `file` part with no token is rejected, so
                # discover the real form in-session first; the captured token would
                # belong to another session and be refused.
                found = await self._upload_form_from_source(client, exchange, headers)
                if found is not None:
                    url, file_field, extra_fields = found
                read_headers = {k: v for k, v in (headers or {}).items()
                                if (k or "").lower() != "content-type"}
                files_data = {file_field: (filename, io.BytesIO(marker.encode()), "text/html")}
                # GatedAsyncClient exposes only .request() (R04): calling .post()/.get()
                # raised AttributeError before any request was ever sent.
                resp = await client.request(method, url, headers=read_headers or None,
                                            data=extra_fields or None, files=files_data)
                return await self._after_upload(client, resp, url, read_headers, marker, filename)
        except SafetyGateBlocked:
            return self._skip("mutating file upload not authorized (set validators.allow_mutating_replay)")
        except httpx.HTTPError as e:
            return ValidationResult(
                self.name, "error", "file_upload", summary=f"upload HTTP error: {e}")

    async def _after_upload(self, client, resp, url, headers, marker, filename):
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
        for cand in ordered:
            try:
                await global_throttle.acquire()
                r = await client.request("GET", cand, headers=headers or None)
            except httpx.HTTPError:
                continue
            if r.status_code < 400 and marker in (r.text or ""):
                retrieve, upload_url = r, cand
                break

        if retrieve is None:
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
