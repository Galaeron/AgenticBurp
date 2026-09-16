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
        files_data = {
            "file": (filename, io.BytesIO(marker.encode()), "text/html"),
        }

        try:
            await global_throttle.acquire()
            async with GatedAsyncClient(get_default_gate(), self.name, timeout=self.timeout,
                                        follow_redirects=True, verify=False) as client:
                # GatedAsyncClient exposes only .request() (R04): calling .post()/.get()
                # raised AttributeError before any request was ever sent.
                resp = await client.request(method, url, headers=headers or None, files=files_data)
        except SafetyGateBlocked:
            return self._skip("mutating file upload not authorized (set validators.allow_mutating_replay)")
        except httpx.HTTPError as e:
            return ValidationResult(
                self.name, "error", "file_upload", summary=f"upload HTTP error: {e}")

        if resp.status_code >= 400:
            return ValidationResult(
                self.name, "not_confirmed", "file_upload", confidence=0.0, confirmed=False,
                summary=f"Upload rejected with status {resp.status_code}.",
                evidence=f"POST {url} with {filename} (text/html) → {resp.status_code}.")

        upload_url = None
        body = resp.text or ""
        if filename in body:
            import re
            m = re.search(r'(?:href|src|url)["\s:=]+([^\s"<>]+' + re.escape(filename) + r')', body)
            if m:
                found = m.group(1).strip('"\'')
                if found.startswith("/"):
                    p = urlsplit(url)
                    upload_url = f"{p.scheme}://{p.netloc}{found}"
                elif found.startswith("http"):
                    upload_url = found

        if not upload_url:
            try:
                resp_json = resp.json()
                for key in ("url", "path", "file_url", "download_url", "location"):
                    if key in resp_json and isinstance(resp_json[key], str):
                        val = resp_json[key]
                        if val.startswith("/"):
                            p = urlsplit(url)
                            upload_url = f"{p.scheme}://{p.netloc}{val}"
                        elif val.startswith("http"):
                            upload_url = val
                        if upload_url:
                            break
            except Exception:
                pass

        if not upload_url:
            return ValidationResult(
                self.name, "not_confirmed", "file_upload", confidence=0.3, confirmed=False,
                summary="File accepted but no retrievable URL found in the response.",
                evidence=f"Upload succeeded ({resp.status_code}) but could not locate "
                         f"the stored file URL to verify content-type bypass.")

        try:
            await global_throttle.acquire()
            async with GatedAsyncClient(get_default_gate(), self.name, timeout=self.timeout,
                                        follow_redirects=True, verify=False) as client:
                retrieve = await client.request("GET", upload_url, headers=headers or None)
        except httpx.HTTPError:
            return ValidationResult(
                self.name, "not_confirmed", "file_upload", confidence=0.2, confirmed=False,
                summary=f"Could not retrieve uploaded file from {upload_url}.")

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
