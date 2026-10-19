"""tool_proxy.py -- I05: an external tool's traffic is accounted to the owning run.

A tool such as sqlmap makes its own HTTP requests, which the run's TargetTransport
never sees: they would escape the run's request budget, scope, gate, cancellation
and TLS policy. Instead of the real target, the tool is given a loopback REVERSE
PROXY for that one target origin. Every request the tool makes to the proxy is
replayed through `run.target_transport()` -- one budget unit each, the run's scope
and gate, its TLS trust and credential sessions -- and the response handed back.
The tool never learns the real origin, so it has no address to bypass the proxy
with; absolute redirects are rewritten back to the proxy (same origin) or to a
refusal path (another origin).

When the run refuses a request because its budget is exhausted or it was
cancelled, `stop_requested` turns true; the tool runner polls it with the run's
cancel signal and stops the tool's process tree.

HTTP/1.1, one request per connection (`Connection: close`), text bodies only (the
transport carries text); a body that is not UTF-8 is refused, never sent.
"""
from __future__ import annotations

import asyncio
import logging
from urllib.parse import urlsplit, urlunsplit

log = logging.getLogger("harness.tool_proxy")

_MAX_HEADER_BYTES = 64 * 1024
_MAX_BODY_BYTES = 4 * 1024 * 1024
_OFF_ORIGIN_PATH = "/__harness_off_origin__"
_HOP_BY_HOP = {"connection", "keep-alive", "proxy-connection", "proxy-authorization",
               "proxy-authenticate", "te", "trailer", "transfer-encoding", "upgrade",
               "host", "content-length"}
_RESPONSE_DROP = {"connection", "keep-alive", "transfer-encoding", "content-length",
                  "content-encoding"}
_REASONS = {200: "OK", 400: "Bad Request", 403: "Forbidden", 411: "Length Required",
            413: "Payload Too Large", 415: "Unsupported Media Type", 502: "Bad Gateway",
            503: "Service Unavailable"}


def _origin(url: str) -> str:
    p = urlsplit(url)
    return urlunsplit((p.scheme.lower(), p.netloc.lower(), "", "", ""))


class ToolProxy:
    """Loopback reverse proxy for one target origin, forwarding through a run."""

    def __init__(self, run, target_url: str, *, capability: str,
                 bind_host: str = "127.0.0.1"):
        self.run = run
        self.target_origin = _origin(target_url)
        self.capability = capability
        self.bind_host = bind_host
        self.port: int | None = None
        self.forwarded = 0
        self.refused: dict[str, int] = {}
        self.stop_reason = ""
        self._server: asyncio.base_events.Server | None = None

    # --- lifecycle --------------------------------------------------------------
    async def start(self) -> "ToolProxy":
        self._server = await asyncio.start_server(self._handle, self.bind_host, 0)
        self.port = self._server.sockets[0].getsockname()[1]
        return self

    async def close(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    async def __aenter__(self) -> "ToolProxy":
        return await self.start()

    async def __aexit__(self, *exc) -> None:
        await self.close()

    # --- what the tool is given -------------------------------------------------
    @property
    def origin(self) -> str:
        return f"http://{self.bind_host}:{self.port}"

    def url_for(self, target_url: str) -> str:
        """The proxy URL standing in for `target_url` (same path and query)."""
        p = urlsplit(target_url)
        if _origin(target_url) != self.target_origin:
            raise ValueError("the tool proxy serves exactly one target origin")
        return urlunsplit(("http", f"{self.bind_host}:{self.port}", p.path or "/", p.query, ""))

    @property
    def stop_requested(self) -> bool:
        return bool(self.stop_reason)

    def receipt(self) -> dict:
        return {"proxy_forwarded": self.forwarded, "proxy_refused": dict(self.refused),
                "proxy_stop_reason": self.stop_reason}

    # --- one connection, one request ---------------------------------------------
    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            status, headers, body = await self._serve(reader)
        except Exception as exc:   # never let one bad request take the proxy down
            log.debug("tool proxy request failed: %s", type(exc).__name__)
            status, headers, body = 502, {}, b"harness tool proxy: request failed"
        try:
            head = [f"HTTP/1.1 {status} {_REASONS.get(status, 'Response')}"]
            for k, v in headers.items():
                head.append(f"{k}: {v}")
            head += [f"Content-Length: {len(body)}", "Connection: close", "", ""]
            writer.write("\r\n".join(head).encode("latin-1", errors="replace") + body)
            await writer.drain()
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def _serve(self, reader: asyncio.StreamReader):
        try:
            raw = await reader.readuntil(b"\r\n\r\n")
        except asyncio.LimitOverrunError:
            return 400, {}, b"harness tool proxy: header too large"
        except asyncio.IncompleteReadError:
            return 400, {}, b"harness tool proxy: incomplete request"
        if len(raw) > _MAX_HEADER_BYTES:
            return 400, {}, b"harness tool proxy: header too large"
        lines = raw.decode("latin-1").split("\r\n")
        try:
            method, target, _version = lines[0].split(" ", 2)
        except ValueError:
            return 400, {}, b"harness tool proxy: malformed request line"
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if not line:
                continue
            name, _, value = line.partition(":")
            headers[name.strip()] = value.strip()
        lower = {k.lower(): v for k, v in headers.items()}
        if "chunked" in lower.get("transfer-encoding", "").lower():
            return 411, {}, b"harness tool proxy: chunked request bodies are not supported"
        length = int(lower.get("content-length") or 0)
        if length > _MAX_BODY_BYTES:
            return 413, {}, b"harness tool proxy: request body too large"
        body_bytes = await reader.readexactly(length) if length else b""
        try:
            body = body_bytes.decode("utf-8") if body_bytes else None
        except UnicodeDecodeError:
            self._refuse("binary_body")
            return 415, {}, b"harness tool proxy: non-UTF-8 request bodies are not forwarded"

        p = urlsplit(target)            # origin-form ("/x?y") or absolute-form
        if p.path == _OFF_ORIGIN_PATH:
            self._refuse("off_origin_redirect")
            return 403, {}, b"harness tool proxy: redirect target is outside the tool's origin"
        url = self.target_origin + (p.path or "/") + (f"?{p.query}" if p.query else "")
        send_headers = {k: v for k, v in headers.items() if k.lower() not in _HOP_BY_HOP}

        out = await self.run.target_transport().send_creds(
            method.upper(), url, capability=self.capability, headers=send_headers,
            body=body, max_redirects=0)
        if out.outcome in ("ok", "error"):
            self.forwarded += 1
        if out.outcome != "ok":
            self._refuse(out.outcome)
            if out.outcome in ("budget_exhausted", "cancelled"):
                self.stop_reason = self.stop_reason or out.outcome
                return 503, {}, f"harness tool proxy: run {out.outcome}".encode()
            if out.outcome == "error":
                return 502, {}, b"harness tool proxy: upstream transport error"
            return 403, {}, f"harness tool proxy: refused by the run ({out.outcome})".encode()

        resp_headers = {k: v for k, v in (out.headers or {}).items()
                        if k.lower() not in _RESPONSE_DROP}
        location = next((k for k in resp_headers if k.lower() == "location"), None)
        if location:
            resp_headers[location] = self._rewrite_location(url, resp_headers[location])
        return out.status or 502, resp_headers, (out.body or "").encode("utf-8")

    def _rewrite_location(self, request_url: str, location: str) -> str:
        p = urlsplit(location)
        if not p.scheme and not p.netloc:
            return location                         # relative: stays on the proxy
        if _origin(location) == self.target_origin:
            return urlunsplit(("http", f"{self.bind_host}:{self.port}", p.path or "/", p.query, ""))
        return f"http://{self.bind_host}:{self.port}{_OFF_ORIGIN_PATH}"

    def _refuse(self, reason: str) -> None:
        self.refused[reason] = self.refused.get(reason, 0) + 1
