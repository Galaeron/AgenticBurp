"""
Out-of-band (OOB) collaborator -- an in-process HTTP callback listener.

Blind SSRF and blind XXE leave no evidence in the response: the only proof the
target performed the attacker-controlled fetch is that it CALLS BACK to a listener
we control. This is that listener -- the Burp-Collaborator role, but local and
dependency-free.

Why in-process (not a container): unlike sqlmap, this needs no offensive binary
and nothing lands on host disk -- it's a plain HTTP server. It binds an ephemeral
loopback port; a target running on the host reaches it at http://127.0.0.1:<port>/
<token>. (Full internet-facing OOB with DNS would want a real interactsh-style
service; for a local target a loopback HTTP listener is sufficient and simpler.)

Usage:
    c = collaborator.shared()
    tok = c.token(); url = c.url(tok)        # embed url in the payload
    ... send the payload ...
    if await c.wait_for_hit(tok): CONFIRMED   # the target fetched our url
"""
from __future__ import annotations

import asyncio
import atexit
import http.server
import ipaddress
import os
import re
import secrets
import threading
import time
from dataclasses import dataclass
from urllib.parse import urlsplit


def _loopback(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _target_origin(url: str) -> str:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("callback preflight needs an HTTP(S) target origin")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return f"{parsed.scheme}://{parsed.hostname.lower()}:{port}"


@dataclass(frozen=True)
class Settings:
    bind_host: str = "127.0.0.1"
    advertise_host: str = "127.0.0.1"
    port: int = 0
    approved_origin: str = ""

    @classmethod
    def load(cls, config=None, environ=None):
        """One construction contract; explicit environment overrides local config."""
        env = os.environ if environ is None else environ
        cfg = (config or {}).get("collaborator", {})
        if not isinstance(cfg, dict):
            raise ValueError("collaborator must be a mapping")
        values = {}
        for name in ("bind_host", "advertise_host", "port", "approved_origin"):
            key = "AGENTICVIBE_OOB_" + name.upper()
            if key in env:
                values[name] = env[key]
            elif name in cfg:
                values[name] = cfg[name]
        if "advertise_host" not in values:
            values["advertise_host"] = values.get("bind_host", "127.0.0.1")
        port = values.get("port", 0)
        if isinstance(port, bool) or not re.fullmatch(r"[0-9]+", str(port)):
            raise ValueError("collaborator port must be an integer in 0..65535")
        values["port"] = int(port)
        result = cls(**values)
        result.validate()
        return result

    def validate(self):
        if not 0 <= self.port <= 65535:
            raise ValueError("collaborator port must be in 0..65535")
        for host in (self.bind_host, self.advertise_host):
            if not isinstance(host, str) or not re.fullmatch(r"[a-zA-Z0-9.-]+", host):
                raise ValueError("collaborator host must be an IPv4 address or DNS name")
        if self.advertise_host == "0.0.0.0":
            raise ValueError("collaborator cannot advertise a wildcard address")
        origin = f"http://{self.advertise_host}:{self.port}"
        external = not (_loopback(self.bind_host) and _loopback(self.advertise_host))
        if external and (not self.port or self.approved_origin != origin):
            raise ValueError("non-loopback collaborator requires an exact approved_origin and explicit port")
        if self.approved_origin and self.approved_origin != origin:
            raise ValueError("collaborator approved_origin does not match advertised origin")


class _Recorder(http.server.BaseHTTPRequestHandler):
    def _hit(self):
        try:
            path = urlsplit(self.path).path
            with self.server.hit_lock:  # type: ignore[attr-defined]
                if path in self.server.tokens:  # type: ignore[attr-defined]
                    self.server.hits.add(path)  # type: ignore[attr-defined]
        except Exception:
            pass
        try:
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")
        except Exception:
            pass

    do_GET = do_POST = do_PUT = do_HEAD = do_OPTIONS = _hit

    def log_message(self, *args):  # silence the default stderr logging
        pass


class _OwnedServer(http.server.ThreadingHTTPServer):
    # HTTPServer enables SO_REUSEADDR, which permits competing binds on Windows.
    allow_reuse_address = False
    allow_reuse_port = False


class Collaborator:
    """A running loopback HTTP listener that records the paths it is hit on."""

    def __init__(self, host: str = "127.0.0.1", *, settings: Settings | None = None):
        settings = settings or Settings(bind_host=host, advertise_host=host)
        settings.validate()
        self.settings = settings
        self._srv = _OwnedServer((settings.bind_host, settings.port), _Recorder)
        self._srv.hits = set()  # type: ignore[attr-defined]
        self._srv.tokens = set()  # type: ignore[attr-defined]
        self._srv.hit_lock = threading.Lock()  # type: ignore[attr-defined]
        self.host, self.port = self._srv.server_address
        self.advertise_host = settings.advertise_host
        self._stopped = False
        self._reachable_targets: set[str] = set()
        self._thread = threading.Thread(target=self._srv.serve_forever, daemon=True)
        self._thread.start()

    def token(self) -> str:
        token = "oob" + secrets.token_hex(16)
        with self._srv.hit_lock:
            self._srv.tokens.add("/" + token)
        return token

    def url(self, token: str) -> str:
        return f"http://{self.advertise_host}:{self.port}/{token}"

    def was_hit(self, token: str) -> bool:
        with self._srv.hit_lock:
            return "/" + token in self._srv.hits

    def record_preflight(self, token: str, target_url: str) -> bool:
        """Call only after a probe from the owned target network, never the host."""
        origin = _target_origin(target_url)
        reached = self.was_hit(token)
        if reached:
            self._reachable_targets.add(origin)
        else:
            self._reachable_targets.discard(origin)
        return reached

    def health(self) -> dict:
        return {"available": not self._stopped, "origin": self.url("").rstrip("/"),
                "verified_target_origins": sorted(self._reachable_targets)}

    def unavailable_reason(self, target_url: str) -> str:
        if self._stopped:
            return "callback listener is stopped"
        if _target_origin(target_url) in self._reachable_targets:
            return ""
        # A loopback target URL can be a published container port. Its address
        # alone never proves that the target can reach this listener.
        return "callback reachability from the target network is unverified; assessment incomplete"

    async def wait_for_hit(self, token: str, timeout: float = 6.0) -> bool:
        """Poll for a callback carrying `token`, up to `timeout` seconds."""
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if self.was_hit(token):
                return True
            await asyncio.sleep(0.25)
        return False

    def stop(self) -> None:
        """Stop serving AND release the listening socket (idempotent). `shutdown()`
        alone only ends the serve loop; the bound socket stays open until
        `server_close()`, which leaked one loopback socket per stopped collaborator."""
        if self._stopped:
            return
        self._stopped = True
        try:
            self._srv.shutdown()
        except Exception:
            pass
        try:
            self._srv.server_close()
        except Exception:
            pass
        self._thread.join(timeout=2.0)


_SHARED: Collaborator | None = None
_ATEXIT_REGISTERED = False
_SHARED_LOCK = threading.RLock()


class ConfiguredCollaborator:
    """Registry-owned lazy listener: validation now, bind before the first probe.

    Separate registries never silently adopt each other's fixed-port listener.
    """
    def __init__(self, config):
        self.settings = Settings.load(config)
        self._listener = None
        self._lock = threading.RLock()
        atexit.register(self.stop)

    def start(self):
        with self._lock:
            if self._listener is None:
                self._listener = Collaborator(settings=self.settings)
            return self._listener

    def stop(self):
        with self._lock:
            if self._listener is not None:
                self._listener.stop()

    def __getattr__(self, name):
        return getattr(self.start(), name)


def resolve(listener):
    if isinstance(listener, ConfiguredCollaborator):
        return listener.start()
    return listener if listener is not None else shared()


def unavailable_result(listener, target_url, validator, vulnerability_class):
    """Injected legacy fixtures have no health API; real listeners report uncertainty."""
    check = getattr(listener, "unavailable_reason", None)
    reason = check(target_url) if check is not None else ""
    if reason:
        from harness.validators.base import ValidationResult
        return ValidationResult(validator, "inconclusive", vulnerability_class,
                                confirmed=False, confidence=0.0, summary=reason)
    return None


def shared() -> Collaborator:
    """The process-wide collaborator, started on first use. Its serve loop is a daemon
    thread, but its listening socket is not released by the daemon dying: it is closed
    by `stop_shared()`, which is registered to run at interpreter exit."""
    global _SHARED, _ATEXIT_REGISTERED
    with _SHARED_LOCK:
        if _SHARED is None:
            _SHARED = Collaborator(settings=Settings.load())
            if not _ATEXIT_REGISTERED:
                atexit.register(stop_shared)
                _ATEXIT_REGISTERED = True
        return _SHARED


def stop_shared() -> None:
    """Stop and forget the process-wide collaborator (idempotent); the next `shared()`
    starts a fresh one."""
    global _SHARED
    with _SHARED_LOCK:
        collaborator, _SHARED = _SHARED, None
        if collaborator is not None:
            collaborator.stop()
