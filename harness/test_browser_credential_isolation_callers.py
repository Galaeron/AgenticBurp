"""I05 batch D: the run's browser keeps the captured identity on the run's origin.

Real Chromium against owned loopback servers: the run origin A (127.0.0.1), the
same host on another port B, another in-scope host H (127.0.0.2) and an
out-of-scope host O (127.0.0.3). `.test` names resolve through a patched
socket.getaddrinfo (as in test_destination_policy_callers), which reaches the
browser only through the run's pins. Every server records method, path and the
Authorization/Cookie it actually received.

Checks: the identity's Authorization and cookie reach A and nothing else --
not B through a subresource, frame, popup or prefetch (D1), not B, H or O
through a redirect hop of a navigation, a frame or a subresource (D2), and the
same for `capture_requests` (D3); an A -> B -> A chain gets it back on A (D4);
the browser connects a name only to its run-pinned address and refuses a
special-purpose answer (D5). Each fix has a fault injection that must be
detected.

Skipped, with the reason, when Playwright's Chromium is not installed.
"""
from __future__ import annotations

import asyncio
import json
import socket
import socketserver
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from harness import safety_gate
from harness.browser_driver import PlaywrightDriver, _IdentityRouter, playwright_available
from harness.run_context import RunContext, ScopePolicy

_REAL_GETADDRINFO = socket.getaddrinfo
TOKEN = "RUN-TOKEN-A"
COOKIE = "RUN-COOKIE-A"
IDENTITY = {"Authorization": f"Bearer {TOKEN}", "Cookie": f"sid={COOKIE}; theme=dark"}
SCOPE = ScopePolicy(allowed_hosts=frozenset({"127.0.0.1", "127.0.0.2"}))


class _Origin:
    """Owned loopback server; `pages(path)` returns (status, headers, body) or None."""

    def __init__(self, ip: str, pages=None, port: int = 0):
        self.ip = ip
        self.got: list[tuple[str, str, str]] = []   # ("GET /path", authorization, cookie)
        self._lock = threading.Lock()
        self.pages = pages or (lambda path: None)
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _any(self):
                headers = {k.lower(): v for k, v in self.headers.items()}
                with outer._lock:
                    outer.got.append((f"{self.command} {self.path}",
                                      headers.get("authorization", ""), headers.get("cookie", "")))
                page = outer.pages(self.path.split("?")[0])
                status, extra, body = page or (200, {"Content-Type": "text/plain"}, "ok")
                data = body.encode()
                self.send_response(status)
                for k, v in (extra.items() if isinstance(extra, dict) else extra):
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(data)

            do_GET = do_POST = do_HEAD = _any

        class Server(ThreadingHTTPServer):
            daemon_threads = True

            def server_bind(self):
                # HTTPServer.server_bind reverse-resolves the bind address (getfqdn);
                # for 127.0.0.2 that lookup times out after ~5 s. No name is needed.
                socketserver.TCPServer.server_bind(self)
                self.server_name, self.server_port = self.server_address[:2]

        self._server = Server((ip, port), Handler)
        self.port = self._server.server_address[1]
        self.origin = f"http://{ip}:{self.port}"
        threading.Thread(target=self._server.serve_forever, daemon=True).start()

    def paths(self) -> list[str]:
        with self._lock:
            return [req.split(" ", 1)[1].split("?")[0] for req, _, _ in self.got]

    def credentialed(self) -> list[str]:
        """Requests that carried any part of the run's identity."""
        with self._lock:
            return [req for req, auth, cookie in self.got if TOKEN in auth or COOKIE in cookie]

    def received(self, path: str) -> list[tuple[str, str]]:
        with self._lock:
            return [(auth, cookie) for req, auth, cookie in self.got
                    if req.split(" ", 1)[1].split("?")[0] == path]

    def close(self):
        self._server.shutdown()
        self._server.server_close()


class _Resolver:
    """Answers for `.test` names: each call returns the next listed address (the
    last one repeats). Every other name resolves for real."""

    def __init__(self, answers: dict[str, list[str]]):
        self.answers = {name: list(ips) for name, ips in answers.items()}

    def __call__(self, host, port, *args, **kwargs):
        name = host.decode() if isinstance(host, bytes) else host
        if name in self.answers:
            seq = self.answers[name]
            ip = seq.pop(0) if len(seq) > 1 else seq[0]
            return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "",
                     (ip, int(port or 0)))]
        return _REAL_GETADDRINFO(host, port, *args, **kwargs)


def _html(body: str):
    return 200, {"Content-Type": "text/html"}, f"<!doctype html><html><body>{body}</body></html>"


def _redirect(location: str):
    return 302, {"Location": location}, ""


@unittest.skipUnless(playwright_available(), "Playwright Chromium is not installed")
class _BrowserFixture(unittest.TestCase):
    def setUp(self):
        safety_gate.reset_default_gate()
        self.addCleanup(safety_gate.reset_default_gate)
        self.a = self._origin("127.0.0.1", self._pages_a)
        self.b = self._origin("127.0.0.1", self._pages_b)   # same host, other port
        self.h = self._origin("127.0.0.2", self._pages_b)   # other host, in scope
        self.o = self._origin("127.0.0.3")                  # out of scope

    def _origin(self, ip, pages=None, port=0) -> _Origin:
        server = _Origin(ip, pages, port)
        self.addCleanup(server.close)
        return server

    def _pages_a(self, path):
        a, b, h, o = self.a.origin, self.b.origin, self.h.origin, self.o.origin
        spec = json.dumps({"prefetch": [{"source": "list",
                                         "urls": [f"{b}/spec", f"{o}/spec", f"{a}/spec-a"]}]})
        return {
            "/isolation": _html(
                '<script>console.log("jar:" + document.cookie)</script>'
                f'<img src="{b}/img"><img src="{h}/img">'
                f'<iframe src="{b}/framed"></iframe><iframe src="{o}/framed"></iframe>'
                f'<link rel="prefetch" href="{o}/prefetch">'
                f'<script type="speculationrules">{spec}</script>'
                f'<script>fetch("{b}/fetch", {{credentials: "include"}}).catch(() => 0);'
                f'fetch("{h}/fetch", {{credentials: "include"}}).catch(() => 0);'
                f'window.open("{b}/popup"); window.open("{o}/popup");'
                'fetch("/api").then(r => r.text()).then(t => console.log("api:" + t));</script>'),
            "/redir-port": _redirect(f"{b}/landed"),
            "/redir-host": _redirect(f"{h}/landed"),
            "/redir-out": _redirect(f"{o}/landed"),
            "/redir-same": _redirect("/landed-same"),
            "/nested-redirects": _html(
                f'<iframe src="{a}/redir-host"></iframe><iframe src="{a}/redir-out"></iframe>'
                f'<img src="{a}/redir-port"><img src="{a}/redir-same">'
                f'<script>fetch("{a}/redir-host", {{credentials: "include"}}).catch(() => 0)</script>'),
            "/chain": _redirect(f"{b}/bounce"),
            "/back": _html("back on A"),
            "/rotate": (200, [("Content-Type", "text/html"),
                              ("Set-Cookie", f"sid={COOKIE}-ROTATED; Path=/"),
                              ("Set-Cookie", "app=APPVAL; Path=/")],
                        '<!doctype html><script>console.log("jar:" + document.cookie);'
                        'fetch("/after").then(() => 0)</script>'
                        f'<iframe src="{b}/framed"></iframe>'),
            "/sw": _html('<script>navigator.serviceWorker.register("/sw.js")'
                         '.then(() => console.log("sw registered"), e => console.log("swerr " + e))'
                         '</script>'),
            "/sw.js": (200, {"Content-Type": "application/javascript"},
                       'self.addEventListener("install", e => { self.skipWaiting();'
                       ' e.waitUntil(fetch("/sw-same")) });'),
        }.get(path)

    def _pages_b(self, path):
        return {"/bounce": _redirect(f"{self.a.origin}/back")}.get(path)

    def _visit(self, path, *, mode="visit", headers=IDENTITY, scope=SCOPE, wait_ms=1500):
        driver = PlaywrightDriver()
        call = driver.visit if mode == "visit" else driver.capture_requests
        return asyncio.run(call(f"{self.a.origin}{path}", wait_ms=wait_ms,
                                headers=headers, scope=scope))

    def assertOnlyRunOriginCredentialed(self):
        for label, server in (("B (same host, other port)", self.b),
                              ("H (in-scope host)", self.h), ("O (out of scope)", self.o)):
            self.assertEqual(server.credentialed(), [],
                             f"{label} received the run's identity: {server.got}")
        self.assertEqual(self.o.got, [], f"the out-of-scope host was reached: {self.o.got}")

    def assertCredentialed(self, path):
        got = self.a.received(path)
        self.assertTrue(got, f"A never received {path}: {self.a.got}")
        auth, cookie = got[0]
        self.assertEqual(auth, f"Bearer {TOKEN}", f"{path} on A lost the Authorization")
        self.assertIn(f"sid={COOKIE}", cookie, f"{path} on A lost the identity cookie")
        self.assertIn("theme=dark", cookie, f"{path} on A lost a second identity cookie")


class SameHostOtherPortTests(_BrowserFixture):
    """D1: the identity's cookie never reaches another port of the run's host."""

    def test_identity_stays_on_the_run_origin_across_every_channel(self):
        obs = self._visit("/isolation")
        self.assertEqual(obs.load_error, "")
        self.assertCredentialed("/isolation")
        self.assertCredentialed("/api")
        self.assertIn("api:ok", obs.console)                   # the page used its session
        self.assertOnlyRunOriginCredentialed()
        # In-scope navigations to B still happen -- without the identity.
        self.assertIn("/framed", self.b.paths())
        self.assertIn("/popup", self.b.paths())

    def test_the_browser_cookie_jar_never_holds_the_identity(self):
        obs = self._visit("/isolation")
        jar = [line for line in obs.console if line.startswith("jar:")]
        self.assertEqual(jar, ["jar:"], "page script can read the identity cookie")

    def test_identity_rotation_stays_out_of_the_jar_and_app_cookies_still_work(self):
        self._visit("/rotate")
        after = self.a.received("/after")
        self.assertTrue(after, self.a.got)
        auth, cookie = after[0]
        self.assertEqual(auth, f"Bearer {TOKEN}")
        self.assertIn(f"sid={COOKIE}-ROTATED", cookie, "the re-issued identity cookie was lost")
        self.assertNotIn(f"sid={COOKIE};", cookie + ";", "the stale identity value was sent")
        self.assertIn("app=APPVAL", cookie, "an application cookie the page set was lost")
        self.assertOnlyRunOriginCredentialed()

    def test_identity_in_the_jar_is_detected(self):
        """Fault injection: the identity cookies are seeded into the browser's jar again."""
        original = _IdentityRouter.install

        async def seed_the_jar(router, context):
            await original(router, context)
            await context.add_cookies([{"name": k, "value": v, "domain": "127.0.0.1", "path": "/"}
                                       for k, v in router.identity_cookies.items()])

        with patch.object(_IdentityRouter, "install", seed_the_jar):
            self._visit("/isolation")
        self.assertTrue(self.b.credentialed(),
                        "a seeded jar no longer reaches the other port -- vacuous")


class RedirectHopTests(_BrowserFixture):
    """D2: no redirect hop carries the identity off the run origin."""

    def test_main_frame_redirect_to_another_port_drops_the_identity(self):
        obs = self._visit("/redir-port")
        self.assertEqual(obs.load_error, "")
        self.assertCredentialed("/redir-port")
        self.assertEqual(len(self.b.received("/landed")), 1, self.b.got)
        self.assertOnlyRunOriginCredentialed()

    def test_main_frame_redirect_out_of_scope_sends_nothing_there(self):
        obs = self._visit("/redir-out")
        self.assertNotEqual(obs.load_error, "")
        self.assertOnlyRunOriginCredentialed()

    def test_frame_and_subresource_redirects(self):
        self._visit("/nested-redirects")
        self.assertIn("/landed", self.h.paths())                # the frame's hop, re-issued
        self.assertCredentialed("/landed-same")                 # same-origin hop keeps it
        self.assertOnlyRunOriginCredentialed()

    def test_continuing_identity_requests_natively_is_detected(self):
        """Fault injection: identity requests are continued with header overrides
        again (the pre-I05-D handler), so Chromium follows their redirects itself."""

        async def old_handle(router, route, request):
            decision = router._decide(request.url, request.method, request.resource_type,
                                      request.is_navigation_request(), account=True)
            if not decision.allow:
                await route.abort()
            elif decision.attach_credentials and router.identity_headers:
                await route.continue_(headers={**request.headers, **router.identity_headers})
            else:
                await route.continue_()

        with patch.object(_IdentityRouter, "handle", old_handle):
            self._visit("/redir-port")
        self.assertTrue(self.b.credentialed(),
                        "a natively followed hop no longer carries the identity -- vacuous")

    def test_allowing_service_workers_is_detected(self):
        """Fault injection: the context lets service workers run (their traffic is
        never routed). The control is test_service_workers_never_run."""
        from playwright.async_api import Browser
        original = Browser.new_context

        async def allow_workers(browser, **kwargs):
            kwargs.pop("service_workers", None)
            return await original(browser, **kwargs)

        with patch.object(Browser, "new_context", allow_workers):
            self._visit("/sw", wait_ms=2500)
        self.assertIn("/sw-same", self.a.paths(),
                      "an allowed service worker no longer sends unrouted -- vacuous")

    def test_service_workers_never_run(self):
        self._visit("/sw", wait_ms=2500)
        self.assertNotIn("/sw-same", self.a.paths())


class CaptureParityTests(_BrowserFixture):
    """D3: capture_requests applies the same boundary as visit."""

    def test_capture_requests_keeps_the_identity_on_the_run_origin(self):
        obs = self._visit("/isolation", mode="capture")
        self.assertEqual(obs.load_error, "")
        self.assertCredentialed("/isolation")
        self.assertCredentialed("/api")
        self.assertOnlyRunOriginCredentialed()
        captured = [ex["url"] for ex in obs.exchanges]
        self.assertTrue(any(url.endswith("/api") for url in captured), captured)

    def test_capture_requests_redirects_drop_the_identity(self):
        self._visit("/redir-port", mode="capture")
        self.assertEqual(len(self.b.received("/landed")), 1, self.b.got)
        self.assertOnlyRunOriginCredentialed()


class ChainTests(_BrowserFixture):
    """D4 (positive): back on the run origin after A -> B -> A, the identity is sent."""

    def test_identity_returns_on_the_run_origin_after_a_chain(self):
        obs = self._visit("/chain")
        self.assertEqual(obs.load_error, "")
        self.assertEqual(len(self.b.received("/bounce")), 1, self.b.got)
        self.assertCredentialed("/back")
        self.assertOnlyRunOriginCredentialed()


@unittest.skipUnless(playwright_available(), "Playwright Chromium is not installed")
class AddressPinTests(unittest.TestCase):
    """D5: the browser connects a name only to its run-pinned address."""

    def setUp(self):
        safety_gate.reset_default_gate()
        self.addCleanup(safety_gate.reset_default_gate)
        page = lambda path: _html('<img src="/img"><script>fetch("/f")</script>') \
            if path == "/page" else None
        self.first = _Origin("127.0.0.1", page)
        self.internal = _Origin("127.0.0.2", page, self.first.port)   # the rebound answer
        for server in (self.first, self.internal):
            self.addCleanup(server.close)

    def _visit_pinned(self, headers, extra_patches=()):
        """The run pins app.test to 127.0.0.1 first; every later lookup answers
        127.0.0.2."""
        resolver = _Resolver({"app.test": ["127.0.0.1", "127.0.0.2"]})
        run = RunContext.create(allowed_hosts=["app.test"], max_requests=50,
                                gate_config={"active_enabled": True})

        async def go():
            async with run:
                await run.address_pins.address_for("app.test")
                return await PlaywrightDriver().visit(
                    f"http://app.test:{self.first.port}/page", wait_ms=1000,
                    headers=headers, scope=run.scope)

        patches = [patch("socket.getaddrinfo", side_effect=resolver), *extra_patches]
        for p in patches:
            p.start()
        try:
            return asyncio.run(go())
        finally:
            for p in reversed(patches):
                p.stop()

    def test_anonymous_page_requests_use_the_pinned_address(self):
        obs = self._visit_pinned(headers=None)
        self.assertEqual(obs.load_error, "")
        self.assertEqual(sorted(self.first.paths()), ["/f", "/img", "/page"])
        self.assertEqual(self.internal.got, [])

    def test_identity_page_requests_use_the_pinned_address(self):
        obs = self._visit_pinned(headers=IDENTITY)
        self.assertEqual(obs.load_error, "")
        self.assertEqual(sorted(self.first.paths()), ["/f", "/img", "/page"])
        self.assertTrue(all(TOKEN in auth for _, auth, _ in self.first.got), self.first.got)
        self.assertEqual(self.internal.got, [])

    def test_unpinned_router_sends_are_detected(self):
        """Fault injection: the router's client connects by name again."""
        self._visit_pinned(headers=None, extra_patches=[
            patch("harness.run_context._pinned_backend", return_value=None)])
        self.assertTrue(self.internal.got,
                        "an unpinned router no longer reaches the rebound address -- vacuous")

    def test_special_purpose_answer_is_refused(self):
        resolver = _Resolver({"meta.test": ["169.254.169.254"]})
        with patch("socket.getaddrinfo", side_effect=resolver), \
                self.assertLogs("harness.browser_driver", level="INFO") as logs:
            obs = asyncio.run(PlaywrightDriver(launch_timeout_ms=5000).visit(
                "http://meta.test/latest/meta-data/", wait_ms=0, headers=IDENTITY,
                scope=ScopePolicy(allowed_hosts=frozenset({"meta.test"}))))
        self.assertNotEqual(obs.load_error, "")
        self.assertTrue(any("special-purpose" in line for line in logs.output), logs.output)


class ResolverRulesTests(unittest.TestCase):
    """D5: what Chromium may still connect on its own (traffic the route never
    sees, such as a speculation-rules prefetch) resolves only in-scope names, each
    to its run pin. Over plain http a `.test` page is not a secure context and
    Chromium sends it no such traffic, so the rules are checked as launched."""

    def _rules(self, hosts, url, answers, *, pins=True):
        run = RunContext.create(allowed_hosts=hosts, max_requests=5,
                                config={} if pins else {"security": {"pin_connect_address": False}})

        async def go():
            async with run:
                await run.address_pins.address_for("app.test") if pins else None
                router = _IdentityRouter(url=url, headers=None, scope=run.scope, cancel=None,
                                         gate=None, budget=None, timeout_s=5, label="test")
                return await router.launch_args()

        with patch("socket.getaddrinfo", side_effect=_Resolver(answers)):
            return asyncio.run(go())

    def test_names_map_to_the_run_pin_and_everything_else_is_unresolvable(self):
        args = self._rules(["app.test", "127.0.0.2"], "http://app.test:8080/",
                           {"app.test": ["127.0.0.1", "127.0.0.2"]})
        self.assertEqual(args, ["--host-resolver-rules=MAP app.test 127.0.0.1, "
                                "MAP * ~NOTFOUND, EXCLUDE 127.0.0.2"])

    def test_a_special_purpose_answer_is_never_mapped(self):
        args = self._rules(["app.test", "meta.test"], "http://app.test/",
                           {"app.test": ["127.0.0.1"], "meta.test": ["169.254.169.254"]})
        self.assertEqual(args, ["--host-resolver-rules=MAP app.test 127.0.0.1, MAP * ~NOTFOUND"])

    def test_a_run_without_pins_lets_chromium_resolve_in_scope_names_only(self):
        args = self._rules(["app.test"], "http://app.test/", {"app.test": ["127.0.0.1"]},
                           pins=False)
        self.assertEqual(args, ["--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE app.test"])


class ConnectionBoundaryTests(_BrowserFixture):
    """D5: what the browser still sends on its own (unrouted prefetches) is bounded
    by the resolver allow-list."""

    def test_dropping_the_resolver_rules_is_detected(self):
        """Fault injection: Chromium is launched without the resolver allow-list."""

        async def no_rules(router):
            return []

        with patch.object(_IdentityRouter, "launch_args", no_rules):
            self._visit("/isolation", wait_ms=2500)
        self.assertTrue(self.o.got,
                        "an unrouted prefetch no longer reaches the out-of-scope host -- vacuous")


if __name__ == "__main__":
    unittest.main()
