"""RV-G (code review 02; I05's no-run routes): the routes that fetch outside a
run, and the settings toggle that arms them, obey scope, credential, active-mode
and confirmation policy.

Every test drives the real route through FastAPI's TestClient against owned
loopback servers that count the requests they actually receive. 127.0.0.1 is
in scope; 127.0.0.2 is not and stands in for any outside host.

- R01: POST /settings accepts JSON booleans only. The string "false" is refused
  (422) instead of arming active testing.
- R02: /crawl, /crawl-roles and /engagement/{host}/advance own a run, so a
  redirect out of scope is never followed and a custom credential header
  (X-Api-Key) never leaves its own origin.
- R03: /engagement/{host}/advance sends nothing while active testing is off.
- R07: a destructive path listed in robots.txt is not fetched.
- R15: /probe-missing-auth confirms missing authentication only for an
  endpoint declared protected whose payload an authenticated baseline also gets.

Each finding has its reviewer control as a negative control and one fault
injection that restores the defect and must be detected.
"""
from __future__ import annotations

import re
import shutil
import socketserver
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from harness import global_throttle, safety_gate, store

_IN_SCOPE = "127.0.0.1"
_OUTSIDE = "127.0.0.2"


class _Target:
    """Owned loopback server. `routes` maps a path to a function of the request
    headers (lower-cased) returning (status, headers, body); every request,
    routed or not, is recorded as (method, path, headers)."""

    def __init__(self, ip: str, routes: dict | None = None):
        self.ip = ip
        self.routes = dict(routes or {})
        self.requests: list[tuple[str, str, dict]] = []
        self._lock = threading.Lock()
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _serve(self):
                headers = {k.lower(): v for k, v in self.headers.items()}
                with outer._lock:
                    outer.requests.append((self.command, self.path, headers))
                route = outer.routes.get(self.path.split("?", 1)[0])
                status, extra, body = route(headers) if route else (404, {}, "")
                data = body.encode()
                self.send_response(status)
                for name, value in extra.items():
                    self.send_header(name, value)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_POST = do_HEAD = _serve

        class Server(ThreadingHTTPServer):
            daemon_threads = True

            def server_bind(self):
                # Skip HTTPServer's reverse lookup of the bind address (slow for 127.0.0.2).
                socketserver.TCPServer.server_bind(self)
                self.server_name, self.server_port = self.server_address[:2]

        self._server = Server((ip, 0), Handler)
        self.port = self._server.server_address[1]
        self.origin = f"http://{ip}:{self.port}"
        threading.Thread(target=self._server.serve_forever, daemon=True).start()

    def paths(self) -> list[str]:
        with self._lock:
            return [path for _, path, _ in self.requests]

    def close(self):
        self._server.shutdown()
        self._server.server_close()


def _page(body: str, status: int = 200, **headers):
    return lambda _headers: (status, headers, body)


def _redirect(location: str):
    return lambda _headers: (302, {"Location": location}, "")


class _RouteFixture(unittest.TestCase):
    """The real server module, scoped to 127.0.0.1, with an isolated store."""

    def setUp(self):
        import harness.server as server
        from fastapi.testclient import TestClient
        self.server = server
        self._tmp = tempfile.mkdtemp(prefix="rvg_routes_")
        self._saved_db = store._DB_PATH
        store._DB_PATH = Path(self._tmp) / "state.db"
        self._saved_hosts = server.orchestrator.allowed_hosts
        self._saved_active = server.orchestrator.validator_registry.active_enabled
        server.orchestrator.allowed_hosts = [_IN_SCOPE]
        global_throttle.configure(0)
        safety_gate.reset_default_gate()
        self.client = TestClient(server.app, base_url="http://localhost",
                                 headers={"Authorization": f"Bearer {server._mutation_token()}"})
        self._targets: list[_Target] = []

    def tearDown(self):
        for target in self._targets:
            target.close()
        self.server.orchestrator.allowed_hosts = self._saved_hosts
        self.server.orchestrator.validator_registry.set_active_enabled(self._saved_active)
        store._DB_PATH = self._saved_db
        safety_gate.reset_default_gate()
        shutil.rmtree(self._tmp, ignore_errors=True)

    def target(self, ip: str = _IN_SCOPE, routes: dict | None = None) -> _Target:
        target = _Target(ip, routes)
        self._targets.append(target)
        return target

    def arm(self, enabled: bool = True):
        self.server.orchestrator.validator_registry.set_active_enabled(enabled)


class SettingsStrictBooleanTests(_RouteFixture):
    """R01. Reviewer check: validators.active_enabled="false" must not arm
    active mode. Control: boolean false keeps it off."""

    def _active(self) -> bool:
        return self.server.orchestrator.validator_registry.active_enabled

    def test_non_boolean_toggles_are_refused_and_change_nothing(self):
        self.arm(False)
        cloud_before = self.client.get("/settings").json()["coordinator"]["cloud_reasoning"]
        for value in ("false", "true", "False", 0, 1, None):
            for payload in ({"validators": {"active_enabled": value}},
                            {"validators": {"cross_identity": value}},
                            {"coordinator": {"cloud_reasoning": value}}):
                with self.subTest(payload=payload):
                    resp = self.client.post("/settings", json=payload)
                    self.assertEqual(resp.status_code, 422, resp.text)
                    self.assertFalse(self._active())
        state = self.client.get("/settings").json()
        self.assertFalse(state["validators"]["active_enabled"])
        self.assertEqual(state["coordinator"]["cloud_reasoning"], cloud_before)

    def test_boolean_control_still_toggles(self):
        self.arm(False)
        resp = self.client.post("/settings", json={"validators": {"active_enabled": False}})
        self.assertEqual(resp.status_code, 200, resp.text)
        self.assertFalse(self._active())
        resp = self.client.post("/settings", json={"validators": {"active_enabled": True}})
        self.assertEqual(resp.status_code, 200, resp.text)
        self.assertTrue(self._active())
        self.assertTrue(resp.json()["validators"]["active_enabled"])

    def test_fault_injection_unvalidated_string_arms_active_mode(self):
        # Bypass the request model's validation (as the old untyped dict did):
        # the same "false" now reaches the handler and arms active mode, which
        # the checks above would report.
        import asyncio
        self.arm(False)
        toggles = self.server._ValidatorToggles.model_construct(
            _fields_set={"active_enabled"}, active_enabled="false")
        request = self.server.SettingsRequest.model_construct(validators=toggles)
        asyncio.run(self.server.update_settings(
            request, authorization=f"Bearer {self.server._mutation_token()}"))
        self.assertTrue(self._active())


class CrawlRedirectScopeTests(_RouteFixture):
    """R02 on /crawl. Reviewer check: a redirect to an outside host is not
    followed and X-Api-Key is not forwarded there. Control: an in-scope
    redirect is still followed."""

    def _crawl(self, start: str, **extra):
        body = {"base_url": start, "headers": {"X-Api-Key": "synthetic-key"}, "max_pages": 5}
        body.update(extra)
        resp = self.client.post("/crawl", json=body)
        self.assertEqual(resp.status_code, 200, resp.text)
        return resp.json()

    def test_redirect_out_of_scope_is_not_contacted(self):
        outside = self.target(_OUTSIDE, {"/": _page("outside")})
        site = self.target(routes={"/": _redirect(outside.origin + "/")})
        self.arm()
        out = self._crawl(site.origin + "/")
        self.assertEqual(outside.requests, [])
        self.assertEqual(site.paths(), ["/", "/robots.txt"])
        self.assertEqual(site.requests[0][2].get("x-api-key"), "synthetic-key")
        self.assertTrue(any("out_of_scope" in e for e in out["errors"]), out["errors"])

    def test_in_scope_redirect_is_followed_and_credentials_stay_on_their_origin(self):
        other = self.target(routes={"/other": _page("<p>other origin</p>")})
        site = self.target(routes={
            "/start": _redirect("/landing"),
            "/landing": _page(f'<a href="/hop">hop</a>'),
            "/hop": _redirect(other.origin + "/other"),
        })
        self.arm()
        self._crawl(site.origin + "/start")
        sent = {path: headers for _, path, headers in site.requests}
        self.assertIn("/landing", sent)
        self.assertEqual(sent["/landing"].get("x-api-key"), "synthetic-key")
        # Another in-scope origin is reached, without the caller's credential.
        self.assertEqual(other.paths(), ["/other"])
        self.assertNotIn("x-api-key", other.requests[0][2])

    def test_fault_injection_crawl_without_the_run_escapes(self):
        from harness import crawler
        real_crawl = crawler.crawl

        async def without_run(*args, run_context=None, session_ref=None, **kwargs):
            return await real_crawl(*args, **kwargs)

        outside = self.target(_OUTSIDE, {"/": _page("outside")})
        site = self.target(routes={"/": _redirect(outside.origin + "/")})
        self.arm()
        with patch.object(crawler, "crawl", without_run):
            self._crawl(site.origin + "/")
        self.assertEqual(outside.paths(), ["/"])
        self.assertEqual(outside.requests[0][2].get("x-api-key"), "synthetic-key")


class RoleRouteRedirectScopeTests(_RouteFixture):
    """R02 on /crawl-roles and /engagement/{host}/advance: the role crawl and its
    access-matrix probes run in the route's own run."""

    def _site(self):
        outside = self.target(_OUTSIDE, {"/": _page("outside"), "/data": _page('{"x": 1}')})
        site = self.target(routes={
            "/": _page('<a href="/away">away</a> <a href="/data">data</a>'),
            "/away": _redirect(outside.origin + "/"),
            "/data": _page('{"orders": [1, 2]}'),
        })
        return site, outside

    def _roles(self):
        return [{"role": "user", "headers": {"X-Api-Key": "synthetic-key"}},
                {"role": "anonymous", "headers": {}}]

    def test_crawl_roles_stays_in_scope(self):
        site, outside = self._site()
        self.arm()
        resp = self.client.post("/crawl-roles", json={
            "base_url": site.origin + "/", "roles": self._roles(), "max_pages": 5,
            "register_identities": False})
        self.assertEqual(resp.status_code, 200, resp.text)
        self.assertEqual(outside.requests, [])
        keyed = [headers.get("x-api-key") for _, path, headers in site.requests if path == "/data"]
        # Probed once per role: the user's key goes, the anonymous probe has none.
        self.assertIn("synthetic-key", keyed)
        self.assertIn(None, keyed)

    def test_advance_stays_in_scope(self):
        site, outside = self._site()
        self.arm()
        resp = self.client.post(f"/engagement/{_IN_SCOPE}/advance", json={
            "base_url": site.origin + "/", "roles": self._roles(), "max_pages": 5})
        self.assertEqual(resp.status_code, 200, resp.text)
        self.assertEqual(outside.requests, [])
        self.assertIn("/data", site.paths())

    def test_fault_injection_role_crawl_without_the_run_escapes(self):
        from harness import role_crawl
        real_crawl_roles = role_crawl.crawl_roles

        async def without_run(*args, run_context=None, session_refs=None, **kwargs):
            return await real_crawl_roles(*args, **kwargs)

        site, outside = self._site()
        self.arm()
        with patch.object(role_crawl, "crawl_roles", without_run):
            resp = self.client.post("/crawl-roles", json={
                "base_url": site.origin + "/", "roles": self._roles(), "max_pages": 5,
                "register_identities": False})
        self.assertEqual(resp.status_code, 200, resp.text)
        self.assertTrue(outside.requests)
        self.assertIn("synthetic-key", [h.get("x-api-key") for _, _, h in outside.requests])


class AdvanceActiveModeTests(_RouteFixture):
    """R03. Reviewer check: advance sends nothing while active testing is off.
    Control: armed, it advances."""

    def _advance(self, site):
        return self.client.post(f"/engagement/{_IN_SCOPE}/advance", json={
            "base_url": site.origin + "/", "roles": [{"role": "user"}],
            "max_pages": 1, "max_endpoints": 1})

    def _site(self):
        return self.target(routes={"/": _page('<a href="/a">a</a>')})

    def test_disabled_active_mode_refuses_before_any_send(self):
        site = self._site()
        self.arm(False)
        resp = self._advance(site)
        self.assertEqual(resp.status_code, 403, resp.text)
        self.assertIn("active operations are disabled", resp.json()["detail"])
        self.assertEqual(site.requests, [])

    def test_armed_control_advances(self):
        site = self._site()
        self.arm()
        resp = self._advance(site)
        self.assertEqual(resp.status_code, 200, resp.text)
        self.assertIn("/", site.paths())
        self.assertIn("worklist", resp.json())

    def test_fault_injection_removing_the_gate_sends(self):
        site = self._site()
        self.arm(False)
        with patch.object(self.server, "_require_active_crawl", lambda url: None):
            resp = self._advance(site)
        self.assertEqual(resp.status_code, 200, resp.text)
        self.assertTrue(site.requests)


class RobotsDestructiveNavigationTests(_RouteFixture):
    """R07. Reviewer check: /logout is skipped as a link and must also be
    skipped when robots.txt lists it. Control: a benign robots path is fetched."""

    def _crawl(self, site):
        self.arm()
        resp = self.client.post("/crawl", json={"base_url": site.origin + "/", "max_pages": 6})
        self.assertEqual(resp.status_code, 200, resp.text)
        return resp.json()

    def test_robots_destructive_path_is_not_fetched(self):
        site = self.target(routes={
            "/": _page('<a href="/logout">logout</a>'),
            "/robots.txt": _page("User-agent: *\nDisallow: /logout\nAllow: /ordinary\n"),
            "/ordinary": _page("<p>ordinary</p>"),
            "/logout": _page("signed out"),
        })
        out = self._crawl(site)
        self.assertIn("/ordinary", site.paths())          # control: benign robots path
        self.assertNotIn("/logout", site.paths())
        self.assertIn("/logout", out["suppressed_navigation"])
        self.assertNotIn("/logout", out["endpoints"])
        self.assertIn("/ordinary", out["endpoints"])

    def _robots_only_site(self):
        # /logout is advertised ONLY by robots.txt, so robots is the source under test.
        return self.target(routes={
            "/": _page("<p>home</p>"),
            "/robots.txt": _page("Disallow: /account/logout\nAllow: /ordinary\n"),
            "/ordinary": _page("<p>ordinary</p>"),
            "/account/logout": _page("signed out"),
        })

    def test_robots_only_destructive_path_is_not_fetched(self):
        site = self._robots_only_site()
        self._crawl(site)
        self.assertIn("/ordinary", site.paths())
        self.assertNotIn("/account/logout", site.paths())

    def test_fault_injection_without_the_filter_fetches_logout(self):
        from harness import crawler
        site = self._robots_only_site()
        with patch.object(crawler, "_DESTRUCTIVE_NAVIGATION", re.compile(r"(?!x)x")):
            self._crawl(site)
        self.assertIn("/account/logout", site.paths())


class MissingAuthPreconditionTests(_RouteFixture):
    """R15. Reviewer check: a public catalogue probed with expected_protected=false
    is not confirmed. Control: a denied endpoint stays negative. Positive
    control: a declared-protected endpoint that serves its authenticated payload
    anonymously is still confirmed."""

    _CATALOGUE = '{"products": [{"name": "Public catalogue", "price": 10}]}'
    _REPORT = '{"salaries": [{"name": "a", "salary": 90000}]}'

    def _site(self):
        def profile(headers):
            if headers.get("authorization") == "Bearer real-session":
                return 200, {}, '{"email": "owner@example.test", "ssn": "x"}'
            return 200, {}, '{"name": "guest view"}'
        return self.target(routes={
            "/products": _page(self._CATALOGUE),
            "/api/report": _page(self._REPORT),          # the real bug: no auth check
            "/api/tickets": lambda h: (401, {}, "login required"),
            "/api/profile": profile,                     # public variant for anonymous
        })

    def _probe(self, site, paths, **extra):
        self.arm()
        body = {"base_url": site.origin, "paths": paths}
        body.update(extra)
        resp = self.client.post("/probe-missing-auth", json=body)
        self.assertEqual(resp.status_code, 200, resp.text)
        return resp.json()

    def test_public_resource_is_not_confirmed(self):
        site = self._site()
        out = self._probe(site, ["/products"], expected_protected=False)
        self.assertEqual(site.paths(), ["/products"])
        self.assertFalse(any(f["confirmed"] for f in out["findings"]), out)
        self.assertEqual(out["outcomes"][0]["classification"], "unauthenticated_access")

    def test_declared_protected_needs_a_matching_authenticated_baseline(self):
        site = self._site()
        # No credentials supplied: no baseline, nothing confirmed, one send.
        out = self._probe(site, ["/api/report"], expected_protected=True)
        self.assertFalse(any(f["confirmed"] for f in out["findings"]), out)
        self.assertEqual(len(site.requests), 1)
        # The anonymous body is only a public variant of the authenticated one.
        out = self._probe(site, ["/api/profile"], expected_protected=True,
                          headers={"Authorization": "Bearer real-session"})
        self.assertFalse(any(f["confirmed"] for f in out["findings"]), out)

    def test_positive_control_protected_payload_served_anonymously_is_confirmed(self):
        site = self._site()
        out = self._probe(site, ["/api/report"], expected_protected=True,
                          headers={"Authorization": "Bearer real-session", "Accept": "*/*"})
        self.assertEqual([f["confirmed"] for f in out["findings"]], [True])
        auths = [headers.get("authorization") for _, _, headers in site.requests]
        self.assertEqual(auths, [None, "Bearer real-session"])   # anonymous, then baseline

    def test_denied_endpoint_control_stays_negative(self):
        site = self._site()
        out = self._probe(site, ["/api/tickets"], expected_protected=True,
                          headers={"Authorization": "Bearer real-session"})
        self.assertEqual(out["findings"], [])
        self.assertEqual(out["outcomes"][0]["classification"], "protected")
        # anonymous + garbage token; no baseline is spent on a denial
        self.assertEqual(len(site.requests), 2)

    def test_fault_injection_without_the_precondition_confirms_public(self):
        from harness import missing_auth_probe

        async def always_confirm(*args, **kwargs):
            return ""

        site = self._site()
        with patch.object(missing_auth_probe, "_unconfirmed_reason", always_confirm):
            out = self._probe(site, ["/products"], expected_protected=False)
        self.assertTrue(any(f["confirmed"] for f in out["findings"]), out)


if __name__ == "__main__":
    unittest.main()
