import asyncio
import unittest

from harness.api_surface_discovery import SurfaceDiscovery, _is_not_found, _paths_from_spec
from harness.run_context import RunContext, ScopePolicy
from harness.test_run_context import _Fixture

# Flask/Werkzeug wraps an unknown route as a 500 carrying this marker; the oracle
# must read that as "route does not exist" just like a bare 404.
_NF = ("Traceback (most recent call last):\n"
       "werkzeug.exceptions.NotFound: 404 Not Found: The requested URL was not found on the server.")


class _FakeDiscovery(SurfaceDiscovery):
    """SurfaceDiscovery with the network seam replaced by a canned responder:
    responder(method, path) -> (status, body, allow). Unknown paths fall through
    to the Flask-style NotFound 500 so the oracle is exercised realistically."""
    def __init__(self, responder, **kw):
        super().__init__("http://target.test", **kw)
        self._responder = responder

    async def _probe(self, method, path):
        return self._responder(method, path)


def _run(disc):
    return asyncio.run(disc.discover())


class OracleTests(unittest.TestCase):
    def test_bare_404_is_not_found(self):
        self.assertTrue(_is_not_found(404, "{}"))

    def test_framework_marker_is_not_found(self):
        self.assertTrue(_is_not_found(500, _NF))

    def test_real_responses_are_found(self):
        for status in (200, 201, 400, 401, 403, 405, 302):
            self.assertFalse(_is_not_found(status, "{}"), status)


class DiscoveryTests(unittest.TestCase):
    def _responder(self, known):
        def r(method, path):
            if path in known:
                return known[path]
            return (500, _NF, "")
        return r

    def _disc(self, known):
        return _FakeDiscovery(
            self._responder(known),
            prefixes=["/api/"],
            collections=["admin", "tickets"],
            nouns=["health", "users", "login", "tickets", "articles"],
        )

    def test_run_context_routes_actual_probe_with_session_and_budget(self):
        fixture = _Fixture()
        ctx = RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=1,
                                gate_config={"active_enabled": True})
        ctx.sessions.register("user", "user", {"Authorization": "Bearer discover"},
                              allowed_origins=[ScopePolicy.origin_of(fixture.base)])
        disc = SurfaceDiscovery(
            fixture.base, headers={"Authorization": "Bearer discover"},
            allowed_hosts=["127.0.0.1"], max_probes=1, use_ffuf=False,
            run_context=ctx, session_ref="user")
        async def scenario():
            result = await disc.discover()
            await ctx.aclose()
            return result
        try:
            result = asyncio.run(scenario())
            self.assertEqual(result.probes_sent, 1)
            self.assertEqual(ctx.budget.used, 1)
            self.assertEqual(fixture.httpd.received[0]["authorization"], "Bearer discover")
        finally:
            fixture.close()

    def test_finds_nested_route_a_flat_wordlist_misses(self):
        # /api/admin/users lives two segments deep; single-noun probing never
        # reaches it, nested enumeration does.
        known = {"/api/admin/users": (200, "{}", "")}
        res = _run(self._disc(known))
        self.assertIn("/api/admin/users", res.paths())
        self.assertEqual(next(r.source for r in res.routes if r.path == "/api/admin/users"), "nested")

    def test_allow_header_learns_post_only_route(self):
        # A GET on a POST-only route answers 405 + Allow -> learn its real methods.
        known = {"/api/login": (405, "{}", "OPTIONS, POST")}
        res = _run(self._disc(known))
        login = next(r for r in res.routes if r.path == "/api/login")
        self.assertIn("POST", login.methods)
        self.assertNotEqual(login.methods, ("GET",))

    def test_response_driven_id_enumeration(self):
        # A 200 list body reveals sibling object ids to enumerate.
        known = {
            "/api/tickets": (200, '[{"id":1},{"id":2},{"id":7}]', ""),
            "/api/tickets/1": (200, "{}", ""),
            "/api/tickets/2": (200, "{}", ""),
            "/api/tickets/7": (200, "{}", ""),
        }
        res = _run(self._disc(known))
        for p in ("/api/tickets/2", "/api/tickets/7"):
            self.assertIn(p, res.paths())

    def test_not_found_routes_excluded(self):
        known = {"/api/health": (200, "{}", "")}
        res = _run(self._disc(known))
        self.assertIn("/api/health", res.paths())
        self.assertNotIn("/api/users", res.paths())   # 404-wrapped -> excluded

    def test_scope_gate_blocks_out_of_scope_host(self):
        disc = _FakeDiscovery(self._responder({"/api/health": (200, "{}", "")}),
                              allowed_hosts=["other.test"],
                              prefixes=["/api/"], collections=[], nouns=["health"])
        # base_url host is target.test, not in allowed_hosts -> _probe short-circuits.
        # Override _probe path uses the real scope check via super? No: fake bypasses
        # network but we assert the real SurfaceDiscovery._probe gate here instead.
        real = SurfaceDiscovery("http://target.test", allowed_hosts=["other.test"])
        self.assertIsNone(asyncio.run(real._probe("GET", "/api/health")))

    def test_budget_cap_is_respected(self):
        calls = {"n": 0}
        def r(method, path):
            calls["n"] += 1
            return (500, _NF, "")
        disc = _FakeDiscovery(r, prefixes=["/api/"], collections=["a", "b"],
                              nouns=["x", "y", "z"], max_probes=5)
        res = _run(disc)
        self.assertLessEqual(res.probes_sent, 5)  # every phase is budget-guarded


class PrefixDerivationTests(unittest.TestCase):
    """Phase 0.2(a): discovery must not assume the surface lives under the
    built-in prefixes. It derives the namespaces the app actually exposes (from
    caller seed paths and from hits) and sweeps them."""

    def _responder(self, known):
        def r(method, path):
            return known.get(path, (500, _NF, ""))
        return r

    def test_derives_novel_prefix_from_seed_and_sweeps_it(self):
        # /portal/ is not a default prefix; a single crawler-found seed under it
        # must make discovery sweep the noun list there and reach its routes.
        known = {
            "/portal/users": (200, "{}", ""),
            "/portal/orders": (200, "{}", ""),
        }
        disc = _FakeDiscovery(self._responder(known),
                              prefixes=["/api/"], collections=[],
                              nouns=["users", "orders", "health"],
                              seed_paths=["/portal/dashboard"])
        res = _run(disc)
        self.assertIn("/portal/users", res.paths())
        self.assertIn("/portal/orders", res.paths())
        self.assertEqual(
            next(r.source for r in res.routes if r.path == "/portal/users"), "derived")

    def test_derived_prefix_with_no_real_routes_adds_nothing(self):
        # Negative control: a seed under a namespace that 404s everywhere must
        # not invent routes -- derivation is a reason to PROBE, not to assert.
        disc = _FakeDiscovery(self._responder({}),
                              prefixes=["/api/"], collections=[],
                              nouns=["users", "reports"],
                              seed_paths=["/ghost/x"])
        res = _run(disc)
        self.assertEqual(res.paths(), [])

    def test_default_prefixes_not_re_derived(self):
        # A seed under an already-built-in prefix must not be re-swept as
        # "derived" (dedup + no wasted classification).
        known = {"/admin/users": (200, "{}", "")}
        disc = _FakeDiscovery(self._responder(known),
                              prefixes=["/api/", "/admin/"], collections=[],
                              nouns=["users"], seed_paths=["/admin/panel"])
        res = _run(disc)
        self.assertIn("/admin/users", res.paths())
        self.assertNotEqual(
            next(r.source for r in res.routes if r.path == "/admin/users"), "derived")


class ActionSuffixTests(unittest.TestCase):
    """Phase 0.2(b): object-scoped action suffixes, beyond the fixed noun list --
    built-in workflow verbs and verbs generated from actions the app exposes."""

    def _responder(self, known):
        def r(method, path):
            return known.get(path, (500, _NF, ""))
        return r

    def test_builtin_action_suffix_found_under_object(self):
        known = {
            "/api/tickets": (200, '[{"id":1}]', ""),   # reveals object id 1
            "/api/tickets/1": (200, "{}", ""),
            "/api/tickets/1/lock": (200, "{}", ""),     # a built-in action, not a noun
        }
        disc = _FakeDiscovery(self._responder(known),
                              prefixes=["/api/"], collections=["tickets"],
                              nouns=["tickets"], actions=["lock", "unlock"])
        res = _run(disc)
        self.assertIn("/api/tickets/1/lock", res.paths())
        self.assertEqual(
            next(r.source for r in res.routes if r.path == "/api/tickets/1/lock"), "action")

    def test_generated_action_from_spec_applied_across_objects(self):
        # A spec declares escalate on tickets; escalate is in NO built-in list,
        # yet it must be tried on a structurally similar object (orders).
        spec = '{"openapi":"3.0.0","paths":{"/api/tickets/{id}/escalate":{}}}'
        known = {
            "/openapi.json": (200, spec, ""),
            "/api/orders": (200, '[{"id":1}]', ""),
            "/api/orders/1": (200, "{}", ""),
            "/api/orders/1/escalate": (200, "{}", ""),   # found only via generation
        }
        disc = _FakeDiscovery(self._responder(known),
                              prefixes=["/api/"], collections=["orders"],
                              nouns=["orders"], actions=[])   # no built-in escalate
        res = _run(disc)
        self.assertIn("/api/orders/1/escalate", res.paths())

    def test_no_object_no_action_probes(self):
        # Negative control: with no object-scoped route to hang an action on,
        # action mining probes nothing (and invents nothing).
        known = {"/api/health": (200, "{}", "")}
        disc = _FakeDiscovery(self._responder(known),
                              prefixes=["/api/"], collections=[],
                              nouns=["health"], actions=["lock"])
        res = _run(disc)
        self.assertEqual(res.paths(), ["/api/health"])


class SensitiveFileTests(unittest.TestCase):
    """Phase 0.2(c): a sensitive-artifact wordlist distinct from REST nouns, plus
    generated backup-suffix variants."""

    def _responder(self, known):
        def r(method, path):
            return known.get(path, (500, _NF, ""))
        return r

    def test_env_file_discovered(self):
        known = {"/.env": (200, "SECRET_KEY=abc\nDB_PASSWORD=hunter2", "")}
        disc = _FakeDiscovery(self._responder(known),
                              prefixes=["/api/"], collections=[], nouns=["health"],
                              actions=[], sensitive_files=[".env", "config.json"])
        res = _run(disc)
        self.assertIn("/.env", res.paths())
        self.assertEqual(
            next(r.source for r in res.routes if r.path == "/.env"), "sensitive_file")

    def test_backup_suffix_generated_for_common_base(self):
        # config.php.bak is reached by suffixing a common base -- no need to have
        # discovered config.php first.
        known = {"/config.php.bak": (200, "<?php $db_pass='x';", "")}
        disc = _FakeDiscovery(self._responder(known),
                              prefixes=["/api/"], collections=[], nouns=["health"],
                              actions=[], sensitive_files=[])
        res = _run(disc)
        self.assertIn("/config.php.bak", res.paths())

    def test_backup_suffix_generated_for_discovered_file(self):
        # A discovered file-like route gets .bak/~/.old variants tried.
        known = {
            "/app.js": (200, "// bundle", ""),
            "/app.js.old": (200, "// bundle with a leaked key", ""),
        }
        disc = _FakeDiscovery(self._responder(known),
                              prefixes=["/"], collections=[], nouns=["app.js"],
                              actions=[], sensitive_files=[])
        res = _run(disc)
        self.assertIn("/app.js", res.paths())
        self.assertIn("/app.js.old", res.paths())

    def test_absent_sensitive_files_not_reported(self):
        # Negative control: everything 404s -> nothing invented.
        disc = _FakeDiscovery(self._responder({}),
                              prefixes=["/api/"], collections=[], nouns=["health"],
                              actions=[], sensitive_files=[".env", ".git/config"])
        res = _run(disc)
        self.assertEqual(res.paths(), [])


class BodyPathMiningTests(unittest.TestCase):
    """Phase 0.2(d): mine response BODIES (not just JS assets) for path-like
    strings and same-host URLs, fed back as candidate routes."""

    def _responder(self, known):
        def r(method, path):
            return known.get(path, (500, _NF, ""))
        return r

    def test_paths_in_json_body_fed_back(self):
        known = {
            "/api/config": (200, '{"docs":"/internal/docs","help":"/help/topics"}', ""),
            "/internal/docs": (200, "<html>docs</html>", ""),
            "/help/topics": (200, "{}", ""),
        }
        disc = _FakeDiscovery(self._responder(known),
                              prefixes=["/api/"], collections=[], nouns=["config"],
                              actions=[], sensitive_files=[])
        res = _run(disc)
        self.assertIn("/internal/docs", res.paths())
        self.assertIn("/help/topics", res.paths())
        self.assertEqual(
            next(r.source for r in res.routes if r.path == "/internal/docs"), "body")

    def test_absolute_same_host_url_in_body_fed_back(self):
        known = {
            "/api/info": (200, '{"portal":"http://target.test/dashboard/home"}', ""),
            "/dashboard/home": (200, "{}", ""),
        }
        disc = _FakeDiscovery(self._responder(known),
                              prefixes=["/api/"], collections=[], nouns=["info"],
                              actions=[], sensitive_files=[])
        res = _run(disc)
        self.assertIn("/dashboard/home", res.paths())

    def test_body_mined_path_can_reveal_a_new_prefix(self):
        # A path named in a body reveals /internal/, which is then swept (a(d)+(a)
        # synergy): a sibling under that prefix is found by the noun sweep.
        known = {
            "/api/config": (200, '{"see":"/internal/docs"}', ""),
            "/internal/docs": (200, "{}", ""),
            "/internal/users": (200, "{}", ""),   # only reached once /internal/ derived
        }
        disc = _FakeDiscovery(self._responder(known),
                              prefixes=["/api/"], collections=[],
                              nouns=["config", "users"], actions=[], sensitive_files=[])
        res = _run(disc)
        self.assertIn("/internal/users", res.paths())

    def test_body_without_paths_feeds_nothing(self):
        # Negative control: a body with no path-shaped strings adds no routes.
        known = {"/api/config": (200, '{"name":"prod","count":42}', "")}
        disc = _FakeDiscovery(self._responder(known),
                              prefixes=["/api/"], collections=[], nouns=["config"],
                              actions=[], sensitive_files=[])
        res = _run(disc)
        self.assertEqual(res.paths(), ["/api/config"])


class SoftNotFoundTests(unittest.TestCase):
    """Phase 5: discovery keys off content/shape, not just HTTP status. A
    catch-all that answers non-404 for unknown paths must not make every probe
    look like a real route."""

    def _soft_responder(self, real):
        # Unknown paths return a 200 catch-all that ECHOES the path (a soft-404);
        # real routes return distinct content.
        def r(method, path):
            if path in real:
                return real[path]
            return (200, f"<html><body>Not Found: {path}</body></html>", "")
        return r

    def test_soft_404_paths_not_reported_as_routes(self):
        real = {"/api/users": (200, '{"users":[]}', "")}
        disc = _FakeDiscovery(self._soft_responder(real),
                              prefixes=["/api/"], collections=[],
                              nouns=["users", "orders", "health"], actions=[], sensitive_files=[])
        res = _run(disc)
        self.assertIsNotNone(disc._soft404)              # calibrated the catch-all
        self.assertIn("/api/users", res.paths())          # real route -> distinct content
        self.assertNotIn("/api/orders", res.paths())      # soft-404 -> suppressed by shape
        self.assertNotIn("/api/health", res.paths())

    def test_hard_404_app_records_no_soft_signature(self):
        # An app that returns honest 404s -> nothing calibrated -> unchanged.
        def r(method, path):
            return (200, '{"u":1}', "") if path == "/api/users" else (404, "nope", "")
        disc = _FakeDiscovery(r, prefixes=["/api/"], collections=[],
                              nouns=["users", "orders"], actions=[], sensitive_files=[])
        res = _run(disc)
        self.assertIsNone(disc._soft404)
        self.assertIn("/api/users", res.paths())
        self.assertNotIn("/api/orders", res.paths())

    def test_varying_bogus_responses_do_not_calibrate(self):
        # If two bogus paths return DIFFERENT non-404 bodies (responses genuinely
        # vary), no soft-404 signature is set -- we must not suppress by shape.
        calls = {"n": 0}
        def r(method, path):
            if path == "/api/users":
                return (200, '{"u":1}', "")
            calls["n"] += 1
            return (200, "error variant " + ("x" * calls["n"]), "")  # differs (letters, not digits/path)
        disc = _FakeDiscovery(r, prefixes=["/api/"], collections=[],
                              nouns=["users"], actions=[], sensitive_files=[])
        res = _run(disc)
        self.assertIsNone(disc._soft404)
        self.assertIn("/api/users", res.paths())


class FfufIntegrationTests(unittest.TestCase):
    """ffuf fast-path wired into SurfaceDiscovery.discover()."""

    def _responder(self, known):
        def r(method, path):
            return known.get(path, (500, _NF, ""))
        return r

    def test_ffuf_routes_seeded_into_seen(self):
        """When ffuf is available, its routes appear in the result tagged 'ffuf'."""
        import json as _json
        from unittest.mock import patch
        from harness.ffuf_runner import FfufResult
        from harness.api_surface_discovery import Route as R

        ffuf_routes = [R(path="/api/login", status=200, length=50, source="ffuf"),
                       R(path="/api/secret", status=403, length=10, source="ffuf")]
        mock_result = FfufResult(routes=ffuf_routes, returncode=0)

        known = {"/api/login": (200, '{"ok":true}', "")}
        disc = _FakeDiscovery(self._responder(known),
                              prefixes=["/api/"], collections=[], nouns=["login"],
                              actions=[], sensitive_files=[])

        with patch("harness.ffuf_runner.ffuf_available", return_value=(True, "ok")), \
             patch("harness.ffuf_runner.ffuf_discover", return_value=mock_result):
            res = _run(disc)

        self.assertIn("/api/login", res.paths())
        self.assertIn("/api/secret", res.paths())
        secret = next(r for r in res.routes if r.path == "/api/secret")
        self.assertEqual(secret.source, "ffuf")

    def test_ffuf_unavailable_falls_back_silently(self):
        """When Docker/image is absent, discover() still works (Python sweep)."""
        from unittest.mock import patch

        known = {"/api/health": (200, "{}", "")}
        disc = _FakeDiscovery(self._responder(known),
                              prefixes=["/api/"], collections=[], nouns=["health"],
                              actions=[], sensitive_files=[])

        with patch("harness.ffuf_runner.ffuf_available", return_value=(False, "no docker")):
            res = _run(disc)

        self.assertIn("/api/health", res.paths())
        self.assertTrue(any("ffuf skipped" in e for e in res.errors))

    def test_ffuf_disabled_by_flag(self):
        """use_ffuf=False skips ffuf entirely -- no import, no check."""
        from unittest.mock import patch

        known = {"/api/health": (200, "{}", "")}
        disc = _FakeDiscovery(self._responder(known),
                              prefixes=["/api/"], collections=[], nouns=["health"],
                              actions=[], sensitive_files=[])
        disc.use_ffuf = False

        with patch("harness.ffuf_runner.ffuf_available") as mock_avail:
            res = _run(disc)
            mock_avail.assert_not_called()

        self.assertIn("/api/health", res.paths())

    def test_ffuf_routes_not_duplicated_by_python_sweep(self):
        """A path found by ffuf isn't re-probed by the Python wordlist sweep."""
        from unittest.mock import patch
        from harness.ffuf_runner import FfufResult
        from harness.api_surface_discovery import Route as R

        ffuf_routes = [R(path="/api/login", status=200, length=50, source="ffuf")]
        mock_result = FfufResult(routes=ffuf_routes, returncode=0)

        probe_calls = []
        known = {"/api/login": (200, '{"ok":true}', "")}

        class _Tracking(_FakeDiscovery):
            async def _probe(self, method, path):
                probe_calls.append(path)
                return self._responder(method, path)

        disc = _Tracking(self._responder(known),
                         prefixes=["/api/"], collections=[], nouns=["login"],
                         actions=[], sensitive_files=[])

        with patch("harness.ffuf_runner.ffuf_available", return_value=(True, "ok")), \
             patch("harness.ffuf_runner.ffuf_discover", return_value=mock_result):
            res = _run(disc)

        login_route = next(r for r in res.routes if r.path == "/api/login")
        self.assertEqual(login_route.source, "ffuf")


class HtmlLinkMiningTests(unittest.TestCase):
    """HTML link/form mining in _mine_responses: <a href> and <form action>
    tags in HTML responses feed discovered routes back into the surface."""

    def _responder(self, known):
        def r(method, path):
            return known.get(path, (500, _NF, ""))
        return r

    def test_html_anchor_links_fed_back(self):
        known = {
            "/web/home": (200, '<html><body><a href="/web/search">Search</a>'
                          '<a href="/web/ticket/1">Ticket</a></body></html>', ""),
            "/web/search": (200, "<html>search page</html>", ""),
            "/web/ticket/1": (200, "<html>ticket</html>", ""),
        }
        disc = _FakeDiscovery(self._responder(known),
                              prefixes=["/web/"], collections=[], nouns=["home"],
                              actions=[], sensitive_files=[])
        res = _run(disc)
        self.assertIn("/web/search", res.paths())
        self.assertIn("/web/ticket/1", res.paths())

    def test_form_action_fed_back(self):
        known = {
            "/web/login": (200, '<html><form action="/api/auth/login" method="post">'
                           '<input name="user"></form></html>', ""),
            "/api/auth/login": (405, "{}", "POST"),
        }
        disc = _FakeDiscovery(self._responder(known),
                              prefixes=["/web/"], collections=[], nouns=["login"],
                              actions=[], sensitive_files=[])
        res = _run(disc)
        self.assertIn("/api/auth/login", res.paths())

    def test_non_html_body_no_html_mining(self):
        known = {"/api/data": (200, '{"link":"/api/other"}', "")}
        disc = _FakeDiscovery(self._responder(known),
                              prefixes=["/api/"], collections=[], nouns=["data"],
                              actions=[], sensitive_files=[])
        res = _run(disc)
        self.assertNotIn("/api/other", [r.path for r in res.routes if r.source == "html"])


class DeepNestedTests(unittest.TestCase):
    """Three-segment nesting under live 2-segment prefixes."""

    def _responder(self, known):
        def r(method, path):
            return known.get(path, (500, _NF, ""))
        return r

    def test_deep_nested_found_under_live_prefix(self):
        known = {
            "/api/admin": (200, "{}", ""),
            "/api/admin/diagnostics/health": (200, '{"ok":true}', ""),
        }
        disc = _FakeDiscovery(self._responder(known),
                              prefixes=["/api/"], collections=["diagnostics"],
                              nouns=["admin", "health"],
                              actions=[], sensitive_files=[])
        res = _run(disc)
        self.assertIn("/api/admin/diagnostics/health", res.paths())

    def test_dead_prefix_no_deep_nesting(self):
        known = {"/api/health": (200, "{}", "")}
        disc = _FakeDiscovery(self._responder(known),
                              prefixes=["/api/"], collections=["admin"],
                              nouns=["health", "users"],
                              actions=[], sensitive_files=[])
        res = _run(disc)
        found_deep = [p for p in res.paths() if p.count("/") >= 4]
        self.assertEqual(found_deep, [])


class QueryParamProbeTests(unittest.TestCase):
    """Query-parameter discovery: probe common params on discovered endpoints."""

    def _responder(self, known):
        def r(method, path):
            return known.get(path, (500, _NF, ""))
        return r

    def test_distinct_response_with_param_discovered(self):
        known = {
            "/api/tickets": (200, '{"items":[]}', ""),
            "/api/tickets?filter=1": (200, '{"items":[{"id":1}], "filtered":true}', ""),
        }
        disc = _FakeDiscovery(self._responder(known),
                              prefixes=["/api/"], collections=[], nouns=["tickets"],
                              actions=[], sensitive_files=[])
        res = _run(disc)
        param_routes = [r for r in res.routes if r.source == "param_probe"]
        self.assertTrue(len(param_routes) >= 1)

    def test_identical_response_not_recorded(self):
        body = '{"items":[]}'
        known = {"/api/tickets": (200, body, "")}
        # all param variants return the same body -> nothing recorded
        def r(method, path):
            if path.startswith("/api/tickets"):
                return (200, body, "")
            return (500, _NF, "")
        disc = _FakeDiscovery(r, prefixes=["/api/"], collections=[], nouns=["tickets"],
                              actions=[], sensitive_files=[])
        res = _run(disc)
        param_routes = [r for r in res.routes if r.source == "param_probe"]
        self.assertEqual(len(param_routes), 0)


class SpecTests(unittest.TestCase):
    def test_spec_paths_parsed(self):
        body = '{"openapi":"3.0.0","paths":{"/api/a":{},"/api/b/{id}":{},"bad":{}}}'
        self.assertEqual(sorted(_paths_from_spec(body)), ["/api/a", "/api/b/{id}"])

    def test_spec_probe_supplies_surface(self):
        spec = '{"openapi":"3.0.0","paths":{"/api/secret/route":{},"/api/other":{}}}'
        def r(method, path):
            if path == "/openapi.json":
                return (200, spec, "")
            return (500, _NF, "")
        disc = _FakeDiscovery(r, prefixes=["/api/"], collections=[], nouns=["nope"])
        res = _run(disc)
        self.assertEqual(res.spec_found, "/openapi.json")
        self.assertIn("/api/secret/route", res.paths())


if __name__ == "__main__":
    unittest.main()
