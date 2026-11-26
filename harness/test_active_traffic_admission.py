"""ARC-1 and ARC-2 (2026-11-19 principal audit): admission for routes that send
target traffic.

ARC-1. A static call-graph scan of `app.routes` finds every handler that reaches
`RunContext.create`, `standalone_context` or `transport_for`; server's admission
registry must list exactly those routes. Each gated route carries the one shared
dependency, `require_active_traffic`, and with validators.active_enabled=false
each answers 403 while an owned loopback target counts zero requests.
Negative control: strip the dependency from one route; the structural check
reports it, the behavioural check fails, and that route then sends.

ARC-9. The routes live in router modules (harness/server_routes_*.py) whose
handlers are closures over the server module, so the scan resolves closure
variables too, and every router module's routes are in app.routes. Admission is
single-sourced in harness.server_admission. Negative controls: a router route that
reaches a send path without the dependency fails the scan; a scan without closure
resolution misses the router routes; an included (lazy) router hides its routes.

ARC-2. With iterative_agent.enabled and server.allowed_hosts=[], POST /active-probe
answers 403 and the target receives nothing. Each layer refuses on its own: the
route's active scope admission, run_active_probe's standalone admission, and the
standalone context's active default (its transport refuses the send).
Negative control: the old default (active_mode=False, no admission) sends the
model-chosen request to the unscoped host.

Every target is an owned loopback server (test_no_run_route_callers._Target);
nothing leaves 127.0.0.1.
"""
from __future__ import annotations

import ast
import asyncio
import importlib
import inspect
import shutil
import tempfile
import textwrap
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi import APIRouter, FastAPI
from fastapi.routing import APIRoute

from harness import (global_throttle, iterative_agent, run_context, safety_gate,
                     server_admission, store)
from harness.test_no_run_route_callers import _IN_SCOPE, _Target, _page

_MISSING = object()


# ---------------------------------------------------------------------------
# Static call-graph scan
# ---------------------------------------------------------------------------

def _function(obj):
    if isinstance(obj, (classmethod, staticmethod)):
        obj = obj.__func__
    if inspect.ismethod(obj):
        obj = obj.__func__
    return obj if inspect.isfunction(obj) else None


def _product_code(fn) -> bool:
    module = getattr(fn, "__module__", "") or ""
    return module.startswith("harness") and not module.rsplit(".", 1)[-1].startswith("test_")


def _static_attr(base, name):
    try:
        return inspect.getattr_static(base, name)
    except AttributeError:
        if isinstance(base, types.ModuleType):
            try:
                return importlib.import_module(f"{base.__name__}.{name}")
            except ImportError:
                pass
        return _MISSING


def _local_imports(tree) -> dict:
    """Names bound by `from harness... import` / `import harness...` inside a body."""
    names = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and not node.level and (node.module or "").startswith("harness"):
            module = importlib.import_module(node.module)
            for alias in node.names:
                names[alias.asname or alias.name] = _static_attr(module, alias.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.startswith("harness"):
                    module = importlib.import_module(alias.name)
                    names[alias.asname or "harness"] = module if alias.asname else importlib.import_module("harness")
    return names


def _closure_vars(fn) -> dict:
    """A closure's free variables and their values; an empty cell is skipped."""
    names = {}
    for name, cell in zip(fn.__code__.co_freevars, fn.__closure__ or ()):
        try:
            names[name] = cell.cell_contents
        except ValueError:
            pass
    return names


class TrafficScan:
    """Which route handlers can reach a run-owning send path?

    Each function's own source is parsed and every loaded name or attribute is
    resolved against that function's namespace: module globals, its closure
    variables (a router handler reads the server module as `srv`), its local
    harness imports, and `self` (the live owner: the server's orchestrator for its
    routes, so instance-attribute dispatch such as `self.agent_manager.x` is
    followed too).
    Product functions and methods are followed, including ones passed as callbacks;
    anything outside `harness` (or in a test module) is not. Resolution is static
    (`inspect.getattr_static`), so no property or handler code runs."""

    def __init__(self, *, closures: bool = True):
        self.closures = closures
        self.sinks = {
            id(run_context.RunContext.__dict__["create"].__func__): "RunContext.create",
            id(run_context.standalone_context): "standalone_context",
            id(run_context.transport_for): "transport_for",
        }
        self._edges: dict = {}

    def _edges_of(self, fn, owner) -> list:
        key = (fn, id(owner))
        if key in self._edges:
            return self._edges[key]
        self._edges[key] = edges = []
        try:
            tree = ast.parse(textwrap.dedent(inspect.getsource(fn)))
        except (OSError, TypeError, SyntaxError):
            return edges
        scope = dict(fn.__globals__)
        if self.closures:
            scope.update(_closure_vars(fn))
        scope.update(_local_imports(tree))

        def resolve(node):
            if isinstance(node, ast.Name):
                if node.id == "self" and owner is not None:
                    return owner
                return scope.get(node.id, _MISSING)
            if isinstance(node, ast.Attribute):
                base = resolve(node.value)
                return _MISSING if base is _MISSING else _static_attr(base, node.attr)
            return _MISSING

        for node in ast.walk(tree):
            if not isinstance(node, (ast.Name, ast.Attribute)) or not isinstance(node.ctx, ast.Load):
                continue
            value = resolve(node)
            target = None if value is _MISSING else _function(value)
            if target is None:
                continue
            if id(target) in self.sinks:
                edges.append((None, None, self.sinks[id(target)]))
                continue
            if not _product_code(target):
                continue
            new_owner = None
            if isinstance(node, ast.Attribute):
                base = resolve(node.value)
                if not isinstance(base, types.ModuleType):
                    new_owner = base
            if new_owner is None and "." in target.__qualname__:
                new_owner = owner
            edges.append((target, new_owner, target.__qualname__))
        return edges

    def path_to_sink(self, fn, owner=None):
        """The first call path from `fn` to a sink, or None."""
        stack, seen = [(fn, owner, (fn.__qualname__,))], set()
        while stack:
            current, current_owner, path = stack.pop()
            if (current, id(current_owner)) in seen:
                continue
            seen.add((current, id(current_owner)))
            for target, target_owner, name in self._edges_of(current, current_owner):
                if target is None:
                    return path + (name,)
                stack.append((target, target_owner, path + (name,)))
        return None

    def traffic_routes(self, app, owner) -> dict:
        found = {}
        for route in app.routes:
            if not isinstance(route, APIRoute):
                continue
            path = self.path_to_sink(_function(route.endpoint), owner)
            if path:
                for method in route.methods:
                    found[(method, route.path)] = path
        return found


def _unregistered(server, scanned) -> set:
    """Scanned traffic routes the admission registry does not list."""
    registered = (set(server.ACTIVE_TRAFFIC_ROUTES) | set(server.ACTIVE_TRAFFIC_WHEN)
                  | set(server.PASSIVE_RUN_ROUTES))
    return set(scanned) - registered


def _synthetic_router(srv, *, gated: bool) -> APIRouter:
    """A router module's shape: one handler, a closure over the server module,
    that reaches standalone_context through srv.orchestrator.run_active_probe."""
    router = APIRouter()

    @router.post("/synthetic-traffic",
                 dependencies=list(server_admission._ACTIVE_TRAFFIC) if gated else [])
    async def synthetic_traffic():
        return await srv.orchestrator.run_active_probe(None, "", "")

    return router


def _ungated(server, routes) -> list:
    """Registered active-traffic routes that do not carry require_active_traffic."""
    missing = []
    for route in routes:
        if not isinstance(route, APIRoute):
            continue
        for method in route.methods:
            if (method, route.path) not in server.ACTIVE_TRAFFIC_ROUTES:
                continue
            if not any(dep.call is server.require_active_traffic for dep in route.dependant.dependencies):
                missing.append((method, route.path))
    return sorted(missing)


def _without_admission(server, path: str) -> list:
    """app.routes with require_active_traffic stripped from the route at `path`."""
    routes = []
    for route in server.app.router.routes:
        if isinstance(route, APIRoute) and route.path == path:
            route = APIRoute(
                route.path, route.endpoint, methods=list(route.methods), name=route.name,
                response_model=route.response_model,
                dependencies=[d for d in route.dependencies
                              if d.dependency is not server.require_active_traffic])
        routes.append(route)
    return routes


# ---------------------------------------------------------------------------
# Fixture: the real server module against an owned loopback target
# ---------------------------------------------------------------------------

class _AdmissionFixture(unittest.TestCase):
    def setUp(self):
        import harness.server as server
        from fastapi.testclient import TestClient
        self.server = server
        orchestrator = server.orchestrator
        tmp = tempfile.mkdtemp(prefix="arc1_admission_")
        self.addCleanup(shutil.rmtree, tmp, True)
        self.addCleanup(setattr, store, "_DB_PATH", store._DB_PATH)
        store._DB_PATH = Path(tmp) / "state.db"
        for name in ("allowed_hosts", "iterative_agent_enabled", "engagement_driver_execute"):
            self.addCleanup(setattr, orchestrator, name, getattr(orchestrator, name))
        self.addCleanup(orchestrator.validator_registry.set_active_enabled,
                        orchestrator.validator_registry.active_enabled)
        orchestrator.allowed_hosts = [_IN_SCOPE]
        orchestrator.iterative_agent_enabled = True
        orchestrator.engagement_driver_execute = True
        global_throttle.configure(0)
        safety_gate.reset_default_gate()
        self.addCleanup(safety_gate.reset_default_gate)
        self.client = TestClient(server.app, base_url="http://localhost",
                                 headers={"Authorization": f"Bearer {server._mutation_token()}"})
        self.site = _Target(_IN_SCOPE, routes={
            "/": _page('<a href="/a">a</a>'), "/a": _page("<p>a</p>"),
            "/api/report": _page('{"report": 1}')})
        self.addCleanup(self.site.close)
        self.transport_sends: list[str] = []
        real_execute = run_context.TargetTransport.execute

        async def counting_execute(transport, request, **kwargs):
            self.transport_sends.append(request.url)
            return await real_execute(transport, request, **kwargs)
        counter = patch.object(run_context.TargetTransport, "execute", counting_execute)
        counter.start()
        self.addCleanup(counter.stop)

    def arm(self, enabled: bool):
        self.server.orchestrator.validator_registry.set_active_enabled(enabled)

    def exchange(self, path: str = "/api/report") -> dict:
        return {"url": self.site.origin + path, "method": "GET", "request_headers": {},
                "request_body": "", "response_status": 200, "response_headers": {},
                "response_body": ""}

    def calls(self) -> dict:
        """One request per traffic route; each would reach the target if admitted."""
        origin = self.site.origin
        return {
            ("POST", "/crawl"): ("/crawl", {"base_url": origin + "/", "max_pages": 2}),
            ("POST", "/crawl-roles"): ("/crawl-roles", {
                "base_url": origin + "/", "roles": [{"role": "anonymous"}], "max_pages": 2,
                "register_identities": False}),
            ("POST", "/engagement/{host}/advance"): (f"/engagement/{_IN_SCOPE}/advance", {
                "base_url": origin + "/", "roles": [{"role": "user"}], "max_pages": 1,
                "max_endpoints": 1}),
            ("POST", "/engagement/{host}/investigate"): (
                f"/engagement/{_IN_SCOPE}/investigate", {"base_url": origin + "/"}),
            ("POST", "/probe-missing-auth"): ("/probe-missing-auth", {
                "base_url": origin, "paths": ["/api/report"]}),
            ("POST", "/active-probe"): ("/active-probe", {
                "exchange": self.exchange(), "hypothesis": "idor on report id", "specialty": "idor"}),
            ("POST", "/engagement/{host}/run"): (f"/engagement/{_IN_SCOPE}/run", {
                "base_url": origin + "/", "execute": True, "max_targets": 1, "max_rounds": 1}),
        }

    def assert_refused_without_sends(self, key):
        path, body = self.calls()[key]
        received, sent = len(self.site.requests), len(self.transport_sends)
        response = self.client.post(path, json=body)
        self.assertEqual(response.status_code, 403, f"{key}: {response.text}")
        self.assertIn("active operations are disabled", response.json()["detail"])
        self.assertEqual(self.site.requests[received:], [], key)
        self.assertEqual(self.transport_sends[sent:], [], key)


# ---------------------------------------------------------------------------
# ARC-1
# ---------------------------------------------------------------------------

class TrafficRouteRegistryTests(unittest.TestCase):
    """The registry is exactly what the source reaches, and every gated route
    carries the shared dependency."""

    def setUp(self):
        import harness.server as server
        self.server = server

    def test_every_route_reaching_a_run_is_registered(self):
        scanned = TrafficScan().traffic_routes(self.server.app, self.server.orchestrator)
        registered = (set(self.server.ACTIVE_TRAFFIC_ROUTES) | set(self.server.ACTIVE_TRAFFIC_WHEN)
                      | set(self.server.PASSIVE_RUN_ROUTES))
        self.assertEqual(set(scanned), registered, scanned)
        self.assertEqual(_unregistered(self.server, scanned), set())
        # The audit's six routes are gated unconditionally.
        self.assertLessEqual({
            ("POST", "/crawl"), ("POST", "/crawl-roles"), ("POST", "/engagement/{host}/advance"),
            ("POST", "/engagement/{host}/investigate"), ("POST", "/probe-missing-auth"),
            ("POST", "/active-probe")}, set(self.server.ACTIVE_TRAFFIC_ROUTES))
        self.assertFalse(set(self.server.ACTIVE_TRAFFIC_ROUTES) & set(self.server.PASSIVE_RUN_ROUTES))

    def test_the_scan_follows_handlers_into_the_orchestrator(self):
        """Scanner control: /active-probe reaches standalone_context only through
        Orchestrator.run_active_probe; a handler that never sends is not reported."""
        scan = TrafficScan()
        endpoints = {route.path: route.endpoint for route in self.server.app.routes
                     if isinstance(route, APIRoute)}
        probe_path = scan.path_to_sink(_function(endpoints["/active-probe"]), self.server.orchestrator)
        self.assertIn("ConfirmMixin.run_active_probe", probe_path)
        self.assertIsNone(scan.path_to_sink(_function(endpoints["/settings"]), self.server.orchestrator))

    def test_every_gated_route_carries_the_shared_dependency(self):
        self.assertEqual(_ungated(self.server, self.server.app.routes), [])

    def test_negative_control_stripped_route_is_reported(self):
        stripped = _without_admission(self.server, "/probe-missing-auth")
        self.assertEqual(_ungated(self.server, stripped), [("POST", "/probe-missing-auth")])

    def test_the_scan_covers_every_router_module(self):
        """ARC-9: every harness/server_routes_*.py is registered on the app, each
        router contributes routes, and the scanned traffic routes come from them."""
        files = {f"harness.{path.stem}" for path in Path(__file__).parent.glob("server_routes_*.py")}
        self.assertEqual({module.__name__ for module in self.server.ROUTER_MODULES}, files)
        endpoint_modules = {route.endpoint.__module__ for route in self.server.app.routes
                            if isinstance(route, APIRoute)}
        self.assertEqual(endpoint_modules, files)
        scanned = TrafficScan().traffic_routes(self.server.app, self.server.orchestrator)
        by_route = {(method, route.path): route.endpoint.__module__
                    for route in self.server.app.routes if isinstance(route, APIRoute)
                    for method in route.methods}
        self.assertLessEqual({by_route[key] for key in scanned}, files)

    def test_app_routes_are_flat(self):
        """The scan reads app.routes. An included router is one lazy entry there
        (FastAPI 0.141), so its routes would escape the scan. Control: the same
        traffic route is found when registered and missed when included."""
        lazy = [route for route in self.server.app.routes
                if not isinstance(route, APIRoute) and type(route).__name__ != "Route"]
        self.assertEqual(lazy, [])
        scan = TrafficScan()
        registered, included = FastAPI(), FastAPI()
        registered.router.routes.extend(_synthetic_router(self.server, gated=False).routes)
        included.include_router(_synthetic_router(self.server, gated=False))
        self.assertIn(("POST", "/synthetic-traffic"),
                      scan.traffic_routes(registered, self.server.orchestrator))
        self.assertEqual(scan.traffic_routes(included, self.server.orchestrator), {})

    def test_admission_is_single_sourced(self):
        """ARC-9: the dependency, the master switch and the registry are defined
        once, in harness.server_admission; server re-exports, routers import."""
        for name in ("require_active_traffic", "_ACTIVE_TRAFFIC", "ACTIVE_TRAFFIC_ROUTES",
                     "ACTIVE_TRAFFIC_WHEN", "PASSIVE_RUN_ROUTES"):
            self.assertIs(getattr(self.server, name), getattr(server_admission, name), name)
        self.assertFalse(hasattr(self.server, "_admit_active_traffic"))
        for module in self.server.ROUTER_MODULES:
            for name in ("require_active_traffic", "_admit_active_traffic", "_ACTIVE_TRAFFIC"):
                if hasattr(module, name):
                    self.assertIs(getattr(module, name), getattr(server_admission, name),
                                  f"{module.__name__}.{name}")
        definition = ("def require_active_traffic", "def _admit_active_traffic",
                      "_ACTIVE_TRAFFIC =", "ACTIVE_TRAFFIC_ROUTES =")
        for path in Path(__file__).parent.glob("*.py"):
            if path.name == "server_admission.py" or path.name.startswith("test_"):
                continue
            text = path.read_text(encoding="utf-8")
            for needle in definition:
                self.assertNotIn(needle, text, f"{path.name} defines {needle!r}")

    def test_the_scan_resolves_router_closures(self):
        """Scanner control: a router handler reaches the orchestrator only through
        its closure variable `srv`. Without closure resolution the scan misses it."""
        endpoint = next(route.endpoint for route in self.server.app.routes
                        if isinstance(route, APIRoute) and route.path == "/active-probe")
        self.assertIn("srv", endpoint.__code__.co_freevars)
        self.assertIsNotNone(TrafficScan().path_to_sink(endpoint, self.server.orchestrator))
        self.assertIsNone(TrafficScan(closures=False).path_to_sink(endpoint, self.server.orchestrator))

    def test_negative_control_router_route_without_the_dependency(self):
        """Fault injection: a router route that reaches standalone_context without
        require_active_traffic. The registry check reports it; listed in the
        registry but still ungated, the dependency check reports it; its gated twin
        passes both."""
        app_routes = list(self.server.app.routes)
        ungated = _synthetic_router(self.server, gated=False).routes
        scanned = TrafficScan().traffic_routes(types.SimpleNamespace(routes=app_routes + ungated),
                                               self.server.orchestrator)
        self.assertIn("ConfirmMixin.run_active_probe", scanned[("POST", "/synthetic-traffic")])
        self.assertEqual(_unregistered(self.server, scanned), {("POST", "/synthetic-traffic")})
        listed = self.server.ACTIVE_TRAFFIC_ROUTES | {("POST", "/synthetic-traffic")}
        with patch.object(self.server, "ACTIVE_TRAFFIC_ROUTES", listed):
            self.assertEqual(_ungated(self.server, app_routes + ungated),
                             [("POST", "/synthetic-traffic")])
            gated = _synthetic_router(self.server, gated=True).routes
            self.assertEqual(_ungated(self.server, app_routes + gated), [])


class TrafficRouteAdmissionTests(_AdmissionFixture):
    """With active mode off every traffic route answers 403 and sends nothing,
    even with a scope covering the target and the iterative agent enabled."""

    def test_passive_mode_refuses_every_traffic_route_with_zero_sends(self):
        self.arm(False)
        calls = self.calls()
        self.assertEqual(set(calls), set(self.server.ACTIVE_TRAFFIC_ROUTES) | set(self.server.ACTIVE_TRAFFIC_WHEN))
        for key in calls:
            with self.subTest(route=key):
                self.assert_refused_without_sends(key)

    def test_plan_only_engagement_run_stays_passive(self):
        """Control: /engagement/{host}/run sends only with execute=true; a plan
        while passive is still answered, and sends nothing."""
        self.arm(False)
        response = self.client.post(f"/engagement/{_IN_SCOPE}/run",
                                    json={"base_url": self.site.origin + "/", "max_targets": 1})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(self.site.requests, [])
        self.assertEqual(self.transport_sends, [])

    def test_armed_control_reaches_the_target(self):
        """Positive control: the counters see real sends once active mode is on."""
        self.arm(True)
        path, body = self.calls()[("POST", "/probe-missing-auth")]
        response = self.client.post(path, json=body)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertIn("/api/report", self.site.paths())
        self.assertTrue(self.transport_sends)

    def test_negative_control_route_without_the_dependency_sends(self):
        """Fault injection: strip require_active_traffic from one route. The
        acceptance check then fails for that route, and its probe reaches the target."""
        self.arm(False)
        stripped = _without_admission(self.server, "/probe-missing-auth")
        with patch.object(self.server.app.router, "routes", stripped):
            with self.assertRaises(AssertionError):
                self.assert_refused_without_sends(("POST", "/probe-missing-auth"))
        self.assertIn("/api/report", self.site.paths())
        self.assertTrue(self.transport_sends)


# ---------------------------------------------------------------------------
# ARC-2
# ---------------------------------------------------------------------------

def _old_default_standalone(real):
    def standalone(*args, **kwargs):
        return real(*args, **{**kwargs, "active_mode": False})
    return standalone


class ActiveProbeEmptyScopeTests(_AdmissionFixture):
    """/active-probe with the agent enabled and server.allowed_hosts=[]."""

    def setUp(self):
        super().setUp()
        self.arm(True)
        self.server.orchestrator.allowed_hosts = []
        self.agent_sends: list[tuple] = []

        async def model_run(agent, exchange, hypothesis, specialty, **kwargs):
            # The model's first move: re-send the captured request through the
            # agent's own send path (its run's TargetTransport).
            self.agent_sends.append(await agent._execute("GET", exchange.url, {}, None))
            return iterative_agent.IterativeResult(agent=f"iterative:{specialty}", stop_reason="gave_up")
        model = patch.object(iterative_agent.IterativeAgent, "run", model_run)
        model.start()
        self.addCleanup(model.stop)

    def _probe(self):
        return self.client.post("/active-probe", json={
            "exchange": self.exchange(), "hypothesis": "idor on report id", "specialty": "idor"})

    def _layers(self, *, route=True, orchestrator=True, active_default=True, probe_gate=True):
        from harness import orchestrator_confirm
        patches = []
        if not probe_gate:
            # ARC-11: the pre-fix gate -- the process-wide default, seeded from
            # server.allowed_hosts at startup -- instead of the probe's own gate,
            # which is scoped to the orchestrator's (here empty) hosts.
            patches.append(patch.object(orchestrator_confirm.ConfirmMixin, "_standalone_probe_gate",
                                        lambda self: safety_gate.get_default_gate()))
        if not route:
            patches.append(patch.object(self.server, "_require_active_scope", lambda *a, **k: None))
        if not orchestrator:
            patches.append(patch.object(orchestrator_confirm, "_require_standalone_probe_scope",
                                        lambda *a, **k: None))
        if not active_default:
            patches.append(patch.object(run_context, "standalone_context",
                                        _old_default_standalone(run_context.standalone_context)))
        return patches

    def _run(self, **layers):
        patches = self._layers(**layers)
        for p in patches:
            p.start()
        try:
            return self._probe()
        finally:
            for p in reversed(patches):
                p.stop()

    def test_empty_scope_refuses_with_zero_sends(self):
        response = self._run()
        self.assertEqual(response.status_code, 403, response.text)
        self.assertIn("no server.allowed_hosts configured", response.json()["detail"])
        self.assertEqual(self.agent_sends, [])
        self.assertEqual(self.site.requests, [])
        self.assertEqual(self.transport_sends, [])

    def test_route_admission_alone_refuses(self):
        response = self._run(orchestrator=False, active_default=False)
        self.assertEqual(response.status_code, 403, response.text)
        self.assertEqual(self.agent_sends, [])
        self.assertEqual(self.site.requests, [])

    def test_standalone_probe_admission_alone_refuses(self):
        response = self._run(route=False, active_default=False)
        self.assertEqual(response.status_code, 403, response.text)
        self.assertIn("allowed_hosts", response.json()["detail"])
        self.assertEqual(self.agent_sends, [])
        self.assertEqual(self.site.requests, [])

    def test_active_standalone_default_alone_blocks_the_send(self):
        response = self._run(route=False, orchestrator=False)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(len(self.agent_sends), 1)
        status, reason = self.agent_sends[0]
        self.assertIsNone(status)
        self.assertIn("out of scope", reason)
        self.assertEqual(self.site.requests, [])

    def test_per_call_probe_gate_alone_blocks_the_send(self):
        """ARC-11: the standalone probe's own gate is scoped to the orchestrator's
        hosts, so with every other layer off the empty scope still sends nothing."""
        response = self._run(route=False, orchestrator=False, active_default=False)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(len(self.agent_sends), 1)
        status, reason = self.agent_sends[0]
        self.assertIsNone(status)
        self.assertIn("out of scope", reason)
        self.assertEqual(self.site.requests, [])

    def test_negative_control_old_default_sends_to_the_unscoped_host(self):
        response = self._run(route=False, orchestrator=False, active_default=False,
                             probe_gate=False)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(self.agent_sends[0][0], 200)
        self.assertIn("/api/report", self.site.paths())


class StandaloneContextDefaultTests(unittest.TestCase):
    """standalone_context() is active by default: an empty scope admits nothing."""

    def _in_scope(self, **kwargs) -> bool:
        async def check():
            context = run_context.standalone_context([], **kwargs)
            try:
                return context.scope.in_scope("http://127.0.0.1:8080/api/report")
            finally:
                await context.aclose()
        return asyncio.run(check())

    def test_default_is_active_and_empty_scope_fails_closed(self):
        self.assertIs(inspect.signature(run_context.standalone_context).parameters["active_mode"].default, True)
        self.assertFalse(self._in_scope())

    def test_negative_control_explicit_passive_mode_admits_any_host(self):
        self.assertTrue(self._in_scope(active_mode=False))


if __name__ == "__main__":
    unittest.main()
