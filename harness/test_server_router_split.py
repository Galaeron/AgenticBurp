"""ARC-9 (2026-11-19 principal audit), server part: harness.server split into
router modules (harness/server_routes_*.py), registered on harness.server.app.

Caller level: one route of each router answers through harness.server.app, and an
active route is refused (403) by the shared admission before its handler runs.
Structure: every route of each router is on the app; the endpoint and request-model
names stay readable on harness.server, and a router name that would shadow one of
server's own fails the import; every name a test patches on harness.server is
defined in server.py and read by the routers as srv.<name>, so the patch reaches
the route.
A reload of harness.server keeps the names.
Negative controls: with admission opened the same request reaches the handler; a
router that reads a patched name as its own global is reported; a shadowing name
raises, and so does a reload without the record of the last load's names.

Passive: a temporary store, active mode off; nothing sends target traffic.
"""
from __future__ import annotations

import ast
import importlib
import re
import shutil
import symtable
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from fastapi import HTTPException
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from pydantic import BaseModel

from harness import server_admission, store
from harness.test_orchestrator_split_guard import files_with_tests

HARNESS = Path(__file__).resolve().parent
_HOST = "captured.example"
# How tests name the server module when they patch it.
_SERVER_ALIAS = re.compile(r"(^|\.)(server|server_module|server_mod|srv|harness_server)$")


class _ServerFixture(unittest.TestCase):
    def setUp(self):
        import harness.server as server
        self.server = server
        tmp = tempfile.mkdtemp(prefix="arc9_routers_")
        self.addCleanup(shutil.rmtree, tmp, True)
        self.addCleanup(setattr, store, "_DB_PATH", store._DB_PATH)
        store._DB_PATH = Path(tmp) / "state.db"
        registry = server.orchestrator.validator_registry
        self.addCleanup(registry.set_active_enabled, registry.active_enabled)
        registry.set_active_enabled(False)
        self.client = TestClient(server.app, base_url="http://localhost",
                                 headers={"Authorization": f"Bearer {server._mutation_token()}"})
        self.addCleanup(self.client.close)

    def served_by(self, method: str, path: str) -> str:
        """The router module whose endpoint the app routes `method path` to."""
        for route in self.server.app.routes:
            if isinstance(route, APIRoute) and route.path == path and method in route.methods:
                return route.endpoint.__module__
        self.fail(f"no route {method} {path}")


class RouterCallerTests(_ServerFixture):
    """One route of each router, called through harness.server.app."""

    def test_admin_router(self):
        self.assertEqual(self.served_by("GET", "/health"), "harness.server_routes_admin")
        response = self.client.get("/health")
        self.assertEqual((response.status_code, response.json()), (200, {"status": "ok"}))

    def test_ingest_router(self):
        self.assertEqual(self.served_by("GET", "/tools"), "harness.server_routes_ingest")
        response = self.client.get("/tools")
        self.assertEqual(response.status_code, 200, response.text)
        self.assertIn("by_category", response.json())

    def test_engagement_router(self):
        self.assertEqual(self.served_by("GET", "/engagement/{host}"), "harness.server_routes_engagement")
        response = self.client.get(f"/engagement/{_HOST}")
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["host"], _HOST)

    def test_reports_router(self):
        self.assertEqual(self.served_by("GET", "/report"), "harness.server_routes_reports")
        response = self.client.get("/report", params={"url": f"https://{_HOST}/"})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertTrue(response.headers["content-type"].startswith("text/markdown"))
        self.assertIn(_HOST, response.text)

    def test_investigate_router_reads_the_shared_job_state(self):
        """The router lists the jobs held in harness.server._INVESTIGATE_JOBS."""
        self.assertEqual(self.served_by("GET", "/engagement/{host}/investigate"),
                         "harness.server_routes_investigate")
        self.assertEqual(self.client.get(f"/engagement/{_HOST}/investigate").json(),
                         {"host": _HOST, "jobs": []})
        job = {"job_id": "arc9-job", "host": _HOST, "base_url": f"https://{_HOST}/",
               "status": "running", "started_at": time.time(), "finished_at": None,
               "error": None, "result": None}
        with patch.dict(self.server._INVESTIGATE_JOBS, {"arc9-job": job}):
            listed = self.client.get(f"/engagement/{_HOST}/investigate")
        self.assertEqual(listed.status_code, 200, listed.text)
        self.assertEqual([j["job_id"] for j in listed.json()["jobs"]], ["arc9-job"])
        self.assertEqual(self.client.get(f"/engagement/{_HOST}/investigate/arc9-job").status_code, 404)

    def test_data_router_wipe_stays_off_by_default(self):
        """The wipe route reads harness.server._WIPE_ENDPOINT_ENABLED, which ships false."""
        self.assertEqual(self.served_by("DELETE", "/engagement/{host}/evidence"),
                         "harness.server_routes_data")
        self.assertFalse(self.server._WIPE_ENDPOINT_ENABLED)
        response = self.client.delete(f"/engagement/{_HOST}/evidence")
        self.assertEqual(response.status_code, 403, response.text)
        self.assertIn("wipe endpoint disabled", response.json()["detail"])
        with patch.object(self.server, "_WIPE_ENDPOINT_ENABLED", True), \
                patch.object(store, "wipe_engagement", return_value={"host": _HOST}) as wipe:
            armed = self.client.delete(f"/engagement/{_HOST}/evidence")
        self.assertNotIn("wipe endpoint disabled", armed.text)
        wipe.assert_called_once()

    def test_active_router_route_refused_without_admission(self):
        """/crawl with active mode off: 403 from the shared dependency, and the
        handler's own scope checks never run."""
        self.assertEqual(self.served_by("POST", "/crawl"), "harness.server_routes_active")
        body = {"base_url": f"https://{_HOST}/", "max_pages": 1}
        scope = Mock(side_effect=HTTPException(status_code=409, detail="synthetic scope stop"))
        with patch.object(self.server, "_require_target_fetch", Mock()) as fetch, \
                patch.object(self.server, "_require_active_scope", scope):
            refused = self.client.post("/crawl", json=body)
            self.assertEqual(refused.status_code, 403, refused.text)
            self.assertIn("active operations are disabled", refused.json()["detail"])
            fetch.assert_not_called()
            scope.assert_not_called()
            # Control: with the master switch opened the handler runs, reads the
            # patched server helpers, and stops at the synthetic scope refusal.
            with patch.object(server_admission, "_admit_active_traffic", lambda orchestrator: None):
                admitted = self.client.post("/crawl", json=body)
        self.assertEqual(admitted.status_code, 409, admitted.text)
        fetch.assert_called_once()
        scope.assert_called_once()

    def test_active_route_authenticates_before_admission(self):
        response = self.client.post("/crawl", json={"base_url": f"https://{_HOST}/"},
                                    headers={"Authorization": "Bearer synthetic-wrong-token"})
        self.assertEqual(response.status_code, 401, response.text)


class RouterStructureTests(unittest.TestCase):
    def setUp(self):
        import harness.server as server
        self.server = server

    def router_routes(self) -> dict:
        return {module.__name__: {(tuple(sorted(r.methods)), r.path, r.endpoint.__name__)
                                  for r in module.build_router(self.server).routes}
                for module in self.server.ROUTER_MODULES}

    def test_every_router_route_is_on_the_app(self):
        on_app: dict = {}
        for route in self.server.app.routes:
            if isinstance(route, APIRoute):
                on_app.setdefault(route.endpoint.__module__, set()).add(
                    (tuple(sorted(route.methods)), route.path, route.endpoint.__name__))
        self.assertEqual(on_app, self.router_routes())
        for name, routes in on_app.items():
            self.assertTrue(routes, name)

    def exported(self) -> dict:
        names = {}
        for route in self.server.app.routes:
            if isinstance(route, APIRoute):
                names[route.endpoint.__name__] = route.endpoint
        for module in self.server.ROUTER_MODULES:
            for name, obj in vars(module).items():
                if isinstance(obj, type) and issubclass(obj, BaseModel) and obj.__module__ == module.__name__:
                    names[name] = obj
        return names

    def test_endpoint_and_model_names_stay_readable_on_server(self):
        exported = self.exported()
        for name in ("engagement_investigate", "engagement_investigate_cancel", "get_settings",
                     "update_settings", "InvestigateRequest", "SettingsRequest", "_ValidatorToggles"):
            self.assertIn(name, exported)
        for name, obj in exported.items():
            self.assertIs(getattr(self.server, name), obj, name)

    def test_negative_control_a_shadowing_router_name_raises(self):
        exported = self.exported()
        for name in exported:
            delattr(self.server, name)
        try:
            self.assertEqual(self.server._router_names(), exported)
            # Set through vars(): the patch-target scan below would (rightly) report
            # a plain `server.health = ...` as a patch that reaches no route.
            vars(self.server)["health"] = object()
            with self.assertRaisesRegex(RuntimeError, "'health' is not unique"):
                self.server._router_names()
        finally:
            for name, obj in exported.items():
                setattr(self.server, name, obj)
        self.assertIs(self.server.health, exported["health"])

    def test_reload_keeps_the_router_names(self):
        """importlib.reload(harness.server), which several tests do, runs the module
        again in its old namespace; the names the last load exported are dropped
        first, so they do not count as collisions. Negative control: without that
        record the reload fails on the first exported name."""
        importlib.reload(self.server)
        exported = self.exported()
        self.assertEqual(set(self.server._ROUTER_EXPORTS), set(exported))
        for name, obj in exported.items():
            self.assertIs(getattr(self.server, name), obj, name)
        names = self.server._ROUTER_EXPORTS
        del vars(self.server)["_ROUTER_EXPORTS"]
        try:
            with self.assertRaisesRegex(RuntimeError, "is not unique in harness.server"):
                importlib.reload(self.server)
        finally:
            vars(self.server)["_ROUTER_EXPORTS"] = names
            importlib.reload(self.server)
        self.assertIs(self.server.health, self.exported()["health"])


def _server_patch_targets() -> dict[str, list[str]]:
    """Names tests patch or assign on harness.server -> where."""
    found: dict[str, list[str]] = {}
    for path in files_with_tests():
        source = path.read_text(encoding="utf-8-sig")
        if "server" not in source:
            continue
        for node in ast.walk(ast.parse(source)):
            name = None
            if isinstance(node, ast.Call):
                fn = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", "")
                args = node.args
                if (fn in ("object", "setattr") and len(args) >= 2 and isinstance(args[1], ast.Constant)
                        and isinstance(args[1].value, str) and _SERVER_ALIAS.search(ast.unparse(args[0]))):
                    name = args[1].value
                elif (fn == "patch" and args and isinstance(args[0], ast.Constant)
                      and isinstance(args[0].value, str) and args[0].value.startswith("harness.server.")):
                    name = args[0].value.split(".")[2]
            elif isinstance(node, (ast.Assign, ast.AugAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for target in targets:
                    if isinstance(target, ast.Attribute) and _SERVER_ALIAS.search(ast.unparse(target.value)):
                        name = target.attr
            if name:
                found.setdefault(name, []).append(f"{path.name}:{node.lineno}")
    return found


def _module_bindings(source: str) -> set[str]:
    """Names bound at the top level of a module source."""
    names = set()
    for node in ast.parse(source).body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            names.update(n.id for t in targets for n in ast.walk(t) if isinstance(n, ast.Name))
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            names.update((a.asname or a.name).split(".")[0] for a in node.names)
    return names


def _own_reads(source: str, names: set[str], filename: str) -> list[str]:
    """`names` a router binds or reads as its own module global (or builtin) rather
    than through `srv`: the server patch would then not reach that read."""
    problems = [f"{filename} binds {name}" for name in sorted(names & _module_bindings(source))]

    def walk(table):
        if table.get_type() != "module":
            for symbol in table.get_symbols():
                if symbol.get_name() in names and symbol.is_referenced() and symbol.is_global():
                    problems.append(f"{filename}:{table.get_name()} reads {symbol.get_name()}")
        for child in table.get_children():
            walk(child)
    walk(symtable.symtable(source, filename, "exec"))
    return problems


class ServerPatchTargetTests(unittest.TestCase):
    """A patch of harness.server.<name> must reach the routes that use it."""

    def setUp(self):
        self.targets = _server_patch_targets()
        self.server_source = (HARNESS / "server.py").read_text(encoding="utf-8")

    def test_the_scan_finds_the_known_patches(self):
        for name in ("orchestrator", "_WIPE_ENDPOINT_ENABLED", "_require_active_scope",
                     "_update_engagement", "surface_prioritizer"):
            self.assertIn(name, self.targets)

    def test_patched_names_are_defined_in_server(self):
        import harness.server as server
        routers = {m.__name__ for m in server.ROUTER_MODULES}
        defined = _module_bindings(self.server_source)
        for name, where in sorted(self.targets.items()):
            in_router = any(hasattr(__import__(m, fromlist=["_"]), name) for m in routers)
            if name in defined or not (hasattr(server, name) or in_router):
                continue  # defined here, or not a server name (another object called `server`)
            self.fail(f"{where}: patches harness.server.{name}, which server.py does not define, "
                      f"so the patch does not reach the route")

    def test_routers_read_patched_names_through_srv(self):
        names = set(self.targets) & _module_bindings(self.server_source)
        problems = []
        for path in sorted(HARNESS.glob("server_routes_*.py")):
            problems += _own_reads(path.read_text(encoding="utf-8"), names, path.name)
        self.assertEqual(problems, [])

    def test_negative_control_a_router_reading_its_own_copy_is_reported(self):
        bad = ("from harness.server import _require_auth\n"
               "def build_router(srv, router=None):\n"
               "    def handler(authorization=None):\n"
               "        _require_auth(authorization)\n"
               "        return orchestrator\n"
               "    return router\n")
        good = ("def build_router(srv, router=None):\n"
                "    def handler(authorization=None):\n"
                "        srv._require_auth(authorization)\n"
                "        return srv.orchestrator\n"
                "    return router\n")
        names = {"_require_auth", "orchestrator"}
        self.assertEqual(_own_reads(bad, names, "bad.py"),
                         ["bad.py binds _require_auth", "bad.py:handler reads _require_auth",
                          "bad.py:handler reads orchestrator"])
        self.assertEqual(_own_reads(good, names, "good.py"), [])


if __name__ == "__main__":
    unittest.main()
