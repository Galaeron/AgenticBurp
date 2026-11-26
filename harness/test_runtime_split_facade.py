"""ARC-9 guard for the h3 split: run_context, ollama_client and browser_driver are each a
facade over sibling modules, and a patch on the facade must reach every caller exactly as
when each was one module.

The contract: a sibling ends with `from harness import <facade> as <alias>` and reads, at call
time, every name a test patches on the facade, and every facade name it does not bind itself,
as `<alias>.<name>`. A sibling that copied a name at import (`from harness.run_context import
_clock`) would keep the old object after `patch.object(run_context, "_clock", ...)`. The static
checker (symtable) and the bytecode checker find that shape. The patched-name set is read from
the test suite itself, so a test that starts patching a new name is covered without editing
this file. The reach tests patch each facade name the moved code reads and require the call to
land on the patch; the negative controls feed the checkers and the reach probes a module bound
at import and require them to fail.
"""
from __future__ import annotations

import ast
import asyncio
import builtins
import dis
import importlib
import inspect
import os
import re
import subprocess
import sys
import symtable
import types
import unittest
from pathlib import Path
from unittest.mock import patch

import httpx

from harness import browser_driver, ollama_client, run_context

HARNESS = Path(__file__).resolve().parent
REPO = HARNESS.parent
FACADES = {
    "run_context": ("_rc", ("run_context_sessions", "run_context_requests", "run_context_destination")),
    "ollama_client": ("_oc", ("ollama_client_errors", "ollama_client_context", "ollama_client_wire")),
    "browser_driver": ("_bd", ("browser_driver_router", "browser_driver_uploads")),
}
# What the test suite patched on each facade when the split landed; the live scan must
# still find at least these (a check that the scan itself works).
KNOWN_PATCHED = {
    "run_context": {"TRANSPORT_CONTROLLED_HEADERS", "_clock", "_default_resolver",
                    "_drop_transport_controlled", "_pinned_backend", "_target_client",
                    "is_credential_header", "is_identity_credential_header",
                    "standalone_context", "transport_for"},
    "ollama_client": {"MAX_TIMEOUT_RETRIES", "OllamaTransientError", "_CONTEXT_PROBE_RETRY_SECONDS",
                      "_DROPPED_CONNECTION_ERRORS", "_MAX_TRANSIENT_RETRIES", "_backoff_sleep",
                      "_cancellation_requested", "_is_transient_status", "_strip_inline_thinking"},
    "browser_driver": {"_MAX_SCRIPT_BODIES", "_ROUTE_DRAIN_SECONDS", "_SCRIPT_BYTES_TOTAL",
                       "_same_cookie_host", "available", "default_driver", "playwright_available"},
}
BUILTINS = set(dir(builtins))


def _source(name: str) -> str:
    return (HARNESS / f"{name}.py").read_text(encoding="utf-8-sig")


def alias_import(facade: str) -> str:
    return f"from harness import {facade} as {FACADES[facade][0]}"


def top_level_definitions(source: str) -> set[str]:
    """Names a module defines itself (def, class, assignment); imports excluded."""
    names = set()
    for st in ast.parse(source).body:
        if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(st.name)
        elif isinstance(st, (ast.Assign, ast.AnnAssign)):
            for t in (st.targets if isinstance(st, ast.Assign) else [st.target]):
                names.update(n.id for n in ast.walk(t) if isinstance(n, ast.Name))
    return names


def runtime_bindings(source: str) -> set[str]:
    """Names a module binds when it runs: definitions and imports, minus the
    `if TYPE_CHECKING:` block (annotation-only)."""
    names = top_level_definitions(source)
    for st in ast.parse(source).body:
        if isinstance(st, (ast.Import, ast.ImportFrom)):
            names.update(a.asname or a.name.split(".")[0] for a in st.names)
    return names


# ---------------------------------------------------------------------------
# The patched-name scan: every module attribute the test suite replaces on a facade
# ---------------------------------------------------------------------------

def _module_aliases(tree: ast.AST, facade: str) -> set[str]:
    names = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.ImportFrom) and n.module == "harness":
            names.update(a.asname or a.name for a in n.names if a.name == facade)
        elif isinstance(n, ast.Import):
            names.update(a.asname for a in n.names if a.name == f"harness.{facade}" and a.asname)
    return names


def patched_in(source: str, facade: str) -> set[str]:
    """Facade attributes one test module replaces: `patch("harness.<facade>.<name>")`,
    `patch.object(<facade>, "<name>")`, `setattr(<facade>, "<name>", ...)` and
    `<facade>.<name> = ...`. A deeper path (`harness.run_context.TargetTransport.execute`)
    replaces an attribute of a shared object, not a module binding, so it is not counted."""
    tree = ast.parse(source)
    aliases = _module_aliases(tree, facade)
    dotted = re.compile(rf"^harness\.{facade}\.(\w+)$")
    found = set()

    def is_module(node) -> bool:
        if isinstance(node, ast.Name):
            return node.id in aliases
        return ast.unparse(node) == f"harness.{facade}"

    for n in ast.walk(tree):
        if isinstance(n, ast.Constant) and isinstance(n.value, str):
            m = dotted.match(n.value)
            if m:
                found.add(m.group(1))
        elif isinstance(n, ast.Call) and len(n.args) >= 2 and isinstance(n.args[1], ast.Constant):
            fn = ast.unparse(n.func)
            if ((fn.endswith("patch.object") or fn == "setattr" or fn.endswith(".setattr"))
                    and is_module(n.args[0]) and isinstance(n.args[1].value, str)):
                found.add(n.args[1].value)
        elif isinstance(n, (ast.Assign, ast.AugAssign)):
            for t in (n.targets if isinstance(n, ast.Assign) else [n.target]):
                if isinstance(t, ast.Attribute) and is_module(t.value):
                    found.add(t.attr)
    return found


_PATCHED_CACHE: dict[str, set[str]] = {}


def patched_names(facade: str) -> set[str]:
    if facade not in _PATCHED_CACHE:
        names = set()
        roots = [HARNESS, REPO / "testing", REPO / "evaluation_integrity"]
        for path in sorted(p for root in roots if root.is_dir() for p in root.rglob("test_*.py")
                           if "__pycache__" not in p.parts):
            text = path.read_text(encoding="utf-8-sig", errors="ignore")
            if facade not in text:
                continue
            try:
                names |= patched_in(text, facade)
            except SyntaxError:
                continue
        _PATCHED_CACHE[facade] = names
    return _PATCHED_CACHE[facade]


# ---------------------------------------------------------------------------
# The contract checkers
# ---------------------------------------------------------------------------

def facade_violations(source: str, facade: str, patched: set[str]) -> list[str]:
    """What breaks the facade contract in one sibling's source:
    - a function or class body that reads a patched name bare, or a name the sibling
      does not bind itself (it lives on the facade), or declares `global`;
    - a runtime import of the facade or of another sibling, other than the bound-last
      alias import;
    - an alias import that is not the sibling's last statement."""
    alias, siblings = FACADES[facade]
    problems = []
    tree = ast.parse(source)
    binds = runtime_bindings(source)

    def walk(table, prefix=""):
        for child in table.get_children():
            qual = f"{prefix}{child.get_name()}"
            for sym in child.get_symbols():
                name = sym.get_name()
                if sym.is_declared_global():
                    problems.append(f"{qual}: `global {name}` (rebind it on the facade)")
                elif sym.is_global() and sym.is_referenced():
                    if name in patched:
                        problems.append(f"{qual}: reads patched {name} bare, not as {alias}.{name}")
                    elif name not in binds and name not in BUILTINS:
                        problems.append(f"{qual}: reads {name}, which it does not bind (use {alias}.{name})")
            walk(child, f"{qual}.")
    walk(symtable.symtable(source, "<sibling>", "exec"))

    guarded = {id(n) for st in tree.body if isinstance(st, ast.If) and ast.unparse(st.test) == "TYPE_CHECKING"
               for n in ast.walk(st)}
    own = {f"harness.{facade}"} | {f"harness.{s}" for s in siblings}
    for n in ast.walk(tree):
        if id(n) in guarded:
            continue
        if isinstance(n, ast.ImportFrom) and n.module in own:
            problems.append(f"line {n.lineno}: from {n.module} import (binds facade names at import)")
        elif isinstance(n, ast.ImportFrom) and n.module == "harness":
            for a in n.names:
                if a.name in siblings or (a.name == facade and ast.unparse(n) != alias_import(facade)):
                    problems.append(f"line {n.lineno}: {ast.unparse(n)}")
        elif isinstance(n, ast.Import):
            for a in n.names:
                if a.name in own:
                    problems.append(f"line {n.lineno}: import {a.name}")
    if not tree.body or ast.unparse(tree.body[-1]) != alias_import(facade):
        problems.append(f"the last statement must be `{alias_import(facade)}` (import order)")
    elif sum(ast.unparse(st) == alias_import(facade) for st in tree.body) != 1:
        problems.append(f"`{alias_import(facade)}` appears more than once")
    return problems


def missing_on_facade(source: str, facade: str, module) -> list[str]:
    """`<alias>.<name>` reads of a name the facade does not have (a typo or an unexported name)."""
    alias = FACADES[facade][0]
    return sorted({n.attr for n in ast.walk(ast.parse(source))
                   if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name)
                   and n.value.id == alias and not hasattr(module, n.attr)})


def _code_objects(module) -> list[types.CodeType]:
    """Every code object a module's functions and methods run (nested ones included)."""
    seen, out = set(), []

    def add(code):
        if id(code) in seen:
            return
        seen.add(id(code))
        out.append(code)
        for const in code.co_consts:
            if isinstance(const, types.CodeType):
                add(const)

    def visit(obj, depth=0):
        if isinstance(obj, (staticmethod, classmethod)):
            obj = obj.__func__
        if isinstance(obj, property):
            for f in (obj.fget, obj.fset, obj.fdel):
                if f is not None:
                    visit(f, depth)
            return
        if isinstance(obj, types.FunctionType) and obj.__module__ == module.__name__:
            # A decorated function (contextlib.contextmanager) keeps its own body in
            # __wrapped__; the wrapper's code is the decorator's, not this module's.
            add(inspect.unwrap(obj).__code__)
        elif isinstance(obj, type) and obj.__module__ == module.__name__ and depth < 3:
            for v in vars(obj).values():
                visit(v, depth + 1)
    for v in list(vars(module).values()):
        visit(v)
    return out


def bare_global_loads(module, names: set[str]) -> list[str]:
    """(code name, global) pairs where a module's own code loads one of `names` as a
    global -- from its own namespace, where a facade patch never lands."""
    hits = set()
    for code in _code_objects(module):
        for ins in dis.get_instructions(code):
            if ins.opname in ("LOAD_GLOBAL", "LOAD_NAME") and ins.argval in names:
                hits.add(f"{code.co_qualname}: {ins.argval}")
    return sorted(hits)


def synthetic_module(source: str, name: str = "synthetic_sibling") -> types.ModuleType:
    module = types.ModuleType(name)
    exec(compile(source, f"<{name}>", "exec"), module.__dict__)
    return module


BOUND_AT_IMPORT = ("from harness.run_context import _clock, _default_resolver\n\n"
                   "def now():\n    return _clock()\n\n"
                   "def resolver():\n    return _default_resolver\n")
READ_THROUGH_FACADE = ("def now():\n    return _rc._clock()\n\n"
                       "def resolver():\n    return _rc._default_resolver\n\n"
                       "from harness import run_context as _rc  # noqa: E402\n")


# ---------------------------------------------------------------------------
# Shape
# ---------------------------------------------------------------------------

class FacadeShapeTests(unittest.TestCase):
    def test_every_sibling_definition_is_the_same_object_on_the_facade(self):
        for facade, (_alias, siblings) in FACADES.items():
            module = importlib.import_module(f"harness.{facade}")
            for sib in siblings:
                sibling = importlib.import_module(f"harness.{sib}")
                for name in sorted(top_level_definitions(_source(sib))):
                    with self.subTest(sibling=sib, name=name):
                        self.assertTrue(hasattr(module, name), "the facade must re-export it")
                        self.assertIs(getattr(module, name), getattr(sibling, name))

    def test_no_name_is_defined_twice(self):
        for facade, (_alias, siblings) in FACADES.items():
            seen = {name: facade for name in top_level_definitions(_source(facade))}
            for sib in siblings:
                for name in top_level_definitions(_source(sib)):
                    self.assertNotIn(name, seen, f"{name} defined in {seen.get(name)} and {sib}")
                    seen[name] = sib

    def test_every_patched_name_is_still_a_facade_attribute(self):
        for facade in FACADES:
            module = importlib.import_module(f"harness.{facade}")
            for name in sorted(patched_names(facade)):
                with self.subTest(facade=facade, name=name):
                    self.assertTrue(hasattr(module, name))

    def test_the_patched_name_scan_finds_the_known_patches(self):
        for facade, known in KNOWN_PATCHED.items():
            with self.subTest(facade=facade):
                self.assertEqual(known - patched_names(facade), set())

    def test_the_scan_reads_each_patch_form(self):
        source = ("from harness import run_context as rc\nimport harness.ollama_client as oc\n"
                  "from unittest import mock\n"
                  "mock.patch('harness.run_context.a_string')\n"
                  "mock.patch('harness.run_context.Klass.method')\n"
                  "mock.patch.object(rc, 'an_object')\n"
                  "setattr(rc, 'a_setattr', 1)\n"
                  "monkeypatch.setattr(rc, 'a_monkeypatch', 1)\n"
                  "rc.an_assignment = 2\n"
                  "oc.not_this_facade = 3\n")
        self.assertEqual(patched_in(source, "run_context"),
                         {"a_string", "an_object", "a_setattr", "a_monkeypatch", "an_assignment"})

    def test_siblings_keep_the_contract(self):
        for facade, (_alias, siblings) in FACADES.items():
            patched = patched_names(facade)
            for sib in siblings:
                with self.subTest(sibling=sib):
                    self.assertEqual(facade_violations(_source(sib), facade, patched), [])

    def test_every_facade_read_names_a_facade_attribute(self):
        for facade, (_alias, siblings) in FACADES.items():
            module = importlib.import_module(f"harness.{facade}")
            for sib in siblings:
                with self.subTest(sibling=sib):
                    self.assertEqual(missing_on_facade(_source(sib), facade, module), [])

    def test_no_sibling_code_loads_a_patched_name_as_a_global(self):
        # The runtime counterpart of the symtable check: the compiled code itself.
        for facade, (_alias, siblings) in FACADES.items():
            patched = patched_names(facade)
            for sib in siblings:
                sibling = importlib.import_module(f"harness.{sib}")
                with self.subTest(sibling=sib):
                    self.assertTrue(_code_objects(sibling), "no code found to check")
                    self.assertEqual(bare_global_loads(sibling, patched), [])

    def test_callers_outside_the_facades_never_import_a_sibling(self):
        # A caller that imported harness.run_context_sessions (etc.) directly would bind the
        # sibling's objects, not the facade's, and bypass a facade patch.
        siblings = {s for _a, sibs in FACADES.values() for s in sibs}
        skip = siblings | set(FACADES)
        offenders = []
        roots = [HARNESS, REPO / "testing", REPO / "evaluation_integrity"]
        for path in sorted(p for root in roots if root.is_dir() for p in root.rglob("*.py")):
            if "__pycache__" in path.parts or path.name.startswith("test_") or path.stem in skip:
                continue
            try:
                tree = ast.parse(path.read_text(encoding="utf-8-sig"))
            except (SyntaxError, UnicodeDecodeError):
                continue
            for n in ast.walk(tree):
                mods = ([n.module or ""] + [f"{n.module}.{a.name}" for a in n.names] if isinstance(n, ast.ImportFrom)
                        else [a.name for a in n.names] if isinstance(n, ast.Import) else [])
                if any(m.removeprefix("harness.") in siblings for m in mods if m.startswith("harness.")):
                    offenders.append(f"{path.relative_to(REPO).as_posix()}:{n.lineno}")
        self.assertEqual(offenders, [])

    def test_each_sibling_imports_first_in_a_fresh_interpreter(self):
        env = {k: v for k, v in os.environ.items() if k != "HARNESS_ENGAGEMENT_ID"}
        env["PYTHONPATH"] = str(REPO)
        for facade, (alias, siblings) in FACADES.items():
            for sib in siblings:
                names = sorted(top_level_definitions(_source(sib)))
                code = (f"import harness.{sib} as s, sys; f = sys.modules['harness.{facade}']; "
                        f"assert s.{alias} is f, 'alias not bound to the facade'; "
                        f"assert all(getattr(f, n) is getattr(s, n) for n in {names!r}), 'incomplete facade'")
                with self.subTest(sibling=sib):
                    proc = subprocess.run([sys.executable, "-c", code], cwd=REPO, env=env,
                                          capture_output=True, text=True, timeout=120)
                    self.assertEqual(proc.returncode, 0, proc.stderr[-2000:])


class ContractCheckerNegativeControls(unittest.TestCase):
    """The checkers must flag each way a sibling can bind a facade name at import."""

    def check(self, source, facade="run_context"):
        return facade_violations(source, facade, patched_names(facade))

    def test_an_import_bound_copy_is_flagged(self):
        found = self.check(BOUND_AT_IMPORT + f"\n{alias_import('run_context')}\n")
        self.assertTrue(any("from harness.run_context import" in p for p in found), found)
        self.assertTrue(any("reads patched _clock bare" in p for p in found), found)

    def test_a_local_copy_of_a_patched_name_is_flagged(self):
        found = self.check(f"_clock = None\n\ndef f():\n    return _clock()\n\n{alias_import('run_context')}\n")
        self.assertTrue(any("reads patched _clock bare" in p for p in found), found)

    def test_a_global_rebinding_is_flagged(self):
        found = self.check(f"def f(c):\n    global _clock\n    _clock = c\n\n{alias_import('run_context')}\n")
        self.assertTrue(any("`global _clock`" in p for p in found), found)

    def test_a_facade_import_at_the_top_is_flagged(self):
        found = self.check(f"{alias_import('run_context')}\n\ndef f():\n    return _rc._clock()\n")
        self.assertTrue(any("last statement" in p for p in found), found)

    def test_importing_another_sibling_is_flagged(self):
        found = self.check(f"from harness.run_context_sessions import SessionManager\n\n"
                           f"def f():\n    return SessionManager()\n\n{alias_import('run_context')}\n")
        self.assertTrue(any("from harness.run_context_sessions import" in p for p in found), found)

    def test_a_real_sibling_mutated_back_to_a_bare_patched_read_is_flagged(self):
        source = _source("run_context_destination")
        self.assertIn("resolver or _rc._default_resolver", source)
        found = self.check(source.replace("resolver or _rc._default_resolver", "resolver or _default_resolver", 1))
        self.assertEqual(found, ["AddressPins.__init__: reads patched _default_resolver bare, "
                                 "not as _rc._default_resolver"])

    def test_a_real_sibling_mutated_to_read_a_facade_only_name_bare_is_flagged(self):
        source = _source("browser_driver_uploads")
        self.assertIn("_bd._with_identity(", source)
        found = self.check(source.replace("_bd._with_identity(", "_with_identity(", 1), "browser_driver")
        self.assertEqual(len(found), 1, found)
        self.assertIn("reads _with_identity, which it does not bind", found[0])

    def test_the_read_through_form_passes(self):
        self.assertEqual(self.check(READ_THROUGH_FACADE), [])

    def test_an_unexported_facade_read_is_flagged(self):
        self.assertEqual(missing_on_facade("def f():\n    return _rc._no_such_name\n", "run_context", run_context),
                         ["_no_such_name"])

    def test_the_bytecode_check_sees_a_bare_load(self):
        bound = synthetic_module(BOUND_AT_IMPORT)
        self.assertEqual(bare_global_loads(bound, {"_clock", "_default_resolver"}),
                         ["now: _clock", "resolver: _default_resolver"])
        self.assertEqual(bare_global_loads(synthetic_module(READ_THROUGH_FACADE), {"_clock", "_default_resolver"}),
                         [])

    def test_the_bytecode_check_sees_inside_a_decorated_function(self):
        bound = synthetic_module("import contextlib\n\n@contextlib.contextmanager\n"
                                 "def scope():\n    yield _clock()\n")
        self.assertEqual(bare_global_loads(bound, {"_clock"}), ["scope: _clock"])


# ---------------------------------------------------------------------------
# Reach: each facade name the moved code reads, patched on the facade
# ---------------------------------------------------------------------------

class RunContextReachTests(unittest.TestCase):
    def test_clock_patch_reaches_the_route_circuit(self):
        health = run_context.TransportHealth()
        key = health.route_key("GET", "http://app.test/api/x")
        with patch.object(run_context, "_clock", return_value=1000.0):
            health.route_observed(key, 500, threshold=1)
        self.assertEqual(health._routes[key].opened_at, 1000.0)
        with patch.object(run_context, "_clock", return_value=1005.0):
            self.assertTrue(health.route_blocked(key, cooldown=10.0))
        with patch.object(run_context, "_clock", return_value=1011.0):
            self.assertFalse(health.route_blocked(key, cooldown=10.0), "the half-open probe is admitted")

    def test_clock_negative_control_a_module_bound_at_import_misses_the_patch(self):
        bound, through = synthetic_module(BOUND_AT_IMPORT), synthetic_module(READ_THROUGH_FACADE)
        with patch.object(run_context, "_clock", return_value=-1.0):
            self.assertNotEqual(bound.now(), -1.0)
            self.assertEqual(through.now(), -1.0)

    def test_identity_header_patch_reaches_bind_headers(self):
        sessions = run_context.SessionManager()
        sessions.register("s1", "alice", {"Authorization": "Bearer a"},
                          allowed_origins={"http://app.test"})
        self.assertEqual(sessions.bind_headers({"Authorization": "Bearer a"}), ("s1", {}))
        with patch.object(run_context, "is_identity_credential_header", return_value=False) as mock:
            self.assertEqual(sessions.bind_headers({"Authorization": "Bearer a"}),
                             (None, {"Authorization": "Bearer a"}))
        self.assertTrue(mock.called)

    def test_target_client_patch_reaches_the_session_client(self):
        sentinel = object()
        session = run_context.ManagedSession("s1", "alice")
        with patch.object(run_context, "_target_client", return_value=sentinel) as mock:
            self.assertIs(session.client(5.0), sentinel)
        self.assertTrue(mock.called)

    def test_default_resolver_patch_reaches_address_pins(self):
        def fake(host):
            return "10.9.8.7"
        with patch.object(run_context, "_default_resolver", fake):
            pins = run_context.AddressPins()
            self.assertIs(pins.resolver, fake)
            self.assertEqual(asyncio.run(pins.address_for("app.test")), "10.9.8.7")
        self.assertEqual(pins.pinned(), {"app.test": "10.9.8.7"})

    def test_default_resolver_negative_control_a_module_bound_at_import_misses_the_patch(self):
        bound, through = synthetic_module(BOUND_AT_IMPORT), synthetic_module(READ_THROUGH_FACADE)
        marker = object()
        with patch.object(run_context, "_default_resolver", marker):
            self.assertIsNot(bound.resolver(), marker)
            self.assertIs(through.resolver(), marker)

    def test_pinned_backend_patch_reaches_the_target_client(self):
        pins = run_context.AddressPins(resolver=lambda host: "10.9.8.7")
        with patch.object(run_context, "_pinned_backend", wraps=run_context._pinned_backend) as mock:
            client = run_context._target_client(verify=False, timeout=1.0, http2=False, pins=pins)
        try:
            mock.assert_called_once_with(pins)
        finally:
            asyncio.run(client.aclose())


class _FakeRoute:
    def __init__(self):
        self.fulfilled = None
        self.aborted = False

    async def fulfill(self, **kwargs):
        self.fulfilled = kwargs

    async def abort(self):
        self.aborted = True


class _FakeRequest:
    def __init__(self, url, resource_type="script"):
        self.url, self.method, self.resource_type = url, "GET", resource_type
        self.headers, self.post_data_buffer = {}, None

    def is_navigation_request(self):
        return False


class BrowserRouterReachTests(unittest.TestCase):
    URL = "http://app.test/static/app.js"

    def _router(self):
        scope = run_context.ScopePolicy(allowed_hosts=frozenset({"app.test"}))
        router = browser_driver._IdentityRouter(url="http://app.test/", headers=None, scope=scope, cancel=None,
                                                gate=None, budget=None, timeout_s=1.0, label="facade-test")
        router.script_bodies = []

        async def send(url, method, headers, body, hop_cookies):
            return httpx.Response(200, headers={"content-type": "text/javascript", "set-cookie": "app=1"},
                                  content=b"console.log(1)", request=httpx.Request(method, url))
        router._send = send
        return router

    def _fetch(self, router):
        route = _FakeRoute()
        asyncio.run(router._send_and_fulfill(route, _FakeRequest(self.URL), False))
        self.assertIsNotNone(route.fulfilled)
        return route.fulfilled

    def test_unpatched_the_script_is_kept_and_its_cookie_forwarded(self):
        router = self._router()
        fulfilled = self._fetch(router)
        self.assertEqual(router.script_bodies, ["console.log(1)"])
        self.assertEqual(fulfilled["headers"].get("set-cookie"), "app=1")

    def test_max_script_bodies_patch_reaches_the_router(self):
        router = self._router()
        with patch.object(browser_driver, "_MAX_SCRIPT_BODIES", 0):
            self._fetch(router)
        self.assertEqual(router.script_bodies, [])

    def test_script_bytes_total_patch_reaches_the_router(self):
        router = self._router()
        with patch.object(browser_driver, "_SCRIPT_BYTES_TOTAL", 3):
            self._fetch(router)
        self.assertEqual(router.script_bodies, [])

    def test_same_cookie_host_patch_reaches_the_router(self):
        router = self._router()
        with patch("harness.browser_driver._same_cookie_host", return_value=False) as mock:
            fulfilled = self._fetch(router)
        self.assertTrue(mock.called)
        self.assertNotIn("set-cookie", fulfilled["headers"])


class OllamaFacadeReachTests(unittest.TestCase):
    """The moved ollama code reads no patched name; the patched names that moved are read by
    OllamaClient (still in ollama_client.py) through the facade's own namespace, so a patch on
    the facade replaces exactly the object that code reads."""

    def test_moved_patched_names_are_read_by_facade_code_through_its_namespace(self):
        moved = {n for sib in FACADES["ollama_client"][1] for n in top_level_definitions(_source(sib))}
        names = patched_names("ollama_client") & moved
        self.assertTrue(names)
        readers = {ins.argval for code in _code_objects(ollama_client) for ins in dis.get_instructions(code)
                   if ins.opname in ("LOAD_GLOBAL", "LOAD_NAME")}
        for name in sorted(names):
            with self.subTest(name=name):
                self.assertIn(name, readers, "no facade code reads it; its patch reaches nothing")

    def test_wire_reads_the_error_type_through_the_facade(self):
        from harness import ollama_client_wire
        sentinel = type("PatchedInvalidJSON", (Exception,), {})
        with patch.object(ollama_client, "OllamaInvalidJSONError", sentinel):
            with self.assertRaises(sentinel):
                ollama_client_wire._openai_envelope({"choices": []})


if __name__ == "__main__":
    unittest.main()
