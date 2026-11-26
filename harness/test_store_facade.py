"""ARC-9 guard for the store split: harness.store is a facade over nine repositories, and a patch
on the facade must reach every caller, exactly as when store.py was one module.

The contract (harness/store.py): the facade owns the mutable state; a repository function reads
every store-level name as `_store.<name>` at call time and rebinds state on the facade. A
repository that copied a name at import (`from harness.store import _DB_PATH`) would keep the old
object after `store._DB_PATH = tmp`, and its writes would go to the real harness_state.db. The
static checker finds that shape; the reach tests patch each helper other code patches and require
the call to land on the patch. The negative controls feed both a module that binds at import and
require them to fail.
"""
from __future__ import annotations

import ast
import importlib
import os
import sqlite3
import subprocess
import sys
import symtable
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from harness import evidence_ledger, store
from harness.models import Finding, HttpExchange

HARNESS = Path(__file__).resolve().parent
REPO = HARNESS.parent
REPOSITORIES = ("store_schema", "store_layout", "store_findings", "store_observations", "store_plans",
                "store_proofs", "store_ledger", "store_engagement", "store_maintenance")
FACADE_IMPORT = "from harness import store as _store"


def _source(name: str) -> str:
    return (HARNESS / f"{name}.py").read_text(encoding="utf-8-sig")


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


def facade_state() -> set[str]:
    """The mutable state the facade owns: everything store.py assigns itself."""
    return top_level_definitions(_source("store"))


def store_names() -> set[str]:
    """Every name that lives on the facade: its state plus each repository's definitions."""
    names = facade_state()
    for repo in REPOSITORIES:
        names |= top_level_definitions(_source(repo))
    return names


def _rebound_on_facade(tree: ast.AST) -> set[str]:
    targets = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Assign):
            targets += n.targets
        elif isinstance(n, (ast.AugAssign, ast.AnnAssign)):
            targets.append(n.target)
    return {t.attr for t in targets
            if isinstance(t, ast.Attribute) and isinstance(t.value, ast.Name) and t.value.id == "_store"}


def facade_violations(source: str, names: set[str], state: set[str]) -> list[str]:
    """What breaks the facade contract in one repository's source:
    - a function or class body that reads a store name as a bare global (a copy bound at
      import, or a name that only exists on the facade), or declares `global`;
    - an import of the facade or another repository other than the bound-last facade import;
    - a rebinding through `_store.` of a name that is not facade state;
    - a definition of facade state in the repository."""
    problems = []
    tree = ast.parse(source)

    def walk(table):
        for child in table.get_children():
            for sym in child.get_symbols():
                name = sym.get_name()
                if sym.is_declared_global():
                    problems.append(f"{child.get_name()}: `global {name}` (rebind it as _store.{name})")
                elif sym.is_global() and name in names:
                    problems.append(f"{child.get_name()}: reads {name} bare, not as _store.{name}")
            walk(child)
    walk(symtable.symtable(source, "<repository>", "exec"))

    for n in ast.walk(tree):
        if isinstance(n, ast.ImportFrom) and n.module and (n.module == "harness.store"
                                                          or n.module.startswith("harness.store_")):
            problems.append(f"line {n.lineno}: from {n.module} import (binds store names at import)")
        elif isinstance(n, ast.ImportFrom) and n.module == "harness":
            for a in n.names:
                if a.name.startswith("store_") or (a.name == "store" and ast.unparse(n) != FACADE_IMPORT):
                    problems.append(f"line {n.lineno}: {ast.unparse(n)}")
        elif isinstance(n, ast.Import):
            for a in n.names:
                if a.name == "harness.store" or a.name.startswith("harness.store_"):
                    problems.append(f"line {n.lineno}: import {a.name}")
    if not tree.body or ast.unparse(tree.body[-1]) != FACADE_IMPORT:
        problems.append(f"the last statement must be `{FACADE_IMPORT}` (import order)")
    for name in sorted(_rebound_on_facade(tree) - state):
        problems.append(f"rebinds _store.{name}, which is not facade state")
    for name in sorted(top_level_definitions(source) & state):
        problems.append(f"defines facade state {name}")
    return problems


def missing_on_facade(source: str, facade) -> list[str]:
    """`_store.<name>` reads of a name the facade does not have (a typo or an unexported name)."""
    return sorted({n.attr for n in ast.walk(ast.parse(source))
                   if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name)
                   and n.value.id == "_store" and not hasattr(facade, n.attr)})


def sees_patched_db_path(read_path) -> bool:
    """Whether `read_path()` (the database file a caller would use) follows a patch of
    harness.store._DB_PATH, by both forms tests use: patch.object and plain assignment."""
    with tempfile.TemporaryDirectory() as d:
        target = Path(d) / "patched.db"
        with patch.object(store, "_DB_PATH", target):
            by_patch = Path(read_path()) == target
        original = store._DB_PATH
        store._DB_PATH = target
        try:
            by_assignment = Path(read_path()) == target
        finally:
            store._DB_PATH = original
    return by_patch and by_assignment


def connected_file(connect) -> Path:
    conn = connect()
    try:
        return Path(next(row[2] for row in conn.execute("PRAGMA database_list") if row[1] == "main"))
    finally:
        conn.close()


def call_reaches_patch(name: str, call, **patch_kwargs) -> bool:
    """Patch harness.store.<name>, make the call, and report whether the patch was called."""
    with patch(f"harness.store.{name}", **patch_kwargs) as mock:
        call()
    return mock.called


def synthetic_module(source: str) -> types.ModuleType:
    module = types.ModuleType("synthetic_repository")
    exec(compile(source, "<synthetic_repository>", "exec"), module.__dict__)
    return module


BOUND_AT_IMPORT = ("from pathlib import Path\nfrom harness.store import _DB_PATH, _db_identity\n\n"
                   "def db_path():\n    return Path(_DB_PATH)\n\n"
                   "def identity(conn):\n    return _db_identity(conn)\n")
READ_THROUGH_FACADE = ("from pathlib import Path\n\n"
                       "def db_path():\n    return Path(_store._DB_PATH)\n\n"
                       "def identity(conn):\n    return _store._db_identity(conn)\n\n"
                       "from harness import store as _store  # noqa: E402\n")


def _exchange(**headers) -> HttpExchange:
    return HttpExchange(url="https://example.com/api/users", method="GET", request_headers=dict(headers),
                        request_body="", response_status=200, response_headers={}, response_body="ok")


def _finding() -> Finding:
    return Finding(vulnerability_class="xss", confidence=0.5, summary="s", evidence="e",
                   suggested_test="t", basis="derived")


class FacadeShapeTests(unittest.TestCase):
    def test_every_repository_definition_is_the_same_object_on_the_facade(self):
        for repo in REPOSITORIES:
            module = importlib.import_module(f"harness.{repo}")
            for name in sorted(top_level_definitions(_source(repo))):
                with self.subTest(repo=repo, name=name):
                    self.assertTrue(hasattr(store, name), "the facade must re-export it")
                    self.assertIs(getattr(store, name), getattr(module, name))

    def test_no_name_is_defined_twice(self):
        seen = {name: "store" for name in facade_state()}
        for repo in REPOSITORIES:
            for name in top_level_definitions(_source(repo)):
                self.assertNotIn(name, seen, f"{name} defined in {seen.get(name)} and {repo}")
                seen[name] = repo

    def test_repositories_keep_the_contract(self):
        names, state = store_names(), facade_state()
        problems = {repo: found for repo in REPOSITORIES
                    if (found := facade_violations(_source(repo), names, state))}
        self.assertEqual(problems, {})

    def test_every_facade_read_names_a_facade_attribute(self):
        problems = {repo: found for repo in REPOSITORIES if (found := missing_on_facade(_source(repo), store))}
        self.assertEqual(problems, {})

    def test_callers_outside_the_store_never_import_a_repository(self):
        # A caller that imported harness.store_x directly would bypass every facade patch.
        offenders = []
        roots = [HARNESS, REPO / "testing", REPO / "evaluation_integrity"]
        for path in sorted(p for root in roots if root.is_dir() for p in root.rglob("*.py")):
            if ("__pycache__" in path.parts or path.name.startswith("test_")
                    or path.stem in REPOSITORIES + ("store",)):
                continue
            try:
                tree = ast.parse(path.read_text(encoding="utf-8-sig"))
            except (SyntaxError, UnicodeDecodeError):
                continue   # not importable either, so it cannot bypass a patch
            for n in ast.walk(tree):
                mods = ([n.module or ""] + [f"harness.{a.name}" for a in n.names] if isinstance(n, ast.ImportFrom)
                        else [a.name for a in n.names] if isinstance(n, ast.Import) else [])
                if any(m.startswith("harness.store_") for m in mods):
                    offenders.append(f"{path.relative_to(REPO).as_posix()}:{n.lineno}")
        self.assertEqual(offenders, [])

    def test_each_repository_imports_first_in_a_fresh_interpreter(self):
        env = {k: v for k, v in os.environ.items() if k != "HARNESS_ENGAGEMENT_ID"}
        env["PYTHONPATH"] = str(REPO)
        for repo in REPOSITORIES:
            code = (f"import harness.{repo} as r, sys; s = sys.modules['harness.store']; "
                    f"assert r._store is s and s.persist_findings and s._connect, 'incomplete facade'")
            with self.subTest(repo=repo):
                proc = subprocess.run([sys.executable, "-c", code], cwd=REPO, env=env,
                                      capture_output=True, text=True, timeout=120)
                self.assertEqual(proc.returncode, 0, proc.stderr[-2000:])

    def test_a_retried_import_after_a_failed_selection_rebinds_the_repositories(self):
        # An invalid HARNESS_ENGAGEMENT_ID makes the facade's import raise. The retried import
        # must give repositories that read through the new facade. Negative control: the same
        # facade source with its cleanup removed leaves them bound to the discarded module.
        env = {k: v for k, v in os.environ.items() if k != "HARNESS_ENGAGEMENT_ID"}
        env["PYTHONPATH"] = str(REPO)
        cleanup = "        del sys.modules[_repository]\n"
        self.assertIn(cleanup, _source("store").replace("\r\n", "\n"))
        for strip_cleanup, expected in ((False, "bound"), (True, "stale")):
            code = RETRY_SCRIPT.format(strip=strip_cleanup)
            with self.subTest(strip_cleanup=strip_cleanup):
                proc = subprocess.run([sys.executable, "-c", code], cwd=REPO, env=env,
                                      capture_output=True, text=True, timeout=120)
                self.assertEqual(proc.returncode, 0, proc.stderr[-2000:])
                self.assertEqual(proc.stdout.strip(), expected)


RETRY_SCRIPT = '''
import os, sys, types
from pathlib import Path
import harness
path = Path(harness.__file__).with_name("store.py")
source = path.read_text(encoding="utf-8").replace("\\r\\n", "\\n")
if {strip}:
    source = source.replace("        del sys.modules[_repository]\\n", "        pass\\n")
module = types.ModuleType("harness.store")
module.__file__ = str(path)
sys.modules["harness.store"] = module          # what the import system does, then undoes on failure
os.environ["HARNESS_ENGAGEMENT_ID"] = " surrounded by whitespace "
try:
    exec(compile(source, str(path), "exec"), module.__dict__)
except ValueError:
    sys.modules.pop("harness.store", None)
else:
    sys.exit("the invalid engagement ID was accepted")
del os.environ["HARNESS_ENGAGEMENT_ID"]
from harness import store
import harness.store_schema as schema
print("bound" if schema._store is store and store._connect is schema._connect else "stale")
'''


class ContractCheckerNegativeControls(unittest.TestCase):
    """The checker must flag each way a repository can bind a store name at import."""

    def setUp(self):
        self.names, self.state = store_names(), facade_state()

    def check(self, source):
        return facade_violations(source, self.names, self.state)

    def test_an_import_bound_copy_is_flagged(self):
        found = self.check(BOUND_AT_IMPORT + f"\n{FACADE_IMPORT}\n")
        self.assertTrue(any("from harness.store import" in p for p in found), found)
        self.assertTrue(any("reads _DB_PATH bare" in p for p in found), found)

    def test_a_local_copy_of_state_is_flagged(self):
        found = self.check(f"_DB_PATH = None\n\ndef f():\n    return _DB_PATH\n\n{FACADE_IMPORT}\n")
        self.assertTrue(any("reads _DB_PATH bare" in p for p in found), found)
        self.assertTrue(any("defines facade state _DB_PATH" in p for p in found), found)

    def test_a_global_rebinding_is_flagged(self):
        found = self.check(f"def f(path):\n    global _DB_PATH\n    _DB_PATH = path\n\n{FACADE_IMPORT}\n")
        self.assertTrue(any("`global _DB_PATH`" in p for p in found), found)

    def test_rebinding_a_function_through_the_facade_is_flagged(self):
        found = self.check(f"def f():\n    _store._connect = None\n\n{FACADE_IMPORT}\n")
        self.assertTrue(any("rebinds _store._connect" in p for p in found), found)

    def test_a_facade_import_at_the_top_is_flagged(self):
        found = self.check(f"{FACADE_IMPORT}\n\ndef f():\n    return _store._DB_PATH\n")
        self.assertTrue(any("last statement" in p for p in found), found)

    def test_a_real_repository_mutated_back_to_a_bare_read_is_flagged(self):
        source = _source("store_schema")
        self.assertIn("os.stat(_store._DB_PATH)", source)
        found = self.check(source.replace("os.stat(_store._DB_PATH)", "os.stat(_DB_PATH)", 1))
        self.assertEqual(found, ["_db_identity: reads _DB_PATH bare, not as _store._DB_PATH"])

    def test_the_read_through_form_passes(self):
        self.assertEqual(self.check(READ_THROUGH_FACADE), [])

    def test_an_unexported_facade_read_is_flagged(self):
        self.assertEqual(missing_on_facade("def f():\n    return _store._no_such_name\n", store),
                         ["_no_such_name"])


class PatchReachTests(unittest.TestCase):
    """Each helper other code patches on harness.store: the patch reaches the repository call."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._original = store._DB_PATH
        store._DB_PATH = Path(self._tmp.name) / "facade.db"

    def tearDown(self):
        store._DB_PATH = self._original
        self._tmp.cleanup()

    def test_db_path_reaches_the_connection_and_the_layout(self):
        from harness import store_layout, store_schema
        self.assertTrue(sees_patched_db_path(lambda: connected_file(store._connect)))
        self.assertTrue(sees_patched_db_path(lambda: connected_file(store_schema._connect)))
        self.assertTrue(sees_patched_db_path(store_layout.legacy_store_path))
        self.assertTrue(sees_patched_db_path(store.legacy_store_path))
        self.assertEqual(store.active_engagement(), "")   # a fixture path counts as the legacy store

    def test_db_path_negative_control_a_module_bound_at_import_fails(self):
        bound = synthetic_module(BOUND_AT_IMPORT)
        self.assertFalse(sees_patched_db_path(bound.db_path))
        through = synthetic_module(READ_THROUGH_FACADE)
        self.assertTrue(sees_patched_db_path(through.db_path))

    def test_a_write_in_every_repository_lands_in_the_patched_database(self):
        exchange = _exchange()
        store.persist_findings(exchange, "facade_agent", [_finding()])
        store.suppress_finding("fp-facade", "test")
        self.assertEqual(store.record_observation(exchange)["status"], "stored")
        self.assertEqual(store.enqueue_work_item({"item_id": "w-facade", "engagement_id": "e"}), "inserted")
        blob = store.put_evidence_blob(b"facade blob")
        store.persist_ledger_event({"event_id": "ev-facade", "event_type": "observation",
                                    "finding_ref": "f-facade", "summary": "s"})
        self.assertTrue(store.save_knowledge_note(["facade"], "note"))
        conn = sqlite3.connect(store._DB_PATH)
        try:
            counts = {t: conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
                      for t in ("findings", "finding_suppressions", "exchange_observations", "work_items",
                                "evidence_blobs", "ledger_events", "ledger_chain", "knowledge_notes")}
        finally:
            conn.close()
        self.assertTrue(all(counts.values()), counts)
        self.assertTrue(store.evidence_blob_resolves(blob))
        # store_maintenance: the purge deletes from the same file.
        self.assertGreaterEqual(store.purge_evidence_blobs_older_than(1, now=time.time() + 100), 1)
        self.assertFalse(store.evidence_blob_resolves(blob))

    def test_db_identity_patch_reaches_connect(self):
        from harness import store_schema
        self.assertTrue(call_reaches_patch("_db_identity", lambda: store._connect().close(),
                                           wraps=store._db_identity))
        self.assertTrue(call_reaches_patch("_db_identity", lambda: store_schema._connect().close(),
                                           wraps=store._db_identity))

    def test_db_identity_negative_control_a_module_bound_at_import_fails(self):
        conn = sqlite3.connect(":memory:")
        try:
            bound, through = synthetic_module(BOUND_AT_IMPORT), synthetic_module(READ_THROUGH_FACADE)
            self.assertFalse(call_reaches_patch("_db_identity", lambda: bound.identity(conn), return_value=None))
            self.assertTrue(call_reaches_patch("_db_identity", lambda: through.identity(conn), return_value=None))
        finally:
            conn.close()

    def test_captured_principal_patch_reaches_findings_and_observations(self):
        exchange = _exchange(Authorization="Bearer facade")
        with patch("harness.store.captured_principal_id", return_value="captured:patched") as mock:
            store.persist_findings(exchange, "facade_agent", [_finding()])
            store.record_observation(exchange)
        self.assertEqual(mock.call_count, 2)
        conn = sqlite3.connect(store._DB_PATH)
        try:
            self.assertEqual(conn.execute("SELECT captured_principal_id FROM findings").fetchall(),
                             [("captured:patched",)])
            self.assertEqual(conn.execute("SELECT captured_principal_id FROM exchange_observations").fetchall(),
                             [("captured:patched",)])
        finally:
            conn.close()

    def test_persist_ledger_event_patch_reaches_the_ledger_emit(self):
        ledger = evidence_ledger.EvidenceLedger()
        with patch.object(store, "persist_ledger_event") as mock:
            ev = evidence_ledger.emit(evidence_ledger.EventType.OBSERVATION, "f-facade", "s", ledger=ledger)
        mock.assert_called_once()
        self.assertEqual(mock.call_args.args[0]["event_id"], ev.event_id)

    def test_caller_helpers_are_looked_up_on_the_facade(self):
        # put_evidence_blob, persist_test_plans and persist_validation_submission are called
        # from outside the store, as `store.<name>` on `from harness import store`. This checks
        # that binding (statically, and for module-level bindings by identity under a patch); the
        # caller-level reach of these patches is exercised by the tests that patch them
        # (test_evidence_ledger_wiring, test_agent_routing_caller, test_parameter_binding_caller...).
        callers = {"put_evidence_blob": ["run_context", "browser_driver"],
                   "persist_test_plans": ["orchestrator_detect", "orchestrator_confirm", "pivot_memory"],
                   "persist_validation_submission": ["orchestrator_confirm"]}
        for name, modules in callers.items():
            for caller in modules:
                with self.subTest(name=name, caller=caller):
                    tree = ast.parse(_source(caller))
                    self.assertTrue(any(isinstance(n, ast.Attribute) and n.attr == name
                                        and isinstance(n.value, ast.Name) and n.value.id == "store"
                                        for n in ast.walk(tree)), f"{caller} reads store.{name}")
                    self.assertTrue(any(isinstance(n, ast.ImportFrom) and n.module == "harness"
                                        and any(a.name == "store" and a.asname is None for a in n.names)
                                        for n in ast.walk(tree)), f"{caller} binds the facade as store")
                    module = importlib.import_module(f"harness.{caller}")
                    with patch(f"harness.store.{name}") as mock:
                        if hasattr(module, "store"):   # bound at module level
                            self.assertIs(module.store, store)
                            self.assertIs(getattr(module.store, name), mock)


if __name__ == "__main__":
    unittest.main()
