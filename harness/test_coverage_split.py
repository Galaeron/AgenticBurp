"""ARC-9 guard for the h1 splits: coverage_model, coverage_tracker and api_surface_discovery stay
the import path (a facade) over sibling modules, and a patch on the facade must reach every caller,
exactly as when each was one module.

The contract (each facade's docstring): the facade owns the names tests patch; code that moved
reads such a name as `<alias>.<name>` (`_ct`, `_asd`) at call time, never a copy bound at import.
A moved module that did `from harness.coverage_tracker import _fair_cells` would keep the old
function after `patch.object(coverage_tracker, "_fair_cells", ...)`. The static checker finds that
shape; the reach tests patch every such name and drive the moved code through its real caller; the
negative controls feed the checker a module that binds at import, and give a moved module a stale
snapshot of the facade, and require both to fail.
coverage_model moves no reader of a patched name (REUSED_LEGACY_IDS, is_current_wstg_id,
LEGACY_CHECK_ID_ALIASES are read by the ids functions that stay in the facade), so its reach tests
pin that placement.
"""
from __future__ import annotations

import ast
import asyncio
import contextlib
import functools
import importlib
import os
import subprocess
import symtable
import sys
import time
import types
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import NamedTuple
from unittest.mock import MagicMock, patch

from harness import api_surface_discovery as asd
from harness import coverage_model, coverage_tracker
from harness.coverage_model import CellStatus
from harness.engagement import EngagementState
from harness.models import HttpExchange
from harness.role_crawl import RoleSession

HARNESS = Path(__file__).resolve().parent
REPO = HARNESS.parent


class Split(NamedTuple):
    facade: str
    moved: tuple[str, ...]
    alias: str | None                  # how moved code reads the facade; None = it never does
    through: frozenset                 # names moved code must read as <alias>.<name>
    mixins: tuple[str, ...] = ()
    cls: str = ""


SPLITS = {
    "coverage_model": Split(
        "coverage_model", ("coverage_model_cells", "coverage_model_checks", "coverage_model_catalog"),
        None, frozenset()),
    "coverage_tracker": Split(
        "coverage_tracker",
        ("coverage_tracker_tables", "coverage_tracker_matrix", "coverage_tracker_drive",
         "coverage_tracker_report"),
        "_ct", frozenset({"time", "REQUEST_LEVEL_INPUTS", "_LEG_STATUS", "_LEG_STATUS_UNKNOWN",
                          "_fair_cells", "_time_fair_cells", "_listed_in_compact_ledger", "log"}),
        ("_MatrixMixin", "_DriveMixin", "_ReportMixin"), "CoverageTracker"),
    "api_surface_discovery": Split(
        "api_surface_discovery",
        ("api_surface_data", "api_surface_sensitive", "api_surface_probe", "api_surface_walk",
         "api_surface_mining"),
        "_asd", frozenset({"_host_in_scope", "sensitive_file_verdict"}),
        ("_ProbeMixin", "_WalkMixin", "_MiningMixin"), "SurfaceDiscovery"),
}


def _source(name: str) -> str:
    return (HARNESS / f"{name}.py").read_text(encoding="utf-8-sig")


def top_level_definitions(source: str) -> set[str]:
    """Names a module defines itself (def, class, assignment, loop target); imports excluded."""
    names = set()
    for st in ast.parse(source).body:
        if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(st.name)
        elif isinstance(st, (ast.Assign, ast.AnnAssign)):
            for t in (st.targets if isinstance(st, ast.Assign) else [st.target]):
                names.update(n.id for n in ast.walk(t) if isinstance(n, ast.Name))
    return names


def split_violations(source: str, facade: str, alias: str | None, through: frozenset) -> list[str]:
    """What breaks the contract in one moved module's source:
    - a function or class body that reads a name the facade owns as a bare global, or declares
      `global` for it (a copy bound at import, or a name that only the facade rebinds);
    - an import that binds the facade's names at import (`from harness.<facade> import ...`);
    - a star import;
    - the facade import in any form but `from harness import <facade> as <alias>`, bound last
      (so the module imports first and the facade finds it complete), or any facade import at
      all in a module whose split has no alias;
    - a rebinding through the alias (the facade owns the state)."""
    problems = []
    tree = ast.parse(source)

    def walk(table):
        for child in table.get_children():
            for sym in child.get_symbols():
                name = sym.get_name()
                if name not in through:
                    continue
                if sym.is_declared_global():
                    problems.append(f"{child.get_name()}: `global {name}` (rebind it as {alias}.{name})")
                elif sym.is_global() and sym.is_referenced():
                    problems.append(f"{child.get_name()}: reads {name} bare, not as {alias}.{name}")
            walk(child)
    walk(symtable.symtable(source, "<moved>", "exec"))

    wanted = f"from harness import {facade} as {alias}" if alias else None
    for n in ast.walk(tree):
        if isinstance(n, ast.ImportFrom) and any(a.name == "*" for a in n.names):
            problems.append(f"line {n.lineno}: star import")
        if isinstance(n, ast.ImportFrom) and n.module == f"harness.{facade}":
            problems.append(f"line {n.lineno}: from harness.{facade} import (binds its names at import)")
        elif isinstance(n, ast.ImportFrom) and n.module == "harness" and any(a.name == facade for a in n.names):
            if ast.unparse(n) != wanted:
                problems.append(f"line {n.lineno}: {ast.unparse(n)} (only `{wanted}` is allowed)")
        elif isinstance(n, ast.Import) and any(a.name == f"harness.{facade}" for a in n.names):
            problems.append(f"line {n.lineno}: import harness.{facade}")
    has_alias_import = any(isinstance(n, ast.ImportFrom) and n.module == "harness"
                           and any(a.name == facade for a in n.names) for n in ast.walk(tree))
    if alias is None and has_alias_import:
        problems.append(f"imports the facade, but the {facade} split has no alias")
    if alias is not None and has_alias_import and (not tree.body or ast.unparse(tree.body[-1]) != wanted):
        problems.append(f"the last statement must be `{wanted}` (import order)")
    for n in ast.walk(tree):
        targets = []
        if isinstance(n, ast.Assign):
            targets = n.targets
        elif isinstance(n, (ast.AugAssign, ast.AnnAssign)):
            targets = [n.target]
        for t in targets:
            if isinstance(t, ast.Attribute) and isinstance(t.value, ast.Name) and t.value.id == alias:
                problems.append(f"line {n.lineno}: rebinds {alias}.{t.attr} (the facade owns it)")
    return problems


def missing_on_facade(source: str, alias: str | None, facade_module) -> list[str]:
    """`<alias>.<name>` reads of a name the facade does not have (a typo or an unexported name)."""
    if alias is None:
        return []
    return sorted({n.attr for n in ast.walk(ast.parse(source))
                   if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name)
                   and n.value.id == alias and not hasattr(facade_module, n.attr)})


@functools.lru_cache(maxsize=None)
def _scan_callers() -> dict:
    """Every name any file uses from a facade (`from harness.<m> import a`, `<alias>.a`,
    `patch.object(<alias>, "a")`, "harness.<m>.a" strings), and every non-test file that imports
    a moved module directly."""
    facades = set(SPLITS)
    moved = {m: s.facade for s in SPLITS.values() for m in s.moved}
    used: dict[str, dict[str, str]] = {f: {} for f in facades}
    direct: list[str] = []
    for root in (HARNESS, REPO / "testing", REPO / "tools", REPO / "evaluation_integrity"):
        for path in sorted(root.rglob("*.py")) if root.is_dir() else []:
            if "__pycache__" in path.parts or path.name == Path(__file__).name:
                continue          # this guard names the facades and moved modules itself
            try:
                tree = ast.parse(path.read_text(encoding="utf-8-sig"))
            except (SyntaxError, UnicodeDecodeError):
                continue
            alias: dict[str, str] = {}
            where = path.relative_to(REPO).as_posix()
            for n in ast.walk(tree):
                if isinstance(n, ast.ImportFrom):
                    mod = n.module or ""
                    if mod == "harness":
                        for a in n.names:
                            if a.name in facades:
                                alias[a.asname or a.name] = a.name
                            elif a.name in moved:
                                direct.append(where)
                    elif mod.startswith("harness.") and mod.count(".") == 1:
                        if mod[8:] in facades:
                            for a in n.names:
                                used[mod[8:]].setdefault(a.name, where)
                        elif mod[8:] in moved:
                            direct.append(where)
                elif isinstance(n, ast.Import):
                    for a in n.names:
                        if a.name.startswith("harness.") and a.name.count(".") == 1:
                            if a.name[8:] in facades:
                                alias[a.asname or a.name] = a.name[8:]
                            elif a.name[8:] in moved:
                                direct.append(where)
                elif isinstance(n, ast.Constant) and isinstance(n.value, str) and n.value.startswith("harness."):
                    parts = n.value.split(".")
                    if len(parts) >= 3 and parts[1] in facades:
                        used[parts[1]].setdefault(parts[2], where)
            for n in ast.walk(tree):
                if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and n.value.id in alias:
                    used[alias[n.value.id]].setdefault(n.attr, where)
                elif (isinstance(n, ast.Call) and len(n.args) >= 2 and isinstance(n.args[0], ast.Name)
                      and n.args[0].id in alias and isinstance(n.args[1], ast.Constant)
                      and isinstance(n.args[1].value, str)):
                    used[alias[n.args[0].id]].setdefault(n.args[1].value, where)
    return {"used": used, "direct": direct}


# ---------------------------------------------------------------------------------------------
# Static contract: shape, definitions, callers
# ---------------------------------------------------------------------------------------------
class FacadeShapeTests(unittest.TestCase):
    def test_every_moved_definition_is_the_same_object_on_the_facade(self):
        for split in SPLITS.values():
            facade = importlib.import_module(f"harness.{split.facade}")
            for m in split.moved:
                module = importlib.import_module(f"harness.{m}")
                for name in sorted(top_level_definitions(_source(m))):
                    with self.subTest(facade=split.facade, module=m, name=name):
                        self.assertTrue(hasattr(facade, name), "the facade must re-export it")
                        self.assertIs(getattr(facade, name), getattr(module, name))

    def test_no_name_is_defined_twice(self):
        for split in SPLITS.values():
            seen = {name: split.facade for name in top_level_definitions(_source(split.facade))}
            for m in split.moved:
                for name in top_level_definitions(_source(m)):
                    self.assertNotIn(name, seen, f"{name} defined in {seen.get(name)} and {m}")
                    seen[name] = m

    def test_moved_modules_keep_the_contract(self):
        for split in SPLITS.values():
            problems = {m: found for m in split.moved
                        if (found := split_violations(_source(m), split.facade, split.alias, split.through))}
            self.assertEqual(problems, {}, split.facade)

    def test_every_facade_read_names_a_facade_attribute(self):
        for split in SPLITS.values():
            facade = importlib.import_module(f"harness.{split.facade}")
            problems = {m: found for m in split.moved
                        if (found := missing_on_facade(_source(m), split.alias, facade))}
            self.assertEqual(problems, {}, split.facade)

    def test_the_patched_names_exist_on_the_facade(self):
        for split in SPLITS.values():
            facade = importlib.import_module(f"harness.{split.facade}")
            self.assertEqual([n for n in sorted(split.through) if not hasattr(facade, n)], [], split.facade)

    def test_callers_outside_the_split_never_import_a_moved_module(self):
        # A caller that imported harness.coverage_tracker_drive directly would bypass every facade patch.
        offenders = sorted(set(p for p in _scan_callers()["direct"]
                               if not Path(p).name.startswith("test_")
                               and Path(p).stem not in {m for s in SPLITS.values() for m in s.moved}
                               and Path(p).stem not in SPLITS))
        self.assertEqual(offenders, [])

    def test_every_name_a_caller_uses_is_still_on_the_facade(self):
        for facade_name, used in _scan_callers()["used"].items():
            facade = importlib.import_module(f"harness.{facade_name}")
            missing = {n: where for n, where in used.items() if not hasattr(facade, n)}
            self.assertEqual(missing, {}, facade_name)
        # the scan is not vacuous: it sees the names the patch tests use
        self.assertIn("_fair_cells", _scan_callers()["used"]["coverage_tracker"])
        self.assertIn("_host_in_scope", _scan_callers()["used"]["api_surface_discovery"])
        self.assertIn("REUSED_LEGACY_IDS", _scan_callers()["used"]["coverage_model"])

    def test_the_facade_class_is_composed_of_its_mixins_without_overlap(self):
        for split in SPLITS.values():
            if not split.cls:
                continue
            facade = importlib.import_module(f"harness.{split.facade}")
            klass = getattr(facade, split.cls)
            mixins = [getattr(importlib.import_module(f"harness.{m}"), name)
                      for m in split.moved for name in split.mixins
                      if hasattr(importlib.import_module(f"harness.{m}"), name)
                      and name in top_level_definitions(_source(m))]
            self.assertEqual({c.__name__ for c in mixins}, set(split.mixins))
            self.assertEqual([c for c in klass.__mro__[1:-1]], mixins)
            owned = {n: [c.__name__ for c in [klass] + mixins if n in vars(c)] for n in
                     {n for c in [klass] + mixins for n in vars(c) if n not in
                      ("__module__", "__doc__", "__dict__", "__weakref__", "__qualname__",
                       "__firstlineno__", "__static_attributes__", "__annotations__",
                       "__annotate__", "__annotate_func__", "__classdictcell__")}}
            self.assertEqual({n: c for n, c in owned.items() if len(c) > 1}, {}, "a name defined twice")

    def test_a_moved_module_can_be_imported_first(self):
        # The moved modules import the facade last, the facade imports them first: both orders must work.
        env = dict(os.environ, PYTHONPATH=str(REPO))
        for m in ("coverage_tracker_drive", "coverage_tracker_report", "api_surface_probe",
                  "api_surface_mining"):
            with self.subTest(module=m):
                r = subprocess.run([sys.executable, "-c", f"import harness.{m}"], cwd=REPO, env=env,
                                   capture_output=True, text=True)
                self.assertEqual(r.returncode, 0, r.stderr[-400:])


# ---------------------------------------------------------------------------------------------
# Negative controls for the static checker
# ---------------------------------------------------------------------------------------------
TRACKER = SPLITS["coverage_tracker"]
BOUND_AT_IMPORT = ("import time\nfrom harness.coverage_tracker import _fair_cells\n\n\n"
                   "def f():\n    return time.monotonic(), _fair_cells\n")
READ_THROUGH_FACADE = ("def f():\n    return _ct.time.monotonic(), _ct._fair_cells\n\n\n"
                       "from harness import coverage_tracker as _ct  # noqa: E402\n")


class StaticControlTests(unittest.TestCase):
    def violations(self, source, split=TRACKER):
        return split_violations(source, split.facade, split.alias, split.through)

    def test_a_clean_module_passes(self):
        self.assertEqual(self.violations(READ_THROUGH_FACADE), [])

    def test_a_module_that_binds_names_at_import_is_flagged(self):
        found = self.violations(BOUND_AT_IMPORT)
        self.assertTrue(any("reads time bare" in p for p in found), found)
        self.assertTrue(any("binds its names at import" in p for p in found), found)

    def test_a_global_declaration_is_flagged(self):
        found = self.violations("def f():\n    global time\n    time = 1\n\n\n"
                                "from harness import coverage_tracker as _ct\n")
        self.assertTrue(any("`global time`" in p for p in found), found)

    def test_a_star_import_is_flagged(self):
        self.assertTrue(any("star import" in p for p in self.violations("from os.path import *\n")))

    def test_the_facade_import_must_come_last(self):
        found = self.violations("from harness import coverage_tracker as _ct\n\n\ndef f():\n    return _ct.time\n")
        self.assertTrue(any("last statement" in p for p in found), found)

    def test_a_rebinding_through_the_alias_is_flagged(self):
        found = self.violations("def f():\n    _ct.time = None\n\n\nfrom harness import coverage_tracker as _ct\n")
        self.assertTrue(any("rebinds _ct.time" in p for p in found), found)

    def test_a_split_without_an_alias_may_not_import_its_facade(self):
        found = split_violations("from harness import coverage_model\n", "coverage_model", None, frozenset())
        self.assertTrue(any("no alias" in p for p in found), found)

    def test_a_read_of_a_name_the_facade_lacks_is_found(self):
        self.assertEqual(missing_on_facade("x = _ct.no_such_name\n_ct.time\n", "_ct", coverage_tracker),
                         ["no_such_name"])


# ---------------------------------------------------------------------------------------------
# coverage_tracker: the moved readers
# ---------------------------------------------------------------------------------------------
BASE = "http://127.0.0.1:9/"          # loopback; the legs are stubs, nothing is sent
ROLES = [RoleSession("anonymous", {})]


def _state():
    state = EngagementState(host="127.0.0.1")
    state.ingest_role_crawl({"endpoints": [
        {"method": "GET", "path": p, "by_role": {"anonymous": 200},
         "reachable_roles": ["anonymous"], "object_scoped": False} for p in ("/api/search0", "/api/page0")]})
    url = f"{BASE}api/search0?term=x"
    state.record_template(url, "GET", HttpExchange(url=url, method="GET", response_status=200))
    return state


async def _stub_leg(identity, method, path, check):
    return SimpleNamespace(status="not_confirmed", sent_count=1, summary="stub leg")


async def _stub_case(identity, method, path, check, case, **kwargs):
    return SimpleNamespace(status="not_confirmed", sent_count=1, summary="stub leg",
                           tested_parameters=((case.parameter_location, case.parameter_name),))


def drive_legs(run_leg=_stub_leg, driveable=("cors",)):
    out = []
    asyncio.run(coverage_tracker.build_coverage_driven(
        _state(), ROLES, run_leg, driveable=set(driveable), budget=50, deadline=1e12, tracker_out=out))
    return out[0]


def drive_cases(run_case=_stub_case, driveable=("sqlmap", "cors")):
    out = []
    asyncio.run(coverage_tracker.build_coverage_cases_driven(
        _state(), ROLES, run_case, driveable=set(driveable), budget=200, deadline=1e12, tracker_out=out))
    return out[0]


class _TimeSpy:
    """A fake `time` for coverage_tracker that records which function read the clock."""

    def __init__(self):
        self.callers: set[str] = set()

    def monotonic(self):
        self.callers.add(sys._getframe(1).f_code.co_name)
        return 1000.0

    def __getattr__(self, name):
        return getattr(time, name)


class _DictSpy(dict):
    """A dict that records which function looked a key up."""

    def __init__(self, *args):
        super().__init__(*args)
        self.callers: set[str] = set()

    def get(self, key, default=None):
        self.callers.add(sys._getframe(1).f_code.co_name)
        return super().get(key, default)

    def __contains__(self, key):
        self.callers.add(sys._getframe(1).f_code.co_name)
        return super().__contains__(key)


def facade_snapshot(facade) -> types.SimpleNamespace:
    """What a moved module would see if it had bound the facade's names at import."""
    return types.SimpleNamespace(**{n: getattr(facade, n) for n in dir(facade)})


class stale_alias:
    """Give moved modules a snapshot of the facade for their alias: the defect the contract forbids."""

    def __init__(self, facade, *modules):
        self.facade, self.modules = facade, modules

    def __enter__(self):
        snap = facade_snapshot(self.facade)
        self.patches = [patch.object(importlib.import_module(f"harness.{m}"), self.facade_alias(m), snap)
                        for m in self.modules]
        for p in self.patches:
            p.start()

    def facade_alias(self, module):
        return "_ct" if module.startswith("coverage_tracker") else "_asd"

    def __exit__(self, *exc):
        for p in self.patches:
            p.stop()


class TrackerReachTests(unittest.TestCase):
    def test_time_reaches_the_leg_and_the_case_drives(self):
        spy = _TimeSpy()
        with patch.object(coverage_tracker, "time", spy):
            drive_legs()
            self.assertIn("drive_coverage_legs", spy.callers)
            drive_cases()
        self.assertTrue({"drive_coverage_cases", "_drive_parameter_cases"} <= spy.callers, spy.callers)

    def test_request_level_inputs_reaches_both_case_readers(self):
        spy = _DictSpy({"sqlmap": "query"})
        with patch.object(coverage_tracker, "REQUEST_LEVEL_INPUTS", spy):
            drive_cases(driveable=("sqlmap",))
        self.assertTrue({"_drive_parameter_cases", "_drive_request_level"} <= spy.callers, spy.callers)

    def test_leg_status_and_its_unknown_default_reach_the_leg_result(self):
        spy = _DictSpy()
        with patch.object(coverage_tracker, "_LEG_STATUS", spy), \
                patch.object(coverage_tracker, "_LEG_STATUS_UNKNOWN", CellStatus.ERROR):
            tracker = drive_legs()
        self.assertIn("_record_leg_result", spy.callers)
        statuses = {tracker.matrix.cells()[key].status for key in tracker.attempted}
        self.assertEqual(statuses, {CellStatus.ERROR})
        # control: unpatched, the same leg reads as an executed negative
        tracker = drive_legs()
        self.assertEqual({tracker.matrix.cells()[key].status for key in tracker.attempted},
                         {CellStatus.NOT_DETECTED})

    def test_the_fair_share_schedulers_reach_the_drive_order(self):
        with patch.object(coverage_tracker, "_fair_cells", return_value=[]) as fair, \
                patch.object(coverage_tracker, "_time_fair_cells", return_value=[]) as timed:
            list(coverage_tracker._drive_order([], frozenset()))
            self.assertEqual((fair.call_count, timed.call_count), (1, 0))
            list(coverage_tracker._drive_order([], frozenset(), {}))
            self.assertEqual((fair.call_count, timed.call_count), (2, 1))

    def test_the_fair_share_schedulers_reach_a_drive(self):
        with patch.object(coverage_tracker, "_fair_cells", wraps=coverage_tracker._fair_cells) as fair, \
                patch.object(coverage_tracker, "_time_fair_cells",
                             wraps=coverage_tracker._time_fair_cells) as timed:
            drive_legs()                     # under a deadline: the time-fair order
        self.assertTrue(fair.called and timed.called)

    def test_the_compact_ledger_filter_reaches_the_phase_ledger(self):
        tracker = drive_legs()
        everything = len(tracker.phase_ledger(compact=False)["cells"])
        self.assertGreater(everything, 0)
        with patch.object(coverage_tracker, "_listed_in_compact_ledger", return_value=False) as listed:
            ledger = tracker.phase_ledger(compact=True)
        self.assertTrue(listed.called)
        self.assertEqual(ledger["cells"], [])
        with patch.object(coverage_tracker, "_listed_in_compact_ledger", return_value=True):
            self.assertEqual(len(tracker.phase_ledger(compact=True)["cells"]), everything)

    def test_the_logger_reaches_the_drive_and_the_checkpoint(self):
        async def boom(identity, method, path, check):
            raise RuntimeError("boom")
        with patch.object(coverage_tracker, "log") as log:
            drive_legs(boom)
        self.assertTrue(log.debug.called)
        tracker = coverage_tracker.CoverageTracker()

        def failing(_checkpoint):
            raise RuntimeError("callback")
        tracker.on_checkpoint = failing
        with patch.object(coverage_tracker, "log") as log:
            tracker._checkpoint_after(coverage_tracker.CHECKPOINT_EVERY_LEGS)
        log.warning.assert_called_once()

    def test_names_defined_in_one_module_and_patched_on_the_facade_reach_their_callers(self):
        # build_coverage* stay in the facade and read CoverageTracker there; resume_context_key is read
        # by callers through the facade only (job_status_passive patches it); both are facade attributes.
        recorded = []

        class Recording(coverage_tracker.CoverageTracker):
            def __init__(self, *a, **k):
                recorded.append(self)
                super().__init__(*a, **k)
        with patch.object(coverage_tracker, "CoverageTracker", Recording):
            coverage_tracker.build_coverage(_state(), ROLES)
        self.assertEqual(len(recorded), 1)
        with patch.object(coverage_tracker, "resume_context_key", return_value="fixed"):
            self.assertEqual(coverage_tracker.resume_context_key({}), "fixed")

    # --- negative controls: a moved module with a stale copy of the facade must fail the reach ---
    def test_control_a_stale_alias_does_not_see_a_patched_time(self):
        spy = _TimeSpy()
        with stale_alias(coverage_tracker, "coverage_tracker_drive", "coverage_tracker_report"), \
                patch.object(coverage_tracker, "time", spy):
            drive_legs()
            drive_cases()
        self.assertEqual(spy.callers, set(), "a snapshot of the facade must not see the patch")

    def test_control_a_stale_alias_does_not_see_a_patched_leg_status(self):
        with stale_alias(coverage_tracker, "coverage_tracker_drive"), \
                patch.object(coverage_tracker, "_LEG_STATUS", {}), \
                patch.object(coverage_tracker, "_LEG_STATUS_UNKNOWN", CellStatus.ERROR):
            tracker = drive_legs()
        self.assertEqual({tracker.matrix.cells()[key].status for key in tracker.attempted},
                         {CellStatus.NOT_DETECTED})

    def test_control_a_stale_alias_does_not_see_a_patched_scheduler(self):
        with stale_alias(coverage_tracker, "coverage_tracker_drive"), \
                patch.object(coverage_tracker, "_fair_cells", return_value=[]) as fair:
            list(coverage_tracker._drive_order([], frozenset()))
        self.assertFalse(fair.called)

    def test_control_a_stale_alias_does_not_see_a_patched_ledger_filter(self):
        tracker = drive_legs()
        with stale_alias(coverage_tracker, "coverage_tracker_report"), \
                patch.object(coverage_tracker, "_listed_in_compact_ledger", return_value=False) as listed:
            tracker.phase_ledger(compact=True)
        self.assertFalse(listed.called)

    def test_control_a_stale_alias_does_not_see_a_patched_request_level_table(self):
        spy = _DictSpy({"sqlmap": "query"})
        with stale_alias(coverage_tracker, "coverage_tracker_drive"), \
                patch.object(coverage_tracker, "REQUEST_LEVEL_INPUTS", spy):
            drive_cases(driveable=("sqlmap",))
        self.assertEqual(spy.callers, set())


# ---------------------------------------------------------------------------------------------
# api_surface_discovery
# ---------------------------------------------------------------------------------------------
_NF = ("Traceback (most recent call last):\n"
       "werkzeug.exceptions.NotFound: 404 Not Found: The requested URL was not found on the server.")


class _Canned(asd.SurfaceDiscovery):
    """SurfaceDiscovery with its network seam replaced by a canned responder."""

    def __init__(self, responder, **kw):
        super().__init__("http://target.test", **kw)
        self._responder = responder

    async def _probe(self, method, path):
        return self._responder(method, path)


class SurfaceReachTests(unittest.TestCase):
    def test_host_in_scope_reaches_the_probe(self):
        d = asd.SurfaceDiscovery("http://127.0.0.1:9", allowed_hosts=[])
        with patch.object(asd, "_host_in_scope", return_value=False) as scope:
            self.assertIsNone(asyncio.run(d._probe("GET", "/x")))
        scope.assert_called_once_with("http://127.0.0.1:9/x", [])

    def test_host_in_scope_reaches_html_link_mining(self):
        html = '<html><body><a href="http://elsewhere.test/admin">x</a></body></html>'
        d = _Canned(lambda m, p: (500, _NF, ""), allowed_hosts=["target.test"], use_ffuf=False)
        d._seen = {"/home": asd.Route("/home", 200)}

        async def raw(method, path):
            return (200, html, "")
        d._raw = raw
        checked = []

        async def check(path, source):
            checked.append(path)
        d._check = check
        with patch.object(asd, "_host_in_scope", return_value=True) as scope:
            asyncio.run(d._mine_responses())
        self.assertTrue(scope.called)
        self.assertIn("/admin", checked)          # the patched scope let the off-host link through
        checked.clear()
        asyncio.run(d._mine_responses())           # control: unpatched, the real scope refuses it
        self.assertNotIn("/admin", checked)

    def test_sensitive_file_verdict_reaches_the_sensitive_record(self):
        d = asd.SurfaceDiscovery("http://target.test")
        verdict = asd.SensitiveFileVerdict("dotenv", "confirmed", "patched verdict")
        with patch.object(asd, "sensitive_file_verdict", return_value=verdict) as spy:
            record = d._sensitive_record("/.env", asd.Route("/.env", 200, ("GET",), 12))
        spy.assert_called_once_with("/.env", 200, "")
        self.assertEqual((record["reason"], record["confirmed"]), ("patched verdict", True))

    def test_the_wordlists_reach_the_constructor(self):
        for name, attr in (("DEFAULT_NOUNS", "nouns"), ("DEFAULT_COLLECTIONS", "collections"),
                           ("DEFAULT_ACTIONS", "actions"), ("DEFAULT_PREFIXES", "prefixes"),
                           ("DEFAULT_SENSITIVE_FILES", "sensitive_files")):
            with self.subTest(name=name), patch.object(asd, name, ("zzz",)):
                self.assertEqual(getattr(asd.SurfaceDiscovery("http://target.test"), attr), ["zzz"])

    def test_the_mining_reserve_and_late_fraction_reach_discover(self):
        def responder(method, path):
            if path == "/api/login":
                return (500, "{}", "") if method == "GET" else (200, "", "POST, OPTIONS")
            return (500, _NF, "")

        def run(**patches):
            disc = _Canned(responder, use_ffuf=False, max_probes=15,
                           prefixes=["/api/", "/admin/", "/internal/", "/v1/", "/v2/"],
                           collections=["admin", "tickets", "users", "orders"],
                           nouns=["login"] + [f"noun{i}" for i in range(40)])
            with contextlib.ExitStack() as stack:
                for name, value in patches.items():
                    stack.enter_context(patch.object(asd, name, value))
                result = asyncio.run(disc.discover())
            return next(r for r in result.routes if r.path == "/api/login").methods
        self.assertIn("POST", run())
        self.assertEqual(run(_ALLOW_MINING_RESERVE=0, _LATE_DISCOVERY_FRACTION=0), ("GET",))

    def test_discover_still_reads_the_thresholds_through_the_facade(self):
        # The readers of both thresholds stay in the facade class; if one moved, it would need `_asd.`.
        for name in ("_ALLOW_MINING_RESERVE", "_LATE_DISCOVERY_FRACTION"):
            self.assertIn(name, asd.SurfaceDiscovery.discover.__code__.co_names)

    # --- negative controls ---
    def test_control_a_stale_alias_does_not_see_a_patched_scope(self):
        d = asd.SurfaceDiscovery("http://127.0.0.1:9", allowed_hosts=[])
        with stale_alias(asd, "api_surface_probe"), \
                patch.object(asd, "_host_in_scope", return_value=False) as scope:
            self.assertIsNone(asyncio.run(d._probe("GET", "/x")))     # the real check fails closed too
        self.assertFalse(scope.called)

    def test_control_a_stale_alias_does_not_see_a_patched_verdict(self):
        d = asd.SurfaceDiscovery("http://target.test")
        verdict = asd.SensitiveFileVerdict("dotenv", "confirmed", "patched verdict")
        with stale_alias(asd, "api_surface_mining"), \
                patch.object(asd, "sensitive_file_verdict", return_value=verdict) as spy:
            record = d._sensitive_record("/.env", asd.Route("/.env", 200, ("GET",), 12))
        self.assertFalse(spy.called)
        self.assertNotEqual(record["reason"], "patched verdict")


# ---------------------------------------------------------------------------------------------
# coverage_model: the ids and the import guard stay with the names tests patch
# ---------------------------------------------------------------------------------------------
class CoverageModelReachTests(unittest.TestCase):
    LEGACY = "WSTG-BUSL-08"        # a legacy alias key that is also a current id

    def test_the_readers_of_the_patched_names_are_defined_in_the_facade(self):
        for name in ("is_legacy_check_id", "resolve_check_id", "_check_catalog_ids",
                     "REUSED_LEGACY_IDS", "LEGACY_CHECK_ID_ALIASES"):
            self.assertIn(name, top_level_definitions(_source("coverage_model")))

    def test_reused_legacy_ids_reaches_the_legacy_checks(self):
        self.assertFalse(coverage_model.is_legacy_check_id(self.LEGACY))
        with patch.object(coverage_model, "REUSED_LEGACY_IDS", frozenset()):
            self.assertTrue(coverage_model.is_legacy_check_id(self.LEGACY))

    def test_the_legacy_alias_table_reaches_resolve_check_id(self):
        with patch.dict(coverage_model.LEGACY_CHECK_ID_ALIASES, {"WSTG-INJT-05": "WSTG-INJT-01"}):
            self.assertEqual(coverage_model.resolve_check_id("WSTG-INJT-05"), "WSTG-INJT-01")

    def test_is_current_wstg_id_reaches_the_import_guard(self):
        coverage_model._check_catalog_ids()
        with patch.object(coverage_model, "is_current_wstg_id", lambda _id: False):
            with self.assertRaises(Exception):
                coverage_model._check_catalog_ids()

    def test_the_catalog_is_one_object_on_every_path(self):
        from harness import coverage_model_catalog
        self.assertIs(coverage_model.CHECK_CATALOG, coverage_model_catalog.CHECK_CATALOG)
        self.assertIs(coverage_model.CHECKS_BY_ID, coverage_model_catalog.CHECKS_BY_ID)
        self.assertIs(coverage_tracker.CHECK_CATALOG, coverage_model.CHECK_CATALOG)

    def test_control_a_sibling_that_binds_a_patched_name_at_import_is_flagged(self):
        bound = "from harness.coverage_model import REUSED_LEGACY_IDS\n\n\ndef f(x):\n    return x in REUSED_LEGACY_IDS\n"
        found = split_violations(bound, "coverage_model", None, frozenset({"REUSED_LEGACY_IDS"}))
        self.assertTrue(any("binds its names at import" in p for p in found), found)
        self.assertTrue(any("reads REUSED_LEGACY_IDS bare" in p for p in found), found)


if __name__ == "__main__":
    unittest.main()
