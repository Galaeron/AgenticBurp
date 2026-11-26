"""ARC-9 guard for the validator splits (write_integrity, sqlmap, business_flow, auth_sequence).

Each of the four validators keeps its module, class, name and registration; their pure helpers and
(for write_integrity) the planning and judging methods live in sibling modules and were moved
verbatim (the proof is `.test-work/audit-fix-20261120/h2-validator-split/verify_verbatim.py`).
This module pins what a caller or a test can still rely on:

- every name the repo imports from, or reads off, one of the four modules still resolves there, and
  it is the very object the sibling defines;
- the class stays in its module, mixins sit before `Validator` and shadow none of its members;
- the three names tests patch on a validator module (`sqlmap.parse_injection_points`,
  `sqlmap.TOOL_REPORTED`, `auth_sequence_validator.get_default_gate`) are read by code that stayed in
  that module, so a patch reaches the caller; a patch on the sibling or on the name's source module
  does not (the negative control, and a static check that no sibling reads one of them);
- the safety machinery (gate calls, scope checks, the run executor, the sqlmap launch, raw clients)
  did not move: no sibling contains it, and the same checker finds it in each original;
- moved code that logs keeps the original module's logger name.
"""
from __future__ import annotations

import ast
import asyncio
import importlib
import logging
import re
import symtable
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from harness.models import Finding, HttpExchange
from harness.validators import (auth_sequence_support, auth_sequence_validator as asv, business_flow_support,
                                business_flow_validator as bf, registry, sqlmap, sqlmap_params, sqlmap_policy,
                                sqlmap_report, sqlmap_signals, write_integrity_judges, write_integrity_plans,
                                write_integrity_support, write_integrity_validator as wi)
from harness.validators.base import Validator

HARNESS = Path(__file__).resolve().parent
REPO = HARNESS.parent
VALIDATORS = HARNESS / "validators"

# original module -> (validator class, the siblings its moved code lives in)
SPLITS = {
    "write_integrity_validator": ("WriteIntegrityValidator", ("write_integrity_support", "write_integrity_plans",
                                                              "write_integrity_judges")),
    "sqlmap": ("SqlmapValidator", ("sqlmap_policy", "sqlmap_params", "sqlmap_signals", "sqlmap_report")),
    "business_flow_validator": ("BusinessFlowValidator", ("business_flow_support",)),
    "auth_sequence_validator": ("AuthSequenceValidator", ("auth_sequence_support",)),
}
MIXINS = {wi: (write_integrity_plans._PlanningMixin, write_integrity_judges._JudgingMixin)}

# Names tests patch on a validator module, and the module whose code must read them.
PATCHED = {"sqlmap": ("parse_injection_points", "TOOL_REPORTED"), "auth_sequence_validator": ("get_default_gate",)}
PATCHED_NAMES = {n for names in PATCHED.values() for n in names}

# What may never be in a sibling: the gate, scope checks, the run executor, the sqlmap launch and any
# client. (`httpx.Response` / `httpx.Headers` in an annotation or a read is a type, not a client.)
SAFETY_MACHINERY = re.compile(
    r"\.authorize\(|authorize_burst|GatedAsyncClient|executor\(\)|get_default_gate|allow_mutating_replay|"
    r"active_enabled|scope_lock|\.in_scope\(|run_process|tool_runner|subprocess|httpx\.AsyncClient|"
    r"httpx\.Client\b|\.request\(|CONTROL_|control_outcome")


def _source(stem: str) -> str:
    return (VALIDATORS / f"{stem}.py").read_text(encoding="utf-8")


def bare_reads(source: str, names: set[str]) -> list[str]:
    """Where a module's code reads one of `names` as a bare global (a binding made at import, which a
    patch on the original module cannot reach)."""
    problems = []

    def walk(table):
        for sym in table.get_symbols():
            if sym.get_name() in names and sym.is_referenced() and sym.is_global() and not sym.is_assigned():
                problems.append(f"{table.get_name()}: reads {sym.get_name()} bare")
        for child in table.get_children():
            walk(child)

    walk(symtable.symtable(source, "<sibling>", "exec"))
    return problems


def top_level_definitions(source: str) -> set[str]:
    names = set()
    for st in ast.parse(source).body:
        if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(st.name)
        elif isinstance(st, (ast.Assign, ast.AnnAssign)):
            for t in (st.targets if isinstance(st, ast.Assign) else [st.target]):
                names.update(n.id for n in ast.walk(t) if isinstance(n, ast.Name))
    return names


def machinery_in(source: str) -> list[str]:
    return sorted({m.group(0) for line in source.splitlines() if not line.lstrip().startswith("#")
                   for m in SAFETY_MACHINERY.finditer(line)})


def used_names() -> dict[str, set[str]]:
    """Every name the repo imports from, or reads off an alias of, one of the four modules."""
    found = {m: set() for m in SPLITS}
    for root in (HARNESS, REPO / "testing", REPO / "evaluation_integrity", REPO / "tools"):
        if not root.is_dir():
            continue
        for path in root.rglob("*.py"):
            if "blind-test-kit" in path.parts or "__pycache__" in path.parts:
                continue
            try:
                tree = ast.parse(path.read_text(encoding="utf-8-sig"))
            except (SyntaxError, UnicodeDecodeError):
                continue
            alias = {m: set() for m in SPLITS}
            for n in ast.walk(tree):
                if isinstance(n, ast.ImportFrom):
                    mod = n.module or ""
                    for m in SPLITS:
                        if mod == f"harness.validators.{m}" or (n.level == 1 and mod == m):
                            found[m].update(a.name for a in n.names if a.name != "*")
                        elif mod in ("harness.validators", "validators") or (n.level == 1 and mod == ""):
                            alias[m].update(a.asname or a.name for a in n.names if a.name == m)
                elif isinstance(n, ast.Import):
                    for a in n.names:
                        for m in SPLITS:
                            if a.name == f"harness.validators.{m}" and a.asname:
                                alias[m].add(a.asname)
            for n in ast.walk(tree):
                if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name):
                    for m in SPLITS:
                        if n.value.id in alias[m]:
                            found[m].add(n.attr)
    return found


class ExportSurfaceTests(unittest.TestCase):
    def test_every_name_the_repo_uses_still_resolves_on_the_original_module(self):
        for modname, names in used_names().items():
            module = importlib.import_module(f"harness.validators.{modname}")
            self.assertTrue(names, f"no caller of {modname} found: the scan is broken")
            missing = sorted(n for n in names if not hasattr(module, n))
            self.assertEqual(missing, [], f"{modname} no longer exports {missing}")

    def test_a_moved_name_is_the_object_its_sibling_defines(self):
        checked = 0
        for modname, (_cls, siblings) in SPLITS.items():
            module = importlib.import_module(f"harness.validators.{modname}")
            for stem in siblings:
                sib = importlib.import_module(f"harness.validators.{stem}")
                for name in sorted(top_level_definitions(_source(stem))):
                    if hasattr(module, name):
                        checked += 1
                        self.assertIs(getattr(module, name), getattr(sib, name), f"{modname}.{name} is a copy")
        self.assertGreater(checked, 40)

    def test_the_exports_the_registry_and_orchestrator_use_come_from_the_siblings(self):
        self.assertIs(asv._PASS_KEYS, auth_sequence_support._PASS_KEYS)
        self.assertIs(asv._session_jwts, auth_sequence_support._session_jwts)
        self.assertIs(bf.flow_kind, business_flow_support.flow_kind)
        self.assertIs(bf._Tamper, business_flow_support._Tamper)
        self.assertIs(sqlmap.parse_injection_points, sqlmap_report.parse_injection_points)
        self.assertIs(sqlmap._mutate_json_param, sqlmap_params._mutate_json_param)
        self.assertIs(sqlmap.create_endpoint_reason, sqlmap_policy.create_endpoint_reason)
        self.assertIs(sqlmap._text_has_db_error_markers, sqlmap_signals._text_has_db_error_markers)
        self.assertIs(wi.route_set, write_integrity_support.route_set)
        self.assertIs(wi.MASS_ASSIGNMENT_CREATE, write_integrity_support.MASS_ASSIGNMENT_CREATE)


class ClassStaysPutTests(unittest.TestCase):
    def test_each_validator_class_lives_in_its_original_module_and_the_registry_uses_that_class(self):
        for modname, (cls, _siblings) in SPLITS.items():
            module = importlib.import_module(f"harness.validators.{modname}")
            klass = getattr(module, cls)
            self.assertEqual(klass.__module__, f"harness.validators.{modname}")
            self.assertIs(getattr(registry, cls, klass), klass)   # the registry's own import, where it has one
            self.assertTrue(issubclass(klass, Validator))

    def test_mixins_sit_before_validator_and_shadow_none_of_its_members(self):
        klass = wi.WriteIntegrityValidator
        mro = klass.__mro__
        members = []
        for mixin in MIXINS[wi]:
            self.assertLess(mro.index(mixin), mro.index(Validator))
            mine = {n for n in vars(mixin) if not n.startswith("__")}
            members.append(mine)
            self.assertEqual(sorted(mine & set(vars(Validator))), [], f"{mixin.__name__} shadows a Validator member")
            for name in mine:
                self.assertIs(getattr(klass, name), getattr(mixin, name), name)
        self.assertEqual(sorted(members[0] & members[1]), [], "two mixins define the same method")
        self.assertEqual(sorted(set(vars(klass)) & (members[0] | members[1])), [], "the class redefines a moved method")

    def test_class_attributes_the_registry_and_routing_read_are_unchanged(self):
        self.assertEqual(wi.WriteIntegrityValidator.name, "write_integrity")
        self.assertEqual(wi.WriteIntegrityValidator.finding_classes, wi.FINDING_CLASSES)
        self.assertEqual(bf.BusinessFlowValidator.name, "business_flow")
        self.assertEqual(bf.BusinessFlowValidator.finding_classes, bf.FINDING_CLASSES)
        self.assertEqual(sqlmap.SqlmapValidator.name, "sqlmap")
        self.assertEqual(asv.AuthSequenceValidator.name, "auth_sequence")


class SiblingsReadNoPatchableNameTests(unittest.TestCase):
    """The only module-level names tests patch are read by code that stayed in the original module."""

    def test_no_sibling_reads_a_patched_name(self):
        for modname, (_cls, siblings) in SPLITS.items():
            for stem in siblings:
                self.assertEqual(bare_reads(_source(stem), PATCHED_NAMES), [], stem)

    def test_the_readers_of_the_patched_names_are_still_in_their_original_module(self):
        for modname, names in PATCHED.items():
            source = _source(modname)
            for name in names:
                self.assertTrue(bare_reads(source, {name}), f"{modname} no longer reads {name}")

    def test_control_a_sibling_that_binds_a_patched_name_at_import_is_flagged(self):
        synthetic = "from harness.safety_gate import get_default_gate\n\ndef f():\n    return get_default_gate().config\n"
        self.assertEqual(len(bare_reads(synthetic, PATCHED_NAMES)), 1)
        clean = "def f(gate):\n    return gate.config\n"
        self.assertEqual(bare_reads(clean, PATCHED_NAMES), [])


def _finding(cls: str) -> Finding:
    return Finding(vulnerability_class=cls, confidence=0.5, summary="candidate", evidence="fixture",
                   suggested_test="verify", basis="derived")


class PatchedNameReachTests(unittest.TestCase):
    """A patch on the original module reaches the caller; the control patches where it would not."""

    def _confirm(self, output: str = "no injection points here"):
        validator = sqlmap.SqlmapValidator(allowed_hosts=["shop.invalid"])
        exchange = HttpExchange(url="http://shop.invalid/api?id=1", method="GET")
        return asyncio.run(validator._sqlmap_confirmation(_finding("sql_injection"), exchange, output, ["sqlmap"]))

    def test_patching_sqlmap_parse_injection_points_reaches_the_confirmation(self):
        seen = []
        with patch("harness.validators.sqlmap.parse_injection_points",
                   side_effect=lambda out: seen.append(out) or []):
            self._confirm("OUT")
        self.assertEqual(seen, ["OUT"])

    def test_control_patching_the_sibling_does_not_reach_the_confirmation(self):
        seen = []
        with patch("harness.validators.sqlmap_report.parse_injection_points",
                   side_effect=lambda out: seen.append(out) or [{"boom": 1}]):
            result = self._confirm("OUT")
        self.assertEqual(seen, [], "the validator read the sibling's name, so a patch on sqlmap would miss it")
        self.assertEqual(result.injection_points, ())

    def test_patching_sqlmap_tool_reported_reaches_the_result(self):
        with patch("harness.validators.sqlmap.TOOL_REPORTED", "sentinel-source"):
            result = self._confirm()
        self.assertEqual(result.evidence_source, "sentinel-source")

    def test_control_patching_the_name_in_base_does_not_reach_the_result(self):
        with patch("harness.validators.base.TOOL_REPORTED", "sentinel-source"):
            result = self._confirm()
        self.assertEqual(result.evidence_source, "tool_reported")

    def _validate_fixation(self):
        validator = asv.AuthSequenceValidator()
        exchange = HttpExchange(url="http://shop.invalid/api/login", method="POST",
                                request_body='{"email": "a@b.c", "password": "x"}')
        return asyncio.run(validator.validate(_finding("session_fixation"), exchange))

    def test_patching_auth_sequence_get_default_gate_reaches_validate(self):
        calls = []
        gate = SimpleNamespace(config=SimpleNamespace(allow_mutating_replay=False))
        with patch.object(asv, "get_default_gate", side_effect=lambda *a, **k: calls.append(1) or gate):
            result = self._validate_fixation()
        self.assertTrue(calls, "validate did not read asv.get_default_gate")
        self.assertEqual(result.status, "skipped")
        self.assertIn("allow_mutating_replay", result.summary)

    def test_control_patching_the_gates_source_module_does_not_reach_validate(self):
        calls = []
        gate = SimpleNamespace(config=SimpleNamespace(allow_mutating_replay=False))
        with patch("harness.safety_gate.get_default_gate", side_effect=lambda *a, **k: calls.append(1) or gate), \
                patch.object(asv, "get_default_gate", side_effect=lambda *a, **k: gate):
            self._validate_fixation()
        self.assertEqual(calls, [], "a patch on safety_gate leaked into the validator's own binding")


class SafetyMachineryStaysTests(unittest.TestCase):
    def test_no_sibling_holds_gate_scope_executor_launch_or_client_code(self):
        for _modname, (_cls, siblings) in SPLITS.items():
            for stem in siblings:
                self.assertEqual(machinery_in(_source(stem)), [], f"{stem} holds safety machinery")

    def test_the_write_validators_hold_no_raw_client_in_any_sibling(self):
        # test_safety_gate pins this for write_integrity_validator.py and business_flow_validator.py; the
        # moved code must not reintroduce a client through a sibling.
        for stem in ("write_integrity_support", "write_integrity_plans", "write_integrity_judges",
                     "business_flow_support"):
            self.assertNotIn("httpx", _source(stem), f"{stem} must not hold a raw client")
        self.assertNotIn("httpx", _source("write_integrity_validator"))
        self.assertNotIn("httpx", _source("business_flow_validator"))

    def test_control_each_original_still_holds_its_machinery(self):
        for modname in SPLITS:
            self.assertTrue(machinery_in(_source(modname)), f"{modname}: the checker found nothing, so it proves nothing")
        self.assertIn("executor()", machinery_in(_source("business_flow_validator")) + machinery_in(
            _source("write_integrity_validator")))
        self.assertIn(".authorize(", machinery_in(_source("write_integrity_validator")))
        self.assertIn("GatedAsyncClient", machinery_in(_source("auth_sequence_validator")))
        self.assertIn(".authorize(", machinery_in(_source("sqlmap")))

    def test_control_the_checker_flags_a_sibling_that_would_send(self):
        self.assertIn(".authorize(", machinery_in("def f(run):\n    return run.gate.authorize(a=1)\n"))
        self.assertIn("executor()", machinery_in("async def f(self):\n    return await self.run_context.executor().x()\n"))
        self.assertEqual(machinery_in("# gate.authorize( in a comment\ndef f(r: httpx.Response):\n    return r\n"), [])


class MovedCodeLogsUnderTheOriginalLoggerTests(unittest.TestCase):
    NAME = "harness.validators.write_integrity_validator"

    def test_siblings_log_under_the_original_module_logger(self):
        self.assertEqual(write_integrity_support.log.name, self.NAME)
        self.assertIs(write_integrity_support.log, wi.log)
        self.assertIs(write_integrity_judges.log, wi.log)

    def test_a_record_from_a_moved_method_is_seen_by_a_listener_on_the_original_logger(self):
        with self.assertLogs(self.NAME, "DEBUG") as logs:
            write_integrity_judges.log.debug("write_integrity: moved-method probe")
        self.assertEqual(len(logs.records), 1)

    def test_control_a_name_taken_from___name___would_miss_the_original_logger(self):
        self.assertNotEqual(logging.getLogger(write_integrity_judges.__name__).name, self.NAME)


if __name__ == "__main__":
    unittest.main()
