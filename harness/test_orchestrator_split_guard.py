"""ARC-9 guard: no star imports, orchestrator modules under the size limit, a size ratchet
for the rest, and patch targets that name a module which really looks the name up.

Why these checks exist: `orchestrator_chain.py` was 3,790 lines with `investigate_engagement`
one 2,600-line function, and every orchestrator module took its namespace from
`from harness.orchestrator_helpers import *`, so a reader could not tell where a name came
from and a patch on a moved name silently did nothing. The negative controls at the bottom
feed each checker a synthetic violation and require it to fire; run on b7492ca8 this module
fails (star imports, the 3,790-line chain module, the 1,259-line helpers module).
"""
from __future__ import annotations

import ast
import importlib
import re
import unittest
from pathlib import Path

HARNESS = Path(__file__).resolve().parent
REPO = HARNESS.parent
MODULE_LINE_LIMIT = 1200

# Modules over the limit, at their size when ARC-9's orchestrator part landed (b7492ca8 plus the
# orchestrator split; store.py and server.py at the wave-5 merge, with ARC-13 (its ledger_chain
# side table) and OPS-5).
# A module may shrink and then drops out of the table; it may not grow.
# Raise a ceiling only with the owner's say-so. The table names the next ARC-9 splits:
# store.py (repositories), server.py (APIRouters), then the rest.
OVERSIZED_CEILING = {
    "store.py": 4412,
    "coverage_model.py": 2174,
    "validators/write_integrity_validator.py": 2002,
    "api_surface_discovery.py": 1928,
    "validators/sqlmap.py": 1791,
    "browser_driver.py": 1754,
    "ollama_client.py": 1734,
    "experiment.py": 1721,
    "coverage_tracker.py": 1707,
    "run_context.py": 1706,
    "validators/business_flow_validator.py": 1514,
    "validators/auth_sequence_validator.py": 1514,
    "engagement.py": 1446,
    "validators/cross_identity_validator.py": 1381,
    "issues.py": 1226,
    "validators/api_security_validator.py": 1204,
    "iterative_agent.py": 1201,
}

_MODULE_REF = re.compile(r"^harness\.(orchestrator\w*)\.(\w+)((?:\.\w+)*)$")


def product_modules() -> list[Path]:
    """Every non-test module of the harness package."""
    return sorted(p for p in HARNESS.rglob("*.py")
                  if not p.name.startswith("test_") and "__pycache__" not in p.parts)


def files_with_tests() -> list[Path]:
    roots = [HARNESS, REPO / "testing", REPO / "evaluation_integrity"]
    return sorted(p for root in roots if root.is_dir() for p in root.rglob("test_*.py")
                  if "__pycache__" not in p.parts)


def line_count(text: str) -> int:
    return len(text.splitlines())


def star_imports(source: str) -> list[int]:
    """Line numbers of `from x import *` statements."""
    tree = ast.parse(source)
    return [n.lineno for n in ast.walk(tree)
            if isinstance(n, ast.ImportFrom) and any(a.name == "*" for a in n.names)]


def oversize(sizes: dict[str, int], ceiling: dict[str, int], limit: int = MODULE_LINE_LIMIT) -> list[str]:
    """What is wrong with the sizes: a module over the limit that is not in the ratchet,
    one that grew past its ceiling, a ratchet entry whose module is gone or now fits."""
    problems = []
    for name, n in sorted(sizes.items()):
        if n > limit and name not in ceiling:
            problems.append(f"{name}: {n} lines is over {limit} and not in OVERSIZED_CEILING")
        elif name in ceiling and n > ceiling[name]:
            problems.append(f"{name}: grew to {n} lines, ceiling {ceiling[name]}")
    for name, cap in sorted(ceiling.items()):
        if name not in sizes:
            problems.append(f"{name}: in OVERSIZED_CEILING but the module is gone")
        elif sizes[name] <= limit:
            problems.append(f"{name}: now {sizes[name]} lines; drop its OVERSIZED_CEILING entry")
    return problems


def _global_loads(tree: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(tree) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)}


def _defined_at_top(tree: ast.Module) -> set[str]:
    names = set()
    for st in tree.body:
        if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(st.name)
        elif isinstance(st, (ast.Assign, ast.AnnAssign)):
            for t in (st.targets if isinstance(st, ast.Assign) else [st.target]):
                names.update(n.id for n in ast.walk(t) if isinstance(n, ast.Name))
    return names


def _module_aliases(tree: ast.AST) -> dict[str, str]:
    """Local name -> orchestrator module it is bound to (`from harness import x as y`)."""
    aliases = {}
    for n in ast.walk(tree):
        if isinstance(n, ast.ImportFrom) and n.module == "harness":
            for a in n.names:
                if a.name.startswith("orchestrator"):
                    aliases[a.asname or a.name] = a.name
        elif isinstance(n, ast.Import):
            for a in n.names:
                if a.name.startswith("harness.orchestrator") and a.asname:
                    aliases[a.asname] = a.name.split(".")[1]
    return aliases


def _call_name(node: ast.Call) -> str:
    f = node.func
    return f.id if isinstance(f, ast.Name) else (f.attr if isinstance(f, ast.Attribute) else "")


def patch_targets(source: str) -> list[tuple[int, str, str]]:
    """(line, module, name) for each patch of an orchestrator module in a test source.

    Covers `patch("harness.orchestrator_x.name[.attr]")`, `patch.object(<module alias>, "name")`
    and `chain_patch("name")` (which targets every orchestrator_chain* module)."""
    tree = ast.parse(source)
    aliases = _module_aliases(tree)
    found = []
    for n in ast.walk(tree):
        if not isinstance(n, ast.Call):
            continue
        fn = _call_name(n)
        if fn == "chain_patch" and n.args and isinstance(n.args[0], ast.Constant):
            found.append((n.lineno, "orchestrator_chain*", n.args[0].value))
        elif fn == "patch" and n.args and isinstance(n.args[0], ast.Constant) and isinstance(n.args[0].value, str):
            m = _MODULE_REF.match(n.args[0].value)
            if m:
                found.append((n.lineno, m.group(1), m.group(2)))
        elif (fn == "object" and isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Name)
              and n.func.value.id == "patch" and len(n.args) >= 2 and isinstance(n.args[1], ast.Constant)):
            target = n.args[0]
            if isinstance(target, ast.Name) and target.id in aliases:
                found.append((n.lineno, aliases[target.id], n.args[1].value))
    return found


def unused_patch_targets(source: str, read_module) -> list[str]:
    """Patch targets whose module neither reads nor defines the name, so the patch changes nothing
    the module's own code sees (the old module after its code moved on: an import that nothing uses).

    `read_module(name)` returns the module's source, or None for a name that is not a module."""
    problems = []
    for line, module, name in patch_targets(source):
        modules = (sorted(p.stem for p in HARNESS.glob("orchestrator_chain*.py"))
                   if module == "orchestrator_chain*" else [module])
        verdicts = []
        for m in modules:
            text = read_module(m)
            if text is None:
                verdicts.append(f"harness.{m} does not exist")
                continue
            tree = ast.parse(text)
            verdicts.append(None if name in _global_loads(tree) | _defined_at_top(tree)
                            else f"harness.{m} never reads {name!r}")
        if all(v is not None for v in verdicts):
            problems.append(f"line {line}: patch of {module}.{name}: " + "; ".join(verdicts))
    return problems


def _read_module(name: str):
    path = HARNESS / f"{name}.py"
    return path.read_text(encoding="utf-8-sig") if path.is_file() else None


class StarImportTests(unittest.TestCase):
    def test_no_star_import_in_a_harness_module(self):
        offenders = {}
        for path in product_modules():
            lines = star_imports(path.read_text(encoding="utf-8-sig"))
            if lines:
                offenders[path.relative_to(HARNESS).as_posix()] = lines
        self.assertEqual(offenders, {}, "import the names a module uses explicitly")


class ModuleSizeTests(unittest.TestCase):
    def test_orchestrator_modules_stay_under_the_limit(self):
        sizes = {p.name: line_count(p.read_text(encoding="utf-8-sig")) for p in HARNESS.glob("orchestrator*.py")}
        self.assertIn("orchestrator_chain.py", sizes, sorted(sizes))  # the glob found the modules
        over = {name: n for name, n in sizes.items() if n > MODULE_LINE_LIMIT}
        self.assertEqual(over, {}, f"split a module over {MODULE_LINE_LIMIT} lines by stage")

    def test_oversized_modules_cannot_grow(self):
        sizes = {p.relative_to(HARNESS).as_posix(): line_count(p.read_text(encoding="utf-8-sig"))
                 for p in product_modules()}
        self.assertEqual(oversize(sizes, OVERSIZED_CEILING), [])

    def test_chain_patch_covers_every_chain_module_on_disk(self):
        from harness import chain_stage_patch
        on_disk = {p.stem for p in HARNESS.glob("orchestrator_chain*.py")}
        self.assertEqual(set(chain_stage_patch.CHAIN_MODULES), on_disk)


class DriverContractTests(unittest.TestCase):
    def test_the_driver_keeps_the_decorators_of_the_function_it_replaced(self):
        # The split once dropped these: the identity lease and the review-overlap reaper wrap the
        # whole engagement, so they belong on the driver, not on a stage.
        tree = ast.parse((HARNESS / "orchestrator_chain.py").read_text(encoding="utf-8-sig"))
        cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "ChainMixin")
        fn = next(n for n in cls.body if getattr(n, "name", "") == "investigate_engagement")
        self.assertEqual({ast.unparse(d) for d in fn.decorator_list},
                         {"identity_headers.leased", "review_overlap.reaps_review_overlaps"})


class PatchTargetTests(unittest.TestCase):
    def test_every_orchestrator_patch_target_is_looked_up_by_its_module(self):
        problems = {}
        for path in files_with_tests():
            if path == Path(__file__).resolve():
                continue
            source = path.read_text(encoding="utf-8-sig")
            if "orchestrator" not in source and "chain_patch" not in source:
                continue
            found = unused_patch_targets(source, _read_module)
            if found:
                problems[path.relative_to(REPO).as_posix()] = found
        self.assertEqual(problems, {}, "a patch on a module that does not read the name tests nothing")


class NegativeControlTests(unittest.TestCase):
    """Each checker must fire on a synthetic violation (the controls that give the guards meaning)."""

    def test_star_import_is_detected(self):
        self.assertEqual(star_imports("from harness.orchestrator_helpers import *  # noqa\n"), [1])
        self.assertEqual(star_imports("from harness.orchestrator_helpers import log\n"), [])

    def test_oversized_module_outside_the_ratchet_is_detected(self):
        self.assertTrue(oversize({"a.py": 1201}, {}))
        self.assertEqual(oversize({"a.py": 1200}, {}), [])

    def test_growth_past_the_ceiling_is_detected(self):
        self.assertTrue(oversize({"a.py": 1301}, {"a.py": 1300}))
        self.assertEqual(oversize({"a.py": 1300}, {"a.py": 1300}), [])

    def test_stale_ratchet_entries_are_detected(self):
        self.assertTrue(oversize({"a.py": 900}, {"a.py": 1300}))
        self.assertTrue(oversize({}, {"gone.py": 1300}))

    def test_patch_of_a_name_the_module_never_reads_is_detected(self):
        reader = {"orchestrator_x": "def f():\n    return helper()\n",
                  "orchestrator_y": "from m import helper\n\ndef g():\n    return 1\n"}
        read = reader.get
        good = 'from unittest.mock import patch\npatch("harness.orchestrator_x.helper", new=1)\n'
        bad = 'from unittest.mock import patch\npatch("harness.orchestrator_y.helper", new=1)\n'
        self.assertEqual(unused_patch_targets(good, read), [])
        self.assertEqual(len(unused_patch_targets(bad, read)), 1)

    def test_patch_object_through_a_module_alias_is_checked(self):
        read = {"orchestrator_y": "from m import helper\n"}.get
        bad = ("from unittest.mock import patch\nfrom harness import orchestrator_y as oy\n"
               'patch.object(oy, "helper", 1)\n')
        self.assertEqual(len(unused_patch_targets(bad, read)), 1)

    def test_a_patch_through_a_name_to_an_attribute_is_checked_on_the_name(self):
        read = {"orchestrator_x": "from harness import store\n\ndef f():\n    return store.put()\n"}.get
        deep = 'from unittest.mock import patch\npatch("harness.orchestrator_x.store.put", new=1)\n'
        self.assertEqual(unused_patch_targets(deep, read), [])

    def test_a_patch_of_a_missing_module_is_detected(self):
        bad = 'from unittest.mock import patch\npatch("harness.orchestrator_gone.f", new=1)\n'
        self.assertEqual(len(unused_patch_targets(bad, {}.get)), 1)

    def test_chain_patch_needs_a_chain_module_that_reads_the_name(self):
        from harness import chain_stage_patch
        with self.assertRaises(AttributeError):
            chain_stage_patch.chain_patch("a_name_no_chain_module_has")
        with chain_stage_patch.chain_patch("transport_for", new=None):
            for module in chain_stage_patch.chain_modules_with("transport_for"):
                self.assertIsNone(getattr(importlib.import_module(f"harness.{module}"), "transport_for"))
        self.assertTrue(callable(importlib.import_module("harness.orchestrator_chain").transport_for))

    def test_chain_patch_reaches_every_stage_that_uses_the_name(self):
        from harness import chain_stage_patch
        # The capture review is called from the worklist and the finish stage, the header audit
        # from the legs stage; a patch of the old module reached all of them.
        self.assertEqual(chain_stage_patch.chain_modules_with("review_captured_exchanges"),
                         ["orchestrator_chain_worklist", "orchestrator_chain_finish"])
        self.assertEqual(chain_stage_patch.chain_modules_with("universal_header_audit"),
                         ["orchestrator_chain_legs"])
        self.assertNotIn("orchestrator_chain", chain_stage_patch.chain_modules_with("review_captured_exchanges"))


if __name__ == "__main__":
    unittest.main()
