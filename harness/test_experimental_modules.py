"""ARC-10: a library-only module is marked, so nobody mistakes it for an enforced control.

Seven modules had no production importer: `execution_planes` reads like an enforced
control but is only a record. Each one that is still not imported by production code
must say so: an `EXPERIMENTAL = True` constant and an "EXPERIMENTAL" line in its
docstring. Wiring one in later (then it has an importer) or deleting it are owner
decisions; this test only makes sure the state is stated, not hidden.

Controls: a module with neither an importer nor the marker fails the check, and so does a
marker that is only half there; a module with a production importer passes without one.
"""
import ast
import functools
import importlib
import os
import unittest

import harness

ARC10_MODULES = ("execution_planes", "report_share", "work_queue", "provider_trace",
                 "mcp_adapter", "fix_verifier", "rag_retriever")

_ROOT = os.path.dirname(os.path.abspath(harness.__file__))


def _production_files():
    for dirpath, dirnames, filenames in os.walk(_ROOT):
        dirnames[:] = [d for d in dirnames if d not in ("__pycache__", "testing")]
        for fn in filenames:
            if fn.endswith(".py") and not fn.startswith("test_"):
                yield os.path.join(dirpath, fn)


@functools.lru_cache(maxsize=None)
def _tree_of(path: str):
    """The parsed AST of an on-disk production file (None if unreadable)."""
    try:
        with open(path, encoding="utf-8") as f:
            return ast.parse(f.read())
    except (OSError, UnicodeDecodeError, SyntaxError):
        return None


def production_importers(module: str, overrides: dict | None = None) -> list[str]:
    """Production files (not tests, not the module itself) that import `harness.<module>`,
    found from the AST: `import harness.m`, `from harness import m`, `from harness.m
    import x`, a relative form, or `import_module("harness.m")`. `overrides` maps a
    path to replacement source (used by the controls)."""
    overrides = overrides or {}
    own = os.path.join(_ROOT, module + ".py")
    found = []
    on_disk = list(_production_files())
    paths = on_disk + [p for p in overrides if p not in set(on_disk)]
    for path in paths:
        if os.path.abspath(path) == own:
            continue
        text = overrides.get(path)
        if text is None:
            tree = _tree_of(path)
        else:
            try:
                tree = ast.parse(text)
            except SyntaxError:
                tree = None
        if tree is None:
            continue
        for node in ast.walk(tree):
            hit = False
            if isinstance(node, ast.Import):
                hit = any(a.name == f"harness.{module}" for a in node.names)
            elif isinstance(node, ast.ImportFrom):
                if node.module == f"harness.{module}":
                    hit = True
                elif node.module == "harness" or (node.level and not node.module):
                    hit = any(a.name == module for a in node.names)
                elif node.level and node.module == module:
                    hit = True
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                hit = node.value == f"harness.{module}"     # import_module("harness.m")
            if hit:
                found.append(os.path.relpath(path, _ROOT).replace(os.sep, "/"))
                break
    return sorted(found)


def marker_problems(module: str, *, source: str | None = None,
                    overrides: dict | None = None) -> list[str]:
    """What is wrong with `module`'s ARC-10 state; [] when it has a production importer
    or carries the full marker. `source` replaces the module's own text (controls)."""
    if production_importers(module, overrides):
        return []
    if source is None:
        with open(os.path.join(_ROOT, module + ".py"), encoding="utf-8") as f:
            source = f.read()
    tree = ast.parse(source)
    doc = ast.get_docstring(tree) or ""
    has_constant = any(
        isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "EXPERIMENTAL"
                                          for t in n.targets)
        and isinstance(n.value, ast.Constant) and n.value.value is True
        for n in tree.body)
    problems = []
    if "EXPERIMENTAL" not in doc:
        problems.append("the docstring has no EXPERIMENTAL header")
    if not has_constant:
        problems.append("there is no module-level EXPERIMENTAL = True")
    return problems


class ExperimentalMarkerTests(unittest.TestCase):
    def test_every_listed_module_has_a_production_importer_or_the_marker(self):
        for module in ARC10_MODULES:
            self.assertEqual(
                marker_problems(module), [],
                f"harness/{module}.py has no production importer and is not marked "
                f"experimental (ARC-10): wire it in, or add the marker")

    def test_the_marker_is_real_at_runtime(self):
        for module in ARC10_MODULES:
            if production_importers(module):
                continue
            mod = importlib.import_module(f"harness.{module}")
            self.assertIs(mod.EXPERIMENTAL, True, module)
            self.assertIn("EXPERIMENTAL", mod.__doc__, module)

    def test_the_importer_scan_sees_each_import_form(self):
        fake = os.path.join(_ROOT, "zz_fake_importer.py")
        for text in ("import harness.work_queue\n", "from harness import work_queue\n",
                     "from harness.work_queue import WorkItem\n", "from . import work_queue\n",
                     "import importlib\nimportlib.import_module('harness.work_queue')\n"):
            self.assertIn("zz_fake_importer.py", production_importers("work_queue", {fake: text}), text)
        self.assertEqual(production_importers("work_queue", {fake: "import harness.store\n"}), [])

    # ---- negative controls ----
    def test_control_an_unmarked_library_module_fails(self):
        """A module with no importer and no marker is reported (the pre-fix state)."""
        with open(os.path.join(_ROOT, "work_queue.py"), encoding="utf-8") as f:
            text = f.read()
        stripped = text.replace("EXPERIMENTAL = True", "").replace("EXPERIMENTAL", "")
        self.assertEqual(sorted(marker_problems("work_queue", source=stripped)),
                         ["the docstring has no EXPERIMENTAL header",
                          "there is no module-level EXPERIMENTAL = True"])

    def test_control_half_a_marker_fails(self):
        with open(os.path.join(_ROOT, "work_queue.py"), encoding="utf-8") as f:
            text = f.read()
        no_const = text.replace("EXPERIMENTAL = True", "")
        self.assertEqual(marker_problems("work_queue", source=no_const),
                         ["there is no module-level EXPERIMENTAL = True"])

    def test_control_a_production_importer_needs_no_marker(self):
        fake = os.path.join(_ROOT, "zz_fake_importer.py")
        self.assertEqual(
            marker_problems("work_queue", source='"""no header"""\n',
                            overrides={fake: "from harness import work_queue\n"}), [])


if __name__ == "__main__":
    unittest.main()
