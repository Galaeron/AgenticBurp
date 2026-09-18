"""
Tripwire: no test file may run in NO tier.

The root cause of this project's recurring "green tests, dead pipeline" scare has a
CI-shaped sibling: a test file that `python -m unittest discover` cannot collect
(module-level `def test_*` functions and pytest fixtures instead of a
`unittest.TestCase`) silently contributes ZERO tests to the unittest suite. Three
files had drifted into exactly that state -- ~48 tests, including a security test
(`test_prompt_injection_is_data`) and one that was actually FAILING on a stale
import path -- running in no CI tier at all.

Those files are now run explicitly via pytest in both CI tiers (see
.github/workflows/ci.yml, the "pytest-native tests" step). This test makes the
arrangement self-enforcing: every `harness/test_*.py` must be EITHER
unittest-collectable OR listed in `_PYTEST_NATIVE_CI` below. Add a new
pytest-native file? This test fails until you also add it to that CI step and to
this list -- so a test file can never again quietly run nowhere.
"""
from __future__ import annotations

import ast
import unittest
from pathlib import Path

_HARNESS = Path(__file__).resolve().parent

# Files intentionally written in pytest style (module-level test functions /
# fixtures). unittest's discover cannot collect these, so CI runs them explicitly
# via `python -m pytest` (both the fast and nightly tiers). KEEP THIS IN SYNC with
# the "pytest-native tests" step in .github/workflows/ci.yml.
_PYTEST_NATIVE_CI = {
    "test_plugin_system.py",
    "test_execution_protocol.py",
    "test_hardening.py",
}


def _is_unittest_collectable(path: Path) -> bool:
    """True if `python -m unittest discover` would collect at least one test from
    this file: a class deriving (directly or indirectly by name) from TestCase, or
    an explicit `unittest.main()` entrypoint. Parsed statically -- no import side
    effects, and robust to files that need optional deps to import."""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="ignore"))
    except SyntaxError:
        return True  # a syntax error is a different, louder failure -- not our concern
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            for base in node.bases:
                name = base.attr if isinstance(base, ast.Attribute) else getattr(base, "id", "")
                if "TestCase" in (name or ""):
                    # must also actually contain a test_* method
                    if any(isinstance(b, ast.FunctionDef) and b.name.startswith("test")
                           for b in node.body):
                        return True
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == "main"
                and isinstance(node.func.value, ast.Name) and node.func.value.id == "unittest"):
            return True
    return False


class NoOrphanTestFilesTest(unittest.TestCase):
    def test_every_test_file_runs_in_some_tier(self):
        orphans = []
        for path in sorted(_HARNESS.glob("test_*.py")):
            if path.name == Path(__file__).name:
                continue
            if path.name in _PYTEST_NATIVE_CI:
                continue
            if not _is_unittest_collectable(path):
                orphans.append(path.name)
        self.assertEqual(
            orphans, [],
            "These test files are NOT collectable by `unittest discover` and are NOT in "
            "the pytest-native CI allowlist, so they run in NO tier -- the silent "
            "'dead test' gap. Either give them a unittest.TestCase (and unittest.main), "
            "or add them to the 'pytest-native tests' step in .github/workflows/ci.yml "
            f"AND to _PYTEST_NATIVE_CI in this file: {orphans}")

    def test_pytest_native_allowlist_is_not_stale(self):
        """Every file we claim is pytest-native must still exist and still be
        pytest-native -- so the allowlist can't rot into hiding a real orphan."""
        for name in sorted(_PYTEST_NATIVE_CI):
            path = _HARNESS / name
            self.assertTrue(path.exists(), f"allowlisted pytest file {name} no longer exists")
            self.assertFalse(
                _is_unittest_collectable(path),
                f"{name} is now unittest-collectable; remove it from _PYTEST_NATIVE_CI "
                "(and the pytest CI step no longer needs to name it)")


if __name__ == "__main__":
    unittest.main()
