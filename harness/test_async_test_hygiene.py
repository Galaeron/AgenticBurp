"""
Meta-test / lint (W-5): an `async def test_*` only actually executes under an
async-capable base class (unittest.IsolatedAsyncioTestCase). In a plain
unittest.TestCase, calling the method returns an un-awaited coroutine and the
test is reported as PASSED without running a single assertion -- the exact bug
that left the circuit breaker effectively untested behind green CI.

This scans every test module in the harness and fails if that pattern is
present, so the whole class of "green but never executed" async tests cannot
silently come back. It also flags module-level `async def test_*` functions,
which the project's `python -m unittest discover` runner does not collect at
all (they need pytest-asyncio, which this project does not configure).
"""
import ast
import pathlib
import unittest

# Bases that actually run `async def test_*` methods. A subclass of one of
# these is resolved transitively within the same module below.
ASYNC_CAPABLE_BASES = {"IsolatedAsyncioTestCase"}

HERE = pathlib.Path(__file__).parent


def _base_names(cls: ast.ClassDef):
    names = []
    for b in cls.bases:
        if isinstance(b, ast.Attribute):
            names.append(b.attr)
        elif isinstance(b, ast.Name):
            names.append(b.id)
    return names


def scan_source(source: str, filename: str = "<string>"):
    """
    Return (class_violations, module_level_async_tests) for one source string.

    class_violations: list of (classname, bases, [async_test_method_names])
        for classes that define async test methods but are not derived from an
        async-capable base.
    module_level_async_tests: list of function names defined at module scope.
    """
    tree = ast.parse(source, filename=filename)
    local_bases = {
        n.name: _base_names(n)
        for n in ast.walk(tree)
        if isinstance(n, ast.ClassDef)
    }

    def is_async_capable(clsname, seen=None):
        seen = seen or set()
        if clsname in seen:
            return False
        seen.add(clsname)
        bases = local_bases.get(clsname, [])
        if any(b in ASYNC_CAPABLE_BASES for b in bases):
            return True
        # Resolve locally-defined base classes transitively.
        return any(is_async_capable(b, seen) for b in bases if b in local_bases)

    class_violations = []
    module_level = []
    for node in tree.body:
        if isinstance(node, ast.AsyncFunctionDef) and node.name.startswith("test_"):
            module_level.append(node.name)
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            async_tests = [
                m.name
                for m in node.body
                if isinstance(m, ast.AsyncFunctionDef) and m.name.startswith("test_")
            ]
            if async_tests and not is_async_capable(node.name):
                class_violations.append((node.name, _base_names(node), async_tests))
    return class_violations, module_level


class TestAsyncTestHygiene(unittest.TestCase):
    def test_no_async_test_in_non_async_capable_class(self):
        offenders = []
        for path in sorted(HERE.glob("test_*.py")):
            violations, _ = scan_source(path.read_text(encoding="utf-8"), path.name)
            for classname, bases, methods in violations:
                offenders.append(
                    f"{path.name}::{classname}(bases={bases}) has async tests "
                    f"{methods} but is not an IsolatedAsyncioTestCase -- these "
                    f"pass without executing."
                )
        self.assertEqual(
            offenders,
            [],
            "async test methods that never actually run:\n" + "\n".join(offenders),
        )

    def test_no_module_level_async_tests(self):
        offenders = []
        for path in sorted(HERE.glob("test_*.py")):
            _, module_level = scan_source(path.read_text(encoding="utf-8"), path.name)
            for name in module_level:
                offenders.append(f"{path.name}::{name}")
        self.assertEqual(
            offenders,
            [],
            "module-level async test functions are not collected by "
            "`unittest discover`:\n" + "\n".join(offenders),
        )

    def test_scanner_catches_a_deliberately_misplaced_async_test(self):
        """The guard must actually fire on the bad pattern (acceptance check)."""
        bad = (
            "import unittest\n"
            "class Bad(unittest.TestCase):\n"
            "    async def test_thing(self):\n"
            "        assert False\n"
        )
        violations, _ = scan_source(bad)
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0][0], "Bad")
        self.assertIn("test_thing", violations[0][2])

    def test_scanner_accepts_isolated_asyncio_and_local_subclasses(self):
        good = (
            "import unittest\n"
            "class Base(unittest.IsolatedAsyncioTestCase):\n"
            "    pass\n"
            "class Derived(Base):\n"
            "    async def test_thing(self):\n"
            "        pass\n"
            "class Direct(unittest.IsolatedAsyncioTestCase):\n"
            "    async def test_other(self):\n"
            "        pass\n"
        )
        violations, module_level = scan_source(good)
        self.assertEqual(violations, [])
        self.assertEqual(module_level, [])

    def test_scanner_flags_module_level_async_test(self):
        bad = "async def test_orphan():\n    pass\n"
        _, module_level = scan_source(bad)
        self.assertEqual(module_level, ["test_orphan"])


if __name__ == "__main__":
    unittest.main()
