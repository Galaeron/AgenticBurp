"""Guard discovery and CI selections; a main() call is not a collected test.

Static checks are conservative. Runtime discovery remains the authority.
"""
from __future__ import annotations
import ast
from collections import Counter
from pathlib import Path
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from harness import suite
from harness.suite import PYTEST_NATIVE, SMOKE_MODULES, commands

ROOT = Path(__file__).resolve().parent.parent


def discovery_issues(source: str, *, pytest_native: bool = False) -> list[str]:
    tree = ast.parse(source)
    issues = []
    classes = {n.name: n for n in tree.body if isinstance(n, ast.ClassDef)}
    # Explicit imported bases used by this repository, not substring matching.
    bases = {'TestCase', 'IsolatedAsyncioTestCase', 'EvidenceCase'}
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and node.module == 'unittest':
            bases.update(n.asname or n.name for n in node.names if n.name in bases)

    def is_case(node, seen=frozenset()):
        if node.name in seen:
            return False
        for base in node.bases:
            name = base.attr if isinstance(base, ast.Attribute) else getattr(base, 'id', '')
            if name in bases or (name in classes and is_case(classes[name], seen | {node.name})):
                return True
        return False

    definitions = 0
    for scope in [tree, *classes.values()]:
        names = Counter(n.name for n in scope.body
                        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)))
        for name, count in names.items():
            if count > 1:
                issues.append(f"shadowed definition: {getattr(scope, 'name', 'module')}.{name}")
        for node in scope.body:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) or not node.name.startswith('test'):
                continue
            definitions += 1
            if scope is tree:
                collected = pytest_native and node.name.startswith('test_')
            else:
                collected = is_case(scope) or (pytest_native and scope.name.startswith('Test') and node.name.startswith('test_'))
            if not collected:
                issues.append(f"uncollected test: {getattr(scope, 'name', 'module')}.{node.name}")
    if not definitions:
        issues.append('no test definitions (unittest.main() is not a test)')
    return issues


class NoOrphanTestFilesTest(unittest.TestCase):
    def test_every_definition_has_a_runner(self):
        errors = []
        for path in sorted((ROOT / 'harness').glob('test_*.py')):
            rel = path.relative_to(ROOT).as_posix()
            errors.extend(f'{rel}: {issue}' for issue in discovery_issues(
                path.read_text(encoding='utf-8-sig'), pytest_native=rel in PYTEST_NATIVE))
        self.assertEqual(errors, [])

    def test_selections_exist_and_are_unique(self):
        self.assertEqual(len(PYTEST_NATIVE), len(set(PYTEST_NATIVE)))
        self.assertEqual(len(SMOKE_MODULES), len(set(SMOKE_MODULES)))
        for rel in [*PYTEST_NATIVE, *(m.replace('.', '/') + '.py' for m in SMOKE_MODULES)]:
            self.assertTrue((ROOT / rel).is_file(), rel)
        for rel in PYTEST_NATIVE:
            self.assertTrue(discovery_issues((ROOT / rel).read_text(encoding='utf-8')),
                            f'{rel} no longer needs pytest selection')

    def test_ci_uses_canonical_selections_in_both_tiers(self):
        import yaml
        jobs = yaml.safe_load((ROOT / '.github/workflows/ci.yml').read_text(encoding='utf-8'))['jobs']
        for name in ('fast', 'nightly'):
            scripts = [step.get('run', '').strip() for step in jobs[name]['steps']]
            self.assertIn('python -m harness.suite native', scripts, name)
            self.assertIn('python -m harness.suite evaluation', scripts, name)
        self.assertIn('python -m harness.suite smoke', [s.get('run', '').strip() for s in jobs['fast']['steps']])
        self.assertTrue(any('unittest discover -t . -s harness' in s.get('run', '') for s in jobs['nightly']['steps']))

    def test_full_includes_unittest_native_and_evaluation(self):
        full = commands('full')
        self.assertIn('discover', full[0])
        self.assertIn(['-m', 'harness.coverage_manifest', '--check'], full)
        self.assertIn(['-m', 'harness.coverage_manifest', '--check'], commands('smoke'))
        for command in commands('native') + commands('evaluation'):
            self.assertIn(command, full)

    def test_guard_rejects_empty_entrypoint_and_fake_case(self):
        for source in ('import unittest\nunittest.main()', 'class FakeTestCase: pass\nclass T(FakeTestCase):\n def test_x(self): pass'):
            with self.subTest(source=source):
                self.assertTrue(discovery_issues(source))

    def test_guard_catches_mixed_style_and_shadowed_tests(self):
        source = 'import unittest\nclass T(unittest.TestCase):\n def test_x(self): pass\n def test_x(self): pass\ndef test_lost(): pass\n'
        issues = discovery_issues(source)
        self.assertTrue(any('shadowed' in s for s in issues))
        self.assertTrue(any('test_lost' in s for s in issues))
        self.assertFalse(any('test_lost' in s for s in discovery_issues(source, pytest_native=True)))

    def test_guard_accepts_inherited_async_and_pytest_tests(self):
        source = 'import unittest\nclass Base(unittest.IsolatedAsyncioTestCase): pass\nclass T(Base):\n async def test_x(self): pass\n'
        self.assertEqual(discovery_issues(source), [])
        self.assertEqual(discovery_issues('def test_x(): pass', pytest_native=True), [])

    def test_runner_keeps_failures_even_when_later_groups_pass(self):
        with patch.object(suite.subprocess, 'run', side_effect=[
            SimpleNamespace(returncode=1), SimpleNamespace(returncode=0),
            SimpleNamespace(returncode=0), SimpleNamespace(returncode=0),
            SimpleNamespace(returncode=0),
        ]) as run, patch('builtins.print'):
            self.assertEqual(suite.main(['full']), 1)
            self.assertEqual(run.call_count, 5)

    def test_runner_success_and_dry_run(self):
        with patch.object(suite.subprocess, 'run', return_value=SimpleNamespace(returncode=0)) as run, patch('builtins.print'):
            self.assertEqual(suite.main(['native']), 0)
            self.assertEqual(run.call_count, 1)
            run.reset_mock()
            self.assertEqual(suite.main(['full', '--list']), 0)
            run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
