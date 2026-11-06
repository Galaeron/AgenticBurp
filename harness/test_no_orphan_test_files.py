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
CASE_BASE_MODULES = frozenset({
    'harness.coverage_evidence_case',
    'harness.test_pairing_contract',
    'harness.test_experiment_cycle',
    'harness.test_retry_rounds',
    'harness.test_role_crawl',
    'harness.test_security_headers_validator',
})


def _case_class_names(tree, seen_modules=frozenset()):
    """Prove known imported bases by reading their AST, without importing tests."""
    classes = {node.name: node for node in tree.body if isinstance(node, ast.ClassDef)}
    bindings = {}
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                bindings[alias.asname or alias.name.split('.')[0]] = (
                    alias.name if alias.asname else alias.name.split('.')[0])
        elif isinstance(node, ast.ImportFrom) and not node.level:
            for alias in node.names:
                bindings[alias.asname or alias.name] = f'{node.module}.{alias.name}'

    def dotted(node):
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            parent = dotted(node.value)
            return f'{parent}.{node.attr}' if parent else ''
        return ''

    imported = {}

    def is_case(name, seen=frozenset()):
        if name in seen:
            return False
        for base in classes[name].bases:
            name_in_source = dotted(base)
            if name_in_source in classes:
                if is_case(name_in_source, seen | {name}):
                    return True
                continue
            root, _, suffix = name_in_source.partition('.')
            qualified = bindings.get(root, '') + (f'.{suffix}' if suffix else '')
            if qualified in {'unittest.TestCase', 'unittest.IsolatedAsyncioTestCase'}:
                return True
            module, _, imported_name = qualified.rpartition('.')
            if module not in CASE_BASE_MODULES or module in seen_modules:
                continue
            if module not in imported:
                path = ROOT.joinpath(*module.split('.')).with_suffix('.py')
                imported[module] = _case_class_names(
                    ast.parse(path.read_text(encoding='utf-8-sig')), seen_modules | {module})
            if imported_name in imported[module]:
                return True
        return False

    return {name for name in classes if is_case(name)}


def discovery_issues(source: str, *, pytest_native: bool = False) -> list[str]:
    tree = ast.parse(source)
    issues = []
    classes = {n.name: n for n in tree.body if isinstance(n, ast.ClassDef)}
    case_classes = _case_class_names(tree)

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
                collected = scope.name in case_classes or (pytest_native and scope.name.startswith('Test') and node.name.startswith('test_'))
            if not collected:
                issues.append(f"uncollected test: {getattr(scope, 'name', 'module')}.{node.name}")
    if not definitions:
        issues.append('no test definitions (unittest.main() is not a test)')
    return issues


class NoOrphanTestFilesTest(unittest.TestCase):
    def test_imported_pairing_base_is_recognized_without_accepting_arbitrary_bases(self):
        source = 'from harness.test_pairing_contract import PairingCallerTests\nclass T(PairingCallerTests):\n def test_x(self): pass\n'
        self.assertEqual(discovery_issues(source), [])
        self.assertTrue(discovery_issues(source.replace('PairingCallerTests', 'ArbitraryBase')))

    def test_imported_experiment_bases_and_aliases_are_proven_statically(self):
        sources = (
            'from harness.test_experiment_cycle import _CycleCase as Base\nclass T(Base):\n def test_x(self): pass\n',
            'from harness import test_experiment_cycle as cycle\nclass T(cycle.InvestigateWiringTests):\n def test_x(self): pass\n',
            'import harness.test_experiment_cycle as cycle\nclass T(cycle._CycleCase):\n def test_x(self): pass\n',
            'from unittest import TestCase as Base\nclass T(Base):\n def test_x(self): pass\n',
        )
        for source in sources:
            with self.subTest(source=source):
                self.assertEqual(discovery_issues(source), [])

    def test_guard_rejects_imported_names_without_proven_unittest_ancestry(self):
        sources = (
            'from unknown import _CycleCase\nclass T(_CycleCase):\n def test_x(self): pass\n',
            'from harness.test_experiment_cycle import _CallerBase\nclass T(_CallerBase):\n def test_x(self): pass\n',
            'import unknown as cycle\nclass T(cycle.InvestigateWiringTests):\n def test_x(self): pass\n',
            'import unknown\nclass T(unknown.TestCase):\n def test_x(self): pass\n',
            'class A(B): pass\nclass B(A): pass\nclass T(A):\n def test_x(self): pass\n',
        )
        for source in sources:
            with self.subTest(source=source):
                self.assertTrue(discovery_issues(source))

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

    def test_ci_full_tier_uses_canonical_selections(self):
        # Rule 2: one `full` tier runs on every push/PR (the former fast-smoke /
        # full-nightly split is gone). It must reference the canonical
        # harness.suite selections (native + evaluation) rather than a
        # hand-maintained copy of the module lists, and run the whole unittest
        # discover plus the coverage gate.
        import yaml
        jobs = yaml.safe_load((ROOT / '.github/workflows/ci.yml').read_text(encoding='utf-8'))['jobs']
        scripts = [step.get('run', '').strip() for step in jobs['full']['steps']]
        self.assertIn('python -m harness.suite native', scripts)
        self.assertIn('python -m harness.suite evaluation', scripts)
        self.assertTrue(any('unittest discover -t . -s harness' in s for s in scripts),
                        'full tier must run the whole unittest discover')
        self.assertTrue(any('coverage_manifest --check' in s for s in scripts),
                        'full tier must run the coverage gate')

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
        ]) as run, patch('builtins.print'), \
             patch('harness.verification_snapshot.preflight'):
            self.assertEqual(suite.main(['full']), 1)
            self.assertEqual(run.call_count, 5)

    def test_runner_success_and_dry_run(self):
        with patch.object(suite.subprocess, 'run', return_value=SimpleNamespace(returncode=0)) as run, patch('builtins.print'), \
             patch('harness.verification_snapshot.preflight'):
            self.assertEqual(suite.main(['native']), 0)
            self.assertEqual(run.call_count, 1)
            run.reset_mock()
            self.assertEqual(suite.main(['full', '--list']), 0)
            run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
