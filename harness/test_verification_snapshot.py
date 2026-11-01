"""Caller controls for reproducible verification copies; synthetic sources only."""
import contextlib
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from harness import suite
from harness import verification_snapshot as snapshot


class VerificationSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.source = self.root / 'source'
        self.source.mkdir()
        for name in snapshot.REQUIRED:
            path = self.source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'')
        (self.source / 'harness/__init__.py').write_text('')
        (self.source / 'harness/verification_snapshot.py').write_bytes(Path(snapshot.__file__).read_bytes())
        (self.source / 'testing/synthetic.py').write_text('VALUE = 42\n')
        self.tracked = [*snapshot.REQUIRED, 'harness/__init__.py', 'testing/synthetic.py']
        self.dest = self.root / 'snapshot'

    def create(self, **kwargs):
        def git(args):
            return ('\0'.join(self.tracked) + '\0').encode() if 'ls-files' in args else b'synthetic-revision\n'
        with patch.object(snapshot.subprocess, 'check_output', side_effect=git):
            return snapshot.create(self.source, self.dest, **kwargs)

    def test_missing_dependency_fails_before_copy_by_filename(self):
        name = 'testing/web-objective-benchmark/manifest.json'
        (self.source / name).unlink()
        with self.assertRaisesRegex(snapshot.SnapshotError, name):
            self.create()
        self.assertFalse(self.dest.exists())

    def test_create_records_exact_content_and_excludes_runtime_and_keys(self):
        for name in ('harness/old.db', 'harness/config.local.yaml', 'testing/AnSwEr_KeY.txt',
                     'testing/blind-target/app.py'):
            path = self.source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('synthetic excluded file')
            self.tracked.append(name)
        result = self.create()
        self.assertEqual(result['source_revision'], 'synthetic-revision')
        self.assertIn('testing/web-objective-benchmark/manifest.json', result['files'])
        self.assertEqual(len(result['source_hash']), 64)
        for name in result['excluded']:
            self.assertFalse((self.dest / name).exists())
        snapshot.preflight(self.dest, dependencies=False)
        with self.assertRaisesRegex(snapshot.SnapshotError, 'already exists'):
            self.create()

    def test_only_exact_safe_target_test_dependencies_are_copied(self):
        forbidden = ('testing/blind-target-2/app.py',
                     'testing/blind-target-2/AnSwEr_KeY.json',
                     'testing/blind-target-2/other_runner.py')
        self.tracked.extend(forbidden)
        # Forbidden paths need not exist: selection excludes them before any read.
        result = self.create()
        for name in snapshot.SAFE_TARGET_TEST_FILES:
            self.assertIn(name, result['files'])
            self.assertEqual((self.dest / name).read_bytes(), b'')
        for name in forbidden:
            self.assertIn(name, result['excluded'])
            self.assertFalse((self.dest / name).exists())

    def test_missing_safe_runner_or_fixture_fails_preflight_by_filename(self):
        for name in snapshot.SAFE_TARGET_TEST_FILES:
            with self.subTest(name=name):
                path = self.source / name
                path.unlink()
                with self.assertRaisesRegex(snapshot.SnapshotError, name):
                    snapshot.preflight(self.source, dependencies=False)
                path.write_bytes(b'')

    def test_changed_source_and_stale_runtime_fail_preflight(self):
        self.create()
        target = self.dest / 'testing/synthetic.py'
        target.write_text('VALUE = 99\n')
        with self.assertRaisesRegex(snapshot.SnapshotError, 'testing/synthetic.py'):
            snapshot.preflight(self.dest, dependencies=False)
        target.write_text('VALUE = 42\n')
        (self.dest / 'harness/harness_state.db').touch()
        with self.assertRaisesRegex(snapshot.SnapshotError, 'harness_state.db'):
            snapshot.preflight(self.dest, dependencies=False)

    def test_required_asset_removal_fails_before_any_suite_subprocess(self):
        self.create()
        (self.dest / 'testing/passive_study_summary.py').unlink()
        with patch.object(suite, 'ROOT', self.dest), patch.object(suite.subprocess, 'run') as run:
            with contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                self.assertEqual(suite.main(['full']), 2)
            run.assert_not_called()
        self.assertIn('testing/passive_study_summary.py', diagnostic.getvalue())

    def test_missing_external_dependency_names_requirements(self):
        with patch.object(snapshot.importlib.util, 'find_spec', return_value=None):
            with self.assertRaisesRegex(snapshot.SnapshotError, 'pytest.*harness/requirements.lock'):
                snapshot.preflight(self.source)

    def test_include_is_explicit_and_cannot_escape_or_include_keys(self):
        with self.assertRaisesRegex(snapshot.SnapshotError, 'Unsafe inventory path'):
            self.create(include=['../outside.py'])
        with self.assertRaisesRegex(snapshot.SnapshotError, 'forbidden answer key'):
            self.create(include=['testing/answer_key.json'])

    def test_subprocess_cannot_fall_back_to_parent_namespace_package(self):
        self.create()
        (self.source / 'testing/parent_only.py').write_text('VALUE = "parent-leak"\n')
        env = dict(os.environ, PYTHONPATH=os.pathsep.join((str(self.dest), str(self.source))))
        def run(code, *flags):
            return subprocess.run([sys.executable, *flags, '-c', code], cwd=self.dest,
                                  env=env, capture_output=True, text=True, timeout=15)
        good = run('from testing.synthetic import VALUE; print(VALUE)')
        self.assertEqual(good.returncode, 0, good.stderr)
        self.assertEqual(good.stdout.strip(), '42')
        bad = run('from testing.parent_only import VALUE; print(VALUE)')
        self.assertNotEqual(bad.returncode, 0)
        self.assertIn('Snapshot missing local module: testing.parent_only', bad.stderr)
        self.assertNotIn('parent-leak', bad.stdout)
        # Defect injection: disable bootstrap; ordinary namespace lookup leaks.
        mutant = run('from testing.parent_only import VALUE; print(VALUE)', '-S')
        self.assertEqual(mutant.returncode, 0, mutant.stderr)
        self.assertEqual(mutant.stdout.strip(), 'parent-leak')

    def test_missing_guard_fails_closed_at_interpreter_start(self):
        self.create()
        (self.dest / 'harness/verification_snapshot.py').unlink()
        env = dict(os.environ, PYTHONPATH=str(self.dest))
        result = subprocess.run([sys.executable, '-c', 'print("MUST NOT RUN")'], cwd=self.dest,
                                env=env, capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 2)
        self.assertNotIn('MUST NOT RUN', result.stdout)
        self.assertIn('verification_snapshot.py', result.stderr)


if __name__ == '__main__':
    unittest.main()
