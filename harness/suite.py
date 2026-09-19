"""Canonical local/CI test selections; execution tiers do not prove model accuracy."""
from __future__ import annotations
import argparse
import os
from pathlib import Path
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parent.parent
SMOKE_MODULES = (
    'harness.test_smoke_detection', 'harness.test_smoke_investigate',
    'harness.test_smoke_shape_precondition', 'harness.test_smoke_authorization_workflow',
    'harness.test_smoke_phase0_capture_review', 'harness.test_mass_assignment_slice',
    'harness.test_open_redirect_slice', 'harness.test_coverage_manifest',
    'harness.test_pipeline_gate', 'harness.test_no_orphan_test_files',
    'harness.test_async_test_hygiene',
)
PYTEST_NATIVE = (
    'harness/test_plugin_system.py', 'harness/test_execution_protocol.py',
    'harness/test_hardening.py',
)


def commands(tier: str) -> list[list[str]]:
    native = ['-m', 'pytest', '-q', *PYTEST_NATIVE]
    coverage_gate = ['-m', 'harness.coverage_manifest', '--check']
    evaluation = [
        ['-m', 'unittest', 'discover', '-s', 'testing', '-p', 'test_*.py'],
        ['-m', 'unittest', 'discover', '-s', 'evaluation_integrity/tests', '-p', 'test_*.py'],
    ]
    if tier == 'native':
        return [native]
    if tier == 'evaluation':
        return evaluation
    if tier == 'smoke':
        return [['-m', 'unittest', *SMOKE_MODULES], coverage_gate]
    if tier == 'full':
        return [['-m', 'unittest', 'discover', '-t', '.', '-s', 'harness', '-p', 'test_*.py'], coverage_gate, native, *evaluation]
    raise ValueError(f'Unknown test tier: {tier}')


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('tier', choices=('smoke', 'native', 'evaluation', 'full'))
    parser.add_argument('--list', action='store_true', help='Print commands without running tests')
    args = parser.parse_args(argv)
    failed = False
    # Isolate suites while preserving the caller's explicit import environment.
    env = os.environ.copy()
    # Local runs must not reuse evidence merely because Git HEAD is unchanged.
    env.setdefault('COVERAGE_RUN_ID', 'local-' + uuid.uuid4().hex)
    env['PYTHONPATH'] = os.pathsep.join(str(Path(p or '.').resolve()) for p in sys.path)
    for command in commands(args.tier):
        print(subprocess.list2cmdline([sys.executable, *command]), flush=True)
        if not args.list:
            result = subprocess.run([sys.executable, *command], cwd=ROOT, env=env)
            failed |= result.returncode != 0
    return int(failed)


if __name__ == '__main__':
    raise SystemExit(main())
