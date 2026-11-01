"""Create an inventoried, fresh verification checkout without editable-import fallback."""
from __future__ import annotations
import argparse
import hashlib
import importlib.abc
import importlib.machinery
import importlib.metadata
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

INVENTORY = 'verification-inventory.json'
# Exact safe test infrastructure only; copy bytes without inspecting target labels.
SAFE_TARGET_TEST_FILES = (
    'testing/blind-target-2/run_blind_eval.py',
    'testing/blind-target-2/blind_eval_exchanges.json',
)
REQUIRED = (
    'harness/suite.py', 'harness/verification_snapshot.py',
    'harness/test_verification_snapshot.py', 'harness/requirements.lock',
    'testing/passive_study_summary.py', 'testing/test_passive_study_summary.py',
    'testing/run_web_objective_smoke.py', 'testing/test_run_web_objective_auth.py',
    'testing/test_web_objective_benchmark.py',
    'testing/test_remediation_scoring_eligibility.py',
    'testing/web-objective-benchmark/manifest.json',
    *SAFE_TARGET_TEST_FILES,
)
PACKAGES = {'pytest': 'pytest', 'httpx': 'httpx', 'yaml': 'PyYAML',
            'pydantic': 'pydantic', 'fastapi': 'fastapi', 'flask': 'Flask',
            'mitmproxy': 'mitmproxy'}
LOCAL_PACKAGES = ('harness', 'testing', 'evaluation_integrity')


class SnapshotError(ValueError):
    pass


def exclusion(name: str) -> str:
    parts = Path(name).parts
    lower = name.lower().replace('\\', '/')
    if 'answerkey' in re.sub('[^a-z0-9]', '', lower):
        return 'forbidden answer key'
    if lower.endswith('/app.py') and lower.startswith('testing/'):
        return 'target implementation'
    if any(p.lower() in ('.git', '.test-work', '.venv', '__pycache__', 'archive', 'reviews',
                          'node_modules', '.pytest_cache', '.audit-external') for p in parts):
        return 'generated or historical directory'
    if (lower not in SAFE_TARGET_TEST_FILES
            and any(p.lower().startswith(('blind-target', 'vulncorp-', 'run-')) for p in parts)):
        return 'target or run artifacts'
    if lower.endswith(('.db', '.db-wal', '.db-shm', '.sqlite', '.sqlite3', '.log', '.pyc')):
        return 'runtime artifact'
    if Path(name).name.lower() in ('.env', 'config.local.yaml', 'sitecustomize.py', INVENTORY):
        return 'local configuration or generated inventory'
    return ''


def _file(root: Path, relative: str) -> Path:
    path = root / relative
    if Path(relative).is_absolute() or '..' in Path(relative).parts or not path.resolve().is_relative_to(root.resolve()):
        raise SnapshotError(f'Unsafe inventory path: {relative}')
    if path.is_symlink():
        raise SnapshotError(f'Symlink is not a reproducible source file: {relative}')
    return path


def _digest(path: Path) -> str:
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def preflight(root: Path, *, dependencies: bool = True) -> None:
    root = root.resolve()
    for name in REQUIRED:
        if not _file(root, name).is_file():
            raise SnapshotError(f'Missing verification dependency: {name}')
    marker = root / INVENTORY
    if marker.exists():
        inventory = json.loads(marker.read_text(encoding='utf-8'))
        for name, expected in inventory['files'].items():
            if exclusion(name):
                raise SnapshotError(f'Excluded file in inventory: {name}')
            path = _file(root, name)
            if not path.is_file():
                raise SnapshotError(f'Missing snapshot file: {name}')
            if _digest(path) != expected:
                raise SnapshotError(f'Snapshot source changed: {name}')
        # No reuse of a previous snapshot's runtime state. Create a new snapshot.
        for folder in ('harness', 'runtime'):
            for path in (root / folder).rglob('*'):
                if path.is_file() and re.search(r'\.(?:db|sqlite3?)(?:-wal|-shm)?$', path.name):
                    raise SnapshotError(f'Snapshot runtime database is not fresh: {path.relative_to(root)}')
    if dependencies:
        for module in PACKAGES:
            if importlib.util.find_spec(module) is None:
                raise SnapshotError(f'Missing test dependency {module}: see harness/requirements.lock')


class _LocalOnly(importlib.abc.MetaPathFinder):
    def __init__(self, root):
        self.root = Path(root).resolve()

    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] not in LOCAL_PACKAGES:
            return None
        locations = [str(self.root)] if path is None else [
            p for p in path if Path(p).resolve().is_relative_to(self.root)]
        spec = importlib.machinery.PathFinder.find_spec(fullname, locations)
        if spec is None:
            raise ModuleNotFoundError(f'Snapshot missing local module: {fullname}', name=fullname)
        return spec


def isolate_imports(root: Path) -> None:
    """Fail closed before another path or editable finder can supply local code."""
    root = root.resolve()
    for name, module in tuple(sys.modules.items()):
        if name.split('.')[0] in LOCAL_PACKAGES:
            origin = getattr(module, '__file__', None)
            if origin and not Path(origin).resolve().is_relative_to(root):
                raise SnapshotError(f'Local import escaped snapshot: {name}: {origin}')
    sys.meta_path[:] = [f for f in sys.meta_path if 'Editable' not in getattr(f, '__name__', '')]
    sys.path_hooks[:] = [h for h in sys.path_hooks if 'Editable' not in getattr(h, '__name__', '')]
    sys.meta_path.insert(0, _LocalOnly(root))


def create(source: Path, destination: Path, *, include=()) -> dict:
    source, destination = source.resolve(), destination.absolute()
    if destination.exists():
        raise SnapshotError(f'Snapshot destination already exists: {destination}')
    names = subprocess.check_output(['git', '-C', str(source), 'ls-files', '-z']).decode().split('\0')
    names = sorted(set(filter(None, names)) | set(REQUIRED) | set(include))
    selected, excluded = [], {}
    for name in names:
        reason = exclusion(name)
        if reason:
            if name in include or name in REQUIRED:
                raise SnapshotError(f'Cannot include {name}: {reason}')
            excluded[name] = reason
            continue
        if not _file(source, name).is_file():
            raise SnapshotError(f'Missing source inventory file: {name}')
        selected.append(name)
    preflight(source, dependencies=False)
    destination.mkdir(parents=True)
    hashes = {}
    for name in selected:
        origin, target = _file(source, name), destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        # Includes the benchmark manifest as opaque bytes: never parse or print labels.
        before = _digest(origin)
        shutil.copyfile(origin, target)
        hashes[name] = _digest(target)
        if hashes[name] != before or _digest(origin) != before:
            raise SnapshotError(f'Source changed while copying: {name}')
    for name, expected in hashes.items():
        if _digest(_file(source, name)) != expected:
            raise SnapshotError(f'Source changed during snapshot creation: {name}')
    payload = json.dumps(hashes, sort_keys=True).encode()
    inventory = {'schema': 1, 'source': str(source),
                 'source_revision': subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD']).decode().strip(),
                 'source_hash': hashlib.sha256(payload).hexdigest(),
                 'creation_interpreter': {'executable': sys.executable, 'version': sys.version},
                 'dependencies': {d: importlib.metadata.version(d) for d in PACKAGES.values()
                                  if importlib.util.find_spec(next(k for k,v in PACKAGES.items() if v == d))},
                 'files': hashes, 'excluded': excluded}
    (destination / INVENTORY).write_text(json.dumps(inventory, indent=2), encoding='utf-8')
    (destination / 'sitecustomize.py').write_text(
        'import importlib.util, os, sys\nfrom pathlib import Path\n'
        'try:\n'
        '    root = Path(__file__).resolve().parent\n'
        '    spec = importlib.util.spec_from_file_location("_snapshot_guard", root / "harness/verification_snapshot.py")\n'
        '    guard = importlib.util.module_from_spec(spec)\n'
        '    spec.loader.exec_module(guard)\n'
        '    guard.isolate_imports(root)\n'
        'except BaseException as error:\n'
        '    print("Snapshot import guard failed: " + str(error), file=sys.stderr, flush=True)\n'
        '    os._exit(2)\n', encoding='utf-8')
    preflight(destination, dependencies=False)
    return inventory


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('create', 'check'))
    parser.add_argument('--source', type=Path, default=Path.cwd())
    parser.add_argument('--destination', type=Path)
    parser.add_argument('--include', action='append', default=[])
    args = parser.parse_args(argv)
    try:
        if args.action == 'create':
            if args.destination is None:
                parser.error('--destination is required for create')
            result = create(args.source, args.destination, include=args.include)
            print(f"Snapshot: {args.destination}; files={len(result['files'])}; source_hash={result['source_hash']}")
        else:
            preflight(args.source)
            print(f'Verification preflight passed: {args.source.resolve()} ({sys.executable})')
    except (SnapshotError, OSError) as error:
        print(f'Verification preflight failed: {error}', file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
