"""Refresh the blind-test-kit's bundled harness/ copy from the real package.

The kit vendors a copy of harness/ so it can be handed to a blind tester as a
self-contained package. That copy drifts: see HARNESS_IS_STALE.md. Run this to
overwrite the fork with the current repo harness/ before a run that must reflect
shipped code.

IMPORTANT: the current harness uses absolute imports (`from harness import ...`),
so after syncing, harness_driver.py must add THIS kit directory (the parent of
harness/) to sys.path and import `from harness import ...` -- not insert harness/
itself and `import <module>`. If the driver still uses bare imports, either fix
it or drive the real package from a full checkout instead of this isolated kit.
"""
from __future__ import annotations

import shutil
import sys
from pathlib import Path

KIT_DIR = Path(__file__).resolve().parent
REPO_HARNESS = KIT_DIR.parent.parent / "harness"
DEST = KIT_DIR / "harness"

_SKIP_DIRS = {"__pycache__", ".pytest_cache"}
_SKIP_SUFFIXES = {".pyc", ".db", ".lock", ".log"}


def _ignore(_dir, names):
    return [n for n in names
            if n in _SKIP_DIRS or any(n.endswith(s) for s in _SKIP_SUFFIXES)]


def main() -> int:
    if not REPO_HARNESS.is_dir():
        print(f"repo harness/ not found at {REPO_HARNESS}", file=sys.stderr)
        return 1
    if DEST.exists():
        shutil.rmtree(DEST)
    shutil.copytree(REPO_HARNESS, DEST, ignore=_ignore)
    n = sum(1 for _ in DEST.rglob("*.py"))
    print(f"synced {n} .py files from {REPO_HARNESS} -> {DEST}")
    print("Reminder: ensure harness_driver.py imports `from harness import ...` "
          "with the kit dir (not harness/) on sys.path -- see HARNESS_IS_STALE.md.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
