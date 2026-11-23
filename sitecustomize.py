# Test-environment hook. This file is tracked, and it is not packaged: pyproject.toml ships only
# `harness*`, so an installed copy of the harness has no sitecustomize.
#
# Python imports a module called `sitecustomize` at startup when its directory is on the import path.
# This one is found when the repository root is on PYTHONPATH: `python -m harness.suite` exports its own
# sys.path to every test child process it starts from the root, and `PYTHONPATH=<worktree>` does it by hand.
# It drops the editable-install finders, so a module missing from this checkout fails with ImportError here
# instead of loading from the other checkout a venv's `pip install -e .` points at.
#
# So tests run through it see a stricter import environment than an installed package or a plain
# `python -m harness.server` from a shell without PYTHONPATH. See "Import isolation" in docs/TESTING.md.
# `harness.verification_snapshot` writes its own, stricter sitecustomize into a snapshot; this is not that file.
import sys
sys.meta_path[:] = [f for f in sys.meta_path if "Editable" not in getattr(f, "__name__", "")]
sys.path_hooks[:] = [h for h in sys.path_hooks if "Editable" not in getattr(h, "__name__", "")]
