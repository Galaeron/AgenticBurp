"""Every name any caller or test uses from the three h1 modules must still be on the module.

Scans harness/, testing/, tools/, evaluation_integrity/ (and .test-work/ scripts) for
  from harness.<m> import a, b          from harness import <m> [as x]  -> x.name
  import harness.<m> [as x]             "harness.<m>.name" strings (patch targets, importlib)
and checks hasattr(module, name) for each, plus that every top-level name the original module
defined (def, class, assignment) is still there. Run from the repo root with PYTHONPATH set:
    python check_callers.py [module ...]
Exit 1 if any name is missing.
"""
from __future__ import annotations

import ast
import importlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from split_lib import git_original  # noqa: E402

MODULES = sys.argv[1:] or ["coverage_model", "coverage_tracker", "api_surface_discovery"]
ROOTS = ["harness", "testing", "tools", "evaluation_integrity", ".test-work"]


def used_names(mods) -> dict[str, dict[str, set[str]]]:
    used = {m: {} for m in mods}
    for root in ROOTS:
        for path in sorted(Path(root).rglob("*.py")):
            if "__pycache__" in path.parts or ".claude" in path.parts:
                continue
            try:
                text = path.read_text(encoding="utf-8-sig")
                tree = ast.parse(text)
            except (SyntaxError, UnicodeDecodeError, OSError):
                continue
            alias = {}
            for n in ast.walk(tree):
                if isinstance(n, ast.ImportFrom):
                    if n.module == "harness":
                        for a in n.names:
                            if a.name in mods:
                                alias[a.asname or a.name] = a.name
                    elif n.module and n.module.startswith("harness.") and n.module.split(".")[1] in mods \
                            and n.module.count(".") == 1:
                        for a in n.names:
                            used[n.module.split(".")[1]].setdefault(a.name, set()).add(path.as_posix())
                elif isinstance(n, ast.Import):
                    for a in n.names:
                        if a.name.startswith("harness.") and a.name.split(".")[1] in mods and a.name.count(".") == 1:
                            alias[a.asname or a.name] = a.name.split(".")[1]
                elif isinstance(n, ast.Constant) and isinstance(n.value, str) and n.value.startswith("harness."):
                    parts = n.value.split(".")
                    if len(parts) >= 3 and parts[1] in mods:
                        used[parts[1]].setdefault(parts[2], set()).add(path.as_posix())
            for n in ast.walk(tree):
                if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and n.value.id in alias:
                    used[alias[n.value.id]].setdefault(n.attr, set()).add(path.as_posix())
                elif (isinstance(n, ast.Call) and len(n.args) >= 2 and isinstance(n.args[0], ast.Name)
                      and n.args[0].id in alias and isinstance(n.args[1], ast.Constant)
                      and isinstance(n.args[1].value, str)):
                    # patch.object(alias, "name"), setattr(alias, "name", ...), getattr(alias, "name")
                    used[alias[n.args[0].id]].setdefault(n.args[1].value, set()).add(path.as_posix())
    return used


def original_names(m: str) -> set[str]:
    out = set()
    for st in ast.parse(git_original(f"harness/{m}.py")).body:
        if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            out.add(st.name)
        elif isinstance(st, (ast.Assign, ast.AnnAssign)):
            for t in (st.targets if isinstance(st, ast.Assign) else [st.target]):
                out |= {n.id for n in ast.walk(t) if isinstance(n, ast.Name)}
        elif isinstance(st, ast.For):
            out |= {n.id for n in ast.walk(st.target) if isinstance(n, ast.Name)}
    return out


def original_imports(m: str) -> set[str]:
    out = set()
    for st in ast.parse(git_original(f"harness/{m}.py")).body:
        if isinstance(st, (ast.Import, ast.ImportFrom)) and not (
                isinstance(st, ast.ImportFrom) and st.module == "__future__"):
            out |= {(a.asname or a.name).split(".")[0] for a in st.names}
    return out


def main() -> int:
    bad = 0
    used = used_names(set(MODULES))
    for m in MODULES:
        mod = importlib.import_module(f"harness.{m}")
        missing_used = sorted(n for n in used[m] if not hasattr(mod, n) and n not in ("__file__",))
        missing_defs = sorted(n for n in original_names(m) if not hasattr(mod, n))
        gone_imports = sorted(n for n in original_imports(m) if not hasattr(mod, n))
        print(f"{m}: {len(used[m])} names used by callers, {len(original_names(m))} original definitions; "
              f"missing used={missing_used or 'none'} missing definitions={missing_defs or 'none'}")
        print(f"    original imports no longer on the module (not used by any caller): {gone_imports or 'none'}")
        bad += bool(missing_used or missing_defs)
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
