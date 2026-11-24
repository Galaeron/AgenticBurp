"""List every name that code or tests patch or assign on the three ARC-9 h1 modules.

For each .py file under harness/, testing/, tools/, evaluation_integrity/ it resolves the
module aliases (`from harness import m as a`, `import harness.m as a`, `import harness.m`),
then reports:
  patch.object(<alias>, "name")      patch("harness.m.name")      patch.dict(<alias>.name ...)
  setattr(<alias>, "name", ...)      <alias>.name = ...           monkeypatch.setattr(...)
Run from the repository root: python find_patch_targets.py [module ...]
"""
from __future__ import annotations

import ast
import sys
from collections import defaultdict
from pathlib import Path

MODULES = sys.argv[1:] or ["coverage_model", "coverage_tracker", "api_surface_discovery"]
ROOTS = ["harness", "testing", "tools", "evaluation_integrity"]


def aliases(tree: ast.AST) -> dict[str, str]:
    out = {}
    for n in ast.walk(tree):
        if isinstance(n, ast.ImportFrom) and n.module == "harness":
            for a in n.names:
                if a.name in MODULES:
                    out[a.asname or a.name] = a.name
        elif isinstance(n, ast.Import):
            for a in n.names:
                if a.name.startswith("harness.") and a.name.split(".")[1] in MODULES and a.name.count(".") == 1:
                    out[a.asname or a.name] = a.name.split(".")[1]
    return out


def attr_chain(node) -> str | None:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def const_str(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return "".join(v.value if isinstance(v, ast.Constant) else "{}" for v in node.values)
    return None


def main() -> int:
    hits = defaultdict(set)   # (module, name) -> {"file:line form"}
    for root in ROOTS:
        for path in sorted(Path(root).rglob("*.py")):
            if "__pycache__" in path.parts:
                continue
            try:
                tree = ast.parse(path.read_text(encoding="utf-8-sig"))
            except (SyntaxError, UnicodeDecodeError):
                continue
            al = aliases(tree)

            def record(mod, name, node, form):
                hits[(mod, name)].add(f"{path.as_posix()}:{node.lineno} {form}")

            def resolve_target(expr):
                chain = attr_chain(expr)
                if chain is None:
                    return None
                if chain in al:
                    return al[chain]
                for m in MODULES:
                    if chain == f"harness.{m}":
                        return m
                return None

            for n in ast.walk(tree):
                if isinstance(n, ast.Call):
                    fn = attr_chain(n.func) or ""
                    last = fn.rsplit(".", 1)[-1]
                    if fn.endswith("patch.object") or fn.endswith("monkeypatch.setattr") or fn == "setattr":
                        if len(n.args) >= 2:
                            mod = resolve_target(n.args[0])
                            name = const_str(n.args[1])
                            if mod and name:
                                record(mod, name, n, "patch.object")
                    elif fn.endswith("patch") or fn.endswith("patch.dict") or fn.endswith("patch.multiple"):
                        if n.args:
                            s = const_str(n.args[0])
                            if s and s.startswith("harness."):
                                parts = s.split(".")
                                if len(parts) >= 3 and parts[1] in MODULES:
                                    record(parts[1], ".".join(parts[2:]), n, "patch(str)")
                            elif fn.endswith("patch.dict") and n.args:
                                chain = attr_chain(n.args[0])
                                if chain and "." in chain:
                                    head, _, tail = chain.partition(".")
                                    if head in al:
                                        record(al[head], tail, n, "patch.dict")
                elif isinstance(n, (ast.Assign, ast.AugAssign)):
                    for t in (n.targets if isinstance(n, ast.Assign) else [n.target]):
                        if isinstance(t, ast.Attribute):
                            mod = resolve_target(t.value)
                            if mod:
                                record(mod, t.attr, n, "assign")
    for (mod, name), where in sorted(hits.items()):
        w = sorted(where)
        print(f"{mod}.{name}: {len(w)} site(s), e.g. {w[0]}")
    if not hits:
        print("no patch targets found")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
