"""Static proof that the h1 splits moved code verbatim.

For each top-level statement of the original module (git show 44bfda57) and each method of a
split class, find the statement that now defines the same thing (the facade or a moved module),
read `<alias>.X` back as `X` for the patched names, and require identical ASTs. Also: nothing lost,
nothing defined twice, nothing new except the mixin classes, the kept statements of the facade
in the original order, and no alias read outside the patched-name set.

Run from the repo root:  python verify_split.py coverage_model|coverage_tracker|api_surface_discovery [...]
Exit 0 only when every module verifies.
"""
from __future__ import annotations

import ast
import copy
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from split_lib import HARNESS, git_original  # noqa: E402

CONFIG = {
    "coverage_model": {
        "modules": ["coverage_model_cells", "coverage_model_checks", "coverage_model_catalog"],
        "alias": None, "rewrite": set(), "classes": {},
    },
    "coverage_tracker": {
        "modules": ["coverage_tracker_tables", "coverage_tracker_matrix", "coverage_tracker_drive",
                    "coverage_tracker_report"],
        "alias": "_ct",
        "rewrite": {"time", "REQUEST_LEVEL_INPUTS", "_LEG_STATUS", "_LEG_STATUS_UNKNOWN", "_fair_cells",
                    "_time_fair_cells", "_listed_in_compact_ledger", "log"},
        "classes": {"CoverageTracker": ["_MatrixMixin", "_DriveMixin", "_ReportMixin"]},
    },
    "api_surface_discovery": {
        "modules": ["api_surface_data", "api_surface_sensitive", "api_surface_probe", "api_surface_walk",
                    "api_surface_mining"],
        "alias": "_asd",
        "rewrite": {"_host_in_scope", "sensitive_file_verdict"},
        "classes": {"SurfaceDiscovery": ["_ProbeMixin", "_WalkMixin", "_MiningMixin"]},
    },
}


def key_of(st: ast.stmt):
    if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return ("def", st.name)
    if isinstance(st, ast.ClassDef):
        return ("class", st.name)
    if isinstance(st, (ast.Assign, ast.AnnAssign)):
        ts = st.targets if isinstance(st, ast.Assign) else [st.target]
        return ("assign", tuple(n.id for t in ts for n in ast.walk(t) if isinstance(n, ast.Name)))
    return ("stmt", ast.dump(st))


def is_boilerplate(st: ast.stmt) -> bool:
    return isinstance(st, (ast.Import, ast.ImportFrom)) or (
        isinstance(st, ast.Expr) and isinstance(st.value, ast.Constant) and isinstance(st.value.value, str))


class Unalias(ast.NodeTransformer):
    def __init__(self, alias, names):
        self.alias, self.names, self.count, self.foreign = alias, names, 0, []

    def visit_Attribute(self, node):
        self.generic_visit(node)
        if self.alias and isinstance(node.value, ast.Name) and node.value.id == self.alias:
            if node.attr in self.names:
                self.count += 1
                return ast.copy_location(ast.Name(id=node.attr, ctx=node.ctx), node)
            self.foreign.append(node.attr)
        return node


def numbered(stmts):
    seen, out = {}, []
    for st in stmts:
        k = key_of(st)
        n = seen.get(k, 0)
        seen[k] = n + 1
        out.append(((k, n), st))
    return out


def dump(node) -> str:
    return ast.dump(node, include_attributes=False)


def strip_members(cls: ast.ClassDef, moved: set[str]) -> ast.ClassDef:
    c = copy.deepcopy(cls)
    c.body = [m for m in c.body if not (isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))
                                         and m.name in moved)]
    c.bases = []
    return c


def verify(name: str) -> list[str]:
    cfg = CONFIG[name]
    orig = ast.parse(git_original(f"harness/{name}.py"))
    problems: list[str] = []
    new_trees = {m: ast.parse((HARNESS / f"{m}.py").read_text(encoding="utf-8")) for m in [name] + cfg["modules"]}
    un = Unalias(cfg["alias"], cfg["rewrite"])

    # every moved/kept top-level statement of the new modules
    new_defs, facade_order = {}, []
    for m, tree in new_trees.items():
        for kn, st in numbered([s for s in tree.body if not is_boilerplate(s)]):
            if m == name:
                facade_order.append(kn)
            if kn in new_defs:
                problems.append(f"{kn} defined in both {new_defs[kn][0]} and {m}")
            new_defs[kn] = (m, st)

    # the mixin members, flattened to (class, method)
    mixin_of: dict[tuple[str, str], tuple[str, ast.AST]] = {}
    mixin_class_keys = set()
    for cls, mixins in cfg["classes"].items():
        for m in cfg["modules"]:
            for st in new_trees[m].body:
                if isinstance(st, ast.ClassDef) and st.name in mixins:
                    mixin_class_keys.add((("class", st.name), 0))
                    for mem in st.body:
                        if isinstance(mem, (ast.FunctionDef, ast.AsyncFunctionDef)):
                            if (cls, mem.name) in mixin_of:
                                problems.append(f"method {cls}.{mem.name} defined in two mixins")
                            mixin_of[(cls, mem.name)] = (m, mem)
                        elif not (isinstance(mem, ast.Expr) and isinstance(mem.value, ast.Constant)):
                            problems.append(f"{st.name} has a non-method member {ast.unparse(mem)[:60]}")

    compared = methods = 0
    claimed = set()
    kept_order = []
    for kn, st in numbered([s for s in orig.body if not is_boilerplate(s)]):
        got = new_defs.get(kn)
        if got is None:
            problems.append(f"lost: {kn}")
            continue
        claimed.add(kn)
        module, new = got
        if isinstance(st, ast.ClassDef) and st.name in cfg["classes"]:
            moved = {mem.name for (c, mem_name), (_, mem) in mixin_of.items() if c == st.name
                     for mem in [mem]}
            o_cls = strip_members(st, moved)
            n_cls = strip_members(copy.deepcopy(new), set())
            if dump(un.visit(copy.deepcopy(o_cls))) != dump(un.visit(copy.deepcopy(n_cls))):
                problems.append(f"changed: class {st.name} (members kept in the facade)")
            if module != name:
                problems.append(f"class {st.name} left the facade")
            # every original method: kept (compared above) or moved
            for mem in st.body:
                if isinstance(mem, (ast.FunctionDef, ast.AsyncFunctionDef)) and mem.name in moved:
                    mm, new_m = mixin_of[(st.name, mem.name)]
                    methods += 1
                    if dump(un.visit(copy.deepcopy(mem))) != dump(un.visit(copy.deepcopy(new_m))):
                        problems.append(f"changed: {st.name}.{mem.name} in {mm}")
            extra = {m for (c, m) in mixin_of if c == st.name} - {m.name for m in st.body
                                                                  if isinstance(m, (ast.FunctionDef,
                                                                                    ast.AsyncFunctionDef))}
            if extra:
                problems.append(f"methods that are not in the original {st.name}: {sorted(extra)}")
            # the bases name exactly the mixins
            bases = [ast.unparse(b) for b in new.bases]
            if bases != cfg["classes"][st.name]:
                problems.append(f"{st.name} bases {bases} != {cfg['classes'][st.name]}")
            compared += 1
        else:
            if dump(un.visit(copy.deepcopy(st))) != dump(un.visit(copy.deepcopy(new))):
                problems.append(f"changed: {kn} in {module}")
            compared += 1
        if module == name:
            kept_order.append(kn)

    extra = set(new_defs) - claimed - mixin_class_keys
    if extra:
        problems.append(f"new top-level statements: {sorted(extra)}")
    if [k for k in facade_order if k in set(kept_order)] != kept_order:
        problems.append("the facade's kept statements are not in the original order")
    if un.foreign:
        problems.append(f"alias read of a name outside the patched set: {sorted(set(un.foreign))}")
    print(f"{name}: compared {compared} top-level statements and {methods} moved methods; "
          f"{un.count} alias reads undone; {len(mixin_class_keys)} mixin classes")
    return problems


if __name__ == "__main__":
    names = sys.argv[1:] or list(CONFIG)
    bad = 0
    for n in names:
        probs = verify(n)
        print("PROBLEMS:", probs if probs else "none")
        bad += bool(probs)
    sys.exit(1 if bad else 0)
