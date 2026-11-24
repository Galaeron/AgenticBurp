"""Shared machinery for the ARC-9 h1 splits (coverage_model, coverage_tracker, api_surface_discovery).

The splits are generated from the original module at BASE_REV (git show), so they are
reproducible and the moved code is copied, never retyped:

  * a top-level statement moves with the comment block directly above it;
  * a class is split by moving whole methods into mixin classes (`class Facade(MixinA, MixinB)`);
  * a name the original module owns and tests patch is read through the facade at call time:
    every bare read of it in moved code becomes `<alias>.<name>` (alias imported last);
  * imports of every moved module are derived from the names its code reads (symtable), so none
    is retyped either.

verify_split.py proves the result is the same code (AST comparison with the alias undone).
"""
from __future__ import annotations

import ast
import builtins
import subprocess
import symtable
from dataclasses import dataclass, field
from pathlib import Path

BASE_REV = "44bfda57"
REPO = Path(__file__).resolve().parents[3]
HARNESS = REPO / "harness"
LINE_LIMIT = 98


def git_original(relpath: str) -> str:
    raw = subprocess.check_output(["git", "-C", str(REPO), "show", f"{BASE_REV}:{relpath}"])
    return raw.decode("utf-8").replace("\r\n", "\n")


def write_crlf(path: Path, text: str) -> None:
    if not text.endswith("\n"):
        text += "\n"
    with open(path, "w", encoding="utf-8", newline="\r\n") as fh:
        fh.write(text)


@dataclass
class Piece:
    """One verbatim span of the original: leading comment block plus the statement."""
    text: str
    blanks: int                       # blank lines the original had before it (capped by assemble)
    defined: tuple[str, ...] = ()
    key: str = ""


def _targets(st) -> list[str]:
    names = []
    if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        names.append(st.name)
    elif isinstance(st, (ast.Assign, ast.AnnAssign)):
        for t in (st.targets if isinstance(st, ast.Assign) else [st.target]):
            names += [n.id for n in ast.walk(t) if isinstance(n, ast.Name)]
    elif isinstance(st, ast.For):
        names += [n.id for n in ast.walk(st.target) if isinstance(n, ast.Name)]
    return names


class Orig:
    def __init__(self, relpath: str):
        self.rel = relpath
        self.text = git_original(relpath)
        self.lines = self.text.split("\n")
        self.tree = ast.parse(self.text)
        self.body = self.tree.body
        self.imports: dict[str, ast.stmt] = {}
        self.future = False
        for st in self.body:
            if isinstance(st, ast.ImportFrom) and st.module == "__future__":
                self.future = True
            elif isinstance(st, (ast.Import, ast.ImportFrom)):
                for a in st.names:
                    self.imports[(a.asname or a.name).split(".")[0]] = st
        self.symtab = symtable.symtable(self.text, relpath, "exec")

    # -- spans -------------------------------------------------------------------------------
    @staticmethod
    def start(node) -> int:
        decos = getattr(node, "decorator_list", None) or []
        return min([node.lineno] + [d.lineno for d in decos])

    def _piece(self, node, prev_end: int) -> Piece:
        start = self.start(node)
        first = prev_end + 1
        while first < start and self.lines[first - 1].strip() == "":
            first += 1
        blanks = first - (prev_end + 1)
        text = "\n".join(self.lines[first - 1:node.end_lineno])
        return Piece(text=text, blanks=blanks, defined=tuple(_targets(node)),
                     key=f"{self.rel}:{start}")

    def top_pieces(self) -> list[tuple[ast.stmt, Piece]]:
        out, prev = [], 0
        for st in self.body:
            if isinstance(st, (ast.Import, ast.ImportFrom)) or (
                    isinstance(st, ast.Expr) and isinstance(st.value, ast.Constant)
                    and isinstance(st.value.value, str)):
                prev = st.end_lineno
                continue
            out.append((st, self._piece(st, prev)))
            prev = st.end_lineno
        return out

    def piece_at(self, line: int) -> tuple[ast.stmt, Piece]:
        for st, pc in self.top_pieces():
            if self.start(st) == line or st.lineno == line:
                return st, pc
        raise KeyError(f"no top-level statement starts at line {line}")

    def pieces_in(self, a: int, b: int) -> list[tuple[ast.stmt, Piece]]:
        return [(st, pc) for st, pc in self.top_pieces() if a <= self.start(st) <= b]

    def cls(self, name: str) -> ast.ClassDef:
        return next(s for s in self.body if isinstance(s, ast.ClassDef) and s.name == name)

    def members(self, name: str) -> list[tuple[ast.stmt, Piece]]:
        c = self.cls(name)
        assert self.lines[c.lineno - 1].rstrip().endswith(":"), "multi-line class header"
        out, prev = [], c.lineno
        for st in c.body:
            out.append((st, self._piece(st, prev)))
            prev = st.end_lineno
        return out

    # -- scopes ------------------------------------------------------------------------------
    def module_symbols(self) -> set[str]:
        return {s.get_name() for s in self.symtab.get_symbols()}


def _all_tables(tab):
    yield tab
    for ch in tab.get_children():
        yield from _all_tables(ch)


def external_names(body_text: str) -> set[str]:
    """Names the code reads from module scope that it neither defines nor gets from builtins."""
    top = symtable.symtable(body_text, "<module>", "exec")
    defined = {s.get_name() for s in top.get_symbols()
               if s.is_assigned() or s.is_imported() or s.is_namespace()}
    need = set()
    for tab in _all_tables(top):
        for s in tab.get_symbols():
            if s.is_global() and s.is_referenced():
                need.add(s.get_name())
            elif tab is top and s.is_referenced() and not (s.is_assigned() or s.is_imported()
                                                          or s.is_namespace()):
                need.add(s.get_name())
    return {n for n in need - defined
            if not hasattr(builtins, n) and not (n.startswith("__") and n.endswith("__"))}


def shadowed_names(body_text: str, names: set[str]) -> set[str]:
    """Names in `names` that some scope of the text binds locally (a rewrite there would be wrong)."""
    top = symtable.symtable(body_text, "<module>", "exec")
    hit = set()
    for tab in _all_tables(top):
        if tab is top:
            continue
        for s in tab.get_symbols():
            if s.get_name() in names and (s.is_local() or s.is_parameter()) and not s.is_global():
                hit.add(s.get_name())
    return hit


def rewrite_reads(piece_text: str, names: set[str], alias: str) -> tuple[str, int]:
    """`name` -> `alias.name` for every bare Name read of a name in `names`."""
    if not names:
        return piece_text, 0
    src = piece_text
    try:
        tree = ast.parse(src)
    except SyntaxError:
        tree = ast.parse("class _W:\n" + src)      # a method (indented) cannot parse alone
        src = "class _W:\n" + src
        wrapped = True
    else:
        wrapped = False
    lines = src.split("\n")
    edits = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Name) and n.id in names:
            if not isinstance(n.ctx, ast.Load):
                raise ValueError(f"{n.id} is assigned or deleted in moved code (line {n.lineno})")
            edits.append((n.lineno, n.col_offset, n.id))
    for lineno, col, ident in sorted(edits, reverse=True):
        raw = lines[lineno - 1].encode("utf-8")
        assert raw[col:col + len(ident)] == ident.encode("utf-8")
        lines[lineno - 1] = (raw[:col] + (alias + ".").encode("utf-8") + raw[col:]).decode("utf-8")
    out = "\n".join(lines)
    if wrapped:
        out = out.split("\n", 1)[1]
    return out, len(edits)


# ------------------------------------------------------------------------------------------------
@dataclass
class ModuleSpec:
    name: str                          # harness.<name>
    doc: str
    pieces: list = field(default_factory=list)       # list[(label, [Piece...])]
    rewrite: set = field(default_factory=set)
    alias_import: str = ""             # e.g. "from harness import coverage_tracker as _ct"
    alias: str = "_ct"
    mixins: list = field(default_factory=list)       # [(MixinName, doc, [member Pieces])]

    # filled by the planner
    defined: set = field(default_factory=set)
    rewrites_made: int = 0


def format_from_import(module: str, names: list[str], noqa: str = "") -> str:
    one = f"from {module} import {', '.join(names)}{noqa}"
    if len(one) <= LINE_LIMIT:
        return one
    lines = [f"from {module} import ({noqa}"]
    cur = "   "
    for n in names:
        piece = f" {n},"
        if len(cur) + len(piece) > LINE_LIMIT:
            lines.append(cur)
            cur = "   "
        cur += piece
    lines.append(cur)
    lines[-1] = lines[-1].rstrip(",") + ","
    lines.append(")")
    return "\n".join(lines)


def import_lines(orig: Orig, needed: set[str], siblings: dict[str, str], exclude: set[str] = frozenset(),
                 self_name: str = "") -> list[str]:
    """Import statements for `needed`: original imports (kept as the original wrote them) and
    sibling modules' names."""
    std: dict[str, list[str]] = {}          # module -> names
    plain: list[str] = []
    harness_from: dict[str, list[str]] = {}
    for name in sorted(needed - set(exclude)):
        if name in siblings and siblings[name] != self_name:
            harness_from.setdefault(f"harness.{siblings[name]}", []).append(name)
            continue
        st = orig.imports.get(name)
        if st is None:
            raise KeyError(f"{self_name or 'module'}: cannot resolve `{name}`")
        if isinstance(st, ast.Import):
            for a in st.names:
                if (a.asname or a.name).split(".")[0] == name:
                    plain.append(f"import {a.name}" + (f" as {a.asname}" if a.asname else ""))
        else:
            for a in st.names:
                if (a.asname or a.name) == name:
                    spelled = a.name + (f" as {a.asname}" if a.asname else "")
                    target = harness_from if st.module.startswith("harness") else std
                    target.setdefault(st.module, []).append(spelled)
    out = sorted(set(plain))
    for mod in sorted(std):
        out.append(format_from_import(mod, sorted(std[mod])))
    first_party = []
    for mod in sorted(harness_from):
        first_party.append(format_from_import(mod, sorted(harness_from[mod])))
    return out + ([""] if out and first_party else []) + first_party


def _join(blocks: list[Piece]) -> str:
    text = ""
    for i, pc in enumerate(blocks):
        if i:
            text += "\n" * (min(pc.blanks, 2) + 1)
        text += pc.text
    return text


def render_module(orig: Orig, spec: ModuleSpec, siblings: dict[str, str], extra_header: str = "") -> str:
    """The whole text of one moved module."""
    blocks: list[Piece] = []
    for label, pcs in spec.pieces:
        for pc in pcs:
            text, n = rewrite_reads(pc.text, spec.rewrite, spec.alias)
            spec.rewrites_made += n
            blocks.append(Piece(text=text, blanks=pc.blanks, defined=pc.defined, key=pc.key))
    for mname, mdoc, members in spec.mixins:
        mp = [Piece(text=rewrite_reads(m.text, spec.rewrite, spec.alias)[0], blanks=min(m.blanks, 1))
              for m in members]
        spec.rewrites_made += sum(rewrite_reads(m.text, spec.rewrite, spec.alias)[1] for m in members)
        head = f'class {mname}:\n    """{mdoc}"""\n'
        body = head + "\n" + _join_members(mp)
        blocks.append(Piece(text=body, blanks=2, defined=(mname,)))
    body_text = _join(blocks)
    bad = shadowed_names(body_text, spec.rewrite)
    if bad:
        raise ValueError(f"{spec.name}: rewritten names are locals somewhere: {sorted(bad)}")
    need = external_names(body_text)
    if spec.alias:
        need.discard(spec.alias)
    imports = import_lines(orig, need, siblings, self_name=spec.name)
    parts = [f'"""{spec.doc}"""']
    if orig.future:
        parts.append("from __future__ import annotations")
    head = "\n".join(parts)
    imp = "\n".join(imports)
    text = head + ("\n\n" + imp if imp else "") + "\n\n\n" + body_text.lstrip("\n")
    if spec.alias_import:
        text += "\n\n\n" + spec.alias_import + "  # noqa: E402"
    return text


def _join_members(pieces: list[Piece]) -> str:
    out = ""
    for i, p in enumerate(pieces):
        if i:
            out += "\n" * (p.blanks + 1)
        out += p.text
    return out


def render_facade(orig: Orig, moved_tops: set[str], moved_members: dict[str, set[str]],
                  bases: dict[str, list[str]], addendum: str, reexports: dict[str, list[str]],
                  mixin_imports: dict[str, list[str]], extra_need: set[str] = frozenset()) -> str:
    """The original module with the moved statements and methods taken out and the imports of
    the moved names put in their place."""
    kept_blocks: list[Piece] = []
    for st, pc in orig.top_pieces():
        if pc.key in moved_tops:
            continue
        if isinstance(st, ast.ClassDef) and st.name in moved_members:
            header = f"class {st.name}({', '.join(bases[st.name])}):"
            kept = [(m, p) for m, p in orig.members(st.name)
                    if not (isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))
                            and m.name in moved_members[st.name])]
            body = _join_members([Piece(text=p.text, blanks=min(p.blanks, 1)) for _, p in kept])
            # keep the comment block above the class with the class
            lead = pc.text.split("\n")
            idx = next(i for i, ln in enumerate(lead) if ln.startswith("class "))
            text = "\n".join(lead[:idx] + [header]) + "\n" + body
            kept_blocks.append(Piece(text=text, blanks=pc.blanks, defined=pc.defined, key=pc.key))
        else:
            kept_blocks.append(pc)
    body_text = _join(kept_blocks)
    reexported = {n for names in reexports.values() for n in names}
    reexported |= {n for names in mixin_imports.values() for n in names}
    need = external_names(body_text) | {b for bs in bases.values() for b in bs} | set(extra_need)
    imports = import_lines(orig, need - reexported, {}, self_name="facade")
    first_party = []
    for mod in sorted(reexports):
        first_party.append(format_from_import(f"harness.{mod}", sorted(reexports[mod]), "  # noqa: F401"))
    for mod in sorted(mixin_imports):
        first_party.append(format_from_import(f"harness.{mod}", sorted(mixin_imports[mod])))
    # the original module docstring, extended
    doc_node = orig.body[0]
    assert isinstance(doc_node, ast.Expr) and isinstance(doc_node.value, ast.Constant)
    doc_lines = orig.lines[:doc_node.end_lineno]
    assert doc_lines[-1].strip() == '"""', doc_lines[-1]
    doc_text = "\n".join(doc_lines[:-1]) + "\n" + addendum.rstrip("\n") + "\n" + doc_lines[-1]
    parts = [doc_text]
    if orig.future:
        parts.append("from __future__ import annotations")
    out = "\n".join(parts)
    if imports:
        out += "\n\n" + "\n".join(imports)
    joint = "\n" if imports and imports[-1].startswith("from harness") else "\n\n"
    out += joint + "\n".join(first_party) + "\n\n\n" + body_text.lstrip("\n")
    return out
