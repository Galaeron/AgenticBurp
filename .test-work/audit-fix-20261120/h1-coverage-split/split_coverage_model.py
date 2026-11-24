"""Generate the coverage_model split from harness/coverage_model.py at BASE_REV.

    coverage_model_cells    Phase, CellStatus, CellResult, CaseKey, input-case derivation   (data model)
    coverage_model_checks   applicability predicates, ExternalRef, Check                    (check model)
    coverage_model_catalog  CHECK_CATALOG, the caller-independent set, CHECKS_BY_ID         (the table)
    coverage_model          the facade: ids and aliases (it owns REUSED_LEGACY_IDS and reads
                            is_current_wstg_id, both patched), the import guard, CHECKS_BY_PHASE,
                            CoverageMatrix; re-exports every moved name.

No patched name is read by moved code (the readers stay in the facade), so the siblings import
each other directly and there is no alias.
Run from the repo root: python .test-work/audit-fix-20261120/h1-coverage-split/split_coverage_model.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from split_lib import HARNESS, ModuleSpec, Orig, render_facade, render_module, write_crlf  # noqa: E402

ORIG = Orig("harness/coverage_model.py")
SPLIT_NOTE = ("Part of the ARC-9 split of harness.coverage_model. Import these names from\n"
              "harness.coverage_model, the facade, not from this module.")


def spec(name, doc, lo, hi):
    pieces = [pc for _, pc in ORIG.pieces_in(lo, hi)]
    return ModuleSpec(name=name, doc=doc + "\n\n" + SPLIT_NOTE + "\n", pieces=[(name, pieces)])


cells = spec("coverage_model_cells",
             "Coverage data model: phases, cell statuses and results, the (parameter, location) case\n"
             "key and the derivation of input cases from a captured request or a client route template.",
             34, 416)
checks = spec("coverage_model_checks",
              "Check model: the applicability predicates, ExternalRef and the Check row type.", 418, 751)
catalog = spec("coverage_model_catalog",
               "The WSTG / PortSwigger Academy check catalog: CHECK_CATALOG (the code-defined rows), the\n"
               "caller-independent set that marks rows, and CHECKS_BY_ID.", 752, 1487)
MODULES = [cells, checks, catalog]

siblings = {}
for m in MODULES:
    for _, pcs in m.pieces:
        for pc in pcs:
            for n in pc.defined:
                siblings[n] = m.name
    m.defined = {n for _, pcs in m.pieces for pc in pcs for n in pc.defined}

if __name__ == "__main__":
    moved_keys = set()
    for m in MODULES:
        for _, pcs in m.pieces:
            moved_keys |= {pc.key for pc in pcs}
    for m in MODULES:
        text = render_module(ORIG, m, siblings)
        write_crlf(HARNESS / f"{m.name}.py", text)
        print(f"{m.name}: {len(text.splitlines())} lines, {len(m.defined)} names")
    reexports = {m.name: sorted(m.defined) for m in MODULES}
    facade = render_facade(
        ORIG, moved_keys, {}, {},
        addendum=("\nThe module is split by seam (ARC-9). This module stays the import path and holds the\n"
                  "check-id aliases and import guard (they read `REUSED_LEGACY_IDS` and\n"
                  "`is_current_wstg_id`, which tests patch here) and the CoverageMatrix; it re-exports\n"
                  "every name of its siblings:\n\n"
                  "    coverage_model_cells    Phase, CellStatus, CellResult, CaseKey, input cases\n"
                  "    coverage_model_checks   applicability predicates, ExternalRef, Check\n"
                  "    coverage_model_catalog  CHECK_CATALOG, CHECKS_BY_ID"),
        reexports=reexports, mixin_imports={})
    write_crlf(HARNESS / "coverage_model.py", facade)
    print(f"coverage_model: {len(facade.splitlines())} lines")
