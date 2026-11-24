"""Generate the coverage_tracker split from harness/coverage_tracker.py at BASE_REV.

    coverage_tracker_tables  policy tables and pure helpers (leg/case status maps, confirmations,
                             fair-share scheduling, attempt facts, resume key)
    coverage_tracker_matrix  _MatrixMixin: class resolution, build, recording, readiness
    coverage_tracker_drive   _DriveMixin: the leg and case drive loops, plus _drive_order
    coverage_tracker_report  _ReportMixin: finalize, credit, checkpoint, phase ledger, report
    coverage_tracker         the facade: CoverageTracker (state and __init__, bases = the mixins),
                             the build_coverage* entry points, endpoint_view; re-exports every name.

Names the facade owns and tests patch (`time`, `REQUEST_LEVEL_INPUTS`, `_LEG_STATUS`,
`_LEG_STATUS_UNKNOWN`, `_fair_cells`, `_time_fair_cells`, `_listed_in_compact_ledger`) and its logger
are read by moved code as `_ct.<name>` at call time. `_ct` is imported last in each moved module.
Run from the repo root: python .test-work/audit-fix-20261120/h1-coverage-split/split_coverage_tracker.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from split_lib import HARNESS, ModuleSpec, Orig, render_facade, render_module, write_crlf  # noqa: E402

ORIG = Orig("harness/coverage_tracker.py")
SPLIT_NOTE = ("Part of the ARC-9 split of harness.coverage_tracker. Import these names from\n"
              "harness.coverage_tracker, the facade, not from this module.")
PATCHED = {"time", "REQUEST_LEVEL_INPUTS", "_LEG_STATUS", "_LEG_STATUS_UNKNOWN", "_fair_cells",
           "_time_fair_cells", "_listed_in_compact_ledger", "log"}
ALIAS_IMPORT = "from harness import coverage_tracker as _ct"
CLASS = "CoverageTracker"

TOP_FOR_TABLES = [39, 40, 43, 48, 71, 89, 115, 142, 152, 159, 164, 199, 222, 232, 236, 243, 248, 249,
                  253, 257, 264, 267, 271, 287, 297, 318, 333, 358, 361, 386, 389, 399, 407, 1558]
TOP_FOR_DRIVE = [370]            # _drive_order: it reads the patched _fair_cells / _time_fair_cells
MATRIX = ["_specific_check", "resolve_class", "checks_for_class", "class_is_ambiguous", "build",
          "_probe_identity", "record_findings_from_state", "record_execution_events", "_unauthenticated",
          "evaluate_readiness", "pending_leg_cells"]
DRIVE = ["drive_coverage_legs", "_record_leg_result", "reopen_unattempted", "drive_remaining",
         "record_held_result", "expand_parameter_cases", "drive_coverage_cases", "_drive_request_level",
         "_record_case_result", "_record_parameter_result", "_drive_parameter_cases"]
REPORT = ["finalize_pending_reasons", "_lacks_capture", "credit_caller_independent", "credited_summary",
          "restore_checkpoint", "phase_ledger", "report", "checkpoint", "_checkpoint_after"]

members = {m.name: pc for m, pc in ORIG.members(CLASS) if hasattr(m, "name")}


def pick(names):
    missing = [n for n in names if n not in members]
    assert not missing, missing
    return [members[n] for n in names]


tables = ModuleSpec(
    name="coverage_tracker_tables",
    doc=("Policy tables and pure helpers of the coverage tracker: how a leg or case result maps to a\n"
         "cell status, which legs confirm which rows, fair-share scheduling of the drive queue,\n"
         "attempt facts and the resume-context key.\n\n" + SPLIT_NOTE + "\n"),
    pieces=[("tables", [ORIG.piece_at(n)[1] for n in TOP_FOR_TABLES])])
matrix = ModuleSpec(
    name="coverage_tracker_matrix",
    doc=("The matrix-building methods of CoverageTracker: resolving a finding's class to catalog rows,\n"
         "filling cells from the engagement state and execution events, readiness and pending legs.\n\n"
         + SPLIT_NOTE + "\n"),
    mixins=[("_MatrixMixin", "Methods of CoverageTracker moved verbatim; see harness.coverage_tracker.",
             pick(MATRIX))])
drive = ModuleSpec(
    name="coverage_tracker_drive",
    doc=("The drive loops of CoverageTracker: running the queued legs and the per-parameter cases within\n"
         "the leg and time budgets, and recording each result into the matrix.\n\n"
         + SPLIT_NOTE + "\n\nA name the facade owns and tests patch (`time`, `REQUEST_LEVEL_INPUTS`, `_LEG_STATUS`,\n"
         "`_fair_cells`, ...) is read as `_ct.<name>` at call time, so a patch on harness.coverage_tracker\n"
         "reaches this code exactly as when it was one module.\n"),
    pieces=[("drive", [ORIG.piece_at(n)[1] for n in TOP_FOR_DRIVE])],
    mixins=[("_DriveMixin", "Methods of CoverageTracker moved verbatim; see harness.coverage_tracker.",
             pick(DRIVE))],
    rewrite=set(PATCHED), alias_import=ALIAS_IMPORT)
report = ModuleSpec(
    name="coverage_tracker_report",
    doc=("The finishing methods of CoverageTracker: pending reasons, caller-independent credit,\n"
         "checkpoint and restore, the phase ledger and the report.\n\n" + SPLIT_NOTE + "\n\n"
         "`_listed_in_compact_ledger` and the logger are read as `_ct.<name>` at call time (a test patches\n"
         "the former on harness.coverage_tracker).\n"),
    mixins=[("_ReportMixin", "Methods of CoverageTracker moved verbatim; see harness.coverage_tracker.",
             pick(REPORT))],
    rewrite=set(PATCHED), alias_import=ALIAS_IMPORT)
MODULES = [tables, matrix, drive, report]

siblings = {}
for m in MODULES:
    m.defined = {n for _, pcs in m.pieces for pc in pcs for n in pc.defined} | {x[0] for x in m.mixins}
    for n in m.defined:
        siblings[n] = m.name

if __name__ == "__main__":
    moved_tops = {pc.key for m in MODULES for _, pcs in m.pieces for pc in pcs}
    moved_methods = set(MATRIX + DRIVE + REPORT)
    kept = [n for n in members if n not in moved_methods]
    print("methods kept in the facade class:", kept)
    for m in MODULES:
        text = render_module(ORIG, m, siblings)
        write_crlf(HARNESS / f"{m.name}.py", text)
        print(f"{m.name}: {len(text.splitlines())} lines, {len(m.defined)} names, "
              f"{m.rewrites_made} alias reads")
    reexports = {m.name: sorted(n for n in m.defined if not n.endswith("Mixin")) for m in MODULES
                 if any(not n.endswith("Mixin") for n in m.defined)}
    for m in MODULES:      # one import statement per module: its re-exports and its mixin
        if m.mixins:
            reexports.setdefault(m.name, []).extend(x[0] for x in m.mixins)
    mixin_imports = {}
    facade = render_facade(
        ORIG, moved_tops, {CLASS: moved_methods}, {CLASS: ["_MatrixMixin", "_DriveMixin", "_ReportMixin"]},
        addendum=("\nThe module is split by seam (ARC-9). This module stays the import path and owns the state\n"
                  "tests patch (`time`, `REQUEST_LEVEL_INPUTS`, the logger); it re-exports every name below,\n"
                  "and CoverageTracker is composed of three mixins whose code reads those names back through\n"
                  "this module at call time:\n\n"
                  "    coverage_tracker_tables  status maps, confirmation tables, fair-share scheduling, helpers\n"
                  "    coverage_tracker_matrix  class resolution, build, recording, readiness\n"
                  "    coverage_tracker_drive   the leg and case drive loops\n"
                  "    coverage_tracker_report  finalize, credit, checkpoint, phase ledger, report"),
        reexports=reexports, mixin_imports=mixin_imports,
        extra_need={"time", "REQUEST_LEVEL_INPUTS"})   # patched; read by moved code as _ct.<name>
    write_crlf(HARNESS / "coverage_tracker.py", facade)
    print(f"coverage_tracker: {len(facade.splitlines())} lines")
