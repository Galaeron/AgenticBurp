"""Defect injection for harness/test_coverage_split.py: move one read of a patched name out of the
facade's reach (a copy bound at import), in a COPY of the harness tree, and require the guard to fail.

Each mutant rewrites `<alias>.<name>` back to a bare `<name>` bound by an import at the top of the
moved module, which is what `from harness.<facade> import <name>` would do. The copy lives under
.test-work/.../mutant (inside the repo tree, deleted afterwards); the real files are never touched.
Run from the repo root:  python .test-work/audit-fix-20261120/h1-coverage-split/mutants.py
Prints, per mutant, the guard tests that failed (the static checker and the reach test must be there).
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
MUTANT = HERE / "mutant"

# (label, module, alias, name, import line that binds the name at import, reach test expected to fail)
MUTANTS = [
    ("tracker drive: time", "coverage_tracker_drive", "_ct", "time", "import time",
     "test_time_reaches_the_leg_and_the_case_drives"),
    ("tracker drive: _LEG_STATUS", "coverage_tracker_drive", "_ct", "_LEG_STATUS",
     "from harness.coverage_tracker_tables import _LEG_STATUS",
     "test_leg_status_and_its_unknown_default_reach_the_leg_result"),
    ("tracker drive: _LEG_STATUS_UNKNOWN", "coverage_tracker_drive", "_ct", "_LEG_STATUS_UNKNOWN",
     "from harness.coverage_tracker_tables import _LEG_STATUS_UNKNOWN",
     "test_leg_status_and_its_unknown_default_reach_the_leg_result"),
    ("tracker drive: _fair_cells", "coverage_tracker_drive", "_ct", "_fair_cells",
     "from harness.coverage_tracker_tables import _fair_cells",
     "test_the_fair_share_schedulers_reach_the_drive_order"),
    ("tracker drive: _time_fair_cells", "coverage_tracker_drive", "_ct", "_time_fair_cells",
     "from harness.coverage_tracker_tables import _time_fair_cells",
     "test_the_fair_share_schedulers_reach_the_drive_order"),
    ("tracker drive: REQUEST_LEVEL_INPUTS", "coverage_tracker_drive", "_ct", "REQUEST_LEVEL_INPUTS",
     "from harness.validators.injection_targets import REQUEST_LEVEL_INPUTS",
     "test_request_level_inputs_reaches_both_case_readers"),
    ("tracker drive: log", "coverage_tracker_drive", "_ct", "log",
     "import logging\nlog = logging.getLogger('harness.coverage_tracker')",
     "test_the_logger_reaches_the_drive_and_the_checkpoint"),
    ("tracker report: _listed_in_compact_ledger", "coverage_tracker_report", "_ct",
     "_listed_in_compact_ledger", "from harness.coverage_tracker_tables import _listed_in_compact_ledger",
     "test_the_compact_ledger_filter_reaches_the_phase_ledger"),
    ("tracker report: log", "coverage_tracker_report", "_ct", "log",
     "import logging\nlog = logging.getLogger('harness.coverage_tracker')",
     "test_the_logger_reaches_the_drive_and_the_checkpoint"),
    ("surface probe: _host_in_scope", "api_surface_probe", "_asd", "_host_in_scope",
     "from harness.api_surface_data import _host_in_scope", "test_host_in_scope_reaches_the_probe"),
    ("surface mining: _host_in_scope", "api_surface_mining", "_asd", "_host_in_scope",
     "from harness.api_surface_data import _host_in_scope", "test_host_in_scope_reaches_html_link_mining"),
    ("surface mining: sensitive_file_verdict", "api_surface_mining", "_asd", "sensitive_file_verdict",
     "from harness.api_surface_sensitive import sensitive_file_verdict",
     "test_sensitive_file_verdict_reaches_the_sensitive_record"),
]


def build_copy() -> None:
    if MUTANT.exists():
        shutil.rmtree(MUTANT)
    shutil.copytree(REPO / "harness", MUTANT / "harness",
                    ignore=shutil.ignore_patterns("__pycache__", ".coverage_runs", "*.db", "*.lock",
                                                  "coverage_evidence"))


def mutate(module: str, alias: str, name: str, bind: str) -> int:
    path = MUTANT / "harness" / f"{module}.py"
    text = path.read_text(encoding="utf-8")
    new, n = re.subn(rf"\b{alias}\.{re.escape(name)}\b", name, text)
    assert n, f"{module}: no {alias}.{name} read to mutate"
    new = new.replace("from __future__ import annotations\n", "from __future__ import annotations\n" + bind + "\n", 1)
    path.write_text(new, encoding="utf-8")
    return n


def run_guard() -> tuple[int, list[str]]:
    env = dict(os.environ, PYTHONPATH=str(MUTANT))
    r = subprocess.run([sys.executable, "-m", "unittest", "harness.test_coverage_split"], cwd=MUTANT,
                       env=env, capture_output=True, text=True, encoding="utf-8", errors="replace")
    failed = re.findall(r"^(?:FAIL|ERROR): (\w+) \(harness\.test_coverage_split\.(\w+)", r.stderr, re.M)
    return r.returncode, [f"{cls}.{t}" for t, cls in failed]


def main() -> int:
    ok = True
    try:
        for label, module, alias, name, bind, reach in MUTANTS:
            build_copy()
            hits = mutate(module, alias, name, bind)
            rc, failed = run_guard()
            static = any(f.endswith("test_moved_modules_keep_the_contract") for f in failed)
            reach_failed = any(f.endswith(reach) for f in failed)
            verdict = "CAUGHT" if rc != 0 and static and reach_failed else "MISSED"
            ok &= verdict == "CAUGHT"
            print(f"{verdict}  {label} ({hits} read(s))  static={static} reach={reach_failed}  "
                  f"failing: {len(failed)}")
    finally:
        shutil.rmtree(MUTANT, ignore_errors=True)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
