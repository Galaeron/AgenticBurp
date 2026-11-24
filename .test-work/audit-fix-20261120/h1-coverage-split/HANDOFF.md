# h1-coverage-split: ARC-9, coverage_model / coverage_tracker / api_surface_discovery
Branch `claude/arc9-h1-coverage-0c7f1e`, base `44bfda57`. Commits `eb471d19` coverage_model, `9e5b276d` coverage_tracker, `86d04860`
api_surface_discovery, `6773feed` guard test + proof tooling, then this file. No push, PR or merge. Largest new file 754 lines;
the three entries left `OVERSIZED_CEILING` (two comment lines added under the table).

## Module map (each original stays the import path and re-exports every moved name, private ones too)
- `coverage_model.py` 738 (ids, aliases, import guard, CHECKS_BY_PHASE, CoverageMatrix) + `_cells` 400, `_checks` 354, `_catalog` 754.
- `coverage_tracker.py` 302 (CoverageTracker state + `__init__`, build_coverage*, endpoint_view) + `_tables` 379, `_matrix` 329
  (`_MatrixMixin`), `_drive` 482 (`_DriveMixin`, `_drive_order`), `_report` 317 (`_ReportMixin`).
- `api_surface_discovery.py` 434 (SurfaceDiscovery state, `__init__`, `discover`) + `_data` 376, `_sensitive` 460, `_probe` 237,
  `_walk` 267, `_mining` 281 (mixins). Classes split by whole methods: `class CoverageTracker(_MatrixMixin, ...)`.

## Patch-reach proof
- `find_patch_targets.py` (AST, through aliases) lists 27 names tests patch or assign on the three modules (`patch_targets_before.txt`).
- Moved code reads a patched name as `_ct.<name>` / `_asd.<name>` at call time (alias imported last): `time` (7 reads),
  `REQUEST_LEVEL_INPUTS` (2), `_LEG_STATUS`, `_LEG_STATUS_UNKNOWN`, `_fair_cells`, `_time_fair_cells`, `_listed_in_compact_ledger`, the
  logger; `_host_in_scope` (2), `sensitive_file_verdict`. Readers that stayed in the facade need no rewrite: asd DEFAULT_*,
  `_ALLOW_MINING_RESERVE`, `_LATE_DISCOVERY_FRACTION`; coverage_model REUSED_LEGACY_IDS, is_current_wstg_id, the alias table.
  SurfaceDiscovery, build_coverage*, CoverageTracker, resume_context_key, sensitive_file_finding are read by outside callers only.
- `harness/test_coverage_split.py` (44 tests): facade shape, a symtable checker, a reach test per name that drives the real caller,
  negative controls (a module that binds at import; a moved module given a snapshot of the facade).
- `mutants.py`: 12 injections (each alias read turned into an import-bound copy) in a copy of the tree: all CAUGHT by the checker
  and the matching reach test (`mutants_result.txt`).
- `verify_split.py`: every statement and method of `44bfda57` is identical once `_ct.`/`_asd.` is undone (70 / 45+31 / 97+30,
  22 reads undone); none lost, duplicated or new but the 6 mixins. `check_callers.py`: every name a caller or test uses is still there.
  Regenerate with the three `split_*.py` scripts (they read `git show 44bfda57`).

## Gates (system python 3.14, PYTHONPATH = this worktree, one process per module)
- Tip `6773feed`: smoke rc 0 (241 tests); precondition 74, split_guard 16, transport_inventory 22, coverage_split 44,
  coverage_manifest 38, wstg_catalog_ids 21: all OK (`gates_final.tsv`). `gates_*_core.tsv` predate a blank-line regeneration.
- The 70 `harness/test_*.py` modules mentioning the three modules (`gates_referencing.tsv`, 1,483 tests): 69 OK. `test_review_overlap`
  failed once (18 sends, needs >20: a wall-clock drive on a busy machine) and passed twice alone (`gates_rerun_review_overlap.tsv`).
## Owner notes
- `transport_inventory.py` lists `api_surface_discovery.py` as the target-HTTP site; the executor call now sits in `api_surface_probe.py`
  and ffuf-through-run in `api_surface_walk.py`. Its tests pass (the facade still names `run_context`) but the registry names the old
  file. Not edited (shared file, h2/h3 hit the same for sqlmap, ollama_client, browser_driver): register the new files at integration.
- Moved functions report `__module__` `harness.coverage_tracker_drive` etc. and methods `_DriveMixin.x`; nothing reads them. The facades
  no longer re-export stdlib imports (hashlib, json, uuid...); no caller used them.
- `ARCHITECTURE.md` and `AGENTS.md` still name the three facades (true); not edited. NOTES.md not overwritten (three parallel batches).
  Expect trivial merge conflicts on the `OVERSIZED_CEILING` lines and the comment above them.
