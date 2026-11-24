"""Generate the api_surface_discovery split from harness/api_surface_discovery.py at BASE_REV.

    api_surface_data       constants and wordlists, Route, SurfaceResult, small helpers, _host_in_scope,
                           and the HTML / OpenAPI spec parsing helpers
    api_surface_sensitive  WL-05 sensitive-file content signatures, verdict and finding
    api_surface_probe      _ProbeMixin: probing and not-found / soft-404 calibration
    api_surface_walk       _WalkMixin: ffuf fast paths, directory scan and recursion
    api_surface_mining     _MiningMixin: sensitive-file probes, response / subresource / action mining
    api_surface_discovery  the facade: SurfaceDiscovery (state, __init__, spec-behind-UI, discover;
                           bases = the mixins); re-exports every name.

`_host_in_scope` and `sensitive_file_verdict` are patched by tests and read by moved code, so
the mixins read them as `_asd.<name>` at call time. The wordlists and `_ALLOW_MINING_RESERVE` /
`_LATE_DISCOVERY_FRACTION` that tests patch are read only by `__init__` and `discover`, which stay
in the facade.
Run from the repo root: python .test-work/audit-fix-20261120/h1-coverage-split/split_api_surface.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from split_lib import HARNESS, ModuleSpec, Orig, render_facade, render_module, write_crlf  # noqa: E402

ORIG = Orig("harness/api_surface_discovery.py")
SPLIT_NOTE = ("Part of the ARC-9 split of harness.api_surface_discovery. Import these names from\n"
              "harness.api_surface_discovery, the facade, not from this module.")
ALIAS_IMPORT = "from harness import api_surface_discovery as _asd"
CLASS = "SurfaceDiscovery"
PATCHED_READ_BY_MOVED_CODE = {"_host_in_scope", "sensitive_file_verdict"}

PROBE = ["_probe", "_budget_left", "_raw", "_norm_body_hash", "_prefix_wildcard", "_norm_body_len",
         "_content_type", "_soft404_match", "_not_found", "_ancestor_prefixes", "_note_soft404",
         "_note_live", "_calibrate_not_found", "_check"]
WALK = ["_ffuf_fast_path", "_ffuf_through_run", "_directories", "_directory_pruned", "_scan_directory",
        "_recurse_directories", "_derive_prefixes"]
MINING = ["_probe_sensitive_files", "_mirrors", "_sensitive_record", "_mine_responses",
          "_representative_ids", "_mine_subresources", "_mine_deep_nested", "_probe_query_params",
          "_mine_actions"]

members = {m.name: pc for m, pc in ORIG.members(CLASS) if hasattr(m, "name")}


def pick(names):
    missing = [n for n in names if n not in members]
    assert not missing, missing
    return [members[n] for n in names]


def tops(*ranges):
    return [pc for a, b in ranges for _, pc in ORIG.pieces_in(a, b)]


data = ModuleSpec(
    name="api_surface_data",
    doc=("Data and pure helpers of the API surface discovery: the probe wordlists and thresholds, the\n"
         "Route and SurfaceResult records, the scope and not-found helpers, and the HTML / OpenAPI\n"
         "spec parsing helpers.\n\n" + SPLIT_NOTE + "\n"),
    pieces=[("data", tops((34, 284), (1359, 1481)))])
sensitive = ModuleSpec(
    name="api_surface_sensitive",
    doc=("WL-05 sensitive-file content signatures: which artifact class a path is, whether a 2xx body\n"
         "carries that class's structure, the verdict and the finding it becomes.\n\n" + SPLIT_NOTE + "\n"),
    pieces=[("sensitive", tops((1482, 1928)))])
probe = ModuleSpec(
    name="api_surface_probe",
    doc=("Probing and not-found calibration of SurfaceDiscovery: the scoped, budgeted request, the\n"
         "soft-404 / wildcard fingerprints and the existence check.\n\n" + SPLIT_NOTE + "\n\n"
         "`_host_in_scope` is read as `_asd.<name>` at call time (a test patches it on the facade).\n"),
    mixins=[("_ProbeMixin", "Methods of SurfaceDiscovery moved verbatim; see harness.api_surface_discovery.",
             pick(PROBE))],
    rewrite=set(PATCHED_READ_BY_MOVED_CODE), alias="_asd", alias_import=ALIAS_IMPORT)
walk = ModuleSpec(
    name="api_surface_walk",
    doc=("Directory walking of SurfaceDiscovery: the ffuf fast paths (direct and through the run), the\n"
         "directory scan and its bounded recursion, and prefix derivation.\n\n" + SPLIT_NOTE + "\n"),
    mixins=[("_WalkMixin", "Methods of SurfaceDiscovery moved verbatim; see harness.api_surface_discovery.",
             pick(WALK))])
mining = ModuleSpec(
    name="api_surface_mining",
    doc=("Mining of SurfaceDiscovery: sensitive-file probes and records, and the routes mined from\n"
         "responses, subresources, nested ids, query parameters and actions.\n\n" + SPLIT_NOTE + "\n\n"
         "`_host_in_scope` and `sensitive_file_verdict` are read as `_asd.<name>` at call time (tests\n"
         "patch them on the facade).\n"),
    mixins=[("_MiningMixin", "Methods of SurfaceDiscovery moved verbatim; see harness.api_surface_discovery.",
             pick(MINING))],
    rewrite=set(PATCHED_READ_BY_MOVED_CODE), alias="_asd", alias_import=ALIAS_IMPORT)
MODULES = [data, sensitive, probe, walk, mining]

siblings = {}
for m in MODULES:
    m.defined = {n for _, pcs in m.pieces for pc in pcs for n in pc.defined} | {x[0] for x in m.mixins}
    for n in m.defined:
        siblings[n] = m.name

if __name__ == "__main__":
    moved_tops = {pc.key for m in MODULES for _, pcs in m.pieces for pc in pcs}
    moved_methods = set(PROBE + WALK + MINING)
    print("methods kept in the facade class:", [n for n in members if n not in moved_methods])
    for m in MODULES:
        text = render_module(ORIG, m, siblings)
        write_crlf(HARNESS / f"{m.name}.py", text)
        print(f"{m.name}: {len(text.splitlines())} lines, {len(m.defined)} names, "
              f"{m.rewrites_made} alias reads")
    reexports = {m.name: sorted(n for n in m.defined if not n.endswith("Mixin")) for m in MODULES}
    reexports = {k: v for k, v in reexports.items() if v}
    for m in MODULES:
        if m.mixins:
            reexports.setdefault(m.name, []).extend(x[0] for x in m.mixins)
    facade = render_facade(
        ORIG, moved_tops, {CLASS: moved_methods}, {CLASS: ["_ProbeMixin", "_WalkMixin", "_MiningMixin"]},
        addendum=("\nThe module is split by seam (ARC-9). This module stays the import path and holds\n"
                  "SurfaceDiscovery's state, `__init__`, `discover` and the spec-behind-UI probe (they read the\n"
                  "wordlists and thresholds that tests patch here); it re-exports every name below, and\n"
                  "SurfaceDiscovery is composed of three mixins whose code reads the patched names it needs\n"
                  "(`_host_in_scope`, `sensitive_file_verdict`) back through this module at call time:\n\n"
                  "    api_surface_data       wordlists, thresholds, Route, SurfaceResult, spec / HTML helpers\n"
                  "    api_surface_sensitive  sensitive-file signatures, verdict, finding\n"
                  "    api_surface_probe      probing and not-found calibration\n"
                  "    api_surface_walk       ffuf fast paths, directory scan and recursion\n"
                  "    api_surface_mining     sensitive-file probes, response / subresource / action mining"),
        reexports=reexports, mixin_imports={})
    write_crlf(HARNESS / "api_surface_discovery.py", facade)
    print(f"api_surface_discovery: {len(facade.splitlines())} lines")
