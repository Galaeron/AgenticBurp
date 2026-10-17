"""I11: classify requirement-coverage gaps against validators and tracked tests.

Run from the repository root: python testing/classify_coverage_gaps.py
Name-based heuristic; see docs/COVERAGE_GAP_CLASSIFICATION_2026-10-17.md.
"""
import re, subprocess, pathlib, sys
from harness.coverage_model import CHECK_CATALOG
from harness import coverage_manifest as cm
covered = {s.check_id for s in cm.REQUIREMENT_TESTS if s.mode == "automated"}
manual = {s.check_id for s in cm.REQUIREMENT_TESTS if s.mode == "manual"}
tracked = set(subprocess.run(["git", "ls-files", "harness"], capture_output=True, text=True).stdout.split())
tests = [p for p in tracked if re.match(r"harness/test_.*\.py$", p)]
src = {p: pathlib.Path(p).read_text(encoding="utf-8", errors="replace") for p in tests}
vfiles = {p for p in tracked if p.startswith("harness/validators/") and p.endswith(".py")}
rows = []
for c in CHECK_CATALOG:
    if c.id in covered: continue
    conf = c.confirmation
    vf = [p for p in vfiles if pathlib.Path(p).stem.startswith(conf.split("|")[0].strip().replace("-", "_"))]
    cls = None
    for p in vf:
        m = re.search(r"^class (\w+Validator)\(", pathlib.Path(p).read_text(encoding="utf-8"), re.M)
        if m: cls = m.group(1); break
    hits = sorted(p.split("/")[-1][:-3] for p, t in src.items() if cls and cls in t) if cls else []
    caller = [h for h in hits if any(k in h for k in ("leg_live", "pipeline_gate", "smoke", "caller", "engagement", "investigate"))]
    if c.id in manual: kind = "manual prerequisite"
    elif not cls: kind = "no deterministic validator (agent/manual confirmation)"
    elif caller: kind = "implemented; caller/fixture tests exist; evidence not wired"
    elif hits: kind = "implemented; unit tests only; caller evidence missing"
    else: kind = "implemented; no tests found"
    rows.append((c.id, c.name, conf, cls or "-", kind, ", ".join(caller[:3]) or "-", len(hits)))
print("| Requirement | Name | Confirmation | Validator | Classification | Caller/fixture tests | Test modules |")
print("|---|---|---|---|---|---|---|")
for r in rows: print("| " + " | ".join(str(x) for x in r) + " |")
import collections; print(); print(collections.Counter(r[4] for r in rows))
