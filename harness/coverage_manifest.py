"""
Requirement-coverage manifest -- WSTG requirements ⇄ regression tests + evidence.

This is deliberately SEPARATE from `coverage_model.CoverageMatrix`:

- `CoverageMatrix` is the per-RUN outcome substrate (identity × endpoint × check
  cells filled by what a live engagement actually did on a target).
- This module is the per-REPO *requirement coverage* ledger: which WSTG
  requirements have an isolated, deterministic regression test standing behind
  them, what that test's last recorded outcome was, and where its evidence lives.

The two must not be conflated, and the guiding rule here is the improving-notes
one:

    **A passing test does not prove an entire requirement is covered.**

So a requirement with a passing regression test is reported as ``covered_partial``
(the specific *aspect* the test exercises), never "complete" -- the scenarios the
test does not touch stay visible as residual gaps. And, crucially:

    **Missing evidence or a skipped/failed/manual test never counts as covered.**

Coverage is computed *from evidence artifacts on disk*, not from the mere
existence of a test function: if the artifact is absent, the requirement is a gap,
full stop. A regression test writes its artifact (via `write_evidence`) only on the
path where its assertions actually held, so the artifact's presence is meaningful.

Report vocabulary (the improving-notes set): pass / fail / skipped / manual /
not_applicable, plus `not_implemented` flagged SEPARATELY as a missing-implementation
gap (a requirement with no wired automated test at all).
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from coverage_model import CHECKS_BY_ID, CHECK_CATALOG, Check

# Committed evidence directory -- the regression tests write their artifacts here,
# and `reconcile()` reads them back. Kept under harness/ so it travels with the
# code and CI checkout. Deterministic filenames + deterministic content mean a
# green re-run leaves the working tree clean.
EVIDENCE_DIR = Path(__file__).resolve().parent / "coverage_evidence"


# ---------------------------------------------------------------------------
# Reporting vocabulary
# ---------------------------------------------------------------------------

class TestStatus(str, Enum):
    """The outcome of ONE regression test (never the coverage of a requirement)."""
    PASS = "pass"
    FAIL = "fail"
    SKIPPED = "skipped"
    MANUAL = "manual"                 # verified/handled by a human, not automated
    NOT_APPLICABLE = "not_applicable"
    NOT_IMPLEMENTED = "not_implemented"  # no wired test / no evidence artifact found

    @classmethod
    def coerce(cls, value: str) -> "TestStatus":
        try:
            return cls(str(value).strip().lower())
        except ValueError:
            # An unrecognized status is conservatively a FAIL, never a silent pass.
            return cls.FAIL


# A test outcome counts toward requirement coverage ONLY if it is a real pass.
_COVERING_STATUSES = frozenset({TestStatus.PASS})
# Statuses that are gaps but are NOT "missing implementation".
_GAP_STATUSES = frozenset({TestStatus.FAIL, TestStatus.SKIPPED, TestStatus.MANUAL})


class RequirementStatus(str, Enum):
    """The coverage rollup for a WHOLE requirement -- distinct from TestStatus."""
    COVERED_PARTIAL = "covered_partial"   # ≥1 aspect has passing evidence (never "complete")
    GAP_FAILED = "gap_failed"             # a wired test is failing
    GAP_SKIPPED = "gap_skipped"           # a wired test is skipped / evidence missing
    GAP_MANUAL = "gap_manual"             # only manual verification is declared
    GAP_UNIMPLEMENTED = "gap_unimplemented"  # no wired test at all (missing implementation)
    NOT_APPLICABLE = "not_applicable"     # requirement declared N/A for the target class


# ---------------------------------------------------------------------------
# Static wiring: which regression test covers which requirement (and how)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TestSpec:
    """A repo-declared link from a WSTG requirement to a regression test.

    `aspect` names the *specific* scenario of the requirement the test exercises,
    so the report can honestly say "this aspect is covered" rather than "the whole
    requirement is covered". `kind` is "automated" (an evidence artifact is expected)
    or "manual" (a documented human-verification step -- always a gap for automated
    coverage, surfaced under `manual`)."""
    check_id: str
    test_id: str            # "module.TestClass.test_method"
    aspect: str
    kind: str = "automated"       # "automated" | "manual"
    evidence_file: str = ""       # basename under EVIDENCE_DIR (automated specs)

    def __post_init__(self):
        if self.check_id not in CHECKS_BY_ID:
            raise ValueError(f"TestSpec references unknown WSTG check id {self.check_id!r}")
        if self.kind not in ("automated", "manual"):
            raise ValueError(f"TestSpec.kind must be 'automated' or 'manual', got {self.kind!r}")


def _slug(text: str) -> str:
    """A filesystem-safe, deterministic slug for an aspect label."""
    s = re.sub(r"[^a-z0-9]+", "_", (text or "").lower()).strip("_")
    return s[:60] or "aspect"


def evidence_basename(check_id: str, aspect: str) -> str:
    """The deterministic evidence filename for a (requirement, aspect) pair."""
    return f"{check_id}__{_slug(aspect)}.json"


# The registry. One entry per (requirement, aspect). Grows as regression tests are
# added; today it carries the mass-assignment vertical slice. Everything else in the
# catalog with no entry is surfaced by `reconcile()` as a GAP_UNIMPLEMENTED, which is
# the honest "requirement checklist, gaps flagged" the improving notes ask for.
_MASS_ASSIGNMENT_ASPECT = (
    "PATCH ordinary update leaves server-controlled fields unchanged "
    "(verified by an independent re-read)"
)

REQUIREMENT_TESTS: tuple[TestSpec, ...] = (
    TestSpec(
        check_id="WSTG-CONF-09",
        test_id="test_mass_assignment_slice.MassAssignmentSliceTest."
                "test_patched_upholds_protected_field_invariant",
        aspect=_MASS_ASSIGNMENT_ASPECT,
        kind="automated",
        evidence_file=evidence_basename("WSTG-CONF-09", _MASS_ASSIGNMENT_ASPECT),
    ),
)


# ---------------------------------------------------------------------------
# Evidence artifacts
# ---------------------------------------------------------------------------

@dataclass
class EvidenceRecord:
    """One test's recorded outcome, as written to / read from an evidence artifact."""
    check_id: str
    test_id: str
    aspect: str
    status: TestStatus
    invariant: str = ""
    reason: str = ""
    observed: dict = field(default_factory=dict)
    wstg_version: str = ""
    academy_url: str = ""
    # `run_label` is a caller-supplied, deterministic marker (NOT a wall clock),
    # so a committed artifact stays byte-stable across reproducible re-runs.
    run_label: str = "deterministic-regression"
    path: str = ""       # filled on load; not part of the on-disk body

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "test_id": self.test_id,
            "aspect": self.aspect,
            "status": self.status.value,
            "invariant": self.invariant,
            "reason": self.reason,
            "observed": self.observed,
            "wstg_version": self.wstg_version,
            "academy_url": self.academy_url,
            "run_label": self.run_label,
        }

    @classmethod
    def from_dict(cls, d: dict, *, path: str = "") -> "EvidenceRecord":
        return cls(
            check_id=str(d.get("check_id", "")),
            test_id=str(d.get("test_id", "")),
            aspect=str(d.get("aspect", "")),
            status=TestStatus.coerce(d.get("status", "")),
            invariant=str(d.get("invariant", "")),
            reason=str(d.get("reason", "")),
            observed=d.get("observed") or {},
            wstg_version=str(d.get("wstg_version", "")),
            academy_url=str(d.get("academy_url", "")),
            run_label=str(d.get("run_label", "deterministic-regression")),
            path=path,
        )


def write_evidence(*, check_id: str, test_id: str, aspect: str, status,
                   invariant: str = "", reason: str = "", observed: dict | None = None,
                   evidence_dir: Path | str = EVIDENCE_DIR,
                   run_label: str = "deterministic-regression") -> Path:
    """Write a regression test's evidence artifact deterministically and return its
    path. Content is sorted-key JSON with no wall clock, so a green re-run of a
    deterministic test produces byte-identical output (clean working tree). Pulls the
    versioned WSTG ref + Academy URL from the catalog so the artifact is self-describing."""
    if check_id not in CHECKS_BY_ID:
        raise ValueError(f"evidence references unknown WSTG check id {check_id!r}")
    st = status if isinstance(status, TestStatus) else TestStatus.coerce(status)
    check = CHECKS_BY_ID[check_id]
    rec = EvidenceRecord(
        check_id=check_id, test_id=test_id, aspect=aspect, status=st,
        invariant=invariant, reason=reason, observed=observed or {},
        wstg_version=check.wstg_version, academy_url=check.academy_url,
        run_label=run_label,
    )
    d = Path(evidence_dir)
    d.mkdir(parents=True, exist_ok=True)
    path = d / evidence_basename(check_id, aspect)
    path.write_text(json.dumps(rec.to_dict(), indent=2, sort_keys=True) + "\n",
                    encoding="utf-8")
    return path


def load_evidence(evidence_dir: Path | str = EVIDENCE_DIR) -> dict[tuple[str, str], EvidenceRecord]:
    """Load every evidence artifact under `evidence_dir`, keyed by (check_id, aspect).
    A malformed artifact is skipped (it can never satisfy coverage -- absence of a
    valid record is a gap, never a pass)."""
    out: dict[tuple[str, str], EvidenceRecord] = {}
    d = Path(evidence_dir)
    if not d.is_dir():
        return out
    for p in sorted(d.glob("*.json")):
        try:
            body = json.loads(p.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            continue
        if not isinstance(body, dict) or not body.get("check_id"):
            continue
        rel = p.relative_to(d.parent) if d.parent in p.parents else p
        rec = EvidenceRecord.from_dict(body, path=rel.as_posix())
        out[(rec.check_id, rec.aspect)] = rec
    return out


# ---------------------------------------------------------------------------
# Reconciliation: specs + evidence -> requirement coverage report
# ---------------------------------------------------------------------------

def _resolve_spec(spec: TestSpec, evidence: dict) -> dict:
    """Resolve one TestSpec to a concrete outcome, reading its evidence artifact.

    The status here is the TEST outcome (pass/fail/...). A manual spec is always
    reported MANUAL. An automated spec's outcome comes ONLY from a present, matching
    evidence artifact; a missing artifact is NOT_IMPLEMENTED (never a pass)."""
    if spec.kind == "manual":
        return {"test_id": spec.test_id, "aspect": spec.aspect, "kind": "manual",
                "status": TestStatus.MANUAL, "evidence_path": None,
                "reason": "manual verification step -- no automated regression evidence"}
    rec = evidence.get((spec.check_id, spec.aspect))
    if rec is None:
        return {"test_id": spec.test_id, "aspect": spec.aspect, "kind": "automated",
                "status": TestStatus.NOT_IMPLEMENTED, "evidence_path": None,
                "reason": "no evidence artifact on disk -- the regression test has not "
                          "produced passing evidence (never counted as covered)"}
    # A recorded pass must be backed by a matching test_id, else the artifact is stale.
    if rec.status == TestStatus.PASS and spec.test_id and rec.test_id and rec.test_id != spec.test_id:
        return {"test_id": spec.test_id, "aspect": spec.aspect, "kind": "automated",
                "status": TestStatus.FAIL, "evidence_path": rec.path,
                "reason": f"evidence test_id {rec.test_id!r} does not match declared "
                          f"{spec.test_id!r} (stale/mismatched artifact)"}
    return {"test_id": spec.test_id, "aspect": spec.aspect, "kind": "automated",
            "status": rec.status, "evidence_path": rec.path,
            "reason": rec.reason or f"evidence status={rec.status.value}"}


def _rollup(check: Check, resolved: list[dict]) -> dict:
    """Roll resolved specs up into a single requirement-coverage verdict."""
    covered = [r for r in resolved if r["status"] in _COVERING_STATUSES]
    covered_aspects = [r["aspect"] for r in covered]

    if not resolved:
        status = RequirementStatus.GAP_UNIMPLEMENTED
    elif covered:
        # A pass covers only its aspect -- NEVER the whole requirement.
        status = RequirementStatus.COVERED_PARTIAL
    elif any(r["status"] == TestStatus.FAIL for r in resolved):
        status = RequirementStatus.GAP_FAILED
    elif any(r["status"] in (TestStatus.SKIPPED, TestStatus.NOT_IMPLEMENTED) for r in resolved):
        status = RequirementStatus.GAP_SKIPPED
    elif all(r["status"] == TestStatus.MANUAL for r in resolved):
        status = RequirementStatus.GAP_MANUAL
    else:
        status = RequirementStatus.GAP_SKIPPED

    # Residual gaps: every resolved spec that did NOT contribute passing evidence,
    # PLUS the always-true honest note that untested scenarios of the requirement
    # remain even when one aspect passed (partial, never complete).
    residual = [{"aspect": r["aspect"], "status": r["status"].value, "reason": r["reason"]}
                for r in resolved if r["status"] not in _COVERING_STATUSES]
    note = ""
    if status == RequirementStatus.COVERED_PARTIAL:
        note = ("partial coverage: the passing aspect(s) are verified; other scenarios "
                "of this requirement are not exercised by a regression test yet")

    return {
        "check_id": check.id,
        "name": check.name,
        "wstg_ref": check.wstg_ref(),
        "wstg_version": check.wstg_version,
        "phase": check.phase.value,
        "confirmation": check.confirmation,
        "academy_ref": check.academy_ref,
        "academy_url": check.academy_url,
        "requirement_status": status.value,
        "covered_aspects": covered_aspects,
        "residual_gaps": residual,
        "note": note,
        "tests": [{"test_id": r["test_id"], "aspect": r["aspect"], "kind": r["kind"],
                   "status": r["status"].value, "evidence_path": r["evidence_path"],
                   "reason": r["reason"]} for r in resolved],
    }


def reconcile(specs: tuple[TestSpec, ...] = REQUIREMENT_TESTS, *,
              evidence_dir: Path | str = EVIDENCE_DIR,
              checks: tuple[Check, ...] = CHECK_CATALOG) -> dict:
    """Reconcile the declared specs + on-disk evidence into a requirement-coverage
    report over the WHOLE catalog. Requirements with no spec are surfaced as
    GAP_UNIMPLEMENTED so the checklist is complete and gaps are explicit."""
    evidence = load_evidence(evidence_dir)
    by_check: dict[str, list[TestSpec]] = {}
    for spec in specs:
        by_check.setdefault(spec.check_id, []).append(spec)

    requirements: list[dict] = []
    for check in checks:
        resolved = [_resolve_spec(s, evidence) for s in by_check.get(check.id, [])]
        requirements.append(_rollup(check, resolved))

    # Totals -- requirement-level (coverage) and test-level (outcomes), kept separate.
    req_by_status: dict[str, int] = {}
    for r in requirements:
        req_by_status[r["requirement_status"]] = req_by_status.get(r["requirement_status"], 0) + 1
    test_by_status: dict[str, int] = {}
    for r in requirements:
        for t in r["tests"]:
            test_by_status[t["status"]] = test_by_status.get(t["status"], 0) + 1

    covered_partial = req_by_status.get(RequirementStatus.COVERED_PARTIAL.value, 0)
    total_reqs = len(requirements)
    return {
        "totals": {
            "requirements": total_reqs,
            "covered_partial": covered_partial,
            # honest denominator: coverage is partial-by-construction, so this is
            # "requirements with ANY passing regression evidence", not "% done".
            "gaps": total_reqs - covered_partial - req_by_status.get(
                RequirementStatus.NOT_APPLICABLE.value, 0),
            "requirement_status_counts": req_by_status,
            "test_status_counts": test_by_status,
        },
        "requirements": requirements,
        # Convenience slices for the report / CI gate.
        "gaps": [r for r in requirements
                 if r["requirement_status"] not in (RequirementStatus.COVERED_PARTIAL.value,
                                                     RequirementStatus.NOT_APPLICABLE.value)],
        "unimplemented": [r["check_id"] for r in requirements
                          if r["requirement_status"] == RequirementStatus.GAP_UNIMPLEMENTED.value],
        "manual": [r["check_id"] for r in requirements
                   if r["requirement_status"] == RequirementStatus.GAP_MANUAL.value],
    }


def declared_coverage_ok(report: dict) -> tuple[bool, list[str]]:
    """CI gate helper: every requirement that has an AUTOMATED spec declared must
    actually be covered by passing evidence. Returns (ok, problems). A requirement
    with no spec (GAP_UNIMPLEMENTED) or a manual-only one is a KNOWN gap, not a
    regression -- it does not fail this gate; a declared automated test that is
    failing or has lost its evidence DOES."""
    problems: list[str] = []
    for r in report.get("requirements", []):
        automated = [t for t in r["tests"] if t["kind"] == "automated"]
        if not automated:
            continue
        if r["requirement_status"] != RequirementStatus.COVERED_PARTIAL.value:
            for t in automated:
                if t["status"] != TestStatus.PASS.value:
                    problems.append(
                        f"{r['check_id']} :: {t['aspect']}: declared automated test "
                        f"{t['test_id']} is '{t['status']}' ({t['reason']})")
    return (not problems), problems


def render_markdown(report: dict) -> str:
    """Render the requirement-coverage report as Markdown for a human / CI log."""
    t = report["totals"]
    lines = [
        "# WSTG requirement-coverage report",
        "",
        "_Requirement coverage is tracked SEPARATELY from test outcomes: a passing "
        "test proves only the aspect it exercises, never the whole requirement. "
        "Missing evidence, skipped, failed, and manual checks never count as covered._",
        "",
        f"- Requirements in catalog: **{t['requirements']}**",
        f"- With passing regression evidence (partial coverage): **{t['covered_partial']}**",
        f"- Gaps (unimplemented / manual / skipped / failed): **{t['gaps']}**",
        "",
        f"- Requirement status counts: `{t['requirement_status_counts']}`",
        f"- Test outcome counts: `{t['test_status_counts']}`",
        "",
        "## Requirements",
        "",
        "| WSTG ref | Name | Requirement status | Tests (status) | Evidence |",
        "| --- | --- | --- | --- | --- |",
    ]
    for r in report["requirements"]:
        if r["tests"]:
            tests_cell = "<br>".join(f"{t['status']}: {t['test_id'].split('.')[-1]}"
                                     for t in r["tests"])
            ev_cell = "<br>".join(t["evidence_path"] or "-" for t in r["tests"])
        else:
            tests_cell, ev_cell = "-", "-"
        lines.append(
            f"| {r['wstg_ref']} | {r['name']} | {r['requirement_status']} "
            f"| {tests_cell} | {ev_cell} |")
    if report.get("gaps"):
        lines += ["", "## Gaps (flagged)", ""]
        for g in report["gaps"]:
            lines.append(f"- **{g['wstg_ref']} {g['name']}** — {g['requirement_status']}")
            for rg in g["residual_gaps"]:
                lines.append(f"  - {rg['status']}: {rg['aspect']} — {rg['reason']}")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":  # pragma: no cover - manual/CI invocation
    import argparse
    import sys

    ap = argparse.ArgumentParser(description="WSTG requirement-coverage report")
    ap.add_argument("--evidence-dir", default=str(EVIDENCE_DIR))
    ap.add_argument("--json", action="store_true", help="emit JSON instead of Markdown")
    ap.add_argument("--check", action="store_true",
                    help="exit non-zero if a declared automated requirement is not "
                         "covered by passing evidence")
    args = ap.parse_args()

    rep = reconcile(evidence_dir=args.evidence_dir)
    print(json.dumps(rep, indent=2) if args.json else render_markdown(rep))
    if args.check:
        ok, problems = declared_coverage_ok(rep)
        if not ok:
            print("\nDECLARED-COVERAGE CHECK FAILED:", file=sys.stderr)
            for p in problems:
                print(f"  - {p}", file=sys.stderr)
            sys.exit(1)
