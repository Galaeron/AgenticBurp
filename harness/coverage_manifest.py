"""
Requirement-coverage manifest -- security requirements ⇄ regression tests + evidence.

This is deliberately SEPARATE from `coverage_model.CoverageMatrix`:

- `CoverageMatrix` is the per-RUN outcome substrate (identity × endpoint × check
  cells filled by what a live engagement actually did on a target).
- This module is the per-REPO *requirement coverage* ledger: which requirements have
  an isolated regression test standing behind them, what that test's outcome was IN
  THE CURRENT RUN, and where its evidence lives.

Guiding rules (each one is a fix for a real hole the reviewer found):

- **A passing test proves only the aspect it exercises, never a whole requirement.**
  A requirement with a passing aspect is `covered_partial`; every other aspect
  (failed / skipped / missing / manual) stays visible as a residual gap, INCLUDING
  under a partially-covered requirement.
- **Evidence is bound to the current run.** Every artifact records a `run_id`; the
  gate only trusts artifacts whose `run_id` matches this run and lives in a
  run-specific directory. A stale passing artifact from a previous run can NOT
  satisfy a new run, and a failed/skipped execution overwrites the old verdict.
- **Outcomes come from the test runner, not the test body** (`coverage_evidence_case`):
  a fail or skip is recorded as such, so "the test did not run / did not pass" is
  never silently a pass.
- **Identity must match exactly.** Evidence with an empty or mismatched `test_id`,
  an unsupported schema, or a duplicate file for one aspect is rejected -- it never
  counts as covered.
- **Reproducible observations are separate from execution metadata.** The `observation`
  block (what the fixture showed) is reproducible; the `execution` block (status,
  run id, timestamp) is per-run.

Report vocabulary: pass / fail / skipped / manual / not_applicable, plus
`not_implemented` flagged SEPARATELY (a declared automated aspect with no fresh
evidence, or a requirement with no test at all).
"""
from __future__ import annotations

import functools
import json
import os
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

from harness.coverage_model import CHECKS_BY_ID, CHECK_CATALOG, Check

SCHEMA_VERSION = 1
_HARNESS = Path(__file__).resolve().parent


# ---------------------------------------------------------------------------
# Run identity + run-specific evidence directory (freshness -- issue 2)
# ---------------------------------------------------------------------------

@functools.lru_cache(maxsize=1)
def current_run_id() -> str:
    """A stable identifier for THIS run/commit, shared by the test-writer process
    and the gate process. Prefers an explicit `COVERAGE_RUN_ID` (CI sets it to the
    commit sha), else the current git HEAD, else a clearly-marked local fallback.
    Cached so the writer and a same-process reader agree."""
    env = os.environ.get("COVERAGE_RUN_ID")
    if env:
        return env.strip()
    try:
        out = subprocess.run(["git", "rev-parse", "HEAD"], cwd=str(_HARNESS),
                             capture_output=True, text=True, timeout=5)
        if out.returncode == 0 and out.stdout.strip():
            return out.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        pass
    return "local-unknown-run"


def run_evidence_dir(run_id: str | None = None) -> Path:
    """The run-specific evidence directory. An explicit `COVERAGE_EVIDENCE_DIR` wins
    (CI points both steps at one fresh path); otherwise a per-run subdir under
    `.coverage_runs/` (git-ignored). Keying by run id keeps runs from bleeding into
    each other without any shared mutable committed directory."""
    env = os.environ.get("COVERAGE_EVIDENCE_DIR")
    if env:
        return Path(env)
    return _HARNESS / ".coverage_runs" / (run_id or current_run_id())


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
    NOT_IMPLEMENTED = "not_implemented"  # no fresh evidence for a declared automated aspect

    @classmethod
    def coerce(cls, value) -> "TestStatus":
        try:
            return cls(str(value).strip().lower())
        except ValueError:
            # An unrecognized status is conservatively a FAIL, never a silent pass.
            return cls.FAIL


# A test outcome counts toward requirement coverage ONLY if it is a real pass.
_COVERING_STATUSES = frozenset({TestStatus.PASS})


class RequirementStatus(str, Enum):
    """The coverage rollup for a WHOLE requirement -- distinct from TestStatus."""
    COVERED_PARTIAL = "covered_partial"   # ≥1 aspect has fresh passing evidence (never "complete")
    GAP_FAILED = "gap_failed"             # a wired test is failing
    GAP_SKIPPED = "gap_skipped"           # a wired test is skipped / evidence missing
    GAP_MANUAL = "gap_manual"             # only manual verification is declared
    GAP_UNIMPLEMENTED = "gap_unimplemented"  # no wired test at all (missing implementation)
    NOT_APPLICABLE = "not_applicable"     # requirement declared N/A for the target, with rationale


# ---------------------------------------------------------------------------
# Static wiring: which regression test covers which requirement (and how)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TestSpec:
    """A repo-declared link from a requirement to a regression test.

    `aspect` names the SPECIFIC scenario the test exercises (so the report says "this
    aspect is covered", never "the requirement is covered"). `mode` is "automated" (a
    fresh evidence artifact is expected) or "manual" (a documented human step -- always
    a gap for automated coverage). `label` is the semantic kind of evidence
    (e.g. "fixture_invariant", "harness_confirmation") so a fixture self-test is never
    presented as application-wide or pipeline coverage (issue 5)."""
    check_id: str
    test_id: str            # "module.TestClass.test_method" (must match the runner's)
    aspect: str
    mode: str = "automated"       # "automated" | "manual"
    label: str = "automated"      # semantic evidence kind
    evidence_file: str = ""       # basename under the evidence dir (automated specs)

    def __post_init__(self):
        if self.check_id not in CHECKS_BY_ID:
            raise ValueError(f"TestSpec references unknown check id {self.check_id!r}")
        if self.mode not in ("automated", "manual"):
            raise ValueError(f"TestSpec.mode must be 'automated' or 'manual', got {self.mode!r}")
        if self.mode == "automated" and not self.test_id:
            raise ValueError("an automated TestSpec must declare a non-empty test_id")


def _slug(text: str) -> str:
    """A filesystem-safe, deterministic slug for an aspect label."""
    s = re.sub(r"[^a-z0-9]+", "_", (text or "").lower()).strip("_")
    return s[:60] or "aspect"


def evidence_basename(check_id: str, aspect: str) -> str:
    """The deterministic evidence filename for a (requirement, aspect) pair."""
    return f"{check_id}__{_slug(aspect)}.json"


# ---- the mass-assignment vertical slice (internal id, external refs in catalog) ----
_MASS = "AV-MASSASSIGN-01"
_ASPECT_INVARIANT = ("patched fixture leaves server-controlled fields unchanged under "
                     "an ordinary update (independent re-read)")
_ASPECT_CONFIRM = ("harness SequenceValidator confirms mass assignment on the vulnerable "
                   "fixture (write then independent re-read differential)")
_ASPECT_CONTROL = ("harness SequenceValidator returns a controlled negative on the "
                   "patched fixture")

# ---- the open-redirect vertical slice (WSTG-INPV-17, a genuine WSTG id) ----
_OR = "WSTG-INPV-17"
_ASPECT_OR_INVARIANT = ("patched login neutralises an off-origin next and never issues "
                        "an off-origin redirect")
_ASPECT_OR_CONFIRM = ("harness OpenRedirectValidator confirms open redirect on the "
                      "vulnerable fixture (off-origin Location)")
_ASPECT_OR_CONTROL = ("harness OpenRedirectValidator returns a controlled negative on the "
                      "patched fixture")

REQUIREMENT_TESTS: tuple[TestSpec, ...] = (
    TestSpec(_MASS,
             "test_mass_assignment_slice.MassAssignmentSliceTest."
             "test_patched_upholds_protected_field_invariant",
             _ASPECT_INVARIANT, mode="automated", label="fixture_invariant",
             evidence_file=evidence_basename(_MASS, _ASPECT_INVARIANT)),
    TestSpec(_MASS,
             "test_mass_assignment_slice.MassAssignmentSliceTest."
             "test_harness_sequence_validator_confirms_vulnerable",
             _ASPECT_CONFIRM, mode="automated", label="harness_confirmation",
             evidence_file=evidence_basename(_MASS, _ASPECT_CONFIRM)),
    TestSpec(_MASS,
             "test_mass_assignment_slice.MassAssignmentSliceTest."
             "test_harness_sequence_validator_controlled_negative_on_patched",
             _ASPECT_CONTROL, mode="automated", label="harness_control",
             evidence_file=evidence_basename(_MASS, _ASPECT_CONTROL)),

    # open redirect (WSTG-INPV-17)
    TestSpec(_OR,
             "test_open_redirect_slice.OpenRedirectSliceTest."
             "test_patched_neutralises_off_origin_redirect",
             _ASPECT_OR_INVARIANT, mode="automated", label="fixture_invariant",
             evidence_file=evidence_basename(_OR, _ASPECT_OR_INVARIANT)),
    TestSpec(_OR,
             "test_open_redirect_slice.OpenRedirectSliceTest."
             "test_harness_validator_confirms_vulnerable",
             _ASPECT_OR_CONFIRM, mode="automated", label="harness_confirmation",
             evidence_file=evidence_basename(_OR, _ASPECT_OR_CONFIRM)),
    TestSpec(_OR,
             "test_open_redirect_slice.OpenRedirectSliceTest."
             "test_harness_validator_controlled_negative_on_patched",
             _ASPECT_OR_CONTROL, mode="automated", label="harness_control",
             evidence_file=evidence_basename(_OR, _ASPECT_OR_CONTROL)),

    # Manual checks: genuinely need a human / host access, so they are declared MANUAL
    # (a flagged gap, never automated coverage) rather than left as silent
    # "unimplemented". CSRF and file-upload oracles were retired to manual
    # (ORACLE_RETIREMENTS.md); file-permission needs host access.
    TestSpec("WSTG-CONF-09", "", "server files/directories are least-privilege "
             "(host-level review)", mode="manual", label="manual"),
    TestSpec("WSTG-SESS-05", "", "state-changing requests carry anti-CSRF protection "
             "(manual PoC / analyst review)", mode="manual", label="manual"),
    TestSpec("WSTG-BUSL-09", "", "upload endpoints validate type/size/content "
             "(manual review)", mode="manual", label="manual"),
)

# Public aliases the slice test modules reference at decoration time, so each test's
# @evidence_for aspects stay in lock-step with the declared specs above.
MASS_ASSIGNMENT_CHECK_ID = _MASS
ASPECT_MASS_INVARIANT = _ASPECT_INVARIANT
ASPECT_MASS_CONFIRM = _ASPECT_CONFIRM
ASPECT_MASS_CONTROL = _ASPECT_CONTROL
OPEN_REDIRECT_CHECK_ID = _OR
ASPECT_OR_INVARIANT = _ASPECT_OR_INVARIANT
ASPECT_OR_CONFIRM = _ASPECT_OR_CONFIRM
ASPECT_OR_CONTROL = _ASPECT_OR_CONTROL


# ---------------------------------------------------------------------------
# Applicability declarations (issue 6): explicit, with rationale
# ---------------------------------------------------------------------------

# check_id -> (applicable, rationale). Absent means "applicable by default". A
# declaration here is the honest, auditable place to record a scope-based exclusion
# (e.g. "no XML endpoints in scope"); it is intentionally empty in the shipped repo
# so we never fabricate a scope claim -- the mechanism is exercised by the tests.
REQUIREMENT_APPLICABILITY: dict[str, tuple[bool, str]] = {}


def applicability_of(check_id: str,
                     table: dict[str, tuple[bool, str]] | None = None) -> tuple[bool, str]:
    table = REQUIREMENT_APPLICABILITY if table is None else table
    if check_id in table:
        return table[check_id]
    return (True, "applicable by default; no scope-based exclusion declared")


# ---------------------------------------------------------------------------
# Evidence artifacts (reproducible observation vs per-run execution -- issue 2)
# ---------------------------------------------------------------------------

@dataclass
class EvidenceRecord:
    check_id: str
    aspect: str
    status: TestStatus
    kind: str = "automated"
    invariant: str = ""
    observation: dict = field(default_factory=dict)   # reproducible
    # execution metadata (per-run):
    test_id: str = ""
    run_id: str = ""
    recorded_at: str = ""
    reason: str = ""
    schema_version: int = SCHEMA_VERSION
    # runtime-only:
    path: str = ""
    conflict: bool = False
    invalid_reason: str = ""

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "check_id": self.check_id,
            "aspect": self.aspect,
            "kind": self.kind,
            "invariant": self.invariant,
            "observation": self.observation,
            "execution": {
                "test_id": self.test_id,
                "status": self.status.value,
                "run_id": self.run_id,
                "recorded_at": self.recorded_at,
                "reason": self.reason,
            },
        }

    @classmethod
    def from_dict(cls, d: dict, *, path: str = "") -> "EvidenceRecord":
        ex = d.get("execution") or {}
        return cls(
            check_id=str(d.get("check_id", "")),
            aspect=str(d.get("aspect", "")),
            status=TestStatus.coerce(ex.get("status", "")),
            kind=str(d.get("kind", "automated")),
            invariant=str(d.get("invariant", "")),
            observation=d.get("observation") or {},
            test_id=str(ex.get("test_id", "")),
            run_id=str(ex.get("run_id", "")),
            recorded_at=str(ex.get("recorded_at", "")),
            reason=str(ex.get("reason", "")),
            schema_version=d.get("schema_version"),
            path=path,
        )


def write_evidence(*, check_id: str, aspect: str, status, test_id: str,
                   kind: str = "automated", invariant: str = "", reason: str = "",
                   observation: dict | None = None, run_id: str | None = None,
                   recorded_at: str | None = None,
                   evidence_dir: Path | str | None = None) -> Path:
    """Write a regression test's evidence artifact for the CURRENT run and return its
    path. The observation block is reproducible; the execution block binds the record
    to `run_id` (defaults to the current run) with a timestamp. Writes into the
    run-specific dir by default."""
    if check_id not in CHECKS_BY_ID:
        raise ValueError(f"evidence references unknown check id {check_id!r}")
    st = status if isinstance(status, TestStatus) else TestStatus.coerce(status)
    rid = run_id or current_run_id()
    rec = EvidenceRecord(
        check_id=check_id, aspect=aspect, status=st, kind=kind, invariant=invariant,
        observation=observation or {}, test_id=test_id, run_id=rid,
        recorded_at=recorded_at or datetime.now(timezone.utc).isoformat(timespec="seconds"),
        reason=reason)
    d = Path(evidence_dir) if evidence_dir is not None else run_evidence_dir(rid)
    d.mkdir(parents=True, exist_ok=True)
    path = d / evidence_basename(check_id, aspect)
    path.write_text(json.dumps(rec.to_dict(), indent=2, sort_keys=True) + "\n",
                    encoding="utf-8")
    return path


def load_evidence(evidence_dir: Path | str | None = None, *,
                  run_id: str | None = None) -> dict[tuple[str, str], EvidenceRecord]:
    """Load evidence artifacts, keyed by (check_id, aspect), enforcing:

    - **freshness**: when `run_id` is given, artifacts from a DIFFERENT run are
      ignored entirely (a stale pass can never satisfy the gate -- issue 2);
    - **schema validation**: a wrong/absent `schema_version` is surfaced as an
      invalid FAIL record, never a pass (issue 3);
    - **no duplicates**: two artifacts for one aspect become a conflict FAIL rather
      than letting the last file silently win (issue 3).
    """
    d = Path(evidence_dir) if evidence_dir is not None else run_evidence_dir(run_id)
    buckets: dict[tuple[str, str], list[EvidenceRecord]] = {}
    if not d.is_dir():
        return {}
    for p in sorted(d.glob("*.json")):
        try:
            body = json.loads(p.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            continue
        if not isinstance(body, dict) or not body.get("check_id") or body.get("aspect") is None:
            continue
        rel = p.relative_to(d.parent) if d.parent in p.parents else p
        rec = EvidenceRecord.from_dict(body, path=rel.as_posix())
        # Freshness FIRST: a record from another run is not part of this run at all.
        if run_id is not None and rec.run_id != run_id:
            continue
        # Schema validation (on records that survived freshness).
        if rec.schema_version != SCHEMA_VERSION:
            rec.conflict = True
            rec.status = TestStatus.FAIL
            rec.invalid_reason = f"unsupported schema_version {rec.schema_version!r} (expected {SCHEMA_VERSION})"
        buckets.setdefault((rec.check_id, rec.aspect), []).append(rec)

    out: dict[tuple[str, str], EvidenceRecord] = {}
    for key, recs in buckets.items():
        if len(recs) == 1:
            out[key] = recs[0]
        else:
            conflict = EvidenceRecord(
                check_id=key[0], aspect=key[1], status=TestStatus.FAIL, conflict=True,
                invalid_reason=f"{len(recs)} duplicate evidence artifacts for this aspect "
                               f"({', '.join(sorted(r.path for r in recs))}) -- refusing to let one win",
                path=";".join(sorted(r.path for r in recs)))
            out[key] = conflict
    return out


# ---------------------------------------------------------------------------
# Reconciliation: specs + evidence -> requirement coverage report
# ---------------------------------------------------------------------------

def _resolve_spec(spec: TestSpec, evidence: dict) -> dict:
    """Resolve one TestSpec to a concrete TEST outcome, reading its evidence artifact.
    Requires an EXACT, non-empty identity match (issue 3) and rejects conflicts."""
    base = {"test_id": spec.test_id, "aspect": spec.aspect, "mode": spec.mode,
            "label": spec.label}
    if spec.mode == "manual":
        return {**base, "status": TestStatus.MANUAL, "evidence_path": None,
                "reason": "manual verification step -- no automated regression evidence"}
    rec = evidence.get((spec.check_id, spec.aspect))
    if rec is None:
        return {**base, "status": TestStatus.NOT_IMPLEMENTED, "evidence_path": None,
                "reason": "no fresh evidence artifact for this run -- the regression test "
                          "did not execute and pass in this run (never counted as covered)"}
    if rec.conflict:
        return {**base, "status": TestStatus.FAIL, "evidence_path": rec.path,
                "reason": rec.invalid_reason or "invalid/duplicate evidence artifact"}
    # Exact, NON-EMPTY identity match required -- an empty or mismatched test_id fails.
    if not rec.test_id or rec.test_id != spec.test_id:
        return {**base, "status": TestStatus.FAIL, "evidence_path": rec.path,
                "reason": f"evidence test_id {rec.test_id!r} does not exactly match declared "
                          f"{spec.test_id!r} (empty or mismatched identity)"}
    return {**base, "status": rec.status, "evidence_path": rec.path,
            "reason": rec.reason or f"evidence status={rec.status.value}"}


def _rollup(check: Check, resolved: list[dict], applicable: bool, rationale: str) -> dict:
    """Roll resolved specs up into a single requirement-coverage verdict."""
    covered = [r for r in resolved if r["status"] in _COVERING_STATUSES]
    covered_aspects = [r["aspect"] for r in covered]
    # Residual gaps: every resolved aspect that did NOT contribute passing evidence --
    # retained EVEN when the requirement is partially covered (issue 6).
    residual = [{"aspect": r["aspect"], "label": r["label"], "status": r["status"].value,
                 "reason": r["reason"]}
                for r in resolved if r["status"] not in _COVERING_STATUSES]

    if not applicable:
        status = RequirementStatus.NOT_APPLICABLE
    elif not resolved:
        status = RequirementStatus.GAP_UNIMPLEMENTED
    elif covered:
        status = RequirementStatus.COVERED_PARTIAL  # a pass covers only its aspect
    elif any(r["status"] == TestStatus.FAIL for r in resolved):
        status = RequirementStatus.GAP_FAILED
    elif any(r["status"] in (TestStatus.SKIPPED, TestStatus.NOT_IMPLEMENTED) for r in resolved):
        status = RequirementStatus.GAP_SKIPPED
    elif all(r["status"] == TestStatus.MANUAL for r in resolved):
        status = RequirementStatus.GAP_MANUAL
    else:
        status = RequirementStatus.GAP_SKIPPED

    note = ""
    if status == RequirementStatus.COVERED_PARTIAL:
        note = ("partial coverage: the passing aspect(s) are verified; other scenarios of "
                "this requirement are not exercised yet (see residual_gaps)")

    return {
        "check_id": check.id,
        "name": check.name,
        "ref": check.reference_label(),
        "is_wstg": check.is_wstg(),
        "wstg_version": check.wstg_version if check.is_wstg() else "",
        "phase": check.phase.value,
        "confirmation": check.confirmation,
        "external_refs": [{"catalog": e.catalog, "ref": e.ref, "url": e.url, "title": e.title}
                          for e in check.external_refs],
        "applicability": {"applicable": applicable, "rationale": rationale},
        "requirement_status": status.value,
        "covered_aspects": covered_aspects,
        "residual_gaps": residual,
        "note": note,
        "tests": [{"test_id": r["test_id"], "aspect": r["aspect"], "mode": r["mode"],
                   "label": r["label"], "status": r["status"].value,
                   "evidence_path": r["evidence_path"], "reason": r["reason"]}
                  for r in resolved],
    }


def _is_gap(req: dict) -> bool:
    """A requirement belongs in the top-level gaps list if it is not N/A and has any
    unresolved aspect -- INCLUDING a partially-covered requirement with a failing or
    missing sibling aspect (issue 6)."""
    if req["requirement_status"] == RequirementStatus.NOT_APPLICABLE.value:
        return False
    if req["requirement_status"] == RequirementStatus.COVERED_PARTIAL.value:
        return bool(req["residual_gaps"])
    return True


def reconcile(specs: tuple[TestSpec, ...] = REQUIREMENT_TESTS, *,
              evidence_dir: Path | str | None = None, run_id: str | None = None,
              checks: tuple[Check, ...] = CHECK_CATALOG,
              applicability: dict[str, tuple[bool, str]] | None = None) -> dict:
    """Reconcile declared specs + this run's evidence into a requirement-coverage
    report over the whole catalog. `run_id` defaults to the current run (so only
    fresh evidence counts); pass an explicit one in tests."""
    rid = run_id if run_id is not None else current_run_id()
    evidence = load_evidence(evidence_dir, run_id=rid)
    by_check: dict[str, list[TestSpec]] = {}
    for spec in specs:
        by_check.setdefault(spec.check_id, []).append(spec)

    requirements: list[dict] = []
    for check in checks:
        applicable, rationale = applicability_of(check.id, applicability)
        resolved = [_resolve_spec(s, evidence) for s in by_check.get(check.id, [])]
        requirements.append(_rollup(check, resolved, applicable, rationale))

    req_by_status: dict[str, int] = {}
    for r in requirements:
        req_by_status[r["requirement_status"]] = req_by_status.get(r["requirement_status"], 0) + 1
    test_by_status: dict[str, int] = {}
    for r in requirements:
        for t in r["tests"]:
            test_by_status[t["status"]] = test_by_status.get(t["status"], 0) + 1

    covered_partial = req_by_status.get(RequirementStatus.COVERED_PARTIAL.value, 0)
    not_applicable = req_by_status.get(RequirementStatus.NOT_APPLICABLE.value, 0)
    total_reqs = len(requirements)
    gaps = [r for r in requirements if _is_gap(r)]
    return {
        "run_id": rid,
        "totals": {
            "requirements": total_reqs,
            "applicable": total_reqs - not_applicable,
            "not_applicable": not_applicable,
            "covered_partial": covered_partial,
            "gaps": len(gaps),
            "requirement_status_counts": req_by_status,
            "test_status_counts": test_by_status,
        },
        "requirements": requirements,
        "gaps": gaps,
        "unimplemented": [r["check_id"] for r in requirements
                          if r["requirement_status"] == RequirementStatus.GAP_UNIMPLEMENTED.value],
        "manual": [r["check_id"] for r in requirements
                   if r["requirement_status"] == RequirementStatus.GAP_MANUAL.value],
        "not_applicable": [r["check_id"] for r in requirements
                           if r["requirement_status"] == RequirementStatus.NOT_APPLICABLE.value],
    }


def declared_coverage_ok(report: dict) -> tuple[bool, list[str]]:
    """CI gate: EVERY declared automated aspect must be a fresh pass -- checked
    INDEPENDENTLY per aspect, so one passing aspect can never hide a failing sibling
    (issue 1). Manual aspects and requirements declared not-applicable are known,
    non-regression states and are skipped."""
    problems: list[str] = []
    for r in report.get("requirements", []):
        if r["requirement_status"] == RequirementStatus.NOT_APPLICABLE.value:
            continue
        for t in r["tests"]:
            if t["mode"] != "automated":
                continue
            if t["status"] != TestStatus.PASS.value:
                problems.append(
                    f"{r['check_id']} :: [{t['label']}] {t['aspect']}: declared automated "
                    f"test {t['test_id']} is '{t['status']}' ({t['reason']})")
    return (not problems), problems


def render_markdown(report: dict) -> str:
    """Render the requirement-coverage report as Markdown for a human / CI log."""
    t = report["totals"]
    lines = [
        "# Requirement-coverage report",
        "",
        f"_Run id: `{report.get('run_id', '')}`. Requirement coverage is tracked "
        "SEPARATELY from test outcomes: a passing test proves only the aspect it "
        "exercises, never the whole requirement. Only FRESH evidence from this run "
        "counts; missing / skipped / failed / manual never count as covered._",
        "",
        f"- Requirements in catalog: **{t['requirements']}** "
        f"(applicable **{t['applicable']}**, not-applicable **{t['not_applicable']}**)",
        f"- With fresh passing regression evidence (partial coverage): **{t['covered_partial']}**",
        f"- Gaps (unimplemented / manual / skipped / failed / residual): **{t['gaps']}**",
        "",
        f"- Requirement status counts: `{t['requirement_status_counts']}`",
        f"- Test outcome counts: `{t['test_status_counts']}`",
        "",
        "## Requirements",
        "",
        "| Ref | Name | Requirement status | Aspects (label: status) | Evidence |",
        "| --- | --- | --- | --- | --- |",
    ]
    for r in report["requirements"]:
        if r["tests"]:
            tests_cell = "<br>".join(f"{x['label']}: {x['status']}" for x in r["tests"])
            ev_cell = "<br>".join(x["evidence_path"] or "-" for x in r["tests"])
        else:
            tests_cell, ev_cell = "-", "-"
        lines.append(f"| {r['ref']} | {r['name']} | {r['requirement_status']} "
                     f"| {tests_cell} | {ev_cell} |")
    if report.get("gaps"):
        lines += ["", "## Gaps (flagged, incl. residual aspects under partial coverage)", ""]
        for g in report["gaps"]:
            lines.append(f"- **{g['ref']} {g['name']}** — {g['requirement_status']}")
            for rg in g["residual_gaps"]:
                lines.append(f"  - [{rg['label']}] {rg['status']}: {rg['aspect']} — {rg['reason']}")
    na = [r for r in report["requirements"]
          if r["requirement_status"] == RequirementStatus.NOT_APPLICABLE.value]
    if na:
        lines += ["", "## Not applicable (declared, with rationale)", ""]
        for r in na:
            lines.append(f"- **{r['ref']} {r['name']}** — {r['applicability']['rationale']}")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":  # pragma: no cover - manual/CI invocation
    import argparse
    import sys

    ap = argparse.ArgumentParser(description="Requirement-coverage report")
    ap.add_argument("--evidence-dir", default=None,
                    help="evidence directory (default: this run's run-specific dir)")
    ap.add_argument("--run-id", default=None,
                    help="run id to reconcile against (default: current run/commit)")
    ap.add_argument("--json", action="store_true", help="emit JSON instead of Markdown")
    ap.add_argument("--check", action="store_true",
                    help="exit non-zero if a declared automated aspect is not a fresh pass")
    args = ap.parse_args()

    rid = args.run_id if args.run_id is not None else current_run_id()
    rep = reconcile(evidence_dir=args.evidence_dir, run_id=rid)
    print(json.dumps(rep, indent=2) if args.json else render_markdown(rep))
    if args.check:
        ok, problems = declared_coverage_ok(rep)
        if not ok:
            print("\nDECLARED-COVERAGE CHECK FAILED:", file=sys.stderr)
            for p in problems:
                print(f"  - {p}", file=sys.stderr)
            sys.exit(1)
