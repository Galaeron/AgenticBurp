"""
evidence_grade.py -- evidence-supported grading tier adapter (PR-4, BP-1b).

Populates ``strict_score.py``'s (PR-3) ``evidence_supported`` metric family
from REAL evidence grading, by adapting
``evaluation_integrity/evidence_audit.py``'s ``audit_findings`` (the
confirmation-claim auditor) into ``strict_score``'s ``EvidenceGradeHook``
contract (``Callable[[exchange_id, exact_class, raw_prediction_string],
str]`` returning one of ``{"supported", "unsupported", "insufficient",
"unavailable"}`` -- only ``"supported"`` counts towards an evidence-backed
TP; see ``strict_score.score_evidence_supported``).

This module does NOT re-derive proof/case/verdict/artifact validity itself
-- that stays ``audit_findings``' job alone (REUSE, not a second evidence
reader). It only:

  1. Calls ``audit_findings(findings, proofs, cases, artifacts)`` once per
     run and maps EACH of its per-finding ``support`` diagnostics onto one
     of FOUR PR-4 tiers (see ``grade_findings`` / the mapping table below).
  2. Folds those four tiers into the two-valued vocabulary
     ``score_evidence_supported`` actually branches on (``"supported"`` vs
     everything else), so the existing PR-3 hook contract does not need to
     change shape for PR-4 to plug into it.
  3. Distinguishes "no evidence instrumentation for this run" (the
     ``evidence_grade_hook`` PR-3 documents as staying ``unavailable`` when
     absent) from "evidence instrumentation ran and genuinely supported
     nothing" (a real 0), which a hook that is merely *always constructed*
     could not do -- see ``build_evidence_grade_hook``.

Tier mapping (``audit_findings`` support level -> PR-4 tier), the exact
rule ``grade_findings`` implements:

  * ``support == "supported"`` (a resolvable, case-matched, executed,
    non-legacy proof whose verdict is ``confirmed`` and whose referenced
    exchange artifacts all resolve with a successful transport outcome --
    the FULL set of checks ``audit_findings`` already performs) is split
    into the two POSITIVE PR-4 tiers by inspecting the SAME proof object
    ``audit_findings`` already resolved by ``proof_id`` (never re-deriving
    support/verdict/case-matching -- purely a refinement of an
    already-"supported" grade):
      - ``differential_reproduced`` when the proof records an executed
        BEFORE/AFTER comparison, i.e. it carries BOTH a
        ``baseline_artifact_id`` AND an ``attack_artifact_id`` (the schema
        ``evidence_audit.py`` and its tests already use for a differential
        proof). This is the stronger tier: it says the confirmation
        rests on a reproduced before/after diff, not just one captured
        exchange.
      - ``captured`` otherwise -- a resolvable, adequate, case-bound proof
        that only references a single side of evidence (just an attack
        artifact, or only ``control_artifact_ids``). This distinction IS
        expressible from the data ``audit_findings`` and its proof schema
        already carry (``baseline_artifact_id``/``attack_artifact_id``),
        so it is not folded away -- see the module docstring's "if that
        distinction isn't expressible ... fold it conservatively" clause:
        here it is expressible, so it is not conservatively collapsed.
  * ``support == "unverifiable"`` (a confirmation WAS claimed but the
    audit could not stand it up) is split by inspecting the diagnostic's
    own ``reasons`` list -- no re-derivation, just reading what
    ``audit_findings`` already said:
      - ``insufficient`` when EVERY reason is specifically about the
        supplied *artifacts* set being incomplete/absent/ambiguous/
        failed-transport for an otherwise-identified proof (see
        ``_ARTIFACT_INSUFFICIENCY_REASONS``) -- i.e. the claim and its
        proof/case linkage are fine, but the evidence artifacts backing it
        are missing or incomplete.
      - ``unsupported`` for every other unverifiable reason: a bare
        ``confirmed: true`` with NO proof reference at all, an orphan/
        ambiguous proof or case id, a proof resolving to a DIFFERENT case,
        a non-``confirmed`` verdict, a non-executed or legacy proof, a
        missing invariant/observed result, or a validator-name mismatch.
        This matches the PR-4 acceptance language verbatim: a bare-true
        no-proof finding and a wrong-case proof are BOTH described there
        as "unsupported"/"unverifiable", not as "insufficient".
  * ``support == "not_claimed"`` (the finding never claimed confirmation)
    or ``"unknown_claim"`` (a ``confirmed`` field present but not a
    boolean) -- neither is one of PR-4's four named tiers, and there is no
    claim here to grade "insufficient" (that tier presumes a claim WAS
    made). Both fold conservatively into ``unsupported``: absence of a
    confirmation claim can never be evidence-backed.

``unavailable`` (the PR-3 sentinel, never a fabricated 0) is emitted at the
WHOLE-RUN level, not per finding, by ``build_evidence_grade_hook`` --
see its docstring.

Offline, deterministic, no third-party dependency, no model/network/target
I/O. Never reads ``*ANSWER_KEY*`` or a blind target's ``app.py``.
"""
from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path
from typing import Any, Literal

# Mirrors the sys.path trick testing/strict_score.py and its tests already
# use so `evidence_grade.py` can be imported either as `testing.evidence_grade`
# (package-qualified, via `python -m unittest testing.test_evidence_grade`)
# or with `testing/` itself on sys.path (bare `import evidence_grade`).
_TESTING_DIR = Path(__file__).resolve().parent
if str(_TESTING_DIR) not in sys.path:
    sys.path.insert(0, str(_TESTING_DIR))

from strict_score import EvidenceGradeHook, Predictions, classify_exact, score  # noqa: E402

# `evaluation_integrity` is a proper top-level package (has __init__.py) next
# to `testing/` at the repo root, so this import works whenever the process
# is invoked from the repo root (as harness.suite and `python -m unittest`
# both require) without any sys.path manipulation -- no second evidence
# reader is built here, this is the one and only import of the auditor.
from evaluation_integrity.evidence_audit import audit_findings  # noqa: E402

Tier = Literal["captured", "differential_reproduced", "unsupported", "insufficient"]

# `audit_findings` diagnostic `reasons` strings (verbatim substrings) that
# are specifically about the supplied `artifacts` set being incomplete --
# see the module docstring's "unverifiable" -> {insufficient, unsupported}
# split. Keep in sync with evaluation_integrity/evidence_audit.py's reason
# text; a mismatch here only makes grading MORE conservative (an
# artifact-insufficiency reason we fail to recognise falls back to
# "unsupported", never silently promoted to "insufficient" or "captured").
_ARTIFACT_INSUFFICIENCY_REASONS: tuple[str, ...] = (
    "proof has no resolvable exchange-artifact references",
    "proof references exchange artifacts absent from the supplied set",
    "proof references ambiguous duplicate exchange-artifact ids",
    "proof references an exchange artifact without a successful transport outcome",
)

_SUPPORTED_TIERS: frozenset[str] = frozenset({"captured", "differential_reproduced"})

# Tie-break rank when more than one finding record maps to the same
# (exchange_id, exact_class, raw_prediction_string) triple (e.g. two
# finding rows for the same repeated raw prediction with different proof
# outcomes): prefer the MOST favourable tier found for that triple, mirroring
# strict_score's own `any(...)`-across-raw-predictions semantics in
# `score_evidence_supported` (a class counts as evidence-backed if ANY of
# its raw predictions on that exchange graded "supported").
_TIER_RANK: dict[str, int] = {"unsupported": 0, "insufficient": 0,
                              "captured": 1, "differential_reproduced": 2}


def _is_artifact_insufficiency(reasons: list[str]) -> bool:
    """True iff every reason in `reasons` is about the artifacts set being
    incomplete/absent/ambiguous (never about the proof/case/verdict itself)."""
    return bool(reasons) and all(
        any(marker in reason for marker in _ARTIFACT_INSUFFICIENCY_REASONS)
        for reason in reasons
    )


def _is_differential(proof: dict[str, Any] | None) -> bool:
    """A "supported" proof is `differential_reproduced` (vs plain
    `captured`) when it records an executed BEFORE/AFTER comparison -- both
    a baseline and an attack exchange artifact -- not just one captured
    exchange. Reads the SAME proof object `audit_findings` already
    resolved by `proof_id`; never re-derives support itself."""
    if not proof:
        return False
    return bool(proof.get("baseline_artifact_id")) and bool(proof.get("attack_artifact_id"))


def grade_findings(findings: list[dict[str, Any]], proofs: list[dict[str, Any]],
                   cases: list[dict[str, Any]], artifacts: list[dict[str, Any]],
                   ) -> dict[str, dict[str, Any]]:
    """Run `audit_findings` ONCE and grade each finding into one of the four
    PR-4 tiers. Returns ``{finding_id: {"tier", "support", "reasons"}}`` --
    every finding present in `findings` gets exactly one entry, keyed by its
    own `finding_id` (as `audit_findings`' diagnostics already are)."""
    audit = audit_findings(findings, proofs, cases, artifacts)
    proof_by_id = {str(p["proof_id"]): p for p in proofs if p.get("proof_id")}

    graded: dict[str, dict[str, Any]] = {}
    for diag in audit["diagnostics"]:
        support = diag["support"]
        reasons = diag["reasons"]
        tier: Tier
        if support == "supported":
            proof = proof_by_id.get(diag["proof_id"] or "")
            tier = "differential_reproduced" if _is_differential(proof) else "captured"
        elif support == "unverifiable":
            tier = "insufficient" if _is_artifact_insufficiency(reasons) else "unsupported"
        else:  # "not_claimed" or "unknown_claim" -- no claim to grade; fold conservatively
            tier = "unsupported"
        graded[diag["finding_id"]] = {"tier": tier, "support": support, "reasons": reasons}
    return graded


def predictions_from_findings(findings: list[dict[str, Any]]) -> Predictions:
    """Build the `Predictions` shape `strict_score.score()` expects
    (``dict[exchange_id, list[raw vulnerability_class string]]``) from the
    same per-exchange findings list passed to `build_evidence_grade_hook`,
    so a caller does not have to derive predictions twice from two
    differently-shaped views of the same run."""
    predictions: Predictions = {}
    for finding in findings:
        exchange_id = str(finding.get("exchange_id") or "")
        raw = finding.get("vulnerability_class")
        if not exchange_id or not raw:
            continue
        predictions.setdefault(exchange_id, []).append(raw)
    return predictions


def build_evidence_grade_hook(
    findings: list[dict[str, Any]], proofs: list[dict[str, Any]],
    cases: list[dict[str, Any]], artifacts: list[dict[str, Any]],
) -> tuple[EvidenceGradeHook | None, dict[str, Any]]:
    """Build the `strict_score.EvidenceGradeHook` for one run's evidence
    artifacts, plus a per-tier breakdown report.

    Returns ``(hook, tier_report)``.

    ``hook`` is ``None`` when this run has NO evidence instrumentation at
    all (``proofs``, ``cases`` AND ``artifacts`` are all empty) -- callers
    MUST pass that straight through as
    ``strict_score.score(..., evidence_grade_hook=None)``, which is exactly
    the PR-3 scaffold's existing "no hook" branch: the `evidence_supported`
    family reports the explicit ``"unavailable"`` sentinel, never a
    fabricated zero. If ANY of `proofs`/`cases`/`artifacts` is non-empty,
    instrumentation IS considered present for this run (even if grading
    ultimately supports nothing) and a real callable hook is returned --
    that later case is a genuine 0, not "unavailable"; see
    `score_with_evidence`'s docstring and `testing/test_evidence_grade.py`'s
    negative-control tests for the two cases side by side.

    ``tier_report`` mirrors that same distinction for direct inspection
    (``status`` is ``"unavailable"`` or ``"computed"``) and, when
    computed, carries the full per-finding grade (`"per_finding"`) plus
    aggregate tier counts (`"tier_counts"`).
    """
    if not proofs and not cases and not artifacts:
        return None, {
            "status": "unavailable",
            "note": ("no evidence instrumentation (proofs/cases/artifacts all "
                     "empty) supplied for this run -- see strict_score's "
                     "evidence_grade_hook=None sentinel behaviour"),
            "per_finding": None,
            "tier_counts": None,
        }

    graded = grade_findings(findings, proofs, cases, artifacts)

    # Index by the exact triple the hook is called with, so the hook is a
    # pure lookup at score() time (no re-auditing per call).
    index: dict[tuple[str, str, str], Tier] = {}
    for finding in findings:
        exchange_id = str(finding.get("exchange_id") or "")
        raw = finding.get("vulnerability_class") or ""
        exact_class = classify_exact(raw)
        if not exchange_id or exact_class is None:
            continue
        tier = graded.get(finding["finding_id"], {}).get("tier", "unsupported")
        key = (exchange_id, exact_class, raw)
        existing = index.get(key)
        if existing is None or _TIER_RANK[tier] > _TIER_RANK[existing]:
            index[key] = tier

    def hook(exchange_id: str, exact_class: str, raw_prediction: str) -> str:
        tier = index.get((exchange_id, exact_class, raw_prediction))
        if tier is None:
            # A raw prediction strict_score is scoring has no corresponding
            # finding record in THIS run's evidence artifacts at all -- not
            # "no claim" (predictions carry no confirmation field to begin
            # with) but definitely nothing to call it "supported" on:
            # graded the same as an under-evidenced claim, "insufficient".
            return "insufficient"
        return "supported" if tier in _SUPPORTED_TIERS else tier

    tier_counts = Counter(g["tier"] for g in graded.values())
    tier_report = {
        "status": "computed",
        "note": None,
        "per_finding": graded,
        "tier_counts": dict(sorted(tier_counts.items())),
    }
    return hook, tier_report


def score_with_evidence(manifest, findings: list[dict[str, Any]],
                        proofs: list[dict[str, Any]], cases: list[dict[str, Any]],
                        artifacts: list[dict[str, Any]], *,
                        predictions: Predictions | None = None) -> dict[str, Any]:
    """Convenience wrapper: score `predictions` (derived from `findings` via
    `predictions_from_findings` unless explicitly supplied) against
    `manifest` with a REAL evidence-grading hook built from `findings` +
    `proofs` + `cases` + `artifacts`, and attach the per-tier breakdown onto
    the returned `evidence_supported` family as `"tiers"`.

    This is the ONLY function in this module that imports/calls
    `strict_score.score` -- `strict_score.py` itself is never modified;
    wiring happens entirely on this side, which is what keeps
    `strict_score.py` "a pure scorer" as the task brief asks (it does not
    need to know anything about tiers, audits, or evidence artifact
    shapes -- only about the two-valued hook contract it already had from
    PR-3)."""
    if predictions is None:
        predictions = predictions_from_findings(findings)
    hook, tier_report = build_evidence_grade_hook(findings, proofs, cases, artifacts)
    report = score(manifest, predictions, evidence_grade_hook=hook)
    report["evidence_supported"]["tiers"] = tier_report
    return report
