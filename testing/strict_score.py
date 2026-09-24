"""
strict_score.py -- versioned strict exact-class scorer + indiscriminate
baselines (PR-3, BP-1a).

Fixes R06: ``testing/score.py`` maps a finding's raw ``vulnerability_class``
string to a COARSE OWASP-2021 bucket (e.g. A03:Injection covers SQLi AND
XSS AND SSTI AND command injection together), and its SSRF keyword list
includes the bare substring ``"request forgery"`` -- so a literal
``"cross-site request forgery"`` finding silently counts as SSRF (`csrf`
itself is not even in its vocabulary). Under that scheme an indiscriminate
detector that alerts on every exchange, or that fires every class on every
exchange, looks high-recall: any finding of any class satisfies a coarse
bucket's TP.

This module keeps ``testing/score.py`` UNCHANGED (it stays the explicit
coarse/historical metric -- see its own ``METRIC_SCOPE``) and adds a strict
scorer on top of the PR-2 exact-class label manifest
(``testing.labels.manifest``). It classifies a raw ``vulnerability_class``
string to ONE exact alias from ``labels.manifest.EXACT_CLASSES`` (or
``None``), and reports THREE metric families side by side, never merged:

  * ``any_alert_coverage``   -- the OLD coarse notion, kept and clearly
    labelled as *coverage*, not recall: did the exchange get >=1 finding of
    ANY class at all. An indiscriminate detector scores 1.0 here trivially
    -- that is the point of keeping it visible next to, not instead of, the
    metric below.
  * ``exact_class``          -- strict exact-class precision/recall/F1,
    micro and per-class. A TP requires a predicted exact class that is
    literally in that exchange's ``expected_classes``; any other predicted
    class on that exchange is an FP (see ``score_exact_class`` for the
    "doubly so" tested-negative-control bookkeeping); a positive exchange
    with none of its expected classes predicted is a miss (FN) for each
    unmatched expected class.
  * ``evidence_supported``   -- DEFINED here (see ``score_evidence_supported``
    and ``EvidenceGradeHook``) but left as an explicit ``"unavailable"``
    sentinel -- NEVER a fabricated ``0`` -- until a caller supplies an
    evidence-grading hook. PR-4/BP-1b (reusing
    ``evaluation_integrity/evidence_audit.py``) populates this by passing
    ``evidence_grade_hook=...`` into ``score()`` without needing to reshape
    this API.

Matching + dedup units (explicit, load-bearing for the tests):
  * Duplicate predictions of the SAME exact class on the SAME exchange
    count ONCE -- predicted classes are deduplicated per exchange via a
    ``set`` before any TP/FP arithmetic, so repeating a finding string
    cannot inflate recall.
  * A missing prediction for a known positive exchange/class is a miss
    (FN), never silently ignored.
  * ``inconclusive`` (unresolved) and ``setup`` exchanges are EXCLUDED from
    scoring entirely -- this module only ever iterates
    ``Manifest.scorable()`` (positive + negative), reusing PR-2's own
    partitioning rather than re-deriving "is this scorable" locally. They
    are never treated as secure and never eligible to become FPs, no
    matter what a predictor emits for their exchange_id.

Baselines (``baseline_silent``, ``baseline_always_alert``,
``baseline_all_classes``) are first-class, independently callable/testable
functions -- the negative controls this module's acceptance criteria hinge
on. See ``passes_precision_gate`` / ``passes_recall_gate``.

Predictions are represented the same shape ``testing/score.py`` already
uses (``dict[exchange_id, list[raw vulnerability_class string]]``) so an
existing findings adapter needs no reshaping to feed this scorer too.

This module is pure offline scoring/analysis: no model, network, target,
or third-party dependency.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Callable

# `labels` is a bare top-level package under testing/ (mirrors the sys.path
# trick testing/score.py and testing/test_label_manifest.py already use).
_TESTING_DIR = Path(__file__).resolve().parent
if str(_TESTING_DIR) not in sys.path:
    sys.path.insert(0, str(_TESTING_DIR))

from labels.manifest import EXACT_CLASSES, Manifest  # noqa: E402

SCORER_VERSION = "1.0.0"

# What a caller passes in: exchange_id -> raw vulnerability_class strings a
# predictor emitted for that exchange (may be empty/absent -- absent and
# empty are treated identically, both mean "no finding for this exchange").
Predictions = dict[str, list[str]]

# (exchange_id, exact_class, raw_prediction_string) -> one of
# {"supported", "unsupported", "insufficient", "unavailable"}. PR-4/BP-1b
# supplies the real implementation (reusing evaluation_integrity's
# evidence_audit.py); only "supported" counts towards an evidence-backed TP
# here -- see score_evidence_supported.
EvidenceGradeHook = Callable[[str, str, str], str]


# --- exact-class classifier --------------------------------------------------
# Ordered most-specific label phrases first is a READABILITY choice, not a
# correctness requirement: classify_exact() below picks the LONGEST matching
# keyword across ALL classes, not the first list entry that matches, so the
# result does not depend on this tuple's order (that is the "order-safe"
# fix for R06 -- a future edit that reorders this list, or adds an
# overlapping keyword to the wrong class, cannot silently resurrect the
# "cross-site request forgery" -> ssrf bug: csrf's specific phrase is
# strictly longer than any generic "request forgery"-shaped ssrf keyword,
# so it always wins on specificity regardless of list position). No keyword
# below is also a substring of a keyword for a different class; the
# longest-match rule is defense in depth on top of that.
_EXACT_CLASS_KEYWORDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("csrf", ("cross-site request forgery", "cross site request forgery", "csrf", "xsrf")),
    ("ssrf", ("server-side request forgery", "server side request forgery", "ssrf")),
    ("sqli", ("sql injection", "nosql injection", "sqli", "sql")),
    ("xss", ("cross-site scripting", "cross site scripting", "xss", "scripting")),
    ("ssti", ("server-side template injection", "server side template injection",
              "ssti", "template injection")),
    ("command_injection", ("os command injection", "os command", "command injection",
                           "cmdi", "shell injection", "shell command")),
    ("idor", ("insecure direct object reference", "insecure direct object", "idor", "bola",
              "broken object level authorization", "broken object-level authorization",
              "object-level authorization")),
    ("path_traversal", ("path traversal", "directory traversal", "local file inclusion",
                        "file inclusion", "lfi")),
    ("jwt", ("json web token", "jwt", "alg none", "algorithm none", "signature bypass",
             "token forgery")),
    ("auth_bypass", ("authentication bypass", "auth bypass", "login bypass",
                     "session fixation", "mfa bypass", "credential stuffing")),
    ("security_misconfiguration", ("security misconfiguration", "misconfig",
                                   "default credential", "directory listing", "verbose error",
                                   "cors misconfig", "open redirect", "missing security header")),
    ("info_disclosure", ("information disclosure", "info disclosure", "sensitive data exposure",
                         "data exposure", "sensitive information", "source code disclosure")),
    ("business_logic", ("business logic", "workflow abuse", "logic flaw",
                        "price manipulation", "quantity manipulation")),
)

# The keyword table's classes must be exactly the manifest's controlled
# vocabulary -- a mismatch here would mean this module could classify to an
# alias the manifest schema itself rejects (or silently never predict one
# EXACT_CLASSES alias). Checked at import time so drift fails loudly.
assert frozenset(c for c, _ in _EXACT_CLASS_KEYWORDS) == EXACT_CLASSES, (
    "strict_score._EXACT_CLASS_KEYWORDS classes must match labels.manifest.EXACT_CLASSES exactly")


def _normalize(s: str) -> str:
    """Lower-case and treat ``_``/``-`` as spaces, so ``sql_injection``,
    ``sql-injection`` and ``"SQL Injection"`` all match one keyword."""
    return (s or "").lower().replace("_", " ").replace("-", " ")


def classify_exact(vulnerability_class: str) -> str | None:
    """Map a raw ``vulnerability_class`` string to ONE exact alias in
    ``EXACT_CLASSES``, or ``None`` if it matches none of them.

    Picks the LONGEST matching keyword across every class (not the first
    class whose keyword list matches) -- see the module-level comment above
    ``_EXACT_CLASS_KEYWORDS`` for why that makes this order-safe."""
    c = _normalize(vulnerability_class)
    if not c:
        return None
    best_class: str | None = None
    best_len = -1
    for exact_class, keywords in _EXACT_CLASS_KEYWORDS:
        for kw in keywords:
            if len(kw) > best_len and kw in c:
                best_class = exact_class
                best_len = len(kw)
    return best_class


def _predicted_classes(raw: list[str]) -> set[str]:
    """Dedup unit: distinct exact classes a raw prediction list resolves
    to, as a set. Two raw strings that both classify to ``sqli`` (or the
    same raw string repeated) contribute exactly one ``sqli`` -- this is
    what keeps duplicate predictions from inflating recall."""
    return {c for c in (classify_exact(r) for r in raw) if c is not None}


# --- metric family: any-alert coverage (the old coarse notion) --------------

def any_alert_coverage(manifest: Manifest, predictions: Predictions) -> dict:
    """Did each scorable exchange get >=1 finding of ANY class at all,
    regardless of whether it was the right class. This is the metric an
    indiscriminate always-alert (or all-classes) predictor maxes out
    trivially -- it is reported explicitly labelled as COVERAGE, never as
    "recall", and must always be read next to ``exact_class`` below, not
    instead of it."""
    scorable = manifest.scorable()
    n = len(scorable)
    covered = sum(1 for r in scorable if predictions.get(r.exchange_id))
    return {
        "metric": "any_alert_coverage",
        "label": ("coverage: >=1 finding of ANY class per exchange -- NOT recall. "
                  "An indiscriminate detector scores 1.0 here trivially; see "
                  "exact_class for the metric that actually penalizes wrong-class "
                  "and over-alerting predictions."),
        "n_scorable": n,
        "n_covered": covered,
        "coverage": round(covered / n, 3) if n else None,
    }


# --- metric family: strict exact-class precision/recall ---------------------

def score_exact_class(manifest: Manifest, predictions: Predictions) -> dict:
    """Strict exact-class precision/recall/F1, micro and per-class.

    For every scorable (positive + negative) record:
      * each of its ``expected_classes`` that IS among the exchange's
        (deduplicated) predicted classes is a TP for that class; each that
        is NOT is a miss (FN) for that class -- this is exchange-level: a
        positive exchange with zero matching predictions racks up one FN
        per expected class it carries, never a single blanket miss that
        would hide a partially-correct multi-class prediction.
      * every predicted class NOT in ``expected_classes`` is an FP for that
        class, whether the exchange is a negative control or a positive
        exchange the predictor over-alerted on. When that FP's class is
        also in the record's ``tested_negative_classes`` it is doubly bad
        (a documented, specifically-tested negative control was violated,
        not just an untested absence of evidence) -- surfaced via the
        separate ``fp_on_tested_negative_control`` counters rather than by
        literally double-counting it into tp/fp/fn (a precision fraction
        needs each false positive counted exactly once to stay meaningful).
    """
    classes = sorted(EXACT_CLASSES)
    tp = {c: 0 for c in classes}
    fp = {c: 0 for c in classes}
    fn = {c: 0 for c in classes}
    support = {c: 0 for c in classes}
    fp_on_tested_negative = {c: 0 for c in classes}

    for record in manifest.scorable():
        predicted = _predicted_classes(predictions.get(record.exchange_id, []))
        expected = set(record.expected_classes)
        tested_negative = set(record.tested_negative_classes)

        for c in expected:
            support[c] += 1
            if c in predicted:
                tp[c] += 1
            else:
                fn[c] += 1

        for c in predicted:
            if c not in expected:
                fp[c] += 1
                if c in tested_negative:
                    fp_on_tested_negative[c] += 1

    rows = []
    for c in classes:
        prec = tp[c] / (tp[c] + fp[c]) if (tp[c] + fp[c]) else None
        rec = tp[c] / support[c] if support[c] else None
        f1 = (2 * prec * rec / (prec + rec)) if (prec and rec) else (
            0.0 if (prec is not None and rec is not None) else None)
        rows.append({
            "class": c, "support": support[c], "tp": tp[c], "fp": fp[c], "fn": fn[c],
            "fp_on_tested_negative_control": fp_on_tested_negative[c],
            "precision": round(prec, 3) if prec is not None else None,
            "recall": round(rec, 3) if rec is not None else None,
            "f1": round(f1, 3) if f1 is not None else None,
        })

    TP, FP, FN = sum(tp.values()), sum(fp.values()), sum(fn.values())
    micro_p = TP / (TP + FP) if (TP + FP) else 0.0
    micro_r = TP / (TP + FN) if (TP + FN) else 0.0
    micro_f1 = 2 * micro_p * micro_r / (micro_p + micro_r) if (micro_p + micro_r) else 0.0
    return {
        "metric": "exact_class_precision_recall",
        "per_class": rows,
        "overall": {"tp": TP, "fp": FP, "fn": FN,
                    "precision": round(micro_p, 3), "recall": round(micro_r, 3),
                    "f1": round(micro_f1, 3)},
        "fp_on_tested_negative_control_total": sum(fp_on_tested_negative.values()),
    }


# --- metric family: evidence-supported precision/recall (PR-4 scaffold) -----

def score_evidence_supported(manifest: Manifest, predictions: Predictions,
                             evidence_grade_hook: EvidenceGradeHook | None = None) -> dict:
    """Evidence-supported precision/recall -- the structure PR-4/BP-1b
    populates. With no hook supplied this returns an explicit
    ``status: "unavailable"`` sentinel with every numeric field ``None``:
    NEVER a fabricated ``0`` that would read as "we checked and found no
    evidence-backed findings" when really no evidence grading ran at all.

    When ``evidence_grade_hook`` is supplied, a predicted class only counts
    as an evidence-backed TP (or FP, for an over-prediction) if the hook
    grades at least one of the raw predictions that resolved to it as
    ``"supported"`` for that exchange/class. An expected class that was
    predicted but never graded ``"supported"`` is a miss here (FN) even
    though it is a TP in ``exact_class`` -- the two families answer
    different questions on purpose and must never be merged."""
    if evidence_grade_hook is None:
        return {
            "metric": "evidence_supported_precision_recall",
            "status": "unavailable",
            "per_class": None,
            "overall": {"tp": None, "fp": None, "fn": None,
                        "precision": None, "recall": None, "f1": None},
            "note": ("No evidence_grade_hook supplied -- this is an explicit "
                     "sentinel, not a real zero. PR-4/BP-1b (reusing "
                     "evaluation_integrity/evidence_audit.py) fills this in by "
                     "passing evidence_grade_hook=... into score()/"
                     "score_evidence_supported(), without reshaping this API."),
        }

    classes = sorted(EXACT_CLASSES)
    tp = {c: 0 for c in classes}
    fp = {c: 0 for c in classes}
    fn = {c: 0 for c in classes}
    support = {c: 0 for c in classes}

    for record in manifest.scorable():
        raw = predictions.get(record.exchange_id, [])
        by_class: dict[str, list[str]] = {}
        for r in raw:
            c = classify_exact(r)
            if c is not None:
                by_class.setdefault(c, []).append(r)
        expected = set(record.expected_classes)

        for c in expected:
            support[c] += 1
            raws = by_class.get(c, [])
            graded_supported = any(
                evidence_grade_hook(record.exchange_id, c, r) == "supported" for r in raws)
            if graded_supported:
                tp[c] += 1
            else:
                fn[c] += 1

        for c, raws in by_class.items():
            if c not in expected:
                if any(evidence_grade_hook(record.exchange_id, c, r) == "supported" for r in raws):
                    fp[c] += 1
                # An over-prediction the hook could not support is already
                # visible as an exact_class FP; it does not also inflate
                # the evidence-supported FP count (nothing was proven).

    rows = []
    for c in classes:
        prec = tp[c] / (tp[c] + fp[c]) if (tp[c] + fp[c]) else None
        rec = tp[c] / support[c] if support[c] else None
        f1 = (2 * prec * rec / (prec + rec)) if (prec and rec) else (
            0.0 if (prec is not None and rec is not None) else None)
        rows.append({
            "class": c, "support": support[c], "tp": tp[c], "fp": fp[c], "fn": fn[c],
            "precision": round(prec, 3) if prec is not None else None,
            "recall": round(rec, 3) if rec is not None else None,
            "f1": round(f1, 3) if f1 is not None else None,
        })

    TP, FP, FN = sum(tp.values()), sum(fp.values()), sum(fn.values())
    micro_p = TP / (TP + FP) if (TP + FP) else 0.0
    micro_r = TP / (TP + FN) if (TP + FN) else 0.0
    micro_f1 = 2 * micro_p * micro_r / (micro_p + micro_r) if (micro_p + micro_r) else 0.0
    return {
        "metric": "evidence_supported_precision_recall",
        "status": "computed",
        "per_class": rows,
        "overall": {"tp": TP, "fp": FP, "fn": FN,
                    "precision": round(micro_p, 3), "recall": round(micro_r, 3),
                    "f1": round(micro_f1, 3)},
    }


# --- combined report ----------------------------------------------------------

def score(manifest: Manifest, predictions: Predictions, *,
          evidence_grade_hook: EvidenceGradeHook | None = None) -> dict:
    """Score `predictions` against `manifest`, emitting all three metric
    families side by side (never merged). See the module docstring."""
    return {
        "scorer": "testing.strict_score",
        "scorer_version": SCORER_VERSION,
        "corpus": manifest.corpus,
        "n_scorable": len(manifest.scorable()),
        "n_positive": len(manifest.positives()),
        "n_negative": len(manifest.negatives()),
        "n_unresolved_excluded": len(manifest.unresolved()),
        "n_setup_excluded": len(manifest.setup_records()),
        "any_alert_coverage": any_alert_coverage(manifest, predictions),
        "exact_class": score_exact_class(manifest, predictions),
        "evidence_supported": score_evidence_supported(manifest, predictions, evidence_grade_hook),
    }


# --- precision/recall gates ---------------------------------------------------

def passes_precision_gate(report: dict, threshold: float, *, family: str = "exact_class") -> bool:
    """True iff `report[family]`'s overall precision is defined (not the
    `unavailable` sentinel) and >= `threshold`. An undefined precision
    never passes -- it is not silently treated as 0.0 or 1.0."""
    fam = report.get(family)
    if not fam:
        raise KeyError(f"unknown metric family {family!r} in report")
    precision = (fam.get("overall") or {}).get("precision")
    if precision is None:
        return False
    return precision >= threshold


def passes_recall_gate(report: dict, threshold: float, *, family: str = "exact_class") -> bool:
    """True iff `report[family]`'s overall recall is defined and >=
    `threshold`. Symmetric to `passes_precision_gate`; used by the silent
    baseline's negative-control assertion (recall must fail, not merely be
    "low")."""
    fam = report.get(family)
    if not fam:
        raise KeyError(f"unknown metric family {family!r} in report")
    recall = (fam.get("overall") or {}).get("recall")
    if recall is None:
        return False
    return recall >= threshold


# --- baselines: mandatory negative controls -----------------------------------

def baseline_silent(manifest: Manifest) -> Predictions:
    """Predicts nothing on every scorable exchange. Negative control: exact-
    class recall must be 0 on any manifest with >=1 positive record (a
    detector that never alerts cannot recall anything)."""
    return {r.exchange_id: [] for r in manifest.scorable()}


def baseline_always_alert(manifest: Manifest, fixed_class: str = "sqli") -> Predictions:
    """Predicts exactly ONE fixed/arbitrary exact class on every scorable
    exchange -- any_alert coverage is 1.0 by construction. Negative
    control: on a balanced manifest this MUST fail the exact-class
    precision gate even at that perfect coverage -- it is only ever right
    on the subset of exchanges that happen to expect `fixed_class`, and
    wrong (FP) on every other positive exchange plus every negative one."""
    if fixed_class not in EXACT_CLASSES:
        raise ValueError(f"fixed_class must be one of {sorted(EXACT_CLASSES)}, got {fixed_class!r}")
    return {r.exchange_id: [fixed_class] for r in manifest.scorable()}


def baseline_all_classes(manifest: Manifest) -> Predictions:
    """Predicts EVERY exact class on every scorable exchange. Negative
    control: perfect exact-class recall (every expected class is always
    among the predictions, by construction) but the worst-case precision --
    every exchange also racks up an FP for every class it was NOT
    positive/expected for (12 FPs per single-class positive exchange, 13
    per negative exchange)."""
    all_classes = sorted(EXACT_CLASSES)
    return {r.exchange_id: list(all_classes) for r in manifest.scorable()}
