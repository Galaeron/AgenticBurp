"""Repeated / blind evaluation program (W-23).

Extends W-8's single scored run into a REPEATED one: run the same seeded eval
N (>=5) times, report mean +/- variance per metric so a headline number is never
trusted on a single run's luck (full-pipeline recall has swung 8/13 -> 7/13 on
variance alone), and gate on a recall AND precision floor. Variance is
QUANTIFIED (stdev/min/max), so it is explained rather than observed anecdotally,
and a run whose spread is too wide to trust the mean is flagged.

This is the harness; the runs themselves need the GPU corpus, and the scored CI
tier (W-8) is its enforcement point. The per-run scorer is injectable, so the
aggregation + floor logic is tested without a live model; a real program plugs
testing/score.py in, once per seed.
"""
from __future__ import annotations

import statistics
from dataclasses import dataclass, field

# Above this per-metric stdev, the mean is too unstable to trust on its own.
_HIGH_VARIANCE_STDEV = 0.10


@dataclass
class EvalRun:
    recall: float
    precision: float
    per_class_recall: dict = field(default_factory=dict)
    seed: int = 0
    # P1.7: which corpus (+ implicitly, whatever budget/config the caller
    # bundles into this label -- e.g. "test-target@budget400") this run was
    # scored against. Empty means unlabeled; EvalReport.compare() treats an
    # unlabeled corpus the same as a mismatched one -- never assumed same.
    corpus_id: str = ""


@dataclass
class EvalReport:
    runs: list[EvalRun]
    recall_floor: float | None = None
    precision_floor: float | None = None

    def _agg(self, select) -> dict:
        vals = [select(r) for r in self.runs]
        if not vals:
            return {"mean": None, "stdev": None, "min": None, "max": None, "n": 0, "high_variance": False}
        stdev = round(statistics.pstdev(vals), 4) if len(vals) > 1 else 0.0
        return {
            "mean": round(statistics.fmean(vals), 4),
            "stdev": stdev,
            "min": round(min(vals), 4),
            "max": round(max(vals), 4),
            "n": len(vals),
            "high_variance": stdev > _HIGH_VARIANCE_STDEV,
        }

    def summary(self) -> dict:
        return {
            "runs": len(self.runs),
            "recall": self._agg(lambda r: r.recall),
            "precision": self._agg(lambda r: r.precision),
        }

    def passes_floor(self) -> tuple[bool, list[str]]:
        """(ok, reasons). Gates on the MEAN so one lucky run can't clear the bar,
        and complains if variance is too high to trust the mean at all."""
        s = self.summary()
        reasons: list[str] = []
        if self.recall_floor is not None and s["recall"]["mean"] is not None \
                and s["recall"]["mean"] < self.recall_floor:
            reasons.append(f"mean recall {s['recall']['mean']} < floor {self.recall_floor}")
        if self.precision_floor is not None and s["precision"]["mean"] is not None \
                and s["precision"]["mean"] < self.precision_floor:
            reasons.append(f"mean precision {s['precision']['mean']} < floor {self.precision_floor}")
        for metric in ("recall", "precision"):
            if s[metric]["high_variance"]:
                reasons.append(
                    f"{metric} variance too high to trust the mean "
                    f"(stdev {s[metric]['stdev']} over {s[metric]['n']} runs)")
        return (not reasons, reasons)

    def corpus_ids(self) -> set[str]:
        """Every distinct corpus_id label across this report's runs, INCLUDING
        the empty string when any run is unlabeled -- a caller checking
        `fully_labeled()` first will therefore never mistake "one of my runs
        had no label" for "my runs only ever used one (labeled) corpus"."""
        return {r.corpus_id for r in self.runs}

    def fully_labeled(self) -> bool:
        """True only when every run in this report carries a non-empty
        corpus_id. A report is REJECTED as a partial-label report (R08) if
        even one run is unlabeled -- an unlabeled run is not evidence it
        matches anything, so it must never be silently dropped from the
        comparison instead of disqualifying it."""
        return bool(self.runs) and all(r.corpus_id for r in self.runs)

    def compare(self, other: "EvalReport") -> dict:
        """Compare this report's summary against another's (e.g. two model
        variants, or before/after a change), honestly labelling whether the
        delta is comparable under checked (corpus-matched) conditions -- NOT
        a claim of causal model attribution (P1.7/R08). `attributable_to_model_only`
        is True only when BOTH reports are `fully_labeled()` (every run
        carries a non-empty corpus_id -- a report with even one unlabeled
        run is rejected outright, never partially credited) AND their
        corpus_id sets are identical. Matching corpus labels establishes
        corpus/config compatibility only; it is not proof the observed delta
        is caused by the model alone."""
        mine, theirs = self.corpus_ids(), other.corpus_ids()
        comparable = self.fully_labeled() and other.fully_labeled() and mine == theirs
        s1, s2 = self.summary(), other.summary()

        def _delta(metric: str):
            a, b = s1[metric]["mean"], s2[metric]["mean"]
            return round(b - a, 4) if (a is not None and b is not None) else None

        if comparable:
            reason = ("same corpus label(s) on both sides, every run labeled -- "
                      "comparable under checked conditions, not proof of causal model attribution")
        else:
            reason = (f"different, unlabeled, or partially unlabeled corpora "
                      f"({mine or '(none)'} vs {theirs or '(none)'}) "
                      "-- this delta may reflect corpus/budget differences, not the model alone")

        return {
            "recall_delta": _delta("recall"),
            "precision_delta": _delta("precision"),
            "attributable_to_model_only": comparable,
            "reason": reason,
        }


def run_repeated(scorer, seeds, *, recall_floor: float | None = None,
                 precision_floor: float | None = None) -> EvalReport:
    """Run `scorer(seed) -> EvalRun` once per seed (>=5 recommended for variance)."""
    runs = [scorer(s) for s in seeds]
    return EvalReport(runs=runs, recall_floor=recall_floor, precision_floor=precision_floor)
