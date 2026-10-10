"""Apply the strict scorer to a saved run -- the runner that makes PR-3/PR-5
load-bearing (NC-1, from re-review finding N01).

Why this exists: `testing/strict_score.py` (exact-class scorer + baselines) and
`testing/eval_adapter.py` (`rescore_saved_run`) were built and tested in cycle 1,
but nothing OUTSIDE the testing tier consumed them -- a live/benchmark run still
reported through the coarse OWASP-category scorer. This module is the entry point
that CONSUMES them: it takes a saved run artifact off disk, recomputes the strict
scorecard (read-only, no model/target/store -- via `eval_adapter.rescore_saved_run`),
and -- crucially -- runs the three mandatory indiscriminate baselines through the
same precision/recall gates as a built-in negative control. If a baseline PASSES a
gate (i.e. the manifest + scorer cannot tell an indiscriminate guesser apart from a
real detector), the runner REFUSES to certify the scorecard and raises, rather than
emitting a number that looks trustworthy but isn't.

Coarse OWASP-category metrics are never presented as current: if a saved artifact
carries a legacy coarse block (or one is passed in), it is echoed only under an
explicit ``historical_coarse`` label, never at the top level beside the strict
metrics.

Offline, deterministic, read-only. Invokes no model, no target, no network, and no
`harness.store`.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

# Mirror the sys.path idiom testing/eval_adapter.py already uses so this imports
# whether the caller put testing/ on sys.path or imports us package-qualified.
_TESTING_DIR = Path(__file__).resolve().parent
if str(_TESTING_DIR) not in sys.path:
    sys.path.insert(0, str(_TESTING_DIR))

import strict_score  # noqa: E402
import eval_adapter  # noqa: E402
from labels.manifest import Manifest, load_manifest  # noqa: E402

# Default gate thresholds. The point of a gate is a bar a real detector should be
# able to clear and an indiscriminate baseline must not. 0.5 is a deliberately
# modest, defensible default -- the baselines fail it by construction on any
# balanced manifest (always-alert is right on at most one class; all-classes racks
# up an FP for every non-matching class; silent recalls nothing). Callers can
# raise the bar; they should not lower it below what the baselines can clear.
DEFAULT_PRECISION_GATE = 0.5
DEFAULT_RECALL_GATE = 0.5


class StrictScorecardError(ValueError):
    """Raised when the runner refuses to certify a scorecard: the mandatory
    indiscriminate baselines did NOT all fail their gates, so on this manifest the
    strict scorer cannot distinguish a real detector from a guesser. Emitting the
    scorecard anyway would reproduce exactly the "looks high-recall, means nothing"
    defect the strict scorer exists to prevent."""


def baseline_controls(manifest: Manifest, *, precision_gate: float,
                      recall_gate: float) -> dict[str, Any]:
    """Run the three mandatory baselines through the gates. Each control is
    SATISFIED when its baseline FAILS the gate it is meant to fail:

    * always_alert (one fixed class everywhere) must FAIL the precision gate;
    * all_classes (every class everywhere)      must FAIL the precision gate;
    * silent (nothing anywhere)                 must FAIL the recall gate.

    Returns a report with each baseline's gate outcome and an overall
    ``discriminating`` flag (True iff every control is satisfied)."""
    always = strict_score.baseline_always_alert(manifest)
    allcls = strict_score.baseline_all_classes(manifest)
    silent = strict_score.baseline_silent(manifest)

    r_always = strict_score.score(manifest, always)
    r_allcls = strict_score.score(manifest, allcls)
    r_silent = strict_score.score(manifest, silent)

    # A control is OK when the baseline does NOT pass the gate it should fail.
    always_passes = strict_score.passes_precision_gate(r_always, precision_gate)
    allcls_passes = strict_score.passes_precision_gate(r_allcls, precision_gate)
    silent_passes = strict_score.passes_recall_gate(r_silent, recall_gate)

    controls = {
        "always_alert": {
            "gate": "precision", "threshold": precision_gate,
            "passed_gate": always_passes, "control_ok": not always_passes,
            "overall": r_always["exact_class"]["overall"],
        },
        "all_classes": {
            "gate": "precision", "threshold": precision_gate,
            "passed_gate": allcls_passes, "control_ok": not allcls_passes,
            "overall": r_allcls["exact_class"]["overall"],
        },
        "silent": {
            "gate": "recall", "threshold": recall_gate,
            "passed_gate": silent_passes, "control_ok": not silent_passes,
            "overall": r_silent["exact_class"]["overall"],
        },
    }
    controls["discriminating"] = all(c["control_ok"] for c in controls.values()
                                     if isinstance(c, dict))
    return controls


def _historical_coarse(saved: dict, coarse_metrics: dict | None) -> dict | None:
    """Wrap any coarse OWASP-category metrics under an explicit historical label
    so they can never be read as the current/strict contract. Prefers an
    explicitly passed block, else a legacy block carried on the saved artifact."""
    coarse = coarse_metrics
    if coarse is None:
        for key in ("coarse_metrics", "legacy_coarse_metrics", "legacy_metrics"):
            if isinstance(saved.get(key), dict):
                coarse = saved[key]
                break
    if coarse is None:
        return None
    return {
        "label": "historical (coarse OWASP-category scorer -- NOT the strict "
                 "exact-class contract; shown for comparison only)",
        "metrics": coarse,
    }


def apply_strict_scorecard(
    saved: dict, manifest: Manifest, *, git_revision: str,
    precision_gate: float = DEFAULT_PRECISION_GATE,
    recall_gate: float = DEFAULT_RECALL_GATE,
    coarse_metrics: dict | None = None,
) -> dict[str, Any]:
    """Recompute the strict scorecard for a saved run and certify it against the
    mandatory baselines. Raises `StrictScorecardError` if the baselines do not all
    fail their gates on this manifest. Read-only; calls no model/target/store."""
    controls = baseline_controls(manifest, precision_gate=precision_gate,
                                 recall_gate=recall_gate)
    if not controls["discriminating"]:
        failed = [name for name, c in controls.items()
                  if isinstance(c, dict) and not c["control_ok"]]
        raise StrictScorecardError(
            f"refusing to certify a strict scorecard on corpus {manifest.corpus!r}: "
            f"baseline(s) {failed} passed a gate they must fail at "
            f"precision>={precision_gate}/recall>={recall_gate} -- the scorer cannot "
            f"tell an indiscriminate guesser apart from a real detector here.")

    artifact = eval_adapter.rescore_saved_run(saved, manifest, git_revision=git_revision)

    return {
        "kind": artifact["kind"],  # historical_rescore
        "scorer": "testing.strict_score",
        "host": artifact["host"],
        "corpus": artifact["corpus"],
        "provenance": artifact["provenance"],
        "metrics": artifact["metrics"],
        "report_cross_check": artifact["report_cross_check"],
        "baseline_controls": controls,
        "gates": {"precision": precision_gate, "recall": recall_gate},
        "historical_coarse": _historical_coarse(saved, coarse_metrics),
    }


def run_from_files(
    saved_path: str | Path, manifest_path: str | Path, *, git_revision: str,
    precision_gate: float = DEFAULT_PRECISION_GATE,
    recall_gate: float = DEFAULT_RECALL_GATE,
) -> dict[str, Any]:
    """Load a saved-run JSON artifact and a label manifest from disk, then
    `apply_strict_scorecard`. Neither file is written; nothing else is read."""
    saved = json.loads(Path(saved_path).read_text(encoding="utf-8"))
    manifest = load_manifest(manifest_path)
    return apply_strict_scorecard(
        saved, manifest, git_revision=git_revision,
        precision_gate=precision_gate, recall_gate=recall_gate)


def _fmt_overall(o: dict | None) -> str:
    if not o:
        return "precision=?     recall=?"
    p, r = o.get("precision"), o.get("recall")
    ps = "unavailable" if p is None else f"{p:.3f}"
    rs = "unavailable" if r is None else f"{r:.3f}"
    return f"precision={ps:>11} recall={rs}"


def format_scorecard(scorecard: dict) -> str:
    lines: list[str] = []
    lines.append(f"# Strict scorecard ({scorecard['kind']}) -- corpus={scorecard['corpus']} "
                 f"host={scorecard['host']}")
    lines.append(f"scorer={scorecard['scorer']}  provenance={scorecard['provenance']}")
    lines.append("")
    metrics = scorecard.get("metrics") or {}
    for family in ("exact_class", "evidence_supported", "any_alert_coverage"):
        fam = metrics.get(family)
        if isinstance(fam, dict):
            overall = fam.get("overall") if isinstance(fam.get("overall"), dict) else fam
            lines.append(f"  {family:24s} {_fmt_overall(overall)}")
    lines.append("")
    lines.append("Baseline negative controls (each MUST fail its gate):")
    ctrls = scorecard["baseline_controls"]
    for name in ("always_alert", "all_classes", "silent"):
        c = ctrls[name]
        verdict = "OK (failed gate)" if c["control_ok"] else "!! PASSED GATE -- non-discriminating"
        lines.append(f"  {name:14s} {c['gate']}>={c['threshold']}: {verdict}  {_fmt_overall(c['overall'])}")
    lines.append(f"  => discriminating={ctrls['discriminating']}")
    hc = scorecard.get("historical_coarse")
    if hc:
        lines.append("")
        lines.append(f"  [{hc['label']}]")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Apply the strict exact-class scorer to a saved run (read-only). "
                    "Refuses to certify a scorecard whose baselines do not fail their gates.")
    ap.add_argument("saved_run", help="path to a saved-run JSON artifact (build_eval_artifact shape)")
    ap.add_argument("manifest", help="path to an exact-class label manifest JSON")
    ap.add_argument("--git-revision", default="unknown", help="git revision to stamp in provenance")
    ap.add_argument("--precision-gate", type=float, default=DEFAULT_PRECISION_GATE)
    ap.add_argument("--recall-gate", type=float, default=DEFAULT_RECALL_GATE)
    args = ap.parse_args(argv)
    try:
        scorecard = run_from_files(
            args.saved_run, args.manifest, git_revision=args.git_revision,
            precision_gate=args.precision_gate, recall_gate=args.recall_gate)
    except StrictScorecardError as e:
        print(f"REFUSED: {e}", file=sys.stderr)
        return 2
    print(format_scorecard(scorecard))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
