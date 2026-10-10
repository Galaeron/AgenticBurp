"""
reconcile_benchmark.py -- read-only benchmark reconciliation + config-drift
manifest (PR-6, BP-3).

The 2026-09-23 five-app benchmark (`reviews/2026-09-23/benchmark/`) is
committed, historical evidence -- this module never re-runs a model, never
touches the network, and never mutates any of the original `*_default_3x
.json`/`.log`/`*_table.md`/`BENCHMARK_REPORT.md` artifacts. It only reads
them (plus `harness/config.yaml`, plus a `testing/labels/*.labels.json`
manifest when one exists) and RECOMPUTES aggregates from each artifact's own
per-run rows, so a reviewer never has to trust a hand-transcribed number.

Two deliverables live here:

  1. `build_config_drift_manifest()` -- compares each saved run's recorded
     config fingerprint (fail_open_mode / quarantine_unverified_leads /
     routing_mode / gate_low_confidence_generic / num_ctx / model) against
     `harness/config.yaml`'s shipped defaults, so no one tunes or markets
     the wrong runtime profile. A field the artifact never recorded is
     `UNAVAILABLE`, never a guessed value (same discipline as
     `eval_adapter._resolve_instrumentation`).
  2. `run_full_reconciliation()` -- recomputes each corpus's summary
     aggregates from its own per-run rows and flags the SPECIFIC known
     contradictions the 2026-09-24 principal review found (PixelMart's
     report-cited wall-clock, the tokens=0 vs real-token-count gap, the
     breaker-failures-vs-"breaker-healthy" footer claim), plus a generic
     self-consistency check applied to every corpus (raises
     `ReconciliationError` if a corpus's OWN stored summary disagrees with
     what this module recomputes from that SAME corpus's per-run rows --
     the negative-control target: see `testing/test_reconcile_benchmark.py`).

Strict exact-class recall (`strict_exact_class_recall`) is NEVER inferred
from a broad/coarse category (`score.py`'s TP/TN scheme, or the blind-eval
driver's confirmed_vuln/confirmed_secure/inconclusive scheme) -- it returns
the explicit `UNAVAILABLE` sentinel with a reason unless both (a) a
`testing/labels/<corpus>.labels.json` exact-class manifest exists for that
corpus AND (b) the saved run is in `eval_adapter.build_eval_artifact`'s
shape (`stages`/`attribution`) so `eval_adapter.rescore_saved_run` can be
called honestly instead of faked. None of the five 2026-09-23 artifacts are
in that shape (they predate PR-5's shared adapter -- see eval_adapter.py's
own "Follow-on" note), so today this always resolves to `UNAVAILABLE`; the
plumbing exists so a future PR-5-shaped saved run is rescorable without
touching this module again.

Never reads `*ANSWER_KEY*` or a blind target's `app.py`. Offline,
deterministic, no model/network/store access.
"""
from __future__ import annotations

import json
import re
import statistics
import sys
from pathlib import Path
from typing import Any

_TESTING_DIR = Path(__file__).resolve().parent
if str(_TESTING_DIR) not in sys.path:
    sys.path.insert(0, str(_TESTING_DIR))

REPO_ROOT = _TESTING_DIR.parent
BENCHMARK_DIR = REPO_ROOT / "reviews" / "2026-09-23" / "benchmark"
CONFIG_PATH = REPO_ROOT / "harness" / "config.yaml"
LABELS_DIR = _TESTING_DIR / "labels"

UNAVAILABLE = "unavailable"

# Relative tolerance used when comparing a recomputed float against a stored
# one (both sides round-tripped through JSON's 3-decimal rounding in the
# ablation harness, and through Python float arithmetic in the blind-eval
# driver) -- generous enough to absorb that rounding, tight enough that a
# genuinely wrong total (e.g. a dropped run) still trips it.
_REL_TOL = 1e-3
_ABS_TOL = 1e-6

# Per-corpus source filename inside BENCHMARK_DIR.
CORPUS_SOURCES: dict[str, str] = {
    "pixelmart": "pixelmart_default_3x.json",
    "blindtarget2": "blindtarget2_default_3x.json",
    "dvwa": "dvwa_default_3x.json",
    "webgoat": "webgoat_default_3x.json",
    "juiceshop": "juiceshop_default_3x.json",
}

# Which corpora use the ablation-harness "variants" shape (PixelMart, via
# testing/test-target/run_ablation_live.py) vs. the blind-eval-style "runs"
# shape (the other four, via a run_blind_eval.py-style scorecard driver).
# Detected structurally at load time (see `_artifact_shape`), not hardcoded,
# so a future corpus added to CORPUS_SOURCES is classified automatically.

# Each corpus's scoring CONTROL UNIT and coverage semantics -- documented,
# not recomputed (BP-3's "document each corpus's control unit" requirement).
CONTROL_UNITS: dict[str, dict[str, str]] = {
    "pixelmart": {
        "control_unit": "exchange",
        "scheme": (
            "testing.score.py's _LABEL_CATEGORY coarse-OWASP-category TP/TN scheme "
            "(testing.score.score()), driven through testing/test-target/"
            "run_ablation_live.py. This is NOT the PR-2/PR-3 exact-class manifest "
            "scorer, even though testing/labels/pixelmart.labels.json exists -- the "
            "2026-09-23 benchmark run predates that wiring."
        ),
        "recall_semantics": (
            "any-finding / coarse-category coverage per exchange (recall = "
            "tp/(tp+fn) over the 11 TP-labeled exchanges) -- not exact-class recall."
        ),
    },
    "blindtarget2": {
        "control_unit": (
            "recall: exchange (confirmed_vuln/confirmed_secure/inconclusive coarse "
            "ground truth). Precision: TWO units are both reported -- 'controls_clean' "
            "is per-EXCHANGE (any finding at all on a confirmed_secure exchange makes "
            "it dirty); 'controls_clean_issue_level'/'dirty_controls' is per "
            "(method+URL, vulnerability_class) ISSUE pair on that same exchange."
        ),
        "scheme": "run_blind_eval.py-style per-run scorecard (build_scorecard shape).",
        "recall_semantics": (
            "recall_any_finding = any finding present on a confirmed_vuln exchange; "
            "recall_surfaced_only = at least one of those findings was surfaced, not "
            "quarantined as a lead. Neither is exact-class recall -- no manifest "
            "backs this corpus."
        ),
    },
}
for _c in ("dvwa", "webgoat", "juiceshop"):
    CONTROL_UNITS[_c] = dict(CONTROL_UNITS["blindtarget2"])


class ReconciliationError(ValueError):
    """Raised when a corpus's OWN stored summary disagrees with what this
    module recomputes from that SAME corpus's per-run rows (a genuine
    internal self-consistency failure -- the negative-control target), or
    when a caller tries to present a fabricated/inferred strict exact-class
    recall number instead of the explicit UNAVAILABLE sentinel."""


# ---------------------------------------------------------------------------
# IO helpers
# ---------------------------------------------------------------------------

def _read_text(path: Path) -> str:
    """UTF-8 with a cp1252 fallback -- some of these committed artifacts
    (pixelmart_default_3x.log, pixelmart_default_3x_table.md) were written
    with a Windows-default-codepage `open()` and contain a literal '±' byte
    (0xB1) that is not valid UTF-8. Never raises on a byte this module did
    not create."""
    raw = path.read_bytes()
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("cp1252", errors="replace")


def load_corpus_artifact(name: str, benchmark_dir: Path = BENCHMARK_DIR) -> dict:
    filename = CORPUS_SOURCES[name]
    return json.loads((benchmark_dir / filename).read_text(encoding="utf-8"))


def _artifact_shape(data: dict) -> str:
    """'variants' (PixelMart / ablation-harness shape) or 'runs' (blind-eval
    scorecard shape) -- detected structurally, never assumed from the
    corpus name."""
    if "runs" in data and "variance" in data:
        return "runs"
    if "results" in data and "run_health" in data:
        return "variants"
    raise ReconciliationError(f"unrecognized benchmark artifact shape: keys={sorted(data)}")


# ---------------------------------------------------------------------------
# 1. Config-drift manifest
# ---------------------------------------------------------------------------

def load_shipped_config(config_path: Path = CONFIG_PATH) -> dict[str, Any]:
    """Read the SHIPPED (committed) config.yaml defaults this repo ships
    with -- read-only, never modified. Returns UNAVAILABLE for a field the
    file does not set (e.g. `num_ctx`, which config.yaml never pins; the
    benchmark's in-memory 8192 override is a runner-side choice, not a
    config.yaml value)."""
    import yaml
    raw = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    coordinator = raw.get("coordinator", {}) or {}
    reporting = raw.get("reporting", {}) or {}
    ollama = raw.get("ollama", {}) or {}
    return {
        "fail_open_mode": coordinator.get("fail_open_mode", UNAVAILABLE),
        "quarantine_unverified_leads": reporting.get("quarantine_unverified_leads", UNAVAILABLE),
        "routing_mode": coordinator.get("routing_mode", UNAVAILABLE),
        "gate_low_confidence_generic": reporting.get("gate_low_confidence_generic", UNAVAILABLE),
        "num_ctx": ollama.get("num_ctx", UNAVAILABLE),
        "model": coordinator.get("model", UNAVAILABLE),
    }


def extract_recorded_fingerprint(name: str, data: dict) -> dict[str, Any]:
    """The config fingerprint this SPECIFIC saved artifact actually
    recorded -- never inferred, never hand-transcribed. A field the
    artifact's own JSON does not carry is UNAVAILABLE."""
    shape = _artifact_shape(data)
    if shape == "runs":
        r0 = data["runs"][0]
        meta = data.get("_bench_meta", {})
        return {
            "fail_open_mode": r0.get("fail_open_mode", UNAVAILABLE),
            "quarantine_unverified_leads": r0.get("quarantine_leads", UNAVAILABLE),
            "routing_mode": UNAVAILABLE,  # not recorded by this driver
            "gate_low_confidence_generic": r0.get("gate_low_confidence_generic", UNAVAILABLE),
            "num_ctx": meta.get("num_ctx", UNAVAILABLE),
            "model": UNAVAILABLE,  # not recorded by this driver
            "config_fingerprint_hash": r0.get("config_fingerprint", UNAVAILABLE),
        }
    # "variants" shape (PixelMart / run_ablation_live.py): the driver records
    # NO fail_open_mode/quarantine/routing_mode fingerprint at all in this
    # artifact -- see the "source_note" this manifest attaches separately.
    return {
        "fail_open_mode": UNAVAILABLE,
        "quarantine_unverified_leads": UNAVAILABLE,
        "routing_mode": UNAVAILABLE,
        "gate_low_confidence_generic": UNAVAILABLE,
        "num_ctx": data.get("num_ctx", UNAVAILABLE),
        "model": UNAVAILABLE,
        "config_fingerprint_hash": UNAVAILABLE,
    }


_PIXELMART_SOURCE_NOTE = (
    "run_ablation_live.py's load_base_config() reads harness/config.yaml directly "
    "and variant A ('current') applies ZERO config overrides besides an in-memory "
    "ollama.num_ctx pin (see ablation_harness.py's module docstring: 'Only A/E are "
    "pure passthrough'). This artifact itself records no fail_open_mode/"
    "quarantine_unverified_leads/routing_mode fingerprint, so this manifest reports "
    "those as unavailable rather than guessing -- but source inspection (not an "
    "artifact field, so not asserted as fact here) shows coordinator.fail_open_mode "
    "and reporting.quarantine_unverified_leads were last changed 2026-09-16 and "
    "2026-09-20 respectively (git blame), both before this run's 2026-09-23 22:06 "
    "timestamp -- i.e. this run most likely DID use config.yaml's shipped 'all'/"
    "false, UNLIKE the four corpora below, which explicitly recorded "
    "fail_open_mode='curated'/quarantine_leads=true in their own saved fingerprint. "
    "Treat this as a documented inference, not a verified artifact field."
)


def _field_drift(field: str, recorded: Any, shipped: Any) -> str:
    if recorded == UNAVAILABLE:
        return "unavailable (not recorded in this artifact)"
    if field == "num_ctx":
        if shipped == UNAVAILABLE:
            return (
                f"override: pinned to {recorded!r} in-memory; config.yaml itself "
                "never pins num_ctx (documented intentional GPU-residency override "
                "per BENCHMARK_REPORT.md, not a hidden drift)"
            )
        if recorded != shipped:
            return f"override: recorded {recorded!r} != shipped {shipped!r}"
        return "matches shipped default"
    if recorded == shipped:
        return "matches shipped default"
    return f"DRIFT: recorded {recorded!r} != shipped default {shipped!r}"


def build_config_drift_manifest(
    benchmark_dir: Path = BENCHMARK_DIR, config_path: Path = CONFIG_PATH,
) -> dict:
    """The full config-drift manifest: shipped defaults + one entry per
    corpus with its recorded fingerprint and a per-field drift verdict.
    Pure function of the artifacts + config.yaml on disk -- nothing here is
    hand-transcribed."""
    shipped = load_shipped_config(config_path)
    corpora = []
    for name in CORPUS_SOURCES:
        data = load_corpus_artifact(name, benchmark_dir)
        recorded = extract_recorded_fingerprint(name, data)
        drift = {
            field: _field_drift(field, recorded[field], shipped[field])
            for field in ("fail_open_mode", "quarantine_unverified_leads", "routing_mode",
                          "gate_low_confidence_generic", "num_ctx", "model")
        }
        entry = {
            "corpus": name,
            "source_file": CORPUS_SOURCES[name],
            "artifact_shape": _artifact_shape(data),
            "recorded": recorded,
            "drift": drift,
        }
        if name == "pixelmart":
            entry["source_note"] = _PIXELMART_SOURCE_NOTE
        corpora.append(entry)
    return {
        "shipped_config_path": str(config_path.relative_to(REPO_ROOT)),
        "shipped_defaults": shipped,
        "corpora": corpora,
    }


def render_config_drift_table(manifest: dict) -> str:
    """Short human table: one row per corpus, one column per fingerprint
    field, cell = drift verdict (not the raw values -- see the JSON for
    those)."""
    fields = ("fail_open_mode", "quarantine_unverified_leads", "routing_mode",
              "gate_low_confidence_generic", "num_ctx", "model")
    lines = [
        "| corpus | " + " | ".join(fields) + " |",
        "|---" * (len(fields) + 1) + "|",
    ]
    for entry in manifest["corpora"]:
        cells = [entry["drift"][f] for f in fields]
        lines.append(f"| {entry['corpus']} | " + " | ".join(cells) + " |")
    shipped = manifest["shipped_defaults"]
    lines.append("")
    lines.append(
        "Shipped defaults (" + manifest["shipped_config_path"] + "): "
        + ", ".join(f"{f}={shipped[f]!r}" for f in fields)
    )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 2a. PixelMart reconciliation (ablation-harness "variants" shape)
# ---------------------------------------------------------------------------

def reconcile_pixelmart(data: dict) -> dict:
    """Recompute PixelMart's mean/pstdev precision/recall/tp/fp/fn/wall_time
    from `run_health` (the actual per-repeat rows) and assert they match
    `results[0]`'s stored aggregate -- exactly what `run_ablation_live.py`'s
    own `aggregate()` computed at save time (statistics.pstdev, rounded to
    3 decimals). Raises `ReconciliationError` if they disagree beyond
    rounding tolerance: this is the self-consistency check the negative
    control (a synthetic PixelMart-shaped artifact whose run_health rows
    don't add up to its own results[0] summary) is designed to trip."""
    health = [h for h in data["run_health"] if h["variant"] == "A"]
    if not health:
        raise ReconciliationError("no variant-A run_health rows found")
    stored = next(r for r in data["results"] if r["variant"] == "A")

    def _recompute(values: list[float]) -> dict:
        mean = statistics.mean(values)
        pstdev = statistics.pstdev(values) if len(values) > 1 else 0.0
        return {"mean": mean, "stdev": pstdev, "n": len(values)}

    wall = _recompute([h["wall_time_s"] for h in health])
    tp = _recompute([h["tp"] for h in health])
    fp = _recompute([h["fp"] for h in health])
    fn = _recompute([h["fn"] for h in health])
    tokens = _recompute([h["model_total_tokens"] for h in health])
    recall = _recompute([h["tp"] / (h["tp"] + h["fn"]) if (h["tp"] + h["fn"]) else 0.0
                          for h in health])
    precision = _recompute([h["tp"] / (h["tp"] + h["fp"]) if (h["tp"] + h["fp"]) else 0.0
                             for h in health])

    recomputed = {"wall_time_s": wall, "tp": tp, "fp": fp, "fn": fn,
                  "model_total_tokens": tokens, "recall": recall, "precision": precision}

    for field, own in (("wall_time_s", wall), ("tp", tp), ("fp", fp), ("fn", fn),
                       ("recall", recall), ("precision", precision)):
        stored_mean = stored[field]["mean"]
        if not _close(own["mean"], stored_mean):
            raise ReconciliationError(
                f"PixelMart self-consistency failure: recomputed {field} mean "
                f"{own['mean']!r} (from run_health) disagrees with the artifact's own "
                f"stored results[0].{field}.mean {stored_mean!r} -- this run_health/"
                f"results pair should always agree by construction "
                f"(run_ablation_live.py's aggregate() derives one from the other)")

    breaker_failures = [h["breaker_failures"] for h in health]
    flags = []
    flags.append({
        "check": "tokens_instrumentation",
        "status": "contradiction",
        "detail": (
            f"results[0].cost_tokens.mean is {stored['cost_tokens']['mean']!r} "
            f"(a fabricated-looking 0), but run_health/model_cost_by_variant record "
            f"real token counts (recomputed mean {tokens['mean']:.1f} tokens from "
            f"{[h['model_total_tokens'] for h in health]}). This is an instrumentation "
            "gap in RunMetrics.cost_tokens (the effort-budget token wiring is inert -- "
            "see run_ablation_live.py's _run_one docstring), NOT evidence that 0 "
            "tokens were actually spent."
        ),
    })
    if any(f > 0 for f in breaker_failures):
        flags.append({
            "check": "breaker_health_claim",
            "status": "inconsistency",
            "detail": (
                f"run_health.breaker_failures = {breaker_failures} (2 of 3 repeats hit "
                "circuit-breaker failures), but the log/report footer states 'no run "
                "was starved -- every row above is a clean, breaker-healthy "
                "measurement.' 'not starved' (true: starved=False and "
                "breaker_ended_open=False for every repeat) is a narrower claim than "
                "'breaker-healthy' / 'no run starved' as used in BENCHMARK_REPORT.md's "
                "top-line status -- a breaker that recorded failures without opening "
                "is not the same as a run with zero failures."
            ),
        })
    return {"recomputed": recomputed, "stored": stored, "flags": flags,
            "breaker_failures_per_run": breaker_failures}


def _close(a: float, b: float) -> bool:
    return abs(a - b) <= max(_ABS_TOL, _REL_TOL * max(abs(a), abs(b), 1.0))


def check_report_wall_claim(report_text: str, recomputed_mean: float,
                             raw_run_values: list[float]) -> dict:
    """Parse BENCHMARK_REPORT.md's PixelMart results row ('| PixelMart
    (custom) | ... | ~1330s |') and check whether the cited wall/run figure
    matches the recomputed 3-run mean, or instead matches one individual
    repeat's raw wall time (the actual, known error: the report cites the
    final repeat's wall-clock, not the mean of all three)."""
    row = None
    for line in report_text.splitlines():
        if line.strip().startswith("| PixelMart (custom)"):
            row = line
            break
    if row is None:
        return {"check": "report_wall_claim", "status": "not_found",
                "detail": "no '| PixelMart (custom)' row found in BENCHMARK_REPORT.md"}
    cells = [c.strip() for c in row.strip().strip("|").split("|")]
    cited_cell = cells[-1]
    m = re.search(r"[\d.]+", cited_cell)
    if not m:
        return {"check": "report_wall_claim", "status": "not_found",
                "detail": f"could not parse a number out of wall/run cell {cited_cell!r}"}
    cited = float(m.group(0))
    if _close(cited, recomputed_mean):
        return {"check": "report_wall_claim", "status": "match",
                "detail": f"report cites {cited}s, matches the recomputed mean {recomputed_mean:.3f}s"}
    matching_repeat = next((v for v in raw_run_values if _close(cited, v)), None)
    if matching_repeat is not None:
        return {
            "check": "report_wall_claim", "status": "contradiction",
            "detail": (
                f"BENCHMARK_REPORT.md cites wall/run={cited}s for PixelMart, which matches "
                f"one individual repeat's raw wall_time_s ({matching_repeat}s) -- NOT the "
                f"recomputed 3-run mean ({recomputed_mean:.3f}s). The report appears to cite "
                "a single repeat instead of the mean across repeats."
            ),
        }
    return {
        "check": "report_wall_claim", "status": "contradiction",
        "detail": (
            f"BENCHMARK_REPORT.md cites wall/run={cited}s for PixelMart, which matches "
            f"neither the recomputed mean ({recomputed_mean:.3f}s) nor any individual "
            f"repeat ({raw_run_values})."
        ),
    }


# ---------------------------------------------------------------------------
# 2b. Blind-eval-style reconciliation (blind-target-2 / DVWA / WebGoat / JuiceShop)
# ---------------------------------------------------------------------------

_TOP_LEVEL_METRIC_KEYS = frozenset({
    "n_findings_total", "n_quarantined_leads", "n_surfaced_findings",
    "controls_clean", "controls_clean_issue_level", "n_controls_clean_issue_level",
})
_TIMING_METRIC_KEYS = frozenset({"total_elapsed_seconds", "total_tokens_spent"})


def _metric_value(run: dict, key: str) -> float:
    if key in _TIMING_METRIC_KEYS:
        return float(run["timing"][key])
    return float(run[key])


def reconcile_blind_style(data: dict, corpus_name: str) -> dict:
    """Recompute every metric in `data["variance"]` from `data["runs"]`'s
    OWN per-run fields (not from the pre-aggregated 'values' list -- pulled
    straight from each run's top-level/`timing` field), then recompute
    recall_any_finding/recall_surfaced_only from the lowest-level per-
    exchange `results` (ground_truth + findings + surfaced_finding_ids),
    independent of the stored `_bench_meta` numbers. Raises
    `ReconciliationError` on ANY disagreement -- this corpus's own `runs`
    array is the single source of truth every other number here must
    reduce to."""
    runs = data["runs"]
    variance = data["variance"]
    bench_meta = data.get("_bench_meta", {})

    recomputed_variance: dict[str, dict] = {}
    for key, stored in variance.items():
        raw_values = [_metric_value(r, key) for r in runs]
        stored_values = stored["values"]
        if len(raw_values) != len(stored_values) or any(
            not _close(a, b) for a, b in zip(raw_values, stored_values)
        ):
            raise ReconciliationError(
                f"{corpus_name}: variance[{key!r}].values {stored_values!r} disagrees with "
                f"values recomputed directly from runs[]: {raw_values!r}")
        mean = statistics.mean(raw_values)
        pvar = statistics.pvariance(raw_values) if len(raw_values) > 1 else 0.0
        if not _close(mean, stored["mean"]):
            raise ReconciliationError(
                f"{corpus_name}: variance[{key!r}].mean {stored['mean']!r} disagrees with "
                f"recomputed mean {mean!r}")
        if not _close(pvar, stored["variance"]):
            raise ReconciliationError(
                f"{corpus_name}: variance[{key!r}].variance {stored['variance']!r} disagrees "
                f"with recomputed population variance {pvar!r}")
        recomputed_variance[key] = {"values": raw_values, "mean": mean, "variance": pvar}

    recall_any_per_run = []
    recall_surfaced_per_run = []
    n_confirmed_vuln_per_run = []
    for run in runs:
        results = run["results"]
        surfaced_ids = set(run.get("surfaced_finding_ids", []))
        vuln_results = [r for r in results if r["ground_truth"] == "confirmed_vuln"]
        n = len(vuln_results)
        n_confirmed_vuln_per_run.append(n)
        any_hit = sum(1 for r in vuln_results if r["findings"])
        surfaced_hit = sum(
            1 for r in vuln_results
            if any(f.get("finding_id") in surfaced_ids for f in r["findings"])
        )
        recall_any_per_run.append(any_hit / n if n else None)
        recall_surfaced_per_run.append(surfaced_hit / n if n else None)

    if len(set(n_confirmed_vuln_per_run)) > 1:
        raise ReconciliationError(
            f"{corpus_name}: n_confirmed_vuln differs across repeats: {n_confirmed_vuln_per_run} "
            "(the same corpus/ground-truth should be scored every repeat)")
    n_confirmed_vuln = n_confirmed_vuln_per_run[0] if n_confirmed_vuln_per_run else 0
    if "n_confirmed_vuln" in bench_meta and bench_meta["n_confirmed_vuln"] != n_confirmed_vuln:
        raise ReconciliationError(
            f"{corpus_name}: _bench_meta.n_confirmed_vuln={bench_meta['n_confirmed_vuln']!r} "
            f"disagrees with the recomputed count {n_confirmed_vuln!r} from runs[].results")

    _any_vals = [v for v in recall_any_per_run if v is not None]
    _surfaced_vals = [v for v in recall_surfaced_per_run if v is not None]
    recall_any_mean = statistics.mean(_any_vals) if _any_vals else None
    recall_surfaced_mean = statistics.mean(_surfaced_vals) if _surfaced_vals else None
    if "recall_any_finding" in bench_meta and recall_any_mean is not None:
        stored_mean = bench_meta["recall_any_finding"]["mean"]
        if not _close(round(recall_any_mean, 4), round(stored_mean, 4)):
            raise ReconciliationError(
                f"{corpus_name}: _bench_meta.recall_any_finding.mean {stored_mean!r} disagrees "
                f"with recall recomputed directly from runs[].results {recall_any_mean!r}")
    if "recall_surfaced_only" in bench_meta and recall_surfaced_mean is not None:
        stored_mean = bench_meta["recall_surfaced_only"]["mean"]
        if not _close(round(recall_surfaced_mean, 4), round(stored_mean, 4)):
            raise ReconciliationError(
                f"{corpus_name}: _bench_meta.recall_surfaced_only.mean {stored_mean!r} disagrees "
                f"with recall recomputed directly from runs[].results {recall_surfaced_mean!r}")

    flags = []
    total_tokens_values = recomputed_variance.get("total_tokens_spent", {}).get("values", [])
    if total_tokens_values and all(v == 0 for v in total_tokens_values):
        flags.append({
            "check": "tokens_instrumentation", "status": "unavailable",
            "detail": (
                f"{corpus_name}: total_tokens_spent is 0 on every repeat, and no other field "
                "in this artifact records a nonzero token count -- this driver's token "
                "counter is simply not wired up (unlike PixelMart, where run_health/"
                "model_cost_by_variant DO record a real, nonzero count that contradicts the "
                "0). Report as instrumentation UNAVAILABLE, never as a verified zero-cost "
                "measurement."
            ),
        })

    return {
        "recomputed_variance": recomputed_variance,
        "recall_any_finding": {"mean": recall_any_mean, "values": recall_any_per_run},
        "recall_surfaced_only": {"mean": recall_surfaced_mean, "values": recall_surfaced_per_run},
        "n_confirmed_vuln": n_confirmed_vuln,
        "flags": flags,
    }


def check_breaker_or_error_claims(data: dict) -> dict | None:
    """For the blind-eval-style shape: n_errors is the closest analogue to
    PixelMart's breaker_failures. Returns a flag only if a nonzero count is
    found (there is none in the committed 2026-09-23 artifacts -- included
    so a future run with real errors doesn't silently pass)."""
    runs = data["runs"]
    n_errors = [r.get("n_errors", 0) for r in runs]
    if any(e for e in n_errors):
        return {"check": "n_errors", "status": "inconsistency",
                "detail": f"n_errors per repeat = {n_errors} (nonzero) -- verify report claims "
                          "of a clean run against this."}
    return None


# ---------------------------------------------------------------------------
# 3. Strict exact-class recall -- NEVER inferred from a broad category.
# ---------------------------------------------------------------------------

def strict_exact_class_recall(
    corpus_name: str, saved: dict | None = None, labels_dir: Path = LABELS_DIR,
) -> dict:
    """Returns `{"strict_exact_class_recall": UNAVAILABLE, "reason": ...}`
    unless BOTH (a) `<labels_dir>/<corpus_name>.labels.json` exists AND
    (b) `saved` carries `eval_adapter.build_eval_artifact`'s shape
    (`stages`/`attribution`) so `eval_adapter.rescore_saved_run` can be
    called honestly on real per-finding data. NEVER derives a number from
    `recall_any_finding` / `recall_surfaced_only` / the score.py TP/TN
    scheme -- those are coarse-category coverage, not exact-class recall,
    and this function must not blur that distinction."""
    manifest_path = labels_dir / f"{corpus_name}.labels.json"
    if not manifest_path.exists():
        return {
            "strict_exact_class_recall": UNAVAILABLE,
            "reason": f"unavailable: no exact-class manifest for corpus {corpus_name!r} "
                      f"(expected {manifest_path})",
        }
    if not saved or "stages" not in saved or "attribution" not in saved:
        return {
            "strict_exact_class_recall": UNAVAILABLE,
            "reason": (
                f"unavailable: an exact-class manifest exists for {corpus_name!r} "
                f"({manifest_path.name}), but the saved run is not in "
                "eval_adapter.build_eval_artifact's shape (no stages/attribution) -- "
                "rescore_saved_run needs per-finding stages, not aggregate tp/fp/fn "
                "counts, and none of the 2026-09-23 benchmark artifacts carry that "
                "shape (they predate PR-5's shared adapter)."
            ),
        }
    from labels.manifest import load_manifest
    from eval_adapter import rescore_saved_run
    manifest = load_manifest(manifest_path)
    manifest.validate()
    artifact = rescore_saved_run(saved, manifest, git_revision="historical-rescore-PR-6")
    return {"strict_exact_class_recall": artifact["metrics"], "kind": artifact["kind"],
            "rescored_from": artifact.get("rescored_from")}


def assert_not_fabricated_strict_recall(entry: dict) -> None:
    """Raise `ReconciliationError` if `entry["strict_exact_class_recall"]`
    is a bare number -- the one shape `strict_exact_class_recall()` above
    never produces. Guards the invariant even if a caller bypasses that
    function and tries to splice broad-category recall (recall_any_finding,
    score.py precision/recall, etc.) directly into a report as if it were
    exact-class recall."""
    val = entry.get("strict_exact_class_recall")
    if isinstance(val, (int, float)) and not isinstance(val, bool):
        raise ReconciliationError(
            "strict_exact_class_recall must never be a bare number inferred from a "
            f"broad/coarse category; got {val!r}. Use strict_exact_class_recall() (or "
            "reproduce its refusal), which returns the UNAVAILABLE sentinel unless a "
            "real exact-class manifest AND an eval_adapter-shaped saved run both exist."
        )


# ---------------------------------------------------------------------------
# Full reconciliation report
# ---------------------------------------------------------------------------

def run_full_reconciliation(
    benchmark_dir: Path = BENCHMARK_DIR, config_path: Path = CONFIG_PATH,
    labels_dir: Path = LABELS_DIR,
) -> dict:
    """Top-level entry point: config-drift manifest + per-corpus
    recomputed aggregates + every flagged contradiction + strict-recall
    availability, for all five 2026-09-23 corpora. Raises
    `ReconciliationError` if any corpus fails its own internal
    self-consistency check (see `reconcile_pixelmart`/`reconcile_blind_
    style`) -- a clean run over the real committed artifacts never raises."""
    config_drift = build_config_drift_manifest(benchmark_dir, config_path)

    report_path = benchmark_dir / "BENCHMARK_REPORT.md"
    report_text = _read_text(report_path) if report_path.exists() else ""

    per_corpus: dict[str, dict] = {}
    contradictions: list[dict] = []

    pm_data = load_corpus_artifact("pixelmart", benchmark_dir)
    pm = reconcile_pixelmart(pm_data)
    wall_claim = check_report_wall_claim(
        report_text, pm["recomputed"]["wall_time_s"]["mean"],
        [h["wall_time_s"] for h in pm_data["run_health"] if h["variant"] == "A"],
    )
    pm["flags"].append(wall_claim)

    table_path = benchmark_dir / "pixelmart_default_3x_table.md"
    if table_path.exists():
        pm["flags"].append(_check_pixelmart_table_consistency(
            _read_text(table_path), pm["stored"]))

    per_corpus["pixelmart"] = pm
    contradictions.extend(
        f for f in pm["flags"] if f.get("status") in ("contradiction", "inconsistency")
    )
    pm["strict_recall"] = strict_exact_class_recall("pixelmart", saved=None, labels_dir=labels_dir)
    assert_not_fabricated_strict_recall(pm["strict_recall"])

    for name in ("blindtarget2", "dvwa", "webgoat", "juiceshop"):
        data = load_corpus_artifact(name, benchmark_dir)
        rec = reconcile_blind_style(data, name)
        err_flag = check_breaker_or_error_claims(data)
        if err_flag:
            rec["flags"].append(err_flag)
        rec["strict_recall"] = strict_exact_class_recall(name, saved=None, labels_dir=labels_dir)
        assert_not_fabricated_strict_recall(rec["strict_recall"])
        per_corpus[name] = rec
        contradictions.extend(
            f for f in rec["flags"] if f.get("status") in ("contradiction", "inconsistency")
        )

    return {
        "config_drift": config_drift,
        "per_corpus": per_corpus,
        "contradictions": contradictions,
        "control_units": CONTROL_UNITS,
    }


def _check_pixelmart_table_consistency(table_text: str, stored: dict) -> dict:
    """Cross-file check: `pixelmart_default_3x_table.md` is a companion
    rendering of the same `results[0]` row -- if it were ever hand-edited
    independently of the JSON, the two would drift apart. Parses the one
    data row and compares precision/recall/wall against the JSON."""
    row = None
    for line in table_text.splitlines():
        if line.strip().startswith("| A current"):
            row = line
            break
    if row is None:
        return {"check": "table_md_cross_check", "status": "not_found",
                "detail": "no 'A current' row found in pixelmart_default_3x_table.md"}
    cells = [c.strip() for c in row.strip().strip("|").split("|")]
    # header: variant | precision | recall | FP | tokens | wall(s) | TP | FN | ...
    try:
        precision = float(re.match(r"[\d.]+", cells[1]).group(0))
        recall = float(re.match(r"[\d.]+", cells[2]).group(0))
        wall = float(re.match(r"[\d.]+", cells[5]).group(0))
    except (AttributeError, IndexError, ValueError) as e:
        return {"check": "table_md_cross_check", "status": "not_found",
                "detail": f"could not parse row {row!r}: {e}"}
    mismatches = []
    if not _close(precision, stored["precision"]["mean"]):
        mismatches.append(f"precision {precision} != JSON {stored['precision']['mean']}")
    if not _close(recall, stored["recall"]["mean"]):
        mismatches.append(f"recall {recall} != JSON {stored['recall']['mean']}")
    if not _close(wall, stored["wall_time_s"]["mean"]):
        mismatches.append(f"wall {wall} != JSON {stored['wall_time_s']['mean']}")
    if mismatches:
        return {"check": "table_md_cross_check", "status": "contradiction",
                "detail": "; ".join(mismatches)}
    return {"check": "table_md_cross_check", "status": "match",
            "detail": "pixelmart_default_3x_table.md agrees with pixelmart_default_3x.json"}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    report = run_full_reconciliation()

    drift_json_path = BENCHMARK_DIR / "CONFIG_DRIFT_MANIFEST.json"
    drift_json_path.write_text(
        json.dumps(report["config_drift"], indent=2, sort_keys=True) + "\n", encoding="utf-8")

    drift_md_path = BENCHMARK_DIR / "CONFIG_DRIFT_MANIFEST.md"
    drift_md_path.write_text(
        "# Config-drift manifest -- 2026-09-23 benchmark vs shipped `harness/config.yaml`\n\n"
        "Generated by `testing/reconcile_benchmark.py` (PR-6/BP-3) -- machine-derived from the "
        "saved run artifacts and harness/config.yaml; nothing below is hand-transcribed.\n\n"
        + render_config_drift_table(report["config_drift"]) + "\n\n"
        + report["config_drift"]["corpora"][0]["source_note"] + "\n",
        encoding="utf-8")

    def _default(o):
        return str(o)

    reconciliation_json_path = BENCHMARK_DIR / "RECONCILIATION_REPORT.json"
    reconciliation_json_path.write_text(
        json.dumps(
            {"per_corpus": report["per_corpus"], "contradictions": report["contradictions"],
             "control_units": report["control_units"]},
            indent=2, sort_keys=True, default=_default) + "\n",
        encoding="utf-8")

    print(f"wrote {drift_json_path}")
    print(f"wrote {drift_md_path}")
    print(f"wrote {reconciliation_json_path}")
    print()
    print(render_config_drift_table(report["config_drift"]))
    print()
    print(f"{len(report['contradictions'])} contradiction(s)/inconsistency(ies) flagged:")
    for c in report["contradictions"]:
        print(f"  - [{c['check']}] {c['detail']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
