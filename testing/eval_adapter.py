"""
eval_adapter.py -- shared eval artifact adapter (PR-5, BP-2).

`testing/blind-target-2/run_blind_eval.py` and `testing/test-target/
run_ablation_live.py` are two independent drivers that each hand-roll their
own scoring/visibility bookkeeping (R14: they diverge; a repro driver
referenced by an old note does not exist in this repo). This module is the
shared adapter a future driver migration can consume instead of
reimplementing that bookkeeping a third time -- it does NOT rewrite either
driver (that migration is a documented follow-on; see the module docstring
end).

Two entry points:

  * `build_eval_artifact(...)` -- from a REAL run's persisted findings (store
    rows) + the REAL report decision + a PR-2 label `Manifest`, produce one
    canonical, JSON-serializable eval artifact: finding ids/classes at the
    raw/surfaced/lead(quarantined) stages, per-exchange attribution, a
    `ScoreProvenance` block, and strict metrics (exact-class, any-alert,
    evidence-supported).
  * `rescore_saved_run(...)` -- read-only: recompute strict metrics from an
    artifact ALREADY on disk (as produced by `build_eval_artifact`, or
    anything carrying the same `stages`/`attribution` shape). No model, no
    target, no network, and -- unlike `build_eval_artifact` -- no store
    either: pure recomputation over what is already in `saved`.

REUSE (not reimplemented here):
  * `harness.score_provenance.ScoreProvenance`             -- run provenance.
  * `testing.strict_score` / `testing.evidence_grade`      -- all scoring.
  * `testing.labels.manifest.Manifest`                     -- ground truth.
  * `harness.store.finding_observations` / `all_host_findings` -- exact
    per-exchange attribution (AR-3) and the store's own raw findings.
  * `harness.confirmation_gate.should_quarantine_as_lead` /
    `is_low_confidence_generic_guess`                      -- the SAME two
    predicates `harness.report_generator.generate_markdown_report` applies,
    in the SAME order -- see `compute_stages` -- so this adapter's
    surfaced/lead split cannot diverge from what the report actually shows.
  * `harness.report_generator.generate_markdown_report`     -- called directly
    (it is pure over the `findings` list given -- no store/network import in
    that module) and cross-checked against this adapter's own lead count, so
    a scorer/report disagreement is not just theoretically impossible by
    sharing a predicate, it is actively DETECTED (`EvalAdapterError`) if the
    two ever diverge.

Visibility derivation intentionally goes one step further than
`run_blind_eval.py`'s own `build_scorecard` (which only applies
`should_quarantine_as_lead`, ignoring `gate_low_confidence_generic` in its
OWN counts even though it passes that flag to `generate_markdown_report`):
`compute_stages` below applies BOTH predicates, in the SAME order, exactly as
`generate_markdown_report` does -- because the acceptance bar here is
"scorer and report cannot disagree" for ANY config this driver might use, not
only the default. Feeding this adapter's `individual`-stage findings straight
back into `generate_markdown_report` and diffing the declared lead count is
what turns that claim from "the same predicate was pasted twice" into an
actively-checked invariant.

Offline, deterministic. Never reads `*ANSWER_KEY*` or a blind target's
`app.py`. `build_eval_artifact` touches `harness.store` (to validate the
caller's `stored_findings` against what is actually persisted);
`rescore_saved_run` touches nothing but its own arguments.

Follow-on (explicitly OUT of scope for PR-5): migrate
`testing/blind-target-2/run_blind_eval.py` and
`testing/test-target/run_ablation_live.py` to build their scorecards by
calling `build_eval_artifact` instead of each hand-rolling this bookkeeping.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any, Callable

# Mirrors the sys.path trick testing/strict_score.py and testing/evidence_grade.py
# already use, so this module imports cleanly either as `testing.eval_adapter`
# (package-qualified) or with `testing/` on sys.path directly.
_TESTING_DIR = Path(__file__).resolve().parent
if str(_TESTING_DIR) not in sys.path:
    sys.path.insert(0, str(_TESTING_DIR))

from labels.manifest import Manifest  # noqa: E402
from strict_score import Predictions  # noqa: E402
import evidence_grade as _evidence_grade  # noqa: E402

from harness.score_provenance import ScoreProvenance  # noqa: E402
from harness.confirmation_gate import (  # noqa: E402
    should_quarantine_as_lead, is_low_confidence_generic_guess,
)
from harness.report_generator import generate_markdown_report  # noqa: E402

SCHEMA_VERSION = "1.0.0"
UNAVAILABLE = "unavailable"


class EvalAdapterError(ValueError):
    """Raised for a detected inconsistency this adapter refuses to paper
    over: a raw stage that doesn't match the store, or a computed visibility
    split that disagrees with the actual rendered report."""


# ---------------------------------------------------------------------------
# Small, pure building blocks.
# ---------------------------------------------------------------------------

# Fields kept on every stage entry: enough identity + case coordinates to
# re-derive visibility (should_quarantine_as_lead / is_low_confidence_generic_
# guess), re-run evidence grading, and audit attribution offline later --
# never the free-text summary/evidence/suggested_test fields (out of scope
# for a scoring artifact, and unnecessary weight in a saved-run JSON file).
_SLIM_FIELDS: tuple[str, ...] = (
    "finding_id", "fingerprint", "vulnerability_class", "url", "method",
    "confirmed", "basis", "confidence", "oracle_verified", "proof_id",
    "case_id", "exchange_id", "severity", "parameter_location", "parameter_name",
)


def _slim(f: dict) -> dict:
    """A JSON-safe, minimal view of one store finding dict -- see _SLIM_FIELDS."""
    return {k: f.get(k) for k in _SLIM_FIELDS}


def exchange_descriptor(id_: str, method: str, url: str) -> dict:
    """One exchange's identity, as `attribute_findings`/`compute_stages`'
    callers describe it: the SAME id used as HttpExchange.capture_id when the
    exchange was actually run (so store.finding_observations' exchange_id
    values line up with these ids)."""
    return {"id": str(id_), "method": (method or "").upper(), "url": url or ""}


def compute_stages(
    findings: list[dict], *, quarantine_leads: bool = True,
    gate_low_confidence_generic: bool = False, generic_confidence_floor: float = 0.5,
) -> tuple[list[dict], list[dict], list[dict], list[dict]]:
    """Split `findings` (store-shaped dicts) into (raw, individual, surfaced,
    lead) EXACTLY as `harness.report_generator.generate_markdown_report`
    does: same two predicates (`should_quarantine_as_lead`,
    `is_low_confidence_generic_guess`), same order, same short-circuit
    (`elif`, not independent checks) -- see that function's own per-finding
    loop. `raw` is every finding given (chain hypotheses included);
    `individual` excludes `potential-attack-chain:*` synthetic entries (a
    chain hypothesis is never itself surfaced/quarantined, matching the
    report's own `chains` bucket); `surfaced`/`lead` partition `individual`.
    `individual == surfaced + lead` always, by construction."""
    raw = list(findings)
    individual = [f for f in raw
                  if not str(f.get("vulnerability_class") or "").startswith("potential-attack-chain:")]
    surfaced: list[dict] = []
    lead: list[dict] = []
    for f in individual:
        if quarantine_leads and should_quarantine_as_lead(f):
            lead.append(f)
        elif gate_low_confidence_generic and is_low_confidence_generic_guess(f, generic_confidence_floor):
            lead.append(f)
        else:
            surfaced.append(f)
    return raw, individual, surfaced, lead


_LEADS_NOTE_RE = re.compile(r"\*\*(\d+) quarantined test suggestion\(s\)\*\*")


def _report_declared_lead_count(markdown: str) -> int:
    """Parse `generate_markdown_report`'s own summary line
    (`"... , **N quarantined test suggestion(s)**."`) back out of the
    rendered report -- the ACTUAL report decision, read from its own output,
    not re-derived. Absent entirely (the note is omitted when the leads
    bucket is empty) means 0."""
    m = _LEADS_NOTE_RE.search(markdown)
    return int(m.group(1)) if m else 0


def attribute_findings(
    findings: list[dict], exchanges: list[dict], observations: dict[str, list[str]],
) -> tuple[Predictions, dict[str, Any]]:
    """Attribute each finding to the exchange(s) that actually produced it.

    Prefers AR-3 `harness.store.finding_observations` (exact: the exchange_id
    was stamped at persist time by the exchange that was actually analyzed).
    Falls back to a (method, url) match against `exchanges` ONLY when no
    observation data exists for that finding's fingerprint at all (legacy
    rows / a caller that never called finding_observations) -- and even
    then, ONLY when the (method, url) pair identifies exactly ONE exchange.
    Zero or multiple (method, url) matches with no observation data is
    genuinely ambiguous attribution: the finding is marked UNRESOLVED and
    excluded from `Predictions` entirely, NEVER assigned to every exchange
    sharing that (method, url) -- assigning it to all of them would silently
    inflate coverage/recall on manifest records the finding was never
    actually observed against.

    Returns `(predictions, attribution)`:
      * `predictions`: `dict[exchange_id, list[raw vulnerability_class]]`,
        pre-seeded with every exchange id (even ones with zero findings) --
        the shape `testing.strict_score.score` expects.
      * `attribution`: `{"by_exchange": {exchange_id: [finding_id, ...]},
        "unresolved": [{finding_id, fingerprint, method, url,
        vulnerability_class, candidate_exchange_ids, reason}, ...]}`.
    """
    pair_index: dict[tuple[str, str], list[str]] = {}
    known_ids: set[str] = set()
    for ex in exchanges:
        eid = str(ex["id"])
        known_ids.add(eid)
        pair = ((ex.get("method") or "").upper(), ex.get("url") or "")
        pair_index.setdefault(pair, []).append(eid)

    predictions: Predictions = {eid: [] for eid in known_ids}
    by_exchange: dict[str, list[str]] = {eid: [] for eid in known_ids}
    unresolved: list[dict] = []

    for f in findings:
        fp = f.get("fingerprint") or ""
        raw_class = f.get("vulnerability_class") or ""
        fid = f.get("finding_id") or fp
        obs = [eid for eid in observations.get(fp, []) if eid in known_ids]
        if obs:
            target_ids = obs
        else:
            pair = ((f.get("method") or "").upper(), f.get("url") or "")
            candidates = pair_index.get(pair, [])
            if len(candidates) == 1:
                target_ids = candidates
            else:
                unresolved.append({
                    "finding_id": fid, "fingerprint": fp,
                    "method": pair[0], "url": pair[1], "vulnerability_class": raw_class,
                    "candidate_exchange_ids": list(candidates),
                    "reason": ("no exchange-level observation and (method, url) matches "
                               f"{len(candidates)} exchanges" if candidates else
                               "no exchange-level observation and no (method, url) match"),
                })
                continue
        for eid in target_ids:
            predictions.setdefault(eid, []).append(raw_class)
            by_exchange.setdefault(eid, []).append(fid)

    return predictions, {"by_exchange": by_exchange, "unresolved": unresolved}


def _resolve_instrumentation(instrumentation: dict | None) -> dict:
    """calls/tokens/model identity: any field the caller did not supply is
    recorded as the explicit `UNAVAILABLE` sentinel, never a fabricated 0 --
    same discipline as harness/score_provenance.py's freshness labels and
    testing/strict_score.py's evidence_supported sentinel."""
    fields = ("model_calls", "prompt_tokens", "completion_tokens", "total_tokens", "model")
    src = instrumentation or {}
    return {k: (src[k] if (k in src and src[k] is not None) else UNAVAILABLE) for k in fields}


def _metrics(
    manifest: Manifest, individual: list[dict], predictions: Predictions,
    proofs: list[dict], cases: list[dict], artifacts: list[dict],
) -> dict:
    """Strict metrics via REUSE: testing.evidence_grade.score_with_evidence
    wraps testing.strict_score.score (exact_class + any_alert_coverage) and
    wires in the evidence_supported family, all from ONE call -- `predictions`
    here is this adapter's OWN exchange-attributed predictions (see
    attribute_findings), passed in so evidence_grade doesn't have to
    re-derive them from `individual`'s single legacy exchange_id field."""
    return _evidence_grade.score_with_evidence(
        manifest, individual, proofs, cases, artifacts, predictions=predictions)


# ---------------------------------------------------------------------------
# build_eval_artifact -- the live path (real store, real report decision).
# ---------------------------------------------------------------------------

def build_eval_artifact(
    *,
    host: str,
    stored_findings: list[dict],
    exchanges: list[dict],
    manifest: Manifest,
    quarantine_leads: bool = True,
    gate_low_confidence_generic: bool = False,
    generic_confidence_floor: float = 0.5,
    git_revision: str,
    run_id: str,
    corpus_id: str,
    inputs_hash: str,
    complete: bool,
    instrumentation: dict | None = None,
    proofs: list[dict] | None = None,
    cases: list[dict] | None = None,
    artifacts: list[dict] | None = None,
    validate_against_store: bool = True,
    observations: dict[str, list[str]] | None = None,
) -> dict:
    """Build one canonical eval artifact from a REAL run's persisted
    findings.

    `stored_findings`: `harness.store.all_host_findings(host)`-shaped dicts
    (or a caller-filtered subset -- see `validate_against_store`). `exchanges`:
    `exchange_descriptor(...)` dicts for every exchange actually run, using
    the SAME id as each HttpExchange.capture_id.

    `validate_against_store` (default True): re-queries
    `harness.store.all_host_findings(host)` itself and raises
    `EvalAdapterError` if its fingerprint set differs from `stored_findings`'
    own -- this is what makes "the adapter's raw stage must equal the
    store's raw findings" an enforced invariant rather than a hopeful
    docstring: a finding present in the store but missing from
    `stored_findings` (a synthetic drop) is detected and FAILS loudly,
    never silently under-reported. Pass False only for a host with no
    store to validate against (should not happen for the live path; use
    `rescore_saved_run` for offline/historical data instead).

    `proofs`/`cases`/`artifacts` (all optional): evidence for PR-4 grading.
    When omitted, this best-effort-gathers `proofs`/`cases` via
    `harness.store.proofs_for_case` for every distinct `case_id` among
    `stored_findings` (each proof row already embeds its own `case` dict --
    see `harness.store._proof_row_to_dict` -- so no separate case lookup is
    needed). There is no bulk exchange-artifact accessor in `harness.store`
    today, so `artifacts` stays empty unless the caller supplies it -- when
    NO proofs/cases/artifacts exist at all, `evidence_supported` correctly
    reports the `unavailable` sentinel (testing.strict_score's own
    contract); when proofs exist but artifacts don't, grading correctly
    reports `insufficient` rather than `unavailable` (instrumentation did
    run; the artifacts to back it up were not supplied to this call).

    Raises `EvalAdapterError` if the computed lead count disagrees with what
    `harness.report_generator.generate_markdown_report` actually renders for
    this exact input -- the scorer/report-disagreement invariant, checked
    against the real report, not re-derived.
    """
    from harness import store

    if validate_against_store:
        store_findings = store.all_host_findings(host)
        store_fps = {f.get("fingerprint") for f in store_findings}
        given_fps = {f.get("fingerprint") for f in stored_findings}
        missing = store_fps - given_fps
        extra = given_fps - store_fps
        if missing or extra:
            raise EvalAdapterError(
                f"eval_adapter raw-stage/store mismatch for host {host!r}: "
                f"{len(missing)} finding(s) in the store are missing from stored_findings "
                f"({sorted(x for x in missing if x)!r}); "
                f"{len(extra)} finding(s) in stored_findings are not in the store "
                f"({sorted(x for x in extra if x)!r})")

    if observations is None:
        fingerprints = [f.get("fingerprint") for f in stored_findings if f.get("fingerprint")]
        observations = store.finding_observations(fingerprints) if fingerprints else {}

    if proofs is None and cases is None:
        case_ids = sorted({f.get("case_id") for f in stored_findings if f.get("case_id")})
        gathered_proofs: list[dict] = []
        for cid in case_ids:
            gathered_proofs.extend(store.proofs_for_case(cid))
        proofs = gathered_proofs
        cases = [p["case"] for p in gathered_proofs]
    proofs = proofs if proofs is not None else []
    cases = cases if cases is not None else []
    artifacts = artifacts if artifacts is not None else []

    return _finalize_artifact(
        kind="eval_artifact", host=host, stored_findings=stored_findings, exchanges=exchanges,
        manifest=manifest, quarantine_leads=quarantine_leads,
        gate_low_confidence_generic=gate_low_confidence_generic,
        generic_confidence_floor=generic_confidence_floor,
        git_revision=git_revision, run_id=run_id, corpus_id=corpus_id, inputs_hash=inputs_hash,
        complete=complete, instrumentation=instrumentation, proofs=proofs, cases=cases,
        artifacts=artifacts, observations=observations,
    )


def _finalize_artifact(
    *, kind: str, host: str, stored_findings: list[dict], exchanges: list[dict],
    manifest: Manifest, quarantine_leads: bool, gate_low_confidence_generic: bool,
    generic_confidence_floor: float, git_revision: str, run_id: str, corpus_id: str,
    inputs_hash: str, complete: bool, instrumentation: dict | None,
    proofs: list[dict], cases: list[dict], artifacts: list[dict],
    observations: dict[str, list[str]],
) -> dict:
    """Shared core: pure over its arguments (no store/model/network access
    of its own -- `build_eval_artifact` and `rescore_saved_run` each gather
    their inputs differently, then both funnel here)."""
    raw, individual, surfaced, lead = compute_stages(
        stored_findings, quarantine_leads=quarantine_leads,
        gate_low_confidence_generic=gate_low_confidence_generic,
        generic_confidence_floor=generic_confidence_floor)

    markdown = generate_markdown_report(
        host, stored_findings, quarantine_leads=quarantine_leads,
        gate_low_confidence_generic=gate_low_confidence_generic,
        generic_confidence_floor=generic_confidence_floor)
    declared = _report_declared_lead_count(markdown)
    if declared != len(lead):
        raise EvalAdapterError(
            f"scorer/report visibility disagreement for host {host!r}: adapter computed "
            f"{len(lead)} quarantined lead(s), the rendered report declares {declared}")

    predictions, attribution = attribute_findings(individual, exchanges, observations)
    metrics = _metrics(manifest, individual, predictions, proofs, cases, artifacts)

    provenance = ScoreProvenance(
        git_revision=git_revision, run_id=run_id, corpus_id=corpus_id,
        inputs_hash=inputs_hash, complete=complete)

    return {
        "schema_version": SCHEMA_VERSION,
        "kind": kind,
        "host": host,
        "corpus": manifest.corpus,
        "quarantine_leads": quarantine_leads,
        "gate_low_confidence_generic": gate_low_confidence_generic,
        "generic_confidence_floor": generic_confidence_floor,
        "exchanges": [dict(e) for e in exchanges],
        "stages": {
            "raw": [_slim(f) for f in raw],
            "individual": [_slim(f) for f in individual],
            "surfaced": [_slim(f) for f in surfaced],
            "lead": [_slim(f) for f in lead],
        },
        "attribution": attribution,
        "provenance": provenance.to_dict(),
        "instrumentation": _resolve_instrumentation(instrumentation),
        "evidence_inputs": {"proofs": proofs, "cases": cases, "artifacts": artifacts},
        "metrics": metrics,
        "report_cross_check": {"markdown_declared_lead_count": declared, "consistent": True},
    }


# ---------------------------------------------------------------------------
# rescore_saved_run -- read-only historical rescoring. No model, no target,
# no network, no store: pure recomputation over `saved` (a dict already on
# disk, as produced by build_eval_artifact or carrying the same shape).
# ---------------------------------------------------------------------------

def rescore_saved_run(
    saved: dict, manifest: Manifest, *,
    git_revision: str,
    run_id: str | None = None,
    quarantine_leads: bool | None = None,
    gate_low_confidence_generic: bool | None = None,
    generic_confidence_floor: float | None = None,
) -> dict:
    """Recompute strict metrics for a saved run, read-only.

    `saved` must carry the shape `build_eval_artifact` produces: `host`,
    `stages.raw` (the slim finding dicts), `exchanges`, `attribution`
    (reused as-is -- historical attribution is NOT re-derived from a store
    that may no longer exist), and `evidence_inputs`. Visibility knobs
    (`quarantine_leads` etc.) default to whatever `saved` recorded, so a
    plain rescore reproduces the same stages; a caller may override them to
    ask "how would this have been scored under a different quarantine
    policy" without re-running anything.

    Marked `historical`/rescored in the return value's `kind` and
    `provenance` -- never presented as a fresh run. Invokes no model, no
    target, no network -- and, unlike `build_eval_artifact`, no
    `harness.store` either: everything comes out of `saved` and `manifest`.
    """
    host = saved.get("host") or ""
    raw = list(saved.get("stages", {}).get("raw", []))
    exchanges = list(saved.get("exchanges", []))
    evidence_inputs = saved.get("evidence_inputs") or {}
    proofs = list(evidence_inputs.get("proofs") or [])
    cases = list(evidence_inputs.get("cases") or [])
    artifacts = list(evidence_inputs.get("artifacts") or [])

    ql = saved.get("quarantine_leads", True) if quarantine_leads is None else quarantine_leads
    glcg = (saved.get("gate_low_confidence_generic", False)
            if gate_low_confidence_generic is None else gate_low_confidence_generic)
    floor = (saved.get("generic_confidence_floor", 0.5)
             if generic_confidence_floor is None else generic_confidence_floor)

    # Historical attribution is reused verbatim from what was recorded at
    # build time (see docstring) -- reconstruct fingerprint -> [exchange_id]
    # observations FROM that recorded attribution rather than re-deriving it,
    # so a rescore never silently re-runs the (method, url) fallback logic
    # against data that may have changed shape since the original run.
    by_exchange = (saved.get("attribution") or {}).get("by_exchange") or {}
    finding_by_id = {f.get("finding_id") or f.get("fingerprint"): f for f in raw}
    observations: dict[str, list[str]] = {}
    for eid, finding_ids in by_exchange.items():
        for fid in finding_ids:
            f = finding_by_id.get(fid)
            fp = f.get("fingerprint") if f else fid
            if fp:
                observations.setdefault(fp, []).append(eid)

    saved_run_id = saved.get("provenance", {}).get("run_id", "") if run_id is None else run_id

    artifact = _finalize_artifact(
        kind="historical_rescore", host=host, stored_findings=raw, exchanges=exchanges,
        manifest=manifest, quarantine_leads=ql, gate_low_confidence_generic=glcg,
        generic_confidence_floor=floor, git_revision=git_revision, run_id=saved_run_id,
        corpus_id=manifest.corpus, inputs_hash=saved.get("provenance", {}).get("inputs_hash", ""),
        complete=True, instrumentation=saved.get("instrumentation"),
        proofs=proofs, cases=cases, artifacts=artifacts, observations=observations,
    )
    artifact["rescored_from"] = {
        "original_kind": saved.get("kind"),
        "original_provenance": saved.get("provenance"),
    }
    return artifact
