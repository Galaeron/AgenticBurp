"""Live strict benchmark: replay a captured corpus through the REAL model and
score it with the exact-class strict scorer (NC-1/PR-3/PR-5), not the coarse
any-alert scorecard.

This is the bridge finding N01 said was missing: the live runner
(blind-target-2/run_blind_eval.run_exchanges) populates the store with real
findings; this module then calls eval_adapter.build_eval_artifact against those
stored findings + a per-exchange exact-class manifest to produce exact-class
precision/recall, and runs the three indiscriminate baselines through the same
gates as a built-in negative control.

Corpus exchanges must carry an `id` (== HttpExchange.capture_id) that matches the
manifest exchange_ids; the *.ided.json corpora and testing/labels/*.labels.json
are built to that contract. Passive shipped-default config: analysis replays the
captured request/response, so the target app need not be running.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path

_TESTING_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _TESTING_DIR.parent
_BLIND_DIR = _TESTING_DIR / "blind-target-2"
# Repo root first so `harness.*` and the top-level `evaluation_integrity` package
# (imported transitively by evidence_grade) resolve even when this module is
# imported from a script whose sys.path[0] is elsewhere (not run via -m).
for p in (str(_REPO_ROOT), str(_TESTING_DIR), str(_BLIND_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)

import eval_adapter  # noqa: E402
import strict_score  # noqa: E402
import rescore_run  # noqa: E402
from labels.manifest import load_manifest  # noqa: E402
import run_blind_eval as rbe  # noqa: E402
from harness import store, cache  # noqa: E402


def _git_rev() -> str:
    try:
        out = subprocess.run(["git", "rev-parse", "--short", "HEAD"],
                             capture_output=True, text=True, timeout=5)
        return out.stdout.strip() or "unknown"
    except Exception:
        return "unknown"


def _git_dirty() -> bool:
    """Best-effort worktree-dirty flag for the inputs identity below. Never
    fabricated: any failure to ask git (no repo, git missing, timeout) reads
    as `False` ("not provably dirty"), never a guessed `True`."""
    try:
        out = subprocess.run(["git", "status", "--porcelain"],
                             capture_output=True, text=True, timeout=5,
                             cwd=str(_REPO_ROOT))
        return bool(out.stdout.strip())
    except Exception:
        return False


def _load_config() -> dict:
    import yaml
    cfg = yaml.safe_load((_TESTING_DIR.parent / "harness" / "config.yaml").read_text()) or {}
    return cfg


def _descriptors(exchanges: list[dict]) -> list[dict]:
    return [eval_adapter.exchange_descriptor(rbe.capture_id_for(e, i),
                                             e.get("method", ""), e.get("url", ""))
            for i, e in enumerate(exchanges)]


def _hosts(exchanges: list[dict]) -> list[str]:
    hosts: list[str] = []
    for e in exchanges:
        h = store.host_of(e["url"])
        if h not in hosts:
            hosts.append(h)
    return hosts


async def _one_run(exchanges, config, *, force_agents=None):
    """Run `exchanges` through one fresh orchestrator and RETURN the per-
    exchange outcomes (FR-1 / F04) -- the caller (`run_corpus_strict`) needs
    them to certify whether this run is healthy, so a discarded return value
    here would silently hide any analyze() failure again. Closes/cleans up
    the orchestrator afterward if it exposes a close/aclose/cleanup method
    (none does today; this is a no-op guard against a future one leaking a
    session/connection across runs)."""
    orch = rbe.default_orchestrator_factory(config)
    try:
        return await rbe.run_exchanges(exchanges, orch, force_agents=force_agents)
    finally:
        for meth_name in ("aclose", "close", "cleanup"):
            meth = getattr(orch, meth_name, None)
            if meth is None:
                continue
            try:
                result = meth()
                if asyncio.iscoroutine(result):
                    await result
            except Exception:
                pass
            break


def assess_run_health(outcomes, stored_findings, *, n_expected: int) -> dict:
    """PURE run-health certification (FR-1 / F04): no IO, no model, no store
    access of its own -- takes exactly what the caller already has (the
    per-exchange `ExchangeOutcome`s `run_exchanges` returned, and the
    findings actually persisted for this run) and decides whether the run
    is fit to be certified `complete`/`eligible`.

    A run is certified `eligible=False` (and never stamped `complete=True`)
    when:
      - any exchange failed (`o.error` is truthy) -- one failure is enough;
      - the run never even started/finished all its exchanges (fewer
        outcomes came back than `n_expected`);
      - zero exchanges completed successfully;
      - `stored_findings` is empty even though there were exchanges to
        analyze -- a run that persisted NOTHING is not distinguishable
        offline from a silently-inoperative detector, so it is never
        certified healthy even if every individual exchange reported no
        error (this is deliberately conservative: see FR-1 in
        IMPROVEMENT_BACKLOG.md).

    Partial/failed-run metrics stay VISIBLE to the caller regardless --
    this function only decides the `eligible`/`complete` label, never
    whether the artifact is built or its metrics are computed.

    Works against real `ExchangeOutcome` instances (duck-typed via getattr,
    so a minimal test double with just `.error`/`.findings`/
    `.dispatched_agents` attributes works too)."""
    n_seen = len(outcomes)
    failed = sum(1 for o in outcomes if getattr(o, "error", None))
    completed = n_seen - failed
    missing = max(n_expected - n_seen, 0)
    has_findings = any(getattr(o, "findings", None) for o in outcomes)
    stored_empty = not stored_findings

    reasons: list[str] = []
    if failed:
        reasons.append(f"{failed} of {n_seen} exchange(s) errored")
    if missing:
        reasons.append(f"{missing} expected exchange(s) never ran (got {n_seen} of {n_expected})")
    if n_expected > 0 and completed == 0:
        reasons.append("no exchange completed successfully")
    if n_expected > 0 and stored_empty:
        reasons.append("no findings were persisted to the store for a run with exchanges to analyze")

    # Stage-degradation signal: an exchange that completed without error but
    # dispatched no agents at all did something silently different from
    # normal analysis. Not alone fatal to certification, but always surfaced.
    silent_stage_skips = sum(
        1 for o in outcomes
        if not getattr(o, "error", None) and not getattr(o, "dispatched_agents", None)
    )
    if silent_stage_skips:
        reasons.append(f"{silent_stage_skips} completed exchange(s) dispatched no agents")

    degraded = bool(failed or missing or silent_stage_skips)
    eligible = not (
        failed or missing
        or (n_expected > 0 and completed == 0)
        or (n_expected > 0 and stored_empty)
    )

    return {
        "expected": n_expected,
        "seen": n_seen,
        "completed": completed,
        "failed": failed,
        "missing": missing,
        "has_findings": has_findings,
        "degraded": degraded,
        "eligible": eligible,
        "reasons": reasons,
    }


def _inputs_identity(corpus_path, manifest, config, *, git_revision: str,
                      model_digest: str | None = None) -> dict:
    """Deterministic run-inputs identity (FR-1 / F04), computed entirely
    OFFLINE: corpus bytes + the resolved config dict + the manifest's own
    content hash + git revision (+ a dirty-worktree flag) + a model digest
    WHEN one is actually supplied -- never fabricated; recorded as the
    explicit "unavailable" sentinel otherwise (same discipline as
    `eval_adapter._resolve_instrumentation`'s UNAVAILABLE fields).

    `manifest_hash` is kept as its own field (not just folded into the
    combined hash) so nothing that relied on the old bare
    `inputs_hash=manifest.hash` contract loses access to that value."""
    corpus_hash = hashlib.sha256(Path(corpus_path).read_bytes()).hexdigest()
    config_hash = hashlib.sha256(
        json.dumps(config, sort_keys=True, default=str).encode("utf-8")).hexdigest()
    identity = {
        "corpus_hash": corpus_hash,
        "config_hash": config_hash,
        "manifest_hash": manifest.hash,
        "git_revision": git_revision,
        "git_dirty": _git_dirty(),
        "model_digest": model_digest if model_digest else "unavailable",
    }
    identity_hash = hashlib.sha256(
        json.dumps(identity, sort_keys=True).encode("utf-8")).hexdigest()
    return {**identity, "identity_hash": identity_hash}


def run_corpus_strict(corpus_path, manifest_path, *, config=None, n_runs=3,
                      workdir, git_revision=None, force_agents=None) -> dict:
    """Replay `corpus_path` `n_runs` times through the live orchestrator and, per
    run, build the strict eval artifact against `manifest_path`. Returns
    {corpus, host, runs:[artifact,...], baseline_controls, aggregate,
    inputs_identity, certified, all_runs_eligible}.

    FR-1 / F04: each run is health-certified from its OWN outcomes + what it
    actually persisted (see `assess_run_health`) -- a run where any exchange
    failed, where fewer exchanges ran than expected, or that persisted
    nothing at all, is passed to `build_eval_artifact` as `complete=False`
    (never stamped "complete" from an empty/partial store) and carries a
    `run_health` block explaining why, while its (partial) metrics stay
    fully visible on the artifact -- nothing is hidden, only mislabeled
    honestly. A genuinely healthy run is unaffected: it still certifies
    `complete=True`/`run_health.eligible=True` exactly as before this fix.
    """
    config = config or _load_config()
    git_revision = git_revision or _git_rev()
    exchanges = rbe.load_exchanges(corpus_path)
    manifest = load_manifest(manifest_path)
    descriptors = _descriptors(exchanges)
    hosts = _hosts(exchanges)
    if len(hosts) != 1:
        raise SystemExit(f"strict_benchmark expects a single-host corpus, got {hosts}")
    host = hosts[0]
    quarantine = bool((config.get("reporting", {}) or {}).get("quarantine_unverified_leads", False))
    gate_generic = bool((config.get("reporting", {}) or {}).get("gate_low_confidence_generic", False))
    gate_catchall = bool((config.get("reporting", {}) or {}).get("gate_uncorroborated_catchall", False))
    workdir = Path(workdir)
    workdir.mkdir(parents=True, exist_ok=True)

    identity = _inputs_identity(corpus_path, manifest, config, git_revision=git_revision)

    runs: list[dict] = []
    orig_db = store._DB_PATH
    orig_cache = cache._cache
    try:
        for i in range(n_runs):
            state_db = workdir / f"{manifest.corpus}_state_{i}.db"
            cache_db = workdir / f"{manifest.corpus}_cache_{i}.db"
            for db in (state_db, cache_db):
                if db.exists():
                    db.unlink()
            store._DB_PATH = str(state_db)
            cache.init_cache(db_path=str(cache_db))
            t0 = time.monotonic()
            outcomes = asyncio.run(_one_run(exchanges, config, force_agents=force_agents))
            stored = store.all_host_findings(host)
            health = assess_run_health(outcomes, stored, n_expected=len(exchanges))
            artifact = eval_adapter.build_eval_artifact(
                host=host, stored_findings=stored, exchanges=descriptors, manifest=manifest,
                quarantine_leads=quarantine, gate_low_confidence_generic=gate_generic,
                gate_uncorroborated_catchall=gate_catchall,
                git_revision=git_revision, run_id=f"{manifest.corpus}-run{i}",
                corpus_id=manifest.corpus, inputs_hash=identity["identity_hash"],
                complete=health["eligible"],
                validate_against_store=True)
            artifact["elapsed_seconds"] = round(time.monotonic() - t0, 1)
            artifact["run_health"] = health
            runs.append(artifact)
    finally:
        store._DB_PATH = orig_db
        cache._cache = orig_cache

    controls = rescore_run.baseline_controls(manifest, precision_gate=0.5, recall_gate=0.5)
    certified = sum(1 for r in runs if r.get("run_health", {}).get("eligible"))
    return {
        "corpus": manifest.corpus, "host": host, "git_revision": git_revision,
        "n_runs": n_runs, "quarantine_leads": quarantine,
        "runs": runs, "baseline_controls": controls,
        "aggregate": _aggregate(runs),
        "inputs_identity": identity,
        "certified": certified,
        "all_runs_eligible": bool(runs) and certified == len(runs),
    }


def _aggregate(runs: list[dict]) -> dict:
    def series(fam, metric):
        vals = []
        for r in runs:
            o = ((r.get("metrics", {}).get(fam) or {}).get("overall") or {})
            v = o.get(metric)
            if v is not None:
                vals.append(v)
        return vals
    out = {}
    for fam in ("exact_class", "evidence_supported"):
        for metric in ("precision", "recall", "f1"):
            vals = series(fam, metric)
            if vals:
                out[f"{fam}.{metric}"] = {"mean": round(sum(vals) / len(vals), 3),
                                          "values": vals}
    out["elapsed_seconds"] = [r.get("elapsed_seconds") for r in runs]
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Live strict exact-class benchmark for one corpus.")
    ap.add_argument("corpus"); ap.add_argument("manifest")
    ap.add_argument("--n-runs", type=int, default=3)
    ap.add_argument("--workdir", default="reviews/2026-09-25/benchmark/_work")
    ap.add_argument("--out", required=True)
    ap.add_argument("--force-agents", default="")
    args = ap.parse_args(argv)
    fa = [a for a in args.force_agents.split(",") if a] or None
    result = run_corpus_strict(args.corpus, args.manifest, n_runs=args.n_runs,
                               workdir=args.workdir, force_agents=fa)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    json.dump(result, open(args.out, "w"), indent=2)
    agg = result["aggregate"]
    print(f"[strict] corpus={result['corpus']} host={result['host']} n_runs={result['n_runs']}")
    print(f"  exact_class precision={agg.get('exact_class.precision')} recall={agg.get('exact_class.recall')}")
    print(f"  baseline discriminating={result['baseline_controls']['discriminating']}")
    print(f"  certified={result['certified']}/{result['n_runs']} all_runs_eligible={result['all_runs_eligible']}")
    print(f"  elapsed={agg.get('elapsed_seconds')}  -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
