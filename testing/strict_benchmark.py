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
    orch = rbe.default_orchestrator_factory(config)
    await rbe.run_exchanges(exchanges, orch, force_agents=force_agents)


def run_corpus_strict(corpus_path, manifest_path, *, config=None, n_runs=3,
                      workdir, git_revision=None, force_agents=None) -> dict:
    """Replay `corpus_path` `n_runs` times through the live orchestrator and, per
    run, build the strict eval artifact against `manifest_path`. Returns
    {corpus, host, runs:[artifact,...], baseline_controls, aggregate}."""
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
    workdir = Path(workdir)
    workdir.mkdir(parents=True, exist_ok=True)

    runs: list[dict] = []
    orig_db = store._DB_PATH
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
            asyncio.run(_one_run(exchanges, config, force_agents=force_agents))
            stored = store.all_host_findings(host)
            artifact = eval_adapter.build_eval_artifact(
                host=host, stored_findings=stored, exchanges=descriptors, manifest=manifest,
                quarantine_leads=quarantine, gate_low_confidence_generic=gate_generic,
                git_revision=git_revision, run_id=f"{manifest.corpus}-run{i}",
                corpus_id=manifest.corpus, inputs_hash=manifest.hash, complete=True,
                validate_against_store=True)
            artifact["elapsed_seconds"] = round(time.monotonic() - t0, 1)
            runs.append(artifact)
    finally:
        store._DB_PATH = orig_db

    controls = rescore_run.baseline_controls(manifest, precision_gate=0.5, recall_gate=0.5)
    return {
        "corpus": manifest.corpus, "host": host, "git_revision": git_revision,
        "n_runs": n_runs, "quarantine_leads": quarantine,
        "runs": runs, "baseline_controls": controls,
        "aggregate": _aggregate(runs),
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
    print(f"  elapsed={agg.get('elapsed_seconds')}  -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
