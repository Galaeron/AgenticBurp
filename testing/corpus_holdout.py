"""Priority 4 (evidence base) — frozen, clustered corpus holdout splitter (PR-D/BP-5C).

PR-D / BP-5C require an independent labeled corpus with *clustered splits*, *frozen
sampling*, and an *untouched curated holdout* before any confirmatory efficacy
claim. Independent case authoring is human work; this module is the reproducible
splitting instrument that work needs:

* **Clustered** — cases that share provenance (a vulnerable/fixed ``pair_id``, a
  ``host``/``app``, or an explicit ``cluster``) are assigned as a unit, so a
  patched twin never lands opposite its vulnerable twin and leaks the answer.
* **Frozen** — assignment is a pure hash of ``seed`` + cluster key, so the same
  seed reproduces the exact split byte-for-byte; a new seed reshuffles
  deterministically. No wall-clock, no RNG state.
* **Untouched holdout** — the reserved holdout is flagged so downstream
  tuning/threshold-fitting never consumes it.

Fully offline and deterministic; ``verify_split`` re-derives clusters and refuses
a split with any cross-side leakage.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Callable

DEFAULT_SEED = "agenticvibe-holdout-v1"
_CLUSTER_KEYS = ("cluster", "pair_id", "host", "app")


class CorpusSplitError(ValueError):
    pass


def cluster_of(case: dict[str, Any]) -> str:
    """The grouping key for a case: the first present of cluster/pair_id/host/app,
    else a singleton keyed by the case id (so unrelated cases split freely)."""
    for key in _CLUSTER_KEYS:
        value = case.get(key)
        if value:
            return f"{key}:{value}"
    return f"id:{case.get('id', '')}"


def assign_score(cluster_key: str, seed: str) -> float:
    """Deterministic value in [0, 1) for a cluster under a seed."""
    digest = hashlib.sha256(f"{seed}::{cluster_key}".encode()).hexdigest()
    return int(digest, 16) / 2 ** 256


def split(cases: list[dict[str, Any]], *, holdout_fraction: float = 0.3,
          seed: str = DEFAULT_SEED,
          cluster_key: Callable[[dict[str, Any]], str] = cluster_of) -> dict[str, Any]:
    """Split ``cases`` into train + an untouched holdout, clustered and frozen.

    A cluster goes to the holdout when its seeded score is below
    ``holdout_fraction``. The realized fraction is approximate (it depends on
    cluster sizes) and reported honestly.
    """
    if not 0.0 <= holdout_fraction <= 1.0:
        raise CorpusSplitError("holdout_fraction must be in [0, 1]")
    ids = [c.get("id") for c in cases]
    if any(not i for i in ids):
        raise CorpusSplitError("every case needs a non-empty id")
    if len(set(ids)) != len(ids):
        raise CorpusSplitError("duplicate case ids")

    clusters: dict[str, list[dict[str, Any]]] = {}
    for case in cases:
        clusters.setdefault(cluster_key(case), []).append(case)

    train: list[dict[str, Any]] = []
    holdout: list[dict[str, Any]] = []
    assignment: dict[str, Any] = {}
    for ckey, members in sorted(clusters.items()):
        score = assign_score(ckey, seed)
        to_holdout = score < holdout_fraction
        assignment[ckey] = {"score": round(score, 6), "holdout": to_holdout,
                            "size": len(members)}
        (holdout if to_holdout else train).extend(members)

    total = len(cases)
    return {
        "kind": "corpus_holdout_split",
        "seed": seed,
        "holdout_fraction_requested": holdout_fraction,
        "realized_holdout_fraction": round(len(holdout) / total, 6) if total else None,
        "cluster_count": len(clusters),
        "train_ids": [c["id"] for c in train],
        "holdout_ids": [c["id"] for c in holdout],
        "train": train,
        "holdout": holdout,
        "clusters": assignment,
        "curated_holdout_untouched": True,
    }


def verify_split(result: dict[str, Any], *,
                 cluster_key: Callable[[dict[str, Any]], str] = cluster_of) -> None:
    """Re-derive clusters and refuse any leakage: disjoint ids and no cluster that
    straddles the train/holdout boundary."""
    train, holdout = result.get("train", []), result.get("holdout", [])
    train_ids, holdout_ids = {c["id"] for c in train}, {c["id"] for c in holdout}
    overlap = train_ids & holdout_ids
    if overlap:
        raise CorpusSplitError(f"cases in both train and holdout: {sorted(overlap)}")
    train_clusters = {cluster_key(c) for c in train}
    holdout_clusters = {cluster_key(c) for c in holdout}
    straddle = train_clusters & holdout_clusters
    if straddle:
        raise CorpusSplitError(f"clusters split across sides (leakage): {sorted(straddle)}")


def _load(path: str | Path) -> list[dict[str, Any]]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(value, dict) and isinstance(value.get("cases"), list):
        value = value["cases"]
    if not isinstance(value, list):
        raise CorpusSplitError("cases file must be a JSON list (or {'cases': [...]})")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--cases", required=True, help="JSON list of labeled cases")
    parser.add_argument("--seed", default=DEFAULT_SEED)
    parser.add_argument("--holdout-fraction", type=float, default=0.3)
    parser.add_argument("--out")
    args = parser.parse_args(argv)
    result = split(_load(args.cases), holdout_fraction=args.holdout_fraction,
                   seed=args.seed)
    verify_split(result)
    rendered = json.dumps(result, indent=2, sort_keys=True)
    if args.out:
        Path(args.out).write_text(rendered + "\n", encoding="utf-8")
    print(json.dumps({
        "seed": result["seed"],
        "clusters": result["cluster_count"],
        "train": len(result["train_ids"]),
        "holdout": len(result["holdout_ids"]),
        "realized_holdout_fraction": result["realized_holdout_fraction"],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
