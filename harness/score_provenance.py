"""Bind score artifacts to a run manifest (P0.4, evaluation integrity).

A precision/recall number is only as trustworthy as its provenance: which
git revision produced it, which run, against which corpus, over which
inputs, and whether that run actually completed. Historically a score
artifact (e.g. `recall_final_step5.json`) has been read as "current" long
after the code moved on, or produced by an interrupted run -- this module
gives every score artifact an explicit freshness label instead of letting
the reader assume "a score file exists" means "this is what the code does
today".

Pure and hermetic: no git subprocess calls here (the caller supplies the
revision/corpus it already knows, so this stays trivially testable and has
no side effects). `evaluation_integrity/provenance.py`, referenced by an
earlier source list, does not exist in this repo -- this is that module,
under the real package (`harness.*`).
"""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from pathlib import Path

LABEL_FRESH = "fresh"
LABEL_HISTORICAL = "historical"
LABEL_INVALID = "invalid"


@dataclass
class ScoreProvenance:
    """Auditable record of what produced one score artifact."""
    git_revision: str
    run_id: str
    corpus_id: str
    inputs_hash: str
    complete: bool
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "git_revision": self.git_revision,
            "run_id": self.run_id,
            "corpus_id": self.corpus_id,
            "inputs_hash": self.inputs_hash,
            "complete": self.complete,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ScoreProvenance":
        return cls(
            git_revision=str(d.get("git_revision", "") or ""),
            run_id=str(d.get("run_id", "") or ""),
            corpus_id=str(d.get("corpus_id", "") or ""),
            inputs_hash=str(d.get("inputs_hash", "") or ""),
            complete=bool(d.get("complete", False)),
            created_at=float(d.get("created_at", 0.0) or 0.0),
        )


def _missing_required_field(prov: ScoreProvenance) -> bool:
    return not (prov.git_revision and prov.run_id and prov.corpus_id and prov.inputs_hash)


def freshness_label(prov: ScoreProvenance, current_revision: str, current_corpus: str) -> str:
    """Classify a score artifact against the CURRENT code/corpus.

    - "invalid": the run never completed, or any identifying field is empty.
      An incomplete run's numbers cannot be trusted at all -- never read as
      "historical but real", which would imply it finished honestly.
    - "historical": completed, but produced by a different revision or a
      different corpus than what's current -- a real result, just not for
      the code/corpus in front of you right now.
    - "fresh": completed, same revision, same corpus -- the only label that
      may be read as "what the code does today".
    """
    if not prov.complete or _missing_required_field(prov):
        return LABEL_INVALID
    if prov.git_revision != current_revision or prov.corpus_id != current_corpus:
        return LABEL_HISTORICAL
    return LABEL_FRESH


def compute_inputs_hash(paths: list[str | Path]) -> str:
    """sha256 over the sorted, concatenated contents of every input file.

    Sorted so the hash is order-independent (a caller can pass paths in any
    order and get the same fingerprint), and content-based (not mtime/size)
    so it actually detects a changed fixture/corpus file, not just a touch."""
    hasher = hashlib.sha256()
    for p in sorted(str(p) for p in paths):
        hasher.update(Path(p).read_bytes())
    return hasher.hexdigest()
