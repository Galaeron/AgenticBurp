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

    def __post_init__(self) -> None:
        # R05: a quoted "false"/"true" string (e.g. round-tripped through a
        # loosely-typed JSON/YAML artifact) must never coerce to a truthy
        # `complete` via bare bool(...) -- only a REAL bool, or the exact
        # canonical strings, is accepted; anything else is rejected outright
        # rather than silently guessed at.
        if isinstance(self.complete, str):
            low = self.complete.strip().lower()
            if low not in ("true", "false"):
                raise ValueError(f"complete must be a bool, got string {self.complete!r}")
            self.complete = (low == "true")
        elif not isinstance(self.complete, bool):
            raise ValueError(f"complete must be a bool, got {self.complete!r}")

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
        # `complete` is passed through RAW (not pre-coerced with bare bool(),
        # which would turn the string "false" into True) so __post_init__'s
        # strict bool/"true"/"false" check is the only place that decides it.
        return cls(
            git_revision=str(d.get("git_revision", "") or ""),
            run_id=str(d.get("run_id", "") or ""),
            corpus_id=str(d.get("corpus_id", "") or ""),
            inputs_hash=str(d.get("inputs_hash", "") or ""),
            complete=d.get("complete", False),
            created_at=float(d.get("created_at", 0.0) or 0.0),
        )


def _missing_required_field(prov: ScoreProvenance) -> bool:
    return not (prov.git_revision and prov.run_id and prov.corpus_id and prov.inputs_hash)


def freshness_label(prov: ScoreProvenance, current_revision: str, current_corpus: str, *,
                     expected_run_id: str | None = None,
                     expected_inputs_hash: str | None = None) -> str:
    """Classify a score artifact against the CURRENT code/corpus/run/inputs.

    - "invalid": the run never completed, any identifying field is empty, or
      (when the caller supplies an expectation) the run_id/inputs_hash does
      not match what the caller expects -- an artifact whose declared run or
      inputs don't match reality is not a real historical result, it is a
      fabricated or mismatched claim. An incomplete run's numbers cannot be
      trusted at all -- never read as "historical but real", which would
      imply it finished honestly.
    - "historical": completed, matches any supplied run_id/inputs_hash
      expectation, but produced by a different revision or a different
      corpus than what's current -- a real result, just not for the
      code/corpus in front of you right now.
    - "fresh": completed, same revision, same corpus, and (when checked)
      the same run_id/inputs_hash the caller expected -- the only label that
      may be read as "what the code does today".

    `expected_run_id`/`expected_inputs_hash` are optional so existing callers
    that only track revision/corpus keep working, but when a caller DOES
    supply them (e.g. testing/score.py knows which run it just launched and
    which input files it fed it), a mismatch is treated as invalid rather
    than as "any nonempty value will do" (R05: nonemptiness alone previously
    passed even a fabricated run_id/inputs_hash)."""
    if not prov.complete or _missing_required_field(prov):
        return LABEL_INVALID
    if expected_run_id is not None and prov.run_id != expected_run_id:
        return LABEL_INVALID
    if expected_inputs_hash is not None and prov.inputs_hash != expected_inputs_hash:
        return LABEL_INVALID
    if prov.git_revision != current_revision or prov.corpus_id != current_corpus:
        return LABEL_HISTORICAL
    return LABEL_FRESH


def compute_inputs_hash(paths: list[str | Path]) -> str:
    """sha256 over an unambiguous, sorted manifest of (path, content) pairs.

    Sorted by path so the hash is order-independent (a caller can pass paths
    in any order and get the same fingerprint), and content-based (not
    mtime/size) so it actually detects a changed fixture/corpus file, not
    just a touch. Each file's own digest is length-prefixed together with
    its path before folding into the final hash (R05), so two different
    file-boundary splits of the same total bytes -- e.g. "ab"+"c" vs
    "a"+"bc" -- never collide: naive concatenation-without-separators is
    genuinely ambiguous encoding, not a hash collision, and this manifest
    form closes that regardless of path/content bytes."""
    hasher = hashlib.sha256()
    for p in sorted(str(p) for p in paths):
        content = Path(p).read_bytes()
        file_digest = hashlib.sha256(content).hexdigest()
        path_bytes = p.encode("utf-8")
        hasher.update(len(path_bytes).to_bytes(8, "big"))
        hasher.update(path_bytes)
        hasher.update(len(content).to_bytes(8, "big"))
        hasher.update(file_digest.encode("ascii"))
    return hasher.hexdigest()
