"""
manifest.py -- exact-class label manifest schema + loader/validator (BP-0, PR-2).

Ground-truth spine for strict exact-class scoring (PR-3 / BP-1a). A manifest
records, per captured exchange, one or more EXACT vulnerability classes (not
the coarse OWASP buckets in ``testing/score.py``'s ``_LABEL_CATEGORY``), any
classes the exchange is a NEGATIVE control for (per-class -- a benign SQL
query is not proof the endpoint is secure against every other class), and a
status distinguishing a real positive/negative from an unresolved or
fixture-only ("setup") exchange.

Every label in the seed manifest (``pixelmart.labels.json``) is derived ONLY
from the two PERMITTED public sources named for this task: ``score.py``'s
``_LABEL_CATEGORY`` (coarse OWASP ground truth) and
``test-target/bench.py``'s ``KEYWORDS`` (per-label exact-class keyword
hints), plus the corpus's own self-describing ``label`` strings (the
captured exchange corpus itself is a permitted source). No label here was
derived from ``*ANSWER_KEY*`` or a blind target's ``app.py`` -- see each
record's ``provenance`` field and
``docs/BENCHMARK_PRECISION_IMPLEMENTATION_PATH.md`` (BP-0).

Where the permitted public sources do not pin a single exact class (TP8:
score.py explicitly excludes it as an unprovable-from-one-exchange race
condition, and bench.py's KEYWORDS has no TP8 entry either), ``status`` is
``inconclusive`` and both class lists stay empty -- unresolved labels are
surfaced by the loader (``Manifest.unresolved()``), never silently dropped
or treated as secure.

Typical use::

    from labels.manifest import load_manifest

    manifest = load_manifest("testing/labels/pixelmart.labels.json")
    manifest.validate()          # raises ManifestError on hash mismatch
    manifest.scorable()          # positive + negative records only
    manifest.unresolved()        # inconclusive records, surfaced not dropped
    manifest.negative_controls_for("sqli")
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

# Controlled, closed vocabulary of exact vulnerability-class aliases. This is
# the "documented closed set" the manifest schema requires -- extend it
# deliberately; an expected_classes/tested_negative_classes entry outside
# this set is a validation error, not a silent pass-through.
EXACT_CLASSES: frozenset[str] = frozenset({
    "sqli", "xss", "ssti", "command_injection", "ssrf", "csrf", "idor",
    "path_traversal", "jwt", "auth_bypass", "security_misconfiguration",
    "info_disclosure", "business_logic",
})

STATUSES: frozenset[str] = frozenset({"positive", "negative", "inconclusive", "setup"})

# Closed record/manifest schemas. Any key outside these sets is rejected --
# the label-leak check this module is required to have: a stray free-text
# field (e.g. "notes", "answer", "exploit_detail") is exactly how a label
# could leak into detector input if a record were ever echoed back into a
# prompt, so the loader refuses anything it does not recognise by name
# rather than passing an unknown field through.
_RECORD_FIELDS: frozenset[str] = frozenset({
    "exchange_id", "expected_classes", "tested_negative_classes",
    "label_scope", "status", "provenance",
})
_MANIFEST_FIELDS: frozenset[str] = frozenset({"corpus", "version", "hash", "records"})


class ManifestError(ValueError):
    """Raised for a malformed, inconsistent, or label-leaking manifest."""


@dataclass(frozen=True)
class LabelRecord:
    """One exchange's exact-class ground truth. Structurally validated in
    __post_init__ so an invalid record can never exist, only be rejected."""
    exchange_id: str
    expected_classes: tuple[str, ...]
    tested_negative_classes: tuple[str, ...]
    label_scope: str
    status: str
    provenance: str

    def __post_init__(self) -> None:
        if not self.exchange_id:
            raise ManifestError("record missing exchange_id")
        if self.status not in STATUSES:
            raise ManifestError(
                f"{self.exchange_id}: invalid status {self.status!r} "
                f"(must be one of {sorted(STATUSES)})")
        for c in self.expected_classes:
            if c not in EXACT_CLASSES:
                raise ManifestError(
                    f"{self.exchange_id}: expected_classes has unknown class {c!r} "
                    f"(must be one of {sorted(EXACT_CLASSES)})")
        for c in self.tested_negative_classes:
            if c not in EXACT_CLASSES:
                raise ManifestError(
                    f"{self.exchange_id}: tested_negative_classes has unknown class {c!r} "
                    f"(must be one of {sorted(EXACT_CLASSES)})")
        if not self.provenance:
            raise ManifestError(f"{self.exchange_id}: missing provenance")
        if self.status == "positive" and not self.expected_classes:
            raise ManifestError(
                f"{self.exchange_id}: status=positive requires >=1 expected_classes")
        if self.status == "negative" and self.expected_classes:
            raise ManifestError(
                f"{self.exchange_id}: status=negative must not carry expected_classes "
                "(a negative record cannot also assert a confirmed vulnerability class)")
        if self.status == "setup" and (self.expected_classes or self.tested_negative_classes):
            raise ManifestError(
                f"{self.exchange_id}: status=setup must not carry expected/negative classes "
                "(fixture-building exchanges are never scored)")
        if self.status == "inconclusive" and (self.expected_classes or self.tested_negative_classes):
            raise ManifestError(
                f"{self.exchange_id}: status=inconclusive must not carry expected/negative "
                "classes (an unresolved label cannot also claim a confident class)")

    @classmethod
    def from_dict(cls, d: dict) -> "LabelRecord":
        if not isinstance(d, dict):
            raise ManifestError(f"record is not an object: {d!r}")
        extra = set(d) - _RECORD_FIELDS
        if extra:
            raise ManifestError(
                f"record has unexpected field(s) {sorted(extra)} (possible label leak) -- "
                f"allowed fields are {sorted(_RECORD_FIELDS)}")
        missing = _RECORD_FIELDS - set(d)
        if missing:
            raise ManifestError(f"record missing required field(s): {sorted(missing)}")
        if not isinstance(d["expected_classes"], list):
            raise ManifestError(f"{d.get('exchange_id')!r}: expected_classes must be a list")
        if not isinstance(d["tested_negative_classes"], list):
            raise ManifestError(f"{d.get('exchange_id')!r}: tested_negative_classes must be a list")
        return cls(
            exchange_id=str(d["exchange_id"]),
            expected_classes=tuple(d["expected_classes"]),
            tested_negative_classes=tuple(d["tested_negative_classes"]),
            label_scope=str(d["label_scope"]),
            status=str(d["status"]),
            provenance=str(d["provenance"]),
        )

    def to_dict(self) -> dict:
        return {
            "exchange_id": self.exchange_id,
            "expected_classes": list(self.expected_classes),
            "tested_negative_classes": list(self.tested_negative_classes),
            "label_scope": self.label_scope,
            "status": self.status,
            "provenance": self.provenance,
        }


def compute_hash(records) -> str:
    """Deterministic sha256 over a manifest's record payload.

    Records are sorted by exchange_id before hashing so the hash is
    independent of on-disk array order -- reordering records in the JSON
    file (e.g. a diff-minimizing edit) does not spuriously change it, but
    editing any field's content does. Accepts either LabelRecord instances
    or already-plain dicts (the seed-generation script and the loader both
    call this against the same records, so a stored hash always matches
    what the loader recomputes)."""
    payload = sorted(
        (r.to_dict() if isinstance(r, LabelRecord) else r for r in records),
        key=lambda d: d["exchange_id"],
    )
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Manifest:
    """A loaded, structurally-valid label manifest for one corpus."""
    corpus: str
    version: str
    hash: str
    records: tuple[LabelRecord, ...]

    def __post_init__(self) -> None:
        if not self.corpus:
            raise ManifestError("manifest missing corpus")
        if not self.version:
            raise ManifestError("manifest missing version")
        if not self.hash:
            raise ManifestError("manifest missing hash")
        ids = [r.exchange_id for r in self.records]
        dupes = sorted({i for i in ids if ids.count(i) > 1})
        if dupes:
            raise ManifestError(f"duplicate exchange_id(s): {dupes}")

    # --- lookup --------------------------------------------------------

    def by_id(self, exchange_id: str) -> LabelRecord | None:
        for r in self.records:
            if r.exchange_id == exchange_id:
                return r
        return None

    # --- status partitions ----------------------------------------------
    # These are the loader's scoring-relevant query surface: a caller (e.g.
    # the PR-3 strict scorer) should never re-derive "is this scorable" by
    # eyeballing status strings itself -- it asks the manifest.

    def positives(self) -> list[LabelRecord]:
        return [r for r in self.records if r.status == "positive"]

    def negatives(self) -> list[LabelRecord]:
        return [r for r in self.records if r.status == "negative"]

    def unresolved(self) -> list[LabelRecord]:
        """Inconclusive records. Surfaced explicitly -- NEVER dropped and
        NEVER folded into positives/negatives, and never scored (see
        scorable())."""
        return [r for r in self.records if r.status == "inconclusive"]

    def setup_records(self) -> list[LabelRecord]:
        """Fixture-building exchanges. Never a positive or FP-eligible
        candidate -- excluded from scorable()."""
        return [r for r in self.records if r.status == "setup"]

    def scorable(self) -> list[LabelRecord]:
        """positive + negative records only. Excludes inconclusive
        (unresolved, unscored per the manifest's own unresolved()) and
        setup (fixture-building, never positive/FP-eligible)."""
        return [r for r in self.records if r.status in ("positive", "negative")]

    def negative_controls_for(self, exact_class: str) -> list[LabelRecord]:
        """Records that are an explicit PER-CLASS negative control for
        `exact_class`. Never inferred from status=="negative" alone -- a
        record's tested_negative_classes is the only thing that establishes
        which class(es) it was actually a control for."""
        return [r for r in self.records if exact_class in r.tested_negative_classes]

    # --- integrity -------------------------------------------------------

    def validate(self) -> dict:
        """Recomputes the content hash over the loaded records and compares
        it against the manifest's stored `hash` -- catches a manifest whose
        records were hand-edited without updating the hash (silent drift
        from what was actually reviewed/seeded). Raises ManifestError on
        mismatch; otherwise returns a small summary report."""
        recomputed = compute_hash(self.records)
        if recomputed != self.hash:
            raise ManifestError(
                f"manifest hash mismatch: stored={self.hash!r} recomputed={recomputed!r} "
                "(records were edited without updating the hash)")
        return {
            "corpus": self.corpus,
            "version": self.version,
            "n_records": len(self.records),
            "n_positive": len(self.positives()),
            "n_negative": len(self.negatives()),
            "n_inconclusive": len(self.unresolved()),
            "n_setup": len(self.setup_records()),
        }

    def to_dict(self) -> dict:
        return {
            "corpus": self.corpus,
            "version": self.version,
            "hash": self.hash,
            "records": [r.to_dict() for r in self.records],
        }


def load_manifest(path: str | Path) -> Manifest:
    """Load and structurally validate a label manifest from `path`.

    Raises ManifestError for anything malformed: missing/extra top-level or
    record fields (the label-leak check), a bad `status`, an exact-class
    alias outside the controlled vocabulary, or a duplicate exchange_id --
    never returns a partially-valid Manifest. Does NOT itself check the
    content hash (call `.validate()` on the result for that); a caller that
    wants full structural + integrity validation calls both."""
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ManifestError(f"manifest root must be an object, got {type(raw).__name__}")
    extra = set(raw) - _MANIFEST_FIELDS
    if extra:
        raise ManifestError(
            f"manifest has unexpected top-level field(s) {sorted(extra)} "
            f"(possible label leak) -- allowed fields are {sorted(_MANIFEST_FIELDS)}")
    missing = _MANIFEST_FIELDS - set(raw)
    if missing:
        raise ManifestError(f"manifest missing required field(s): {sorted(missing)}")
    records_raw = raw["records"]
    if not isinstance(records_raw, list):
        raise ManifestError("manifest 'records' must be a list")
    records = tuple(LabelRecord.from_dict(r) for r in records_raw)
    return Manifest(corpus=str(raw["corpus"]), version=str(raw["version"]),
                     hash=str(raw["hash"]), records=records)
