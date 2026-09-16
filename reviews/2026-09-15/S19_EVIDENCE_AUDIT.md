# Evaluation-integrity audit

Audit input valid: **true**.

This is an offline consistency and support audit. It is not a fresh pipeline run,
does not authenticate the artifact producer, and makes no live-efficacy claim.

## Provenance and health

- Provenance: `unknown_or_mismatched`
- Evaluation validity: `unknown`
- Process finished: `True`
- Provenance limitation: no evaluation manifest supplied
- Health limitation: no independently recorded benign target-health controls were supplied

## Confirmation evidence

- Confirmation claims: **167**
- Named validator references: **0**
- Proof references: **115**
- Matching proof-supported confirmations: **0**

Unverifiable confirmation reasons (IDs remain in the JSON diagnostic):

- 52 × confirmation is a bare true boolean with no proof reference
- 115 × proof reference is absent from the supplied artifact set

## Coverage (layers are not summed)

- Request/cell total: 11438
  - attempted: 387 / 11438 (3.38%)
  - skipped: 4052 / 11438 (35.43%)
  - not_applicable: 6999 / 11438 (61.19%)
  - blocked: 0 / 11438 (0.0%)
  - failed: 0 / 11438 (0.0%)
  - unknown: 0 / 11438 (0.0%)
  - positive_evidence: 112 / 11438 (0.98%)
  - controlled_negatives: 0 / 11438 (0.0%)
  - inconclusive: 0 / 11438 (0.0%)
- Parameter/case total: 0
  - attempted: 0 / 0 (unknown)
  - skipped: 0 / 0 (unknown)
  - not_applicable: unknown / 0 (unknown)
  - blocked: 0 / 0 (unknown)
  - failed: 0 / 0 (unknown)
  - unknown: 0 / 0 (unknown)
  - positive_evidence: 0 / 0 (unknown)
  - controlled_negatives: 0 / 0 (unknown)
  - inconclusive: 0 / 0 (unknown)
- Coverage warning: some attempted request-level checks lack decisive evidence

## Counts and metric scope

- Normalized auditable finding records: **378**
- Unique issues: **unknown** (`unavailable`)
- Proof-supported confirmation occurrences: **0**
- Benchmark scope: `endpoint_known_items`
- Original reported finding occurrences: **2428**
- Original reported confirmed occurrences: **887**
- Original reported endpoint-known result: **9 / 13**
- Metric limitation: unique issue count is unknown because trustworthy production issue identity is incomplete
- Metric limitation: source-reported occurrence count differs from normalized auditable records; both are preserved and neither is silently substituted
- Metric limitation: endpoint-known benchmark results are not whole-target recall
- Metric limitation: missing labels or complete prediction/evidence inputs prevent independently deriving TP/FP/FN conclusions

## Source consistency

- `maxcov_results_s19_full.json`: `agenticvibe-maxcov-results/v1`, SHA-256 `a5db4d0bf057f99c4716d6d425bc6eba13faf4ef2a3ce9562ed57b3422e1cb82`, unchanged during read: `true`
- `recall_report_s19_full.json`: `agenticvibe-endpoint-known-recall/v1`, SHA-256 `37ad4cf2bdb4d1f954c1acfbb63dc93daddd16fddd18d5870b10d8f6a2a800e8`, unchanged during read: `true`
