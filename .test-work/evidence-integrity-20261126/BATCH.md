# Batch: evidence integrity on read, export and share (2026-11-26)

## Problem to confirm first
`harness/store.py:377` stores redacted evidence blobs keyed by sha256, and
`evidence_blob_resolves()` re-hashes them, but its comment says only the resolvability
assessment (`evidence_ledger._assess_completeness`) and report/API display consult it. It is
not yet known whether every path that serves or exports blob bytes re-verifies them, or whether
a saved/shared report notices when its evidence later changes.

## Idea (from ARTEX, not its code)
ARTEX re-checks each evidence body's hash on write, on every read and on export, and fails the
read or export on a mismatch. Each finding carries an evidence version; a report saved against
an older version is rejected or flagged stale.

## Requirements
1. Audit every path that returns or exports evidence blob bytes (server endpoints,
   `report_generator.py`, `report_share.py`, `run_manifest.py`, `mcp_adapter.py`, exports). A
   mismatch must be reported as unresolved/error, never served. Fix the gaps you find.
2. If shared or exported reports are persisted snapshots (`report_share.py`), record the
   evidence state they were built from and flag them stale when it changes (new or revised
   proof, ledger revision). If reports are always rendered live, say so and skip this.
3. If both are already covered, change nothing and record the evidence in HANDOFF.

## Tests (each with a negative control)
- A corrupted blob row is reported unresolved by each read/export path; an intact one is served.
- A share built, then evidence revised: stale; built and unchanged: not stale.
