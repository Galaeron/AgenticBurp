# Handoff: evidence integrity on read, export and share (2026-11-26)

Branch `worktree-agent-a297f4c2facc651eb`, base `0fb8cd5`. Commits `75cd000` (store reader), `e2aff45` (callers).

## What changed
- `harness/store.py`: new `read_evidence_blob(h, conn=None) -> (status, bytes|None)`, where status is
  `BLOB_RESOLVED`, `BLOB_MISSING` or `BLOB_HASH_MISMATCH`. It returns bytes only when they still hash
  to `h`. `get_evidence_blob` now returns None on a mismatch (before, it returned the tampered bytes), and
  `evidence_blob_resolves` is built on the new reader. A row rewritten as TEXT is hashed as UTF-8
  instead of raising a TypeError.
- `harness/app_map.py`: this was the one real gap. It read capture bytes without checking them and fed
  their request-body fields into `GET /engagement/{host}/map`. It now uses the verified reader. Each
  observation carries `evidence_status`, and the map adds `sources.evidence_unresolved`, which lists the
  observation ids whose blobs fail the hash check.
- `harness/leads.py`: a mismatched blob was already not served, but the lead's `no_request_reason` said
  "not retained". It now says `NO_REQUEST_UNRESOLVED`. The captured-observation and ledger-send sources
  both report this.
- `harness/writeups.py`: replaced check-then-read with one verified read (same behaviour).

## Audit (each path that returns or exports blob bytes)
| Path | Verdict |
|---|---|
| `store.get_evidence_blob` (raw reader) | fixed: verifies on every read |
| `app_map._observations` -> `/engagement/{host}/map` | fixed (was serving unverified bytes) |
| `leads._observation_request` / `_ledger_request` -> `/engagement/{host}/leads` | already not served; reason fixed |
| `writeups._load_blob` -> export `writeup`, `/engagement/{host}/writeups`, `write_files` | already verified |
| `evidence_ledger` reconstruct / recipe -> `/findings/{ref}/evidence`, `/report` evidence-chain line | already verified: hash-check only, no bytes; tamper test exists (`test_evidence_provenance_passive`) |
| `assessment_health.stored_proof_artifacts_resolve` (proof accounting, run manifest) | already verified (`test_proof_artifacts.test_corrupted_attack_blob_stays_a_candidate`) |
| `store.select_observations` / `get_observation` / `resolve_observation_refs` -> `/observations/{id}` | already verified (corruption shows as `unavailable`); test added |
| `data_maintenance.inspect_database` / `snapshot` (backup export) | already verified: fails closed on a mismatch |
| `report_generator` Markdown, `/report/sarif`, `mcp_adapter` issues resource, `report_share` | not applicable: they read no blob bytes, and their resolvability comes from the ledger rows above |
| `run_manifest` | not applicable: stores counts and refs, no bytes |

## Requirement 2 (stale persisted shares): skipped
Nothing persists a shared report. `report_share.render_offline_html` and `render_http_exports` are pure
functions over export dicts, and no production code calls them (only `test_report_share.py`).
`writeups.write_files` is likewise called only from tests. `/report`, `/report/sarif`, `/writeups`, the
MCP issues resource and the map are all rendered live from the store on each request. The run manifest
(`run-output/<run_id>.json`, which the MCP provenance resource serves) is a persisted run record with
counts. It records no evidence state and is not flagged stale; see the open question below.

## Tests (2026-11-27, `/home/user/.venv-agb/bin/python`, `PLAYWRIGHT_BROWSERS_PATH=/opt/pw-browsers`, worktree root)
- `python -m harness.suite smoke`: exit 0, 182 tests.
- `python -m unittest harness.test_orchestrator_precondition`: 74 OK.
- `python -m unittest <the 77 harness test modules matching blob/leads/writeups/app_map/observation> harness.test_pipeline_gate`:
  1447 tests OK (6 skipped), exit 0.
- New tests, each with an intact control:
  - `test_leads_api.LeadsCallerTests.test_a_corrupted_request_blob_is_reported_unresolved_not_served`
  - `test_app_map.AppMapCallerTests.test_a_corrupted_capture_gives_no_fields_and_is_named_unresolved`
  - `test_writeups.WriteupCallerTests.test_a_corrupted_proof_blob_gives_no_writeup` (regression guard;
    it also passes on the old code)
  - `test_observation_store.CorrectionAndDeletionTests.test_corrupted_evidence_is_reported_not_served`
  - `test_store.EvidenceBlobStoreTests.test_a_row_rewritten_as_text_is_judged_on_content`
- Updated test: `test_store...test_corrupted_blob_fails_hash_verification` asserted that
  `get_evidence_blob` returned the tampered bytes. It now checks the raw row directly and expects None or
  `hash_mismatch` from the reader.
- Negative-control check: with the three source files reverted to HEAD, the leads, app-map and TEXT-row
  tests and the updated store test fail (1 failure, 3 errors). They pass with the fix.

## Unverified
- Full suite: not run (the orchestrator runs it after the merge). No live run; no Java changes.
- The Burp extension's handling of the new `no_request_reason` text and the
  `sources.evidence_unresolved` key has not been checked. Both are additive.

## Next steps / open questions
- Should the persisted run manifest record an evidence-state digest (e.g. a hash over the confirmed
  proofs' blob hashes) so the MCP provenance resource can flag it stale? This is out of this brief's scope.
- The observation APIs report both missing and mismatched blobs as `unavailable`. A separate
  `hash_mismatch` status would change a public value and the selection digest, so it was left as is.
