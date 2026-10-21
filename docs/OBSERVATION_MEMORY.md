# Observation memory (I02 batch C)

A supplied capture analysed through `POST /analyze` (or a standalone
`Orchestrator.analyze`) is retained as an *observation* whether or not it
produced a finding. A later analysis of the same endpoint is given the earlier
observations it may compare against. Design and owner decisions:
`.test-work/i02c-observations-20261019/DESIGN.md` (approved 2026-10-19).

## What is stored

`exchange_observations` holds capture facts, which never change except for the
deletion tombstone. It stores:

- the scope: host and pile;
- the `exchange_id`, which is the client's `capture_id`, or else the content
  hash that finding provenance also uses;
- a keyed content digest and the captured-auth label;
- method, the redacted URL and the normalized endpoint (path kept, query
  values dropped);
- capture time (NULL = unknown) and ingest time;
- capture source, completeness and the supplied `state_version`;
- bounded facts: status, content type, size and up to 32 top-level JSON key
  names, never values;
- a reference to the sanitized exchange in `evidence_blobs`, capped at 64 KiB
  with an explicit truncation flag.

`observation_attributions` is an append-only revision stream of analyst labels
(principal, role, tenant, session). Revision 1 comes from the optional
`AnalysisRequest.observation_attribution`, and is unknown when absent. Labels
that look like credentials are rejected, and no credential value is stored.
`finding_observations` still links findings to exchanges through the same
`exchange_id`.

The optional `HttpExchange` fields `captured_at`, `capture_source`, `completeness`
and `state_version` belong to the I07 contract. Absent means unknown and is
never inferred. The Burp extension does not send them, nor a `capture_id`, yet.

## Identity and duplicates

The key is `(host, engagement_id, exchange_id)`; `engagement_id` `''` is the
site's shared pile.

- The same capture with the same digest is a duplicate (nothing is written).
- The same id with different content is a conflict: it is rejected and the
  stored row is untouched.
- A new capture of the same URL is a new observation.
- A deleted capture stays deleted on re-ingest.
- Volatile headers (Date, ETag, ...) do not change the digest.

## Retrieval

`store.select_observations` is the only reader. It considers the same host,
pile and endpoint, scans at most 200 rows and selects at most 8.

- A row joins on the same recognized credential context, or on the same
  analyst-declared tenant on both sides.
- Declared tenants that differ never join. `anonymous` (no recognized
  credential header) and unknown tenants never join each other.
- Rows that are not joined are reported only as counts per reason.
- Order follows capture time. Rows without one say "ingest order only".

The rendered block is appended to the prior context before the cache digest.
Corrections, deletions and evidence expiry therefore change both the response
and hypothesis cache keys.

Only a supplied capture is retained: the analysis owns its run and no other
run encloses it. Since I05-A2 a standalone analysis publishes its own run, so
the check is made before that. These analyses neither retain nor read
observations:

- engagement-driven analyses (a passed or enclosing run);
- discovery;
- harness-fetched traffic (`retain_observation=False`).
`AnalysisResponse.observation_context` reports what was selected, the
exclusion counts, the write status and the digest.

## Analyst actions and lifecycle

These authenticated routes act within one pile:

| Route | Effect |
|---|---|
| `POST /observations/{id}/attribution` | Appends a complete new revision. It needs `expected_revision` (409 when stale) and returns 410 for a deleted observation. |
| `DELETE /observations/{id}` | Leaves a tombstone. Facts, state label, URL and evidence are removed; the evidence blob goes unless another observation or a ledger event still references it. |
| `GET /observations/{id}` | Returns the observation's status and attribution history. |

Deleted observations are listed as unavailable to later analyses and resolve
as `deleted`.

- `wipe_engagement(host)` and `data_maintenance wipe-context` delete
  observations with the same shared-blob guard.
- Backup receipts count observation evidence references.
- Blob retention expiry shows as evidence unavailable. Observation rows are
  otherwise kept until deleted or wiped.

Migration is additive: two new tables and a `state_metadata` marker.
`PRAGMA user_version` is untouched, and nothing is backfilled from findings.
Rollback is dropping the two tables.

## Evidence boundary

`harness/test_observation_store.py` covers the storage contract, and
`harness/test_observation_migration.py` covers migration and rollback against
the frozen pre-change schema. `harness/test_observation_memory_caller.py`
covers acceptance cases C01, C03, C04, C08 and C09 through the real callers,
with a canned consumer and zero target sends. These establish retrieval and
transport only. Real-model usefulness (I14) and the Burp fields and UI
(I07/I16) remain open.
