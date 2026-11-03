# Finding dedup (juice-shop-8h over-splitting) — handoff, 2026-11-03

Branch `claude/objective-carson-bcec33` (worktree `bm2-discriminator-afa402`). Not pushed.
Source of truth: `DEDUP_ANALYSIS.md` in the i16-persist worktree
(`.test-work/juice-shop-8h-20261103/`). Only its ids, labels and verdicts were used.

## Counts (DB copy of the 8 h run, 141 store rows)

`measure.py` copies `dedup-db-copy/harness_state.db` into `db/<label>.db`, so the live job DB
is never opened. It then runs the analyst's path:
`all_host_findings` → `_collapse_duplicates` / `issue_exports`.
The before run is HEAD code (`before-src/`, a `git archive` export that is not committed).
The after run is this branch.

| Path | Before | After |
|---|---|---|
| Report shortlist (`_collapse_duplicates` survivors) | 121 | **81** |
| Issue export (`issue_exports` / `issue_key`) | 132 | **78** |

Target: about 65–89. Both paths land inside it. Details are in `counts-before.json` and
`counts-after.json`. The largest groups after the change:
- insecure_transport: 1 issue, 29 rows;
- jwt: 1 issue, 10 rows (route-independent, already worked this way);
- idor GET /rest/basket/{id}: 9 rows (C1 minus 159);
- missing_headers: 1 issue, 7 rows.

Why the counts stay above the analyst's 65 (host-wide) floor. Every reason below is a
deliberate refusal to over-merge:
- **"Broken Access Control" stays unmapped.** It covers 6 issues: bare, `(resource scoping)`,
  `(information disclosure)` and three compounds. Mapping it to idor broke
  `test_categories`' ambiguous-OWASP-heading test and the generic-guess gate, where
  `DEFAULT_GENERIC_CLASSES` lists "broken access control (workflow bypass)". Row 159 of C1
  is therefore its own issue. A part that is this umbrella term also blocks
  compound-label mapping (`_AMBIGUOUS_PARTS`).
- **Rate-limit / pagination wordings (6 issues) are unmapped.** No canonical class fits.
  Adding one would be a taxonomy decision, not a dedup fix.
- **CORS stays per endpoint (5 issues)** when no policy fingerprint is recorded. CORS was not
  in the brief's host-wide list.
- **The report stays per principal for non-authorization classes.** Only idor/bola/bfla drop
  `captured_principal_id` (proposal 5). This is why the report (81) sits above the
  issue export (78).
- **Legacy injection rows written before `finding_inputs` existed** carry no input record.
  They stay split by fingerprint (C5: rows 51 and 52 name different parameters).

## What changed

Each item maps to a proposal in the brief:
1. **`harness/categories.py`**
   - New classes `insecure_transport`, `missing_headers` and `bfla` in `CANONICAL_CATEGORIES`.
   - New `_DEDUP_SYNONYMS`: transport, missing headers, BFLA and broken object-level access
     control.
   - Compound "A / B" labels map when every part that maps agrees. Unmapped parts are
     qualifiers, except an `_AMBIGUOUS_PARTS` umbrella term, which blocks the mapping.
   - "Command Injection / RCE" and "Excessive Data Exposure" were already covered (RCE maps
     to command_injection) and are now tested.
   - `legacy_canonicalize` is the frozen pre-change reading.
   - Also enumerated in:
     - `store._NO_ACTIVE_VALIDATOR` (coverage);
     - `report_generator` remediation hints;
     - `chaining` (`bfla` in the access_control alias set);
     - `test_chaining.KNOWN_UNCOVERED`.
2. **The stored fingerprint is unchanged.** `store.finding_fingerprint` now calls
   `legacy_canonicalize`, so suppressions, observations and the W-9 re-key stay keyed exactly
   as before.
   - The new reading `canonicalize(vc) or distinctive_token(vc) or vc.lower()` applies only to
     the issue key and report key: `issues.issue_class`, used by `issue_key`, which the
     report's `_dedup_key` also calls.
3. **`issues.issue_key` drops the disambiguator for unattributed canonical classes.** It keeps
   the per-row `finding_id` disambiguator for raw labels. For input-bearing classes (sqli,
   xss, …), a row with `input_recorded=False` (legacy) keeps its fingerprint as the
   disambiguator.
4. **`insecure_transport` and `missing_headers` group per host**, in `_HEADER_POLICY_CLASSES`
   through `_HOST_WIDE_CLASSES`, even without a policy fingerprint.
5. **Report collapse.**
   - idor and bfla drop `captured_principal_id` from the collapse key. The survivor lists
     `principals` ("Captured auth contexts:") and `member_ids` ("Member findings:").
   - Host-wide classes render "Also observed … on this host".
6. **New `finding_inputs` side table** (`fingerprint`, `case_id` → `parameter_location`,
   `parameter_name`) with the marker `finding-inputs-schema=1`, following the AR-08a/I16
   pattern.
   - `findings` is not altered.
   - `persist_findings` writes it with INSERT OR IGNORE.
   - `all_host_findings` reads it as the fallback after `proof_records` and sets
     `input_recorded`.
   - `wipe_engagement` deletes it (count key `finding_inputs`).
   - Rollback: `DROP TABLE finding_inputs` and delete the marker.

Rule "a merged group never hides a stronger verdict":
- `issues.verdict_rank` ranks confirmed, then oracle-verified, then not LEAD, then severity,
  then confidence. `Issue.best_member` and the report's `_rank_tuple` both use it.
- The issue export adds `member_ids`.
- Never merged: different hosts, methods or recorded parameters. The one exception is the
  two host-wide classes, which merge across endpoints only.

Tests:
- New `harness/test_finding_dedup.py`: C1–C5 rebuilt as synthetic rows, plus negative
  controls, fingerprint stability, the side-table migration and the wipe.
- Updated to the new policy:
  - `test_issues`: the two R04 tests are narrowed and there is one new merge test;
  - `test_host_level_reuse`: "missing security headers" → `missing_headers`;
  - `test_observation_migration`, `test_proof_identity_migration` and `test_i16_persist`:
    the new object and marker are added to the rollback lists.

## Gates

See `py312.status` and `py314.status`; the logs are under `logs/`. Each run covers:
- precondition;
- the touched modules (every test module that exercises the changed functions, plus the
  migration tests);
- `suite smoke`;
- `git diff --check`.

Results (run on the working tree that became commits f1dc7c9..dfdb29f; status files say
head=bae5321):

| Gate | 3.12.14 | 3.14.7 |
|---|---|---|
| `test_orchestrator_precondition` | 0 | 0 |
| touched modules (852 tests) | 1 failure | 1 failure |
| `suite smoke` | 0 | 0 |
| `git diff --check` | 0 | 0 |

The single failure is
`test_report_batch_reads.BatchedReconstructionMatchesSingleRefTests.test_resolvable_present_and_absent_refs_all_match_single_ref`.
- It **already fails on HEAD**: the same module set run on unchanged `bae5321` code
  (`before-src/`) gives 825 tests and the same 1 failure (`logs/head-touched.log`).
- It passes when run alone, on both this branch and HEAD.
- So it is an order-dependent leak into the ledger/blob path. This change touches neither
  file.
- That makes it a follow-up, not part of this change.

## Owner questions

1. Should **"Broken Access Control"** map to anything? It is left unmapped for the reasons in
   the counts section. Mapping it to idor measured 75 (export) / 78 (report) before the revert, and is blocked by
   two existing tests.
2. Should **CORS be host-wide** when no policy fingerprint exists? That would remove about 4
   more issues.
3. **R04 is narrowed.** Unattributed rows of a canonical class on one endpoint now merge.
   Before, every unattributed row was its own issue. Raw labels and legacy input-bearing rows
   still stay apart. Is this acceptable?
4. **`issues._ISSUE_VERSION` is not bumped**, so stored issue-merge overrides stay valid.
   Issue ids of groups that now absorb more members are unchanged where the key is unchanged.
   Bump it if ids must signal the policy change.
5. Should the report **also drop the principal for host-wide transport and headers**? It
   currently splits C3 into 5 + 1 by principal.
6. The report's `_dedup_key` now passes the fingerprint. Raw-label rows in the report
   therefore split by fingerprint, not by `finding_id`, which is the same row identity in
   practice.

## Files

- Code: `harness/categories.py`, `harness/issues.py`, `harness/report_generator.py`,
  `harness/store.py`, `harness/chaining.py`.
- Tests:
  - new: `harness/test_finding_dedup.py`;
  - updated: `harness/test_issues.py`, `harness/test_host_level_reuse.py`,
    `harness/test_chaining.py`, `harness/test_observation_migration.py`,
    `harness/test_proof_identity_migration.py`, `harness/test_i16_persist.py`.
- Here: `measure.py`, `run_gates.sh`, `counts-*.json`, `*.status`, `HANDOFF.md`.
  `db/`, `before-src/` and `logs/` are not committed.
