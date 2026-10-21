# I01 candidate manifest and tracker reconciliation — 2026-10-17

This document is the I01 output from
[the remaining-implementation plan](REMAINING_IMPLEMENTATION_PLAN_2026-10-17.md). It
freezes a candidate and records a disposition for every working-tree change. It also
assigns one canonical owner to each open backlog item. It is a bookkeeping record:
it claims no efficacy, live validation or release readiness. The historical crAPI
no-go still stands.

## Candidate identity

- **Base:** `64e09ed6552aec2979ad02db2dd8393884ca18b3`. It contains the ARCH-3 ceiling and
  cleanup hardening, is pushed to `origin/reconciliation-backlog` and is the head of
  [Galaeron/AgenticBurp#1](https://github.com/Galaeron/AgenticBurp/pull/1).
- **Overlay:** the SPA-discovery and catch-all fixes. It spans 12 files, +439/−30 lines.
  Patch: `.test-work/i01-candidate-overlay.patch` (SHA256 `3b89d945…59644b8`). Per-file
  hashes: `.test-work/i01-candidate-file-hashes.txt`.
- **Committed:** `ba0806918fef8323d83ee1ceeb7f4e610ba0b345` on `reconciliation-backlog`, local
  and not pushed. It was staged from the patch alone, and `git diff 64e09ed6 ba080691 --binary`
  is byte-identical to the patch, so the commit is exactly the tested candidate.

| File | Overlay content |
|---|---|
| `harness/api_surface_discovery.py` | per-prefix catch-all calibration, wildcard pruning, ffuf/query existence checks |
| `harness/crawler.py` | literal same-origin JS module traversal; fetch/axios/XHR call shapes |
| `harness/role_crawl.py` | call-shape methods in the access matrix; capture seed paths |
| `harness/engagement_builder.py` | browser capture under the owning RunContext; identity-bound capture import |
| `harness/orchestrator_chain.py` | forwards `seed_exchanges` and `driver_capture` config; reports capture errors |
| `harness/browser_driver.py` | blocks service workers so route interception holds |
| `harness/driver_capture.py` | docstring only (now has a caller) |
| `harness/server.py` | **only 2 of 5 working-tree hunks:** `seed_exchanges` / `active_discovery` on investigate |
| `harness/test_api_surface_discovery.py` | ffuf hit now needs a real existence response |
| `harness/test_driver_capture.py` | real Chromium → `build_engagement` worklist caller test |
| `harness/test_discovery_spa_wildcards.py` (new) | caller tests and negative controls for the above |
| `docs/SPA_DISCOVERY_FIXES.md` (new) | usage, scope and limitations |

Except `server.py`, every file is byte-identical to the working tree. The hashes of
`api_surface_discovery.py` and `crawler.py` match the 2026-10-16 manifest.

### Reproduce

```sh
git worktree add --detach <dir> 64e09ed6552aec2979ad02db2dd8393884ca18b3
cd <dir>
git apply <repo>/.test-work/i01-candidate-overlay.patch
python -m unittest harness.test_orchestrator_precondition
python -m harness.suite smoke
python -m harness.suite full
```

Run the commands from the candidate root, so that `harness` resolves to the candidate rather than the main checkout.

## Verification of the isolated candidate

Interpreter: `.venv-rationalisation/Scripts/python.exe` (3.12.14), run from a detached
worktree outside the repository. No `config.local.yaml` was present, so the committed
safe defaults applied.

| Command | Result | Log |
|---|---|---|
| `python -m unittest harness.test_orchestrator_precondition` | 74 tests OK, exit 0 | `.test-work/i01-candidate-precondition.log` |
| `python -m harness.suite smoke` | 93 tests OK + coverage gate, exit 0 | `.test-work/i01-candidate-smoke.log` |
| `python -m harness.suite full` | exit 0: 3,164 harness tests OK in 484 s (0 skips); coverage gate passes, with 38 requirements: 2 partial and 36 gaps (33 unimplemented, 3 manual); 38 pytest-native passed; 308 evaluation tests OK, 17 skipped; 42 integrity OK | `.test-work/i01-candidate-full.log` |

Exit codes: `.test-work/i01-candidate-exits.log`. Identity: `.test-work/i01-candidate-identity.log`.

All 17 evaluation skips come from local benchmark artifacts that are absent from a clean
checkout: the untracked 2026-09-23/09-25 benchmark results and the DVWA/WebGoat corpora. They
are not passes. The mixed working tree's 2026-10-16 run reported 3,459 harness and 371 evaluation
tests. The difference is the untracked and W1–W4 tests that the candidate excludes, so the earlier
count was never a count for any committed or committable source state.

CI on PR #1 at `64e09ed6` covers the base from a clean checkout, without the overlay. Both
workflow runs passed "Full suite + coverage gate (all Python tiers)" (7m45s and 9m16s), the
Burp extension build and Java tests (JDK) and the scored-tier provenance check. The nightly
precision and GPU scored-tier jobs were skipped. Neither the Java pass nor the candidate run
says anything about the uncommitted Java edits listed below.

## Disposition of working-tree changes outside the candidate

None of these changes is in the candidate. Nothing here was reverted, staged or committed.
The groups are uncommitted work that each needs its own reviewed, focused commit.

### Modified tracked files

| Group | Files (hunks) | Owner |
|---|---|---|
| **W1 cache trust** | `cache.py` (rejects persisted hypotheses that carry proof/confirmation authority); `orchestrator_detect.py` (the `"owned-context-v2"` namespace hunk, left out of `64e09ed6`); `test_cache_hypothesis_reuse.py`. The read-side rejection is tested only in the untracked `test_engagement_atomic_passive.py`. | I02 |
| **W2 passive ownership / export** | `store.py` (stored coordinates, `original_severity`, observation history); `issues.py` (engagement-scoped issue identity, unavailable-proof marking); `report_generator.py`; `sarif_adapter.py`; `knowledge.py` and `agents/base_agent.py` (no external notes under a captured principal); `server.py` analyze-partition hunk; `data_maintenance.py` docstring; Burp `AnalysisModels.java` / `HarnessPanel.java` (engagement and captured-principal IDs) | I02 (Burp presentation: I16) |
| **W3 health contract** | `server.py` `/health` hunks (exact model-tag match, redacted URL, withheld backend error); Burp `HarnessClient.java` (degraded → model-unavailable) | I16 |
| **W4 label routing** | `validators/base.py` (`_snake_label`: spaced agent labels such as "Verbose Error" reach snake_case validator classes); `test_validator_routing.py`. **No backlog ticket tracks this work.** | I09 |
| **Docs** | `README.md`, `docs/README.md`, `docs/TESTING.md`, `docs/USER_MANUAL.md` point to the untracked remediation-loop docs; commit them together. `COMPETITIVE_LANDSCAPE.md` points to the untracked 2026-10-09 comparison. `CURRENT_STATE.md` is the handover. `IMPROVEMENT_BACKLOG.md` holds the pre-existing DET deferrals and observed-ID note plus these I01 notes. `docs/ARCH_RECONCILIATION_TRACKING.md` holds the I01 test-boundary split. | I01 |

**W2 grouping — owner decision 2026-10-17:** keep ONE shared pile per site by default (the
host-wide partition, today's behaviour). An explicit `engagement_id` is an optional named pile
for separation. The uncommitted W2 `server.py` hunk that defaulted `/analyze` to a fresh
`analyze:<uuid>` partition is therefore REJECTED: exclude it when W2 is split into commits.
Within a pile, the captured principal still isolates history (I02 batch B). A Burp field to
set the optional named pile belongs to I16.

**W2 unavailable-proof marking — adopted in I02 batch A (2026-10-19):** the idea from W2's
`issues.py` hunk (mark a pointer-only proof reference `availability: unavailable`) is now
committed in `8edf5a9`, together with store-level resolution of each confirmation's proof.
The remaining W2 `issues.py` hunks (engagement-scoped issue identity) are still uncommitted.
When W2 is split into commits, rebase its `issues.py` and `store.py` hunks on `8edf5a9`, and
drop the duplicate availability lines.

### Untracked files

| Group | Contents | Disposition |
|---|---|---|
| Candidate | `harness/test_discovery_spa_wildcards.py`, `docs/SPA_DISCOVERY_FIXES.md` | in the overlay |
| Plan of record | `docs/REMAINING_IMPLEMENTATION_PLAN_2026-10-17.md`, this file, `reviews/2026-10-17-project-assessment/` | commit as docs |
| Tests of committed code (pass on the candidate alone) | 18 `harness/test_*` modules: `captured_only_policy`, `captured_shapes_passive`, `data_lifecycle_callers`, `data_maintenance`, `deterministic_first`, `evidence_provenance_passive`, `idor_read_validator`, `objective_completion`, `objective_completion_wiring`, `race_email_validator`, `remediation_inference_budget`, `remediation_inference_usage`, `remediation_scope`, `remediation_sqlite_lifetime`, `remediation_tls`, `run_inference_ownership`, `ssti_readback_urls`, `unverified_priority_consistency` | Regression coverage that is missing from Git, so CI never runs it. Commit as tests only, separately from W1–W4 (I11). |
| Tests that need W1–W3 code | 10 modules: `core_export_parity_passive`, `engagement_atomic_passive`, `evidence_exports_passive`, `health_contract_passive`, `issue_identity_passive`, `job_status_passive`, `pairing_contract`, `privacy_contract`, `token_file_permissions`, `triage_policy_passive`. All fail on the candidate and pass on the mixed tree. | Commit with W1/W2 (I02) or W3 (I16). |
| Burp tests | `FindingPresentationTest`, `HarnessClient{Engagement,Failure,Pairing}Test` (no JDK run here) | with W2/W3 (I16) |
| W2 docs | `CAPTURED_*`, `CORE_EXPORT_CONTRACT`, `DATA_LIFECYCLE`, `HTTPS_TRUST_POLICY`, `ISSUE_IDENTITY`, `JOB_STATUS_RECOVERY`, `PAIRING`, `PASSIVE_*`, `PRIVACY_BOUNDARIES`, `RECONCILED_REMEDIATION_*`, `REMEDIATION_*`, `SCOPE_POLICY`. CURRENT_STATE already cites the register and release gates, but they are not in Git. | with W2 |
| Evaluation WIP | untracked `testing/` runners, labels, benchmarks and tests (`test_remediation_report_clock` is LB-FLAKE) | I12 (LB-FLAKE: I11) |
| Restricted | `testing/blind-target-2/*answerkey*`, `capture_answer_key_exchanges.py`, `testing/vulncorp-helpdesk/` | never read and never stage carelessly (AGENTS.md safeguard 1) |
| Historical | other `reviews/*` folders and `docs/*` dated reports | preserve; not candidate evidence |
| Runtime only | `.test-work/`, `.test-deps/`, `.tmp_lb2/`, `build/`, `burp-extension/{.gradle,build}/`, `harness/*.db.bak-*`, `review_test_output.txt`, `.agents/`, `.claude/`, `.worktrees/` | never commit |

## Canonical owners for open backlog items

The 31 unchecked headings and 4 partial (`[~]`) headings each get one owner. Where the
plan listed more than one ticket for an item, the owner is the ticket that closes its
remaining acceptance; the earlier ticket is a prerequisite.

| Owner | Backlog items |
|---|---|
| I04 | LB-CSRF-REPLAY |
| I05 | P1-10 `[~]`, PR-10 `[~]`, PR-11 `[~]`, NC-O1, NC-O2, NC-O3, SC-9 |
| I09 | DET-SQLI-POST, DET-JWT-DETECT (both re-scoped; see backlog notes); W4 label routing |
| I10 | BM-2 |
| I11 | LB-FLAKE |
| I12 | P1-3 |
| I13 | DET-SSRF, PR-13 `[~]` (live re-measure; I12 prerequisite), NC-O4, BM-3 |
| I14 | PR-B, PR-D, PR-E |
| I15 | P3-2, PR-C, SC-6, SC-14 |
| I16 | P1-5, P2-3, PR-A, NC-O5 (build half via I15) |
| Deferred | P3-3, ER-3, ER-5, SC-10, LB-6, LB-7, BM-1 (superseded by FR-4) |

ARCH residuals are tracked in `docs/ARCH_RECONCILIATION_TRACKING.md`: ARCH-1 and
ARCH-2 caller verification go to I03, and false-confirmation storage/export integration
goes to I02. LB-2's remaining acceptance goes to I06 and I07. Register tickets R15/R19/R20/R21/R25/R28 keep the
mapping given in the plan.

## I01 acceptance status

- Done: a frozen, reproducible candidate; a disposition for every working-tree change;
  one owner per open item; corrected stale tracker text (ARCH test boundaries, LB-2,
  DET-SQLI-POST, DET-JWT-DETECT).
- The candidate is committed as `ba080691` and not pushed; this document follows in its own
  docs commit.
- 16 of the 18 tests of committed code were committed in `1be5ed04`. CI (Python 3.14, clean
  checkout) then showed that `test_data_lifecycle_callers` and `test_unverified_priority_consistency`
  import the uncommitted `test_pairing_contract`. They are untracked again, so 14 remain committed.
  `test_captured_shapes_passive` and `test_data_maintenance` also stay with W2. Local runs had
  missed this because the venv's editable install resolves modules missing from a worktree from
  the main checkout. Leak-free runs now block that finder (see CURRENT_STATE).
- Not done: W1–W4 still need their own reviewed commits, and W2 needs the partition decision first. Untracked
  tests were classified by running each module on its own:
  `.test-work/i01-untracked-tests-vs-candidate.log` and
  `.test-work/i01-wip-dependent-tests-mixed-tree.log`. The 36 coverage-evidence gaps are not
  classified here; that work belongs to I11.
