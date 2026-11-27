# Current state — 2026-11-27 (earlier runs and merges: git history of this file)

## Branch and base
- `ccr-66c758a5-7lmduz` = main `0fb8cd5` (PR #30) + four batches from a read of ARTEX
  (plan `.test-work/artex-borrow-20261126/PLAN.md`; each batch's `HANDOFF.md` beside it). No PR yet.
  - parallel-drive (`beeb71c`): `engagement.coverage_drive_workers` (default 1 = the former
    sequential loop). Timing/state/write/browser legs and non-read methods run alone; one shared
    cell per identity. Two session-refresh race fixes in `TargetTransport` apply at any count.
  - click-explore (`58367cc`): `driver_capture.click_explore` (off; passive forces off). Bounded
    clicks per view; denylisted or in-form controls never clicked; click writes held, never sent;
    click recipes reach the stored_xss read-back.
  - policy-refusal (`b9f1b35`): the iterative agent shows harness refusals to the model as
    policy (`harness/policy_refusal.py`), full once per category, short after; raw reasons,
    counters and stop reasons unchanged; target responses never framed.
  - evidence-integrity (`f11adaf`): `store.read_evidence_blob` re-hashes on every read;
    `get_evidence_blob` returns None on a mismatch; app map and leads name unresolved evidence.
- main holds the r7-r10 chain, the r10 gap fixes, SKL-1/2/5, WG-1/2/3 and PR #30 (oracle-run
  leg fixes, write safety, WG-2 item 5, time-fair coverage drive `dcedade9`, crawl-check fixes).
- Catalog: 62 rows on current WSTG ids (harness/wstg_ids.py); v4.2 ids load through
  LEGACY_CHECK_ID_ALIASES; data stamped `check_id_scheme: 2`; SESS-05 drives csrf (open work 5).
- Off or inert by default: `review_overlap`, `write_integrity` (needs `validators.active_enabled`
  and `allow_mutating_replay`, docs/WRITE_CHECKS.md), route probes, file uploads, discovery
  recursion, click exploration; `coverage_drive_workers: 1`.
- Not on main: `feat/scoreboard-scorer-20261116`; `fcb96d62` (rejected); old/superseded others.

## Checkout (owner's Windows machine)
- Main checkout on `reconciliation-backlog`, ~77 uncommitted files of older work. Leave them.
- W1-W4 WIP `main-checkout-snapshot-20261101` (`2c0cf7f`), NOT merged; ~70 files exist nowhere
  else. Split it per docs/I01_CANDIDATE_MANIFEST_2026-10-17.md.

## Verification
- This branch at `b9f1b35`, 2026-11-27, cloud container, Python 3.13.18 venv
  (harness/requirements.lock + playwright 1.63.0, `PLAYWRIGHT_BROWSERS_PATH=/opt/pw-browsers`):
  full run 1 exit 1 = harness 6756 with 1 failure, `test_idle_review` ...
  `cancelled_mid_sweep_leaves_no_review_running` (engagement returned a result); native 38,
  evaluation 452 / 18 skips, integrity 59 OK. Not reproduced in 22 reruns (alone, per batch
  worktree, under CPU stress on this branch and on base, and an ordered replay of the 191
  modules up to it, 3021 OK). Full run 2 exit 0 (harness 6756 / 8 skips, native 38, eval 452).
- Base `0fb8cd5`, same container, same day: full exit 0 (harness 6676 / 8 skips, native 38,
  evaluation 452 / 18 skips, integrity 59). Per-batch targeted counts: each batch HANDOFF.
- Earlier: `4b3a7062`, `9fab7470` full exit 0 (Python 3.14.7); PR #30 full in CI. Java `a3681c5`
  (2026-11-01, Linux): 379 tests, 0 failures; no Java change since.
- Verify in an in-repo worktree, `PYTHONPATH=<worktree>`. On the owner's machine use system
  Python (not `.venv-rationalisation`); Defender deletes `file_upload_agent.py` under %TEMP%.
- Java: `gradle clean test shadowJar` on the in-repo JDK 17 (`.audit-external/toolchains/jdk17`),
  offline, `GRADLE_RO_DEP_CACHE` at `.audit-external/gradle-cache/caches`.

## Model backend
- Local Ollama needs `ollama.num_ctx: 16384` in harness/config.local.yaml; a cut prompt
  raises `OllamaContextTruncatedError`, and `context_preflight` warns at start.
- `ollama.api: "openai"` sends model calls to llama-server (OpenAI-compatible) at `base_url`.

## Live runs (owned Juice Shop on 127.0.0.1:3002 only; sqlmap only from `harness/sqlmap:1.10.9`)
- r10 (`8727c42d`, gpt-oss-20b): 23.1 h, 236,966 requests, 138 of 1,181 findings confirmed,
  912 legs unrun at budget; 13/116 solved; no XSS confirmed (`.test-work/juice-shop-24h-20261111-r10/`).
- Oracle run 2026-11-14: 31 confirmed, 23 solved. Crawl check 2026-11-16. No live run of the batches.

## Open work (priority order)
0. Owner: may real runs set `validators.write_integrity.allow_unrestorable_self_service_creates`?
   Click exploration now exists (off): a live run must show whether the product card is clicked,
   the reviews call is recorded and a review stored XSS confirms through its recipe.
   Default-credential guessing (ATHN-02) was declined in the backlog.
1. From the WSTG review: INJT-14 has no row, ATHN-04 has no bypass leg, WG-4 needs an owner
   decision, WG-5 needs a mail sink (IMPROVEMENT_BACKLOG.md WG-*).
2. A full Juice Shop run on this branch, plus `coverage_drive_workers: 4` against 1 at the same
   budget and deadline. r10 leftovers: compare result.json with r9; find the check that sent
   ~10k/h to socket.io polling at h4-5; cross_identity still repeats across findings.
3. Owner review of `8040dbf5` (policy reads a decoded NUL both ways, on main).
4. r6 follow-ups (briefs T1-T6 in `.test-work/r5-r6-detection-analysis-20261109/ANALYSIS.md`) and
   review leftovers (sqlmap rows keep confirmed=True for stop logic; a resumed journal can skip
   the query probe; skipped keys advance the lower-tier rotation).
5. Owner check: SESS-05 drives the csrf leg (0.4, no browser PoC). Keep it or set it to manual.
6. Proof/issue dedup (owner, 2026-10-28): one vulnerability, one proof, keyed on host, mechanism,
   principal and check family; other routes become affected locations.
7. Drive throughput: the worker pool measured 9.2 -> 23.9 cells/s at 4 workers offline (50 ms
   latency, throttle off); a set throttle caps it. Open: cross_identity can share one session's
   jar across two cells; the per-endpoint time share is soft above 1 worker; the global throttle
   lock binds to the first event loop; request-level legs never credit per-parameter siblings.
8. `redact_headers` lacks X-CSRF-Token; review 02 residuals: docs/CODE_REVIEW_02_TRIAGE_2026-10-19.md.
9. Owner questions from the batches (details in their HANDOFFs): iterative budget/cancel/session
   refusals count as target distress (3 stop a probe); split Burp `blocked` into harness/target;
   `policy_refusal_repeats` in run totals; held click writes as capture templates, denylist
   breadth, clicks in recrawl rounds; a run-manifest evidence digest; `hash_mismatch` vs
   `unavailable` in the observation APIs.

## Owner decisions in force (detail: git history of this file, the triage docs)
- `/analyze`: one shared pile per site; `engagement_id` names a pile. Stored SSTI opt-in.
- CSRF on real targets is manual-check only. CORS reflection without credentials confirms with
  a note. An XSS dialog showing the computed value confirms. An MFA step-up is not a denial.
- Missing auth confirms only on `authz.protected_paths`; BOLA/BFLA only against `authz.owners`,
  otherwise a labelled LEAD. Sensitive-file severity by class.
- `privacy.external_lookups` true by default (passive-only: false); connect-time pin on.
- Ticket 8 (2026-10-22): full local Juice Shop on port 3002 only. One proof per vulnerability.
- No silent LLM fallback (llm_provider.py); ARTEX-style failover was not adopted.

## Working rules
- Follow AGENTS.md. Never read answer keys, blind labels or blind-target code.
- Preserve prior edits. Never `git add -A`. Never install sqlmap on Windows.
- Record source identity, process ownership, commands and logs per live run; kill by PID tree.
