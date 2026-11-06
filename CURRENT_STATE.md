# Current state — 2026-11-05 (branch `claude/dreamy-bassi-ebd97d`, base `5b03501` = PR #27 on main)

## Checkout
- `main`, `01-11` and `reconciliation-backlog` are one integration line. It merges
  PR #2 (`aacabb8`), the local integration tip `codex/experiment-lifecycle-repair`
  (`1e2c9f8`: assessment batches A-E, Tickets 1-8, the v8-v10 repairs, the architecture
  repair milestone and batches 01, 02, 04 and 08, and the AR follow-ups in
  IMPROVEMENT_BACKLOG.md), I05-D (`78ebfef`) and the brotli/mitmproxy update.
  `codex/t08-final` is recorded as superseded (content not taken).
- The main checkout's uncommitted W1-W4 WIP is on `main-checkout-snapshot-20261101`
  (`2c0cf7f`, base `f563730`), NOT merged. About 70 of its files exist nowhere else:
  W1-W4 code, 10 tests that need it and 27 never-committed docs. Split and review it per
  docs/I01_CANDIDATE_MANIFEST_2026-10-17.md; its `/analyze` hunk already keeps the shared pile.
- Plans: docs/ACTIVE_ASSESSMENT_REPAIR_PLAN_2026-10-21.md (Tickets 1-8). Architecture
  repair: `.test-work/assessment-integration-20261023/architecture-repair/` (main checkout).

## Model context window (this branch, not merged)
- r3 (job 0574e29a0799) left `ollama.num_ctx` unset, so Ollama 0.40.13 ran at n_ctx 4096
  and silently cut 88 prompts (largest 8,118 tokens; capture-review/analysis_pipeline shape)
  to about half the window. **Operator fix:** `ollama.num_ctx: 16384` in
  harness/config.local.yaml, or a cloud model. Defaults unchanged; no `num_ctx: auto`
  (a per-call window reloads the model and can spill VRAM).
- `harness/ollama_client.py` checks each local call against num_ctx or the cached `/api/ps`
  context_length: the prompt fills the window, >5 chars/token at half the window or more,
  prompt plus reply fill it, or done_reason length. A cut raises
  `OllamaContextTruncatedError`, counts as `context_truncated` (model metrics, job summary)
  and adds a `model_context` run error (degraded). `-cloud`/`:cloud` models are never checked.
- `context_preflight` at engagement start warns (instrumentation, manifest, job summary,
  feed) when a local window is below the largest prompt (measured, else 8,118 estimate).
- Breaker: empty body, truncation and 429 no longer count; a 429 honours Retry-After up to
  30 s, else fails fast. Other 4xx still count. Tests: harness/test_ollama_context_window.py.

## Verification
- This branch, 2026-11-05, system Python 3.14: smoke exit 0 (149); the touched modules'
  tests 193 OK. `full` was not run here; CI runs it.
- `main` `a3681c5`, 2026-11-01 (Linux, Python 3.13, Playwright 1.63.0): precondition 74 OK;
  full exit 0 (harness 5014 / 8 skips, native 38, evaluation 440 / 18 skips, integrity 59;
  25 coverage gaps). Java 379 tests, 0 failures. CI's full job installs Playwright + Chromium.
- v8, v9 and v10c gates passed on venv 3.12 and system 3.14 (gates-v8/v9/v10c.status).
  `integrated-v10-*` is invalid because of concurrent edits.
- Verify in an in-repo worktree with `PYTHONPATH=<worktree>` and the untracked
  `sitecustomize.py`. Windows Defender deletes `file_upload_agent.py` from
  worktrees under %TEMP%. CI runs Python 3.14.
- Java: `gradle clean test shadowJar` runs on the in-repo JDK 17
  (`.audit-external/toolchains/jdk17`), offline, with `GRADLE_RO_DEP_CACHE`
  pointing at `.audit-external/gradle-cache/caches`.
- Stop background runs by exact PID tree. TaskStop leaves orphaned processes.

## Live acceptance v8 (2026-10-28, live-v8-gemma4-full/RUN_STATUS.md)
- Owned `av-eval-js-daybreak-20261021` on 127.0.0.1:3002 only; local gemma4 for every
  stage; sqlmap only from Docker `harness/sqlmap:1.10.9`. Job f2a78499593e, 11113 s.
- INCOMPLETE: 5070 applicable checks, 110 executed (discovered 12882, queued 1380, sent 110;
  3516 unsupported/manual, 1270 incomplete). 31,793 requests, 1646 model calls; capture
  review 7051 s.
- 49 confirmed proof instances, 20 vulnerabilities, all one flaw (JWT alg:none accepted).
  Replay audit: 0 false positives (v7: 31). No SQLi confirmed (v7 confirmed login SQLi).

## Open work (priority order)
1. Live run v10: full shape, 8 h, no request cap. Follow RUN_INSTRUCTIONS-v10-full.md
   in the batch directory. It checks 7203a44 (v8's missed login SQLi), 1370b6f and 3acd392
   (item 6). Set `ollama.num_ctx: 16384` locally first (see "Model context window").
2. Capture-review prompt budget, a separate task: shrink the prompts that overflowed in r3.
3. Proof/issue dedup (owner, 2026-10-28): one vulnerability gets one proof, keyed
   on host, mechanism, principal and check family. Other routes become affected
   locations. Today 44 jwt proofs yield 20 vulnerabilities, under mixed classes.
4. Coverage drive throughput: 110 of 1380 queued sent, 1270 incomplete attempts.
5. Redaction false positive: fixed in `dec3828` (branch `claude/arid-redaction-6b6000`,
   not merged). Still open: `redact_headers` has no X-CSRF-Token entry.
6. 3acd392 has had no live run yet. The live check is whether the iterative agent
   adapts to errors deep in a page.
7. harness/active_verification.py:143 falls back to llama3.1:8b (Burp validation only).
8. Still open from before:
   - Code review 02 RV-K.
   - I16 wiring: protected routes, ownership and `suggested_test`.
   - RV-O to RV-S residuals (`.test-work/rv-*-20261021/HANDOFF.md`).
   - The index is the "Status" section of docs/CODE_REVIEW_02_TRIAGE_2026-10-19.md.

## Owner decisions in force (detail: git history of this file, the triage docs)
- `/analyze`: one shared pile per site; `engagement_id` names a pile (W2
  `analyze:<uuid>` hunk rejected). Stored SSTI opt-in (`{ssti: 2}` ceiling).
- CSRF on real targets is manual-check only. CORS reflection without credentials
  confirms with a note. An XSS dialog showing the computed value confirms. An MFA
  step-up redirect is not a denial.
- Missing auth confirms only on `authz.protected_paths`; BOLA/BFLA only against
  `authz.owners`, otherwise a labelled LEAD. Sensitive-file severity by class.
- `privacy.external_lookups` true by default (passive-only: false); connect-time
  pin on; external tools via the counting proxy.
- Ticket 8 authorization (2026-10-22): full local Juice Shop on port 3002 only.
- One proof per vulnerability (2026-10-28), not one per route.

## Working rules
- Follow AGENTS.md. Never read answer keys, blind labels or blind-target
  implementations.
- Preserve prior edits. Never `git add -A`. Never install sqlmap on Windows.
- Record exact source identity, process ownership, commands and logs for every
  live run.
