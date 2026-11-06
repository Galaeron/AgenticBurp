# Current state — 2026-11-06 (`main`, after the 2026-11-06 integration merge)

## Landed on main 2026-11-06 (integration branch `integrate/main-2026-11-06`)
- PR #28 (request budget: SPA soft-404 pruning, sqlmap rerun collapse + verdicts, proof
  reasons, opt-in ffuf) and PR #29 (retry rounds, deadline-bounded legs, full discovery).
- PR #29 gaps: a failed critique marks its capture for a retry round; the coverage matrix
  is refreshed after retry rounds (`coverage_tracker.refresh_after_retry_rounds`).
- Server-error follow-up (`harness/server_errors.py`, `engagement.server_errors`): the 5xx
  answers to the run's own sends are scanned (passive); a stack trace is a confirmed
  `verbose_error_disclosure`, a database error an sql/nosql lead. Lead dispatch
  (`max_lead_confirmations`) defaults to 0. r5 drew 3,779 unexamined 5xx.
- NoSQL findings reach the nosql leg, never sqlmap (`_confirm` in orchestrator_chain.py).
- Ollama context-window truncation guard (`ef513daf`, section below); in-agent retry of a
  transient model error (`29930dbd`); capture-review prompts fit the context budget
  (`d6e3dd10`).
- Passive coverage adapters for WSTG-CONF-02 (`security_headers`) and WSTG-ERRH-01
  (`error_handling`): they were 582 of r3's 2,049 `check_adapter_missing` cells. Passive
  legs spend no `coverage_leg_budget`; `legs_driven` / `cases_driven` count budgeted sends
  only (`passive_legs_judged` reports the rest). Coverage confirmations take the
  validator's severity. Remaining unbound checks: docs/COVERAGE_ADAPTERS.md.
- Per-parameter coverage dispatch (open redirect, SSRF, reflected XSS, path traversal) and
  attribution; a mutating-ceiling cut ends a path-traversal leg instead of reading clean.
- Not yet live-checked: all of the above. Next Juice Shop run should show CONF-02/ERRH-01
  cells conclusive or `leg_precondition_unmet`, and a `server_errors` report.

## Checkout
- `main` merges PR #2, the local integration tip `codex/experiment-lifecycle-repair`
  (`1e2c9f8`), I05-D (`78ebfef`), the brotli/mitmproxy update and PRs #25/#27.
  `codex/t08-final` is superseded (content not taken).
- The main checkout's uncommitted W1-W4 WIP is on `main-checkout-snapshot-20261101`
  (`2c0cf7f`, base `f563730`), NOT merged. About 70 of its files exist nowhere else.
  Split and review it per docs/I01_CANDIDATE_MANIFEST_2026-10-17.md.
- Plans: docs/ACTIVE_ASSESSMENT_REPAIR_PLAN_2026-10-21.md (Tickets 1-8). Architecture
  repair: `.test-work/assessment-integration-20261023/architecture-repair/` (main checkout).

## Model context window (merged 2026-11-06)
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
- `integrate/main-2026-11-06` `768939b6`, 2026-11-06, Windows, system Python 3.14: full
  exit 0 (harness 5614, native 38, evaluation 451 / 17 skips, integrity 59). The first
  full run failed (22 failures, 47 errors): a semantic merge conflict left sqlmap's
  `_validate_request` without PR #28's `light` record (NameError), fixed in `1f32f775`.
  Smoke and per-module tests had passed. Java not rerun.
- `claude/run-until-deadline` `bfea370d`, 2026-11-06, Windows, system Python 3.14: smoke
  exit 0 (149); full exit 0 (harness 5434, native 38, evaluation 451 / 17 skips,
  integrity 59). Java not rerun.
- `main` 2026-11-01 (Linux, Python 3.13, Playwright 1.63.0 + Chromium), `a3681c5`: full
  exit 0 (harness 5014 / 8 skips, native 38, evaluation 440 / 18 skips, integrity 59).
  Java 379 tests, 0 failures. CI's full job installs Playwright + Chromium.
- Verify in an in-repo worktree with `PYTHONPATH=<worktree>`. Windows Defender deletes
  `file_upload_agent.py` from worktrees under %TEMP%. CI runs Python 3.14.
- Java: `gradle clean test shadowJar` on the in-repo JDK 17 (`.audit-external/toolchains/jdk17`),
  offline, `GRADLE_RO_DEP_CACHE` at `.audit-external/gradle-cache/caches`.
- Stop background runs by exact PID tree. TaskStop leaves orphaned processes.

## Live runs 2026-11-05/06 (Juice Shop, 10 h, gemma4:latest, num_ctx 16384)
- r4 (job 2e904173dac3): target lost at T+88 min (Docker Desktop died with a tool shell).
- r5 (job ec2d4f39326d, local merge `72b4c1d1` = PR #28 + #29 + `ef513daf` + `29930dbd`):
  `done` on its own after 9.5 h, 160,937 requests, 2,226 model calls. 249 raw findings,
  89 proof-bound cases in 13 vulnerability groups, which are 3 flaws (jwt alg:none, basket /
  BasketItems IDOR, login-email boolean SQLi), plus missing CSP (hardening). Coverage:
  4,934 applicable, 635 executed, 573 conclusive; `check_adapter_missing` 2,797,
  `leg_precondition_unmet` 713; time budget left 101 worklist nodes and 365 captures
  unreached (r3: 250 executed, 262 budget-exhausted). Gaps found: confident findings
  routed to validators that cannot test them; the sqlmap login proof not bound to its
  finding and review downgrading proven jwt/idor findings; writes never sent; /ftp,
  /metrics, JSONP whoami, /redirect reached but unchecked; ~28k requests on
  /.well-known/csaf/*; 5xx unexamined (fixed above). Evidence (no token or *-private
  files): `AgenticVibe-archive/live-runs-2026-11-05/`.

## Live acceptance v8 (2026-10-28, live-v8-gemma4-full/RUN_STATUS.md)
- Owned `av-eval-js-daybreak-20261021` on 127.0.0.1:3002 only (port 3000 is unrelated).
  Local gemma4:latest for every stage, cloud off. sqlmap only from the Docker image
  `harness/sqlmap:1.10.9`. Job f2a78499593e, 11113.2 s.
- INCOMPLETE: 5070 applicable checks, 110 executed (discovered 12882 → queued 1380 →
  sent 110). Terminal reasons: unsupported_or_manual 3516, incomplete_attempt 1270,
  prerequisite_unmet 174. 31,793 requests; 1646 model calls; capture review 7051 s.
- 648 raw findings, 49 confirmed proof instances, 20 vulnerabilities, all one flaw (JWT
  alg:none). Replay audit: 0 false positives. No SQLi confirmed (v7 confirmed login SQLi).

## Open work (priority order)
1. Fix the r5 gaps (routing, binding, coverage; Live runs above), then a new live run to
   check them and everything that landed 2026-11-06.
2. Proof/issue dedup (owner, 2026-10-28): one vulnerability, one proof, keyed on host,
   mechanism, principal and check family; other routes become affected locations.
3. Coverage drive throughput: 110 of 1380 queued sent, 1270 incomplete attempts (v8).
4. Redaction false positive fixed in `dec3828` (branch `claude/arid-redaction-6b6000`,
   not merged). Open: `redact_headers` has no X-CSRF-Token entry.
5. 3acd392 has had no live run: does the iterative agent adapt to errors deep in a page?
6. harness/active_verification.py:143 falls back to llama3.1:8b (Burp validation only).
7. Coverage catalog (owner decision): ids/names diverge from WSTG v4.2. Genuine ATHN-01
   (credentials over plain HTTP) has a sound passive oracle; see docs/COVERAGE_ADAPTERS.md.
   Opt-in active legs could bind CONF-06 (TRACE echo) and provoke errors for ERRH-01.
8. Still open from before: code review 02 RV-K; I16 wiring (protected routes, ownership,
   `suggested_test`); RV-O to RV-S residuals in `.test-work/rv-*-20261021/HANDOFF.md`;
   docs/CODE_REVIEW_02_TRIAGE_2026-10-19.md "Status" is the index.
9. `reconciliation-backlog` (local, 3 unpushed commits of 2026-11-02 under the main
   checkout's uncommitted edits) was not merged: its fresh `/analyze` engagement_id
   conflicts with the owner decision below.

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
