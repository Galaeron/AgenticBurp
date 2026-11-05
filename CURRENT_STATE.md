# Current state — 2026-11-05 (branch `claude/adoring-khorana-c5adaa`, base `main` `5b035019`)

## This branch (not pushed)
- `dbb0dab7` WSTG-CONF-02 and `93f4b697` WSTG-ERRH-01 get passive coverage adapters
  (`security_headers`, `error_handling`). These two checks were 582 of the 2,049
  `check_adapter_missing` cells in Juice Shop r3 (job 0574e29a0799). Passive legs run first,
  spend no `coverage_leg_budget`, and key their verdict on the captured response. A capture
  a passive leg skips no longer hides another capture's verdict. Coverage confirmations take
  the validator's severity instead of a hardcoded "high".
- The decision for each remaining unbound check (CONF-06, CONF-07, INFO-02, INFO-05,
  SESS-01, ATHN-01) is in docs/COVERAGE_ADAPTERS.md. CONF-07 belongs to PR #29
  (`claude/run-until-deadline`, unmerged).
- Not yet live-checked: the next Juice Shop run should show CONF-02/ERRH-01 cells as
  conclusive or `leg_precondition_unmet`, never `check_adapter_missing`.
- `d4bb2fa6`: `legs_driven` / `cases_driven` count budgeted sends only; the passive
  judgements are `passive_legs_judged` in the coverage report.

## Checkout
- `main` merges PR #2, the local integration tip `codex/experiment-lifecycle-repair`
  (`1e2c9f8`), I05-D (`78ebfef`), the brotli/mitmproxy update and PRs #25/#27.
  `codex/t08-final` is superseded (content not taken).
- The main checkout's uncommitted W1-W4 WIP is on `main-checkout-snapshot-20261101`
  (`2c0cf7f`, base `f563730`), NOT merged. About 70 of its files exist nowhere else.
  Split and review it per docs/I01_CANDIDATE_MANIFEST_2026-10-17.md.
- Plans: docs/ACTIVE_ASSESSMENT_REPAIR_PLAN_2026-10-21.md (Tickets 1-8). Architecture
  repair: `.test-work/assessment-integration-20261023/architecture-repair/` (main checkout).

## Verification
- This branch, `d4bb2fa6`, Windows, system Python 3.14: smoke exit 0 (149 tests); full
  exit 0 (harness 5391, native 38, evaluation 451 / 17 skips, integrity 59). Java not rerun.
- `main` 2026-11-01 (Linux, Python 3.13, Playwright 1.63.0 + Chromium), `a3681c5`: full
  exit 0 (harness 5014 / 8 skips, native 38, evaluation 440 / 18 skips, integrity 59).
  Java 379 tests, 0 failures. CI's full job installs Playwright + Chromium.
- Verify in an in-repo worktree with `PYTHONPATH=<worktree>`. Windows Defender deletes
  `file_upload_agent.py` from worktrees under %TEMP%. CI runs Python 3.14.
- Java: `gradle clean test shadowJar` on the in-repo JDK 17 (`.audit-external/toolchains/jdk17`),
  offline, `GRADLE_RO_DEP_CACHE` at `.audit-external/gradle-cache/caches`.
- Stop background runs by exact PID tree. TaskStop leaves orphaned processes.

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
1. Live run v10: full shape, 8 h, no request cap (RUN_INSTRUCTIONS-v10-full.md in the
   batch directory). It live-checks 7203a44 (v8 missed login SQLi), 1370b6f and 3acd392.
2. Proof/issue dedup (owner, 2026-10-28): one vulnerability, one proof, keyed on host,
   mechanism, principal and check family; other routes become affected locations.
3. Coverage drive throughput: 110 of 1380 queued sent, 1270 incomplete attempts.
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
