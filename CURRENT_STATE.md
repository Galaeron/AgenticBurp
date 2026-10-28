# Current state — 2026-10-28 (branch `codex/assessment-integration`)

## Checkout
- Integration worktree `.test-work/wt-assessment-integration`. The branch is based
  on `9866784`. It carries the assessment-only port `b4bf1fb`, Tickets 1-8 through
  `bc87804` (v7), the repair batches through `9d656d2` (v8) and the iterative
  response view `3acd392`. Not pushed or merged.
- The main checkout (`reconciliation-backlog`, PR Galaeron/AgenticBurp#1) keeps
  uncommitted W1-W4 WIP; it is dispositioned in
  docs/I01_CANDIDATE_MANIFEST_2026-10-17.md. Do not touch it from here.
- Untracked here and never committed: `sitecustomize.py` (blocks the venv's
  editable-install leak) and `.test-tmp/`. Safe `harness/config.yaml` is
  unchanged; live settings live only in ignored config.local.yaml.
- Plans: docs/ACTIVE_ASSESSMENT_REPAIR_PLAN_2026-10-21.md (Tickets 1-8). Repair
  batches and owner notes: `.test-work/assessment-integration-20261023/
  repair-batch-notes.md`. Handoff: HANDOFF.md in that directory.

## Verification
- `9d656d2` (v8) gates passed on venv 3.12 and system 3.14
  (`integrated-v8-py312`/`-py314`, gates-v8.status). `3acd392` gates:
  `integrated-v9-*`, run_gates_v9.sh → gates-v9.status.
- Verify in an in-repo worktree with `PYTHONPATH=<worktree>` and the untracked
  `sitecustomize.py`. Windows Defender deletes `file_upload_agent.py` from
  worktrees under %TEMP%. CI runs Python 3.14.
- Java: `gradle clean test shadowJar` runs on the in-repo JDK 17
  (`.audit-external/toolchains/jdk17`), offline, with `GRADLE_RO_DEP_CACHE`
  pointing at `.audit-external/gradle-cache/caches`.
- Stop background runs by exact PID tree. TaskStop leaves orphaned processes.

## Live acceptance v8 (2026-10-28, live-v8-gemma4-full/RUN_STATUS.md)
- Target: owned `av-eval-js-daybreak-20261021`, 127.0.0.1:3002 only. Port 3000 is
  unrelated and was left alone. Model: local gemma4:latest for every stage; cloud
  off. Callback origin http://host.docker.internal:38698. sqlmap only from the
  Docker image `harness/sqlmap:1.10.9`.
- Job f2a78499593e: done in 11113.2 s. Export 10,192,182 B / 39 pages.
- The assessment is INCOMPLETE:
  - 5070 applicable checks; 110 executed.
  - Funnel: discovered 12882 → queued 1380 → sent 110.
  - Terminal reasons: unsupported_or_manual 3516, incomplete_attempt 1270,
    prerequisite_unmet 174.
- Cost: 31,793 requests; 1646 model calls (22 errors); sqlmap 76 runs, 830 s.
  Capture review takes 7051 s of the run.
- Against v7:
  - capture review left 0 captures unreviewed (v7: 155);
  - iterative duplicates are 17.5% (v7: 49.9%);
  - proofs are executed, with artifacts (v7: all legacy).
- Issues:
  - 648 raw findings; 49 confirmed proof instances; 20 vulnerabilities.
  - Replay audit (22 claims): jwt 17 confirmed, csp 2 hardening, 3 not audited,
    0 false positives (v7: 31).
  - All 20 vulnerabilities are one flaw, JWT alg:none accepted.
  - No SQLi confirmed. v7 confirmed login SQLi.

## Open work (priority order)
1. sqlmap login: it sent 191 requests to POST /rest/user/login and confirmed
   nothing. v7 confirmed that route, and in v7 the answer already varied between
   runs. Diagnose the request, identity and flags offline.
2. Proof/issue dedup (owner, 2026-10-28): one vulnerability gets one proof, keyed
   on host, mechanism, principal and check family. Other routes become affected
   locations. Today 44 jwt proofs yield 20 vulnerabilities, under mixed classes.
3. Coverage drive throughput: 110 of 1380 queued sent, 1270 incomplete attempts.
4. Redaction false positive: metric keys "csrf" and "auth" become
   [REDACTED-SECRET].
5. 3acd392 has had no live run yet. The live check is whether the iterative agent
   adapts to errors deep in a page.
6. harness/active_verification.py:143 falls back to llama3.1:8b (Burp validation
   endpoint only).
7. Still open from before this branch:
   - Code review 02 RV-K.
   - I05 batch D on `i05d-browser-credentials`, waiting for the owner's review.
   - I16 wiring: protected routes, ownership and `suggested_test`.
   - RV-O to RV-S residuals, listed in their `.test-work/rv-*-20261021/HANDOFF.md`.
   - docs/CODE_REVIEW_02_TRIAGE_2026-10-19.md "Status" is the index.

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
