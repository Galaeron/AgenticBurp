# Current state — 2026-10-26 (branch `codex/assessment-integration`)

## Checkout
- Integration worktree `.test-work/wt-assessment-integration`. The branch is based
  on `9866784` and carries the assessment-only port `b4bf1fb`, RV-T, RV-U and
  Ticket 5, followed by Tickets 1-7 (`d975bfc`, `e213f4b`), the review bound
  (`b116c42`) and the stage reservations (`bc87804`). Not pushed or merged.
- The main checkout (`reconciliation-backlog`, PR Galaeron/AgenticBurp#1) keeps
  uncommitted W1-W4 WIP; it is dispositioned in
  docs/I01_CANDIDATE_MANIFEST_2026-10-17.md. Do not touch it from here.
- Untracked here and never committed: `sitecustomize.py` (blocks the venv's
  editable-install leak) and `.test-tmp/`. Safe `harness/config.yaml` is
  unchanged; live settings live only in ignored config.local.yaml.
- Plan: docs/ACTIVE_ASSESSMENT_REPAIR_PLAN_2026-10-21.md (Tickets 1-8). Batch
  evidence and the handoff: `.test-work/assessment-integration-20261023/HANDOFF.md`.

## Verification
- `bc87804` (v7) passed on system Python 3.14 and venv 3.12:
  - precondition 74, smoke 147;
  - full 4196 harness + 440 evaluation (17 skipped) + 59 integrity;
  - source_changed []; inventory hash 149450c0…a169.
- Verify in an in-repo worktree with `PYTHONPATH=<worktree>` and the untracked
  `sitecustomize.py`. Windows Defender deletes `file_upload_agent.py` from
  worktrees under %TEMP%. CI runs Python 3.14.
- Java: `gradle clean test shadowJar` runs on the in-repo JDK 17
  (`.audit-external/toolchains/jdk17`), offline, with `GRADLE_RO_DEP_CACHE`
  pointing at `.audit-external/gradle-cache/caches`.
- Stop background runs by exact PID tree. TaskStop leaves orphaned processes.

## Live acceptance (Ticket 8, 2026-10-26)
- Target: owned `av-eval-js-daybreak-20261021`, 127.0.0.1:3002 only. Port 3000 is
  unrelated and was left alone.
- Model: local gemma4:latest for every stage; cloud selection off (the
  gemma4:31b-cloud quota is exhausted).
- Callback origin: http://host.docker.internal:38698. The exact token was recorded
  and the wrong-token control rejected.
- sqlmap ran only from the Docker image `harness/sqlmap:1.10.9`.
- Full run, job 383f0ebff8e8:
  - The job is terminal, but the assessment is INCOMPLETE: the review time bound
    left 155 captures unreviewed.
  - Funnel: discovered 12882, applicable 5022, queued 1343, attempted 1343,
    sent 89, conclusive 89.
  - Terminal reasons: incomplete_attempt 1254, unsupported_or_manual 3507.
  - Cost: 39,314 requests, 937 model calls (24 HTTP 500s), 9534.6 s.
  - Delivery: paged export verified by SHA256, and restart recovery returned
    identical bytes.
- Issues:
  - 617 raw findings; 164 ledger-confirmed proof instances; 158 proof-bound cases.
  - Strict vulnerabilities: 0, because every proof is legacy.
  - The replay audit of all 149 distinct confirmed claims (`replay_audit.py`, run
    against the owned target) confirmed 2 unique vulnerabilities:
    - SQL injection on the login email returns an admin token.
    - The JWT alg:none token is accepted on 10 routes.
  - The other claims: 24 hardening observations, 15 recon observations, 31 false
    positives, 52 not applicable, 12 not supported, 1 not reproduced and
    3 inconclusive.

## Open work (priority order)
1. Proof artifact ids. orchestrator_confirm's ProofRecord.from_validation_result
   callers pass no baseline/attack/control ids, so no proof can count as a
   vulnerability. The session "Link validator confirmations to stored exchanges"
   owns this.
2. csp_validator reports "no CSP header" even where one is sent, confirms CSP and
   framing claims on JSON responses, and confirms an XSS class from headers alone.
3. recon_validator confirms technology and parameter classes that its own result
   counts as 0.
4. sqlmap evidence is truncated to the banner, so parameter, technique and
   payload are lost. On the login route sqlmap gave a different answer each run.
5. Local-tool results fail to persist (139 records: csp, clickjacking and recon).
   Ollama returned 24 HTTP 500s. Capture review is serial, at 44-65 s per capture.
6. Coverage: 1254 incomplete attempts, mostly SESS-01/ATHZ-02/CRYP-04 cells whose
   validators decline them; the drive takes anonymous cells first;
   discovery_max_probes cannot be set through the investigate API.
7. harness/active_verification.py:143 falls back to llama3.1:8b (Burp validation
   endpoint only).
8. Still open from before this branch:
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

## Working rules
- Follow AGENTS.md. Never read answer keys, blind labels or blind-target
  implementations.
- Preserve prior edits. Never `git add -A`. Never install sqlmap on Windows.
- Record exact source identity, process ownership, commands and logs for every
  live run.
