# Current state — 2026-11-23 (earlier states: git history of this file)

## Branch and base
- Work lives on the local integration branch `integrate/audit-fixes-20261120` (NOT pushed):
  PR #32's tip `d893ed0f` (CI green, not merged; merging needs the owner's OK) plus the 12
  principal-audit code batches (a1 to d3), the model-call pacer config (O11) and four test fixes,
  tip `6fe5538c`. The e1 docs/state commits (DOC-1, DOC-3, DOC-4, DOC-5, OPS-4, STATE-2, STATE-4
  and their follow-ups) sit on top of it.
- Audit and program: `reviews/2026-11-19-principal-audit/REMEDIATION_BACKLOG.md`;
  `.test-work/audit-fix-20261120/PROGRAM.md` and one `<batch>/HANDOFF.md` per batch (main checkout,
  untracked). What changed, by ID: [CHANGELOG.md](CHANGELOG.md) (Unreleased).
- #32 already holds the r11 fixes (R11-1 to R11-10) on top of `main` = `0fb8cd5a` (PR #30,
  2026-11-17). In neither: `feat/scoreboard-scorer-20261116`, `fcb96d62` (rejected), `WorkingSunday`,
  `main-checkout-snapshot-20261101` (about 70 files nowhere else; split it per
  docs/I01_CANDIDATE_MANIFEST_2026-10-17.md) and the `origin/vibe/*` branches.
- The main checkout (`reconciliation-backlog`) has many uncommitted files, including its own
  `NOTES.md`, `CLAUDE.md`, `AGENTS.md` and `CURRENT_STATE.md`. Leave them; reconcile on merge.

## What the audit batches changed that a new agent must know
- Every route that sends target traffic needs `validators.active_enabled` (a1); standalone probes
  fail closed on an empty scope (a1, d2). Model-supplied headers cannot set Host, framing or
  credentials (d1). A per-origin throttle and `runs.max_requests: 100000` bound a run (b1).
- `ollama.allow_cloud_models: false` refuses cloud models (a3). Prompts fit the window the server
  reports, else `prompt_budget.unknown_context_tokens` 4096 (a3). `ollama.rate_limit` paces model
  calls: 10 burst, 10 a minute, 300 s wait bound (O11). `/health` is liveness; readiness is
  `/health/details` with the token (a3).
- A finding's identity and class come from the harness, not the model (c1). Only a held control
  refutes (a2). Counts carry units: occurrences, issues, root causes (c2). Burp-plane results need
  the nonce from `POST /test-plans/{id}/dispatch` (c3); the jar and harness upgrade together.
- Ledger: the `HS-*` safety properties and five more live pairs are registered (d3);
  `coverage_manifest --check` blocks on them. Docs: [LIMITATIONS](docs/LIMITATIONS.md).
- Local Ollama needs `ollama.num_ctx: 16384` in harness/config.local.yaml (a call that did not fit is
  discarded and the run is `degraded`); `ollama.api: "openai"` targets llama-server (USER_MANUAL section 1).
- Session handoff is `NOTES.md` (STATE-2). The backlog's open list is generated from its archive
  (`tools/backlog_index.py`). What is redacted before a model call: USER_MANUAL section 5.

## Verification (system Python 3.14.7; CI runs 3.14)
- This branch (e1), 2026-11-23: smoke and `harness.test_orchestrator_precondition` and the new
  doc checks: see the e1 HANDOFF for counts. The full suite was not run locally (CI runs it once on the PR).
- Integration tip `6fe5538c`: a gate run (smoke, precondition, per-module sweep, pytest-native, Java)
  was in progress when this was written; its result is not recorded here. Per-batch gates are in the
  HANDOFFs and are reported, not re-run: smoke 182 to 241, precondition 74; Java 417 tests, 0 failures
  (c3, JDK 17, Gradle 8.7 offline). Historical: PR #30 full suite green on 3.14 (CI).
- Not verified: the clean-machine first-run walk-through (DOC-3), the CI `dependency-audit-blocking`
  job, `.[dev]` in a clean venv, loading the jar in Burp, TOK-3's live yield over five repeats.
- Verify in an in-repo worktree, `PYTHONPATH=<worktree>`, system Python (not `.venv-rationalisation`);
  Defender deletes `file_upload_agent.py` under %TEMP%. Java: in `burp-extension/`, `gradle
  --gradle-user-home <main>/.audit-external/gradle-cache --offline --no-daemon clean test shadowJar`,
  `JAVA_HOME` at `.audit-external/toolchains/jdk17`.

## Live runs (owned Juice Shop on 127.0.0.1:3002 only; sqlmap only from `harness/sqlmap:1.10.9`)
- r11 (job d157da1bd9fd on `0fb8cd5a`, gpt-oss-20b, :3002, 2026-11-17/18): 23.1 h, 282,316 requests,
  5,242 model calls (19.9 M tokens); 377 of 1,154 findings proof-bound confirmed. By c2's root-cause
  rules (scratch copy of the store): 117 vulnerability groups are 18 root causes. r10 (`8727c42d`):
  138 of 1,181 confirmed, 13 of 116 solved. Files (main checkout): `.test-work/juice-shop-24h-20261117-r11/`.
- 2026-11-14 oracle run (each leg aimed at its endpoint by hand): 22 of 60 confirmed, 20 of 98 solved.

## Open work (priority order)
0. Owner: push `integrate/audit-fixes-20261120` and open one PR (CI runs the full suite); merge
   #32; STATE-1 (decide the ~40 local-only files, move the root to `main`). Unscheduled in PROGRAM.md:
   STATE-3, GAP-1, GAP-3, TOK-1, OPS-5, ARC-9, ARC-13, STRAT-1 to STRAT-5.
1. Decisions the audit batches left (each HANDOFF has its own): validators' no-run fallbacks and the no-run
   `GatedAsyncClient` (d2); the library-only modules of ARC-10 (wire in, move or delete); `fail_open_mode:
   curated` needs a GAP-1 recall comparison (b2); pacer defaults (O11); the Burp plane's request budget
   (c3); smoke policy for slow loopback modules (d3); tag audit `needs: full` and an allowlist lifetime (b3).
2. WSTG review: INJT-14 has no row, ATHN-04 no bypass leg, WG-4 needs an owner decision, WG-5 a mail
   sink (backlog WG-*). R11-7b (live trial) remains; R11-8 is still `[ ]` though its sub-items are done.
3. Owner review of `8040dbf5` (policy reads a decoded NUL both ways). r6 follow-ups (coverage-drive time, end-of-run accounting, passive proofs with artifact ids; briefs
   T1-T6 in `.test-work/r5-r6-detection-analysis-20261109/ANALYSIS.md`); sqlmap rows keep confirmed=True
   for stop logic; a resumed journal can skip the query probe; skipped keys advance the lower-tier rotation.
4. Owner: SESS-05 drives the csrf leg (0.4 observation without a browser PoC; replays need
   `allow_mutating_replay`). Keep it, or set the row back to manual.
5. Proof/issue dedup (owner, 2026-10-28): one vulnerability, one proof, keyed on host, mechanism,
   principal and check family; other routes become affected locations. c2's root causes are the counting half.
6. Coverage drive: request-level legs never credit per-parameter siblings; registry-covered copies with
   0 sends never conclude. `redact_headers` has no X-CSRF-Token entry; `harness/active_verification.py`
   falls back to llama3.1:8b. Code review 02 residuals: docs/CODE_REVIEW_02_TRIAGE_2026-10-19.md.

## Owner decisions in force (detail: the triage docs, the batch HANDOFFs)
- `/analyze`: one shared pile per site; `engagement_id` names a pile. Stored SSTI opt-in (`{ssti: 2}`).
- CSRF on real targets is manual-check only. CORS reflection without credentials confirms with a
  note. An XSS dialog showing the computed value confirms. An MFA step-up redirect is not a denial.
- Missing auth confirms only on `authz.protected_paths`; BOLA/BFLA only against `authz.owners`,
  otherwise a labelled LEAD. Sensitive-file severity by class.
- `privacy.external_lookups` true by default (passive-only: false); connect-time pin on; external
  tools via the counting proxy. Ticket 8 (2026-10-22): full local Juice Shop on port 3002 only.
- One proof per vulnerability (2026-10-28). r11 backlog (2026-11-19): business-flow checks may drive
  multi-step writes on run-owned accounts, restoring where possible; a session JWT with no `exp`, a
  failed-login burst and a password change plus restore may confirm; challenge echo, recovery-lookup
  enumeration and reset-answer guessing confirm by default; credential substitution is allowed inside
  the coverage drive (`engagement.coverage_identity_substitution`, default on). Writes and bursts stay
  behind `active_enabled`, `allow_mutating_replay`, the per-check ceilings and `max_burst_size`.
- Audit batches: no `discovery_enabled` flag (a1); `allow_cloud_models` false, fallback 4096 (a3);
  `runs.max_requests` 100000 (b1); sqlmap "not injectable" stays unverified (a2).

## Working rules
- Follow AGENTS.md; never read answer keys, blind labels or blind-target code. Preserve prior edits;
  never `git add -A`, install sqlmap on Windows or commit `config.local.yaml`. Record source identity,
  process ownership, commands and logs per live run; kill by PID tree.
