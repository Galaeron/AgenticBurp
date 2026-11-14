# Current state — 2026-11-14 (earlier runs and merges: git history of this file)

## Branch and base
- `main` = `integrate/main-2026-11-14` (base `979803d5`). It holds the r7-r10 chain up to
  run/r10 `8727c42d` (llama.cpp OpenAI-compatible backend, coverage replay dedupe, sqlmap
  retried blips, r9 review fixes, capture review beside the request-bound phases), the r10
  gap fixes (Ollama retry of a dropped connection, review while the model is idle,
  open-redirect allowlist bypass, JWT key-confusion key reuse, write-path checks, exposure
  legs, coverage proofs bound to stored findings, one issue per site for a header policy,
  SPA client routes, form templates, file-input uploads) and SKL-1, SKL-2, SKL-5 ported
  from `reconciliation-backlog`.
- New behaviour is off or inert by default: `review_overlap: true` needs a capture_review
  slice; `write_integrity` sits behind `validators.active_enabled: false` and
  `allow_mutating_replay: false` (docs/WRITE_CHECKS.md); route probes, file uploads and
  discovery recursion are off.
- SKL-1: race copies are prepared before one shared release, spread recorded; main's
  verdicts stand (a generic burst is a lead; only the email race read-back confirms).
- `8040dbf5` (policy reads a decoded NUL both ways instead of refusing the path) is on
  main; its author asked for owner review.
- Not on main: WG-1/WG-2 `56d6adae`, WG-3 `4acc0194`, docs `5faed03b` (open item 1);
  `fcb96d62` (owner decision below); `WorkingSunday`, `main-checkout-snapshot-20261101`
  and the `origin/vibe/*` branches (old or superseded).

## Checkout
- The main checkout is on `reconciliation-backlog` with about 77 uncommitted files, among
  them WG-2 item 1 (the BUSL-08 row; `.test-work/skl-20261112/HANDOFF.md`). Leave them.
- The older W1-W4 WIP is on `main-checkout-snapshot-20261101` (`2c0cf7f`, base `f563730`),
  NOT merged; about 70 of its files exist nowhere else. Split and review it per
  docs/I01_CANDIDATE_MANIFEST_2026-10-17.md.

## Verification
- `integrate/main-2026-11-14` `9fab7470`, 2026-11-14, Windows, system Python 3.14.7:
  smoke, precondition and full exit 0 (harness 6419, native 38, evaluation 452 / 17
  skips, integrity 59). burp-extension is unchanged, so Java was not rerun.
- `main` `a3681c5`, 2026-11-01, Linux, Python 3.13: Java 379 tests, 0 failures. CI runs
  Python 3.14; its full job installs Playwright + Chromium.
- Verify in an in-repo worktree with `PYTHONPATH=<worktree>` and system Python, not
  `.venv-rationalisation` (it imports modules from the main checkout). Defender deletes
  `file_upload_agent.py` from worktrees under %TEMP%.
- Java: `gradle clean test shadowJar` on the in-repo JDK 17 (`.audit-external/toolchains/jdk17`),
  offline, `GRADLE_RO_DEP_CACHE` at `.audit-external/gradle-cache/caches`.
- Stop background runs by exact PID tree; TaskStop leaves orphaned processes.

## Model backend
- Local Ollama needs `ollama.num_ctx: 16384` in harness/config.local.yaml; a cut prompt
  raises `OllamaContextTruncatedError`, and `context_preflight` warns at start.
- `ollama.api: "openai"` sends model calls to an OpenAI-compatible server (llama.cpp's
  llama-server) at `base_url`; unset keeps Ollama (harness/config.yaml comments).

## Live runs (owned Juice Shop on 127.0.0.1:3002 only; sqlmap only from `harness/sqlmap:1.10.9`)
- r10 (job 9eb242afd5a0, run/r10 `8727c42d`, llama.cpp gpt-oss-20b, :3004): done in
  23.1 h, 236,966 requests, 1,181 findings, 138 confirmed; 912 coverage legs unrun at
  budget. Target solved 13/116 (5 confirmed, 3 proven but unbound, 5 unreported; binding
  fixed by `d9e1b3c4` + `d52e99f5`). r9: JWT forging, SQLi (login, search), object IDOR;
  XSS never confirmed. Files (main checkout): `.test-work/juice-shop-24h-20261111-r10/`, `-20h-20261110-r9/`.
- 2026-11-14 validator trial, each new leg alone on a fresh :3002 (main checkout
  `.test-work/validator-trial-20261114/`): 13 confirmed, race a lead, restores verified.

## Open work (priority order)
1. Port WG-1/WG-2, WG-3 and docs `5faed03b` from `reconciliation-backlog` onto main. The
   WSTG id rename (e.g. INPV-05 -> INJT-05, CONF-02 -> CONF-14, BUSL-08 -> ATHZ-03) must
   reach main's newer catalog rows, legs and tests, or `_check_catalog_ids` rejects them at
   import. Then commit WG-2 item 1 from the main checkout.
2. A full Juice Shop run on the merge (the legs passed alone; JWT captured-key confusion,
   file_upload and the SPA crawl features were not exercised). r10 leftovers: compare result.json with r9; find the check that sent
   ~10k/h to socket.io polling at h4-5; cross_identity still repeats across findings.
3. Owner review of `8040dbf5`.
4. r6 follow-ups, if r7-r10 did not close them: time for the coverage drive and end-of-job
   accounting; passive-leg proofs carry exchange artifact ids. Briefs T1-T6:
   `.test-work/r5-r6-detection-analysis-20261109/ANALYSIS.md` (main checkout). Review
   leftovers: tool-reported sqlmap rows keep confirmed=True for worklist stop logic; a
   resumed journal can skip the query probe (worklist_investigator.py); skipped keys
   advance the lower-tier rotation (assessment_health.py).
5. Proof/issue dedup (owner, 2026-10-28): one vulnerability, one proof, keyed on host,
   mechanism, principal and check family; other routes become affected locations.
6. Coverage drive throughput (v8: 110 of 1380 queued sent, 1270 incomplete attempts).
7. `redact_headers` has no X-CSRF-Token entry; harness/active_verification.py falls back
   to llama3.1:8b (Burp validation only); 3acd392 has had no live run. Code review 02
   RV-K, I16 wiring, RV-O to RV-S residuals: docs/CODE_REVIEW_02_TRIAGE_2026-10-19.md.

## Owner decisions in force (detail: git history of this file, the triage docs)
- `/analyze`: one shared pile per site; `engagement_id` names a pile (W2
  `analyze:<uuid>` hunk and `fcb96d62` rejected). Stored SSTI opt-in (`{ssti: 2}` ceiling).
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
