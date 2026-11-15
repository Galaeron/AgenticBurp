# Current state — 2026-11-15 (earlier runs and merges: git history of this file)

## Branch and base
- `main` = `port/wstg-ids-2026-11-14` on `integrate/main-2026-11-14` (base `979803d5`).
  It holds the r7-r10 chain up to run/r10 `8727c42d` (llama.cpp backend, r9 fixes), the r10
  gap fixes (Ollama retry of a dropped connection, review while the model is idle,
  open-redirect allowlist bypass, JWT key-confusion key reuse, write-path checks, exposure
  legs, coverage proofs bound to stored findings, one issue per site for a header policy,
  SPA client routes, form templates, file-input uploads) and, ported from
  `reconciliation-backlog`, SKL-1, SKL-2, SKL-5, WG-1/WG-2 `4f316410`, WG-3 `8926b653`,
  docs `ce3b69ba`, WG-2 item 1 (BUSL-08 row, id-scheme stamp) `6db01d2d`, `27ae9e3e` (smoke).
- Catalog: 62 rows on current WSTG ids (harness/wstg_ids.py); v4.2 ids load through
  LEGACY_CHECK_ID_ALIASES. Data is stamped `check_id_scheme: 2`; an unstamped
  `WSTG-BUSL-08` reads as TOCTOU (ATHZ-03). SESS-05 drives the csrf leg (open work 5).
- Off or inert by default: `review_overlap: true` needs a capture_review slice;
  `write_integrity` needs `validators.active_enabled` and `allow_mutating_replay` (both false;
  docs/WRITE_CHECKS.md); route probes, file uploads and discovery recursion are off.
- SKL-1 race: a generic burst is a lead; only the email race read-back confirms.
- This branch, `fix/oracle-leg-gaps-20261114` off main `1f632169` (not merged): leg fixes from
  the oracle run (nosql, file_upload, xxe, race, auth_sequence, listing logs, idor, api_security,
  sequence, client_trust, write_integrity; docs/WRITE_CHECKS.md), tests `test_oracle_gaps_*.py`.
- Not on main: `fcb96d62` (owner decision below); `WorkingSunday`,
  `main-checkout-snapshot-20261101` and the `origin/vibe/*` branches (old or superseded).

## Checkout
- The main checkout is on `reconciliation-backlog` with about 77 uncommitted files. WG-2
  item 1 among them is now on main (`6db01d2d`); the rest is older work. Leave them.
- Older W1-W4 WIP: `main-checkout-snapshot-20261101` (`2c0cf7f`), NOT merged; ~70 files
  exist nowhere else. Split it per docs/I01_CANDIDATE_MANIFEST_2026-10-17.md.

## Verification
- This branch, 2026-11-15, system Python 3.14.7: smoke and precondition exit 0; the 97
  modules touching the changed legs, 2036 OK; full exit 0 (harness 6608, native 38, eval 452).
- Main tip `27ae9e3e`, 2026-11-14, system Python 3.14.7: smoke and precondition exit 0. Full
  not rerun there; the owner reused `9fab7470`'s (2026-11-14).
- `9fab7470`, 2026-11-14, system Python 3.14.7: smoke, precondition and full exit 0 (harness
  6419, native 38, evaluation 452 / 17 skips, integrity 59). Java not rerun (unchanged).
- Java: `a3681c5`, 2026-11-01, Linux, 379 tests, 0 failures. CI: Python 3.14 + Playwright Chromium.
- Verify in an in-repo worktree, `PYTHONPATH=<worktree>`, system Python (not
  `.venv-rationalisation`). Defender deletes `file_upload_agent.py` under %TEMP%.
- Java: `gradle clean test shadowJar` on the in-repo JDK 17 (`.audit-external/toolchains/jdk17`),
  offline, `GRADLE_RO_DEP_CACHE` at `.audit-external/gradle-cache/caches`.

## Model backend
- Local Ollama needs `ollama.num_ctx: 16384` in harness/config.local.yaml; a cut prompt
  raises `OllamaContextTruncatedError`, and `context_preflight` warns at start.
- `ollama.api: "openai"` sends model calls to llama-server (OpenAI-compatible) at `base_url`.

## Live runs (owned Juice Shop on 127.0.0.1:3002 only; sqlmap only from `harness/sqlmap:1.10.9`)
- r10 (job 9eb242afd5a0, `8727c42d`, gpt-oss-20b, :3004): 23.1 h, 236,966 requests, 138 of
  1,181 findings confirmed, 912 legs unrun at budget; 13/116 solved; no XSS confirmed.
  Files (main checkout): `.test-work/juice-shop-24h-20261111-r10/`, `-20h-20261110-r9/`.
- 2026-11-14, fresh :3002, main checkout `.test-work/`: validator trial (each new leg alone,
  `validator-trial-20261114/`) 13 confirmed, race a lead, restores verified. Oracle run (each
  leg aimed at its endpoint by hand): 6db01d2d 22 of 60 confirmed, 20 of 98 solved (r10: 13);
  this branch (pass 3) 31 confirmed, 23 solved, none worse. `oracle-juice-shop-20261114/README.md`.

## Open work (priority order)
0. Owner: may real runs set `validators.write_integrity.allow_unrestorable_self_service_creates`
   (sign-up accounts left, each named)? Not leg gaps: stored XSS on client-rendered pages is
   untested (the leg loads client views only from a crawl's route map; the oracle driver had
   none), and default-credential guessing (ATHN-02) was declined in the backlog.
1. WG-2 item 5: `_LEG_CONFIRMATIONS` gaps in harness/coverage_tracker.py (client_trust's
   wider fields only reach a run once it is listed there). Still open from
   the WSTG review: INJT-14 has no row, ATHN-04 has no bypass leg, WG-4 needs an owner
   decision, WG-5 needs a mail sink (IMPROVEMENT_BACKLOG.md WG-*).
2. A full Juice Shop run on the merge (the legs passed alone; JWT captured-key confusion,
   file_upload, SPA crawl, the WG auth rows and SESS-06 were not exercised). r10
   leftovers: compare result.json with r9; find the check that sent ~10k/h to
   socket.io polling at h4-5; cross_identity still repeats across findings.
3. Owner review of `8040dbf5` (policy reads a decoded NUL both ways, on main).
4. r6 follow-ups (coverage-drive time, end-of-job accounting, passive proofs with artifact
   ids; briefs T1-T6 in `.test-work/r5-r6-detection-analysis-20261109/ANALYSIS.md`) and review
   leftovers (sqlmap rows keep confirmed=True for stop logic; a resumed journal can skip the
   query probe; skipped keys advance the lower-tier rotation).
5. Owner check: SESS-05 now drives the csrf leg (0.4 observation without a browser
   PoC; replays need allow_mutating_replay). Keep it, or set the row back to manual.
6. Proof/issue dedup (owner, 2026-10-28): one vulnerability, one proof, keyed on host,
   mechanism, principal and check family; other routes become affected locations.
7. Coverage drive throughput (v8: 110 of 1380 queued sent, 1270 incomplete attempts).
8. `redact_headers` has no X-CSRF-Token entry; harness/active_verification.py falls back
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
- Follow AGENTS.md. Never read answer keys, blind labels or blind-target code.
- Preserve prior edits. Never `git add -A`. Never install sqlmap on Windows.
- Record source identity, process ownership, commands and logs per live run; kill by PID tree.
