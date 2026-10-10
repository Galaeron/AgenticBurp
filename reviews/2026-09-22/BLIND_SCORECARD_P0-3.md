# Blind scorecard — P0-3 owner/live run (via RB-8)

**Owner-reported / VERIFIED-in-run.** Real Ollama model, real orchestrator, the
curated blind-target-2 corpus. Single pass (not the `run_eval_n_times` variance
aggregation RB-8 also built — see **Not done** below).

## Exact command

```
cd C:\Users\arthu\Documents\AgenticVibe
.venv-rationalisation\Scripts\python.exe testing\blind-target-2\run_blind_eval.py
```

Defaults used (all from `run_blind_eval.py`'s own env-var defaults, none
overridden): `HARNESS_FAIL_OPEN_MODE=curated`, `HARNESS_QUARANTINE_LEADS=1`,
`HARNESS_CROSS_IDENTITY_REJECT=0`. `harness/config.yaml` on disk was not
edited; the mode/quarantine overrides are injected into the in-memory config
dict only (RB-8's design), and `cross_identity_reject=0` means
`validators.active_enabled` stayed `false` — no live traffic was sent to any
target, only replay of pre-captured exchanges through the orchestrator.

## Checkout

- Commit `0f047e80bf1216bd2a7f3efb1d25481e237bf13a` (branch
  `reconciliation-backlog`), 37 untracked files present (new review docs,
  test scratch dirs) but **zero modified tracked files** — the harness source
  actually executed matches HEAD exactly.
- `config_fingerprint`: `514b4afd650ae1103f0c1621df2351ec111b2fcc72e3823426344c68d6e60e83`
- Model: `qwen3:8b` (local Ollama, both coordinator and every agent per
  `harness/config.yaml`'s committed defaults — `coordinator.cloud_primary` and
  `cloud_reasoning` both `false`, so nothing left the host).
- Fresh state/cache DBs (`C:\tmp\blind_eval_state.db`, `C:\tmp\blind_eval_cache.db`,
  cleared before the run).
- Corpus: `testing/blind-target-2/blind_eval_exchanges.json`, 10 hand-labeled
  exchanges (2 `confirmed_vuln`, 6 `confirmed_secure`, 2 `inconclusive`) against
  a helpdesk target the model has never seen. Ground truth derived by hand over
  HTTP only (see the script's own header comment); `ANSWER_KEY.md`/`app.py` in
  that directory were not read for this run, per the project's hard safeguard.
- Completion: exit 0, 0 errors across 10/10 exchanges.

## Result

| metric | this run (2026-09-22) | prior run (2026-09-20, `testing/SCORECARD.md`) |
|---|--:|--:|
| positives detected | **2/2** | 2/2 |
| controls clean | **0/5 unique control URLs** | 1/6 |
| total findings | 60 | 51 |
| surfaced (non-quarantined) | 39 | — (quarantine was a no-op pre-RB-8) |
| quarantined-as-leads | 2 | 0 (no-op) |
| total wall time | 1415.3s (10 exchanges, mean 141.5s/exchange, max 181.1s) | not recorded |
| total tokens spent | 0 | not recorded |

Both labeled `confirmed_vuln` exchanges were flagged with the correct
vulnerability class: exchange 5 (bob reads ticket #1 he doesn't own) got
`insecure_direct_object_reference` + `excessive_data_exposure`; exchange 8
(alice sets `department=admin`) got `MASS ASSIGNMENT / EXCESSIVE DATA BINDING`.
Neither was quarantined.

**Controls are not clean.** All 5 unique control URLs carry at least one
surfaced finding. Quarantine (RB-8's actual fix) suppressed exactly 2 of the
60 raw findings — real, but nowhere near enough to clean the controls; it is
not a substitute for reducing the agents' raw false-positive rate.

## Methodology caveat (read before trusting "0/5" at face value)

`build_scorecard` computes `dirty_controls` **per URL**, not per exchange, and
two URLs in this corpus are shared between a `confirmed_vuln` and a
`confirmed_secure` exchange:
- `GET /api/tickets/1` — exchange 5 (`confirmed_vuln`, bob reads it) and
  exchange 7 (`confirmed_secure`, bob's DELETE on it is blocked).

Because `harness.store.all_host_findings` aggregates by host and the control
set is keyed by URL, a correct IDOR finding on exchange 5 registers as a
"dirty control" for exchange 7's URL as well. That means the true FP rate on
the actually-secure exchanges is *somewhat* better than "0/5" reads — the
remaining 4 control URLs (register, login, tickets/6, tickets/1/comments) are
independently dirty on their own merits (9 findings on `/api/register` alone:
SQL injection, `known-vulnerable-dependency:Werkzeug`, a
`potential-attack-chain:sqli+idor`, etc. — none of that is real for a bare
POST /register), so this doesn't change the qualitative conclusion, but a
future corpus revision should avoid URL reuse across vuln/secure exchanges so
`controls_clean` isn't ambiguous like this.

## Read

Recall held at 2/2 (unchanged from 2026-09-20). Precision on hard negatives
regressed slightly by raw count (60 vs 51 findings; 0/5 vs 1/6 control URLs
clean) but is not a clean apples-to-apples comparison: the 2026-09-20 number
predates RB-1/RB-3/RB-4/RB-5/RB-8 (dependency-dedupe, chain re-link, proof
persistence, the quarantine fix itself) and this run is the first one where
`quarantine_unverified_leads` actually does something (2 findings suppressed
that would previously have been silently counted as "surfaced" with no
routing). The dominant FP driver is unchanged from 2026-09-20's diagnosis:
generic low-confidence agent guesses (`Security misconfiguration`,
`Broken Access Control (Workflow Bypass)`, `SQL injection` at confidence
0.3–0.5) fire on nearly every exchange regardless of actual target behavior,
and `cross_identity_reject` (which would REJECT/downgrade exactly this
pattern on secure object-scoped endpoints) was left OFF for this run because
it requires live traffic — see **Not done** below.

## Not done (scope of this run)

- **`run_eval_n_times` variance pass (n≥5).** RB-8 built this specifically so
  a scorecard reports mean/variance, not one sample. At ~141.5s/exchange ×
  10 exchanges, one pass takes ~24 minutes; a 5-run pass would be ~2 hours of
  local Ollama compute. Not run here — flag if a variance-backed number is
  needed before trusting this as more than one sample.
- **`HARNESS_CROSS_IDENTITY_REJECT=1`.** This is the one documented lever
  from 2026-09-20's diagnosis that should directly cut the IDOR-shaped FPs on
  secure endpoints, but it turns on `validators.active_enabled` and sends
  live (scoped, GET-only) requests at the target — owner-gated, and requires
  the blind-target-2 Flask app actually running on `127.0.0.1:5002` (not
  verified running for this pass; this run replayed captured exchanges only).
- Per-OWASP-category precision/recall (like `testing/score.py` does for
  `test-target`) — blind-target-2 has no equivalent scorer; this report's
  "positives detected"/"controls clean" framing matches the 2026-09-20 entry's
  own methodology for comparability.

Raw results: `C:\tmp\blind_eval_results.json` (not committed — local/owner
artifact, matches this project's existing convention of leaving generated
`maxrun`/results JSON untracked).
