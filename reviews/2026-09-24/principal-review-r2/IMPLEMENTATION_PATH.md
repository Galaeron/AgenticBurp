# Cycle-2 implementation path (from re-review R2)

Derives from [REVIEW.md](REVIEW.md) §4 (new findings N01–N05) and §8 (roadmap).
Same non-negotiables as cycle 1: safe defaults only (`config.yaml` untouched),
caller-level test + negative control per item, never read `*ANSWER_KEY*`/blind
`app.py`, `harness.suite full` green before close, `Co-Authored-By` trailer.

**Loop-consumable order:** NC-1 → NC-2 → NC-3 → NC-4. The `OWNER/LIVE` items
(NC-O1..NC-O5) are NOT loop-consumable — leave `[ ]`, skip, note why. **Coding
constraint:** the Sonnet coder is weekly-limited until 2026-09-28; until then
loop items are Opus-authored (as PR-11/PR-13 were) or deferred.

## Do-not-duplicate map

- NC-1 closes N01, applies existing PR-3/PR-5 (`strict_score`, `eval_adapter`) —
  do not rewrite them; add the runner that consumes them.
- NC-2 advances R11/N04 — first migration only; do not attempt the full catalogue.
- NC-3 finishes R14 — regenerate PR-6's manifest, do not re-derive it.
- NC-4 extends R09/PR-9 — add sink tests, do not re-implement redaction.
- NC-O2/NC-O3 merge R03+N03 into one address-pinning workstream.

## Loop-consumable items

### NC-1 — Apply the strict scorer in an offline runner (N01 / R06)
- **Effort:** M. **Mode:** LOOP. **Depends on:** PR-3/PR-5 (done).
- **Problem (VERIFIED):** no `harness/` importer of `strict_score`/`eval_adapter`;
  a live/benchmark run still scores through coarse `testing/score.py`.
- **Recommendation:** an offline entry point (`testing/`) that takes a saved run
  artifact and emits the strict scorecard via `eval_adapter.rescore_saved_run` /
  `strict_score.score`; coarse metrics printed only under an explicit `historical`
  label; a `ScoreProvenance` stamp on the output.
- **Acceptance:** caller-level test — a saved-run fixture scored end-to-end through
  the new runner yields exact-class precision/recall; the always-alert / all-class /
  silent baselines each **fail the strict precision gate through that runner**
  (negative controls). A clean/consistent run is unchanged. `full` green.
- **Impact:** High (makes R06's fix load-bearing instead of a tested island).

### NC-2 — Verify + gate browser-validator interception (N04 / R01,R11)
- **Effort:** M/L. **Mode:** LOOP.
- **Problem (VERIFIED):** two `visit` paths in `browser_driver.py`; only the
  intercepting one carries PR-10's per-request policy. A validator using the other
  gets no guarantee.
- **Recommendation:** confirm every browser-using validator routes through the
  intercepting `visit`; make a non-intercepted browser context refuse to send (or
  assert-fail in tests). Begin the typed capability catalogue with the browser
  family as the first migration (no big-bang).
- **Acceptance:** test that a browser request issued without the route interceptor
  installed is rejected/raises; enumeration test asserting each browser validator
  uses the intercepting path. NEGATIVE control: an in-scope request through the
  intercepting path still succeeds. `full` green.
- **Impact:** High (closes the "hardened one driver, not the plane" gap).

### NC-3 — Regenerable config/profile drift manifest (R14 residual)
- **Effort:** S. **Mode:** LOOP. **Depends on:** PR-6.
- **Problem:** PR-6's reconciliation is a one-off artifact; drift can recur.
- **Recommendation:** a small generator that emits the config/profile/egress
  manifest from `config.yaml` on demand, plus a test that the committed manifest
  matches regeneration (fails on drift).
- **Acceptance:** generator test — mutating a tracked default makes the drift check
  fail; unchanged config passes. `full` green.
- **Impact:** Medium (keeps R14 closed instead of decaying).

### NC-4 — Per-sink secret-canary tests (R09 residual / N-sec)
- **Effort:** M. **Mode:** LOOP. **Depends on:** PR-9.
- **Problem:** PR-9 redaction is wired but only prompt-path coverage is proven;
  other egress sinks (export, provider payloads, nested audit events) need canary
  proof.
- **Recommendation:** synthetic secret canaries in header/URL/body/nested-state
  asserted absent at every export/provider boundary; an injection payload in a
  non-secret field asserted present (redaction is name-scoped, not blanket).
- **Acceptance:** canary test across each sink; NEGATIVE control — a `q`/`search`
  SQLi/XSS payload survives verbatim. `full` green.
- **Impact:** High for remote-reasoning opt-in.

## OWNER / LIVE (skip — these are now the real blockers)

- **NC-O1 (N02/R02):** stand up + prove the tool egress proxy (or `--network none`
  + host alias); off-scope listener receives zero packets. Needs Docker.
- **NC-O2 (N03/R03):** connect-time address pinning (shared HTTP+browser), or a
  gated lab-mode; prove with a two-origin/DNS-rebinding test.
- **NC-O3 (R01 live):** two-origin browser credential-forwarding proof.
- **NC-O4 (PR-13 live/R15):** recall re-measure sanitized vs contaminated PixelMart
  + BP-4/BP-5C independent-case collection. Needs GPU/Ollama.
- **NC-O5 (R04/R13):** Java/API secure pairing + reproducible build/release gate.
  Needs JDK/Gradle.
