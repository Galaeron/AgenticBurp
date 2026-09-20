# Detection scorecard — test-target (PixelMart)

Real run of the 36-agent harness against the purpose-built, **uncontaminated**
PixelMart corpus (built precisely because Juice Shop is training-contaminated).
Reproduce:

```
cd testing/test-target && python detection_fixture.py build   # model time, once
cd testing && python score.py --corpus test-target --from-cache --min-severity medium
```

- **Model:** qwen3:8b (local Ollama) · **Corpus:** test-target (11 labeled TP + TN)
- **Date:** 2026-09-02 · **Scorer:** `testing/score.py` (exchange-level, OWASP 2021)

## Headline — false-positive reduction (this session)

Two levers, **zero recall loss** throughout (recall held at 0.727, tp=8):

| step | precision | recall | F1 | FPs |
|---|--:|--:|--:|--:|
| baseline (all findings) | 0.229 | 0.727 | 0.348 | 27 |
| + operating point **severity ≥ medium** | 0.333 | 0.727 | 0.457 | 16 |
| + **agent precision fixes** (misconfig, supply_chain) | **0.421** | **0.727** | **0.533** | **11** |

**Net: precision 0.229 → 0.421 (+84 %), FPs 27 → 11 (−59 %), recall unchanged.**

1. **Operating point.** Gating to what an analyst triages (severity ≥ medium) drops
   low-severity missing-header noise — not detections. A *confidence* gate does
   nothing (FPs are high-confidence, c≈0.8–0.95); severity is the knob. sev ≥ high
   over-corrects (recall 0.727→0.545), so medium is the point.
2. **Agent fixes.** `supply_chain` now emits an exposure *finding* only when the body
   literally *is* a served manifest (FPs 5→2). `misconfig` stays in its lane (no more
   XSS/CSRF findings) and rates missing-headers as low (out-of-lane + generic FPs
   gone). Neither touches a true positive in this corpus, so recall is unaffected.

### Per category (severity ≥ medium, after fixes)
| Category | support | precision | recall | F1 |
|---|--:|--:|--:|--:|
| A01 Broken Access Control | 3 | 0.333 | 0.333 | 0.333 |
| A03 Injection | 4 | 0.571 | 1.000 | 0.727 |
| A04 Insecure Design (business logic) | 1 | n/a | 0.000 | n/a |
| A05 Security Misconfiguration | 1 | 0.333 | 1.000 | 0.500 |
| A07 Auth Failures | 1 | 0.500 | 1.000 | 0.667 |
| A10 SSRF | 1 | 0.500 | 1.000 | 0.667 |

## Correction — full-pipeline re-test (2026-09-02) + a scorer-bug fix

A full-pipeline re-test (live PixelMart, all fixes incl. cross-identity) surfaced a
**bug in this scorer** that had understated recall throughout: `score.classify` did not
map `"Insecure Direct Object Reference"` / `"insecure_direct_object_reference"` to A01
(the keyword list had `idor`/`bola` but not `insecure direct object`). Fixed.

**Corrected numbers (agents-only fixture + gate, sev≥medium):** precision **0.476**,
recall **0.909** (tp=10, fp=11, fn=1); **A01 recall 1.0** (not 0.33).

**This corrects two earlier claims in this file:**
- Single-exchange analysis did NOT "miss TP4/TP10 IDOR" — the agents flagged them; the
  scorer mislabelled the class. So the "A01 recall 1/3→2/3 via cross-identity" framing
  in the T3 section below is a **scoring artifact**, not a real recall gain.
- Cross-identity's real, demonstrated value is **CONFIRMATION, not raw recall**: it turns
  an unconfirmed single-exchange IDOR *guess* into a deterministic *proof*. In the
  re-test it CONFIRMED IDOR on **TP3, TP4, TP11 at 0.91** (`finding.confirmed=True`) —
  the "prove the bug" capability the teardown said the harness lacked.

**Full-pipeline re-test (fresh live run, sev≥medium):** recall 0.909, precision 0.286
(fp=25). Lower precision than the cached fixture (fp=11) is **fresh-run agent variance**
(more raw agent findings this pass), not a regression — the runs invoke the agents
independently and single-pass output varies.

**A real cross-identity FP found — and FIXED:** it confirmed IDOR on **TN3
(`GET /api/users/me`)**, a *token-relative* endpoint that returns each identity's OWN
profile. The two self-profiles (`{"email":"alice@…","id":1,…}` vs bob's) are
structurally near-identical, so trigram similarity scored ≥0.70 and read as "same
resource". Fix: the validator now requires an **object identifier in the URL** to swap
(`has_object_identifier`) — a token-relative endpoint (`/me`, `/profile`, `/dashboard`,
no path id) is not an IDOR candidate and is skipped. Verified live: **TN3 → skipped,
TP3 (`/users/2/profile`) → still confirmed**; +2 unit tests.

**Reject/precision benefit not visible here:** PixelMart is deliberately vulnerable, so
cross-identity mostly CONFIRMS; the REJECT→downgrade path (secure endpoints) needs the
blind helpdesk (real secure controls) to demonstrate.

## The 11 remaining FPs — root cause

- **Injection pile-ons on TN4 + TP10 (~7):** sqli/xss/ssrf fire on a reflected
  "attack attempt" (TN4) and a file-disclosure response (TP10). *(Earlier I expected
  the real pipeline's validators to kill these — the blind-target-2 full-pipeline run
  below REFUTED that: validators confirmed 0/10 and did not suppress unconfirmed
  findings. The validator layer does not currently backstop precision.)*
- **Over-reaches (~2):** jwt on a benign exchange (TN5), xss on an SSRF exchange (TP9).
  Broad fix = agent lane discipline in `base_agent` (full rebuild to measure).
- **Taxonomy near-miss (~1):** TP7 "workflow bypass" → A01 vs truth A04. A `score.py`
  `_CATEGORY_KEYWORDS` / per-label-truth calibration, not a detection bug.
- **Residual supply_chain (~1):** TP10 genuinely exposes a manifest-shaped response.

## T3 — multi-request closes the A01 IDOR recall gap (measured)

Single-exchange analysis missed the IDOR cases (A01 recall 0.33: TP3 weak, TP4/TP10
missed). The deterministic cross-identity probe (`cross_identity_probe.py` — two real
identities, the 4-probe source/candidate/attempt/anon comparison) against live
PixelMart:

```
[TP3 profile IDOR] CONFIRMED (confidence=0.91)
[TP4 order IDOR]   CONFIRMED (confidence=0.91)   <- single-exchange MISSED this
```

Both are now **confirmed** — a proof from real cross-identity HTTP, not an LLM guess —
raising A01 IDOR recall from 1/3 to **2/3**, with **no model call**. (TP10 is
file-disclosure, not IDOR; A04 business logic is human-hand-off by design — the harness
flags intent-level flaws for a human rather than fake-confirming them.)

**Takeaway:** the highest-value categories the teardown flagged (IDOR/authz) are exactly
where multi-request turns a missed/low-confidence guess into a *confirmed* finding. The
engagement arc already builds this (`role_crawl.py` → access matrix → cross-identity
BOLA); wiring it on-by-default for object-scoped endpoints is the remaining step.

## blind-target-2 — full pipeline, uncontaminated (independent number)

`run_blind_eval.py`: 10 curated exchanges (2 `confirmed_vuln`, 6 `confirmed_secure`,
2 `inconclusive`) from a helpdesk app the harness has **never seen**, through the FULL
pipeline (agents + validators + live Ollama). Aggregate only (blind instrument kept intact):

| metric | result |
|---|---|
| positives detected (medium+) | **2/2** |
| controls clean | **0/6** — every secure endpoint got a medium+ finding |
| validator-confirmed | **0/10** (sqlmap ×3 not_confirmed, api_validator ×2 skipped) |
| medium+ findings / 10 exchanges | 39 (~4 per exchange) |

**Read:** recall holds on a blind target (2/2), but **precision collapses on hard
negatives (0/6 controls clean)** — worse than test-target. Two FP drivers:
- **9× `known-vulnerable-dependency:Werkzeug`** — the GH-advisory path flags the Flask
  dev-server banner on *every* response. Fix: dedupe dependency findings host-level.
- **9× single-exchange IDOR** on secure endpoints — exactly what **#3's cross-identity
  probe rejects** (a secure endpoint denies cross-identity access). Wiring cross-identity
  on-by-default cuts these FPs *and* lifts IDOR recall — one change, both directions.

**Correction:** the validator layer did NOT rescue precision (0 confirmations; it adds a
`confirmed` flag to true positives but does not suppress unconfirmed findings). The
teardown's "deterministic confirmation leg degrades in practice" is confirmed here.

## Caveats
- Small n (11 TPs), single pass — per-exchange variance (see
  `DETECTION_BENCH_METHODOLOGY.md`). Directional until blind-target-2 corroborates.
- `score.py` demands the *correct* OWASP category, so it is a strict lower bound.

## Tried and rejected
- **Agent lane discipline** (a shared `base_agent` "report only your own class"
  rule, full rebuild): measured **worse** — sev≥medium FPs 11→15, precision
  0.421→0.348, recall unchanged. The 8B model didn't reliably self-identify its
  lane; the out-of-lane FPs persisted and `jwt` newly over-fired. Reverted. The
  effective approach stays **targeted specialty-level fixes** (misconfig/supply_chain).

## Cross-identity (Autorize-style) validator — BUILT (this session)

The top-ranked fix is implemented: `validators/cross_identity_validator.py`, a
tester-fed Autorize. It replays an object-scoped GET as other identities + an
anonymous baseline (credentials supplied via `POST /identities/session-headers`,
held **in memory only, never persisted** — the harness's no-stored-tokens
invariant, same as Autorize needing a configured cookie) and runs the proven
`identity_compare` logic:
- **CONFIRMED** → sets `finding.confirmed` + boosts confidence (real IDOR).
- **deterministic REJECT** (every other identity + anon denied) → downgrades the
  single-exchange guess, mirroring `access_control_gate`.

Off by default (`validators.cross_identity.enabled` + `active_enabled`, GET-only,
scoped to `allowed_hosts`). **Live-verified against PixelMart: profile IDOR
CONFIRMED at 0.91**; 6 unit tests. This is the fix for BOTH the blind IDOR FPs
(secure endpoints → REJECT → downgrade) and the IDOR recall gap (real IDOR →
CONFIRMED).

Also this session: `access_control_gate` now caps severity as well as confidence,
and `score.py` applies the gate so the fixture reflects the shipped pipeline.

## 2026-09-20 — fresh live re-run (current checkout, no cache reuse)

`detection_fixture.py` and `run_blind_eval.py` had been broken since the W-18
`harness.*` package refactor (flat `import store`/`import orchestrator`
instead of `from harness import ...`) — fixed as import-path-only changes to
run this. `testing/score.py` had the same stale `import access_control_gate`
and was fixed the same way.

**test-target, sev≥medium (`python score.py --corpus test-target --from-cache`,
fixture rebuilt live via `detection_fixture.py build`, which force-refreshes
every dispatched agent — this is a live run, not a cache replay):**

| category | support | precision | recall | f1 |
|---|--:|--:|--:|--:|
| A01 Broken Access Control | 3 | 0.429 | 1.000 | 0.600 |
| A03 Injection | 4 | 0.667 | 1.000 | 0.800 |
| A04 Insecure Design | 1 | 1.000 | 1.000 | 1.000 |
| A05 Security Misconfiguration | 1 | 0.200 | 1.000 | 0.333 |
| A07 Auth Failures | 1 | 0.333 | 1.000 | 0.500 |
| A10 SSRF | 1 | 0.500 | 1.000 | 0.667 |

**Overall (micro): precision 0.423, recall 1.000, f1 0.595 (tp=11, fp=15, fn=0).**
vs. the 2026-09-02 baseline above (0.476 / 0.909): recall is now perfect, at the
cost of a few more FPs — inside the variance this doc already documents (a
prior fresh retest saw precision fall to 0.286). Read as one sample in a
~0.29–0.48 precision band, not a fixed score.

**blind-target-2 fresh re-run (`run_blind_eval.py`, 10 exchanges, live
Ollama):** positives detected 2/2 (unchanged). **Controls clean 1/6 — up from
0/6** on 2026-09-02, though still the weakest axis: 5 of 6 genuinely-secure
endpoints still get a spurious medium+ finding, mostly `missing_authentication`/
`security_misconfiguration` guesses the critique pass downgrades but doesn't
fully suppress. Total findings 51 (vs. 39 previously), 0 errors across 10
exchanges.

**VulnCorp-Helpdesk maxrun** (`testing/vulncorp-helpdesk/maxrun/run_maxcov_integrated.py`,
`.worktrees/integration-measure` @ `eb70210`, one day behind main's `249b799`;
full report: `testing/vulncorp-helpdesk/maxrun/recall_report_integrated_full.md`,
not tracked in git per this directory's existing convention): 8.3h wall time,
1,914 fused findings. Against the 13 known planted bugs: **9/13 confirmed**
(8/13 via the intended path), 3/13 detected-unconfirmed, 1/13 missed (SSRF).
**Proof-linked audit** (finding must resolve to an actual persisted proof for
its own case+validator, not just a `confirmed` flag) drops that to **6/13**.
**0 chains detected** — the session-8 "1 chain" claim in
`COMPETITIVE_LANDSCAPE.md` did not reproduce here. `command_injection` and
`ssti` were confirmed at `/api/tickets/import`, outside the tracked 13-item
ground truth. The confirmed-class breakdown is dominated by repetitive
`information_disclosure`/`verbose_error_disclosure` hits (641× / 107× on one
validator) — almost certainly duplicate noise, not distinct bugs, so raw
finding-volume numbers from this run should not be read as a precision claim.

## Remaining
- **Burp UI toggle** for `cross_identity` + a field to paste another identity's
  session headers (config toggle + endpoint exist; the Java panel wiring is
  uncompiled here).
- **Validator 0/10 explained**: there was NO IDOR validator before this, so IDOR
  was never confirmable inline (now fixed); sqlmap/api correctly did not confirm
  non-vulns.
- **Werkzeug dep noise (9×)**: per-advisory dedup already exists; a per-component
  cap is a minor follow-up.
- **Chaining regressed to 0** (2026-09-20 VulnCorp re-run, was 1 in session-8) and
  **proof-linked VulnCorp confirmation (6/13) trails the raw `confirmed` flag
  (9/13)** — both worth root-causing before quoting the session-8 numbers again.
