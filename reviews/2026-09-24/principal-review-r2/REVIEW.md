# AgenticBurp: principal re-review (cycle 2, delta)

Review date: 2026-09-24 (cycle 2). Reviewed checkout: `reconciliation-backlog`,
HEAD `8afa49d`, i.e. the `ca4ee15`-era tree from the [first 2026-09-24 review]
(../principal-review/REVIEW.md) **plus** the offline improvement batch
`c26d769`..`8afa49d` (12 feature PRs + loop docs). Origin
`https://github.com/ArthurTesta/AgenticBurp.git`.

This is a **delta re-review**: it does not re-derive the product reconstruction or
competitive/business analysis, which the first review established and which the
batch did not change (see §11–§16 there — those verdicts still stand). It answers
one question the mission demands after an implementation pass: **did the work
change what a founder should trust, fix, or build next — measured against source,
not commit messages?** Evidence labels: VERIFIED / SUPPORTED / CLAIMED / INFERRED /
UNKNOWN, per [VERIFICATION.md](VERIFICATION.md). No safety default was changed; no
hidden key or blind-target `app.py` was read. Scores are review judgments, not
benchmark measurements.

## 1. Executive verdict

**INFERRED: the batch raised the trust *floor* but not the trust *ceiling*.** The
project is still an advanced single-user copilot prototype, not a demonstrated
autonomous pentesting product. What genuinely improved is real and verified in
source: the canonical suite now runs green in a restricted environment (R05
closed), secret redaction and stage-health degradation are wired into the
production analysis path (R08/R09 mitigated where it counts), and a rigorous
offline evaluation toolkit now exists (exact-class scorer, evidence grading,
reconciliation, corpus-contamination sanitizer). None of that changes the two
things a buyer actually needs proven, because both are OWNER/LIVE and were not
executed: (a) **real detection efficacy on an adequate, uncontaminated corpus**,
and (b) **demonstrated live containment** of browser and external-tool traffic.

The single most important honest finding of this cycle is a nuance the mission
warns about directly — *implemented is not working*:

> **The eval-integrity PRs (PR-3/4/5/6) are correct, tested, and compose each
> other, but no `harness/` runner imports them (VERIFIED). They are a
> non-load-bearing toolkit. A live benchmark run today still scores through the
> old coarse contract.** The instruments that make a score trustworthy exist; the
> live path does not yet use them. (Finding N01.)

Similarly, the two security PRs delivered their *offline halves* precisely — a
per-request-intercepting browser adapter and a fail-closed egress seam — but the
sqlmap caller passes `proxy_url=None` on a `bridge` network, so the container
still has unrestricted egress and `allowed_hosts` is not enforced (N02); and the
DNS-rebinding window (R03) is not just still open but now explicitly declared in
source as "deliberately not built" (N03). These are honest, well-documented seams
awaiting a live proof — not closed boundaries.

**Five decisions for the next cycle:**

1. **Wire the strict scorer into a runner or stop calling the eval "fixed."** One
   offline runner (`rescore_saved_run` → report) that consumes `eval_adapter` /
   `strict_score` on a saved run, with the coarse path marked historical. Until
   then, R06 is an available instrument, not an applied contract.
2. **Convert the egress seam to enforcement, or gate active tool use.** Stand up
   the per-run proxy (or a `--network none` + host-alias-only design) and prove it
   with an off-scope listener. Until then treat sqlmap runs as unconfined.
3. **Decide R03 explicitly:** either build connect-time address pinning or make
   host-scoped active use a documented, gated non-default. The browser adapter's
   per-request checks inherit the same address-blind `ScopePolicy`, so they do not
   close the rebinding gap.
4. **Do the OWNER live proofs (PR-10/11/13 live, PR-A/B/C).** These are the gating
   trust artifacts and none can be produced by an offline loop. They are the real
   blockers now, not more offline modules.
5. **Start the corpus/efficacy work (R15) that everything else waits on.** The
   sanitizer (PR-13) removed one contamination source; it did not create
   independent labeled cases or measure recall inflation.

I would still fund an evidence-and-containment milestone, not six unconditional
months. The batch is good engineering and moved the right levers; it did not yet
produce a single new *demonstrated* trust guarantee a customer could rely on.

## 2. What the batch actually delivered (VERIFIED)

| PR | Finding | What landed | Wired into prod? |
|---|---|---|---|
| PR-1 `c26d769` | R05 | Portable per-user audit sink; guarded handler open; `require_file`/`AuditStorageUnavailable` | YES — whole suite now runs green (VERIFIED exit 0) |
| PR-2 `b8fd09b` | R06 input | Exact-class label manifest + typed loader + PixelMart seed + label-leak/hash guards | Instrument (feeds PR-3/4) |
| PR-3 `809dd9c` | R06 | Strict exact-class scorer; csrf≠ssrf longest-keyword fix; 3 indiscriminate baselines that fail the precision gate | Instrument — **no runner imports it (N01)** |
| PR-4 `112a884` | R10 | Evidence-supported grading tier (`captured`/`differential_reproduced`/`insufficient`/`unsupported`; `unavailable`≠0) | Instrument |
| PR-5 `81558ab` | R06/R10 | Shared eval adapter (raw/surfaced/lead + ScoreProvenance) + read-only `rescore_saved_run` | Instrument |
| PR-6 `605863b` | R14 | Benchmark reconciliation + config-drift manifest + dated corrected assessment | Report artifact |
| PR-7 `a33a1ab` | R08 | Typed `StageOutcome` + `degraded` on `AnalysisResponse`; `_critique` 4-tuple; failed critique can't read clean | **YES** — `orchestrator_detect.py:921/949`, `run_manifest.py:97` |
| PR-9 `07d1e13` | R09 | Schema-aware recursive redaction; URL/body secret-name redaction preserving injection payloads | **YES** — `agents/base_agent.py:254-256` |
| PR-10 `4913488` | R01 | Policy-bound browser adapter; per-request `context.route` interception; no blanket header projection | **YES (offline)** — `browser_driver.py:331`; live 2-origin proof = OWNER |
| PR-11 `d82aab9` | R02 | Fail-closed `EgressPolicy` seam + cleanup wrapper + receipts; sqlmap container rerouted through `tool_runner.run` | **Seam wired (offline)**; enforcement + live proof = OWNER (N02) |
| PR-13 `2d66c5e` | R06/R15 | Corpus contamination audit + sanitizer (byte-identical clean control); PixelMart TP10 = 19 markers, DVWA/WebGoat = 0 | Instrument; live recall re-measure = OWNER |

The batch is disciplined: additive, `config.yaml` untouched, every item carries a
caller-level test and a negative control, and the full suite is green
(harness 2625 / testing 148 / evaluation_integrity 42, exit 0). This is the
strongest, most honest thing to say about it, and it is a real improvement over
the first review's environment, which could not run the suite at all.

## 3. Findings status delta (R01–R16)

| ID | First-review status | Now | Evidence |
|---|---|---|---|
| R01 browser boundary | Open (High) | **Mitigated (offline)** — per-request interception wired; live credential proof pending | `browser_driver.py:239-331` VERIFIED; N04 |
| R02 tool egress | Open (High) | **Seam only** — fail-closed policy wired, egress NOT enforced | N02 VERIFIED |
| R03 address pinning | Open (High) | **Open** — now explicitly "deliberately not built" | `run_context.py:64-75` VERIFIED |
| R04 Java/API token | Open (High) | **Open** — no pairing/lockfile reader in Java | grep VERIFIED |
| R05 audit-log init | Open (High) | **Closed** — suite green in restricted env | suite exit 0 VERIFIED |
| R06 scoring contract | Open (High) | **Instrument built, not applied** | N01 VERIFIED |
| R07 ablations | Open (High) | **Open** — OWNER (needs live model/GPU) | unchanged |
| R08 hidden degradation | Open (High) | **Mitigated** — typed stage health + `degraded` surfaced | `orchestrator_detect.py:921/949` VERIFIED |
| R09 redaction | Open (High) | **Mitigated** — recursive + URL/body secret-name redaction wired | `base_agent.py:254-256` VERIFIED |
| R10 evidence completeness | Open (High) | **Partial** — grading tier exists (instrument); per-run receipts/completeness still open | PR-4/PR-11 receipts; N01 |
| R11 pipeline duplication | Open (Med) | **Open** — one browser driver hardened, catalogue not unified | N04 |
| R12 global state | Open (Med) | **Open** | unchanged |
| R13 release/Java build | Open (Med) | **Open** — OWNER | unchanged |
| R14 config/doc drift | Open (Med) | **Partial** — reconciliation manifest + corrected assessment added; CURRENT_STATE maintained | PR-6 |
| R15 corpus adequacy | Open (High) | **Partial** — one contamination source sanitized; no new independent cases/measure | PR-13; N05 |
| R16 product wedge | Open (Opp) | **Open** — OWNER/product | unchanged |

Net: **1 closed, 4 mitigated, 3 partial, 8 open** (of which 5 are OWNER/LIVE or
product and were never loop-consumable).

## 4. New findings this cycle (highest leverage)

### N01 — The strict evaluation toolkit is not load-bearing
**Domain:** Evaluation / trust. **Severity:** High. **Confidence:** High.
**Evidence status:** VERIFIED (grep of `harness/` finds no importer of
`strict_score`/`eval_adapter`/`classify_exact`; only `testing/evidence_grade.py:103`
imports it — a sibling instrument).
**Problem:** PR-3/4/5/6 are internally correct and mutually composed, but nothing
in the live/benchmark path consumes them. A benchmark run today still scores
through `testing/score.py`'s coarse OWASP-category contract — the exact defect R06
described.
**Why it matters:** the first review's central risk is "green unit tests + broken
real detection." Building a rigorous scorer that no run uses reproduces that shape
one level up: the instrument passes its tests and changes no reported number.
**Failure scenario:** the founder reads "R06 fixed" and trusts the next saved
scorecard, which was produced by the coarse scorer.
**Recommendation:** ship one offline runner that takes a saved run and emits the
strict scorecard via `eval_adapter`/`rescore_saved_run`, print the coarse metrics
only under an explicit `historical` label, and add a test asserting an
indiscriminate baseline fails the strict precision gate *end-to-end through that
runner*. **Effort:** M. **Impact:** High.

### N02 — The egress "boundary" does not restrict egress
**Domain:** Security. **Severity:** High (conditional on active tool use).
**Confidence:** High. **Evidence status:** VERIFIED source.
**Evidence:** `tool_runner.py:127-137` (`EgressPolicy.docker_flags` emits proxy
env only when `proxy_url` is set); default `network="bridge"`, `proxy_url=None`;
sqlmap caller `validators/sqlmap.py:449-450` passes only
`allowed_hosts=(_HOST_ALIAS,)`.
**Problem:** the seam is fail-closed on *policy presence* (good), but the policy it
is given confines nothing: `--network bridge` grants full outbound network and,
with no proxy, `allowed_hosts` is inert metadata. R02's actual ask — "an
authenticated per-run egress proxy or equivalent network sandbox" — is unbuilt.
**Failure scenario:** an approved sqlmap run follows a redirect or emits probes to
an unintended destination; nothing in the offline seam prevents it.
**Recommendation:** either (a) run the container on `--network none` with only a
host alias and route the single allowed destination explicitly, or (b) stand up
the proxy and set `proxy_url`. Prove with an off-scope listener that receives zero
packets. Until then, gate container tools behind an explicit "unconfined egress"
acknowledgement. **Effort:** L (OWNER/live). **Impact:** High.

### N03 — Per-request browser checks still inherit an address-blind scope
**Domain:** Security. **Severity:** High (conditional). **Confidence:** High.
**Evidence status:** VERIFIED source.
**Evidence:** `browser_driver.py:306` `evaluate_browser_request(..., scope=ScopePolicy)`;
`run_context.py:64-75` states the policy pins hostnames, not resolved addresses.
**Problem:** PR-10 correctly checks scheme/origin/method per request, but it
authorizes by *hostname* against the same `ScopePolicy` that R03 flagged. A name
authorized at check time can resolve to a different address at connect time, so
the rebinding window R03 described is not closed by PR-10 for the browser plane
either.
**Recommendation:** resolve-and-pin the connected address (shared with the HTTP
transport), or document host-scoped active browsing as a gated non-default lab
mode. **Effort:** L. **Impact:** High. (Merges with R03 — treat as one workstream.)

### N04 — Capability policy is still assembled per execution path
**Domain:** Architecture / maintainability. **Severity:** Medium.
**Confidence:** High. **Evidence status:** VERIFIED source.
**Evidence:** `browser_driver.py` now has two `visit` implementations (`:157`
legacy, `:239` intercepting); `orchestrator_chain.py` still constructs validators
directly; Java `ValidationExecutor` is a third plane.
**Problem:** PR-10 hardened one driver; R11's underlying duplication is unchanged.
A browser-using validator that does not route through the intercepting `visit`
gets none of PR-10's guarantees.
**Recommendation:** confirm every browser-using validator calls the intercepting
path; begin the single typed capability catalogue (R11) with the browser family as
the first migration. **Effort:** L. **Impact:** High.

### N05 — Contamination sanitized, but corpus adequacy (R15) is untouched
**Domain:** Evaluation. **Severity:** High. **Confidence:** High.
**Evidence status:** VERIFIED (PR-13 audit) + INFERRED (statistical).
**Problem:** PR-13 removes ground-truth annotations from one exchange; it does not
add independent cases, create a holdout, or measure the recall inflation it
documents. The promotion bottleneck the first review named is intact.
**Recommendation:** the OWNER recall re-measure (sanitized vs contaminated) plus
BP-4/BP-5C independent-case collection. **Effort:** L. **Impact:** Transformational.

## 5. Security & threat model (delta)

The batch narrowed three rows of the first review's table and left the rest:

- **Response instructs model to expand scope:** unchanged (deterministic gates);
  PR-9 additionally keeps body/URL secrets out of the prompt (VERIFIED).
- **Browser subresource/redirect changes destination:** improved — per-request
  interception now exists (R01→mitigated) — but address-blind (N03) and possibly
  non-universal across validators (N04). Still P0 for live use until proven.
- **Tool creates its own requests:** **not** improved in substance — seam only
  (N02). Still P0.
- **Secrets reach remote reasoning/artifacts:** improved — recursive + URL/body
  redaction wired (R09→mitigated). Residual: redaction is best-effort by field
  name; still classify sinks and add per-provider export tests.
- **Allowed domain resolves elsewhere:** unchanged (R03/N03), P0 for active use.

No remotely exploitable critical vulnerability was demonstrated. High severities
remain conditional on the relevant active feature being enabled.

## 6. Trustworthiness & efficacy (delta)

Trustworthiness *observability* improved: a degraded run is now flagged rather than
reported clean (PR-7, VERIFIED), and the evidence-grading vocabulary distinguishes
supported from unsupported and `unavailable` from zero (PR-4). Trustworthiness
*of numbers* did not improve, because the strict instruments are not applied
(N01) and no live efficacy run occurred. The first review's core efficacy verdict
is unchanged: **no sound cross-app/operator efficacy estimate exists.** The
sanitizer (PR-13) is a prerequisite to a trustworthy PixelMart number, not the
number itself.

## 7. Scorecard (deltas only; unlisted rows unchanged from the first review)

| Category | Was | Now | Why it moved |
|---|---:|---:|---|
| Reliability | 4 | **6** | Suite green in restricted env; typed stage health; degraded surfaced (VERIFIED) |
| Security of platform | 4 | **5** | Redaction wired + browser interception offline; but egress seam-only (N02), address-blind (N03) |
| Trustworthiness | 4 | **5** | Degradation visible + evidence tiers; numbers still unverified (N01) |
| Evidence quality | 5 | **6** | Grading tier + receipts scaffolding; full replay still open |
| Evaluation maturity | 4 | **5** | Strict instruments + contamination audit exist; not yet applied to a run (N01) |
| Observability | 5 | **6** | Per-stage `degraded`/manifest; export consistency still open |
| Documentation | 5 | **6** | Reconciliation manifest, corrected assessment, maintained CURRENT_STATE |

All other rows (Architecture 6, Code quality 6, Agent architecture 4, Real-world
efficacy 3, Pentester UX 4, Business 3, Enterprise 2, etc.) are **unchanged** —
the batch did not touch what they measure. Efficacy and business readiness cannot
move without the OWNER/LIVE work.

## 8. Roadmap for the next cycle

**Offline, loop-consumable (do first):**

- **NC-1 (N01):** offline strict-scoring runner that applies `eval_adapter`/
  `strict_score` to a saved run; coarse metrics only under `historical`; e2e
  baseline-fails-precision test. **M.**
- **NC-2 (N04):** audit every browser-using validator routes through the
  intercepting `visit`; add a test that a non-intercepted context is rejected.
  Begin the typed capability catalogue with the browser family. **M/L.**
- **NC-3 (R14 residual):** generate the config/profile manifest into docs so the
  drift correction is regenerable, not a one-off report. **S.**
- **NC-4 (R09 residual):** per-provider/export secret-canary tests across every
  egress sink. **M.**

**OWNER / LIVE (cannot be looped — these are now the real blockers):**

- **NC-O1 (N02/R02):** stand up + prove the tool egress proxy (off-scope listener
  = zero packets).
- **NC-O2 (N03/R03):** connect-time address pinning, or gated lab-mode
  documentation, proven with a two-origin/DNS test.
- **NC-O3 (R01 live):** two-origin browser credential-forwarding proof.
- **NC-O4 (PR-13 live/R15):** recall re-measure sanitized vs contaminated +
  independent-case collection.
- **NC-O5 (R04/R13):** Java/API pairing + reproducible build gate.

## 9. Final answer to the founder (delta)

- **Did the batch change the investment decision?** No — it improved the floor
  (reproducible suite, wired observability/redaction) and built the tools you need,
  but produced no new *demonstrated* trust guarantee. The gating proofs are still
  OWNER/LIVE.
- **What to trust now that you couldn't?** That the pipeline initializes and runs
  green anywhere; that a degraded run is visible; that body/URL secrets are kept
  out of prompts. (All VERIFIED in source.)
- **What still not to trust?** Any saved detection score (coarse scorer still in
  the live path, N01); that active browser/tool traffic is contained (seam only,
  N02/N03); any PixelMart recall number (contamination removed but not
  re-measured, N05).
- **Build next?** Apply the strict scorer (NC-1), then spend the scarce OWNER time
  on the three live containment/efficacy proofs — not on more offline modules.
- **Process note:** the offline improve-loop drained its backlog cleanly and
  honestly. Its ceiling is now reached: **the remaining high-value work is
  OWNER/LIVE and cannot be produced by an unattended offline coder.** The next
  cycle should be scoped around executing those proofs, with offline items NC-1..4
  as the only loop-consumable remainder.

### Evidence navigation
Commands, exits and limits: [VERIFICATION.md](VERIFICATION.md). Batch range
`c26d769`..`8afa49d`. Source anchors are inline above by file:line. First-cycle
review and its findings: [../principal-review/REVIEW.md](../principal-review/REVIEW.md).
No live model run, no Java build, no live containment proof, and no efficacy number
were executed or invented this cycle.
