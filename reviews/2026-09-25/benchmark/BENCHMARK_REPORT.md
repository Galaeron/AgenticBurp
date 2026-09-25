# Full performance evaluation — 2026-09-25 (live, strict exact-class)

**Status: complete.** 5 corpora × 3 repeats replayed through the live local model on
2026-09-25; 4 strict-scored against exact-class manifests, blind-target-2 run for raw
detection volume only. Headline: pooled exact-class **P=0.23, R=0.81** — a high-recall,
low-precision detection-triage profile, replacing the prior meaningless `recall(any)=1.0`.

## What was run and why it is trustworthy this time

- **Model:** local Ollama `qwen3:8b` (Q4_K_M), the shipped default. **Config:**
  `harness/config.yaml` shipped defaults (passive; `active_enabled=false`).
- **Targets:** 5 captured corpora replayed through the real orchestrator
  (`orchestrator.analyze` per exchange, 3 repeats each). Replay analyses the
  captured request/response, so the target apps need not be running; this measures
  the DETECTION stage (does the model name the right vulnerability class on a
  captured exchange), not live exploitation.
- **Scoring — the key change from prior runs:** instead of the old
  `recall(any)=1.0` "any finding counts" scorecard, findings are scored with the
  **strict exact-class scorer** (`testing/strict_score.py`, NC-1/PR-3) via the new
  live→strict bridge (`testing/strict_benchmark.py`): each finding is attributed to
  the exact exchange that produced it (AR-3 `finding_observations`, 0 unresolved
  attributions across all runs), then graded against a per-exchange **exact-class manifest**. A match
  requires the *exact* class (csrf≠ssrf, sqli≠xss), not a coarse OWASP category.
- **Negative controls, every corpus:** the three indiscriminate baselines
  (always-alert / all-classes / silent) are run through the precision/recall gates;
  a run is only certified when all three FAIL their gate (`discriminating=True`).
- **Contamination removed:** PixelMart is scored on the **sanitized** corpus
  (PR-13 stripped 19 `BUG:`/`ANSWER_KEY` ground-truth markers its TP10 response
  leaked); numbers here are not inflated by the model reading the answer key.

### Corpus label provenance (exact-class ground truth)

| Corpus | scorable | positives | negatives | label source |
|---|--:|--:|--:|---|
| WebGoat | 5 | 3 | 2 | public WebGoat lessons + corpus labels |
| DVWA | 12 | 8 | 4 | public DVWA modules + corpus labels |
| PixelMart | 17 | 11 | 6 | pre-existing hand-seeded manifest (PR-2), sanitized corpus |
| Juice Shop | 17 | 12 | 5 | public Juice Shop knowledge; NoSQL/open-redirect/CORS cases left `inconclusive` (no in-vocabulary exact class) |
| blind-target-2 | 0 | — | — | **not scored** — answer key off-limits; run for raw detection volume only |

**Honesty caveats (unchanged from the reviews):** 34 labeled positives / 17
negatives across 4 apps is a *small* corpus (R15) — enough to expose gross
precision/recall behavior, not to resolve small margins. DVWA/WebGoat/Juice Shop are
public training apps and may appear in the model's training data (contamination we
cannot rule out). Exact-class labels seeded from public docs carry label-error risk.
These numbers are a **detection-stage** signal on a small, partly-public corpus with
a local 8B model — not a measure of end-to-end exploitation or of blind-target recall.

## Results (mean of 3 repeats) — all 5 complete

| Corpus | exact-class P | exact-class R | F1 | raw findings/run | #exchanges | over-alert × | baselines OK |
|---|--:|--:|--:|--:|--:|--:|---|
| WebGoat | 0.500 | 1.000 | 0.667 | ~17 | 7 | 2.4× | ✓ |
| DVWA | 0.233 | 1.000 | 0.378 | ~48 | 14 | 3.4× | ✓ |
| PixelMart (sanitized) | 0.204 | **0.714** | 0.317 | ~112 | 22 | 5.1× | ✓ |
| Juice Shop | 0.239 | 0.778 | 0.366 | ~215 | 50 | 4.3× | ✓ |
| **POOLED (micro, 4 corpora)** | **0.229** | **0.811** | **0.357** | — | 93 | — | ✓ |
| blind-target-2 | n/a — raw only | n/a | — | ~80 | 42 | 1.9× | n/a |

Pooled micro across the 4 scored corpora: tp=30, fp=101, fn=7. Per-repeat variance is
negligible (e.g. DVWA P = 0.235/0.235/0.229). Every run's indiscriminate baselines
FAIL the gate (`discriminating=True`) — certified exact-class numbers, not the old
any-alert theatre. **blind-target-2** carries no exact-class ground truth (answer key
off-limits), so it is not scored; its ~80 findings/run for 42 exchanges is reported as
raw detection volume only (the same ~2× over-alert ratio holds).

### What the numbers say (consistent across all 4 scored corpora)

**High recall, very low precision — the tool surfaces the real vulnerabilities but
buries them in false positives (3–8× more findings than exchanges).**

- **Recall** is 1.0 on the small WebGoat/DVWA, **0.71–0.78 on the larger PixelMart
  (de-contaminated) and Juice Shop**; pooled **0.81**. The recall gap is a robust,
  cross-corpus finding: on BOTH PixelMart and Juice Shop the model misses exactly the
  reasoning-heavy classes — `auth_bypass` (R=0 on both), `business_logic` (R=0 on
  both), `ssrf` (R=0 on both). It reliably catches pattern-matchable classes (sqli,
  xss, path_traversal, jwt, csrf, idor) and misses the ones that need multi-step
  inference about intent/state. PixelMart's drop from an effective 1.0 to 0.71 is the
  integrity headline: with PR-13's answer-key markers stripped, the model can no
  longer "read" those reasoning-heavy answers.
- **Precision** is 0.20–0.50 (pooled 0.23), driven down by the SAME two "catch-all"
  classes on every corpus: `security_misconfiguration` (DVWA 11 FP with ZERO support
  — pure noise; PixelMart 16; Juice Shop 14) and `info_disclosure` (DVWA 9 / PixelMart
  11 / Juice Shop 8). Strip those two and the concrete-class precision is respectable
  (sqli P=0.5–0.75, csrf P=1.0, path_traversal P=1.0, idor P=0.43–0.5).
- **It fires on the tested-secure controls**: for sqli/xss/idor/command_injection/
  path_traversal, `fp_on_tested_negative_control ≥ 1` — the model cannot tell a
  secure endpoint from a vulnerable one of the same class.
- **Degradation was visible, not hidden** (PR-7 working live): several DVWA runs hit
  `Ollama HTTP 500: token repeat limit` on the critique pass and logged "shipping
  findings unreviewed" rather than silently dropping the stage.

## Competitive comparison (published numbers, retrieved 2026-09-25)

**These are NOT comparable to the numbers above.** Every published result below
measures *end-to-end exploitation* (retrieve a hidden flag) or *bug-bounty volume*,
not passive exact-class detection on captured exchanges. No apples-to-apples
web-detection precision/recall leaderboard exists across these tools (same targets,
access, budget, adjudication). They are context for capability class, not a ranking.

| System | Benchmark | Published result | Task type |
|---|---|---|---|
| PentestGPT v1.0 | XBOW-104 validation suite | **86.5%** (90/104 flags) | end-to-end exploit |
| MAPTA | XBOW-104 | **76.9%** overall (SSTI 85%, SQLi 83%, XSS 57%, blind-SQLi 0%) | end-to-end exploit |
| PentestGPT (paper) | 10 HTB machines, 103 subtasks | 71.8% (Llama-3-8B) / 72.8% (Gemini-1.5) / 78.6% (GPT-4) subtasks | guided pentest subtasks |
| XBOW | HackerOne US leaderboard, Jun 2025 | #1, ~1,060 reports (volume; many dup/informational) | live bug bounty |
| ARTEMIS | live network pentest, Dec 2025 | 9 valid vulns, 82% valid-submission, 2nd/11 | live pentest |
| (agent) | CVE-Bench, Mar 2025 | 13% zero-day / 25% one-day | real-CVE exploit |
| Burp AI / Burp AT (PortSwigger) | — | no published precision/recall; user-invoked assistance / agentic testing inside Burp Pro | assistant / agent |

The closest *capability-class* comparator to this project's local `qwen3:8b` is
PentestGPT's **Llama-3-8B** row (71.8% subtask completion) — but that is guided
exploit subtasks, a strictly harder and different task than passive detection.

Sources: [XBOW pentest](https://xbow.com/pentest), [MAPTA / Multi-Agent Pentesting AI for the Web](https://arxiv.org/html/2508.20816v1), [PentestGPT USENIX'24](https://www.usenix.org/system/files/usenixsecurity24-deng.pdf), [PentestGPT benchmark README](https://github.com/GreyDGL/PentestGPT/blob/main/benchmark/README.md), [AI pentest benchmark scoreboard 2026](https://www.stingrai.io/blog/ai-pentest-benchmark-results-2026), [Burp AI](https://portswigger.net/burp/documentation/desktop/burp-ai), [Burp AT](https://portswigger.net/burp/burp-at).

## Verdict (final — all 5 corpora)

**This run empirically confirms what the two principal reviews argued and what this
session's strict-scoring work was built to expose. Pooled exact-class P=0.23, R=0.81
across 4 labeled corpora (30 tp / 101 fp / 7 fn).**

1. **R06 was right.** The old `recall(any)=1.0` headline was meaningless. Under exact-
   class scoring the same pipeline scores **P≈0.20–0.50, R≈0.71–1.0** — a high-recall,
   low-precision *detection triage* profile, not "perfect."
2. **Contamination was real and material (PR-13/R15).** De-contaminating PixelMart
   dropped recall from an effective 1.0 to **0.71**, and the new misses are precisely
   the reasoning-heavy classes (auth_bypass, business_logic, ssrf). Any pre-sanitization
   PixelMart recall was inflated by the answer-key leak.
3. **The honest product profile:** a local-8B (`qwen3:8b`) copilot that reliably flags
   pattern-matchable vulns (SQLi, XSS, path traversal, JWT, CSRF) with strong per-class
   precision, but drowns them in `info_disclosure`/`security_misconfiguration` catch-all
   noise and cannot separate secure from vulnerable endpoints of the same class. It is a
   **recall-oriented triage layer that needs heavy human filtering** — exactly the
   "passive suggestions under expert supervision" the first review recommended, now
   measured rather than asserted.
4. **Not comparable to the competitor numbers.** XBOW/PentestGPT/MAPTA (77–86% on
   XBOW-104) measure end-to-end *exploitation*; this measures passive *detection* on a
   small, partly-public corpus. Different task, different denominator. The one honest
   cross-read: a local 8B model does creditable detection recall but is not an autonomous
   exploiter, and its precision needs work before the output is trustworthy unfiltered.

**Highest-leverage fixes this data points to** (feeding the next improvement cycle):
raise precision by taming the two catch-all classes (`info_disclosure`,
`security_misconfiguration`) — gate them behind stronger evidence or a confidence floor
— and add a same-class secure-vs-vulnerable discriminator so the tool stops firing on
clean controls. Both would lift precision far more than any recall work. Separately,
the reasoning-heavy recall gap (auth_bypass / business_logic / ssrf consistently
R=0) is unlikely to close with an 8B local model alone — it wants either a stronger
model on those classes or class-specific active probes.

### Reproduce
`testing/strict_benchmark.py <corpus.ided.json> <manifest.labels.json> --n-runs 3
--out <path>` — replays a corpus through the live model and emits the strict
scorecard + baseline gate. Manifests: `testing/labels/{webgoat,dvwa,juiceshop,
pixelmart}.labels.json`. Raw run artifacts: `reviews/2026-09-25/benchmark/
*_strict_3x.json`. Model `qwen3:8b`, shipped-default passive config, 2026-09-25.
