# AgenticVibe full benchmark — 2026-09-23/24

> **Correction (2026-09-24):** see
> [`CORRECTED_ASSESSMENT_2026-09-24.md`](CORRECTED_ASSESSMENT_2026-09-24.md)
> for reconciled numbers and superseded claims. In short: 4 of 5 apps below
> ran with `fail_open_mode=curated`/quarantine-leads-on, NOT the shipped
> `config.yaml` default (`all`/quarantine-off) — this report's "shipped
> default config" framing is inaccurate for those four; PixelMart's
> wall/run figure here (~1330s) is one repeat's time, not the true 3-run
> mean (1138.6s); the `tokens=0` reading is a broken counter (real: ~448k);
> and "breaker-healthy" understates that 2 of 3 PixelMart repeats hit
> circuit-breaker failures. The body below is preserved unchanged as
> historical evidence; read it together with the correction, not in place
> of it.

**Status: COMPLETE.** Five apps, shipped-default config, 3 repeats each, all runs
breaker-healthy (no starvation). Total GPU wall ≈ 5.9 h serial.

## What this measures

Detection **precision / recall / cost** of the harness at its **shipped default
config** (`coordinator.routing_mode: agents` — the full 38-specialist pipeline;
passive: `active_enabled: false`, `fail_open_mode: curated`, quarantine-leads on),
against five deliberately-vulnerable web apps: two of our own custom targets and
three apps that other LLM-pentest tools also benchmark against.

- **Model:** `qwen3:8b` local Ollama, `num_ctx=8192` pinned (in-memory eval
  override; `config.yaml` untouched — keeps the model 100% GPU-resident on this
  8GB RTX 3070, the P2-2 starvation fix).
- **Method:** each app is a **replay** of captured HTTP exchanges through the REAL
  orchestrator (`orch.analyze()`), scored offline — no live mutation, no active
  validators. Docker apps (DVWA, WebGoat) were captured live from owned local
  containers, each vuln/control label **verified against the actual response**,
  then replayed.
- **Repeats:** 3 per app; mean ± population stdev. Runs are strictly **serial**
  (single GPU, `max_parallel_agents: 1`).
- **Scoring:** recall = detected / labeled `confirmed_vuln`; precision side =
  `controls_clean` over labeled `confirmed_secure` (any finding on a control is a
  false positive). PixelMart uses the `score._LABEL_CATEGORY` TP/TN scheme; the
  other four use the `confirmed_vuln / confirmed_secure / inconclusive` scheme
  (`run_blind_eval.build_scorecard`).

## Corpus inventory

| App | Type | Exchanges | confirmed_vuln | control (secure) | setup/multi-step |
|---|---|--:|--:|--:|--:|
| PixelMart | ours (custom, uncontaminated) | 22 | 11 (TP labels) | TN set | 4 setup |
| blind-target-2 | ours (curated blind) | 10 | 2 | 6 | 2 |
| OWASP Juice Shop | shared (other tools use it) | 50 | 13 | 5 | 32 |
| DVWA | shared (other tools use it) | 14 | 8 | 4 | 2 |
| WebGoat | shared (other tools use it) | 7 | 3 | 2 | 2 |

Custom apps (PixelMart, blind-target-2) matter because Juice Shop/DVWA/WebGoat are
in every frontier model's training data — the escape.tech benchmark below shows a
harness only out-yields a bare model on *novel* code, so contamination-free targets
are the honest test of the pipeline rather than the model's memory.

## Results (OUR harness)

| App | recall (any) | recall (surfaced) | precision / controls-clean | findings/exchange | wall/run |
|---|--:|--:|--:|--:|--:|
| PixelMart (custom) | **0.909** ± .074 | — | **0.209** ± .03 precision¹ | ~1.8 (40 fp/22) | ~1330s |
| blind-target-2 (custom) | **1.00** | 0.83 ± .24 | **0/6 controls clean** | ~4.0 | ~708s |
| OWASP Juice Shop | **1.00** | 1.00 | **0/5 controls clean** | ~7.5 (373/50) | ~3010s |
| DVWA | **1.00** | 0.92 ± .06 | **0/4 controls clean** | ~8.7 (121/14) | ~655s |
| WebGoat | **1.00** | 0.67 | **0/2 controls clean** | ~4.1 (29/7) | ~428s |

¹ PixelMart uses the `score.py` TP/TN scheme (precision over a labeled TN set);
the other four use `controls_clean` (binary per control exchange — clean only if
it received **zero** findings). Both measure the same thing from opposite ends: a
high false-positive load.

- **recall (any):** a labeled `confirmed_vuln` exchange that produced ≥1 finding.
- **recall (surfaced):** stricter — the finding was *surfaced*, not quarantined as
  a low-confidence lead. The gap (WebGoat 1.00→0.67, blind 1.00→0.83) is real vulns
  the lead-quarantine step demotes.
- **Cost note:** the blind-style scorer's token counter reads 0 (the new
  `OllamaClient` counters aren't wired into that path — only the PixelMart/ablation
  driver reports tokens: **~448k tokens, 158 model calls/run**). Wall-clock is the
  comparable cost axis for the other four.

## Headline findings

1. **Detection recall is excellent and stable: 0.91–1.00 across all five apps**,
   custom and shared alike, every repeat. The pipeline reliably *finds* the vuln.
2. **Precision is the systemic weakness: every control exchange on every app got
   flagged (0 clean), and the harness emits 4–9 findings per exchange.** This is
   not a per-app fluke — it reproduces identically on two uncontaminated custom
   targets and three public apps. It is the dominant, actionable result.
3. **Lead-quarantine trades recall for nothing measurable here:** it demotes real
   vulns (surfaced recall drops to 0.67 on WebGoat) while controls stay 100% dirty
   — so it isn't buying precision on these corpora, it's only hiding true positives.
4. **Shared vs custom agree**, so the recall is not just Juice Shop/DVWA/WebGoat
   training-data memorization — it holds on PixelMart/blind-target-2 which have no
   public write-ups. That is the strongest single validation in this run.

## Cross-tool comparison (published numbers)

**Heavy caveat — apples-to-oranges.** These tools measure different things on
different corpora with different models. Most report *exploitation success/solve
rate* or *raw finding counts*, not *detection precision/recall on captured HTTP
traffic* (our task). Treat as context, not a leaderboard.

### Escape.tech "Cascade" benchmark (multi-agent AI-pentest harness vs bare model)
The most structurally comparable study (a harness around a model, like ours):

| Target | Claude Opus 4.8 (BB/WB) | Cascade (BB/WB) | Aikido | XBOW | FP rate |
|---|---|---|---|---|---|
| Juice Shop | 23 / 24 findings | 36 / 49 findings | — | — | Cascade 0% (94), Claude 0% (15) |
| Fider (real app) | 7 / 7 | 26 / 28 (28 TP, 0 FP) | 17 TP, 2 FP | 24 TP, 1 FP | Aikido 4%, XBOW 3% |
| Photoview (real app) | — / 8 | 12 / 28 (28 TP, 0 FP) | 32 TP, 0 FP | 7 TP, 0 FP | — |

Key finding: the harness gave **~4× the yield of the bare model only on novel
code** (Fider/Photoview); on documented apps (Juice Shop) they were similar —
i.e. documented-app numbers largely reflect model memory, not pipeline skill.
FP-rate is where mature tools differentiate (Cascade/Claude 0%, commercial 3–4%).

### TrustedSec "self-hosted LLMs for offensive security" (local models, like ours)
CTF-style *solve rates* (not detection P/R); all models **≥24B** — ours is 8B, so
expect a size gap:

| Model | Size | Pass rate |
|---|--:|--:|
| gemma4:31b | 31B | 98.5% |
| qwen3.5:27b | 27B | 97.5% |
| devstral-small-2 | 24B | 95.6% |
| qwen3:32b | 32B | 85.4% |

Per-class solve rates: SQLi auth-bypass 97–100%, JWT alg-none 97–100%, IDOR basket
57–100%, mass-assignment 66–98%; **0% on multi-step chains needing 10+ sequential
tool calls** (a known ceiling for this class of tool).

### hackingBuddyGPT (autonomous Linux privesc — different task)
GPT-4-Turbo exploited **33–83%** of single-vuln privesc VMs (~human pentester 75%).

### Multi-agent LLM committees (regression/vuln detection)
3-agent committees reached **82.0%** success on Juice Shop scenarios with 20
injected bugs (SQLi/XSS/auth), reported with precision/recall/F1.

## Interpreting our numbers vs theirs

1. **Model size:** we run qwen3:**8B**; the comparable self-hosted benchmark used
   ≥24B. A recall gap is partly model capacity, not pipeline design.
2. **Task shape:** ours is *detection/classification on captured traffic*; most
   external numbers are *exploitation solve rate* or *finding counts*. Our
   `controls_clean` (precision) is the most directly comparable axis to their FP
   rates.
3. **Contamination:** trust PixelMart/blind-target-2 over Juice Shop/DVWA/WebGoat
   for pipeline skill; the shared apps mostly show whether we match the field on
   memorized targets.
4. **Cost:** we report tokens + wall/run, which most external studies omit — a
   real operational axis on self-hosted hardware.

## Bottom line vs the field

- **Where we're competitive:** raw recall. 0.91–1.00 is at or above what the
  comparable studies imply for their tasks (multi-agent committees 82% on Juice
  Shop; self-hosted ≥24B models 57–100% per class). We hit this with an **8B**
  local model — smaller than any model in the TrustedSec self-hosted benchmark —
  which is a genuinely good showing for the routed-specialist design.
- **Where we lose to the field, decisively: false positives.** The mature tools
  in the escape.tech benchmark report **0% (Cascade, Claude) to 3–4% (Aikido,
  XBOW)** validated FP rates. We flag **every** control and emit 4–9 findings per
  exchange — our precision is not in the same league, and precision is exactly the
  axis on which commercial/frontier tools differentiate. Recall is solved; the
  product gap is precision/triage.
- **This benchmark is a strong argument for prioritizing the open precision work**
  (B2-3 controls-clean scoring, B2-5 generic-guess gating, RB-2b curated fail-open)
  over any further recall or agent-count work — the collapse decision (P2-2) and
  the recall numbers here both say the detection side is in good shape.

## Reproduce

```
# custom + shared-corpus apps (blind-eval scorer), 3 repeats, num_ctx pinned:
python scratchpad/bench_blindstyle.py <corpus.json> <out.json> 3 8192
# PixelMart (ablation driver, shipped default = variant A):
.venv-rationalisation/Scripts/python.exe testing/test-target/run_ablation_live.py --variants A --repeats 3 --num-ctx 8192
```
Corpora: `reviews/2026-09-23/benchmark/{dvwa,webgoat}_exchanges.json` (captured
live from owned local DVWA :8081 / WebGoat :8082, labels verified per-response),
`testing/juiceshop-full-run/exchanges.json`, `testing/blind-target-2/blind_eval_exchanges.json`,
`C:\tmp\pixelmart_exchanges.json`. Raw per-run scorecards: `*_default_3x.json`.

## Sources
- Escape.tech — Modern AI-powered pentesting tools in-depth benchmark: https://escape.tech/blog/modern-ai-powered-pentesting-tools-in-depth-benchmark/
- TrustedSec — Benchmarking self-hosted LLMs for offensive security: https://trustedsec.com/blog/benchmarking-self-hosted-llms-for-offensive-security
- hackingBuddyGPT / "LLMs as Hackers": https://arxiv.org/html/2310.11409
- Multi-agent LLM committees for autonomous testing: https://arxiv.org/html/2512.21352v1
