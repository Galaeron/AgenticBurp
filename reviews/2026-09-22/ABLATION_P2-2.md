# A-F architecture ablation — P2-2 owner/live run (via RB-7)

**Owner-reported / VERIFIED-in-run, with an important reliability caveat that
blocks a confident keep/collapse decision — read "What this run can and
cannot tell us" before the numbers.**

## Exact commands

```
cd C:\Users\arthu\Documents\AgenticVibe
.venv-rationalisation\Scripts\python.exe testing\test-target\run_ablation_live.py --variants A,B,C,D,F --repeats 1
```

`testing/test-target/run_ablation_live.py` is a new owner-run driver (not part
of `harness/ablation_harness.py`, which ships no `__main__` on purpose — see
its own docstring). It plugs a real, unstubbed Ollama model into RB-7's
existing variant definitions, `RunMetrics`/`aggregate`/`render_table`, and
`run_variant_async` (which itself scores via `testing.score.score()` — no
second scoring implementation). Each `(variant, repeat)` gets a fresh
state+cache DB (`C:\tmp\ablation_live\<variant>\run<i>\`), because
`harness/cache.py` keys a cached `AnalysisResponse` by exchange-content-hash +
model only, not by config — a shared cache across variants would let one
variant's real result silently get served back for another's differently-
configured run.

Because of the reliability issue below, **D and F were each re-run alone, in
their own process**, after the first combined `A,B,C,D,F` invocation
contaminated their rows (details in "What went wrong" below). B's number in
this report is from its own earlier standalone run, not the combined one.

## Checkout

- Commit `0f047e80bf1216bd2a7f3efb1d25481e237bf13a` (`reconciliation-backlog`),
  `harness/config.yaml` and `harness/ablation_harness.py` untouched by this
  session — new files are `testing/test-target/run_ablation_live.py` (this
  driver) plus untracked pre-existing scratch files unrelated to this run.
- Model: `qwen3:8b` (local Ollama). `ollama ps` during this session showed
  `41%/59% CPU/GPU` — the model does not fully fit in this GPU's VRAM.
- Corpus: `C:\tmp\pixelmart_exchanges.json`, 22 exchanges (4 unlabeled
  "setup: ..." + 12 `TP*` + 6 `TN*`) captured previously by
  `testing/test-target/capture_exchanges.py` against a live PixelMart
  instance. This run does **not** need PixelMart running — it replays the
  captured exchanges, same shape as `blind-target-2`'s driver.
- Ground truth: `testing.score._LABEL_CATEGORY` (TP1..TP12 minus TP8,
  matched by each exchange's label prefix) — 11 scored TP labels; `ANSWER_KEY.md`
  in that directory was not read for this run.
- E (minus-graph-loop) was **not run**: `ablation_harness.NO_GRAPH_RESIDUAL`
  documents that `analyze()` (the only entry point every other variant here
  goes through) never reaches the graph loop (`investigate_engagement`,
  a separate entry point) — distinguishing E from A needs an owner-run,
  multi-exchange engagement corpus this session doesn't have. Its row is
  omitted rather than printed as an unmeasured duplicate of A.

## What went wrong (read this before the table)

The first invocation ran all five variants (A,B,C,D,F) sequentially in **one
process**. Partway through variant A, three consecutive specialist-agent
calls each stalled for the full 240s timeout (720s total, 14:33:23–14:45:23)
before failing, which tripped `harness.circuit_breaker`'s shared `"ollama"`
breaker from `CLOSED` to `OPEN`. This is not a new/unknown failure mode —
`harness/config.yaml`'s own committed comments (lines ~24-33) already
document a near-identical prior incident on this same hardware, warning
explicitly: *"Once tripped, the breaker silently zeroed out every remaining
agent for the rest of that run with no error surfaced anywhere in the
response -- empty findings that looked identical to 'the model found
nothing.' ... if timeouts recur at 240s, narrow further from here rather
than assuming this alone is sufficient."* `concurrency.max_parallel_agents`
is already lowered to `1` (fully serialized dispatch) from that prior
incident — evidently not sufficient to eliminate the failure mode on this
box.

Because the circuit breaker is a **process-wide shared singleton**
(`circuit_breaker.get_ollama_circuit_breaker("ollama")`, deliberately shared
so a short-lived client still accumulates failures — see its own
docstring), the breaker was still open when B, D, F started immediately
after A in the same process, in fact well inside its 60s cooldown. This
silently starved every real agent call in B/D/F of the rest of that
invocation, and all three degenerated to **exactly** C's (zero-LLM,
deterministic-only) numbers.

**Diagnosis, not guesswork:** a follow-up single-exchange diagnostic (TP1,
full logging) reproduced the mechanism directly: 3 sequential agent calls
each timed out at 240s (720s total), the breaker flipped `CLOSED -> OPEN`,
and every one of the 4 remaining dispatched agents for that exchange then
returned in milliseconds with **zero real findings** — the only non-empty
"findings" in that exchange's 10 agent-report objects were deterministic-leg
classes (`sqli`, `info_disclosure`, `verbose_error_disclosure` — the exact
same classes C's zero-agent baseline produces), not genuine LLM output.

**This reproduced twice, not once.** D and F were each re-run alone in a
fresh process (so no cross-variant breaker contamination was possible) and
**both** hit the identical pattern independently: wall time 723.5s / 723.9s,
`time_to_first_finding` 720.45s / 720.49s (i.e. the entire run was consumed
by the initial timeout cascade before anything real got through, on
whichever exchange happened to be first), and both landed on C's exact
tp/fp/fn. That consistency across two independent processes says this is a
**systematic, reproducible limitation of running this 36-agent
architecture's default routing on this hardware**, not a one-off fluke.

A's own run was **less** degraded — it got real findings across several
exchanges (`time_to_first_finding = 99.3s`, and its tp/fp differ from C's) —
apparently a later-stage failure in the adversarial critique pass rather
than the earliest agent dispatch itself (`Critique pass ... shipping
findings unreviewed` × 5 exchanges near the end of its run, not from the
start). Its detection numbers are real but the critique review is missing
for ~5/22 exchanges.

## Result

| variant | precision | recall | FP | TP | FN | wall(s) | ttff(s) | status |
|---|--:|--:|--:|--:|--:|--:|--:|---|
| A current | 0.067 | 0.182 | 28 | 2 | 9 | 1242.8 | 99.3 | real, but critique unreviewed on ~5/22 exchanges (see above) |
| B general-model (forced `sqli`) | 0.105 | 0.364 | 34 | 4 | 7 | 532.8 | 2.4 | **clean** — 0 errors, standalone process |
| C deterministic-only (0 agents) | 0.080 | 0.182 | 23 | 2 | 9 | 3.2–79.2\* | 0.2 | **clean** — reproduced identically across 2 independent runs |
| D minus-critique | — | — | — | — | — | 723.5 | 720.5 | **NOT a valid measurement** — degenerated to C's exact floor via the circuit-breaker starvation above |
| F strong-single (curated fail-open) | — | — | — | — | — | 723.9 | 720.5 | **NOT a valid measurement** — same failure, reproduced independently |
| E minus-graph-loop | — | — | — | — | — | — | — | not run — residual, needs an owner-run engagement corpus (see above) |

\* C's wall time varied 3.2s→79.2s across its two runs (both giving identical
tp/fp/fn — C disables every agent by name, so its detection result cannot
depend on the breaker either way). This variance is itself corroborating
evidence for the mechanism above, not noise: C's coordinator still attempts
a real routing call per exchange before discovering "no-valid-targets"; its
first (fresh-breaker) run paid ~3.6s/exchange for 22 real, successful
coordinator calls (≈79s total), while its second run — executed immediately
after A had left the shared breaker OPEN — had those same 22 calls rejected
in-process near-instantly instead of reaching Ollama at all (≈3.2s total).

D and F's rows report metrics as `—` rather than the raw
0.08/0.182/23/2/9 numbers `render_table` would otherwise print, specifically
so this table cannot be misread as "D and F measured the same as C" —
they measured **nothing usable**; the identical numbers are an artifact of
total LLM starvation, not evidence about the no-critique or curated-routing
architectures.

## What this run can and cannot tell us

**Cannot:** answer P2-2's central question (does the ~36-agent design with
critique/graph beat a smaller set, on detection quality) — the two variants
built specifically to probe that (D, F) produced no usable data, and even A
(the baseline every comparison is relative to) has a documented partial
critique failure. Do not use this run's numbers to justify collapsing (or
keeping) the specialist-agent design; both directions would be an
overclaim.

**Can, with confidence** (reproduced twice, independently, with a clean
mechanistic diagnosis): **on this hardware, any variant that dispatches
several sequential specialist-agent LLM calls per exchange has a real,
non-negligible chance of a single stalled call cascading into total,
silent LLM starvation for the rest of that run** — worse than a slow run,
because nothing in the response distinguishes "the model found nothing" from
"the model was never actually asked." This is itself directly relevant
evidence for P2-2: it is an operational fragility that scales with agent
count and that a single-agent (B) or zero-agent (C) design does not share.
`harness/config.yaml` already anticipated exactly this risk and had already
been tuned once (timeout 240s, `max_parallel_agents: 1`) in response to a
prior incident; this run shows that tuning is not sufficient on this box.

**One clean, if narrow, data point:** B (one forced, real agent + normal
critique/pipeline machinery around it) ran in 533s with zero errors and hit
4/11 TPs (recall 0.364) — a higher raw recall than either A's
critique-degraded run or C's zero-agent floor (both 0.182), at the cost of
more false positives (34 vs A's 28 / C's 23). This is one sample, not a
trend, and should not be read as "one agent beats the full pipeline" —
particularly since A's own recall here is itself an underestimate of a
healthy A run.

## Recommendation before re-attempting A/D/F

Per `config.yaml`'s own note, "narrow further from here" — concretely, before
spending more GPU time on this ablation:
1. Verify `ollama ps` shows the model fully GPU-resident (not `41%/59%`
   split) and no other load, or free up VRAM.
2. Consider raising `ollama.timeout_seconds` further, or reducing how many
   agents the coordinator routes to per exchange for a bounded ablation-only
   config override (not the committed default).
3. Add a runner-level circuit-breaker-state check (or a fresh circuit
   breaker per run, mirroring the fresh state/cache DB already done here) so
   a starvation cascade in one repeat cannot silently poison the numbers
   without at least being flagged in the output, the way this report had to
   reconstruct after the fact.

## Not done

- **E (minus-graph-loop):** needs an owner-run, multi-exchange engagement
  corpus through `/investigate` — out of scope for this `analyze()`-only
  driver (see `NO_GRAPH_RESIDUAL`).
- **Repeats ≥5 / variance:** `run_ablation`'s `repeats` parameter supports
  this, but even a single repeat of A/D/F cost 700-1250s and two of five hit
  the starvation failure above; a trustworthy variance pass needs the
  reliability fix above first.
- **A clean D/F measurement:** blocked on the same reliability issue.

Raw results: `C:\tmp\ablation_results.json` / `C:\tmp\ablation_table.md`
(local/owner artifacts, not committed, matching this project's existing
convention for generated results files) — note these reflect only the
**last** invocation run (F alone); A/B/C/D's numbers live in this report and
in the session transcript, not in a single merged JSON, because each
variant that needed isolation was run as a separate process against the
same output path.
