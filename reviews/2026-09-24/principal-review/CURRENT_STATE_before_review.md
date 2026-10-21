# Current state — 2026-09-22

## Checkout

Branch `reconciliation-backlog`, ahead of `main`, 0 behind. HEAD `8dd52d2`.
The agents-subsystem refactor, the precision & blind-control sprint (Items
1–3, base `02de8bf`), the Astra T02–T08 workstream, and the 2026-09-21
consensus-batch RB-1..RB-8 items are all committed and reconciled into this
branch. Full per-item Result lines (evidence tags, tests, commits) live in
[IMPROVEMENT_BACKLOG.md](IMPROVEMENT_BACKLOG.md) — this file tracks current
status and pointers only, not session history.

**Loop re-opened (2026-09-22): Batch 2 (B2-1..B2-5)** filed in
[IMPROVEMENT_BACKLOG.md](IMPROVEMENT_BACKLOG.md) from the P0-3/P2-2 live runs —
offline, loop-consumable. Pick order B2-1→B2-2→B2-3→B2-4→B2-5 (reliability:
B2-1 circuit-breaker `degraded` flag, B2-2 per-run breaker isolation; precision:
B2-3 issue-level controls-clean, B2-4 REJECT stubbed-testable, B2-5 gate the
low-confidence FP guesses). **B2-1 done** (`345fcf8`: `agents_circuit_open` on
`AnalysisResponse` + engagement `errors`→`degraded`). **B2-2 LOOP half done**
(`7927d7e`: opt-in `scoped_ollama_breaker`/`reset_ollama_circuit_breaker`/
`raise_if_ollama_starved` seam; OWNER half — hardware timeout/GPU tuning +
live-driver wiring — stays open). **B2-3 done** (`e05c821`: issue-level
`controls_clean` + `ambiguous_control_urls` exclusion + `per_control_drivers` in
`build_scorecard`, raw metric kept). **B2-3b done** (`e560f6e`: corrects B2-3's
url-only attribution — control/vuln keyed on `(method.upper(), url)`, explicit
vuln-label set, host-wide banners split into `host_level_issues_on_controls`,
issue-level counts + variance + console summary; the shared GET-vuln/DELETE-control
url no longer hides the DELETE control's FP). **B2-4 LOOP half done** (`d1f6390`:
`cross_identity_reject` proven offline against the existing downgrade block — no
production change — + recorded in the scorecard; OWNER/LIVE REJECT-on precision
run stays open). **B2-5 done** (`53d6d66`: `is_low_confidence_generic_guess`
sibling + `reporting.gate_low_confidence_generic` flag shipped OFF, routes
unconfirmed low-confidence generic-class guesses to leads; recall guard airtight,
flag-off byte-for-byte no-op). **Batch 2 LOOP halves all complete.** **ER-1 done**
(`ad6e829`: optional `max_duration_s` wall-clock dimension on `EffortBudget`).
**ER-2 done** (`0ad91e6`: one canonical `RUN_SUMMARY` EvidenceLedger event per
standalone `analyze()` run). **ER-4 done** (`bf8cea3`: config-gated `confirm_replay`
DEFAULT OFF — an active ssrf/ssti/command_injection leg re-runs its confirming
`validate()` once and downgrades to provisional on disagreement; OFF is
byte-for-byte). **All loop-consumable Batch 2 + ER items are now `[x]`.**
**P2-2 ablation: CLOSED `[x]` 2026-09-23 — COLLAPSE, now evidence-backed** (clean
A/B/C/G re-run; G holds recall+precision vs the full 38; see the P2-2 section
below). **AR-1 done** (`994e5a0`: opt-in `coordinator.routing_mode: agents|families`
collapses per-agent model calls into 6 family calls; default `agents` = today's
behavior = the byte-for-byte REVERT state; ships OFF, ablation variant G — this is
what the re-run measured). **AR-2 LOOP half done** (`077b772`: per-run breaker +
fail-open counters on `RunContext`; the OWNER live-driver wiring is now done — the
09-23 driver uses per-run breaker isolation + loud starvation exclusion). **AR-3
done** (`07d650b`: exchange provenance — `capture_id`/`exchange_id`/`run_id` +
`finding_observations` link table; scorecard now attributes a shared-url control to
its OWN exchange, closing the B2-3b follow-on; additive/back-compat, dedup
unchanged). **AR batch complete.** Also landed 2026-09-23 (uncommitted): opt-in
`ollama.num_ctx` context pin (default off; the VRAM/starvation fix) + read-only
model-call/token counters on `OllamaClient`. **No loop-consumable items remain** —
every `[ ]` is OWNER/LIVE or deprioritized (see below). Full suite 2551 OK / 2 skip.

**P2-2 CLOSED `[x]` (2026-09-23) — decision=COLLAPSE, now evidence-backed.** The
clean A/B/C/G re-run (3 repeats, `num_ctx=8192`, 0/12 starved) shows G
(agent-families) holds detection quality vs A (full 38): recall 0.818±0.074 vs
0.788±0.043, precision 0.191±0.019 vs 0.176±0.004 — parity within noise — at ~10%
fewer model calls / ~6% fewer tokens / ~15% less wall. Ladder A≈G ≫ B (0.394) ≫ C
(0.182). Results:
[reviews/2026-09-23/ABLATION_P2-2_RERUN.md](reviews/2026-09-23/ABLATION_P2-2_RERUN.md).
The 2026-09-22 attempt was invalidated by a VRAM-spill breaker cascade (qwen3:8b
at its 32768 default = 10GB/41%-CPU); root-caused and fixed by pinning
`num_ctx=8192` (6.2GB/100% GPU/~3s per call) — A's recall recovered 0.182→0.788
from that alone, so the old numbers are not comparable. Cost win is MODEST (do not
oversell). Enable via `config.local.yaml` `coordinator.routing_mode: "families"`;
committed default stays `"agents"` (byte-for-byte revert). ER-3/ER-5 (new
detection surface) stay deprioritized under the collapse decision — the freeze
resolved *against* adding surface, they are not auto-unblocked by P2-2 being
`[x]`. The RB-1..RB-8 consensus batch is closed.

**External-review borrow batch (2026-09-22): ER-1, ER-2, ER-4** loop-consumable
(pick order ER-1→ER-2→ER-4), filed from a user-requested eval of external
LLM-pentest projects (burpai / hackingBuddyGPT / Strix) against this codebase:
ER-1 wall-clock dimension for `EffortBudget`, ER-2 canonical per-run ledger trace
summary, ER-4 optional reproduction-replay determinism gate. ER-3 (timing-based
blind leg) and ER-5 (per-class agent methodology priming) are filed but
DEPRIORITIZED — P2-2 decided COLLAPSE, so their new-surface freeze resolved
against them; leave `[ ]`, do not pick unless the collapse is shown to hurt recall.
Most borrow ideas were already present here in more mature form (leg-tiered gate,
evidence ledger, token `EffortBudget`) and were deliberately not re-filed; B2-1/
B2-2 already cover breaker-`degraded`/isolation, so ER items reuse them.

**Architecture rebalance batch (2026-09-22): AR-1..AR-3** loop-consumable (pick
order AR-2→AR-3→AR-1), filed from a user-requested architecture review: AR-2
run-scoped breaker + fail-open counters on `RunContext` (and live-driver wiring),
AR-3 exchange provenance on findings, AR-1 opt-in agent-family routing as P2-2's
collapse candidate (ablation variant G, ships OFF). The overlapping evaluation
layers are already P1-3, which gained new evidence rather than a duplicate item.
Placement relative to B2-4/B2-5/ER is the owner's call; recommended before the
P2-2 re-run.

## Verified here (2026-09-21, current HEAD)

From repo root, `.venv-rationalisation/Scripts/python.exe` (Python 3.12.14,
isolated): `-m harness.suite smoke` = **90 OK**, exit 0; `-m harness.suite
full` = **green, exit 0** (unittest **2482 OK, 2 skip** ~260s; pytest-native
38 OK; testing 27 OK; evaluation 42 OK). Offline/stubbed-model, owned-loopback
results only. (Was 2418 pre-RB; RB-1..RB-8 added 64 tests.)

## P0-3 blind-scorecard — RUN done (2026-09-22, owner-reported)

Single live pass, real `qwen3:8b` Ollama, `run_blind_eval.py` (RB-8's fixed
harness) at HEAD `0f047e8`. 2/2 `confirmed_vuln` exchanges detected
(unchanged from the 2026-09-20 pre-RB-8 run); 0/5 unique control URLs clean
by raw count (a URL-reuse artifact between one vuln/secure exchange pair
means this overstates the true FP rate slightly — see the report's
methodology caveat). Full detail, exact command, config fingerprint:
[reviews/2026-09-22/BLIND_SCORECARD_P0-3.md](reviews/2026-09-22/BLIND_SCORECARD_P0-3.md).

Not done in this pass (flagged as follow-ups, not run): the
`run_eval_n_times` variance pass (n≥5, ~2h of local Ollama compute), and the
`cross_identity_reject=1` live-traffic run (needs blind-target-2's Flask app
running plus owner opt-in to active validators).

## P2-2 A/B/C/G ablation — CLEAN re-run (2026-09-23), CLOSED, decision=COLLAPSE

Re-ran A/B/C/G live (3 repeats, `num_ctx=8192`, 0/12 starved) after fixing the
2026-09-22 blocker. **G (agent-families) holds detection quality vs A (full 38):
recall 0.818±0.074 vs 0.788±0.043, precision 0.191±0.019 vs 0.176±0.004 — parity
within noise — at ~10% fewer calls / ~6% fewer tokens / ~15% less wall.** Ladder
A≈G ≫ B (single agent 0.394) ≫ C (0 agents 0.182) → quality lives in the routed
multi-specialist behavior, which G preserves and B destroys. The 09-22 run was
invalidated by a VRAM-spill breaker cascade (qwen3:8b at its 32768 default =
10GB/41%-CPU → 80-100s calls → 3×240s timeouts trip the shared breaker → silent
zeroing); root-caused (harness prompts p99 <4k tokens) and fixed with
`num_ctx=8192` (6.2GB/100% GPU/~3s per call) + per-run breaker isolation in the
driver. A's recall recovered 0.182→0.788 from that fix alone, so the old A/B/D/F
numbers measured a broken pipeline and are superseded. Cost win is MODEST (fixed
coordinator+critique floor + larger family prompts offset the collapse). Full
detail, commands, per-type call decomposition, caveats (single corpus/model,
E residual):
[reviews/2026-09-23/ABLATION_P2-2_RERUN.md](reviews/2026-09-23/ABLATION_P2-2_RERUN.md)
(superseding [reviews/2026-09-22/ABLATION_P2-2.md](reviews/2026-09-22/ABLATION_P2-2.md)).

## Open work and pointers

- **Owner/live remaining:** P2-2 ablation — **DONE 2026-09-23 (COLLAPSE, see
  above)**; residual only: E (minus-graph) needs an engagement corpus, and a
  broader-corpus/second-model confirmation would harden the A≈G parity. RB-1b (Java
  token reader), RB-6 OWNER/JDK half (Java→shared trail + stale HarnessPanel
  subset), RB-2b (`fail_open_mode: curated` default flip, gated on RB-8's
  measured recall delta — the P0-3 run above is a first data point but not
  the ≥5-run variance basis RB-2b should be gated on), P1-10 (DNS pin),
  P0-6/P3-1 (redaction), P1-5 (Burp UX), P3-2/3-3.
- Items 4–6 of the precision/blind-control sprint are scoped in
  [PRECISION_BLIND_CONTROLS_PLAN.md](reviews/2026-09-19/PRECISION_BLIND_CONTROLS_PLAN.md)
  (negative-control builders, per-endpoint baseline, coordinator model split).
- The `.worktrees/astra-*`, `supplemental-evidence`, `t08-final` and
  `../AgenticVibe-impl` checkouts hold only superseded drafts — do not resume
  them. Concurrent branch history and implementation review remain
  revision-bound; do not restart unrelated processes based on old notes.
