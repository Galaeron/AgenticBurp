# Current state — 2026-09-20

## Checkout

Branch `reconciliation-backlog`, ahead of `main`, 0 behind. The agents-subsystem
refactor and the precision & blind-control sprint (Items 1–3) are committed
(base `02de8bf`, HEAD of that batch `bc5f599`). On top, improvement-loop items
**P0-1** (`25a737a`), **P0-2** (`533928c`), **P0-4** (`0e993da`), and **P1-1**
(`33392c9`) landed. Re-verified green (full suite 2342 OK / 2 skip).

## Improvement loop (IMPROVEMENT_BACKLOG.md)

- **P0-1 done (`25a737a`):** EvidenceLedger wired into the live pipeline —
  records each finding's causal chain to an append-only `ledger_events` store
  table; reconstructable via `GET /findings/{ref}/evidence` and a report line.
  Instrumentation-only (no config/verdict/scope/gate/control-flow change).
- **P0-2 done (`533928c`):** run-derived leg trust tiers — `leg_self_test.py`
  fires each active leg against the owned loopback fixture + negative control and
  demotes classes that fail their self-test, via the existing
  `live_verified_markers` override. Demotion-only, OFF by default
  (`leg_self_test.enabled`; static table stays the shipped default), fail-safe to
  demote-all. +8 tests; full suite 2333 OK / 2 skip.
- **P0-4 done (`0e993da`):** reverted committed `server.allowed_hosts` to `[]`
  (live scope now in the git-ignored `config.local.yaml`); added
  `SafeDefaultGuardTests` that fails the suite if any covered safety default drifts
  (allowed_hosts, validators active/mutating, autonomous_discovery, oracle,
  engagement toggles, coordinator.cloud_*).
- **P1-1 done (`33392c9`):** fence-breakout neutralization for untrusted target
  text (body/headers/analyst_note) on top of the nonce fence; adversarial
  injection cannot alter finding state, caps/high-signal-slice preserved,
  defensive-only. +7 tests.
- Follow-on nits filed: P3-4 (bound/rotate in-memory ledger singleton), P3-5
  (extend fence isolation to prior-context/knowledge blocks).
- P0 offline tier done (P0-3 owner-only). Next eligible offline items: P1-2
  (scope-escape adversarial tests), P1-4 (operating profiles), P1-6 (policy
  object). P1-3 depends on P0-3; P1-5 needs a JDK/Burp build.

## Committed this session (agents refactor + sprint Items 1–3)

Five focused commits, `02de8bf..bc5f599`:
- `4dfa89c` refactor(agents): simplify agent lifecycle management —
  `harness/agent_manager.py`, `harness/agents/__init__.py`, `harness/agents/plugin.py`,
  new `harness/test_agent_lifecycle.py`. Plugin/agent-class discovery simplified;
  lazy `_plugin_system` singleton dropped; `get_all_agents(config, ollama)` replaced
  by argument-free `get_all_agent_classes()`.
- `50fe65a` fix(ollama): harden client edge cases —
  `harness/ollama_client.py`, `harness/test_ollama_client.py`.
- Precision & blind-control sprint Items 1–3 (`a549d0b`, `ee54d02`, `bc5f599`).

The two new `harness/config.yaml` knobs ship at safe defaults:
`oracle.safe_passive_default: true` (passive-only re-analysis, zero live traffic)
and `reporting.quarantine_unverified_leads: false` (opt-in via measurement
overlay). `oracle.enabled` remains `false`. Note: the vendored
`testing/blind-test-kit/harness/config.yaml` is updated separately because it is
loaded by bare `yaml.safe_load()` and cannot inherit from the real harness config.

## Precision & blind-control sprint (Items 1–3, committed this session)

- Item 1 — fail_open curated mode for measurement (shipped default stays `all`):
  `run_blind_eval.py` env knob, vendored kit config, `test_fail_open_curated.py`.
- Item 2 — safe passive oracle (`oracle.safe_passive_default: true`, zero live
  traffic): `oracle_framework.oracle_for(passive_only=...)`, `_oracle_gate` modes,
  6 new tests incl. zero-sends negative control.
- Item 3 — quarantine undifferentiated live-class findings as LEADs on blind runs
  (`reporting.quarantine_unverified_leads: false`, shipped OFF):
  `should_quarantine_as_lead`, report "Test Suggestions" section, 12 new tests.

Owner action required (these numbers are NOT verified here):
- Re-run PixelMart + blind helpdesk under `fail_open_mode=curated` and
  `quarantine_unverified_leads=true`; record precision AND recall deltas in this
  file as owner-reported.

## Verified here (2026-09-20, clean committed tree at HEAD `bc5f599`)

From the repository root, using `.venv-rationalisation/Scripts/python.exe`
(Python 3.12.14, isolated deps):

- `-m harness.suite smoke`: **90 tests OK**, exit 0.
- `-m harness.suite full`: **green, exit 0.** Unittest **2,321 tests OK, 2 skips**
  (261s); pytest-native **13 OK**; evaluation **42 OK**.

These are offline/stubbed-model, owned-loopback results only. No real-model
benchmark, blind-target run, hosted CI or Java build was performed here.

## Open work and pointers

- Owner: run both corpora under curated + quarantine; record precision/recall
  deltas in this file as owner-reported (sprint exit criterion).
- Items 4–6 are scoped in [PRECISION_BLIND_CONTROLS_PLAN.md](reviews/2026-09-19/PRECISION_BLIND_CONTROLS_PLAN.md)
  (negative-control builders, per-endpoint baseline, coordinator model split).
  Do not start until Items 1–3 are measured.
- Concurrent branch history and implementation review remain revision-bound; do not
  restart unrelated processes based on old notes.
