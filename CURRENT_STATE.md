# Current state — 2026-09-20

## Checkout

Branch `reconciliation-backlog`, ahead of `main`, 0 behind. The agents-subsystem
refactor and the precision & blind-control sprint (Items 1–3), previously
uncommitted, are now committed as five focused commits (base `02de8bf`, HEAD
`bc5f599`) and re-verified green on the committed tree (see Verified below).

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

Item 1 — fail_open_mode: curated for measurement (shipped default stays `all`):
- `testing/blind-target-2/run_blind_eval.py`: injects `fail_open_mode=curated` via
  `HARNESS_FAIL_OPEN_MODE` env var (default curated); logs config fingerprint +
  fail_open_stats in the run manifest.
- `testing/blind-test-kit/harness/config.yaml` (vendored): added
  `fail_open_mode: "curated"` with a divergence note (this runner uses bare
  yaml.safe_load, no config.local.yaml overlay reaches it).
- `harness/test_fail_open_curated.py`: two new tests — runner config dict threads
  through correctly; fail_open_stats() and config_fingerprint() are capturable.

Item 2 — safe passive oracle (zero live traffic):
- `harness/config.yaml`: added `oracle.safe_passive_default: true` — runs oracle
  only for `active=False` validators (no new requests). Shipped ON; safe by design.
- `harness/oracle_framework.py`: `oracle_for()` gains `passive_only: bool = False`
  parameter; skips active validators when True.
- `harness/orchestrator_confirm.py`: `_oracle_gate` handles the three modes:
  disabled, safe-passive (new), and full-active.
- `harness/test_oracle_framework.py`: 6 new tests in `TestOracleForPassiveOnly`,
  including the zero-sends safety contract negative control.

Item 3 — quarantine undifferentiated live-class findings as LEADs on blind runs:
- `harness/confirmation_gate.py`: `should_quarantine_as_lead(finding) -> bool` —
  true for assumed/recalled + live-class + not confirmed + not oracle-verified.
- `harness/config.yaml`: `reporting.quarantine_unverified_leads: false` (shipped OFF).
- `harness/report_generator.py`: `generate_markdown_report` gains
  `quarantine_leads: bool = False`; quarantined findings routed to a separate
  "Test Suggestions" section.
- `testing/blind-target-2/run_blind_eval.py`: `HARNESS_QUARANTINE_LEADS` env var
  (default 1 = enabled for measurement).
- `harness/test_quarantine_leads.py`: 12 new tests (predicate + report integration).

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
