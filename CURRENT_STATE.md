# Current state — 2026-09-20

## Checkout

Branch `reconciliation-backlog`, ahead of `main`, 0 behind. The agents-subsystem
refactor and the precision & blind-control sprint (Items 1–3) are committed
(base `02de8bf`, HEAD of that batch `bc5f599`). On top, improvement-loop items
**P0-1, P0-2, P0-4, P1-1, P1-2, P1-4** landed. Re-verified green (full suite 2365
OK / 2 skip). Full per-item detail with Result lines is in IMPROVEMENT_BACKLOG.md.

## Improvement loop (IMPROVEMENT_BACKLOG.md)

- **P0-1 (`25a737a`):** EvidenceLedger wired into the live pipeline (append-only
  `ledger_events` table; `GET /findings/{ref}/evidence`). Instrumentation-only.
- **P0-2 (`533928c`):** run-derived leg trust tiers via the `live_verified_markers`
  override; demotion-only, OFF by default (`leg_self_test.enabled`), fail-safe.
- **P0-4 (`0e993da`):** reverted committed `server.allowed_hosts` to `[]` (live
  scope → git-ignored `config.local.yaml`); `SafeDefaultGuardTests` blocks drift.
- **P1-1 (`33392c9`):** fence-breakout neutralization for untrusted target text;
  defensive-only, caps/high-signal-slice preserved.
- **P1-2 (`e54cfb6`):** scope-escape adversarial regression coverage (IP-literal,
  DNS-rebinding, file://+gopher://, mid-hop redirect) — all already blocked; no
  production change.
- **P1-4 (`df91df8`):** 5 named operating profiles via one opt-in `operating_profile`
  selector (ships "none" → no-op); passive-only asserted all-flags-off; safe
  defaults + SafeDefaultGuardTests intact.
- Follow-on nits filed: P3-4 (ledger singleton), P3-5 (fence prior-context).
- P0 offline tier done (P0-3 owner-only). Next eligible offline: P1-6 (policy
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
