# Testing: commands and evidence boundaries

Run from the repository root. `harness/suite.py` is the single selection source
for local runs and CI; inspect a tier with `python -m harness.suite full --list`.

| Command | What runs | What a pass establishes |
|---|---|---|
| `python -m harness.suite smoke` | Pipeline smoke, real discovery gate, discovery/async guards and evidence gate | Selected caller paths still work under controlled inputs |
| `python -m harness.suite native` | pytest-native plugin, execution protocol and hardening tests | Regressions that unittest cannot collect are executed |
| `python -m harness.suite evaluation` | `testing/test_*.py` and `evaluation_integrity/tests/test_*.py` | Score math, stubbed corpus plumbing and standalone evaluation contracts |
| `python -m harness.suite full` | Full harness unittest discovery, evidence gate, native and evaluation tiers in separate processes | Current regression suites pass, subject to reported skips |
| `python -m unittest harness.test_NAME` | One module | Only that module's assertions |

The runner returns nonzero if any subprocess fails and still attempts subsequent
suites for diagnostics. unittest counts methods, not table-driven subtest cases.
Fewer methods after consolidation do not mean fewer checked behaviors.
Smoke/full enforce the requirement-evidence gate as well as test results. Local
runs get a unique coverage run ID unless explicitly supplied, so an unchanged Git
HEAD cannot silently reuse a previous run's evidence.

## Dependencies

CI installs `harness/requirements.lock` on Windows/Python 3.14. For a smaller
local environment, install the core/dev extras and Flask for loopback fixtures:

```sh
python -m venv .venv
# Activate the environment, then:
python -m pip install -e ".[dev]" Flask==3.1.3
```

Full discovery also imports the optional proxy tests, which require
`mitmproxy==12.2.3`. Browser fixture checks require Playwright and Chromium and
may skip without them. Missing dependencies must be reported as errors/skips;
never stub them merely to turn the suite green.

Python 3.12 caveat: mitmproxy 12.2.3 declares typing-extensions <=4.14, while the
current core requires newer versions. The 2026-09-19 local audit restored
`typing-extensions==4.16.0` in its isolated environment to execute the tests;
that is an explicitly reported metadata conflict, not a supported dependency
resolution. Prefer the CI Python version for lockfile reproduction. Hosted CI
and a clean lockfile installation still need their own verification.

## Which tests answer which question?

| Question | Start here | Boundary deliberately replaced / limitation |
|---|---|---|
| Does a model finding survive captured analysis? | `test_smoke_detection` | Canned model output; no model accuracy claim |
| Does shape-driven XXE confirmation run? | `test_smoke_shape_precondition` | Silent model, XXE-only registry, stubbed transport/callback; unexpected shared collaborator is forbidden |
| Does shape-driven JWT confirmation run? | `test_smoke_investigate` | Discovery and HTTP responders are supplied |
| Does discovery actually feed confirmation? | `test_pipeline_gate` | Silent model; local advertised fixture, not arbitrary websites; ffuf disabled |
| Can the pipeline gate detect a broken pipeline? | Defect-injection cases in `test_pipeline_gate` | Deliberately starved discovery, dropped methods, suppressed leg must fail the gate |
| Are scope/budget enforced on validator transport? | `test_validator_transport`, `test_offscope_host_lock`, `test_run_context` | Loopback/denied sends; does not establish oracle soundness |
| Does a leg distinguish vulnerable and secure behavior? | `test_leg_live_verification`, class-specific validator tests | Owned loopback fixture; optional browser/tool dependencies |
| Are weak verdicts prevented from overconfirming? | `test_oracle_retirements`, `test_confirmation_gate`, `test_oracle_framework` | Unit/fixture evidence; inspect caller integration separately |
| Does state survive persistence/export? | `test_verification_state_consistency`, `test_issues`, `test_serialization_roundtrip` | Python round trips do not prove Java display or every export path |
| Are tests silently uncollected? | `test_no_orphan_test_files`, `test_async_test_hygiene` | Static guards plus CI wiring; runtime collection remains authoritative |

The `test_score_provenance`, `test_evidence_audit`, `test_coverage_summary`, and
`test_eval_health` modules are component regressions. The 2026-09-19 review found
missing production enforcement at its base revision; subsequent fixes through
`57bcc02` added consumers and caller checks. Inspect `testing/test_score.py`,
`test_issues`, `test_coverage_tracker` and the actual entry points as well as the
helper tests before declaring an integration requirement met. The separate
`evaluation_integrity/` contract suite does not itself prove every score/export
path enforces that contract.

## CI and live evidence

Fast CI runs smoke, native and evaluation tiers plus the requirement-evidence gate.
Nightly/manual CI runs full unittest discovery, native and evaluation tiers. The
CPU precision job uses a stubbed model. The scored job uses `--from-cache` and
therefore reports historical re-scoring, not a fresh run. The Java job is a
separate manual boundary. A skipped/unavailable job is not a pass.

For real-model/target evaluation, record the checkout and dirty state, config,
corpus, fresh cache, model, run ID, completion/health and supporting artifacts.
Do not read blind answer keys or target implementations. Do not infer improvement
from a helper unit test or compare different corpora as a model-only effect.

## Maintenance rules

- Keep positive, negative and failure-path cases that detect different defects.
  Consolidate repeated setup/assertions only with an explicit old-to-new mapping.
- Shared transport cases live in `test_validator_transport`; validator-specific
  verdict tests stay with their class. Each table case checks observed requests
  and budget, plus its adapter's result contract.
- New module-level pytest tests belong in `suite.PYTEST_NATIVE`; guards fail for
  mixed files whose free functions unittest would silently omit, empty main-only
  modules, and shadowed definitions. Preserve async-capable test bases.
- Requirement declarations must use runner-resolvable packaged test IDs;
  `test_coverage_manifest.DeclaredIdentityTests` guards this binding. The exact
  evidence identity check remains strict; do not normalize away mismatches.
- A failing old assertion is not automatically obsolete. Check the intended
  contract and caller before updating it. Do not hide known defects by deletion,
  broad skips, weakened assertions or a lower expected count.
- Log the command, runtime, result and skips. Keep the latest summary in
  CURRENT_STATE.md and detailed audit evidence outside mandatory onboarding.
