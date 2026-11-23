# Testing: commands and evidence boundaries

Run from the repository root. `harness/suite.py` is the single selection source
for local runs and CI; inspect a tier with `python -m harness.suite full --list`.

| Command | What runs | What a pass establishes |
|---|---|---|
| `python -m harness.suite smoke` | Pipeline smoke, real discovery gate, confirmation-leg fixtures, discovery/async guards and evidence gate | Selected caller paths still work under controlled inputs |
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

CI installs the lock on Windows/Python 3.14. Reproduce that environment with:

```sh
python -m pip install -r harness/requirements.lock
python -m pip install -e . --no-deps
python -m playwright install chromium   # real-browser tests
python -m harness.lock_preflight        # warns when installed versions differ from the lock
```

The server runs the same lock check at startup (warning log) and serves it in the
authenticated `GET /health/details` as `dependency_lock`. It only warns: a package that
is not installed is reported as missing, an installed package at another version as a
mismatch.

For a smaller local environment the `dev` extra declares everything the suite imports
beyond the core dependencies (pytest, Flask, cryptography, brotli, mitmproxy, Playwright):

```sh
python -m venv .venv
# Activate the environment, then:
python -m pip install -e ".[dev]"
python -m playwright install chromium
```

`test_dev_extra_and_testing_doc` scans the test files' imports and fails when a third-party module
is not provided by the core dependencies or the `dev` extra, and when an exact pin in
`pyproject.toml` differs from the lock. That is a static check: a clean-virtualenv install
of the extra followed by `harness.suite full` has not been run.

Full discovery imports the proxy tests, which need `mitmproxy==12.3.1`, and
`test_browser_experiments` fails without Playwright and Chromium (the guarded browser
tests skip). Missing dependencies must be reported as errors/skips; never stub them
merely to turn the suite green.

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
| Are the run's own 5xx answers followed up? | `test_server_errors` | Loopback search route; sqlmap / nosql legs stubbed; also covers the NoSQL-to-nosql-leg routing |
| Do retry rounds spend a time-boxed run's budget? | `test_retry_rounds`, `RefreshAfterRetryRoundsTests` in `test_coverage_tracker` | Stubbed worklist and review; no live model |
| Are tests silently uncollected? | `test_no_orphan_test_files`, `test_async_test_hygiene` | Static guards plus CI wiring; runtime collection remains authoritative |
| Did a module regrow, take a star import, or get a patch that no longer reaches its code? | `test_orchestrator_split_guard` | Static: no `import *`, orchestrator modules at most 1,200 lines, a size ratchet for the other oversized modules, and each `orchestrator*` patch target must be read by its module (`chain_patch` reaches every `orchestrator_chain*` stage) |

The `test_score_provenance`, `test_evidence_audit`, `test_coverage_summary`, and
`test_eval_health` modules are component regressions. The 2026-09-19 review found
missing production enforcement at its base revision; subsequent fixes through
`57bcc02` added consumers and caller checks. Inspect `testing/test_score.py`,
`test_issues`, `test_coverage_tracker` and the actual entry points as well as the
helper tests before declaring an integration requirement met. The separate
`evaluation_integrity/` contract suite does not itself prove every score/export
path enforces that contract.

## Import isolation (`sitecustomize.py`)

The tracked `sitecustomize.py` at the repository root is a test-environment hook, not part of the
product: `pyproject.toml` packages only `harness*`, so an installed harness has none. Python
imports it at startup when the root is on `PYTHONPATH`, which `python -m harness.suite` arranges
for every child process it starts and `PYTHONPATH=<worktree>` does by hand. It removes the
editable-install finders, so a module missing from the checkout under test raises `ImportError`
instead of loading from another checkout that a venv's `pip install -e .` points at. Tests run
through it therefore see a stricter import environment than an installed package, or than
`python -m harness.server` in a shell without `PYTHONPATH`; a passing run does not show that the
installed package imports. `harness/test_sitecustomize_header.py` pins the header and the
behaviour. A verification snapshot (`docs/VERIFICATION_SNAPSHOTS.md`) generates its own, stricter
`sitecustomize.py`; that is a different file.

## CI and live evidence

Read from `.github/workflows/ci.yml`. Smoke is a local fast subset; CI does not run it.
No job below has been run by the change that wrote this section: a workflow is only
verified by its own runs.

| Job | Runs on | What it runs | What a pass establishes |
|---|---|---|---|
| `full` | every push and pull request, the nightly schedule (07:00 UTC) and manual dispatch; windows-latest, Python 3.14 | `pip install -r harness/requirements.lock`, Playwright 1.63.0 and Chromium; full unittest discovery (`python -m unittest discover -t . -s harness -p "test_*.py"`), `harness.suite native`, the requirement-coverage gate (`harness.coverage_manifest --check`), then `harness.suite evaluation` | Every commit is judged by the whole suite on a clean checkout, not a subset |
| `burp-extension-build` | every push and pull request; ubuntu-latest, JDK 17 | `./gradlew test shadowJar` from `burp-extension/` (Gradle 8.7 wrapper, distribution checksum pinned, Java 17 toolchain), after validating the wrapper jar | The Java sources compile and their unit tests pass; loading the jar into Burp is not exercised |
| `dependency-audit` | every trigger; ubuntu-latest | CycloneDX SBOM, base-image digest report, ffuf wordlist hashes, and `pip-audit` on the lock | Advisory only: the `pip-audit` step has `continue-on-error`, so a published CVE never fails a pull request |
| `dependency-audit-blocking` | pushes to `main` and `v*` tags only | `python -m harness.audit_allowlist check`, then `pip-audit` on the lock ignoring only the ids in `.github/pip-audit-allowlist.toml`; on a tag it also emits the SBOM artifact | Fails on any known vulnerability that is not allowlisted, and on an allowlist entry that is expired or lacks an owner, reason or expiry date |
| `nightly-precision` | schedule and manual dispatch only; windows-latest | Score-math self-test and a CPU-only, model-stubbed corpus run that writes `SCORECARD.md` | The scoring plumbing is wired end to end; it says nothing about model accuracy |
| `scored` | schedule, manual dispatch, or a pull request labelled `run-scored`; needs a `[self-hosted, gpu]` runner | `testing/score.py --from-cache` with recall >= 0.80 and precision >= 0.50 | A re-score of a cached fixture (historical), not a fresh run. Without the runner it does not run |
| `scored-status` | always | Reads the `scored` result | One of `historical`, `failed` or `not_run`; a skipped or cancelled `scored` is `not_run` and never reads as a pass |

A skipped or unavailable job is not a pass. The allowlist file has one `[[ignore]]` table
per accepted vulnerability, each with `id`, `owner`, `reason` and an `expires` date;
`python -m harness.audit_allowlist check` validates it locally.

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
- Requirement evidence for the confirmation legs is declared once, in
  `coverage_manifest._CALLER_EVIDENCE`, and bound with
  `@evidence_for(**cm.caller_evidence(key))` on the exact caller test.
  `DeclaredIdentityTests` pins declaration, decorator and test ID together. A bound
  pair is a confirmation on the vulnerable fixture plus a control that must be a real
  negative from a leg that reached the fixture. Each bound class also carries a
  `*_when_the_leg_is_disconnected` test (`testing_fixtures.leg_fault`) that cuts the
  async egress and requires every bound test to fail. A test with an optional
  prerequisite (Playwright, curl) cannot honestly be bound unless CI provides it:
  a skip leaves the declared aspect unproven and fails the evidence gate.
- Harness safety properties (`HS-*`: the rebinding pin, caller `Host`, environment proxies,
  redirect re-checks, cleanup after a mutating leg) are a separate section of the same
  ledger, `coverage_manifest.SAFETY_PROPERTIES`, bound the same way (`_SAFETY_EVIDENCE`) to
  the real-socket tests in `harness/test_live_safety_loopback.py`. They are not WSTG rows
  and not in the requirement totals; `coverage_manifest --check` blocks on them like on any
  declared automated aspect, so a failing `HS-*` test fails the smoke and full tiers.
  `LIMITATIONS.md` says what the ledger does and does not claim.
- A failing old assertion is not automatically obsolete. Check the intended
  contract and caller before updating it. Do not hide known defects by deletion,
  broad skips, weakened assertions or a lower expected count.
- Log the command, runtime, result and skips. Keep the latest summary in
  CURRENT_STATE.md and detailed audit evidence outside mandatory onboarding.
