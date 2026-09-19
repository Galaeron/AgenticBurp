# Test and documentation rationalization — 2026-09-19

## Scope and outcomes

Started on `reconciliation-backlog` at `8f63511`, with pre-existing product/test
edits. Other work landed concurrently through `57bcc02`; `8325b05` subsequently
committed the consolidation while this verification was in progress. No product
feature changes were authored by this audit. The coverage-manifest edit corrects
test identity metadata. Existing Ollama edits were preserved.

Required onboarding used to contain 1,164 lines / 9,535 whitespace-delimited
words across AGENTS.md and CURRENT_STATE.md. It is now 130 lines / 903 whitespace-delimited words (90.5% fewer words), with
a shared orientation, rolling state and task-specific architecture/testing references. CLAUDE.md
is a pointer. Original working copies are preserved under
`archive/onboarding-2026-09-19/`; archived statements are not current instructions.
README's duplicated capability tables, historical scores presented as current,
and obsolete test command were replaced with setup and explicit evidence limits.
Historical leg documents now identify themselves as such.

An initial static scan counted 164 harness test files and 2,278 test definitions.
It found no identical normalized test bodies or shadowed test names. This is a
source inventory, not an execution count or proof that every assertion is sound.
No deletion by test age or use of mocking was justified. The retained suite still
has layered component, transport, caller and fixture coverage.

## Demonstrated consolidation

Seven transport adapters repeated fixture/context setup and scope/budget checks.
All 16 original tests passed before the rewrite. The new shared contract preserves
14 adapter scenarios; two distinct CORS behaviors remain in their original module.
Transport test code shrank from 421 to 160 lines, across seven files to two.

| Old module | Current coverage |
|---|---|
| `test_cors_transport` shared pair | `test_validator_transport`, case `cors`; scope guard and no-mutating-method tests remain in `test_cors_transport` |
| `test_csp_transport` | case `csp`: dict/None plus exact request/budget counts |
| `test_oauth_transport` | case `oauth`: checked/non-vulnerable result plus exact request/budget counts |
| `test_header_injection_transport` | case `header_injection`: non-vulnerable plus exact request/budget counts |
| `test_subdomain_takeover_transport` | case `takeover`: controlled fingerprint URL; denied check stays unchecked |
| `test_web_cache_transport` | case `web_cache`: 200/None plus exact request/budget counts |
| `test_recon_transport` | case `recon`: original robots/.env paths; 200/None plus exact request/budget counts |

The old methods collapsed into named subtests, not removed scenarios. No class's
exploit/negative verdict tests were replaced by this generic transport contract.
The consolidated pair plus discovery guard passed (11 methods at that checkpoint).

## Two concrete stale-confidence failures corrected

1. `test_no_orphan_test_files` previously treated `unittest.main()` and a
   TestCase-like name as collection evidence, and never checked actual CI wiring.
   It now catches uncollected mixed-style functions, main-only modules, shadowed
   definitions and stale selections, with deliberately invalid controls.
2. All six `coverage_manifest.REQUIREMENT_TESTS` IDs used the pre-package names.
   The standalone smoke passed but the real evidence gate rejected every artifact
   because its actual ID began `harness.`. Corrected the six declarations; added
   runtime loader-ID assertions and a rejected old-name control. Exact evidence
   matching is preserved, not relaxed.

The XXE smoke also claimed no network while unrelated enabled validators opened
an actual shared collaborator and waited. Isolated two-case run before the fix:
142.461s. It now explicitly tests the XXE registry slice and forbids the shared
collaborator with a non-swallowable sentinel; both existing controls pass in
0.709s. The broader registry and actual discovery pipeline keep separate tests.
Smoke runtime was 170.894s before this boundary correction and 27.923s afterward
(88 vs 90 methods due to the new identity regressions; no performance guarantee).

`harness.suite` now owns local/CI selections. Smoke/full enforce the evidence gate;
local invocations get a unique run identity by default. Full also runs pytest-native
and both evaluation suites, in isolated subprocesses, and retains any nonzero
result even when later groups pass. The guard tests this failure propagation.

## Verification and limits

Final verification (`.venv-rationalisation/Scripts/python.exe -m harness.suite`):

| Tier | Result |
|---|---|
| `smoke` | 90 tests OK, 27.923s; evidence gate passed |
| `full`: unittest | 2,295 tests OK, 2 skipped, 234.228s |
| `full`: requirement evidence | Passed; undeclared/unimplemented requirement gaps remain visible |
| `full`: pytest-native | 38 passed |
| `full`: score/plumbing | 13 tests OK |
| `full`: standalone evaluation | 42 tests OK |

Both commands exited 0. All 377 recorded source hashes were unchanged from final
run start to completion; HEAD at completion was `8325b05`. See RESULTS.json for
log hashes and tested-source-start.json for source binding. The two skipped checks
require the optional browser. These results apply to the dirty checkout including
the pre-existing Ollama edits, not the clean commit alone.

Local runtime: isolated Python 3.12.14, declared core/dev packages, Flask 3.1.3,
mitmproxy 12.2.3 and typing-extensions 4.16.0. The latter conflicts with mitmproxy's
Python <3.13 metadata; this is an execution workaround, not a clean dependency
resolution. Existing dependency directories imported incomplete namespace modules.
Initial full attempts failed on those dependencies and then sandbox restrictions
on the existing audit-log/pytest temp directories. Tests were re-run with the
required file access; no skips were added to hide those failures.

An intermediate complete run passed: 2,285 unittest methods (2 skipped), 38 pytest,
13 score/plumbing and 42 standalone evaluation tests. Subsequent smoke/evidence
verification exposed and fixed the six stale IDs; the final run includes that gate.
Another task reported 2,293 unittest + 38 + 13 + 42 on ambient Python 3.14 in
CURRENT_STATE.md. That is owner-reported evidence, not this audit's interpreter run.

`tested-source-start.json` binds the final run to hashes of 377 selected source/
configuration files. End-of-run comparison is recorded separately. This is not
an exhaustive capture of every runtime dependency or fixture artifact.

No real-model benchmark, blind-target run, hosted CI execution or Java build was
performed here. Passing these tests is not a declaration that every review finding
is closed. Subsequent pruning should continue by demonstrated overlap and retain
caller/negative controls, rather than targeting an arbitrary lower test count.
