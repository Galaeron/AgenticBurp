# SPA discovery and lifecycle fixes — 2026-10-16

These working-tree changes address the two follow-up lifecycle defects and the
discovery gaps. They do not establish live crAPI recall or production readiness.

## Request ownership

Standalone analysis and iterative probing preserve an explicit zero request
ceiling. Invalid ceilings (negative, boolean or noninteger) fail before context
creation. Analysis closes its owned context even if identity seeding raises.
Borrowed contexts remain owned by their caller.

## JavaScript-generated API traffic

Engagement discovery now connects the existing Playwright capture driver to the
worklist. Enable `driver_capture.enabled: true` in the ignored local configuration
for an authorized run; the committed default remains off. Playwright and Chromium
must be installed. Each selected role visits the engagement base URL, with bounded
settling time and capture count. Scope, mutation gate, cancellation and request
budget are passed from the owning RunContext. Browser TLS verification stays on.
Missing engines and navigation failures are reported as degraded discovery.

This captures fetch/XHR traffic triggered by loading the page. It does not click
through every SPA workflow or automatically log in. Supply current role credentials
and visit the relevant application route, or provide observed browser/Burp exchanges
through `seed_exchanges` on `POST /engagement/{host}/investigate`. These are ordinary
HttpExchange records, including method, URL, request headers/body and response.
The API also accepts `active_discovery: false` to disable speculative route guessing.
That option does not disable other authorized engagement phases.

Imported captures must match the engagement origin, configured scope and supplied
identity credentials. Unknown identities and off-origin captures are rejected with
diagnostics; authenticated observations never imply anonymous access. Import is
bounded to 200 exchanges. Request method, body and query are kept as templates.

Static crawling also follows literal same-origin JavaScript module imports within
the existing depth/page limits and preserves fetch/axios/XHR methods in the access
matrix. Static extraction alone cannot resolve arbitrary runtime expressions.

## Catch-all responses

Discovery compares candidates with two random sibling paths in the same namespace,
using status and normalized response bodies. These controls spend the normal
discovery/run budgets. Matches are suppressed, and speculative expansion beneath
that wildcard prefix stops. Explicit app/capture references still get checked;
distinct real responses survive. Query variants and ffuf-reported routes also pass
existence checks. ffuf is skipped when an owning run context is present because
its external requests cannot consume that context's budget.

`wildcard_prefixes` and `wildcard_candidates_suppressed` describe filtering in the
surface result. This is conservative: an actual route indistinguishable from the
fallback can be suppressed, and arbitrary varying catch-all bodies may evade the
fingerprint. A route match is discovery evidence, never vulnerability confirmation.

## Verification

Caller regressions: `harness.test_discovery_spa_wildcards`,
`harness.test_standalone_analysis_lifecycle`,
`harness.test_iterative_probe_run_context`. Existing discovery budget-reserve
controls remain intact. `harness.test_driver_capture.DriverCaptureTest.
test_real_browser_capture_reaches_engagement_worklist` exercises a real Chromium
browser against the owned local fixture, through the production engagement builder.
Run logs are under `.test-work/discovery-fixes-*.log`; final results are recorded
in CURRENT_STATE.md. No fresh crAPI evaluation or Java build is claimed here.
