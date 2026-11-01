# Active assessment readiness

An investigation job finishing is not proof of complete testing. Read both
`completion_status` and `assessment.status` in its run manifest. The latter is
`incomplete` when applicable checks lack recorded execution, executed checks
remain inconclusive, discovery reports errors/truncation, or coverage is absent.
Manual checks and unavailable capabilities remain visible; they are never
converted into clean negatives to improve the percentage.

## Exact-port scope

For a disposable loopback target, configure `server.allowed_hosts` with the exact
service, for example `127.0.0.1:3002`. Discovery, crawling, feature workflows and
validators use `harness.scope_lock` to interpret this entry. Do not remove the
port to work around a component rejecting the authorized target: that would
authorize other services on the same host.

`harness.test_active_assessment_repair` exercises actual caller dispatch at the
allowed port and refusal at an adjacent port, including the real
discovery-to-confirmation fixture and its patched negative control.

## Work and evidence

- Capture review deduplicates identical observations across discovery and derived
  identity rounds. It interleaves routes and identities before spending its review
  budget. Different credentials, bodies and responses remain distinct.
- Iterative probing stops with `no_progress` after three consecutive actions
  produce no response. A new response resets the counter; duplicates, rejected
  actions and policy blocks do not count as successful tests.
- An unnamed `/analyze` request uses the site's shared history, as documented.
  Explicit engagement names still isolate their observations.
- An inferred detection does not remove its deterministic check from the coverage
  queue. Failed/declined coverage dispatches consume the attempt budget and retain
  an explicit non-negative result.
- `confirmed_issues` counts unique cases whose exact proof and run resolve to a
  confirmed proof record. `confirmed_issue_refs` supplies the pointers. This is not
  a lab scoreboard count or a precision/recall estimate.
- `source.sha256` hashes the imported `harness/**/*.py` files, including uncommitted
  source. An exported directory without its own `.git` does not borrow the parent
  checkout's Git revision. Configuration has a separate redacted fingerprint.
- Model metadata includes critique and surface prioritization as well as the
  coordinator and agents. Configure all stages explicitly when comparing models.

## Verification and run artifacts

The 2026-10-21 repair is recorded in
`.test-work/active-eval-repair-20261021/`. Its `BATCH.md`, gate summaries,
`source-attestation.json`, and `HANDOFF.md` identify the tested snapshot and limits.
The latest isolated live assessment has its own `live-ready/RUN_STATUS.md`, manifest, network
trace and fresh cache/state databases. Private account/config files are runtime
artifacts and must not be staged.

Run readiness requires the requested model to answer, the disposable target to be
reachable, and the Docker sqlmap image to be available. Offline fixture passes do
not establish live vulnerability recall. Keep the shared `harness/config.yaml`
safe; active settings belong only in the isolated run's ignored local config.
