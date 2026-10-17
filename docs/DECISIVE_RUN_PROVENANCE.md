# Decisive evaluation controls

The Ollama provider forwards explicit seeds, including zero; an omitted seed
inherits the shared client's seed. The decisive template sets coordinator,
agent-default and critique temperatures to zero. Validation rejects nonzero
enabled-agent overrides, conflicting seeds and non-Ollama providers. These
are reproducibility controls, not a guarantee of identical model output.

## HTTP evaluation driver

`testing/run_captured_analysis.py` is the versioned implementation of the
external crAPI `eval-run/run_analysis.py` entry point. The external entry point
delegates to it using `--harness-repo`. It no longer infers a remote server's
identity by inspecting a hard-coded sibling checkout.

The driver requires `--decisive-config FILLED.yaml` and a bearer token in
`HARNESS_TOKEN` (or the variable named by `--token-env`). It queries the
authenticated `/run-provenance` endpoint before clearing the cache or analyzing
anything, validates the server's actual controls against the template, and
records the server's configuration hash and startup source identity in every
checkpoint and final result. It checks identity again after each exchange;
drift or unavailable provenance stops the run and marks the saved result invalid.

The endpoint requires a restarted server with these changes. The filled overlay
must already be applied to that server by its owner (merge into ignored
`harness/config.local.yaml`, then restart the owned server). The driver verifies settings;
it does not enable active testing or change scope. Shipped defaults are unchanged.
Use the correct running checkout; updating this repository does not update the
separate `agenticburp-eval/AgenticBurp` checkout or a running Python process.

Example (paths and token supplied by the operator):

```powershell
python run_analysis.py --harness-repo C:\Users\arthu\Documents\AgenticVibe --decisive-config FILLED.yaml --exchanges exchanges.json --out results/decisive.json --label decisive
```

`source` describes the existing allowlisted application-source fingerprint and
its exclusions; it includes eligible uncommitted application changes. The merged
configuration hash includes runtime seed, coordinator settings, agent settings,
scope and the active-mode toggle. Secret configuration values are hashed, not
returned. The driver also records its own source hash and overlay hash.
Model digest and runtime version are explicitly unavailable (`null`) unless
reported by the server; this does not certify model weights, dependencies,
hardware, or all externally loaded resources. The saved Python version is the
driver's version. Identity checks occur at observation boundaries and are not
a lock against concurrent settings changes during a request.

## Regression coverage

- Provider tests assert seed zero reaches the outgoing Ollama JSON through the
  production wrapper, and an omitted override retains the client default.
- The 14-entry cross-user fixture runs through the production confirmation
  caller and real registry with execution/persistence replaced. No identities,
  inactive mode and denied scope each prevent execution. This is not live crAPI
  confirmation or a test of the model discovering the hypothesis.
- Routing regression checks reject newly missing labels even when aggregate
  percentages improve. Historical wording gaps may be fixed without failing a
  test that incorrectly required them to remain broken. The metric remains
  label compatibility, not actual dispatch coverage or vulnerability recall.
- HTTP driver tests exercise result writing and verify wrong settings fail before
  cache clearing or analysis, and source drift produces an invalid result.

No server restart or live crAPI evaluation is performed by these tests.
