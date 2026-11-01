# Confirmation accounting audit — 2026-10-24

Ticket 6 separates exact proof-bound cases from vulnerability counts. Existing
`confirmed_issues` and exact references remain compatible; the result and manifest
now declare their unit as `proof_bound_cases` and add `issue_accounting` and
`confirmed_vulnerabilities`. Historical confirmations are preserved, not silently
reclassified in storage.

## Historical sample and reconciliation

This is a **historical/reported** audit, not a fresh target run. Source artifacts,
relative to the main checkout (not the integration worktree):

- `.test-work/active-eval-repair-20261021/live-ready/runs/fd558601b325.json`
- `.test-work/active-eval-repair-20261021/live-ready/source/harness/harness_state.db`
- Selected metadata: `.test-work/assessment-integration-20261023/ticket6-audit-metadata.json`

The SQLite database was opened read-only. Inspection selected proof/case IDs,
validator names, verdicts, reference presence and principal/request boundaries;
no target implementations, answer keys or credential configuration were read.

Run `fd558601b325` has 51 manifest references to 51 distinct cases, each matching
an exact confirmed proof in that run. Its ledger has 67 confirmed proof instances
across 66 cases; 16 instances are unreferenced by the manifest. The persisted
finding projection contains 37 cases, all present in the manifest; 14 manifest
cases are absent from that projection. Thus neither a finding projection nor a
manifest alone is a complete ledger inventory.

All 67 historical proofs have `legacy=1`, `executed=1`, and empty baseline,
attack and control artifact references. They cannot establish reproducible,
independent vulnerability confirmation under the new accounting contract. This
is an evidence limitation, not proof that every historical verdict was false.

| Validator family | Ledger proofs | Ledger cases | Manifest refs | Audit verdict |
| --- | ---: | ---: | ---: | --- |
| cross_identity | 8 | 7 | 4 | Historical/unverified ownership comparison; repeat requires bound principals and owned-object controls |
| jwt_forge | 20 | 20 | 10 | Historical/unverified; public HTTP 200 is insufficient |
| sqlmap | 9 | 9 | 7 | Historical/unverified; error-only signals remain candidates |
| csp_validator | 20 | 20 | 20 | Hardening observations, not 20 independent vulnerabilities |
| recon_validator | 8 | 8 | 8 | Reconnaissance, not exploit confirmation |
| verbose_error_validator | 2 | 2 | 2 | Hardening observations |

Exact representative pointers below resolve through the database's proof/case
records for that run. Their legacy artifact limitation applies to every row.

| Family | Proof ID | Case ID | Request-template ID | Principal |
| --- | --- | --- | --- | --- |
| cross_identity | e3ffebba553e4c4598514bf5f4bacaae | f34a576b60f3f053 | 6bd177dde3027576 | eval-user-2 |
| jwt_forge | f91aa7ab8f05414884912ef1710fde5e | 0d5e6755e6c13f19 | 6bd177dde3027576 | eval-user-1 |
| sqlmap | 702500f853974af1a5f5ad0059ed2aaf | 17295afc2fd4234e | 0581299369a601e1 | See case record |
| csp_validator | 90eed7da795d4c1097846a8b70c572ac | 2508bb624b0e4a17 | d53764a771b4b18d | captured |
| recon_validator | 623c5b0e05c74536b69cc611d3761644 | 81697e5f5d4239fc | c929dd04b1068fc8 | captured |
| verbose_error_validator | e34d458dee674d68a78ca77de1f47c35 | 21d318913a8724bc | d59bfa80ffe4feaa | captured |

Additional SQL error-signature sample: proof `bc689c2b6e8a4ebe89dc358c33f91733`,
case `35907e38108ee3f1`, request `5ab4651e09319aee`. Boolean-text sample: proof
`67377c2aa7ba4a58a969bf6e54e6e1ca`, case `d5d185c8dc887881`, request
`0581299369a601e1`. Textual signal descriptions do not replace bound controls.

## Current accounting and controls

Accounting retains every proof instance, including instances not selected by a
finding, and reports exclusions for mismatched references. Vulnerabilities need
nonlegacy executed proofs with three distinct baseline/attack/control artifact
references resolving to successful execution events for the exact case and
intact request/response blobs. Missing evidence remains candidate accounting.
Controlled negatives are not candidates. Grouping preserves run, principal,
parameter and workflow boundaries; vulnerability grouping defaults to the exact
case unless an explicit root-cause ID exists. Hardening/recon grouping retains
all case/proof references across routes. This is conservative accounting, not a
claim to infer semantic exploit equivalence from URLs.

The SQL quick probe now retains database errors as inconclusive candidates.
Identical errors and differently sized error pages cannot confirm SQL injection;
an independent true/false response differential still can. Existing JWT public
endpoint and cross-identity ownership controls remain in place.

Focused evidence in `.test-work/assessment-integration-20261023/`:

- `ticket6-focused.log`: 124 tests passed, including cross-identity, JWT,
  no-run caller controls, run manifests and active-assessment repair.
- `ticket6-final-focused.log`: 58 passed, including JWT public-endpoint negative
  and invalid-signature positive loopback controls.
- `ticket6-accounting-final.log`: 7 accounting tests passed.
- `ticket6-freeze-focused.log`: final 58 passed with
  `python -m unittest harness.test_issue_accounting harness.test_sqlmap_validator`.
  Includes server result/manifest accounting, reused-control rejection,
  retained principal boundaries, SQL error-only negatives and differential positive.

These focused checks are offline or owned fixture checks. They establish neither
current model accuracy nor live/blind-target recall. Root owns final combined
snapshot precondition, smoke and full gates on both interpreters.
