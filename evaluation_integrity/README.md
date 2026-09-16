# Evaluation-integrity diagnostics

This directory implements supplemental tasks S-01 through S-05 as standalone,
read-only tooling. It does not import or initialize `harness`, open harness
databases, contact targets, invoke models, or change production scoring.

Run an audit from the repository root with the bundled Python interpreter:

```powershell
& 'C:\Users\arthu\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' `
  -m evaluation_integrity.audit `
  --input C:\path\to\results.json `
  --input C:\path\to\score.json `
  --json C:\path\to\audit.json `
  --markdown C:\path\to\audit.md
```

The generic input adapter accepts schema versions
`evaluation-integrity-input/v1` and `agenticvibe-evaluation-bundle/v1`. Explicit
legacy adapters support the saved max-coverage result and endpoint-known recall
report shapes. Unknown schemas fail the audit instead of producing a clean result.

The report keeps four statements separate:

1. a finding's `confirmed` claim;
2. the presence of a validator name or proof pointer;
3. resolution to the same finding/case and an executed, confirmed proof with
   supplied exchange-artifact references;
4. absence, inconsistency, unsupported legacy structure, or inconclusive proof.

A missing reference is **unverifiable**, not false. Legacy confirmation is never
given manufactured proof. Output contains identifiers and reasons, but adapters
discard raw evidence text, request/response bodies, and credential-bearing fields.

Coverage summaries preserve reported counts and show a denominator beside every
percentage. Request/cell and parameter/case layers are never summed. Missing
fields are unknown, not zero; `not_detected` does not imply a controlled negative.
Process completion, coverage completion, evaluation validity, detection metrics,
and proof-backed issue metrics are separate concepts.

## Manifest and freshness

[`manifest.schema.json`](manifest.schema.json) defines the v1 bundle manifest.
`evaluation_integrity.provenance.check_manifest` verifies required metadata,
invocation binding, paths, and artifact hashes. A clean-tree
`fresh_end_to_end` bundle can be described as a fresh evaluation of the stated
build. A `historical_rescore` remains usable but is never labelled a fresh
end-to-end validation. Dirty or mismatched provenance is unknown.

Hashes establish that the supplied files are internally consistent with the
manifest. They do **not** independently authenticate who created the files, how
they were produced, or whether the producer was trustworthy. Credential values
do not belong in the manifest; only non-secret identities and fingerprints do.

## Tests

```powershell
& 'C:\Users\arthu\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' `
  -m unittest discover -s evaluation_integrity/tests -p 'test_*.py'
```

All fixtures are synthetic and explicitly labelled. They do not read protected
ground truth or blind-target source.
