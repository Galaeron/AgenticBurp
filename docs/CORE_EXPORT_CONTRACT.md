# Core export contract

The supported core outputs are the analysis JSON response, structured issues from
`report_generator.export_issues_for_host`, authenticated Markdown `/report`, SARIF
`/report/sarif`, and the finding evidence API. Include the returned engagement ID
in report reads; optionally filter by captured principal. Direct Python legacy
analysis retains its empty host-only partition for compatibility.

The analysis wire and exports keep evidence maturity, triage priority and impact
severity separate. A confirmation gate may cap displayed severity while
`original_severity` preserves the original impact axis in new stored records.
Legacy records cannot recover an original severity that was never persisted;
their existing severity remains the fallback. SARIF `originalSeverity` is the
exact displayed severity before its lossy level conversion, while
`impact_severity` retains the original impact axis.

Structured issues and SARIF retain proof references. A dangling case/proof
pointer has an explicit `availability: unavailable`, no invented verdict, and
does not establish replayability. SARIF includes the structured artifact status.
Markdown explicitly marks an absent ledger or failed reconstruction unavailable;
the evidence API returns 404 when no persisted events can reconstruct that
finding. A reachable proof record and replayable raw request/response data are
distinct: structured issues retain their raw-capture limitation text. Referenced
blob expiry/persistence degradation remains governed by the evidence and data
lifecycle contracts; exports do not recreate missing bytes.

Issue grouping and observation history use the identity contract in
`ISSUE_IDENTITY.md`. Markdown and SARIF are different representations: SARIF
uses the issue title rather than reproducing every free-text finding summary.
Neither format exports an authenticated application role merely from an analyst
annotation or captured credential label.

PDF/DOCX are optional delivery formats, not core transport APIs. For a readable
document, save the sanitized Markdown report and render it with an operator's
chosen document tool. No built-in PDF/DOCX endpoint, converter integration or
layout fidelity is verified by these tests. No new dependencies or delivery
formats were introduced. Converting Markdown does not add evidence or fix
unsupported replay requirements.

Bounded caller evidence: `test_core_export_parity_passive.py`,
`test_unverified_priority_consistency.py` and `test_issue_identity_passive.py`.
See `reviews/2026-10-05-reconciled-remediation/R24-oct9-state.md` for commands,
failures, corrected fixtures and limitations.
