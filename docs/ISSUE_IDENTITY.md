# Passive issue identity and history

Issue grouping and observation deduplication already exist. New passive finding
records retain parameter location/name and explicit principal alongside their
captured authentication context. Runs of the same known input and ownership
context link to one stable issue; run IDs are excluded from issue identity.
Distinct known inputs, explicit principals, captured authentication contexts and
nonempty engagement IDs remain distinct. Unknown inputs use a finding identity
discriminator. Host-level dependency/banner advisories intentionally group within
one host and engagement, independently of request principal or endpoint.
Callers must reuse an explicit engagement ID for linkage across runs; an analysis
that defaults its engagement ID to a fresh run ID deliberately belongs to a new
partition, so its issues remain separate.

Structured exports keep every persisted case member and its proof history.
Findings without cases can deduplicate to one finding row; their append-only
observation records retain each distinct run/exchange coordinate. Exports label
these as observations, never validation attempts or proof of confirmation.
Markdown uses the same stable issue identity when choosing representatives.
Suppression and reporting filters affect presentation; they do not delete finding,
proof or observation history. Restoring the view restores those references.

The migration adds three columns with empty defaults. Existing proof-linked
records can recover missing coordinates from their proof records. Coordinates
discarded by older passive persistence cannot be reconstructed. Existing stored
fingerprints are not rewritten by this additive change; newly persisted explicit
principals in scoped engagements use both captured and explicit identity, so old
records/suppressions with incomplete coordinates may not link to new fingerprints.
The empty-engagement compatibility partition keeps its existing grouping scheme.
New ownership-scoped issue IDs differ from older IDs that omitted ownership;
external issue-ID references or merge assumptions need explicit reconciliation.
No automatic rewrite, history deletion, active retest or request execution occurs.

Synthetic caller verification exercises the real persistence/export functions
with temporary SQLite, ordinary captured metadata and inert proof records. It
does not establish current model quality, live validation or HTTP/Java caller
integration. R10 ownership and R15 provenance remain independent dependencies.
