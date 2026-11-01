# Sensitive data lifecycle and maintenance boundaries

The current lifecycle is scoped, explicit maintenance. It is not automatic
whole-application retention, secure erasure or encryption at rest. Synthetic
verification does not establish a production backup/deletion procedure.

## Pairing credential publication

Generated credentials are published by `security.write_private_credential_file`
through an empty disposable file in the destination directory. Permissions are
restricted before credential bytes are written, then the file is atomically
replaced. Windows uses the built-in .NET Framework ACL methods under Windows
PowerShell: a protected DACL with one explicit current-user full-control ACE.
POSIX uses 0600. Windows `chmod` is not used as a confidentiality guarantee.

Actual Windows disposable-file controls check the final DACL after creation and
replacement, including disabled inheritance and the current SID as the sole ACE.
The defect control bypasses protection and observes an inherited DACL. No second
Windows account access attempt or administrator isolation is claimed.

If private publication fails, startup keeps the generated credential in memory
but reports failure and warns that the prior lockfile may be stale. Configure a
bearer token through the environment or ignored local override and re-pair.
No credential value is included in that diagnostic. The containing directory
must be owned/trusted by the operator; ACLs do not isolate a compromised process
running as the same user. Administrators/SYSTEM can take ownership. Credentials
and backups still require OS protection; this policy adds no encryption.

## Store and artifact inventory

| Data | Current mechanism | Limit / ownership |
| --- | --- | --- |
| Main SQLite findings, plans, proofs, ledger, state, identities, sessions and knowledge | Durable store; explicit host wipe covers its documented table subset | Raw fields may be sensitive. Partition work does not imply every table has full context ownership. Global identities/ownership/knowledge/work queue and run records require separate lifecycle policy. |
| Content-addressed evidence blobs in main SQLite | Explicit `apply_retention_from_config`; host wipe uses shared-reference guard | Blob age is global, not per context. Expiry can make referenced evidence unavailable; consumers must resolve/hash-check, not trust a reference string. |
| Analysis/exchange caches | Cache expiry/lookup and explicit clear APIs | Cache expiry is not necessarily physical file erasure or the main store's retention. Separate database/files may remain. |
| Audit logs | Structured sanitation and size-based rotating file sink | Rotation is size/backups, not an age-based retention promise. Other configured sinks and historical logs are separate. |
| Provider traces, reports/exports, browser/Burp captures and external tool files | Producer-specific persistence and explicit export | Main store deletion does not remove copies, external sinks, exports or third-party application data. |
| Pairing lockfile / ignored local config | Private credential publication; operator-managed config | Not part of evidence retention/host wipe. Never include in shareable evidence or ordinary report exports. |
| HMAC captured-auth-context key and linkage metadata | Per-store pseudonymous context policy, where supported | Key belongs to sensitive full-store backup; never export it with shareable findings. Digests are linkable pseudonyms, not identities or anonymization. |

## Retention and deletion

`store.evidence_retention_days: 0` means keep forever. A positive value supplies
an age threshold to an explicit maintenance call; startup and scheduler do not
automatically apply it. The helper presently covers evidence blobs only.
Changing that value does not configure retention for findings, session material,
logs, caches, exports or backups. Maintenance on real data must be an explicit
operator action with ownership and backup requirements resolved.

The opt-in `DELETE /engagement/{host}/evidence` is authenticated and disabled by
default. Its current store function deletes the documented host-owned subset.
It is not a promise to delete just one named engagement/principal on a shared
host, nor to remove all application or external artifacts. The content-addressed
blob guard preserves bytes another host's registered finding references.
The separate `python -m harness.data_maintenance wipe-context --source <owned.db>
--engagement-id <explicit-id>` command deletes only rows whose nonempty
`engagement_id` matches exactly in findings, ledger events, scoped engagement
snapshots, private knowledge notes and work items. It applies across hosts in that
named engagement. All surviving ledger references, including legacy and orphan
rows, protect shared blobs; target-only referenced blobs are deleted. Malformed
ledger/reference data aborts the transaction before deletion. An empty ID is
rejected. Tables without explicit context ownership are preserved, including
proof records, sessions, identities, plans, global notes and host-wide state.
Unowned finding observations, suppression/merge rows, validation runs and run
identifiers also remain; their owner is not inferred from an ambiguous link.
The receipt lists deleted counts and preserved unowned tables. Separate caches,
logs and exports are untouched. This is an attributed subset deletion contract,
not complete application erasure or deletion of legacy data by inferred owner.
Stop owned writers/jobs before maintenance and restart after deletion: in-memory
ledgers/jobs are not deleted and continuing writers can recreate records.
The shared-byte guard covers the current registered blob references in ledger
`data_json.request_blob`/`response_blob`. It does not scan arbitrary JSON, external
exports or another database for hashes. Blob integrity checks establish present
byte/hash agreement and count missing ledger references; they do not establish
complete proof-identity or external-artifact referential integrity.

Expiry or deletion must become visible as missing/unresolved evidence in
reconstruction and exports. Existing event references are historical records;
their presence cannot establish that current request/response bytes still exist
or hash-check. Reports must not continue presenting an expired proof as complete.

## Backup and restore

`python -m harness.data_maintenance plan` prints the supported scope inventory
without reading files. `backup --source <owned.db> --destination <new-backup.db>`
uses SQLite's backup API, including committed WAL content. The new snapshot is
restricted before database bytes are written, sealed into DELETE journal mode,
integrity checked, and published without replacing any existing destination.
Its JSON receipt includes all table counts, a snapshot SHA-256 and counts of
missing historical blob references; it contains no row values or credentials.
Present corrupt blobs or malformed ledger/reference data reject publication.
Missing/expired references remain unavailable, rather than becoming restored
proof. This is one SQLite database snapshot, not an application-wide backup.

`restore --source <sealed-backup.db> --destination <new-restore.db>
--expected-sha256 <receipt-digest>` verifies the operator-retained receipt digest,
rejects SQLite sidecars, and follows the same checks/private publication. Restore
requires a quiesced backup in a trusted directory: do not modify it during the
operation. A digest establishes agreement with the retained receipt, not
authenticity against an attacker who can replace both. Existing destinations are
never overwritten; service shutdown and explicit activation of a restored file
remain operator work. No startup recovery or automatic deletion was added.

A full sensitive backup needs application
identity/proof tables, referenced evidence blobs, context/HMAC metadata and any
separately required cache/log/export files. It must preserve access restrictions
and encryption/OS policies independently of the token-file helper.

Synthetic caller tests compare every copied table and verify real production
schema metadata preservation, live-WAL backup, unavailable references, actual
Windows DACL, and corruption/digest/permission/overwrite controls. They establish
the command's bounded behavior; a production rehearsal is still operator work.
Stale generated pairing
credentials should not be restored as current authentication. Disposable
SQLite backup tests do not establish a whole-application restore contract.

## Operator maintenance procedure and unsupported scope

1. Run `plan`; record the owned database paths and every separate cache, audit
   sink, trace directory, report/export, Burp/browser capture, and backup copy.
   Resolve which contexts share a host before considering host deletion. This
   inventory is operator-declared; the command never scans arbitrary directories.
2. Set an organizational retention period and encrypted storage policy for each
   category. SQLite keep-forever defaults remain explicit. Blob expiry alone
   cannot fulfill deletion of findings, identities, session material or global
   notes/work items. Use `wipe-context` for the explicitly attributed subset;
   do not substitute a host wipe where another context still needs the host.
3. Snapshot each required SQLite database to a new restricted path; save each
   nonsecret receipt separately. For non-SQLite files, quiesce the owned producer,
   inventory its closed files, and use an OS backup tool preserving ACLs and
   encryption. Logs rotate by size; age-based cleanup, trace/export copies and
   third-party captures require the owner's own retention procedure.
4. Rehearse restores to fresh paths before maintenance. Compare table identity
   records and resolve/hash-check required blobs in the restored store. Treat a
   nonzero unavailable-reference count as incomplete historical evidence. Stop
   owned services before activating a restored store; re-pair credentials.
5. Apply only documented explicit maintenance APIs to the intended owned data.
   Stop owned services/jobs; review context deletion counts and preserved tables.
   Review cache clear separately from evidence expiry, and review host deletion
   counts against its documented subset. Closed logs/exports/backups must be
   handled separately by the operator. There is no whole-application delete,
   automatic age retention, encryption implementation or secure-erasure claim.
   SQLite freelists, old WAL files, backups and filesystem snapshots can retain
   deleted bytes; logical deletion does not establish physical sanitization.
