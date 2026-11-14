# Write-path checks (`write_integrity`)

`harness/validators/write_integrity_validator.py` confirms five write-path flaw
classes by writing, reading back as every registered identity, and undoing the
write. It is active and inert by default: it runs only when
`validators.allow_mutating_replay` is on, and the run's gate admits each send.

| Class (coverage cell) | What is sent | Confirmed when | Negative control |
|---|---|---|---|
| `cross_identity_write` (AV-WRITE-XID-01) | the captured create with a `*Id` reference, or a path id, swapped for an object another registered principal owns | the read-back stores the other principal's reference | the server refuses it, or binds the reference to the writer's own object |
| `forged_authorship` (AV-WRITE-AUTHOR-01) | an author/owner/user field set to another identity (or a fabricated one) | the read-back stores the forged value | the server binds authorship to the session |
| `business_rule_tamper` (AV-WRITE-BIZ-01) | a quantity, rating, price or total set to -1, on a create or on an update of an existing object | the read-back stores -1 | the server refuses or normalizes it |
| `mass_assignment_create` (AV-MASSASSIGN-02) | the create plus role/admin/verified fields | the attack's read-back carries a privileged value the plain create's does not | the stored object ignores the fields |
| `create_validation` (AV-WRITE-VALID-01) | a duplicate of a unique email/username create, and a create with every string emptied | a second object is stored, or the read-back shows an emptied field | the duplicate and the empty create are refused |

## How each run behaves

- Every create case starts with a plain-create **positive control**. The control
  is DELETEd and its absence verified before any attack is sent, so a broken
  restore path costs one object, never an attack's.
- Every attack create is DELETEd and verified gone. An update tamper is restored
  to its snapshot and verified equal. Each write's restore outcome lands in the
  run's change log (`restored` / `restore_failed`) and in the result's evidence
  (`restore=sent; restored=...; restore_succeeded=true|false`).
- A restore that cannot be verified is an `error` result starting
  `RESTORE FAILED`, naming the object to remove by hand.
- A create runs only when its DELETE route is known: observed in the engagement
  (`state.endpoints`) or declared in `validators.write_integrity.restore_routes`.
  Otherwise the case is skipped, before any write, with the route it needs.
- Other principals' objects come from operator ownership declarations or from
  self-observed ownership (`authz.self_observed_ownership`).
- Discount-code reuse and expiry are not attempted (they need a declared spent code).
- `sequence` hands a mass-assignment finding on a collection create
  (`POST` to a listing) to this leg, because it could never delete what it made.

## Live trial (in `config.local.yaml`, never `config.yaml`)

```yaml
validators:
  active_enabled: true
  allow_mutating_replay: true
  mutating_ceiling_by_check: {write_integrity: 8}   # 4 per create+attack; 8 for create_validation
  write_integrity:
    restore_routes: ["DELETE /api/things/{id}"]       # any create route whose DELETE was not observed
authz:
  self_observed_ownership: true                      # or declare ownership per object
```

Register two non-privileged identities, so cross-identity and authorship checks
have another principal. Use a fresh target container: these checks create and
delete objects.

Tests: `harness/test_write_integrity.py` (generic loopback store; every class
confirmed and controlled, the refusals, a restore failure, and the registry,
confirmation and chain callers).
