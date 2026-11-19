# Write-path checks (`write_integrity`)

`harness/validators/write_integrity_validator.py` confirms six write-path flaw
classes by writing, reading back as every registered identity, and undoing the
write. It is active and inert by default: it runs only when
`validators.allow_mutating_replay` is on, and the run's gate admits each send.

| Class (coverage cell) | What is sent | Confirmed when | Negative control |
|---|---|---|---|
| `cross_identity_write` (AV-WRITE-XID-01) | the captured create with a `*Id` reference, or a path id, swapped for an object another registered principal owns; if that plain reference is refused, parameter pollution: the key duplicated in raw JSON (own value first, then foreign first) and an array form, each only when the ceiling still pays for its DELETE | the read-back stores the other principal's reference | the server refuses it, or binds the reference to the writer's own object |
| `forged_authorship` (AV-WRITE-AUTHOR-01) | an author/owner/user field set to another identity (or a fabricated one), on a create or on a PUT/PATCH of one object (snapshot, own-value control, forged write, written back) | the read-back stores the forged value | the server binds authorship to the session |
| `business_rule_tamper` (AV-WRITE-BIZ-01) | a quantity, rating, price or total set to -1, on a create or on an update of an existing object | the read-back stores -1 | the server refuses or normalizes it |
| `mass_assignment_create` (AV-MASSASSIGN-02) | the create plus role/admin/verified fields | the attack's read-back carries a privileged value the plain create's does not | the stored object ignores the fields |
| `create_validation` (AV-WRITE-VALID-01) | a duplicate of a unique email/username create, and a create with every string emptied | a second object is stored, or the read-back shows an emptied field | the duplicate and the empty create are refused |
| `unauthorized_update` (R11-5) | a PUT/PATCH of one object, first anonymous and then as the capture's own non-owner session, with one field (taken from the captured body, else from the snapshot) set to a marker; the object is snapshotted first and read back by its owner, else by an admin session | the owner's or admin's read-back carries the marker, on a route listed in `authz.protected_paths` (config or the engagement's `protected_paths`; anonymous writer) or an object `authz.owners` declares to someone the writer is not. A change anywhere else is a `supported` LEAD, never confirmed | the write is refused (`control_held`), or answers 2xx but the read-back is unchanged (`not_confirmed`) |

## How each run behaves

- `unauthorized_update` is also reached from `cross_identity`'s write leg: when that
  leg has no owner/baseline session for the capture, no restorable field in the
  captured write (for example a guessed `{name, value}` body), or no owner baseline
  object, it hands the PUT/PATCH to this check instead of skipping (unless
  `validators.write_integrity.enabled` is false). If this check cannot run either,
  the skip keeps the write leg's reason first. It needs a mutating ceiling of at least
  2 (write and write-back) and keeps one writer when the ceiling is below 3. Its
  confirmation carries `mechanism_classes` (`broken_access_control`, plus
  `missing_authentication` for an anonymous writer), so the R11-1 gate binds it only
  to those finding classes. The write-back is sent as the reader, then as each writer
  that got a 2xx, and verified equal to the snapshot.
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
- A PUT/PATCH whose path does not end in an object id (and whose answer names none)
  has no object to snapshot or write back, so it is skipped and the result says why.
- Other principals' objects come from operator ownership declarations or from
  self-observed ownership (`authz.self_observed_ownership`).
- Owner opt-in, off by default (code default; not in config.yaml):
  `validators.write_integrity.allow_unrestorable_self_service_creates: true` lets the
  create cases run on an anonymous sign-up that sends a password and has no DELETE
  route. Its accounts are never deleted; every one is named in the result
  (`left_in_place`). On that path, a refused or unreadable sign-up is read back by
  logging in with the credentials it submitted, through a login route the run
  observed. Only when that login fails before the create, succeeds after it, and
  refuses a wrong password does the result say "stored despite HTTP <status>"; an
  account that already logs in before the create is inconclusive, never claimed.
- Discount-code reuse and expiry are not attempted (they need a declared spent code).
- `sequence` hands a mass-assignment finding on a collection create
  (`POST` to a listing) to this leg, because it could never delete what it made.
- `verb_tamper`'s override POSTs use the same restore routes. An override the
  server ignores runs as a POST; a 201, a Location header or a body naming a new
  id is a negative for the bypass, never an observation. A 201/Location create is
  deleted and verified gone when its DELETE route is known, else named
  `LEFT IN PLACE` (result and change log) and the other override POSTs are
  withheld. An id named only by the body is never deleted on that alone. A path
  where the run already saw a POST create, with no DELETE route, gets no override
  POST (inconclusive, with the reason).

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
confirmation and chain callers); `harness/test_oracle_gaps_write_integrity.py`
(parameter pollution against a split parser, PUT/PATCH authorship, the opt-in and
its login read-back, each with a negative control).
