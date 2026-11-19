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
- Discount-code reuse and expiry are not attempted here; the `business_flow` leg below
  covers forged, expired and another identity's codes.
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

# Multi-step business flows (`business_flow`, R11-7)

`harness/validators/business_flow_validator.py` replays the run's own captured
flow on a run-owned identity, reads the resulting state back, and restores what it
can. It never uses knowledge of the target app: the settlement, the cart writes the
same identity made before it, the coupon or 2FA-disable write, and the captured GETs
that read the state back all come from `experiment_context["captured"]`.

| Row | Class | What it confirms |
|---|---|---|
| `WSTG-BUSL-10` | `payment_tamper` | The captured cart steps and settlement are replayed untampered (the control), then with a client-chosen amount (set to 1 or 0.01), a negative quantity or a nonexistent delivery id. Confirmed when the read-back (a new order's total, a balance delta) shows less was charged than the control, or a negative total. With no amount field, the payment field is dropped, then forged: confirmed only when a read-back shows a granted standing (tier, membership) and no balance debit. A new order alone is a lead (`supported`). |
| `AV-BUSL-COUPON-01` | `coupon_misuse` | A forged code (same shape, random), an expired code (declared, or a captured write answered 4xx with "expir") and another run identity's code (captured or declared) are applied to the captured coupon write. Confirmed when the basket or order read-back shows a discount, or a lower total, that it did not show before. Another identity's code seen only in the capture confirms nothing, since codes may be shared; it is a lead. A coupon carried by the settlement itself goes through the settlement comparison above. |
| `WSTG-BUSL-06` | `mfa_disable_stepup` | The captured 2FA-disable request is replayed with its password or TOTP field dropped, then wrong. Confirmed when the status read-back shows 2FA off. It needs a status read that shows 2FA enabled first; otherwise it writes nothing. |

## How it is gated

- It sends nothing unless `validators.active_enabled`, `validators.allow_mutating_replay`
  and an explicit `validators.mutating_ceiling_by_check.business_flow` are all set.
  The committed `config.yaml` sets none of them. The ceiling must pay for the whole
  plan (a control flow plus one tampered flow) before the first write.
- Only a run-owned identity acts: the capture's credentials must match a session the
  run registered. Ephemeral or foreign credentials skip the check. Every send goes
  through `RunContext.executor()` as that session.
- It never sends DELETE. One flow runs at a time per identity.

## Cart steps and variants (R11-7c)

- The cart steps are the actor's captured POST/PUT/PATCH writes before the first
  capture of the settlement, at most three (the latest). A write counts when its
  path is cart-shaped, or when the run's own captured read-backs show its effect: a
  read before and after it gains an entry carrying one of the write's (name, value)
  pairs, or a read only after it holds an entry carrying two. Auth, 2FA, coupon and
  settlement writes are never cart steps. An unrelated write is not replayed.
- Tampered variants take one per value family first (amount, quantity, delivery),
  then the rest, at most `max_variants` (default 2, hard cap 4); the ceiling bounds
  them again before each flow.
- A refused tampered settlement leaves its flow's cart items in the basket. The next
  settlement-step variant settles that basket without a refill, so it is never fuller
  than the control's. A cart-step variant stops there. Items a refused flow left are
  named `LEFT IN PLACE`.

## Settlement race (R11-7c, off by default)

`validators.business_flow.settlement_race: true` adds a race after a
`payment_tamper` check that did not confirm. It runs only on a flow with cart steps:

1. Fill the basket once and settle twice in sequence: the control shows how many
   entries, and how much balance, one filled basket allows.
2. Fill it once more and send `race_copies` (default 2, hard cap 5) concurrent
   settlements. The safety gate's `authorize_burst` sets the count, so
   `validators.max_burst_size` caps it; below 2 nothing is raced.
3. Confirmed only on the read-back: a read that gained exactly one entry in the
   control gains two or more, or a balance moves by more than the one sequential
   settlement moved it. Status codes decide nothing.

It needs a ceiling for `2 x cart steps + 2 + race_copies` writes on top of the
tamper flows (16 covers one cart step). It is skipped, and the reason named, when
the second sequential settlement also settles (the basket is not consumed), or when
no read-back shows one settlement.

Left open: a race on one balance or a one-time grant with no cart step (the
sequential control would consume it). There is no own catalog row; the race reports
under `WSTG-BUSL-10`.

## Restoring

- **Orders and grants.** A placed order, including the untampered control, cannot be
  undone without DELETE. It is named `LEFT IN PLACE` in the summary and recorded in
  the change log as a failed restore. So is a standing that a payment skip granted.
- **Coupons.** A code in the body is cleared by resending the write with the code
  emptied, or with the code the basket held before, and the clearing is verified on
  the read-back. A code in the path cannot be cleared without DELETE, so it is named.
- **2FA.** It is re-enabled by replaying the identity's own captured enable or setup
  request and verified on the status read. If the identity declares a TOTP secret
  (`role.login.totp_secret`), a 6-8 digit code field in that request gets a freshly
  computed RFC 6238 code. The secret and the codes are never logged or reported. If
  the run has no such request, has no secret, or the replay still fails, the summary
  says `2FA LEFT DISABLED on <identity>` and the change log records it. A setup that
  needs a fresh server-issued value (not only a code) stays disabled.
- **Race.** Orders the race's sequential control and concurrent copies placed are
  named `LEFT IN PLACE`, as are cart items a refused race left in the basket.

## Options (`validators.business_flow`)

- `read_backs`: extra `GET /path` reads of the settled state.
- `coupons`: `{expired: [...], by_identity: {<name>: <code>}}`. A declared code
  belonging to another identity may confirm.
- `mfa_status_reads`: extra 2FA status reads.
- `max_variants`: tampered variants per payment_tamper finding (default 2, hard cap 4).
- `settlement_race` (default false) and `race_copies` (default 2, hard cap 5).

Trial settings, in `config.local.yaml` only:

```yaml
validators:
  active_enabled: true
  allow_mutating_replay: true
  mutating_ceiling_by_check:
    business_flow: 8          # a 3-step cart + settlement: control + one tamper
```

Use a fresh target container: placed orders stay.

Tests: `harness/test_business_flows.py` (loopback shop). It covers:

- a positive and a matched negative for each flow, through the real dispatch;
- payment skip;
- the defaults sending nothing;
- no ceiling, or foreign credentials, sending nothing;
- an unrestorable 2FA disable named in the summary and in the change log;
- the capability gate;
- no DELETE, ever;
- R11-7c: a coupon carried by the settlement body (forged code confirms; checked codes
  hold, and the leftover basket is named); the settlement race (a racy shop confirms,
  a serialized one holds, switch off, burst ceiling 1 and a short ceiling send no race);
  a basket filled through a non-cart path found by its read-back, and an untraced write
  not replayed; variant spread and caps; 2FA re-enabled with a declared TOTP secret,
  and named left disabled with none or a wrong one, with the secret never printed.

