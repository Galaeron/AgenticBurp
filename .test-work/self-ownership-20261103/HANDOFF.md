# Self-observed ownership — handoff (2026-11-03)

Branch `claude/sleepy-wu-832279` (worktree `identity-store-leak-3b4646`), base main `bae5321`.
Not pushed.

## Problem (from `.test-work/juice-shop-8h-20261103/YIELD_ANALYSIS.md`, i16-persist worktree)
116 idor_read and 20 cross_identity proofs ended inconclusive/supported on "no ownership or
deny fact is known", with `ownership_facts`, `identities` and `engagement_declarations` all empty,
even though the harness had logged in two fresh accounts itself and read their own baskets.

## What changed
- `harness/self_ownership.py` (new): `SelfOwnership`, a per-run store fed ONLY by
  `source="transport"` (TargetTransport.execute, final non-redirect response) and
  `source="capture"` (`analyze()` on a run with the store). Any other source is refused and
  counted (`rejected`). It records:
  - self-scoped read (`GET …/whoami|me|current_user|userinfo|self`, 2xx JSON with `id`/`email`):
    binds the requesting principal to that account; the account owns `users/{id}`;
  - login (`POST …login|signin|authenticate|oauth/token|session(s)`, 2xx JSON with `bid`/`basketId`
    AND an email/umail): that account owns `basket/{bid}`;
  - authenticated `POST` to a collection, 2xx JSON `id` (top level or under `data`): the creating
    principal owns `<collection>/{id}`.
  Objects are keyed by (collection stem, id) and matched against any URL path `…/<collection>/<id>`.
  Emails are kept only as a sha256 prefix. Each new fact is also written to the existing
  `ownership_facts` table as an audit copy (provenance `self_observed; owner=…; object=…; route=…;
  <how>`); nothing loads that table back.
- Decision rule (conservative): UNAUTHORIZED only when owner and reader are shown to be DIFFERENT
  accounts (same-kind account key differs), or two distinct operator-named non-alias principals.
  Same account (shared key) → AUTHORIZED. Unbound reader, anonymous reader, or an object two
  accounts were both served → UNKNOWN.
- `principals.OwnershipLedger`: `self_observed` attribute + `authorization_source()` →
  `(decision, "declared"|"self_observed"|"none", provenance)`. Any declaration for the object
  (exact, run-agnostic, pattern, or contradictory patterns, or an experiment-recorded fact)
  decides first; self-observed is consulted only when nothing is declared. `record()` now refuses
  a fact whose provenance starts with `self_observed` (only the store can hold those).
- `cross_identity_validator`: uses `authorization_source`; the credential-alias (provisional)
  downgrade still applies to declared decisions but not to self-observed ones (the account
  binding already answers "is this the same person"). Evidence says "Self-observed ownership…".
- `idor_read_validator`: optional `ownership` / `run_context`. After the existing anonymous
  control proves the foreign object protected, it asks the ledger about the capture's principal
  (run session owning its credentials, else `store.captured_principal_id`). UNAUTHORIZED →
  `confirmed` (0.9); AUTHORIZED (own account) → weaker candidate; else unchanged inconclusive.
  The anonymous-served / no-session / failed-control checks run first, so they keep priority.
- Plumbing: `RunContext.self_ownership` (created in `RunContext.create` iff
  `authz.self_observed_ownership is True`); `_configure_ownership` builds/attaches a ledger when
  the store exists; `_validate_findings` takes the per-run registry copy path when it exists and
  now copies `idor_read` too; `registry.set_ownership` sets idor_read as well; the engagement's
  `IdorReadValidator` gets the shared `ownership` + `run_context`.

## Default: OFF
`authz.self_observed_ownership` is read with a code default of off; `harness/config.yaml` is
untouched. With it absent every path behaves exactly as before (ledger None → no change).
To try it: `authz: {self_observed_ownership: true}` in the ignored `harness/config.local.yaml`.

## Owner questions
1. Should `authz.self_observed_ownership` default ON? It sends no traffic itself (passive);
   the risk is false confirmations, bounded by the different-account rule. If yes, add it to
   `config.yaml` and the safe-default guard tests.
2. idor_read was "never confirms" (RV-D2 V2). It now confirms when the ledger places the object
   with another account (declared or self-observed). Acceptable, or cap it at `supported`?
3. Are the self-scoped route heuristics acceptable (whoami/me/userinfo; login `bid`; POST `id`),
   or should they be operator-listable patterns (e.g. `authz.self_scoped_routes`)?
4. Should JWT-forged sessions be excluded as observers? A forged token's whoami binds that
   session to the victim account — correct as a fact, but it makes later reads by that session
   "same account" (AUTHORIZED), i.e. it can only suppress, never add, a confirmation.
5. Standalone `/analyze` creates a fresh run per exchange, so a store there sees one exchange;
   cross-exchange self-observation only works within an engagement run. Persist account bindings
   per host (new table) to cover standalone? (Not done: store.py is under the dedup session.)

## Not done / not verified
- No live Juice Shop re-run; the 8h numbers are unchanged until one runs with the key on.
- Query-string object ids (`?basketId=6`) are not matched, only path `…/<collection>/<id>`.
- `full` suite not run (task gates: precondition, touched tests, smoke, diff --check).

## Gates (this checkout)
See `gates.md` next to this file.
