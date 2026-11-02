# Batch I16-wiring (Python side) — 2026-11-02

Base: `ff6f7a0` (merged main). Branch `claude/i16-wiring-2a18d0`. Offline only: owned
loopback fixtures, no live target, no config default change.

## What I16 means here (found, before coding)

Sources: CURRENT_STATE.md item 7; docs/CODE_REVIEW_02_TRIAGE_2026-10-19.md (RV-S
follow-ups, RV-T); `.test-work/rv-s-protectedroutes-20261021/HANDOFF.md` residual 1 and 4;
`.test-work/rv-t-crossrequestdecisions-20261021/HANDOFF.md` ("API/Burp wiring is deferred
to I16"); docs/REMAINING_IMPLEMENTATION_PLAN_2026-10-17.md I04 status ("Issue export and
SARIF carry no `suggested_test` for any finding; that parity gap is I16 work").

1. **Protected routes.** The consumer exists: the chain's missing-auth branch builds
   `ProtectedRoutes.for_target(config, base_url, engagement_paths=state.protected_paths)`
   (orchestrator_chain.py ~1337). `state` comes fresh from `build_engagement` each run and
   nothing ever sets `protected_paths`, so only the config source is live.
   Wire: `POST /engagement/{host}/investigate` gains `protected_paths: list[str]` →
   `investigate_engagement(protected_paths=...)` → merged into `state.protected_paths`
   after discovery (built or restored from the journal).
2. **Ownership.** Same shape: `state.owners` is consumed by `_configure_ownership` /
   `_experiment_ownership` (RV-T T2), but nothing sets it. Wire `owners: list[dict]` the
   same way. Entry shape and validation stay `ownership_declarations.load_ownership`'s.
3. **`suggested_test`.**
   - Produced: agents, validators' `manual_verification` (I04, chain `_apply`), and the
     missing-auth probe. Consumed: stored rows, the API, Burp "Next step", Markdown.
   - Gap A (RV-S residual 4): an unlisted route's missing-auth candidate does not say how
     to declare it. Produce a declaration hint in the candidate's `suggested_test` (not in
     summary/evidence, so RV-M M1 assertions stay byte-for-byte).
   - Gap B (I04 parity): `issues.export_issue` and the SARIF export drop it. Carry it in
     the issue export (end of the dict, clear of AR-08b's hunk) and a SARIF result property;
     SARIF import reads it back.

Passive defaults: an absent or empty list sends nothing extra, sets nothing on the state,
and leaves the journal context key unchanged (new request fields are excluded from the key
unless non-empty).

## Out of scope (Java-only or other owners)

- Burp HarnessPanel/HarnessClient fields to send the lists (needs JDK + I01 W-split; RV-K).
- Persisting the lists per host in store.py (AR-08 owns store.py). Lists are per request.
- Custom-header-only auth (RV-S residual 2), probe `_strip_auth` (residual 3).

## Regression first (caller level, through the real engagement path)

- Chain: real `investigate_engagement` with RV-S's loopback + doubled builder/worklist,
  lists passed as the new kwargs (not seeded on the state):
  listed route confirms (source "engagement"); unlisted route stays a candidate and its
  `suggested_test` carries the hint; empty list == no list (same sends, same findings);
  listed route that denies gives no finding.
- Ownership: RV-T's X2 fixture with `owners=` passed as the kwarg: invoice confirms,
  shared does not; without it no confirmation.
- Route: `POST /engagement/{host}/investigate` forwards the lists; omitted → kwargs not
  passed; wrong types → 422; journal key unchanged when empty.
- Export: issue export + SARIF carry `suggested_test`, redacted.
