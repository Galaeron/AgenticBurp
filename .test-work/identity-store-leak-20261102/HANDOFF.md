# Identity-store leak across engagements — HANDOFF (2026-11-02)

Branch `claude/identity-store-leak-3b4646` (not pushed).

## Root cause
`Orchestrator.investigate_engagement` (`harness/orchestrator_chain.py`) registers each
role's headers in the process-global `identity_headers._STORE` keyed by host and never
removes them. In a long-running server a later engagement on the same host reads the
earlier engagement's roles as "other identities" (cross-identity leg, ownership
loading, detect-time IDOR control, registry auto-arm) -> cross-engagement contamination.

## Store map
Writers: `orchestrator_chain.investigate_engagement` (per-role registration);
`server.py` POST identities/session-headers (operator-fed); tests.
Readers: `cross_identity_validator._run_identities` (when no run_context),
`orchestrator._configure_ownership`, `orchestrator_detect` (~L496),
`validators/registry.py` auto-arm (`has_identities`), `server.py` response.
All readers run on async paths inside the engagement task (`asyncio.to_thread` also
copies contextvars), so a contextvar can carry the engagement's scope to them.

## Fix (smallest correct)
`harness/identity_headers.py`: each (host, name) now keeps one claim per owner. Owner
is the current lease (a `ContextVar`) or `None` for operator-fed registrations.
- `@identity_headers.leased` (applied to `investigate_engagement`) opens a lease and
  releases ITS claims in `finally` (return, raise, cancel).
- Readers see operator claims plus claims of their own lease chain only; the last
  visible claim per name wins (same "engagement overrides operator" precedence as before).
- Overlapping engagements on one host neither remove nor see each other's roles.
- An operator identity shadowed by an engagement role of the same name is restored
  afterwards (previously it was overwritten permanently).
- Readers outside any engagement no longer see a live engagement's roles (only operator ones).
- Public API (`set_identity`, `identities_for_host`, `has_identities`, `clear`) unchanged.
Chosen over explicit token register/unregister because it needs no change at the
registration call site or any reader, and no re-indent of the 1500-line function.

`harness/orchestrator_chain.py`: +1 import line, +3 lines (comment + decorator) above
`def investigate_engagement`. Kept clear of PR #10 hunks (L931+, L1017, L1496) and
PR #11 hunks (L23 import block context L23-28, L2266).

## Tests — `harness/test_identity_store_lease.py` (caller-level, real investigate_engagement,
silent model, fake discovery/worklist from test_engagement_chain_relink; synthetic tokens)
1. sequential engagements alice then bob: bob's in-run store reader sees only bob.
2. engagement raising: registrations removed.
3. engagement cancelled: registrations removed.
4. overlapping alice/bob: each sees only itself; alice's release keeps bob's live claim.
5. control: single engagement sees its role + operator identities; operator ones survive,
   shadowed one restored.
Defect injection (decorator removed): all 5 fail (5 = new restore assertion only).
Auto-discovered by `unittest discover` (no suite registration needed).

## Gates (PYTHONPATH=worktree) — all exit 0
| gate | py3.12 venv | py3.14 system |
|---|---|---|
| unittest harness.test_orchestrator_precondition | 0 | 0 |
| unittest harness.test_identity_store_lease | 0 | 0 |
| harness.suite smoke | 0 | 0 |
| harness.suite full (5061 tests) | 0 | 0 |
| git diff --check | 0 | 0 |
Status files: `py312.status`, `py314.status`; script `run_gates.sh`.

## Next step
Review/merge; expect a trivial context conflict only if #10/#11 move the lines next to
the decorator/import. Follow-up (not done): the server's operator `clear`/identities
endpoints still act on the global host bucket (by design).
