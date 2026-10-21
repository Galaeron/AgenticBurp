# Fix batch 1 — 2026-10-21

The first batch of fixes from [WORK_LIST.md](WORK_LIST.md). Branch `fix/cross-request-main-issues` is
based on `reconciliation-backlog` `71e8f12`. The batch was kept separate from PR #1 so that the
in-flight RV-O, RV-P and RV-Q sessions and the I01 W-split WIP are not disturbed.

**Status:** every ticket below is **implemented and caller-verified**, offline on owned loopback
fixtures. None is **live-validated** or **released**.

## What landed

| Ticket | Commit | Model | Change |
|---|---|---|---|
| WL-04 (I10) | `fix(cross_identity): require declared ownership …` | Fable 5.1 | An object-level or function-level cross-identity match confirms only against declared ownership or entitlement. Without a declaration it is a `supported` lead with `manual_verification` guidance: not confirmed, and not counted as a negative. Declared sharing is an authorized observation. `ValidatorRegistry.set_ownership(ledger)` is the single injection seam. Retirement recorded in `ORACLE_RETIREMENTS.md`. |
| WL-05 (I10) | `fix(discovery): confirm sensitive files by content signature …` | Opus 5.5 | A sensitive-file hit confirms only on a 2xx response whose body matches the content signature of its artifact class. Evidence quotes the real status and redacts values. Redirects, HTML shells, empty bodies and unknown types become "existence only" candidates. The sensitive-file phase no longer follows redirects inside a run. |
| WL-12 (I05) | `fix(run_engagement): own one bounded, cancellable run …` | Opus 5.5 | `run_engagement(execute=True)` owns one `RunContext`, or borrows an enclosing one. Its ceiling is `runs.max_requests`, falling back to `analyze.max_requests`. Page analyses borrow that run. Mutating replay is off, and an empty scope fails closed. |
| WL-02 (I06) | `fix(role_crawl): key the access matrix by principal …` | Opus 5.5 | Per-principal records (`by_principal`, `reachable_principals`, principal fingerprints) are authoritative. Role views are derived and never contradictory: when principals of one role disagree, the role cell is a sorted list of statuses. Seed import, `ingest_role_crawl` and `merge_from` merge instead of replacing. One shared object-ID rule covers digits, ≥12 hex characters and canonical UUIDs. |
| WL-11 (I05) | `feat(privacy): disclose and gate third-party lookups …` | Sonnet 5.5 | `privacy.external_lookups` (strict boolean, default `true`, so behaviour is unchanged) turns off the GitHub-advisory, npm/PyPI and CISA KEV lookups at the orchestrator and inside each client. Telemetry counts lookups per service (`external_lookup:<service>`). Disclosure added to `docs/LIMITATIONS.md`. |
| Integration | `test: shared and undeclared objects stay unconfirmed end to end` | (coordinator) | Two tests in `harness/test_principal_access_matrix.py` run `investigate_engagement` with WL-02 and WL-04 combined. The shared announcement and the undeclared invoice are not confirmed. Bypassing the ownership gate restores a confirmation, so the test is not vacuous. |

Fable 5.1 was requested for the hard fixes, but its safeguards refused WL-02 and WL-05/12 at
startup with a `[cyber]` flag on the security-tool context. Those two ran on Opus 5.5. WL-04 ran on
Fable 5.1 without a refusal. Each commit's `Co-Authored-By` line names the model that wrote it.

## Correction to the audit

E19 overstated the egress. The audit said component names *and versions* are sent to five services.
In fact only the ecosystem and package name are sent: to GitHub, and to npm and PyPI in the URL. The
CISA KEV feed is downloaded whole, and the Aikido malware feed has no production caller. E19 and the
decision report's finding 5 have been amended.

## Verification

All runs used Linux, Python 3.13.16 and `harness/requirements.lock` without the Windows-only
`mitmproxy-windows`. Commands are `python -m unittest harness.test_orchestrator_precondition`,
`python -m harness.suite smoke` and `python -m harness.suite full`, run from each worktree root with
no editable install.

| Tree | precondition | smoke | full: harness / native / evaluation / integrity |
|---|---|---|---|
| Baseline `71e8f12` (clean) | 74 OK | 146 OK, 9 skip | 3700 OK, 26 skip / 38 / 381 OK, 18 skip / 59 |
| WL-04 alone | 74 OK | 147 OK | 3716 OK / 38 / 381 / 59 |
| WL-05 + WL-12 alone | 74 OK | 146 OK | 3721 OK / 38 / 381 / 59 |
| WL-02 alone | 74 OK | 146 OK | 3712 OK / 38 / 381 / 59 |
| WL-11 alone | 74 OK | 146 OK | 3721 OK / 38 / 381 / 59 |
| WL-04 + WL-05 + WL-12 + WL-02 | 74 OK | 147 OK, 9 skip | 3749 OK, 26 skip / 38 / 381 OK, 18 skip / 59 |
| **This branch (all of the above + WL-11 + integration test)** | 74 OK | 147 OK, 9 skip | 3772 OK, 26 skip / 38 / 381 OK, 18 skip / 59 |

Every listed run exited 0; the branch row was run on `921916f` (the only later change fills in this row). A clean lockfile install therefore reproduces the counts reported for
`b8e8057` on this platform. That covers WL-01's reproduction acceptance for Linux/3.13; Windows/3.14
CI is still the reference.

Not run: the Java build (no JDK dependency cache), any live target and any real model.

## Behaviour changes operators will notice

- **Cross-identity:** BOLA and BFLA confirmations need a declared owner or entitlement. No
  production source of declarations exists yet (D1), so today every cross-identity match is a lead.
  This is the intended strict interim. Its recall cost is to be measured in WL-14.
- **Sensitive files:** most former "confirmed, high" hits become low or medium existence-only
  candidates. Confirmed hits stay high for every class.
- **`/engagement/{host}/run` with `execute`:** one ceiling for the whole call (1000 by default), not
  1000 per page. An empty scope now sends nothing.
- **Access matrix values:** a `by_role` / `access` cell can be a list of statuses when principals of
  one role disagree. UUID and hex routes are now object-scoped, which also changes issue grouping for
  UUID URLs.
- **One-time cache miss:** adding the `privacy` key changes the default configuration fingerprint,
  so cached analyses miss once.

## Owner decisions raised by this batch

| ID | Decision |
|---|---|
| D1 | Where ownership and entitlement declarations come from (operator API, engagement config, fixture). Should "shared with all authenticated users" be a first-class flag? Should declarations work per route pattern as well as per object URL? |
| D4 | The default for `privacy.external_lookups`, and whether `operating_profile: passive-only` implies `false` |
| — | Per-class severity for confirmed sensitive files; whether to prune `.well-known/security.txt`; whether to drop HTML-shell candidates |
| — | A dedicated `engagement.driver_max_requests` knob, and whether page analyses under the driver may use the operator's mutating policy |
| — | Whether `coverage_tracker` should map `supported` explicitly (today it is INCONCLUSIVE) and use `reachable_principals`. Both live in a file owned by RV-O. |

## Follow-ups found (not fixed here)

- `worklist_investigator` keys `role_headers` by role, so its probes use the last principal of a
  role. Engagement identities are still `rolecrawl:{role}`, and `probe_cross_role_*` (P1.3, no
  caller) is still role-keyed. Proposed owner: I06.
- `/engagement/{host}/run` has no HTTP cancel route, which would need `server.py`. Page analyses
  under the driver no longer emit per-page RUN_SUMMARY ledger events.
- `orchestrator_detect` cannot tell a skipped advisory lookup from a clean one. This only matters if
  a stage flag is forced on while lookups are off; no egress happens either way.

## Still held

These tickets wait for owner decision D2/D3 and for the I01 W-split. They need `store.py`,
`server.py`, `orchestrator_detect.py`, `knowledge.py` / `base_agent.py` or the Java models, all of
which carry WIP:

- WL-03 (relation records)
- WL-06 and WL-07 (advisory answer and multi-capture request)
- WL-08 (Burp parity)
- WL-09 (shared evidence across modes)
- WL-10 (knowledge-note scoping)
- WL-16 (prompt framing)

WL-13 to WL-15 (evaluation freeze and runs) are unchanged.

## Merge notes

The branch touches no file listed as in-flight or WIP in
[WORK_LIST.md](WORK_LIST.md) §1 and the I01 manifest. It does touch these shared files:

- `harness/orchestrator_chain.py`: three separate hunks;
- `harness/config.yaml`: one new key, no value changed;
- `harness/principals.py`: additive;
- `ORACLE_RETIREMENTS.md` and `docs/LIMITATIONS.md`: one entry each;
- `harness/test_pipeline_gate.py`: its positive runs now declare the fixture's ownership, and it
  gained an undeclared-ownership negative. Its defect injections are unchanged.
