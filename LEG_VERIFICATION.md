# Leg verification status — the live-verified vs smoke-only split

> Historical qualification record. Current routing/tiers are defined by
> `harness/confirmation_gate.py` and validators; see ORACLE_RETIREMENTS.md.
> Silence or a skipped leg is not a controlled negative and cannot establish
> refutation. This table is not a fresh verification of the current checkout.

The confirmation legs are not equally trustworthy. A leg that has only ever
passed a **smoke test** (network stubbed at `httpx`, decision logic asserted) is
not the same as one **live-verified** against a real target with a true positive
and a matched negative control. This file is the canonical record of which is
which, and it is the data structure the confirmation gate consumes:
`confirmation_gate.LIVE_VERIFIED_MARKERS` mirrors the **live** column, and Phase 2
verification is what moves a leg from *smoke_only* to *live_verified* there.

Why the gate cares (Phase 1.1): for an **unconfirmed** finding, a live-verified
leg's silence is strong evidence against (→ demote to low, REFUTED); a smoke-only
leg's silence is weak evidence (→ cap at medium, UNPROVEN — don't bury a
possibly-real finding). So promoting a leg here tightens suppression for its
class.

## Status

| Leg | Class | Status | How verified |
|---|---|---|---|
| `cross_identity` | idor / access control | **live_verified** | session-11 max-coverage run vs VulnCorp (IDOR confirmed) |
| `sqlmap` | sqli | **live_verified** | session-11 run (SQLi confirmed, sqlmap-in-container) |
| `jwt_forge` | jwt (alg:none) | **live_verified** | session-11 run (alg:none forgery accepted) |
| `xxe` | xxe | **live_verified** | session-11 run (`/api/tickets/import`, OOB callback) |
| `path_traversal` | path_traversal | **live_verified** | session-11 run (`/uploads/1` → win.ini); re-confirmed via `run_leg_verification` against the fixture |
| `ssti` | ssti | **live_verified** | Phase 2, `test_leg_live_verification` — real Jinja render endpoint (`{{89*97}}`→8633) + escaped-echo negative control |
| `open_redirect` | open_redirect | **live_verified** | Phase 2, `test_leg_live_verification` — real blind 302 to a sentinel host + fixed-target negative control |
| `ssrf` | ssrf | **live_verified** | `test_leg_live_verification` — a real server-side fetch of the `url` param to the in-process collaborator + a no-fetch negative control |
| `command_injection` | command_injection | **live_verified** | `test_leg_live_verification` — a real shell endpoint runs the injected `curl` fetch to the collaborator (skipped when `curl` is absent) + a no-shell negative control |
| `sequence` | mass_assignment | **live_verified** | `test_leg_live_verification` — a real mass-assignable write persists across an independent re-read + an allowlisted-write negative control. **Session 13: generalised** to detect a flipped field at ANY nesting depth (recursive walk) and to derive authority-named candidate fields from the resource's own baseline schema (not just a fixed priv-name list) — + a nested-response/non-canonical-field TP and control |
| `deserialization_oob` | deserialization (pickle RCE) | **live_verified** | Session 13, `test_leg_live_verification` — a real `pickle.loads(cookie)` sink runs a benign OOB beacon (pickle `__reduce__` → loopback fetch of the collaborator) + a `json.loads` negative control. No gadget chain / destructive payload (the passive `deserialization` validator still owns Java/PHP/.NET format-fingerprinting) |
| `auth_sequence` | session_fixation / weak_password / username_enumeration | **live_verified** | Session 13, `test_leg_live_verification` — multi-request auth flows: session id not rotated across login / weak password accepted at register / login response discriminates a valid vs invalid account. Each with a matched control (rotating session / min-length policy / uniform error) |
| `stored_xss` | xss (stored / second-order) | **live_verified** (deterministic path) | Session 13, `test_leg_live_verification` — plant a script-executable payload via a write, confirm it returns UNESCAPED in a `text/html` render on an INDEPENDENT read + an escaped-render control. Optional headless-browser execution proof when a browser is present. This is the plant→observe primitive for second-order flows |
| `secret_disclosure` | jwt (signing key) | live (offline proof) | Phase 3.1 — HMAC verification is cryptographic proof; no live send needed |
| `browser_xss` | xss (reflected) | smoke_only (default) | seam-mocked unit test. OBSERVED confirming live via `run_leg_verification` (real Chromium executed the reflected payload) — but kept smoke_only in the DEFAULT gate set because Chromium is optional infra ON THE HARNESS; on a browser-equipped machine promote it via `apply_confirmation_suppression(live_verified_markers=...)`. The session-13 max-coverage run did NOT promote it — XSS was detected only on non-HTML (JSON) sinks it correctly declined |
| `jwt_forge` (kid) | jwt (kid key-confusion, V9) | **live_verified** | Session 13, `test_leg_live_verification` — `kid`-derived-key confusion (kid used as the HMAC key; kid→empty/unreadable file → empty-key fallback), validly HS256-signed under the confused key, accepted where the garbage control is rejected + a fixed-secret control |

The ~13 analyze-only class validators (`cors`, `csp`, `crypto`, `recon`,
`oauth`, `header_injection`, `http_request_smuggling`, `web_cache_poisoning`,
`subdomain_takeover`, `websocket`, `race_condition`, `api_security`,
`deserialization`) are unit-tested only and are not part of the gate's
confirmable set.

## How to live-verify

- **Hermetic, in the `unittest` suite** — `harness/test_leg_live_verification.py`
  stands up `testing/leg-verification/vuln_fixture.py` on a real localhost socket
  and runs each leg against a true-positive endpoint + a matched control, with
  real HTTP (no stubs): `ssti`, `open_redirect`, `ssrf` and the `sequence`
  (mass-assignment) leg all run here. `command_injection` runs here too but is
  skipped when `curl` is absent (the injected payload needs it on the host). The
  OOB legs reach the in-process collaborator (`collaborator.py`), which is itself
  just a loopback listener — no external service needed.
- **Operator-run** (`python testing/leg-verification/run_leg_verification.py`) for
  the legs whose confirmation depends on host infra the suite can't assume:
  `path_traversal` (a real canonical system file) and `browser_xss` (a real
  Chromium). Both confirmed on the dev machine this session.

When a leg is newly live-verified, add its class markers to
`confirmation_gate.LIVE_VERIFIED_MARKERS` and update the table above.

## Freeze policy (Phase 2.1) — LIFTED for session 13 by operator direction

The freeze ("no new legs until the smoke_only ones are live-verified") did its
job: every leg in the table above is now live-verified against a fixture with a
matched negative control (the only default-`smoke_only` one left is reflected
`browser_xss`, which needs host Chromium). Session 13 was an operator-directed
push to CLOSE THE MISSING-CLASS GAPS, so new legs were added — but under the same
discipline the freeze was protecting: **every new leg ships with a disposable
fixture TP + a matched control + a live-verification test in the same commit.**
No leg was added on a hermetic/mock test alone. Re-apply the freeze once this push
lands: the next unverified leg blocks the one after it.

## Deferred legs — architectural decision needed (session 13)

These missing classes were NOT built this session because each needs an operator
decision the harness shouldn't make unilaterally (they trade off safety or
precision). See `LEG_DECISIONS.md` for the specific question and a recommended
approach for each: **verb-tampering (V15)**, **CSRF (V32)**, **file-upload (V33)**,
**rate-limit absence (V4)**, **reset-token entropy (V3)**, and explicit
**second-order SQLi chain composition (V22)**. The stored/second-order XSS leg
already provides the plant→observe primitive those second-order cases build on.
