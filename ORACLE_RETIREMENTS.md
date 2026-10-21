# Oracle retirements — confirmation verdicts stood down until they qualify

Driven by the 2026-09-09 project review's **confirmation-oracle audit**
([`reviews/2026-09-09/PROJECT_REVIEW.md`](reviews/2026-09-09/PROJECT_REVIEW.md)).
Each leg below used to emit `confirmed=True` from evidence that does **not** exclude
a benign explanation — an "overconfirm." Per the review and the operator's
direction, the unsound **verdict** is retired (the leg now emits a `not_confirmed`
**observation** carrying the same evidence), while the detector/capability is kept.

**This file is the single record of what was stood down and how to restore it.**
A future agent re-qualifies a leg by implementing the "Re-qualify by" control,
proving it against a paired positive/negative real-transport fixture, then flipping
the verdict back to `confirmed=True` and (where noted) re-adding the class to
`confirmation_gate.LIVE_VERIFIED_MARKERS`.

Search the code for `RETIRED (review 2026-09-09)` to find each site, and for
`RETIRED (review 2026-10-21, WL-04)` for the cross-identity retirement below.

| Leg (file) | Why the verdict was unsound | Now emits | Re-qualify by |
|---|---|---|---|
| passive deserialization (`deserialization_validator.py`) | A Java/PHP/ViewState **format signature** ≠ an unsafe-deserialization sink (may be signed / integrity-checked / never deserialized untrusted) | `not_confirmed` observation ("format OBSERVED") | The separate `deserialization_oob` leg (benign OOB pickle/gadget beacon) — keep this one informational, do not restore a verdict |
| rate limit (`rate_limit_validator.py`) | Replaying a **valid** request N× without a 429 can't establish failed-login lockout; counted non-throttle 5xx as clean attempts; as few as 2 confirmed | `not_confirmed` observation ("no throttle in N attempts") | Authorized test account + **invalid-credential** burst + explicit policy/window + cooldown/reset control |
| reset token (`reset_token_validator.py`) | Small-sample predictability pattern ≠ exploitability (2 numeric samples always have a constant delta; public-prefix+random-suffix isn't predictable) | `not_confirmed` observation ("pattern seen, needs holdout") | **Holdout prediction**: forge the next token from prior samples, submit it, show it's accepted for another account; + lifetime/single-use/rate-limit context |
| CSRF (`csrf_validator.py`) | A token-strip **2xx replay** doesn't prove a victim browser sends the request with **ambient** credentials (bearer/JSON aren't ambient; Origin/default-SameSite may protect) | `not_confirmed` observation | Cross-site **browser PoC** with ambient cookies + independent state-change check; controls for bearer-only, Origin enforcement, default SameSite. **Also re-add `csrf` to `LIVE_VERIFIED_MARKERS`.** |
| verb tamper (`verb_tamper_validator.py`, ×3 sites) | An alternate method returning 2xx where the original was denied can be **ordinary routing**, not an authz bypass | `not_confirmed` observation | Compare the **same** protected data/action under the **same** unauthorized principal across methods; public-GET/private-write control. **Also re-add `verb_tamper` to `LIVE_VERIFIED_MARKERS`.** |
| request smuggling (`http_request_smuggling_validator.py`) | Status/length/404 anomalies from an **ordinary-httpx** probe can't prove raw CL/TE desync framing or the front/back-end connection relationship | `not_confirmed` **candidate** | Protocol-specific raw transport controlling framing on a kept-alive connection, proven against a paired front-end/back-end desync fixture |
| web cache poisoning (`web_cache_poisoning_validator.py`) | Reflection of an unkeyed input / cache-friendly response ≠ **cached** attacker influence served to another client | `not_confirmed` **candidate** | A clean **second-client** retrieval returning the attacker's influence / private data under the controlled cache key |
| file upload (`file_upload_validator.py`) — *tightened, not fully retired* | Serving a stored `.html` as `text/plain` or as an **attachment** is a benign storage bypass, not a dangerous execution context | Confirms only when served as an **active** HTML/script/svg Content-Type and NOT an attachment; otherwise `not_confirmed` observation | (already qualified for the active-context case) |
| cross-identity similarity-only (`cross_identity_validator.py`, object-level BOLA and function-level BFLA; review 2026-10-21, WL-04) — *gated, not removed* | Another identity's response matching the source principal's (≥0.70 trigram) while anonymous is denied ≠ a boundary crossing: a resource legitimately shared with **every logged-in user** (a team announcement, a management view shared with all staff) matches identically; an admin namespace is a path-name heuristic, not a declaration of who may reach the function (cf. RV-M M1). Every production construction passed `ownership=None` (E38) | `supported` lead ("ownership NOT declared", `control_outcome=inconclusive`, `manual_verification` guidance) — neither a controlled negative (`confirmation_gate`) nor tested coverage (`coverage_tracker`). Confirms only when a **declared** ownership/entitlement fact says the accessor (or the captured source principal) is not entitled (`principals.OwnershipLedger`, injected through `ValidatorRegistry.set_ownership`); authorized sharing stays the `not_confirmed` observation | Owner decision **D1** (`reviews/2026-10-21-dual-mode-cross-request-audit/WORK_LIST.md` §4): where declarations come from (operator API, engagement config, fixture). Wire that source into `ValidatorRegistry.set_ownership`; the declared-ownership confirmation is already proven on paired loopback fixtures (`test_cross_identity_ownership_gate.py`, `test_smoke_authorization_workflow.py`, `test_pipeline_gate.py`). `idor` stays in `LIVE_VERIFIED_MARKERS` because the verdict is kept behind the declaration, not removed |

Gate effect: `csrf`, `verb_tamper`/`misconfig` were removed from `confirmation_gate.LIVE_VERIFIED_MARKERS` (they stay in `CONFIRMABLE_CLASS_MARKERS`, so the suppression gate now treats them as **provisional** — capped at medium, never "refuted"). `rate_limit`/`reset_token` were already provisional. Tests: `test_oracle_retirements.py`, plus updated cases in `test_missing_legs.py`, `test_deferred_legs.py`, `test_confirmation_gate.py`. (Dedicated hermetic tests for the smuggling/web-cache retirements are a follow-up — they need network mocking; the retirement is a hardcoded `confirmed=False` invariant guarded by the full suite.)

## Log

- **2026-09-10** — Retired the eight verdicts above (review §"Confirmation-oracle audit"). Detectors kept; verdicts stood down to observations/candidates. Suite green.
- **2026-10-21** — WL-04: the similarity-only cross-identity confirmation (BOLA and BFLA) is gated behind declared ownership. Without a declaration the leg emits a `supported` lead with manual-verification guidance; with one it still confirms. No production declaration source exists yet (D1), so production runs emit leads until the owner wires one. Seven existing tests that asserted a similarity-only confirmation were given declared-ownership variants; no negative control was weakened.
