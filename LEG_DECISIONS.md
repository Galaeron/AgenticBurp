# Deferred confirmation legs — architectural decisions needed

> Historical design discussion, not a current backlog. Several legs below have
> since been implemented or had their verdicts retired. Consult the registry,
> ORACLE_RETIREMENTS.md and CURRENT_STATE.md before scheduling new work.

Session 13 built and live-verified active confirmation legs for the tractable
missing classes (deserialization, session-fixation, weak-password, username-
enumeration, stored/second-order XSS, JWT `kid` key-confusion, and generalised
mass-assignment). The classes below were **deliberately paused**: each hinges on a
decision that trades off SAFETY or PRECISION in a way the harness owner should
make, not the harness by default. For each: the confirmation oracle, the specific
decision, and a recommended safe implementation to unblock it.

These are the honest frontier. None is blocked on effort — each is blocked on a
choice. Once a choice is made, the implementation follows the established pattern
(validator + fixture TP + matched control + `test_leg_live_verification` case +
registry/`_confirm`/gate wiring), same as the legs shipped this session.

---

## 1. Verb-tampering / HTTP method access-control bypass (V15)

**Oracle.** Hold identity constant, vary the HTTP method: an endpoint that denies
the intended method (401/403) but serves a substantive 2xx for a different method
(or an `X-HTTP-Method-Override` header) has a method-scoped authorization hole.

**Decision needed.** *Which methods is the leg allowed to send blindly?* The
high-value case (GET-protected but POST/PUT-open) requires sending a **mutating**
method to an endpoint we have not confirmed is safe to mutate — a blind `PUT`/
`DELETE` can destroy data. The safe subset (GET/HEAD/OPTIONS + method-override
headers) misses the most common exploitable shape.

**Recommended.** Ship the SAFE subset now: read-only alternates (HEAD, OPTIONS,
GET) + override headers (`X-HTTP-Method-Override`, `X-Method-Override`,
`X-HTTP-Method`), confirm a denial→2xx transition. Gate the mutating-method
variant behind an explicit `validators.verb_tamper.try_mutating_methods` opt-in
(off by default), routed through the safety gate + `allow_mutating_replay`.

## 2. CSRF (V32)

**Oracle.** A state-changing request is accepted with NO anti-CSRF token and NO
`SameSite` cookie protection, i.e. it would succeed cross-site.

**Decision needed.** *What counts as CONFIRMED server-side?* Same-origin policy is
browser-enforced; from the harness we can only observe that (a) the endpoint
mutates, (b) it requires no CSRF token (replay without the token still succeeds),
and (c) the session cookie lacks `SameSite=Lax/Strict`. That is strong evidence
but not execution proof — do we call (a∧b∧c) "confirmed", or only "high-confidence
unconfirmed"? Confirming it also means replaying a mutating request without the
token (a real state change).

**Recommended.** Treat (a∧b∧c) as CONFIRMED (it is a deterministic, checkable
property), replay gated by `allow_mutating_replay`; otherwise emit a capped
"unconfirmed" so precision isn't overstated. Needs sign-off that the cookie-
attribute + token-not-required combination is an acceptable confirmation bar.

## 3. File-upload abuse (V33)

**Oracle.** Upload a file that violates the intended policy and confirm the
violation has effect — but "effect" is several different bugs.

**Decision needed.** *Which file-upload outcome are we confirming?* Options, each a
different payload and risk profile: (a) content-type/extension bypass (upload a
`.php`/`.html` past a filter — benign to detect if we only check it is *stored*,
not executed); (b) stored-XSS via an uploaded `.html`/`.svg` (covered by the
stored-XSS leg if the file is later served in an HTML context); (c) path traversal
in the filename (covered by path_traversal); (d) RCE via an executable upload
(writes a live handler to the target — high risk).

**Recommended.** Do NOT build a monolithic file-upload leg. Confirm the SAFE,
already-covered slices via the existing legs (stored-XSS for served HTML/SVG,
path_traversal for `../` filenames) and add only a content-type/extension-bypass
CHECK that confirms the file is *stored and retrievable* with a disallowed type
(no execution). The execute-uploaded-code case needs explicit authorization.

## 4. Rate-limit absence (V4)

**Oracle.** N rapid authentication attempts all succeed (no 429 / lockout after a
threshold).

**Decision needed.** *How many attempts = "no rate limit", and how does that
reconcile with the safety gate's mutating-burst ceiling?* The gate caps repeated
mutating requests per finding (`max_mutating_requests_per_finding`, and the burst
ceiling); a meaningful rate-limit test may need more attempts than the ceiling
allows, and hammering a login is itself an aggressive action. Confirming "no limit
within 5" (the current burst ceiling) is a weak signal; real limits often trigger
at 5–10.

**Recommended.** Add a `validators.rate_limit.min_attempts` (default e.g. 15) and
raise the burst ceiling for THIS leg only via `authorize_burst`, confirming only
when all `min_attempts` reach the endpoint un-throttled AND `min_attempts` ≥ the
configured floor (else skip as "inconclusive"). Needs a decision on the floor and
on allowing a larger burst for this specific probe.

## 5. Reset-token / session-token entropy (V3)

**Oracle.** Collect several password-reset (or session) tokens and show they are
predictable — sequential, timestamp-derived, or below an entropy threshold.

**Decision needed.** *What entropy threshold and sample size count as
"predictable", and is generating N reset requests acceptable?* This is a
statistical judgment (there is no clean pass/fail), and it requires triggering
multiple reset flows (emails/side effects). A false "weak" claim on a genuinely-
random-but-short token would be a precision failure.

**Recommended.** Confirm only the UNAMBIGUOUS cases deterministically: tokens that
are strictly sequential/incrementing across samples, or shorter than a hard floor
(e.g. < 64 bits of length), or equal to a predictable value (timestamp, user id,
base64 of the email). Leave fuzzy "looks low-entropy" as unconfirmed. Needs
agreement on the hard floor and on how many reset requests are acceptable to send.

## 6. Second-order SQLi chain composition (V22)

**Oracle.** Plant a SQL payload via write A; trigger it via an unrelated read/admin
action B; observe SQL error/behaviour on B.

**Decision needed.** *How is the trigger endpoint B chosen, and what is the
confirmation signal without running sqlmap on the second-order path?* The stored-
XSS leg gives the plant→observe primitive, but SQLi confirmation needs a
boolean/error/time signal on B, and B is not derivable from A generically — it is a
graph-composition problem (which later action consumes the planted value). sqlmap
does not model a two-request second-order flow.

**Recommended.** Extend `chain_linker`/`chaining` to compose a plant→trigger
candidate when a write finding and a SQLi-suspected read on a shared object exist,
then run a differential (plant a boolean-true vs boolean-false marker via A,
compare B's response). Needs a decision on how aggressively to enumerate candidate
(A,B) pairs, since the fan-out is quadratic in the worklist.
