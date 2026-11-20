# control_outcome inventory (EFF-1, 2026-11-20)

`harness/control_outcome.py` makes a `not_confirmed` result tri-state:

- **held**: `control_held`
- **failed**: `control_failed`
- **unknown**: everything else, including `""`, `not_run`, `inconclusive`,
  `named_parameter_untested` and `partial_coverage`

The confirmation gate (`confirmation_gate._controlled_negatives`) counts only
**held** as a controlled negative, the only state that refutes a finding
(`unconfirmed_hypothesis`). A `not_confirmed` result in any other state leaves a
live-class finding `inconclusive_unverified`.

Coverage reads the result separately (`covers_case`): `""` and `control_held`
still count as the case being exercised.

The criterion was applied by reading each validator's code. A control **held**
when the validator did two things:

1. It delivered the attack to this case.
2. It observed the defence working against a reference that it also observed.

The absence of an oracle signal is not a held control. That includes no callback,
no reflection, no evaluated product, no file contents and no sqlmap verdict.

## Results that now say `control_held`

| Validator / path | Held only when |
|---|---|
| `jwt_forge`, all forgeries rejected | the captured token's own replay (`r_sent`) was seen accepted, and the garbage control and every forgery were rejected. Without that replay the outcome stays unset. |
| `sequence.validate_from_read`, no field persisted | the write answered 2xx and the independent re-read shows every injected field |
| `auth_sequence`, session fixation "session id rotated" | a pre-login cookie existed and the login succeeded (<400) |
| `auth_sequence`, logout invalidation (cookie path and token path) | always. The fresh session was shown authenticated before logout (the positive control) and was denied after it. |
| `auth_sequence`, weak password | the policy-rejection message was observed |
| `auth_sequence`, username enumeration via lookup | the account known to exist got a 2xx that matched the non-existent account's answer |
| `file_upload`, .html stored and served inert | always. The stored copy was served back with our marker, and the inert content type or attachment disposition was observed on that copy. |
| `cross_identity`, `write_integrity` (pre-existing) | unchanged. Already `control_held` or `inconclusive`. |

## Results that now say `control_failed` or `not_run`

| Validator / path | Outcome |
|---|---|
| `nosql`, "negative control unexpectedly reached an administrator page" | `control_failed` |
| `sqlmap`, nonzero exit without its tested-parameter verdict | status `inconclusive`, `not_run` (was `not_confirmed`) |

## Results left unset (unknown, never refutes)

These are absence-of-signal negatives:

- `sqlmap`: a completed "not injectable" verdict. It still exits 1 and stays `not_confirmed`.
- `ssti`, `xxe`, `command_injection`, `ssrf`, `open_redirect`, `path_traversal`
- `deserialization`, `deserialization_oob`
- `browser_xss`, `dom_xss`, `stored_xss`, `idor_read`
- `nosql`: the operator differential, which keeps its coverage marker, and an operator login that is not admin
- `file_upload`: rejected (4xx), not retrievable, or marker absent
- `auth_sequence`:
  - fixation N/A, either with no cookie or with a minted token
  - token `exp` present (decoded only, not shown enforced)
  - indistinguishable login answers for an account not known to exist
- `sequence.validate`: write status discarded, and the read-back was either not JSON or does not show the field

The following validators either cover classes the gate never refutes (provisional
or no-leg classes) or return a passive "held" audit:

- `api_security`, `business_flow`, `challenge_echo`, `client_trust`, `content_exposure`
- `crypto`, `csp`, `csrf`, `error_handling`, `exposure_leads`
- `header_injection`, `http_request_smuggling`, `oauth`, `password_change`, `race_condition`
- `rate_limit`, `recon`, `reset_token`, `security_headers`, `subdomain_takeover`
- `toctou`, `verb_tamper`, `verbose_error`, `web_cache_poisoning`, `websocket`

Several of these pass `finding.vulnerability_class` through, so a live-class
finding could previously have been refuted by one of them. That can no longer
happen.

## Former refutation hazards

Under the old rule, `""` counted as refuting. These "Lead, not confirmed"
results were labelled `not_confirmed` with an empty outcome, so they could
refute a live-class finding:

- `challenge_echo`
- `rate_limit`
- the username-enumeration lookup lead in `auth_sequence`

They are now unknown.
