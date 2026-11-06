# Coverage adapters for checks without a security oracle

A coverage cell is `check_adapter_missing` when its check is in the `unavailable`
table of `ValidatorRegistry.capability_for_check` (harness/validators/registry.py).
The drive then never dispatches it. This file records, per check, whether a
deterministic adapter exists and why the rest stay unbound. Code is authoritative.

Juice Shop run r3 (job 0574e29a0799) skipped 2,049 cells this way: 291 each for
CONF-02, CONF-06, CONF-07, INFO-02, INFO-05, SESS-01 and ERRH-01, plus 12 for ATHN-01.

## Bound (2026-11-05)

Both adapters are passive. They judge each replayable capture the drive hands
them and send nothing. Passive legs run first and spend no `coverage_leg_budget`.
The coverage report's `legs_driven` / `cases_driven` count budgeted sends only;
`passive_legs_judged` counts the passive judgements.
A capture a passive leg skips does not hide another capture's verdict for the same cell.
Their execution key includes the response, so two captures of one request that
drew different responses get separate verdicts.

| Check | Family / validator | CONFIRMED | NOT_DETECTED | Skipped (never a negative) |
|---|---|---|---|---|
| WSTG-CONF-02 | `security_headers` / `security_headers_validator` | 2xx with content lacks `X-Content-Type-Options: nosniff`, or `Referrer-Policy` resolves to `unsafe-url` (severity low) | both held | no response, non-2xx, 204/205/304, HEAD |
| WSTG-ERRH-01 | `error_handling` / `error_handling_validator` | an error response (>= 400) holds a runtime stack trace, a framework error page or a database error string (medium; Werkzeug/Django debug high; Whitelabel low) | judged error response is clean | no response, < 400, HEAD, body not kept, non-document media type |

CONF-02 does not judge CSP or framing (owned by CONF-05) or HSTS (CONF-07). It
also ignores X-XSS-Protection, which is deprecated. The anomaly detector's
six-header audit remains a lead only. ERRH-01 does not provoke errors. An
endpoint whose captures all succeeded is skipped (`leg_precondition_unmet`),
not clean. verbose_error_validator keeps the wider lead set (paths, env-var
names, debug flags) for agent findings.

Tests: harness/test_security_headers_validator.py and
harness/test_error_handling_validator.py. Each covers the oracle, a caller-level
engagement drive with a positive case, a NOT_DETECTED control and a skipped
case, and a disabled control.

## Still unbound, and why

| Check | Reason kept | What would make it sound |
|---|---|---|
| WSTG-CONF-06 | Which methods are enabled is enumeration, not a verdict. The only sound oracle (a TRACE echo of a planted header) needs an active send. | An opt-in active TRACE/XST leg |
| WSTG-CONF-07 | Owned by PR #29 (`claude/run-until-deadline`, unmerged). HSTS means nothing over plain HTTP. | That PR |
| WSTG-INFO-02 | Fingerprinting is reconnaissance. A missing banner does not prove the server cannot be fingerprinted. | None as a pass/fail check |
| WSTG-INFO-05 | Whether a comment's content is sensitive is a judgement call, so any oracle is heuristic. | None deterministic |
| WSTG-SESS-01 | Token entropy needs many fresh-session samples (active). Cookie attributes are WSTG-SESS-02, which is not in the catalog. | An active sampling leg, or adding SESS-02 |
| WSTG-ATHN-01 | "Generic authentication bypass" names no exact procedure. | Re-scope (below) |

The catalog's ids and names do not all match WSTG v4.2. Genuine WSTG-CONF-02 is
"Test Application Platform Configuration". Genuine WSTG-ATHN-01 is "Testing for
Credentials Transported over an Encrypted Channel", which has a sound passive
oracle: a captured credential POST over plain HTTP. Re-mapping the catalog is an
owner decision.
