# Future benign health-control interface

The offline assessor accepts recorded controls; it does not send probes. A future
producer should write one record per independently executed control:

```json
{
  "control_id": "health-homepage-200",
  "kind": "ordinary_application",
  "service": "target",
  "timestamp": "2026-09-15T12:00:00Z",
  "outcome": "pass",
  "expected": "status 200 and stable marker",
  "affected_interval": ["2026-09-15T11:55:00Z", "2026-09-15T12:05:00Z"]
}
```

Required semantics:

- `kind=ordinary_application` is a benign, non-security workload whose expected
  result is known independently. Security payload responses use
  `kind=security_test` and cannot establish ordinary health.
- `service` distinguishes target, model, and other service traffic.
- `outcome` is `pass`, `fail`, or `expected_error`. An expected application error
  is not a health failure merely because its HTTP status is 500.
- `timestamp` records when the control ran. `affected_interval` bounds the
  evaluation results the control qualifies. A failure does not invalidate results
  outside that interval.
- The record should carry non-secret request-template and response-marker hashes
  when a producer needs stronger reproducibility. It must not carry credentials,
  bodies, or sensitive excerpts.

For aggregated logs, each record should include `service`, `timestamp`, `status`,
and `parseable`. The assessor discloses unparseable counts and observable time
windows. It never invalidates a run merely because many status-500 records exist;
validity requires ordinary control outcomes and attributable intervals.

Legacy runs with no controls remain `unknown`. Passing controls yield only
`valid_for_controlled_intervals`; failed controls yield
`invalid_for_affected_intervals`. Broader validity needs explicit interval coverage
from the producer rather than inference by this reader.
