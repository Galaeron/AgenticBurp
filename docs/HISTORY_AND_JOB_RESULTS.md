# History and investigation result contracts

An omitted or empty `engagement_id` on `/analyze` selects the site's shared
history. The response returns `engagement_id: ""`; it does not allocate a new
partition. Separate calls and server restarts retain this history. A nonempty
name selects an isolated partition. Captured-principal filtering still applies
inside each partition.

Read `/report?url=...` or `/report/sarif?url=...` for shared history. Add the
returned `engagement_id` for a named partition. These reports are cumulative
views, not immutable snapshots of one analysis. A run ID identifies execution;
it does not change the history partition. Default report/engagement metadata
uses `shared-site-history`; named metadata uses `explicit-engagement`.
Existing bearer and browser-origin protections apply to report reads.

Investigation polling at `/engagement/{host}/investigate/{job_id}` includes small
results inline. A larger result remains available through `result_ref`, an
authenticated API location. Polling includes `result_available`,
`result_size_bytes`, `result_sha256`, and a bounded `result_summary`. A completed
execution can have a `delivery_error` without becoming an execution `error`.

Fetch `result_ref` with the same bearer credential. It accepts byte `offset`
(default zero) and `limit` (1–262144, default 262144). Each JSON page returns
base64 `data`, `next_offset` (null at the end), `size_bytes` and `sha256`.
Concatenate decoded bytes, verify their total size and SHA256, then parse UTF-8
JSON. The hash covers the complete canonical, redacted JSON bytes, not a page.
Missing or corrupt artifacts return 503; wrong hosts or unknown jobs return 404.
Unavailable results return 409, and offsets beyond the result return 416.

Result bytes and job metadata commit atomically in the managed job SQLite
journal. Retrieval survives process restart and never resumes execution.
Cancellation retains findings already persisted for that run as a partial
result. Result access follows existing job retention (15 minutes after completion
and at most 50 terminal jobs); pruning removes the associated managed result.
Separate run manifests and finding records retain their existing lifecycle.
No user-provided filesystem path is accepted for result retrieval.

To resume conclusive coverage, supply `resume_job_id` on a new investigation.
The prior managed result must be terminal, intact, from the same target origin
(scheme, host and effective port), and from the same source/configuration.
Raw client checkpoints are never used. The investigation independently compares
captured endpoint/identity inputs before reusing executed, conclusive rows;
changed responses require fresh work. A cancelled job without a coverage
checkpoint cannot be resumed through this mechanism.
