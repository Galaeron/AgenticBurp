# Durable job status

Investigation job metadata is persisted in `harness_jobs.db` beside the main
state database. This is a status journal, not an execution queue. Reading it
never schedules, repeats or resumes work. Existing scope and captured-only
admission rules remain in force.

Polling/listing recovers jobs whose owning process is known to have ended as
`interrupted`. Their manifest paths remain visible and artifacts/findings remain
untouched. An operator decides separately whether to make a new explicit request.
Process-liveness errors and reused/live PIDs are treated conservatively as alive;
no cross-process cancellation is sent. Cancellation of a job owned by another
live process returns 409. Cancellation of a locally owned job is durable,
including cancellation before its coroutine starts.

Admission is atomic across processes sharing the journal, capped at four running
or cancelling jobs. Missing journal access rejects new admission with 503 before
work is scheduled. A failed status update is visible as `persistence_error`
in current polling when the journal remains readable, and as a sanitized warning;
after process loss, unavailable terminal status may conservatively recover as
interrupted. A total journal outage returns 503 for admission, polling, listing
and cancellation, including jobs still held in memory. Those operations can be
retried after storage recovers; polling never reexecutes work.

Each accepted submission generates a new identity. There is no submission
idempotency key: repeating a POST after losing its response can create a second
job. Durable status recovery does not provide at-most-once request submission.

Terminal metadata expires after 900 seconds and at most 50 terminal records are
retained. Expired polling returns 404; this deletes metadata only, never evidence
or manifests. Running records are not evicted to manufacture capacity. Serialized
live and durable polling results use the same shared recognized-secret policy and are capped
at two million JSON characters; oversized results require reading the preserved
artifacts. Job exception details are withheld from polling, manifests and warning
logs. Durable admission precedes manifest creation, so a duplicate identity never
overwrites its prior artifact. Manifest initialization failure records a terminal
error and schedules no work. A terminal manifest-write failure becomes visible
incomplete job status instead of an unhandled task exception; cancellation remains
visible. Manifest inputs use the same recognized-secret sanitizer. The journal
is sensitive local state, not encrypted storage. Include
it in protected backups; retention is performed on job operations, not by a timer.

Synthetic verification uses real HTTP routes, temporary SQLite, inert work and an
owned metadata-only subprocess that exits before completion. Tests block target
and provider transports. They do not execute investigations or establish recovery
of active operations. No automatic retry, target replay or reexecution is added.
