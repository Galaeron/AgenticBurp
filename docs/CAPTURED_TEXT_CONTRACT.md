# Captured text input contract

`POST /analyze` accepts a manually supplied `HttpExchange`: URL, method,
request/response header dictionaries, text request/response bodies, optional
response status, analyst note and capture identifier. This contract supports
captured fetch/XHR HTTP exchanges, GraphQL JSON requests and ordinary multipart
text and file metadata. These are input shapes, not a claim of application
coverage, GraphQL schema discovery, binary decoding or model accuracy.

The passive analysis caller receives the supplied method, content type and body.
The model prompt contains text subject to existing redaction, prompt validation
and configured body limits; arbitrary large or encoded bodies are not guaranteed
lossless prompt input. Finding persistence retains method, URL and pseudonymous
captured-auth context. Markdown and SARIF export findings; they are not full raw
HTTP archives. SARIF retains request method, URL and captured-auth labels.

Recognized credential headers produce a state-database-specific keyed label.
An analyst note such as “role A” is unverified annotation, not an authenticated
application role. Custom authentication schemes and role authorization semantics
are not inferred by this label. Engagement-wide exports can intentionally combine
captured principals; use their `captured_principal_id` filter for narrower views.

WebSocket messages have no frame/direction/opcode/session representation in
`HttpExchange`. An HTTP handshake does not establish WebSocket message analysis.
The existing browser capture recorder selects XHR/fetch requests, excluding
WebSocket/eventsource/media types, and reads response text best effort. Binary
request/response fidelity, base64 decoding, streaming/SSE boundaries, multipart
binary attachment fidelity and multivalue-header fidelity are unsupported by this
text contract. No browser capture, proxy capture or target request was executed
to verify this note.

Current bounded caller evidence: `harness/test_captured_shapes_passive.py` uses
four synthetic shapes through the real ASGI analyze route and passive
Orchestrator, an inert provider, temporary SQLite state/cache, evidence reads and
Markdown/SARIF routes. Its body-loss defect injection makes the input-preservation
acceptance fail. See `reviews/2026-10-05-reconciled-remediation/R22-oct9-state.md`.
