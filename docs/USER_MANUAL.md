# User manual

Operator guide for running AgenticVibe. Read [the honest limitations](LIMITATIONS.md)
too — this tool is an unproven research prototype, not a drop-in scanner.

## 1. First run — and why it may "find nothing"

Six steps, in order. The README Quick Start lists the same steps in brief. The
30-minute clean-machine walk-through by someone new to the tool has **not** been
done (**unverified**; it is an owner step, recorded per release).

### 1. Python

Python 3.11 or newer (`requires-python` in `pyproject.toml`). CI runs **Python 3.14**
and the lock file is frozen from it, so prefer 3.14 (see §8).

### 2. Install from the lock

From the repository root. The lock is the dependency set CI tests; the server also
warns at startup, and lists any difference under `dependency_lock` in
`/health/details`, when installed versions differ from it:

```bash
pip install -r harness/requirements.lock
pip install -e . --no-deps
python -m harness.lock_preflight    # optional: report installed-vs-lock mismatches
```

### 3. Model and context settings

Start the backend and pull the default model (the name must match `config.yaml`):

```bash
ollama serve                 # start the model backend
ollama pull qwen3:8b         # pull the default model
```

Put your overrides in the **git-ignored** `harness/config.local.yaml`:

```yaml
ollama:
  num_ctx: 16384             # for llama-server (ollama.api: "openai"): its per-slot window, -c divided by -np
  # allow_cloud_models: true # only for an engagement that permits sending content to Ollama's cloud
```

- **`ollama.num_ctx`.** Ollama loads a model at its own default window and truncates
  a longer prompt, which cuts off the agent's instructions. The harness detects a
  cut call, discards its reply and marks the run `degraded`, so set the window up
  front. 16384 holds the largest prompt measured. It is sent with each request to
  Ollama and is used by the prompt fitting below; with `ollama.api: "openai"` it
  is not sent, only used for the fitting, and the server keeps the window it was
  started with.
- **Prompt fitting (`prompt_budget`).** Before each prompt the harness asks the model
  server for the window it has (llama-server `/props`; Ollama `/api/ps` for a loaded
  model, `/api/show` for the trained maximum), takes the smaller of that and
  `ollama.num_ctx`, and fits agent and critique prompts to it minus
  `prompt_budget.answer_tokens`. Each cut is marked in the prompt and listed per
  capture in the job result's `review_stats.elided`. With no window known it
  fits to `prompt_budget.unknown_context_tokens` (4096): it never sends a prompt
  unfitted, but a small fallback means heavily cut prompts, so set `num_ctx`.
- **`ollama.allow_cloud_models`** is `false`. A model named `*-cloud` or `*:cloud`
  runs on Ollama's cloud, so its prompts leave this machine. With the flag off, a run
  that would use one in any model slot is refused before its first call (HTTP 409 on
  `/analyze` and `/engagement/{host}/investigate`) and a direct call to one is refused
  unsent. `/health/details` shows the state under `model_egress`.
- **`ollama.rate_limit`** is one token bucket shared by every model call in the
  process. Shipped: `enabled: true`, `burst_calls: 10`, `calls_per_minute: 10`,
  `max_wait_seconds: 300`. Up to `burst_calls` calls start back to back, then
  `calls_per_minute`; a call that is not admitted within `max_wait_seconds` fails
  unsent (it is not retried and does not trip the circuit breaker). On a slow local
  model it rarely binds. Raising it or setting `enabled: false` loosens a
  safeguard, so do it in `config.local.yaml`. The run manifest records the values
  in force and the waits under `model_rate_limit`.

### 4. Build the Burp extension (optional)

See §6: the Gradle wrapper, a JDK 17 toolchain and the checksum-pinned Gradle 8.7.
Load the resulting `*-all.jar` in Burp Suite → Extensions.

### 5. Start the server and pair

```bash
python -m harness.server     # start the harness on 127.0.0.1:8787
```

`$HARNESS_TOKEN` is the pairing token the Burp extension uses: your
`server.auth_token` or `HARNESS_BEARER_TOKEN` if you set one, else the ephemeral
token the server writes to `harness/.harness_token.lock` at every start. Every
state-changing route needs it, even from loopback. In Burp, paste it into the
**Pairing token** field of the LLM Harness tab (or export `HARNESS_BEARER_TOKEN` before
starting Burp). `GET /pairing/check` proves the token is accepted:

```bash
export HARNESS_TOKEN="$(cat harness/.harness_token.lock)"   # PowerShell: $env:HARNESS_TOKEN = (Get-Content harness\.harness_token.lock -Raw).Trim()
curl -s -H "Authorization: Bearer $HARNESS_TOKEN" http://127.0.0.1:8787/pairing/check
```

Then **check readiness** — this is the first thing to do if results look empty:

```bash
curl -s -H "Authorization: Bearer $HARNESS_TOKEN" http://127.0.0.1:8787/health/details
```

`GET /health` is liveness only: it needs no token, contacts nothing and answers
`{"status": "ok"}` while the server runs. `GET /health/details` caches its backend probe for 10 s
(`probe_age_seconds`); `model_egress` lists any slot that holds a cloud model
and whether `ollama.allow_cloud_models` lets it run. Its `status` is `"ok"` only
when Ollama is reachable **and** every configured local model is pulled. If it
is `"degraded"`, the `ollama` block says why
(`reachable: false`, or `missing_models: ["qwen3:8b"]` with an `ollama pull`
hint) and `agent_models` shows the model each agent will actually use. A server
with no working model still answers `/analyze` with HTTP 200, but the response
is marked `degraded: true`, lists `agent_errors`, and the summary leads with a
warning — the findings are then from deterministic checks only, not the LLM.

### 6. A first `/analyze`

Save one captured exchange as `exchange.json` (the fields of `HttpExchange`; only
`url` and `method` are required):

```json
{"exchange": {"url": "http://127.0.0.1:8080/rest/user/login", "method": "POST",
              "request_headers": {"Content-Type": "application/json"},
              "request_body": "{\"email\":\"a@b.test\",\"password\":\"x\"}",
              "response_status": 401, "response_headers": {"Content-Type": "application/json"},
              "response_body": "{\"error\":\"Invalid email or password.\"}"}}
```

```bash
curl -s -X POST http://127.0.0.1:8787/analyze \
  -H "Authorization: Bearer $HARNESS_TOKEN" -H "Content-Type: application/json" \
  --data @exchange.json
```

(In PowerShell use `curl.exe`.) The response lists `dispatched_agents`,
`agent_reports` and a `summary`. It can take minutes on a single consumer GPU (§4).
From Burp, right-click a request → **Send to LLM Harness** does the same call.

The committed defaults are **passive and safe**: active validators, autonomous
discovery, the oracle, cloud routing and cloud reasoning are all OFF, and
`server.allowed_hosts` is empty. In this mode the harness only reviews the
exact traffic you send it, with a small local model — so "it ran and found
almost nothing" is expected until you enable active testing on a scoped target.

## 2. Scope — required before any active traffic

Set the target host(s) in a **git-ignored** `harness/config.local.yaml`
(never commit a flipped value into `config.yaml`):

```yaml
server:
  allowed_hosts: ["127.0.0.1", "localhost"]   # your scoped target
```

Scope is **fail-closed for active traffic**: crawling, probing and active
validators refuse to send anything when `allowed_hosts` is empty. (Passive
analysis of traffic you supply still works with no scope, because it sends
nothing to the target.) Known limitation: scope is matched by **hostname only**
— the port is not part of the check, so anything else on the same host is
technically in scope. This is **not** Burp's own target scope; you must set it
here separately. See [LIMITATIONS.md](LIMITATIONS.md).

## 3. Enabling active testing

Active validators send live requests, so they are gated behind an explicit
opt-in (on top of scope). In `config.local.yaml`:

```yaml
validators:
  active_enabled: true          # allow active, read-only probes + crawling
  # allow_mutating_replay: true # (stricter) allow state-changing replays
```

`active_enabled` is the master switch for every route that sends target
traffic. While it is off, `/crawl`, `/crawl-roles`, `/probe-missing-auth`,
`/active-probe`, `/engagement/{host}/advance`, `/engagement/{host}/investigate`
and `/engagement/{host}/run` with `execute: true` answer 403 before sending
anything; `/analyze` (review of the traffic you supply) and a plan-only
`/engagement/{host}/run` stay available.

Mutating/amplifying probes (race/TOCTOU bursts, mass-assignment) need
`allow_mutating_replay` *and* `max_burst_size` raised above its default of 1,
and are still capped by `safety_gate.py`'s hard ceilings. The OOB
deserialization validator proves RCE by making the target call back to a
local collaborator — treat that as a different class of test that your rules
of engagement may require explicit sign-off for.

For a time-boxed engagement investigation (`investigation_seconds`), two further
opt-ins spend the run's time on follow-ups. Both send active traffic:

```yaml
engagement:
  retry_rounds:
    enabled: true               # re-sweep skipped nodes / failed reviews until the deadline
  server_errors:
    max_lead_confirmations: 5   # send database-error leads from the run's own 5xx to sqlmap / the nosql leg
```

The server-error ledger itself is passive and on by default. The result's
`server_errors` key lists every route that answered 5xx, even when no lead is
sent. `passive-only` forces both opt-ins off.

**Set a request rate limit** for any real engagement (the default is unlimited):

```yaml
throttle:
  max_requests_per_second: 5
```

## 4. Performance — why a request can take minutes, and the knob to change it

The default `concurrency.max_parallel_agents: 1` runs agents one at a time. On a
single consumer GPU, individual `qwen3:8b` calls can take 80–100 s, so one
request that dispatches several agents plus a critique pass can take many
minutes. The default was chosen to avoid exhausting an 8 GB card's VRAM.

To go faster on capable hardware, raise concurrency in `config.local.yaml`:

```yaml
concurrency:
  max_parallel_agents: 3        # watch `ollama ps` / VRAM under load
```

The Burp extension's `/analyze` client timeout is 1800 s (raised from 600 s so a
slow serial dispatch does not time out mid-run); it is adjustable at runtime via
`setAnalysisTimeoutSeconds`. Routing to fewer agents (`coordinator.fail_open_mode:
"curated"`) also cuts latency.

## 5. Data handling (important for client engagements)

**What reaches a model.** Every model call (local Ollama, llama-server, and any
opt-in cloud role) passes `security.sanitize_for_inference` at the provider
boundary, and agents and the coordinator prompt from `security.sanitized_exchange`.
The redaction is **by name, not by content**: it withholds the value of a field
or header whose *name* is a recognised secret name, and it never scans values. A
withheld value becomes `[REDACTED-SECRET]` (a header value:
`[REDACTED -- header present, value withheld from model]`). This is best effort,
not a guarantee that no secret or personal datum reaches the model.

| Class | Treatment | What it covers |
|---|---|---|
| `header-values` | withheld | The values of the Authorization, Cookie, Set-Cookie, X-API-Key, X-Auth-Token and Proxy-Authorization headers. A JWT-shaped `Authorization: Bearer` token keeps only its `alg` and `typ`, never its payload or signature. |
| `secret-named-fields` | withheld | The value of a JSON (including nested), form or `key: value` field whose name is a secret name: `password`, `token`, `secret`, `api_key`, `session`, `csrf` and the rest of `security.SECRET_FIELD_NAMES`. |
| `url-secrets` | withheld | `user:password@` in a URL and the values of secret-named query and fragment parameters, including URLs inside text. |
| `inline-assignments` | withheld | `name=value` and `"name": "value"` assignments in free text, and `Authorization:`-style header lines, for the same names (written with or without `_`, `-` or a space: `accessToken=...`). |
| `known-values` | withheld | Opaque values a caller passes explicitly for one call. There is no global registry of secrets. |
| `pii` | **sent** | Names, e-mail addresses, phone numbers, postal addresses, dates of birth, card numbers and government ID numbers, unless they sit in a field with a secret name. There is no PII detector. |
| `unlisted-names` | **sent** | A secret under a name that is not on the list (for example a `jwt` field). |
| `unlabelled-values` | **sent** | A secret in prose or in a field with an ordinary name. Nothing is detected by pattern or entropy. |
| `injection-payloads` | **sent** | A payload in a non-secret field (a `<script>` in a search box). It is kept on purpose: the detectors need it. |

The deterministic `POST /scan/confidential` is a separate scan that reports
secrets and PII in captured traffic; it does not redact anything.

- **Cloud.** The cloud seams are OFF. `coordinator.cloud_primary: true` sends only an
  anonymized structural projection (method, path, parameter *names*, status,
  response shape). `coordinator.cloud_reasoning: true` sends the real exchange
  content, **after the redaction above**, so personal data and unlisted secrets
  leave the machine. An Ollama cloud model (`*-cloud` or `*:cloud`) is refused
  unless `ollama.allow_cloud_models` is true (SEC-1): a run that would use one is
  rejected before its first call (HTTP 409), and `/health/details` and the run
  manifest record the state under `model_egress`. That flag covers Ollama cloud
  models only; a role you route to another provider with a `provider:` key gets
  the same redacted prompts and is its own egress decision. Many testing
  contracts forbid off-host egress, so confirm before enabling either.
- **Third-party lookups.** Passive analysis also looks up component names at
  third-party services unless `privacy.external_lookups` is false (see
  [LIMITATIONS.md](LIMITATIONS.md), "Model backend & data").
- **On disk.** Findings, cached analyses and logs are written as **unencrypted
  files** under the tool's folder, with no per-engagement separation. Log
  messages and the evidence objects stored for an observation go through the same
  sanitiser, but nothing else is encrypted or redacted at rest. There is a
  `DELETE /engagement/{host}/evidence` wipe (enable `server.enable_wipe_endpoint`).
  Active file-upload / stored-XSS tests may **leave artifacts on the target** and
  there is no automatic cleanup — track and remove them manually.

## 6. Building the Burp extension

Needs a JDK 17-21 on `JAVA_HOME` (Gradle 8.7 cannot be launched by a newer JDK; the build
itself compiles and tests with a Java 17 toolchain, so a JDK 17 must be installed). The
project ships a Gradle wrapper, so no separate Gradle install is needed; the first run
downloads Gradle 8.7, checked against the checksum pinned in
`burp-extension/gradle/wrapper/gradle-wrapper.properties`:

```bash
cd burp-extension
./gradlew shadowJar    # Windows: gradlew.bat shadowJar -> build/libs/*-all.jar
```

Load the JAR in Burp Suite → Extensions → Add. (The Java source compiles and its
unit tests pass; loading into Burp itself has not been exercised in CI.)

## 7. Running the detection benchmark

The scorer is reproducible on any OS, but needs a local model and a corpus you
generate yourself (the tuned corpus is not committed — it carries fixture
session tokens, and committing it is what would make the benchmark non-blind):

```bash
# Build the tuning corpus from the committed PixelMart app:
cd testing/test-target
python app.py                 # shell 1 (http://127.0.0.1:5001)
python capture_exchanges.py   # shell 2 -> corpus/pixelmart_exchanges.json
python detection_fixture.py build   # run the agents (needs Ollama; ~hours on CPU/GPU)
cd .. && python score.py --corpus test-target --from-cache
```

All scratch paths honor env overrides (`DETBENCH_EXCHANGES`, `DETBENCH_STATE_DB`,
`DETBENCH_CACHE_DB`) and default to the OS temp dir — no hardcoded `C:\tmp`.

### Benchmarking against a target it was NOT tuned on (the real test)

The committed corpora have answer keys in the repo, so good scores on them may
reflect tuning, not capability. To measure real ability, point it at an
independently-authored vulnerable app:

1. Run e.g. OWASP **WebGoat**, **DVWA**, or a **PortSwigger** lab locally (none
   is bundled or auto-started by this repo).
2. In `config.local.yaml` set `server.allowed_hosts` to that host **only** and
   `validators.active_enabled: true`.
3. Proxy traffic through Burp, "Send to LLM Harness", and compare what it reports
   against the app's known issues (precision and recall).

This needs an LLM (local Ollama or an API key) and authorization to run active
validation against that host.

## 8. Supported Python

Developed and CI-tested on **Python 3.14** (Windows); the lockfile
(`harness/requirements.lock`) is frozen from that environment. The core harness
also runs on 3.11–3.13. On **3.12**, installing the optional proxy extra
(`harness/requirements-proxy.txt`, `mitmproxy`) can hit a `typing-extensions`
conflict — the core install (no proxy extra) is unaffected; skip the proxy extra
or use a different interpreter for it. See [TESTING.md](TESTING.md).
