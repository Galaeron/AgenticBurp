# User manual

Operator guide for running AgenticVibe. Read [the honest limitations](LIMITATIONS.md)
too — this tool is an unproven research prototype, not a drop-in scanner.

## 1. First run — and why it may "find nothing"

```bash
ollama serve                 # 1. start the model backend
ollama pull qwen3:8b         # 2. pull the default model (name must match config.yaml)
python -m harness.server     # 3. start the harness on 127.0.0.1:8787
```

Then **check readiness** — this is the first thing to do if results look empty:

```bash
curl -s http://127.0.0.1:8787/health
```

`status` is `"ok"` only when Ollama is reachable **and** every configured local
model is pulled. If it is `"degraded"`, the `ollama` block says why
(`reachable: false`, or `missing_models: ["qwen3:8b"]` with an `ollama pull`
hint) and `agent_models` shows the model each agent will actually use. A server
with no working model still answers `/analyze` with HTTP 200, but the response
is marked `degraded: true`, lists `agent_errors`, and the summary leads with a
warning — the findings are then from deterministic checks only, not the LLM.

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

Mutating/amplifying probes (race/TOCTOU bursts, mass-assignment) need
`allow_mutating_replay` *and* `max_burst_size` raised above its default of 1,
and are still capped by `safety_gate.py`'s hard ceilings. The OOB
deserialization validator proves RCE by making the target call back to a
local collaborator — treat that as a different class of test that your rules
of engagement may require explicit sign-off for.

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

- Request/response **bodies are sent to the model unredacted.** Only auth
  *headers* are masked. Bodies routinely carry tokens, PII and passwords.
- The cloud seams are OFF by default. `coordinator.cloud_reasoning: true` sends
  **real request content off the machine**; `cloud_primary` sends only an
  anonymized structural projection. Many testing contracts forbid off-host
  egress — confirm before enabling either.
- Findings, cached analyses and logs are written as **unencrypted files** under
  the tool's folder, with no per-engagement separation. There is a
  `DELETE /engagement/{host}/evidence` wipe (enable `server.enable_wipe_endpoint`).
  Active file-upload / stored-XSS tests may **leave artifacts on the target** and
  there is no automatic cleanup — track and remove them manually.

## 6. Building the Burp extension

Needs JDK 17+. The project does not yet ship a Gradle wrapper, so install Gradle
(8.x) yourself:

```bash
cd burp-extension
gradle shadowJar       # -> build/libs/*.jar
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
