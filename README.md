# Burp LLM Harness

A Burp Suite copilot for captured HTTP analysis and bounded, graph-driven
investigation. Specialist agents propose findings; deterministic validators and
proof records distinguish hypotheses from supported confirmations.

Defaults are passive. Active discovery and confirmation require explicit scope
and configuration. Use the harness against applications you are authorized to test.

For coding tasks, read [AGENTS.md](AGENTS.md) and [CURRENT_STATE.md](CURRENT_STATE.md).
The [documentation map](docs/README.md) points to task-specific references.

## Setup

Python 3.11+ is declared in `pyproject.toml`; CI uses Python 3.14. From the
repository root, preferably in a virtual environment:

```sh
pip install -e .
ollama pull qwen3:8b
ollama serve
```

In another terminal:

```sh
python -m harness.server
```

The default endpoint is `http://127.0.0.1:8787`; check `/health`. Model names,
timeouts, concurrency and allowed hosts are configured in `harness/config.yaml`.
Put live overrides in ignored `harness/config.local.yaml`, which the server deep
merges. Keep committed defaults safe. Check the selected model and available
memory before increasing concurrency; historical machine timings are not guarantees.

Optional browser and proxy dependencies:

```sh
pip install -e ".[browser]"
playwright install chromium
pip install -e ".[proxy]"
```

The pinned proxy and current core dependencies have a typing-extensions conflict
on Python 3.12; see [testing dependencies](docs/TESTING.md). For sqlmap on Windows,
use Docker instead of a host install:

```sh
docker build -t harness/sqlmap:1.10.9 -f tools/sqlmap.Dockerfile tools
```

Configure `validators.sqlmap.container_image` in local overrides. Containers
reach host services via `host.docker.internal`.

## Burp extension

With JDK 17+ and Gradle, run `gradle shadowJar` inside `burp-extension/`. In Burp,
add the JAR from `build/libs/` under Extensions, then set the harness URL in the
LLM Harness tab. A Python test pass does not validate the Java build or UI.

## Development and verification

Run from the repository root:

```sh
python -m harness.suite smoke
python -m harness.suite full
```

[TESTING.md](docs/TESTING.md) explains dependencies, suite selection and evidence
limits. The smoke tier includes real discovery-to-confirmation fixture tests with
negative and defect-injection controls. The full tier also runs regression,
pytest-native and evaluation suites. Both enforce fresh requirement evidence.
Neither proves current real-model accuracy.

See [ARCHITECTURE.md](docs/ARCHITECTURE.md) for code ownership. Confirmation support
is defined by `validators/registry.py`, routing and evidence policy, not a copied
leg-count table. [ORACLE_RETIREMENTS.md](ORACLE_RETIREMENTS.md) records verdicts
that must remain observations until stronger controls qualify them.

## Evidence and limitations

Historical scorecards and dated reviews apply to their recorded inputs and
revision. They are not current recall or precision measurements. The
[2026-09-19 implementation review](reviews/2026-09-19/implementation-review/REVIEW.md)
identified proof-binding, evaluation integration, privacy and export gaps at its
reviewed revision; later commits address them.
[CURRENT_STATE.md](CURRENT_STATE.md) separates current verification from inherited
claims. A helper-level pass, skipped check, cached score or attempted leg must not
be reported as an integrated capability or a confirmed exploit.
