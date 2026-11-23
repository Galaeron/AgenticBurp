# Security policy

AgenticVibe is a research prototype (version 0.1.0, see [CHANGELOG.md](CHANGELOG.md)) that
sends HTTP traffic to targets you authorize and prompts to a model you configure.
[docs/LIMITATIONS.md](docs/LIMITATIONS.md) lists what it does not yet do safely.

## Reporting a vulnerability

Please report a vulnerability **privately**, through GitHub private vulnerability reporting:
open the repository's **Security** tab and choose **Report a vulnerability**. Do not open a
public issue, pull request or discussion for it, and do not post exploit details publicly
until a fix is available.

A useful report has:

- the version or commit you tested (`GET /run-provenance` with the pairing token, or `git rev-parse HEAD`);
- the configuration that matters (`validators.active_enabled`, `server.allowed_hosts`,
  `ollama.allow_cloud_models`, any cloud routing);
- the steps to reproduce, against a target you own. Do not send live traffic to a system you
  are not authorized to test.

There is no bug bounty. Response and fix times are not promised; this is a one-maintainer
research project.

## What is in scope

- A request sent to a host outside `server.allowed_hosts`, or active traffic sent while
  `validators.active_enabled` is off (the scope, safety-gate and admission paths).
- A bypass of the pairing token (`/pairing/check`, the authenticated and state-changing routes)
  or of the loopback, Host and CSRF checks on the local server.
- A secret that the redaction should withhold (see
  [docs/USER_MANUAL.md](docs/USER_MANUAL.md) section 5 for exactly what is and is not redacted)
  reaching a model prompt, a log or an export.
- A model response that can make the harness exceed what its gates allow (prompt injection that
  changes scope, identity, headers or request rate).
- A vulnerable pinned dependency (`harness/requirements.lock`) that a release should not ship.

## What is out of scope

- The deliberately vulnerable targets under `testing/` (`test-target` (PixelMart), `blind-target-2`
  and the `blind-test-kit` target): their flaws are the point.
- Findings the tool reports about someone else's application; report those to that application's owner.
- Personal data in captured traffic that is sent to the model you configured: the docs say it is
  not redacted. Choose a local model, or confirm the egress policy, first.

## Supported versions

Only the latest release (once one exists) and the tip of `main` receive fixes. How a release is
meant to be cut is in [docs/RELEASING.md](docs/RELEASING.md).
