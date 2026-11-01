# Brotli security update (2026-11-01)

CVE-2026-111497 affects the previously locked Brotli 1.2.0 decoder.
The lock now uses Brotli 1.2.1 and mitmproxy 12.3.1. The old mitmproxy
12.2.3 metadata explicitly prohibits Brotli newer than 1.2.0, so upgrading
only Brotli would produce an unsatisfiable installation.

Required companion changes: mitmproxy-rs and mitmproxy-windows 0.12.15,
certifi 2026.10.23, and backports.zstd 1.7.0 on Python below 3.14.
Both optional proxy installation declarations also require patched versions.

For an existing deployment, run with its own Python interpreter from the
repository root, then restart the affected harness/proxy processes:

```powershell
python -m pip install -r harness/requirements.lock
python -m pip check
python -c "import importlib.metadata as m; print(m.version('brotli'), m.version('mitmproxy'))"
```

Expected versions are 1.2.1 and 12.3.1. Updating source declarations does not
replace libraries already loaded by a running process. This task installed a
fresh isolated verification environment, not the user's running deployments.
Separately managed browser, Burp, Node.js, and OS binaries require their own
vendor updates; the Python lockfile does not patch those bundled decoders.

Sources:
- https://github.com/google/brotli/releases/tag/v1.2.1
- https://github.com/advisories/GHSA-9v8h-qqgm-4m35
- https://github.com/mitmproxy/mitmproxy/blob/main/CHANGELOG.md

Verification artifacts: `.test-work/brotli-security-20261101/HANDOFF.md`.
