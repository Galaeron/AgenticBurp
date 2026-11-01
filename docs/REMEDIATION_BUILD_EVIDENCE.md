# Remediation build and environment evidence

Verified 2026-10-08 on Windows with Temurin JDK 17.0.20.1+1 and Gradle 8.7.
Java source encoding is explicitly UTF-8. The declared Montoya compile API is
2023.12.1; compilation does not establish compatibility with every Burp release.
No live Burp UI validation is claimed.

From `burp-extension`, with `JAVA_HOME` pointing to JDK 17 and Gradle on PATH:

```powershell
gradle --no-daemon --offline --rerun-tasks test --tests com.harness.llm.HarnessClientPairingTest shadowJar
```

Offline execution requires populated Gradle dependency caches. Project-local
Gradle 8.7 was downloaded from the official distribution and its published
SHA-256 checked before extraction. No global installation is required. The
four selected tests use owned loopback fixtures; this command is not the full
Java test suite. The resulting extension is
`burp-extension/build/libs/burp-llm-harness-extension-0.1.0-all.jar`.
Gson is shaded; the Burp-provided Montoya API remains compile-only for the main
artifact. Do not infer successful compilation from an older existing JAR.

Python evidence uses 3.12.14 in `.venv-rationalisation`, with recorded dependency
versions. An intermediate wheel built with `pip wheel --no-deps
--no-build-isolation` includes `harness/config.yaml` and workflow pack resources,
and excludes local overrides, tokens and runtime databases. A temporary install
outside this checkout passed startup, authorized reads and unauthorized denial;
all 147 loaded harness modules came from that installation. Dependencies came
from the provisioned environment; this does not verify fresh dependency resolution
or a wider Python/platform matrix.

The real Java HarnessClient also reached production Python HTTP routes using an
owned `reload=False` server, a synthetic passive orchestrator and temporary SQLite.
Authenticated captured analysis and stored SARIF reads passed; missing, wrong and
stale credentials failed, including after an actual owned-server restart. This
checks API pairing, not inference quality or the Burp UI.

Evidence is in `reviews/2026-10-05-reconciled-remediation/r19-packaging-20261005a/`
and `r02-python-java/`. Logs retain the first sandbox access failure and the
Windows encoding diagnostics before correction. The final UTF-8 build produced
SHA-256 `920729d756050b71365b7267cebcb75cd22df1bcbaea5a38db5344b76ecf01f1`.
That artifact identifies this intermediate checkout only. Rebuild and reverify the
final candidate after all accepted changes; R28 remains open. Required full-suite
execution remains blocked by the loop's excluded active fixtures.
