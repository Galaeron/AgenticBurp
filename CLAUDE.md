# Claude onboarding

Read [AGENTS.md](AGENTS.md) and [CURRENT_STATE.md](CURRENT_STATE.md).
Read [NOTES.md](NOTES.md) for the latest session handoff. AGENTS.md owns safeguards;
CURRENT_STATE.md owns project status. Read other files only as the task requires.

- Stack: Python backend (`harness.*`), Java Burp extension, Ollama reasoning.
- Entry points: `harness/server.py`, `harness/orchestrator.py`, `burp-extension/`.
- Python checks (repo root): `python -m harness.suite smoke`,
  `python -m harness.suite full`, `python -m unittest harness.test_orchestrator_precondition`.
- Java build (in `burp-extension/`, with compatible JDK): `gradle shadowJar`.
- Conventions: passive defaults; preserve existing edits; focused commits with
  `Co-Authored-By`. Full safety and verification rules remain in AGENTS.md.
- One task per session. End with an exact next step and file list in NOTES.md;
  overwrite it, do not append history. Keep it under 40 lines.
