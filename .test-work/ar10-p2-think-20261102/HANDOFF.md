# AR-10 P2 — opt-in thinking mode: handoff (2026-11-02)

Branch `claude/ar10-p2-think-b2d670` (base `main` 9b02511). Not pushed.

## Change
- New config key `ollama.think` (read in `harness/orchestrator.py` and the
  standalone client in `harness/analysis_pipeline.py`, next to `num_ctx`/`seed`):
  - unset / `false` / `[]` → every call sends `"think": false`, byte-identical to base;
  - `true` → every Ollama call sends `"think": true`;
  - a list of `model_stage` labels (e.g. `[iterative, critique]`) → only calls inside
    those `with model_stage(...)` blocks send `true`. Per-stage was trivial with the
    existing `_MODEL_STAGE` ContextVar, so a reasoning-only arm needs no model change.
  - Strict parse (`parse_think_setting`): a quoted `"true"`, an int, a dict or an
    empty label raises `ValueError` at Orchestrator construction.
- Response handling (`_send_once`): `message.thinking` is popped from the raw
  envelope and a leading inline `<think>...</think>` block is stripped from
  `content` before JSON parsing. Only the trace length is kept
  (`measurement["thinking_chars"]`, present only when a trace came back, so
  base receipts are unchanged). The audit logger already logged lengths only.
  The inline strip applies regardless of the setting (a leading `<think>` block
  could never be the JSON answer; before, its braces broke the parse).
- Provenance:
  - run manifest `model_versions.think` = `{"setting": "off"|"on"|"stages", "stages": [...]}`
    (`harness/server.py`, from config via `ollama_client.think_setting`);
  - `metrics_snapshot()["think"]` (→ job result `instrumentation.model_metrics.think`
    and manifest `model_metrics`) = setting + `think_calls`, `traces`, `trace_chars`
    as this run's deltas. A result measured reasoning mode only if `think_calls > 0`.
- `harness/config.yaml`: comment only; the key stays unset. No default changed.

## Files
harness/ollama_client.py, harness/orchestrator.py, harness/analysis_pipeline.py,
harness/server.py, harness/config.yaml (comment), harness/test_server.py (manifest
assertion), new harness/test_ollama_think_mode.py (12 tests; discovered by `full`,
TestCase-based so the orphan guard sees it).

## Tests
Caller-level: real Orchestrator from shipped config.yaml, `ollama.base_url` pointed at
a loopback `ThreadingHTTPServer` fake Ollama. Controls (unset, false) compare raw
request bytes to the base payload. Against base sources: the 2 controls pass, the
other 10 tests fail or error (checked by temporarily restoring HEAD sources).

## Gates (PYTHONPATH=worktree; gates.status)
| | precondition | smoke | full |
|---|---|---|---|
| venv 3.12 | 0 | 0 | 0 (harness 5068 OK, native 38, evaluation 440/17 skips, integrity 59) |
| system 3.14 | 0 | 0 | 0 (same counts) |
`git diff --check` 0.

## Owner questions
1. Stage labels are free-form (agents use their own names). Is `[iterative, critique]`
   the intended "reasoning" arm, or should a named alias (e.g. `reasoning`) exist?
2. Remote providers (`coordinator.provider` ≠ ollama) ignore `ollama.think`; the
   manifest records the Ollama setting only. Acceptable for Part C?
3. Not live-verified: whether Ollama honours `think: true` together with
   `format: json` on gemma4/qwen3 (needs a live run; not done here per constraints).

## Next step
Review/merge; then an A/B think-on arm sets `ollama.think` in config.local.yaml only.
