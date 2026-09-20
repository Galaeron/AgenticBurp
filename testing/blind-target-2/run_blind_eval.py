#!/usr/bin/env python3
"""
Blind-target-2 end-to-end eval: runs the CURATED blind_eval_exchanges.json
through the REAL orchestrator with live Ollama. Fresh state+cache DBs (no
warm-cache reuse), results to C:\\tmp\\blind_eval_results.json.

Ground truth (derived by hand over HTTP only, no app.py/answer-key read):
  - POSITIVE: IDOR + excessive data exposure on GET /api/tickets/{id}
    (bob reads ticket#1 he doesn't own; internal_notes leaked to a customer)
  - minor: client-controlled `department` on ticket create
  - CONTROLS (true negatives): comment authz 403, write methods 405,
    high-entropy tokens, own-ticket reads.
The question this run answers: does the harness independently flag the IDOR
on a target the model has never seen?

Measurement knobs (env vars, all default to the precision-measurement setting):
  HARNESS_FAIL_OPEN_MODE       curated | all           (default: curated)
  HARNESS_QUARANTINE_LEADS     1 | 0                   (default: 1)
"""
import asyncio, json, os, sys, time, yaml
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
HARNESS_DIR = PROJECT_ROOT / "harness"
BLIND_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from harness import store
store._DB_PATH = r"C:\tmp\blind_eval_state.db"
from harness import cache
cache.init_cache(db_path=r"C:\tmp\blind_eval_cache.db")

from harness import orchestrator as orch_mod
from harness.models import HttpExchange
from harness.coordinator import fail_open_stats, reset_fail_open_stats
from harness.config_schema import config_fingerprint

# --- Measurement knobs ---------------------------------------------------
_FAIL_OPEN_MODE = os.environ.get("HARNESS_FAIL_OPEN_MODE", "curated")
_QUARANTINE_LEADS = os.environ.get("HARNESS_QUARANTINE_LEADS", "1") not in ("0", "false", "no")

with open(HARNESS_DIR / "config.yaml") as f:
    config = yaml.safe_load(f)

# Inject measurement overrides explicitly so the exact mode is provable from
# the manifest -- do not rely on config.local.yaml reaching this runner.
config.setdefault("coordinator", {})["fail_open_mode"] = _FAIL_OPEN_MODE
config.setdefault("reporting", {})["quarantine_unverified_leads"] = _QUARANTINE_LEADS

_FINGERPRINT = config_fingerprint(config)
print(f"[config] fail_open_mode={_FAIL_OPEN_MODE!r}  quarantine_leads={_QUARANTINE_LEADS}"
      f"  fingerprint={_FINGERPRINT[:16]}")

reset_fail_open_stats()
orch = orch_mod.Orchestrator(config)


async def main():
    exf = BLIND_DIR / "blind_eval_exchanges.json"
    exchanges = json.load(open(exf))
    print(f"[*] {len(exchanges)} curated exchanges through REAL orchestrator (live Ollama)\n")
    stats_before = fail_open_stats()
    results = []
    for idx, e in enumerate(exchanges):
        ex = HttpExchange(
            url=e["url"], method=e["method"], request_headers=e["request_headers"],
            request_body=e["request_body"], response_status=e["response_status"],
            response_headers=e["response_headers"], response_body=e["response_body"],
        )
        t0 = time.monotonic()
        try:
            r = await orch.analyze(ex)
            el = time.monotonic() - t0
            findings = [f.model_dump() for rep in r.agent_reports for f in rep.findings]
            vrs = [v.model_dump() for v in r.validation_reports]
            results.append({"idx": idx, "label": e.get("label"), "ground_truth": e.get("ground_truth"),
                            "dispatched_agents": r.dispatched_agents, "findings": findings,
                            "validation_reports": vrs, "elapsed_seconds": round(el, 1), "error": None})
            print(f"[{idx:2d}] {el:6.1f}s  gt={e.get('ground_truth','?'):16s} {e.get('label','')[:44]}")
            print(f"      agents: {', '.join(r.dispatched_agents) or 'none'}")
            for f in findings:
                print(f"        - {f['vulnerability_class']} (conf={f['confidence']}, sev={f['severity']})")
            for v in vrs:
                if v.get("confirmed"):
                    print(f"        VALIDATOR {v['validator']} CONFIRMED {v.get('finding_class')}")
        except Exception as exc:
            el = time.monotonic() - t0
            results.append({"idx": idx, "label": e.get("label"), "ground_truth": e.get("ground_truth"),
                            "dispatched_agents": [], "findings": [], "validation_reports": [],
                            "elapsed_seconds": round(el, 1), "error": repr(exc)})
            print(f"[{idx:2d}] ERROR {exc}")

    stats_final = fail_open_stats()
    out = r"C:\tmp\blind_eval_results.json"
    manifest = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "config_fingerprint": _FINGERPRINT,
        "fail_open_mode": _FAIL_OPEN_MODE,
        "quarantine_leads": _QUARANTINE_LEADS,
        "fail_open_stats_before": stats_before,
        "fail_open_stats_final": stats_final,
        "results": results,
    }
    json.dump(manifest, open(out, "w"), indent=2)
    print("\n" + "=" * 68)
    print(f"exchanges: {len(results)} | total findings: {sum(len(r['findings']) for r in results)} | "
          f"errors: {sum(1 for r in results if r['error'])}")
    print(f"fail-open triggered: {stats_final['count']} times  (mode={_FAIL_OPEN_MODE!r})")
    print(f"results -> {out}")

asyncio.run(main())
