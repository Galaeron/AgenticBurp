"""Send every captured exchange to the AgenticBurp server, one at a time (step 6).

Usage:
    python run_analysis.py --harness-repo PATH --decisive-config FILLED.yaml --exchanges exchanges.json --out results/run1.json --label run1

Requires HARNESS_TOKEN and a restarted server exposing /run-provenance.
The driver verifies settings; it never applies active settings to a server.

Steps per run: POST /cache/clear; then, for each exchange in order, POST /analyze
with a 900-second client timeout; save every full response; record wall-clock time
per exchange and in total. Results are written after every exchange, so a run can
be inspected while it is still going.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

_AUTH_TOKEN = None


def http_json(method: str, url: str, body: dict | None, timeout: float) -> tuple[int, dict | None]:
    data = None if body is None else json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json", **({"Authorization": "Bearer " + _AUTH_TOKEN} if _AUTH_TOKEN else {})})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read()
        return resp.status, (json.loads(raw) if raw else None)


def main(argv=None) -> int:
    global _AUTH_TOKEN
    ap = argparse.ArgumentParser()
    ap.add_argument("--exchanges", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--label", required=True)
    ap.add_argument("--server", default="http://127.0.0.1:8787")
    ap.add_argument("--timeout", type=float, default=900.0)
    ap.add_argument("--limit", type=int, default=0, help="only the first N exchanges (smoke runs)")
    ap.add_argument("--harness-repo", type=Path, required=True,
                    help="checkout containing the provenance client helpers; server identity is queried remotely")
    ap.add_argument("--decisive-config", type=Path, required=True,
                    help="filled decisive overlay already applied to the intended server")
    ap.add_argument("--token-env", default="HARNESS_TOKEN")
    args = ap.parse_args(argv)
    _AUTH_TOKEN = os.environ.get(args.token_env)
    if not _AUTH_TOKEN:
        ap.error("set the bearer token in the environment variable named by --token-env")
    sys.path.insert(0, str(args.harness_repo.resolve()))
    from testing.remote_run_provenance import checked_provenance, assert_unchanged, driver_identity
    _, remote = http_json("GET", f"{args.server}/run-provenance", None, 30)
    provenance = checked_provenance(remote, args.decisive_config)
    provenance["driver_sha256"] = driver_identity(__file__)


    exchanges = json.loads(args.exchanges.read_text(encoding="utf-8"))
    if args.limit:
        exchanges = exchanges[: args.limit]

    status, health = http_json("GET", f"{args.server}/health", None, 30)
    status, cleared = http_json("POST", f"{args.server}/cache/clear", None, 60)

    meta = {
        "label": args.label,
        "server": args.server,
        "harness_commit": provenance["harness_commit"],
        "provenance": provenance,
        "provenance_valid": True,
        "validity": {"valid_run": False, "reason": "in_progress"},
        "health_at_start": health,
        "cache_clear": cleared,
        "exchanges_file": str(args.exchanges),
        "exchange_count": len(exchanges),
        "client_timeout_s": args.timeout,
        "started_utc": datetime.now(timezone.utc).isoformat(),
    }
    records = []
    total_t0 = time.monotonic()

    for i, ex in enumerate(exchanges):
        t0 = time.monotonic()
        started = datetime.now(timezone.utc).isoformat()
        rec = {"index": i, "exchange": ex, "started_utc": started,
               "http_status": None, "elapsed_s": None, "error": None, "response": None}
        try:
            http_status, body = http_json("POST", f"{args.server}/analyze", {"exchange": ex}, args.timeout)
            rec["http_status"] = http_status
            rec["response"] = body
        except urllib.error.URLError as exc:
            rec["error"] = f"URLError: {exc.reason}"
        except TimeoutError:
            rec["error"] = "timeout"
        except Exception as exc:  # network, JSON, etc.
            rec["error"] = f"{type(exc).__name__}: {exc}"
        rec["elapsed_s"] = round(time.monotonic() - t0, 2)
        records.append(rec)

        bad_raw = sum(1 for r in records if (r.get("response") or {}).get("agent_reports") and
                      any(a.get("raw_error") for a in r["response"]["agent_reports"]))
        print(f"[{args.label}] {i + 1}/{len(exchanges)} {ex['method']} {ex['url'][:90]} "
              f"status={rec['http_status']} t={rec['elapsed_s']}s err={rec['error']} raw_error_so_far={bad_raw}",
              flush=True)

        try:
            _, current = http_json("GET", f"{args.server}/run-provenance", None, 30)
            assert_unchanged(remote, current)
        except Exception as exc:
            meta["provenance_valid"] = False
            meta["provenance_error"] = type(exc).__name__ + ": provenance unavailable or changed"
        meta["total_elapsed_s_so_far"] = round(time.monotonic() - total_t0, 2)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps({"meta": meta, "records": records}, indent=2), encoding="utf-8")
        if not meta["provenance_valid"]:
            break

    n_raw = sum(1 for r in records if r["error"] or any(a.get("raw_error") for a in
                                                       ((r.get("response") or {}).get("agent_reports") or [])))
    n_timeout = sum(1 for r in records if r["error"] == "timeout")
    n = len(records)
    valid = n > 0 and n == len(exchanges) and (n_raw / n) <= 0.10 and n_timeout == 0 and meta["provenance_valid"]
    meta["finished_utc"] = datetime.now(timezone.utc).isoformat()
    meta["total_elapsed_s"] = round(time.monotonic() - total_t0, 2)
    meta["validity"] = {
        "exchanges": n,
        "exchanges_with_raw_error_or_error": n_raw,
        "raw_error_rate": round(n_raw / n, 4) if n else None,
        "timeouts": n_timeout,
        "valid_run": valid,
        "rule": "invalid if incomplete, provenance changes/is unavailable, >10% of exchanges have raw_error (or error), or any request times out",
    }
    args.out.write_text(json.dumps({"meta": meta, "records": records}, indent=2), encoding="utf-8")
    print(f"[{args.label}] done: total={meta['total_elapsed_s']}s valid={valid} "
          f"raw_error/error={n_raw}/{n} timeouts={n_timeout}", flush=True)
    return 0 if valid else 2


if __name__ == "__main__":
    sys.exit(main())
