"""Priority 3 (build/release) — a tiered readiness `doctor` (SC-14 offline half).

SC-14 asks for a doctor that *distinguishes the tiers* of readiness rather than
emitting a single green/red: executable-found vs dependency-installed vs
service-reachable vs auth-accepted vs model-loaded vs browser-usable vs
tool-allowed-for-this-engagement. This module implements the offline-verifiable
tiers (executable / dependency / file / service) and honestly surfaces the
runtime-only tiers (model / auth / browser / tool-scope) as ``requires_runtime``
placeholders instead of pretending to have checked them.

"ready" is true only when every REQUIRED check passed; runtime-gated checks are
listed but never counted as passing until actually exercised (``--runtime``).
Nothing here builds or installs anything — it reports what a fresh machine has.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import shutil
import socket
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent

TIER_EXECUTABLE = "executable"
TIER_DEPENDENCY = "dependency"
TIER_FILE = "file"
TIER_SERVICE = "service"
TIER_MODEL = "model"
TIER_AUTH = "auth"
TIER_BROWSER = "browser"
TIER_TOOL_SCOPE = "tool_scope"

# The runtime-only tiers this offline doctor names but cannot verify without a
# live service/engagement — surfaced so the taxonomy is complete and honest.
RUNTIME_TIERS = (TIER_MODEL, TIER_AUTH, TIER_BROWSER, TIER_TOOL_SCOPE)


def _result(name: str, tier: str, status: str, detail: str, *, required: bool) -> dict[str, Any]:
    return {"name": name, "tier": tier, "status": status, "detail": detail,
            "required": required}


def check_executable(name: str, *, required: bool = True) -> dict[str, Any]:
    path = shutil.which(name)
    return _result(name, TIER_EXECUTABLE, "ok" if path else "missing",
                   path or "not found on PATH", required=required)


def check_dependency(module: str, *, required: bool = True) -> dict[str, Any]:
    try:
        found = importlib.util.find_spec(module) is not None
    except (ImportError, ValueError):
        found = False
    return _result(module, TIER_DEPENDENCY, "ok" if found else "missing",
                   "importable" if found else "not importable", required=required)


def check_file(rel_or_abs: str, *, root: Path = ROOT, required: bool = True) -> dict[str, Any]:
    path = Path(rel_or_abs)
    if not path.is_absolute():
        path = root / path
    exists = path.exists()
    return _result(rel_or_abs, TIER_FILE, "ok" if exists else "missing",
                   str(path) if exists else f"not present at {path}", required=required)


def check_service(name: str, host: str, port: int, *, timeout: float = 1.0,
                  required: bool = False) -> dict[str, Any]:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return _result(name, TIER_SERVICE, "ok", f"reachable at {host}:{port}",
                           required=required)
    except OSError as exc:
        return _result(name, TIER_SERVICE, "unreachable", f"{host}:{port}: {exc}",
                       required=required)


def runtime_placeholder(name: str, tier: str, note: str) -> dict[str, Any]:
    """A runtime-only tier this offline doctor names but does not execute."""
    return _result(name, tier, "requires_runtime", note, required=False)


def report(results: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate check results. ``ready`` = every REQUIRED check has status 'ok'."""
    required_failures = [r for r in results if r["required"] and r["status"] != "ok"]
    counts: dict[str, int] = {}
    tiers: dict[str, list[str]] = {}
    for r in results:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
        tiers.setdefault(r["tier"], []).append(f"{r['name']}={r['status']}")
    return {
        "kind": "release_doctor_report",
        "ready": not required_failures,
        "required_failures": [{"name": r["name"], "tier": r["tier"],
                               "status": r["status"], "detail": r["detail"]}
                              for r in required_failures],
        "counts": counts,
        "tiers": {t: sorted(v) for t, v in sorted(tiers.items())},
        "checks": results,
    }


def default_checks(*, runtime: bool = False) -> list[dict[str, Any]]:
    """The AgenticVibe readiness matrix. Optional tools are non-required (their
    absence is reported, not fatal); the harness's own Python deps and shipped
    files are required. Runtime tiers are placeholders unless ``runtime`` is set."""
    results = [
        # Required: the harness's own runtime deps + shipped files.
        *[check_dependency(m) for m in
          ("fastapi", "uvicorn", "httpx", "pydantic", "yaml")],
        check_file("harness/config.yaml"),
        check_file("pyproject.toml"),
        # Optional external tooling (absence reported, not fatal).
        check_executable("docker", required=False),
        check_executable("java", required=False),
        check_file("burp-extension/gradlew", required=False),
        check_dependency("playwright", required=False),
    ]
    if runtime:
        results.append(check_service("ollama", "127.0.0.1", 11434, required=False))
        results.append(check_service("harness-api", "127.0.0.1", 8787, required=False))
    else:
        results.append(runtime_placeholder(
            "ollama", TIER_MODEL, "start `ollama serve` and re-run with --runtime"))
        results.append(runtime_placeholder(
            "harness-api", TIER_SERVICE, "start the API and re-run with --runtime"))
    results.append(runtime_placeholder(
        "read-auth", TIER_AUTH, "verified only against a running authenticated API"))
    results.append(runtime_placeholder(
        "browser-engine", TIER_BROWSER, "`playwright install chromium`, verified at run"))
    results.append(runtime_placeholder(
        "engagement-scope", TIER_TOOL_SCOPE, "tool allowlist is per-engagement at run"))
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--runtime", action="store_true",
                        help="also probe live services (ollama, harness API)")
    parser.add_argument("--json", action="store_true", help="emit JSON only")
    args = parser.parse_args(argv)
    rep = report(default_checks(runtime=args.runtime))
    if args.json:
        print(json.dumps(rep, indent=2, sort_keys=True))
    else:
        print(f"ready={rep['ready']}")
        for check in rep["checks"]:
            print(f"  [{check['tier']:<10}] {check['name']:<24} {check['status']:<16} "
                  f"{check['detail']}")
        if rep["required_failures"]:
            print("required failures:")
            for f in rep["required_failures"]:
                print(f"  - {f['name']} ({f['tier']}): {f['detail']}")
    return 0 if rep["ready"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
