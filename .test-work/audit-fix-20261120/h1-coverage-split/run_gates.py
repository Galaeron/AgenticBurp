"""Run each named harness test module in its own process and write a summary TSV.

    python run_gates.py <out.tsv> <module> [<module> ...]      e.g. harness.test_coverage_model
    python run_gates.py <out.tsv> --referencing coverage_model coverage_tracker

`--referencing` runs every harness/test_*.py that mentions one of the given module names (the
modules a caller or test imports or patches). A module that unittest finds no tests in (exit 5:
pytest-native) is re-run under pytest. Output goes to the TSV only: module, runner, rc, tests, seconds.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]


def modules_referencing(names: list[str]) -> list[str]:
    pat = re.compile(r"\b(" + "|".join(map(re.escape, names)) + r")\b")
    out = []
    for p in sorted((REPO / "harness").glob("test_*.py")):
        if pat.search(p.read_text(encoding="utf-8-sig", errors="replace")):
            out.append(f"harness.{p.stem}")
    return out


def run(mod: str, env) -> tuple[str, int, str, float]:
    t0 = time.time()
    r = subprocess.run([sys.executable, "-m", "unittest", mod], cwd=REPO, env=env, capture_output=True,
                       text=True, encoding="utf-8", errors="replace", timeout=1500)
    runner, rc, out = "unittest", r.returncode, r.stderr + r.stdout
    m = re.search(r"Ran (\d+) tests?", out)
    n = m.group(1) if m else "?"
    if rc == 5 or (m and n == "0"):
        r = subprocess.run([sys.executable, "-m", "pytest", "-q", "-x", mod.replace(".", "/") + ".py"], cwd=REPO,
                           env=env, capture_output=True, text=True, encoding="utf-8", errors="replace",
                           timeout=1500)
        runner, rc, out = "pytest", r.returncode, r.stdout + r.stderr
        m = re.search(r"(\d+) passed", out)
        n = m.group(1) if m else "?"
    tail = "" if rc == 0 else " | " + " ".join(out.strip().splitlines()[-6:])[:600]
    return runner, rc, n + tail, time.time() - t0


def main() -> int:
    out = Path(sys.argv[1])
    args = sys.argv[2:]
    mods = modules_referencing(args[1:]) if args and args[0] == "--referencing" else args
    env = dict(os.environ, PYTHONPATH=str(REPO))
    failed = 0
    with open(out, "w", encoding="utf-8") as fh:
        fh.write("module\trunner\trc\ttests\tseconds\n")
        for mod in mods:
            runner, rc, n, secs = run(mod, env)
            failed += rc != 0
            fh.write(f"{mod}\t{runner}\t{rc}\t{n}\t{secs:.0f}\n")
            fh.flush()
        fh.write(f"# done: {len(mods)} modules, {failed} failed\n")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
