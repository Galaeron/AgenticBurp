#!/usr/bin/env bash
# Usage: run_gates.sh <label> <python.exe>. Writes logs/<label>-*.log and <label>.status (exit codes only).
set -u
WT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="$WT/.test-work/lb6-objective-20261102"
LABEL="$1"; PY="$2"
cd "$WT"
export PYTHONPATH="$WT"
STATUS="$OUT/$LABEL.status"
echo "label=$LABEL python=$PY head=$(git rev-parse --short HEAD) started=$(date -Is)" > "$STATUS"
"$PY" --version >> "$STATUS" 2>&1
"$PY" -m unittest harness.test_orchestrator_precondition > "$OUT/logs/$LABEL-precondition.log" 2>&1; echo "precondition=$?" >> "$STATUS"
"$PY" -m unittest testing.test_run_web_objective_profile harness.test_objective_completion harness.test_objective_completion_wiring > "$OUT/logs/$LABEL-new.log" 2>&1; echo "new_tests=$?" >> "$STATUS"
"$PY" -m harness.suite smoke > "$OUT/logs/$LABEL-smoke.log" 2>&1; echo "smoke=$?" >> "$STATUS"
"$PY" -m harness.suite full > "$OUT/logs/$LABEL-full.log" 2>&1; echo "full=$?" >> "$STATUS"
git diff --check origin/main HEAD > "$OUT/logs/$LABEL-diffcheck.log" 2>&1; echo "diff_check=$?" >> "$STATUS"
echo "finished=$(date -Is)" >> "$STATUS"
