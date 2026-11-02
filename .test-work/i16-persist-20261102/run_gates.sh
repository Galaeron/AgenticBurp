#!/usr/bin/env bash
# Usage: run_gates.sh <label> <python.exe> [quick|full]. Logs under logs/, exit codes in <label>.status.
set -u
WT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="$WT/.test-work/i16-persist-20261102"
LABEL="$1"; PY="$2"; MODE="${3:-full}"
cd "$WT"
mkdir -p "$OUT/logs"
export PYTHONPATH="$WT"
STATUS="$OUT/$LABEL.status"
echo "label=$LABEL python=$PY head=$(git rev-parse --short HEAD) mode=$MODE started=$(date -Is)" > "$STATUS"
echo "worktree-diff-sha256=$(git diff HEAD | sha256sum | cut -c1-16)" >> "$STATUS"
"$PY" --version >> "$STATUS" 2>&1
"$PY" -m unittest harness.test_orchestrator_precondition > "$OUT/logs/$LABEL-precondition.log" 2>&1; echo "precondition=$?" >> "$STATUS"
"$PY" -m unittest harness.test_i16_wiring > "$OUT/logs/$LABEL-i16.log" 2>&1; echo "i16=$?" >> "$STATUS"
if [ -f harness/test_i16_persist.py ]; then
  "$PY" -m unittest harness.test_i16_persist > "$OUT/logs/$LABEL-persist.log" 2>&1; echo "persist=$?" >> "$STATUS"
fi
"$PY" -m harness.suite smoke > "$OUT/logs/$LABEL-smoke.log" 2>&1; echo "smoke=$?" >> "$STATUS"
if [ "$MODE" = full ]; then
  "$PY" -m harness.suite full > "$OUT/logs/$LABEL-full.log" 2>&1; echo "full=$?" >> "$STATUS"
fi
echo "worktree-diff-sha256-after=$(git diff HEAD | sha256sum | cut -c1-16)" >> "$STATUS"
echo "finished=$(date -Is)" >> "$STATUS"
