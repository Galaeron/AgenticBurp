#!/usr/bin/env bash
# Usage: run_gates.sh <label> <python.exe>. Writes logs/<label>-*.log and <label>.status (exit codes only).
# "touched" = the new test module plus every test module that exercises the changed
# functions (canonicalize/issue_key/collapse/fingerprint/all_host_findings/coverage).
set -u
WT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="$WT/.test-work/finding-dedup-20261103"
LABEL="$1"; PY="$2"
cd "$WT"
mkdir -p "$OUT/logs"
export PYTHONPATH="$WT"
STATUS="$OUT/$LABEL.status"
TOUCHED="harness.test_finding_dedup harness.test_categories harness.test_chaining harness.test_coverage harness.test_report_generator $(grep -rlE 'issue_key|_collapse_duplicates|canonicalize|finding_fingerprint|issue_exports|group_findings_into_issues|all_host_findings|coverage_report' harness/test_*.py | sed 's#/#.#; s#\.py$##' | grep -v test_finding_dedup | sort -u | tr '\n' ' ')"
echo "label=$LABEL python=$PY head=$(git rev-parse --short HEAD) started=$(date -Is)" > "$STATUS"
"$PY" --version >> "$STATUS" 2>&1
"$PY" -m unittest harness.test_orchestrator_precondition > "$OUT/logs/$LABEL-precondition.log" 2>&1; echo "precondition=$?" >> "$STATUS"
"$PY" -m unittest $TOUCHED > "$OUT/logs/$LABEL-touched.log" 2>&1; echo "touched=$?" >> "$STATUS"
grep -E "^Ran |^OK|^FAILED" "$OUT/logs/$LABEL-touched.log" | sed 's/^/touched: /' >> "$STATUS"
"$PY" -m harness.suite smoke > "$OUT/logs/$LABEL-smoke.log" 2>&1; echo "smoke=$?" >> "$STATUS"
git diff --check > /dev/null 2>&1; echo "diff_check=$?" >> "$STATUS"
echo "finished=$(date -Is)" >> "$STATUS"
