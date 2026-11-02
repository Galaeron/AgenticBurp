#!/usr/bin/env bash
# Usage: run_gates.sh <python> <tag>
PY="$1"; TAG="$2"; ROOT="$(cd "$(dirname "$0")/../.." && pwd)"; OUT="$ROOT/.test-work/identity-store-leak-20261102"
cd "$ROOT"; export PYTHONPATH="$ROOT"
: > "$OUT/$TAG.status"
for gate in "unittest harness.test_orchestrator_precondition" "unittest harness.test_identity_store_lease" "harness.suite smoke" "harness.suite full"; do
  "$PY" -m $gate > "$OUT/$TAG-${gate// /_}.log" 2>&1
  echo "$gate exit=$?" >> "$OUT/$TAG.status"
done
git diff --check > /dev/null 2>&1; echo "git diff --check exit=$?" >> "$OUT/$TAG.status"
