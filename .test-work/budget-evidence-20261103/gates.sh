#!/bin/sh
# Gate runner for the budget/evidence slice; writes exit codes + test counts only.
OUT=.test-work/budget-evidence-20261103
TESTS="harness.test_execution_registry harness.test_sqlmap_validator harness.test_sqlmap_points harness.test_evidence harness.test_param_dispatch_caller harness.test_proof_artifacts harness.test_parameter_binding_caller harness.test_discovery_spa_wildcards"
: > "$OUT/gates-summary.txt"
for tag in py312 py314; do
  if [ "$tag" = py312 ]; then PY=../../../.venv-rationalisation/Scripts/python.exe
  else PY="/c/Users/arthu/AppData/Local/Python/pythoncore-3.14-64/python.exe"; fi
  for gate in precondition touched smoke; do
    case $gate in
      precondition) "$PY" -m unittest harness.test_orchestrator_precondition > "$OUT/$tag-$gate.log" 2>&1 < /dev/null ;;
      touched) "$PY" -m unittest $TESTS > "$OUT/$tag-$gate.log" 2>&1 < /dev/null ;;
      smoke) "$PY" -m harness.suite smoke > "$OUT/$tag-$gate.log" 2>&1 < /dev/null ;;
    esac
    rc=$?
    echo "$tag $gate exit=$rc $(grep -E '^Ran [0-9]+ tests' "$OUT/$tag-$gate.log" | tail -1) $(grep -E '^(OK|FAILED)' "$OUT/$tag-$gate.log" | tail -1)" >> "$OUT/gates-summary.txt"
  done
done
git diff --check > /dev/null 2>&1; echo "diff-check exit=$?" >> "$OUT/gates-summary.txt"
