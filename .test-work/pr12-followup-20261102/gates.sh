#!/usr/bin/env bash
# Gates: gates.sh <label> <python>; writes <label>-*.log and <label>-status.txt here.
set -u
cd "$(dirname "$0")/../.."
label=$1; py=$2; d=.test-work/pr12-followup-20261102
export PYTHONPATH=$PWD
: > "$d/$label-status.txt"
step() { name=$1; shift; "$@" > "$d/$label-$name.log" 2>&1; echo "$name exit $?" >> "$d/$label-status.txt"; }
step precondition "$py" -m unittest harness.test_orchestrator_precondition
step focused "$py" -m unittest harness.test_ar10_scorer harness.test_ar10_acceptance_freeze harness.test_ar10_run_costs_steps harness.test_iterative_run_diagnostics harness.test_instrumentation
step smoke "$py" -m harness.suite smoke
step full "$py" -m harness.suite full
git diff --check; echo "diff-check exit $?" >> "$d/$label-status.txt"
