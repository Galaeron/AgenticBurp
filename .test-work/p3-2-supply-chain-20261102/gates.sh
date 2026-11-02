#!/bin/bash
# usage: gates.sh <label> <python>
cd "$(dirname "$0")/../.."
L=$1; P=$2; D=.test-work/p3-2-supply-chain-20261102; S=$D/gates-$L.status
export PYTHONPATH=$(pwd)
: > $S
for g in "precondition|-m unittest harness.test_orchestrator_precondition" "new|-m unittest harness.test_supply_chain" "smoke|-m harness.suite smoke" "full|-m harness.suite full"; do
  n=${g%%|*}; a=${g#*|}
  $P $a > $D/$L-$n.log 2>&1; echo "$n exit=$?" >> $S
done
echo done >> $S
