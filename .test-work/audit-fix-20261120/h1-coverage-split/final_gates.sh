#!/bin/sh
# Final gates on the committed tip: smoke, then every module the task names, one process each.
# Writes only summaries (final_summary.txt, gates_final.tsv); smoke's log is not meant to be read whole.
D=.test-work/audit-fix-20261120/h1-coverage-split
python -m harness.suite smoke > $D/smoke.log 2>&1
echo "smoke rc=$?" > $D/final_summary.txt
tail -3 $D/smoke.log >> $D/final_summary.txt
python $D/run_gates.py $D/gates_final.tsv harness.test_orchestrator_precondition harness.test_orchestrator_split_guard harness.test_transport_inventory harness.test_coverage_split harness.test_coverage_manifest harness.test_wstg_catalog_ids
echo "named gates rc=$?" >> $D/final_summary.txt
python $D/run_gates.py $D/gates_referencing.tsv --referencing coverage_model coverage_tracker api_surface_discovery
echo "referencing rc=$?" >> $D/final_summary.txt
echo finished >> $D/final_summary.txt
