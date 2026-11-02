#!/bin/bash
cd "C:/Users/arthu/Documents/AgenticVibe/.claude/worktrees/i16-persist-77da6a"
export PYTHONPATH="$PWD"
D=.test-work/ar10-p2-think-20261102
S=$D/gates.status; : > $S
for tag in py312 py314; do
  if [ $tag = py312 ]; then PY="C:/Users/arthu/Documents/AgenticVibe/.venv-rationalisation/Scripts/python.exe"; else PY="C:/Users/arthu/AppData/Local/Python/pythoncore-3.14-64/python.exe"; fi
  "$PY" -m unittest harness.test_orchestrator_precondition > $D/$tag-precondition.log 2>&1; echo "$tag precondition $?" >> $S
  "$PY" -m harness.suite smoke > $D/$tag-smoke.log 2>&1; echo "$tag smoke $?" >> $S
  "$PY" -m harness.suite full > $D/$tag-full.log 2>&1; echo "$tag full $?" >> $S
done
git diff --check > $D/diffcheck.log 2>&1; echo "diff-check $?" >> $S
echo DONE >> $S
