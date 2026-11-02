#!/usr/bin/env bash
# Defect injection: inject.sh <file> <sed-expr> <test-module>...; restores <file> from a copy.
set -u
cd "$(dirname "$0")/../.."
f=$1; expr=$2; shift 2
bak=.test-work/pr12-followup-20261102/inject.bak
cp "$f" "$bak"
sed -i "$expr" "$f"
if cmp -s "$f" "$bak"; then echo "INJECTION DID NOT APPLY"; cp "$bak" "$f"; exit 9; fi
PYTHONPATH=$PWD /c/Users/arthu/Documents/AgenticVibe/.venv-rationalisation/Scripts/python.exe -m unittest "$@" 2>&1 | grep -E "^(FAIL|ERROR):|^Ran|^FAILED|^OK"
cp "$bak" "$f"; rm -f "$bak"
