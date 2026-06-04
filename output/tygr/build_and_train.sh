#!/bin/bash
# Build a TYGR dataset from the 6 test programs, then train a fresh (current-PyG) model.
# Run from tygr_original/ with the angr-env python.
set -e
PY=/root/miniconda3/envs/angr-env/bin/python
ROOT=/mnt/d/计算机资料/毕设
TG=$ROOT/tygr_original
OUT=$ROOT/output/tygr
DS=$OUT/ds
BIN=$OUT/bins
mkdir -p "$DS" "$BIN"
cd "$TG"

progs="vulnerable buffer_overflow format_string command_injection memory_vuln taint_flow"

echo "==== [1] compile + datagen each program ===="
for p in $progs; do
  gcc -gdwarf-4 -O0 -w "$ROOT/tests/test_programs/$p.c" -o "$BIN/$p" 2>/dev/null || true
  $PY -m src.index datagen "$BIN/$p" "$DS/$p.pkl" 2>&1 | grep -iE "Well Formed #func|Well Formed #var" | sed "s/^/  $p: /"
done

echo "==== [2] merge ===="
$PY -m src.index datamerge $DS/vulnerable.pkl $DS/buffer_overflow.pkl $DS/format_string.pkl $DS/command_injection.pkl $DS/memory_vuln.pkl $DS/taint_flow.pkl -o "$OUT/merged.pkl" 2>&1 | grep -iE "merg|total|#func" | tail -3 || true
$PY - <<PYEOF
import pickle
d=pickle.load(open("$OUT/merged.pkl","rb"))
print("  merged samples:", len(d) if hasattr(d,"__len__") else "?")
PYEOF

echo "==== [3] split 80/10/10 ===="
$PY -m src.index datasplit "$OUT/merged.pkl" --train "$OUT/tr.pkl" --validation "$OUT/va.pkl" --test "$OUT/te.pkl" 2>&1 | grep -iE "train|valid|test|split" | tail -3 || true

echo "==== [4] train 40 epochs ===="
$PY -m src.index train "$OUT/tr.pkl" "$OUT/va.pkl" -o "$OUT/opm.model" --epoch 40 2>&1 | grep -iE "epoch|acc|loss|error|saved|best" | tail -15 || true

echo "==== [5] predict on test set ===="
$PY -m src.index predict "$OUT/opm.model" "$OUT/te.pkl" "$OUT/pred.pkl" 2>&1 | grep -ivE "unicorn" | tail -8 || true
ls -la "$OUT/opm.model" "$OUT/pred.pkl" 2>/dev/null || echo "  (model/pred not produced)"
echo "==== done ===="
