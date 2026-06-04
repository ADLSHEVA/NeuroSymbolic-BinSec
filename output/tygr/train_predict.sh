#!/bin/bash
PY=/root/miniconda3/envs/angr-env/bin/python
OUT=/mnt/d/计算机资料/毕设/output/tygr
cd /mnt/d/计算机资料/毕设/tygr_original
echo "=== train 40 epochs ==="
$PY -m src.index train "$OUT/tr.pkl" "$OUT/va.pkl" -o "$OUT/opm.model" --epoch 40 2>&1 \
  | grep -iE "epoch|accuracy|f1 |saved|error|traceback|division|nan" | grep -ivE "unicorn" | tail -16
echo "=== predict on test set ==="
$PY -m src.index predict "$OUT/opm.model" "$OUT/te.pkl" "$OUT/pred.pkl" 2>&1 | grep -ivE "unicorn" | tail -8
echo "=== artifacts ==="
ls -la "$OUT/opm.model" "$OUT/pred.pkl" 2>/dev/null || echo "  model/pred NOT produced"
