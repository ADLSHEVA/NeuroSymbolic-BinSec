#!/bin/bash
# Autonomous: wait for corpus build to finish, then train + test. Survives internet loss
# (all local). Models saved per-epoch (corpus.model.best.model) => checkpoint-resumable.
PY=/root/miniconda3/envs/angr-env/bin/python
ROOT=/mnt/d/计算机资料/毕设
OUT=$ROOT/output/tygr
cd "$ROOT/tygr_original"

echo "[auto_train] $(date) waiting for corpus (ctr.pkl + cva.pkl)..."
for i in $(seq 1 360); do                     # up to 3h
  if [ -f "$OUT/ctr.pkl" ] && [ -f "$OUT/cva.pkl" ]; then break; fi
  sleep 30
done
if [ ! -f "$OUT/ctr.pkl" ]; then
  echo "[auto_train] $(date) ctr.pkl never appeared — aborting."; exit 1
fi

echo "[auto_train] $(date) corpus ready:"
ls -la "$OUT/ctr.pkl" "$OUT/cva.pkl" "$OUT/cte.pkl" 2>/dev/null

echo "[auto_train] $(date) TRAINING (60 epochs)..."
$PY -m src.index train "$OUT/ctr.pkl" "$OUT/cva.pkl" -o "$OUT/corpus.model" --epoch 60 \
  2>&1 | grep -ivE "unicorn" | grep -iE "epoch|accuracy|f1|save|error|division|out of bounds|traceback" | tail -40

echo "[auto_train] $(date) TEST on held-out cte.pkl (proves vocab fixed + model predicts):"
$PY -m src.index test "$OUT/corpus.model.best.model" "$OUT/cte.pkl" \
  2>&1 | grep -ivE "unicorn" | grep -iE "accuracy|precision|recall|f1|out of bounds|error|traceback" | tail -12

echo "[auto_train] $(date) DONE"
ls -la "$OUT/corpus.model.best.model" "$OUT/corpus.model.last.model" 2>/dev/null
