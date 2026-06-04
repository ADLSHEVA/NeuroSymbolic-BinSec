#!/bin/bash
# Compile + datagen the whole generated C corpus, then merge & split for training.
PY=/root/miniconda3/envs/angr-env/bin/python
ROOT=/mnt/d/计算机资料/毕设
TG=$ROOT/tygr_original
COR=$ROOT/data/corpus
DS=$ROOT/output/tygr/corpus_ds
BIN=$ROOT/output/tygr/corpus_bins
mkdir -p "$DS" "$BIN"
cd "$TG"

echo "==== [1] compile + datagen all corpus files ===="
n=0
for src in "$COR"/c*.c; do
  b=$(basename "$src" .c)
  gcc -gdwarf-4 -O0 -w "$src" -o "$BIN/$b" 2>/dev/null || continue
  $PY -m src.index datagen "$BIN/$b" "$DS/$b.pkl" 2>&1 | grep -iE "Well Formed #func" | sed "s/^/  $b: /"
  n=$((n+1))
done
echo "datagen'd $n files"

echo "==== [2] merge ===="
$PY -m src.index datamerge $DS/*.pkl -o "$ROOT/output/tygr/corpus_merged.pkl" 2>&1 | grep -iE "Generated size|Total|merg" | tail -2

echo "==== [3] split 80/10/10 ===="
$PY -m src.index datasplit "$ROOT/output/tygr/corpus_merged.pkl" \
  --train "$ROOT/output/tygr/ctr.pkl" \
  --validation "$ROOT/output/tygr/cva.pkl" \
  --test "$ROOT/output/tygr/cte.pkl" 2>&1 | tail -3

echo "==== DONE — ready to train ===="
ls -la "$ROOT/output/tygr/corpus_merged.pkl" "$ROOT/output/tygr/ctr.pkl" "$ROOT/output/tygr/cva.pkl" 2>/dev/null
