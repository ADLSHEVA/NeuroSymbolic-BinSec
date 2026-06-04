#!/bin/bash
PY=/root/miniconda3/envs/angr-env/bin/python
OUT=/mnt/d/计算机资料/毕设/output/tygr
cd /mnt/d/计算机资料/毕设/tygr_original
echo "已完成 pkl: $(ls $OUT/corpus_ds/*.pkl 2>/dev/null | wc -l)"
$PY -m src.index datamerge $OUT/corpus_ds/*.pkl -o $OUT/partial.pkl 2>&1 | grep -iE "Generated size|Total" | tail -1
$PY -m src.index datasplit $OUT/partial.pkl --train $OUT/ptr.pkl --validation $OUT/pva.pkl --test $OUT/pte.pkl >/dev/null 2>&1
echo "=== 试训 4 轮(看是否还 index 越界)==="
$PY -m src.index train $OUT/ptr.pkl $OUT/pva.pkl -o $OUT/partial.model --epoch 4 2>&1 | grep -ivE "unicorn" | grep -iE "out of bounds|error|save epoch4|traceback" | tail -5
echo "=== 试 test(出 accuracy = 词表已修)==="
$PY -m src.index test $OUT/partial.model.best.model $OUT/pte.pkl 2>&1 | grep -ivE "unicorn" | grep -iE "accuracy|out of bounds|error|traceback" | tail -5
