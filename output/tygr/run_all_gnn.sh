#!/bin/bash
# 跨全部测试程序验证 GNN 集成健壮性
cd /mnt/d/计算机资料/毕设
PY=/root/miniconda3/envs/angr-env/bin/python
echo "程序                | GNN函数 | typed变量 | P/R/F1"
echo "--------------------|---------|-----------|--------"
for f in tests/test_programs/*.c; do
  name=$(basename "$f" .c)
  log=$(timeout 500 $PY scripts/run_pipeline.py "$f" -o output/gnn_all/"$name" 2>&1 \
        | grep -ivE "unicorn|cle.loader|angr0|datagen0|GlowVar|NodeLabel")
  gnn=$(echo "$log"   | grep -oE "GNN type recovery: [0-9]+ functions" | grep -oE "[0-9]+" | head -1)
  typed=$(echo "$log" | grep -oE "[0-9]+ typed variables" | grep -oE "[0-9]+" | head -1)
  prf=$(echo "$log"   | grep -oE "P=[0-9.]+, R=[0-9.]+, F1=[0-9.]+" | head -1)
  fellback=$(echo "$log" | grep -c "GNN type recovery unavailable")
  flag=""
  [ "$fellback" -gt 0 ] && flag=" [回退!]"
  printf "%-19s | %-7s | %-9s | %s%s\n" "$name" "${gnn:-?}" "${typed:-?}" "${prf:-?}" "$flag"
done
echo "=== 完成 ==="
