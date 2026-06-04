#!/bin/bash
# 演示:GNN 类型驱动的 sink 识别 —— 自定义手工缓冲拷贝函数
cd /mnt/d/计算机资料/毕设
PY=/root/miniconda3/envs/angr-env/bin/python
SRC=output/tygr/demo_custom_sink.c

echo "================ A) 不开类型 sink(纯名字/结构启发式)================"
unset OPM_TYPE_SINKS
$PY scripts/run_pipeline.py -v $SRC -o output/demo_sink_off 2>&1 \
  | grep -ivE "unicorn|cle.loader|angr0|datagen0|GlowVar|NodeLabel" \
  | grep -iE "Found sink:|store_record|Type-driven|Sinks found:|Total traces|Vulnerable traces" | head -12

echo ""
echo "================ B) 开 GNN 类型 sink(OPM_TYPE_SINKS=1)================"
export OPM_TYPE_SINKS=1
$PY scripts/run_pipeline.py -v $SRC -o output/demo_sink_on 2>&1 \
  | grep -ivE "unicorn|cle.loader|angr0|datagen0|GlowVar|NodeLabel" \
  | grep -iE "Found sink:|store_record|Type-driven|Type-based sink|Sinks found:|Total traces|Vulnerable traces" | head -12
echo "================ 完成 ================"
