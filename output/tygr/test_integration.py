import sys, os
sys.path.insert(0, '/mnt/d/计算机资料/毕设')
from src.type_recovery.inference import recover_types

binary = '/mnt/d/计算机资料/毕设/output/tygr/corpus_bins/c000'

# model_path=None → uses the default OFFICIAL model (x64.O0.base.model) via tygr-orig env
r = recover_types(binary, cfg=None, dfg=None, model_path=None)
print(f"=== OPM recover_types 返回 {len(r)} 个函数 ===")
for fname, out in list(r.items())[:3]:
    print(f"\n函数 {fname}: {len(out.predictions)} 个变量预测")
    for p in out.predictions[:5]:
        print(f"   {p.variable_name:12s} -> {p.predicted_type:8s} (conf={p.confidence}, src={p.source})")
    print(f"   buffer_labels: {out.buffer_labels}")
