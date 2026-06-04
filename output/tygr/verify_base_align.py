import sys
sys.path.insert(0, '/mnt/d/计算机资料/毕设')
from src.binary_analysis.cfg_recovery import recover_cfg
from src.type_recovery.inference import recover_types

dbg = '/mnt/d/计算机资料/毕设/output/gnn_demo/memory_vuln'           # -g binary
strp = '/mnt/d/计算机资料/毕设/output/gnn_demo/memory_vuln.stripped'  # stripped (for CFG)

cfg = recover_cfg(strp)
cfg_names = set(cfg.functions.keys())
r = recover_types(dbg, cfg=cfg, dfg=None, model_path=None)

resolved = [k for k in r.keys() if not k.startswith('func_0x')]
unresolved = [k for k in r.keys() if k.startswith('func_0x')]
print(f"GNN 返回 {len(r)} 函数;按真实名解析 {len(resolved)};未解析(func_0x) {len(unresolved)}")
print("命中 CFG 的函数名样例:")
for k in resolved:
    if k in cfg_names:
        types = [p.predicted_type for p in r[k].predictions]
        print(f"   {k:24s} -> {types[:6]}")
