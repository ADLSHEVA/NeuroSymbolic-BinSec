"""演示:全剥离(--strip-all)后函数名丢失,GNN 仍恢复类型语义。"""
import sys, subprocess, os
sys.path.insert(0, '/mnt/d/计算机资料/毕设')
from src.binary_analysis.cfg_recovery import recover_cfg
from src.type_recovery.inference import recover_types

dbg  = '/mnt/d/计算机资料/毕设/output/gnn_demo/memory_vuln'           # -g(真名)
full = '/mnt/d/计算机资料/毕设/output/gnn_demo/memory_vuln.fullstrip'

# 1) 全剥离副本(strip --strip-all 抹掉 .symtab,本地函数名全没)
subprocess.run(['cp', dbg, full], check=True)
subprocess.run(['strip', '--strip-all', full], check=True)

# 2) 两份 CFG:-g 的有真名,fullstrip 的是 sub_xxxx
cfg_dbg  = recover_cfg(dbg)
cfg_full = recover_cfg(full)
addr_true = {f.address: name for name, f in cfg_dbg.functions.items()}

# 3) 对全剥离二进制做 GNN 类型恢复(用 -g 提取 DWARF 变量,经基址对齐挂到 sub_xxxx)
r = recover_types(dbg, cfg=cfg_full, dfg=None, model_path=None)

print(f"\n{'全剥离后CFG函数名':<16} | {'(对照)真实名':<22} | GNN恢复的类型语义")
print('-'*16 + '-+-' + '-'*22 + '-+-' + '-'*40)
interesting = ('vuln_', 'safe_', 'main')
base = cfg_full.angr_cfg.project.loader.main_object.mapped_base
for sub_name, out in r.items():
    f = cfg_full.functions.get(sub_name)
    if f is None:
        continue
    true = addr_true.get(f.address) or addr_true.get(f.address)  # 同地址真名
    # 同地址真名(两二进制同基址)
    true = addr_true.get(f.address, '?')
    if not any(k in (true or '') for k in interesting):
        continue
    types = [p.predicted_type for p in out.predictions]
    has_buf = any(t in ('char*','pointer','array') for t in types)
    tag = '  <-- GNN标记为缓冲处理函数' if has_buf else ''
    print(f"{sub_name:<16} | {true:<22} | {types[:6]}{tag}")
