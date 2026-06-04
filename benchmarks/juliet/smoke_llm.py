import os, sys
sys.path.insert(0, '/mnt/d/计算机资料/毕设')
sys.path.insert(0, '/mnt/d/计算机资料/毕设/benchmarks/juliet')
from juliet_harness_llm import analyze, adjudicate, BUILD

for variant in ('_bad', '_good'):
    b = os.path.join(BUILD, 'CWE78_OS_Command_Injection__char_console_system_01' + variant)
    paths, tro = analyze(b)
    print(f"{variant}: 污点路径 {len(paths)}, GNN函数 {len(tro or {})}")
    if paths:
        det, surv, tot = adjudicate(paths, tro)
        print(f"   LLM 裁决: 存活 {surv}/{tot} → 检出={det}")
