#!/usr/bin/env python3
"""从克隆的 Juliet 仓库中挑选适合本流水线的单文件基础变体用例。"""
import os, re, shutil, sys

REPO = '/root/juliet_repo/testcases'
OUT  = '/mnt/d/计算机资料/毕设/benchmarks/juliet/cases'
CWES = {
    'CWE121_Stack_Based_Buffer_Overflow': 10,
    'CWE122_Heap_Based_Buffer_Overflow':  10,
    'CWE134_Uncontrolled_Format_String':  10,
    'CWE78_OS_Command_Injection':         10,
}
# 优先这些"源"(我们的污点引擎能识别 stdin/getenv);跳过网络/win32/文件复杂源
PREFER = ('console', 'environment')
SKIP   = ('socket', 'listen', 'w32', 'wchar', 'fscanf', 'file')

def is_single_baseline(name):
    # 单文件基础变体: 以 _01.c 结尾(排除 _01a.c/_01b.c 这类多文件拆分)
    return bool(re.search(r'_01\.c$', name)) and not re.search(r'_\d+[a-z]\.c$', name)

os.makedirs(OUT, exist_ok=True)
picked = []
for cwe, n in CWES.items():
    cdir = os.path.join(REPO, cwe)
    cands = []
    for root, _, files in os.walk(cdir):
        for f in files:
            if not f.endswith('.c') or not is_single_baseline(f):
                continue
            low = f.lower()
            if any(s in low for s in SKIP):
                continue
            score = 0 if any(p in low for p in PREFER) else 1
            cands.append((score, f, os.path.join(root, f)))
    cands.sort()                       # 优先源排前面
    chosen = cands[:n]
    for _, f, path in chosen:
        shutil.copy(path, os.path.join(OUT, f))
        picked.append((cwe, f))
    print(f"{cwe}: 候选 {len(cands)}, 选取 {len(chosen)}")

print(f"\n共选取 {len(picked)} 个用例 -> {OUT}")
