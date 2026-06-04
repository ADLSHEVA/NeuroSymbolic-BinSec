import os, sys
sys.path.insert(0, '/mnt/d/计算机资料/毕设')
sys.path.insert(0, '/mnt/d/计算机资料/毕设/benchmarks/juliet')
from juliet_harness import compile_variant, detect, CASES, BUILD

c = os.path.join(CASES, 'CWE78_OS_Command_Injection__char_console_system_01.c')
bad = os.path.join(BUILD, 'smoke_bad'); good = os.path.join(BUILD, 'smoke_good')
print("编译 bad:", compile_variant(c, '-DOMITGOOD', bad))
print("编译 good:", compile_variant(c, '-DOMITBAD', good))
print("bad 检出路径数 (应>0):", detect(bad))
print("good 检出路径数 (应=0):", detect(good))
