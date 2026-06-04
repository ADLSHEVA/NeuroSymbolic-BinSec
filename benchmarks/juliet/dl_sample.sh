#!/bin/bash
set -e
cd /mnt/d/计算机资料/毕设/benchmarks/juliet
mkdir -p support
BASE="https://raw.githubusercontent.com/arichardson/juliet-test-suite-c/master"
echo "=== 下载支持文件 ==="
for f in io.c std_testcase.h std_testcase_io.h; do
  curl -sL "$BASE/testcasesupport/$f" -o "support/$f"
  echo "  got $f ($(wc -l < support/$f) 行)"
done
echo "=== 下载样例 CWE78 console system ==="
curl -sL "$BASE/testcases/CWE78_OS_Command_Injection/s01/CWE78_OS_Command_Injection__char_console_system_01.c" -o sample.c
echo "  sample.c $(wc -l < sample.c) 行"
