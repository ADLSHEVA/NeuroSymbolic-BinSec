#!/usr/bin/env python3
"""
Juliet 试点评估 harness。
对每个 Juliet 用例编译两个变体:
  - 正例 (-DOMITGOOD): 只含 bad()  → 应检出漏洞
  - 负例 (-DOMITBAD):  只含 good() → 不应检出
用 OPM 核心分析(CFG + 调用图 + 污点)判定"是否检出"(total_paths>0)。
阶段1: 标准名字/结构启发式(无 GNN 类型 sink)。
阶段2: 对阶段1漏检的正例,开 GNN 类型驱动(OPM_TYPE_SINKS),量 GNN 增量召回。
"""
import os, sys, subprocess, glob, json, time, signal

sys.path.insert(0, '/mnt/d/计算机资料/毕设')
JDIR = '/mnt/d/计算机资料/毕设/benchmarks/juliet'
CASES, SUPPORT, BUILD = (os.path.join(JDIR, d) for d in ('cases', 'support', 'build'))
os.makedirs(BUILD, exist_ok=True)

from src.binary_analysis.cfg_recovery import recover_cfg
from src.binary_analysis.call_analysis import analyze_calls
from src.taint_analysis.taint_engine_v2 import run_taint_analysis


class Timeout(Exception): pass
def _alarm(signum, frame): raise Timeout()
signal.signal(signal.SIGALRM, _alarm)


def compile_variant(case_path, define, out):
    cmd = ['gcc', '-g', '-O0', '-w', '-DINCLUDEMAIN', define,
           '-I', SUPPORT, case_path, os.path.join(SUPPORT, 'io.c'), '-o', out]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    return r.returncode == 0


def detect(binary, use_gnn=False, t=120):
    """返回检出的污点路径数(>0 即判为检出)。带超时防 angr 卡死。"""
    signal.alarm(t)
    try:
        cfg = recover_cfg(binary)
        call_graph = analyze_calls(binary, cfg)
        tro = None
        if use_gnn:
            from src.type_recovery.inference import recover_types
            try:
                tro = recover_types(binary, cfg, None, None)
            except Exception:
                tro = None
        res = run_taint_analysis(binary, cfg, call_graph, None, None, tro)
        return int(res['summary']['total_paths'])
    finally:
        signal.alarm(0)


def main():
    cases = sorted(glob.glob(os.path.join(CASES, '*.c')))
    results = []
    print(f"=== 阶段1: 标准检测, {len(cases)} 用例 ===", flush=True)
    for i, c in enumerate(cases, 1):
        name = os.path.basename(c)[:-2]
        rec = {'case': name, 'cwe': name.split('__')[0]}
        badbin = os.path.join(BUILD, name + '_bad')
        goodbin = os.path.join(BUILD, name + '_good')
        try:
            ok_b = compile_variant(c, '-DOMITGOOD', badbin)
            ok_g = compile_variant(c, '-DOMITBAD', goodbin)
            rec['compiled'] = ok_b and ok_g
            if ok_b:
                rec['bad_paths'] = detect(badbin)
            if ok_g:
                rec['good_paths'] = detect(goodbin)
        except Timeout:
            rec['error'] = 'timeout'
        except Exception as e:
            rec['error'] = f"{type(e).__name__}: {e}"
        results.append(rec)
        print(f"[{i}/{len(cases)}] {name}: bad={rec.get('bad_paths','-')} "
              f"good={rec.get('good_paths','-')} {rec.get('error','')}", flush=True)
        json.dump(results, open(os.path.join(JDIR, 'results_standard.json'), 'w'), indent=1)

    # 阶段2: 对阶段1漏检的正例,开 GNN 类型驱动
    os.environ['OPM_TYPE_SINKS'] = '1'
    missed = [r for r in results if r.get('compiled') and r.get('bad_paths', 0) == 0]
    print(f"\n=== 阶段2: GNN 类型驱动重检 {len(missed)} 个阶段1漏检正例 ===", flush=True)
    for i, r in enumerate(missed, 1):
        badbin = os.path.join(BUILD, r['case'] + '_bad')
        try:
            r['bad_paths_gnn'] = detect(badbin, use_gnn=True, t=300)
        except Timeout:
            r['bad_paths_gnn'] = 'timeout'
        except Exception as e:
            r['bad_paths_gnn'] = f"err:{e}"
        print(f"[GNN {i}/{len(missed)}] {r['case']}: bad_gnn={r.get('bad_paths_gnn')}", flush=True)
        json.dump(results, open(os.path.join(JDIR, 'results_standard.json'), 'w'), indent=1)

    summarize(results)


def summarize(results):
    comp = [r for r in results if r.get('compiled')]
    TP = sum(1 for r in comp if r.get('bad_paths', 0) > 0)
    FN = sum(1 for r in comp if r.get('bad_paths', 0) == 0)
    FP = sum(1 for r in comp if r.get('good_paths', 0) > 0)
    TN = sum(1 for r in comp if r.get('good_paths', 0) == 0)
    def prf(tp, fp, fn):
        P = tp / (tp + fp) if tp + fp else 0.0
        R = tp / (tp + fn) if tp + fn else 0.0
        F = 2 * P * R / (P + R) if P + R else 0.0
        return P, R, F
    P, R, F = prf(TP, FP, FN)
    # 阶段2后: 把 GNN 救回的正例计入
    TP2 = TP + sum(1 for r in comp if isinstance(r.get('bad_paths_gnn'), int) and r['bad_paths_gnn'] > 0)
    FN2 = len(comp) - TP2
    P2, R2, F2 = prf(TP2, FP, FN2)
    out = [
        "=" * 60,
        f"JULIET 试点结果  (编译成功 {len(comp)}/{len(results)} 例)",
        "=" * 60,
        "[阶段1 标准: 名字/结构启发式]",
        f"  TP={TP} FN={FN} FP={FP} TN={TN}",
        f"  Precision={P:.3f}  Recall={R:.3f}  F1={F:.3f}",
        "[阶段2 +GNN类型驱动(对漏检正例)]",
        f"  GNN 救回正例: {TP2 - TP}",
        f"  Recall(总)={R2:.3f}  F1={F2:.3f}  (Precision={P2:.3f})",
        "=" * 60,
    ]
    text = "\n".join(out)
    print("\n" + text, flush=True)
    open(os.path.join(JDIR, 'SUMMARY.txt'), 'w').write(text)


if __name__ == '__main__':
    main()
