#!/usr/bin/env python3
"""
Juliet 干净对照 —— 标准检测(不开 OPM_TYPE_SINKS)+ LLM 裁决。
隔离 LLM 的贡献:对标准(名字/结构)检出的路径,用 LLM(GNN 类型作证据)逐路径裁决,
看 LLM 能否滤掉原来的 7 个 goodB2G 误报,同时保住 27 个真阳。
"""
import os, sys, glob, json, signal
sys.path.insert(0, '/mnt/d/计算机资料/毕设')
# 关键:不设 OPM_TYPE_SINKS(标准检测)
os.environ.pop('OPM_TYPE_SINKS', None)

JDIR = '/mnt/d/计算机资料/毕设/benchmarks/juliet'
CASES, BUILD = os.path.join(JDIR, 'cases'), os.path.join(JDIR, 'build')
THRESH = 0.3

from src.binary_analysis.cfg_recovery import recover_cfg
from src.binary_analysis.call_analysis import analyze_calls
from src.taint_analysis.taint_engine_v2 import run_taint_analysis
from src.type_recovery.inference import recover_types
from src.orchestrator.llm_client import LLMClient, LLMConfig

LLM = LLMClient(LLMConfig(provider='openai', api_base=os.environ['MIMO_API_BASE'],
                          api_key=os.environ['MIMO_API_KEY'],
                          model=os.environ.get('MIMO_MODEL', 'gpt-5.4-mini')))


class Timeout(Exception): pass
signal.signal(signal.SIGALRM, lambda s, f: (_ for _ in ()).throw(Timeout()))


def type_evidence(tro, funcs):
    parts = ["### Type Information (from GNN type recovery)"]
    for fn in funcs:
        out = (tro or {}).get(fn)
        if not out:
            continue
        for p in getattr(out, 'predictions', [])[:12]:
            parts.append(f"- {fn}:{p.variable_name}: {p.predicted_type} (conf={p.confidence:.2f})")
    return "\n".join(parts) if len(parts) > 1 else ""


def standard_paths(binary, t=120):
    """标准检测(无 GNN type-sink),返回污点路径。"""
    signal.alarm(t)
    try:
        cfg = recover_cfg(binary)
        cg = analyze_calls(binary, cfg)
        res = run_taint_analysis(binary, cfg, cg, None, None, None)
        return (res.get('taint_state', res).get('taint_paths', []) if isinstance(res, dict) else []), cfg
    finally:
        signal.alarm(0)


def adjudicate(paths, tro):
    survived = 0
    for p in paths:
        funcs = [p.get('source_caller'), p.get('sink_caller'), p.get('source'), p.get('sink')]
        ev = type_evidence(tro, [f for f in funcs if f])
        try:
            signal.alarm(90)
            r = LLM.analyze_taint_path_cot(p, symbolic_evidence=ev)
            signal.alarm(0)
        except Exception:
            signal.alarm(0)
            r = {'is_real_taint': True, 'confidence': 0.5}
        if r.get('is_real_taint', True) and float(r.get('confidence', 0.5)) >= THRESH:
            survived += 1
            break
    return survived > 0, survived, len(paths)


def main():
    cases = sorted(glob.glob(os.path.join(CASES, '*.c')))
    results = []
    for i, c in enumerate(cases, 1):
        name = os.path.basename(c)[:-2]
        rec = {'case': name}
        for variant, suffix in (('bad', '_bad'), ('good', '_good')):
            binp = os.path.join(BUILD, name + suffix)
            if not os.path.exists(binp):
                continue
            try:
                paths, cfg = standard_paths(binp)
                if not paths:
                    rec[variant] = {'paths': 0, 'survived': 0, 'detected_llm': False}
                    continue
                # 仅有路径时才取 GNN 类型作证据
                try:
                    tro = recover_types(binp, cfg, None, None)
                except Exception:
                    tro = {}
                det, surv, tot = adjudicate(paths, tro)
                rec[variant] = {'paths': tot, 'survived': surv, 'detected_llm': det,
                                'detected_std': True}
            except Timeout:
                rec[variant] = {'error': 'timeout'}
            except Exception as e:
                rec[variant] = {'error': f"{type(e).__name__}: {e}"}
        results.append(rec)
        b, g = rec.get('bad', {}), rec.get('good', {})
        print(f"[{i}/{len(cases)}] {name}: bad(std={b.get('paths','-')})->LLM={b.get('detected_llm','-')}"
              f"  good(std={g.get('paths','-')})->LLM={g.get('detected_llm','-')}", flush=True)
        json.dump(results, open(os.path.join(JDIR, 'results_llm_clean.json'), 'w'), indent=1)
    summarize(results)


def summarize(results):
    comp = [r for r in results if 'detected_llm' in r.get('bad', {}) and 'detected_llm' in r.get('good', {})]
    # 标准(LLM前)
    sTP = sum(1 for r in comp if r['bad'].get('paths', 0) > 0)
    sFP = sum(1 for r in comp if r['good'].get('paths', 0) > 0)
    # +LLM后
    TP = sum(1 for r in comp if r['bad'].get('detected_llm'))
    FN = sum(1 for r in comp if not r['bad'].get('detected_llm'))
    FP = sum(1 for r in comp if r['good'].get('detected_llm'))
    TN = sum(1 for r in comp if not r['good'].get('detected_llm'))
    def prf(tp, fp, fn):
        P = tp/(tp+fp) if tp+fp else 0.0; R = tp/(tp+fn) if tp+fn else 0.0
        return P, R, (2*P*R/(P+R) if P+R else 0.0)
    P, R, F = prf(TP, FP, FN)
    txt = ("=" * 60 +
           f"\nJULIET 标准检测 + LLM 裁决  (有效 {len(comp)} 例)\n" + "=" * 60 +
           f"\n[LLM 前(标准)] 检出正例 {sTP}, 误报负例 {sFP}"
           f"\n[LLM 后] TP={TP} FN={FN} FP={FP} TN={TN}"
           f"\n        Precision={P:.3f}  Recall={R:.3f}  F1={F:.3f}"
           f"\n  → LLM 滤掉的负例误报: {sFP - FP} / {sFP}"
           f"\n  → LLM 误杀的正例:     {sTP - TP} / {sTP}\n" + "=" * 60)
    print("\n" + txt, flush=True)
    open(os.path.join(JDIR, 'SUMMARY_LLM_CLEAN.txt'), 'w').write(txt)


if __name__ == '__main__':
    main()
