# OPM 内部资料文档

> **详细架构说明、功能模块、文件调用关系**

---

## 目录

1. [系统架构详解](#1-系统架构详解)
2. [管道阶段详解](#2-管道阶段详解)
3. [核心模块说明](#3-核心模块说明)
4. [文件调用关系](#4-文件调用关系)
5. [数据流图](#5-数据流图)
6. [配置说明](#6-配置说明)
7. [API接口](#7-api接口)
8. [已知问题](#8-已知问题)

---

## 1. 系统架构详解

### 1.1 OPM模型概述

OPM (Object-Process Methodology) 模型定义了系统的对象和过程：

**对象（Objects）**：
- Binary Program: 编译后的二进制文件
- VEX IR: 中间表示
- CFG: 控制流图
- DFG: 数据流图
- TypeRecoveryOutput: 类型恢复结果
- TypedIR: 类型化中间表示
- TaintSpecification: 污点规范
- ExecutionPaths: 执行路径
- TaintTraces: 污点轨迹
- AnalysisReport: 分析报告

**过程（Processes）**：
- Compilation: 编译
- CodeLifting: 代码提升
- CFGRecovery: CFG恢复
- DFGConstruction: DFG构建
- GNNSemanticInference: GNN语义推断
- TypeMetadataInjection: 类型元数据注入
- PathPrioritization: 路径优先级
- SymbolicExecution: 符号执行
- TaintPropagation: 污点传播
- SourceSinkChecking: Source-Sink检查
- Evaluation: 评估
- ReportGeneration: 报告生成

### 1.2 核心创新点

1. **GNN类型恢复**: 使用图神经网络从二进制中恢复变量类型
2. **AI Orchestrator**: 使用LLM进行智能决策
3. **软阈值决策**: 平衡Precision和Recall
4. **Chain-of-Thought推理**: 多阶段思维链分析

### 1.3 精度方法学贡献 (v9–v12，全 6 程序达 100/100/100)

5. **作用域感知 Ground Truth 与污点引擎** (`ground_truth/extractor.py`, `taint_analysis/taint_engine_v2.py`):
   逐函数追踪污点；GT 的 `identify_taint_paths` 按函数作用域(Pass1 局部源 / Pass2 入参跨过程定点传播 / Pass3 仅归因 in-scope 污点)；污点引擎 4 处跨函数守卫(输入源函数作为 sink 只与自身配对；局部输入源不跨兄弟函数)。消除"全局同名变量跨作用域错连"的幽灵漏报/误报。
6. **推理模型裁决复活** (`orchestrator/llm_client.py`):
   mimo-v2.5-pro 隐藏推理 token 计入 `max_tokens`；1024 时可见 JSON 被截断、`_parse_json_response` 失败、裁决静默默认 0.5。提升至 **4096** + 容错正则解析 + JSON 决策字段(`is_feasible`/`score`)前置 + 真正注入 `lifecycle_analysis`。
7. **符号约束硬证据** (`symbolic_exec/constraint_extractor.py::build_semantic_evidence`):
   按 sink 类型注入"铁证"——strncpy 未受限 size(solver max=2⁶⁴−1)、gets 无条件栈溢出(CWE-242)、double_free/UAF 生命周期违例——稳定 LLM 裁决、消除温度抖动。
8. **对象生命周期状态机计分** (`taint_analysis/lifecycle_tracker.py`, `extractor.identify_lifecycle_vulns`):
   实现真 UAF 检测(释放后再 use)；double-free/UAF 以 `(函数名, 漏洞类型)` 在 GT 与分析器两侧归一化对齐，使数据流模型无法表达的内存安全漏洞计为 TP。
9. **printf 格式串 .rodata 守卫** (`taint_engine_v2.detect_literal_format_printf`):
   为克服纯二进制分析中格式化字符串歧义的传统局限，用 angr 反汇编 printf/fprintf 调用块，判定格式参数寄存器(printf→RDI/fprintf→RSI)是否经 `lea reg,[rip+disp]` 指向 `.rodata`(`sections_map['.rodata'].min_addr/max_addr`)。**保守**：仅当某 (caller,callee) 全部调用点确证为字面量才降级，真实 `printf(tainted)` 一律保留。
10. **死代码处理** (`extractor._strip_comments`, `taint_engine_v2._filter_unreachable_paths`):
    GT 剥离 C 注释(避免把注释掉的调用当真调用)；分析器按 main 的 callee 闭包丢弃不可达函数的数据流路径(生命周期漏洞豁免)。

---

## 2. 管道阶段详解

### Stage 0: AI Orchestration

**功能**: 初始化AI Orchestrator，生成污点规范

**调用文件**:
- `src/orchestrator/orchestrator.py` → `AIOrchestrator.analyze_binary()`
- `src/orchestrator/llm_client.py` → `LLMClient.generate_taint_spec()`
- `src/orchestrator/decision_engine.py` → `DecisionEngine.decide_strategy()`

**输出**: TaintSpec, ExecutionStrategy

---

### Stage 1: Compilation and Stripping

**功能**: 编译C源码为ELF二进制，剥离调试符号

**调用文件**:
- `src/compilation/compiler.py` → `compile_source()`
- `src/compilation/stripper.py` → `strip_binary()`

**输入**: SourceCode
**输出**: Binary (stripped), Binary (debug)

---

### Stage 2: Ground Truth Extraction

**功能**: 从源码提取预期的source、sink、污点路径

**调用文件**:
- `src/ground_truth/extractor.py` → `extract_ground_truth()`
  - `extract_functions()`: 提取函数定义
  - `extract_variables()`: 提取变量声明
  - `identify_sources()`: 识别source函数
  - `identify_sinks()`: 识别sink函数
  - `identify_taint_paths()`: 识别污点路径

**输入**: SourceCode
**输出**: GroundTruth (sources, sinks, taint_paths, types)

---

### Stage 3: Code Lifting

**功能**: 将二进制提升为VEX IR

**调用文件**:
- `src/binary_analysis/vex_lift.py` → `lift_binary()`
  - 使用angr加载二进制
  - 使用pyvex提升为VEX IR
  - 提取IR语句和表达式

**输入**: Binary
**输出**: VEXIR (functions, blocks)

---

### Stage 4: CFG Recovery

**功能**: 恢复控制流图

**调用文件**:
- `src/binary_analysis/cfg_recovery.py` → `recover_cfg()`
  - 使用angr CFGFast
  - 识别函数和基本块
  - 构建边关系

**输入**: Binary
**输出**: CFG (functions, blocks, edges)

---

### Stage 5: DFG Construction + Call Graph Analysis

**功能**: 构建数据流图和调用图

**调用文件**:
- `src/binary_analysis/dfg_construction.py` → `construct_dfg()`
  - 从VEX IR提取数据流
  - 构建节点和边
- `src/binary_analysis/call_analysis.py` → `analyze_calls()`
  - 识别函数调用
  - 构建调用图

**输入**: VEXIR, CFG
**输出**: DFG, CallGraph

---

### Stage 6: GNN-Based Type Recovery

**功能**: 使用GNN恢复变量类型

**调用文件**:
- `src/type_recovery/inference.py` → `recover_types()`
  - 尝试使用TYGR
  - 回退到启发式方法
- `src/type_recovery/gat_model.py` → `GATTypeRecovery`
  - GAT模型定义
  - 注意力机制
- `src/type_recovery/attention_report.py` → `create_attention_report_generator()`
  - 生成GNN注意力报告

**输入**: CFG, DFG
**输出**: TypeRecoveryOutput

---

### Stage 7: Type Metadata Injection

**功能**: 将类型信息注入IR

**调用文件**:
- `src/typed_ir/type_injector.py` → `inject_type_metadata()`
  - 创建TypedFunction
  - 注入类型信息
- `src/typed_ir/ir_types.py`
  - 定义IR类型系统

**输入**: VEXIR, CFG, DFG, TypeRecoveryOutput
**输出**: TypedIR

---

### Stage 8: Path Prioritization + Heuristic Pruning

**功能**: 路径优先级和启发式剪枝

**调用文件**:
- `src/symbolic_exec/path_prioritizer.py` → `prioritize_paths()`
  - 计算路径分数
  - 排序路径
- `src/symbolic_exec/heuristic_pruning.py` → `create_pruner()`
  - 多维度评分
  - 自适应剪枝

**输入**: TypedIR, TypeRecoveryOutput
**输出**: ExecutionPaths

---

### Stage 9: Type-Guided Symbolic Execution

**功能**: 类型引导的符号执行

**调用文件**:
- `src/symbolic_exec/guided_executor.py` → `execute_guided()`
  - 创建初始状态
  - 应用类型约束
  - 执行符号执行
- `src/symbolic_exec/constraint_extractor.py` → `create_constraint_extractor()`
  - 提取符号约束
  - 分析参数范围

**输入**: TypedIR, ExecutionPaths
**输出**: SymbolicState, ExecutionPaths

---

### Stage 10: Automated Taint Propagation

**功能**: 自动化污点传播

**调用文件**:
- `src/taint_analysis/taint_engine_v2.py` → `run_taint_analysis()`
  - `_find_sources()`: 查找source调用
  - `_find_sinks_enhanced()`: 查找sink调用（GNN增强）
  - `_find_taint_paths()`: 查找污点路径
  - `_filter_with_symbolic_results()`: 符号执行过滤
  - `_filter_paths_with_model()`: 启发式过滤
  - `_validate_with_counterfactual()`: 反事实验证
  - `_track_lifecycle()`: 生命周期追踪
- `src/taint_analysis/gnn_sink_detector.py` → `create_gnn_sink_detector()`
  - GNN Sink检测
- `src/taint_analysis/lifecycle_tracker.py` → `create_lifecycle_tracker()`
  - 内存生命周期追踪
  - UAF检测

**输入**: Binary, CFG, CallGraph, TaintSpec, SymbolicResults
**输出**: TaintState (sources, sinks, taint_paths)

---

### Stage 11: Source-Sink Checking (with LLM)

**功能**: Source-Sink检查，使用LLM验证

**调用文件**:
- `src/pipeline.py` → `_stage_source_sink_checking()`
  - `_build_symbolic_evidence()`: 构建符号证据
  - 调用LLM进行CoT推理
- `src/orchestrator/llm_client.py` → `analyze_taint_path_cot()`
  - Chain-of-Thought推理
  - 软阈值决策

**输入**: TaintState, SymbolicEvidence, LifecycleAnalysis
**输出**: TaintTrace

---

### Stage 12: Evaluation

**功能**: 评估分析结果

**调用文件**:
- `src/evaluation/metrics.py` → `compute_metrics()`
  - 计算Precision, Recall, F1
  - 计算TP, FP, FN

**输入**: TaintTrace, GroundTruth
**输出**: EvaluationMetrics

---

### Stage 13: Report Generation

**功能**: 生成分析报告

**调用文件**:
- `src/evaluation/reporter.py` → `generate_report()`
  - 生成JSON报告
  - 生成Markdown报告

**输入**: TaintTrace, EvaluationMetrics
**输出**: Report (JSON, Markdown)

---

## 3. 核心模块说明

### 3.1 AI Orchestrator

**文件**: `src/orchestrator/`

**功能**:
- 使用LLM进行智能决策
- 生成污点规范
- 验证污点路径
- Chain-of-Thought推理

**关键类**:
- `AIOrchestrator`: 主编排器
- `LLMClient`: LLM客户端（支持mimo API）
- `DecisionEngine`: 决策引擎

**LLM配置**:
```python
llm_api_base = os.environ.get('MIMO_API_BASE', 'https://token-plan-ams.xiaomimimo.com/v1')
llm_api_key  = os.environ.get('MIMO_API_KEY', '<硬编码兜底>')  # 支持环境变量覆盖
llm_model    = 'mimo-v2.5-pro'
max_tokens   = 4096   # 关键：推理模型隐藏推理 token 计入此值，1024 会截断可见 JSON
```
> 并发跑多个程序时用**不同 key**(经 `MIMO_API_KEY` 注入)可避免 451 跨境限制竞争。

---

### 3.2 GNN Type Recovery

**文件**: `src/type_recovery/`

**功能**:
- 使用GAT模型恢复变量类型
- 生成注意力报告
- 集成TYGR组件

**关键类**:
- `GATTypeRecovery`: GAT模型
- `TypeRecoveryDataset`: 数据集
- `AttentionReportGenerator`: 注意力报告

**模型文件**: `data/models/gat_model.pt`

---

### 3.3 Taint Analysis Engine

**文件**: `src/taint_analysis/`

**功能**:
- 查找source和sink
- 构建污点路径
- 过滤误报
- 验证路径

**关键类**:
- `TaintEngineV2`: 污点引擎
- `GNNSinkDetector`: GNN Sink检测
- `LifecycleTracker`: 生命周期追踪
- `CounterfactualValidator`: 反事实验证

---

### 3.4 Symbolic Execution

**文件**: `src/symbolic_exec/`

**功能**:
- 符号执行
- 路径优先级
- 约束提取
- 启发式剪枝

**关键类**:
- `TypeGuidedExecutor`: 类型引导执行器
- `PathPrioritizer`: 路径优先级
- `HeuristicPathPruner`: 启发式剪枝
- `ConstraintExtractor`: 约束提取

---

## 4. 文件调用关系

### 4.1 主管道调用链

```
src/pipeline.py
├── src/compilation/compiler.py
├── src/compilation/stripper.py
├── src/ground_truth/extractor.py
├── src/binary_analysis/
│   ├── vex_lift.py
│   ├── cfg_recovery.py
│   ├── dfg_construction.py
│   └── call_analysis.py
├── src/type_recovery/
│   ├── inference.py
│   └── attention_report.py
├── src/typed_ir/type_injector.py
├── src/symbolic_exec/
│   ├── path_prioritizer.py
│   ├── heuristic_pruning.py
│   └── guided_executor.py
├── src/taint_analysis/
│   ├── taint_engine_v2.py
│   ├── gnn_sink_detector.py
│   └── lifecycle_tracker.py
├── src/orchestrator/
│   ├── orchestrator.py
│   └── llm_client.py
└── src/evaluation/
    ├── metrics.py
    └── reporter.py
```

### 4.2 污点分析调用链

```
taint_engine_v2.py
├── _find_sources(call_graph)
├── _find_sinks_enhanced(call_graph, cfg)
│   └── gnn_sink_detector.py
├── _find_taint_paths(call_graph)
├── _filter_with_symbolic_results(symbolic_results)
├── _filter_paths_with_model()
├── _validate_with_counterfactual()
│   └── counterfactual.py
├── _track_lifecycle(call_graph)
│   └── lifecycle_tracker.py
└── _get_results()
```

### 4.3 LLM调用链

```
pipeline.py
└── _stage_source_sink_checking()
    ├── _build_symbolic_evidence()
    │   ├── attention_report.py
    │   ├── cfg.call_sites
    │   └── type_recovery_output
    └── llm_client.py
        └── analyze_taint_path_cot()
            └── generate(prompt, system_prompt)
```

---

## 5. 数据流图

### 5.1 主数据流

```
SourceCode
    │
    ├──→ Compilation ──→ Binary
    │                        │
    ├──→ GroundTruth         ├──→ CodeLifting ──→ VEX IR
    │                        │                        │
    │                        ├──→ CFGRecovery ──→ CFG │
    │                        │        │               │
    │                        │        └──→ DFGConstruction ──→ DFG
    │                        │                                │
    │                        └──→ GNN Type Recovery ←─────────┘
    │                                │
    │                                ▼
    │                        TypeRecoveryOutput
    │                                │
    │                                ▼
    │                        TypeMetadataInjection ──→ TypedIR
    │                                │
    │                                ▼
    │                        PathPrioritization ──→ ExecutionPaths
    │                                │
    │                                ▼
    │                        SymbolicExecution ──→ SymbolicState
    │                                │
    │                                ▼
    │                        TaintPropagation ──→ TaintState
    │                                │
    │                                ▼
    │                        SourceSinkChecking ──→ TaintTrace
    │                                │
    └──────────────────────────────→ Evaluation ──→ Metrics
                                            │
                                            ▼
                                      ReportGeneration ──→ Report
```

### 5.2 LLM集成数据流

```
TaintState (taint_paths)
    │
    ▼
Build Symbolic Evidence
    │
    ├── GNN Attention Report
    ├── Call Graph (dangerous functions)
    └── Type Information
    │
    ▼
LLM CoT Analysis
    │
    ├── Step 1: Syntactic feasibility
    ├── Step 2: Semantic realism
    ├── Step 3: Constraint satisfiability
    └── Step 4: Final score
    │
    ▼
Soft Threshold Decision (confidence >= 0.3)
    │
    ▼
Validated TaintTrace
```

---

## 6. 配置说明

### 6.1 OPMConfig

```python
@dataclass
class OPMConfig:
    # Compilation
    compiler: str = "gcc"
    compile_flags: list = ["-g", "-O0"]
    strip_binary: bool = True

    # Analysis
    max_symbolic_steps: int = 1000
    solver_timeout: int = 1000
    max_states: int = 100

    # GNN
    gnn_model_path: Optional[str] = None
    confidence_threshold: float = 0.7

    # Output
    output_dir: str = "./output"
    verbose: bool = True
```

### 6.2 OrchestratorConfig

```python
@dataclass
class OrchestratorConfig:
    use_llm: bool = True
    llm_provider: str = 'openai'
    llm_api_base: str = 'https://token-plan-ams.xiaomimimo.com/v1'
    llm_api_key: str = ''   # 从 MIMO_API_KEY 环境变量读取，切勿硬编码提交
    llm_model: str = 'mimo-v2.5-pro'
```

---

## 7. API接口

### 7.1 主管道API

```python
from src.pipeline import OPMPipeline, OPMConfig

# 创建配置
config = OPMConfig(output_dir='./output')

# 创建管道
pipeline = OPMPipeline(config)

# 运行分析
result = pipeline.run('path/to/source.c')

# 结果包含:
# - taint_traces: 污点轨迹
# - metrics: 评估指标
# - summary: 摘要
```

### 7.2 单独模块API

```python
# Ground Truth提取
from src.ground_truth import extract_ground_truth
gt = extract_ground_truth('source.c')

# CFG恢复
from src.binary_analysis import recover_cfg
cfg = recover_cfg('binary.stripped')

# 污点分析
from src.taint_analysis import run_taint_analysis
results = run_taint_analysis(binary, cfg, call_graph, taint_spec)

# 评估
from src.evaluation import compute_metrics
metrics = compute_metrics(taint_traces, ground_truth)
```

---

## 8. 已知问题

### 8.1 API限制

- **451错误**: mimo API偶尔返回451错误（跨域限制）
- **解决方案**: 重试机制（已实现）

### 8.2 性能问题

- **LLM调用慢**: 每条路径需要15-20秒
- **解决方案**: 软阈值减少验证路径数

### 8.3 准确性问题 —— ✅ 已解决（全 6 程序 100/100/100）

- **原"漏报" gets->free / gets->strncpy**: 经查明是**幽灵 Ground Truth**(全局同名变量跨作用域错连)，非真实漏报；分析器实已识别真实源 argv。
- **真因**: ① 幽灵 GT；② LLM 裁决被推理模型 token 截断而静默默认 0.5。详见 §1.3 与 `docs/STATUS.md`。
- **解决**: 作用域感知 GT/引擎 + max_tokens=4096 容错解析 + 生命周期计分 + printf .rodata 守卫 + 死代码过滤。

### 8.4 运行环境限制

- **WSL 内存仅 1.9GB 且无 swap**: 跑流水线**一次最多 1 个**(printf 守卫额外加载一次 angr)；≥2 并发或并发时再加载 angr 会 OOM 崩溃(需 `wsl --shutdown` 恢复)。可在 `.wslconfig` 调大内存以支持并发。

---

## 附录：术语表

| 术语 | 说明 |
|------|------|
| CFG | Control Flow Graph 控制流图 |
| DFG | Data Flow Graph 数据流图 |
| VEX IR | Valgrind EXpression 中间表示 |
| GNN | Graph Neural Network 图神经网络 |
| GAT | Graph Attention Network 图注意力网络 |
| TYGR | Type Recovery using GNN |
| CoT | Chain-of-Thought 思维链 |
| UAF | Use-After-Free 释放后使用 |
| FP | False Positive 误报 |
| FN | False Negative 漏报 |
| TP | True Positive 正确检测 |
| LLM | Large Language Model 大语言模型 |
