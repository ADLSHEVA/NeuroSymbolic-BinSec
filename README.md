# OPM: AI-Enhanced Automated Taint Analysis System

> **毕设项目**: 基于GNN类型恢复和LLM智能编排的自动化污点分析系统

## 📊 最新指标（全 6 测试程序端到端）

| 指标 | 值 | 说明 |
|------|-----|------|
| **Precision** | 100% | 零误报（FP=0）|
| **Recall** | 100% | 零漏报（FN=0）|
| **F1-Score** | 100% | 6/6 程序全部 100/100/100 |

> 汇总 TP/FP/FN = 27/0/0。原"R=83.33%"系仅 vulnerable.c 且被**幽灵 Ground Truth + LLM 裁决静默失效**双重低估，详见 `docs/STATUS.md` 指标演进与 `docs/INTERNAL.md` 方法学。

## 🏗️ 系统架构

```
┌─────────────────────────────────────────────────────────────────────┐
│                    OPM 污点分析系统架构                              │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  源代码 ──→ 编译 ──→ 二进制(ELF)                                   │
│                │                    │                               │
│                ▼                    ▼                               │
│          Ground Truth        ┌──────────────┐                      │
│                              │  angr/VEX IR  │                      │
│                              └──────┬───────┘                      │
│                                     │                              │
│                    ┌────────────────┼────────────────┐              │
│                    ▼                ▼                ▼              │
│               CFG恢复          DFG构建          VEX IR             │
│                    │                │                │              │
│                    └────────────────┼────────────────┘              │
│                                     ▼                              │
│                          ┌─────────────────┐                       │
│                          │  GNN类型恢复    │  ← TYGR组件           │
│                          └────────┬────────┘                       │
│                                   ▼                                │
│                          Type Recovery Output                      │
│                          (变量类型/指针/缓冲区)                      │
│                                   │                                │
│                    ┌──────────────┼──────────────┐                 │
│                    ▼              ▼              ▼                 │
│              类型元数据注入   路径优先级    污点精度增强              │
│                    │              │              │                 │
│                    └──────────────┼──────────────┘                 │
│                                   ▼                                │
│                          Typed IR (增强IR)                         │
│                                   │                                │
│                                   ▼                                │
│                        ┌─────────────────┐                        │
│                        │  AI Orchestrator │  ← LLM决策代理         │
│                        │  (mimo-v2.5-pro) │                        │
│                        └────────┬────────┘                        │
│                                 ▼                                  │
│                        类型引导符号执行                              │
│                                   │                                │
│                                   ▼                                │
│                    ┌──────────────────────────┐                    │
│                    │  自动化污点传播           │                    │
│                    │  - Source定义             │                    │
│                    │  - Sink定义               │                    │
│                    │  - 传播规则               │                    │
│                    └────────────┬─────────────┘                    │
│                                 ▼                                  │
│                        Source-Sink检查                             │
│                                 │                                  │
│                                 ▼                                  │
│                    ┌──────────────────────────┐                    │
│                    │  评估与报告               │                    │
│                    │  - Precision/Recall/F1   │                    │
│                    │  - JSON/Markdown报告     │                    │
│                    └──────────────────────────┘                    │
└─────────────────────────────────────────────────────────────────────┘
```

## 📁 项目结构

```
NeuroSymbolic-BinSec/                 # <PROJECT_ROOT>
├── src/                              # 主要源码
│   ├── pipeline.py                   # 主管道（13阶段）
│   ├── compilation/                  # 编译模块
│   │   ├── compiler.py               # 编译器
│   │   └── stripper.py              # 二进制剥离
│   ├── ground_truth/                 # Ground Truth提取
│   │   ├── extractor.py             # 提取器
│   │   └── validator.py             # 验证器
│   ├── binary_analysis/              # 二进制分析
│   │   ├── vex_lift.py              # VEX IR提升
│   │   ├── cfg_recovery.py          # CFG恢复
│   │   ├── dfg_construction.py      # DFG构建
│   │   ├── call_analysis.py         # 调用图分析
│   │   └── multimodal_fusion.py     # 多模态融合
│   ├── type_recovery/                # GNN类型恢复
│   │   ├── inference.py             # 推理接口
│   │   ├── gat_model.py             # GAT模型
│   │   ├── gnn_model.py             # GNN模型
│   │   ├── dataset.py               # 数据集
│   │   └── attention_report.py      # 注意力报告
│   ├── typed_ir/                     # 类型化IR
│   │   ├── type_injector.py         # 类型注入
│   │   └── ir_types.py              # IR类型定义
│   ├── symbolic_exec/                # 符号执行
│   │   ├── guided_executor.py       # 引导执行器
│   │   ├── path_prioritizer.py      # 路径优先级
│   │   ├── heuristic_pruning.py     # 启发式剪枝
│   │   └── constraint_extractor.py  # 约束提取
│   ├── taint_analysis/               # 污点分析
│   │   ├── taint_engine_v2.py       # 污点引擎V2
│   │   ├── learned_propagation.py   # 学习传播
│   │   ├── gnn_sink_detector.py     # GNN Sink检测
│   │   ├── counterfactual.py        # 反事实验证
│   │   ├── lifecycle_tracker.py     # 生命周期追踪
│   │   └── rules.py                 # 污点规则
│   ├── orchestrator/                 # AI编排器
│   │   ├── orchestrator.py          # 主编排器
│   │   ├── llm_client.py            # LLM客户端
│   │   └── decision_engine.py       # 决策引擎
│   └── evaluation/                   # 评估模块
│       ├── metrics.py               # 评估指标
│       └── reporter.py              # 报告生成
│
├── tygr/                             # TYGR组件（已有）
│   └── TYGR0/
│
├── tests/                            # 测试程序
│   ├── test_programs/                # C源码（6个，均达100/100/100）
│   │   ├── vulnerable.c             # 综合漏洞
│   │   ├── buffer_overflow.c        # 缓冲区溢出
│   │   ├── format_string.c          # 格式化字符串
│   │   ├── command_injection.c      # 命令注入
│   │   ├── memory_vuln.c            # 内存漏洞（UAF/double-free）
│   │   └── taint_flow.c            # 复杂污点流
│   └── test_binaries/               # 编译后的二进制
│
├── scripts/                          # 脚本
│   ├── run_pipeline.py              # 运行管道
│   ├── run_batch_tests.py           # 批量测试
│   ├── evaluate.py                  # 运行评估
│   ├── train_gat.py                 # 训练GAT
│   ├── train_propagation.py         # 训练传播模型
│   └── generate_training_data.py    # 生成训练数据
│
├── data/                             # 数据
│   ├── models/                       # 训练的模型
│   ├── training/                     # 训练数据
│   └── results/                      # 实验结果
│
├── output/                           # 分析输出
│
├── docs/                             # 文档
│   ├── README.md                    # 本文件
│   ├── INTERNAL.md                  # 内部资料
│   └── architecture.md              # 架构说明
│
└── requirements.txt                  # Python依赖
```

## 🚀 快速开始

### 环境要求

- **操作系统**: Linux 或 Windows + WSL2 (本项目在 Ubuntu 20.04 上开发)
- **Python**: 3.10 (推荐 conda 环境)
- **核心依赖**: angr 9.2.x、pyvex、claripy、PyTorch、PyTorch-Geometric
- **LLM**: 任意 **OpenAI 兼容**的 chat/completions 端点（开发时用 mimo-v2.5-pro）
- **内存**: ⚠️ 建议 ≥4GB 给分析环境；angr 较吃内存，低于 2GB 跑多个程序会 OOM

### 1) 安装

```bash
# 建议用 conda 管理环境
conda create -n binsec python=3.10 -y
conda activate binsec

git clone https://github.com/ADLSHEVA/NeuroSymbolic-BinSec.git
cd NeuroSymbolic-BinSec            # 下文以 <PROJECT_ROOT> 指代此目录
pip install -r requirements.txt
```

### 2) 配置 LLM（环境变量，**切勿硬编码密钥**）

AI Orchestrator 读取以下环境变量；代码中不含任何密钥：

```bash
export MIMO_API_BASE="https://<your-openai-compatible-endpoint>/v1"
export MIMO_API_KEY="<your-api-key>"
export MIMO_MODEL="mimo-v2.5-pro"     # 或任意你的端点提供的模型
```

> 若使用**推理型模型**（reasoning model），其隐藏推理 token 计入 `max_tokens`；本项目已设为 4096，请勿调低（否则可见 JSON 会被截断）。

### 3) 配置 TYGR（GNN 类型恢复，**可选外部依赖**）

类型恢复阶段基于 **[TYGR](https://github.com/sefcom/TYGR)**。TYGR 未随本仓库分发（见 [致谢与许可](#-致谢与许可)）。如需启用 GNN 类型恢复：

```bash
git clone https://github.com/sefcom/TYGR.git tygr   # 放在 <PROJECT_ROOT>/tygr
# 按 TYGR 自身的 README 安装 torch / torch_geometric / pyvex / elftools
```

> 未配置 TYGR 时，类型恢复阶段会**优雅回退**到启发式方法，主流水线仍可运行。

### 4) 运行

```bash
# 单个程序（端到端：编译→二进制分析→符号执行→污点分析→评估）
python scripts/run_pipeline.py tests/test_programs/vulnerable.c -o output/test

# 全部 6 个测试程序
python scripts/run_batch_tests.py
```

输出 `output/<name>/analysis_report.json` 含检测到的污点路径与 Precision/Recall/F1。
> ⚠️ 单个程序约 5–15 分钟（瓶颈是 LLM 逐路径裁决）。内存受限时**一次只跑一个程序**。

## 📈 指标演进总表（v1 → 最终）

> v1–v11 为 `vulnerable.c` 单程序指标；v12 为**全 6 程序**汇总。

| 版本 | P | R | F1 | 改进内容 | 范围 |
|------|-----|-----|-----|----------|------|
| v1 | 0% | 0% | 0% | 初始框架 | vulnerable.c |
| v2 | 40% | 16.67% | 23.53% | 基础实现 | vulnerable.c |
| v3 | 70% | 58.33% | 63.64% | 改进 Ground Truth | vulnerable.c |
| v4 | 100% | 41.67% | 58.82% | 消除误报 | vulnerable.c |
| v5 | 100% | 75% | 85.71% | 提高召回 | vulnerable.c |
| v6 | 75% | 100% | 85.71% | 完美召回 | vulnerable.c |
| v7 | 85.71% | 100% | 92.31% | 最佳平衡 | vulnerable.c |
| v8 | 100% | 83.33% | 90.91% | 软阈值 + CoT | vulnerable.c |
| v9 | 80% | 100% | 88.89% | **作用域感知 GT + 推理模型裁决复活**（查明 83% 召回实为幽灵 GT + LLM 静默失效；修复后暴露 2 个真实 FP）| vulnerable.c |
| v10 | 100% | 87.5% | 93.33% | **污点引擎 4 处跨函数作用域守卫**（清除 argv→gets、gets→strcpy 误报）| vulnerable.c |
| v11 | 100% | 100% | 100% | **gets 无条件栈溢出铁证**（钉死 gets→gets，消除温度抖动）| vulnerable.c |
| **v12** | **100%** | **100%** | **100%** | **生命周期状态机计分 + printf .rodata 守卫 + 注释剥离 + 可达性过滤** | **全 6 程序 (TP/FP/FN=27/0/0)** |

**v12 全 6 程序明细（均 100/100/100）**：vulnerable、memory_vuln、format_string、buffer_overflow、taint_flow、command_injection。

## 🧪 方法学贡献（v9–v12）

1. **作用域感知 Ground Truth 与污点引擎** —— 逐函数追踪污点，消除"全局同名变量跨作用域错连"产生的幽灵漏报/误报。
2. **推理模型裁决复活** —— mimo-v2.5-pro 的隐藏推理 token 计入 `max_tokens`，1024 时可见 JSON 被截断、裁决静默默认 0.5；提升至 4096 + 容错解析 + 决策字段前置。
3. **对象生命周期状态机** —— 将数据流 source→sink 模型无法表达的 double-free / use-after-free 以 `(函数名, 漏洞类型)` 在 GT 与分析器两侧归一化对齐并计分。
4. **printf 格式串 .rodata 守卫** —— 为克服纯二进制分析中格式化字符串歧义的传统局限，用 angr 反汇编 printf/fprintf 调用点，判定格式参数寄存器是否经 `lea reg,[rip+disp]` 指向 `.rodata` 字面量；**保守**降级（仅全部确证为字面量才视为非漏洞），真实 `printf(tainted)` 一律保留。
5. **注释剥离 + 可达性过滤** —— GT 剥离 C 注释（避免把注释掉的调用当真调用）；分析器按 main 的 callee 闭包丢弃死代码中的数据流路径（生命周期漏洞豁免）。

## 🔧 核心功能

### 1. 二进制分析
- VEX IR提升 (angr/pyvex)
- CFG恢复 (angr CFGFast)
- DFG构建
- 调用图分析

### 2. GNN类型恢复
- GAT模型 (Graph Attention Network)
- TYGR组件集成
- 注意力权重可视化

### 3. AI Orchestrator
- mimo-v2.5-pro API
- Chain-of-Thought推理
- 软阈值决策

### 4. 污点分析
- Source-Sink检测
- 跨函数污点传播
- 内存生命周期追踪
- 反事实验证

### 5. 评估框架
- Precision/Recall/F1
- JSON/Markdown报告
- 批量测试

## 🧭 项目状态与如何继续改进

> **本仓库为协作中的在研项目（WIP），非最终状态。** 当前 6 个**合成**测试程序均达 100/100/100，
> 但这只验证了各项修复的正确性；**普适性仍需更大规模、更真实的基准**。

给共创伙伴的路线图（优先级从高到低）：

1. **更大基准（最高优先）** —— 在 [NIST Juliet C/C++ 1.3](https://samate.nist.gov/SARD/test-suites) 的
   相关 CWE 子集（CWE-78/121/122/134/415/416）上评测。Juliet 自带 good/bad 标签可直接当 Ground Truth。
   建议先跑 ~20 个用例的试点，实测单例耗时再外推。**预期 100/100/100 会下降**——那才是有价值的科研数据。
2. **提速 LLM 裁决阶段**（当前瓶颈，~30–40s/路径）—— 仅对"模糊路径"调 LLM、批处理、或换本地模型。
3. **函数内缓冲级数据流** —— 解决 `command_injection.c` 暴露过的"同函数多缓冲错配"（`fgets` 污染 `result`
   而 `popen` 用 `command`），需追踪每个 source/sink 实际操作的缓冲，而非粗粒度同函数配对。
4. **真正接入 GNN 类型恢复** —— 目前 GAT 已训练但未真正用于指导污点分析（见 `docs/STATUS.md`）。
5. **format-string 守卫推广** —— 当前 `.rodata` 守卫处理 printf/fprintf；可扩展到更多变体与间接格式串。

**关键设计与方法学**详见 `docs/INTERNAL.md`（§1.3 精度方法学贡献）与 `docs/architecture.md`（Precision Methodology）；
**指标演进**（v1→v12）见上文与 `docs/STATUS.md`。

## 🙏 致谢与许可

### 致谢 / 参考
本项目的 GNN 类型恢复部分基于并参考了 **[TYGR (sefcom/TYGR)](https://github.com/sefcom/TYGR)**
— *TYGR: Type Inference on Stripped Binaries using Graph Neural Networks*。

> ⚠️ **重要**：TYGR 仓库**没有许可证文件**，依据著作权法即默认 **"All Rights Reserved"（保留所有权利）**，
> 因此**不可再分发**。本仓库**不包含** TYGR 代码；请自行从其官方仓库获取（见[快速开始 §3](#3-配置-tyrgnn-类型恢复可选外部依赖)）。
> 本项目仅在学术意义上**引用/参考**它。

其他参考工作：DIRTY、ORACAL、VISION（二进制语义/漏洞检测方向）。

### 许可
本项目自有代码采用 **MIT License**（见 `LICENSE`）。注意：MIT 仅覆盖本仓库自有代码，
**不**延伸至 TYGR 等外部依赖。
