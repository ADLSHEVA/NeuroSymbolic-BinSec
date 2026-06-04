# NeuroSymbolic-BinSec (OPM): AI-Enhanced Automated Taint Analysis System

> **毕设项目**: 基于 **GNN 类型恢复 + 符号执行硬证据 + LLM 裁决** 的、面向 stripped 二进制的神经-符号自动化污点分析系统。

## ✨ 最新进展（v13：GNN 真正接入 + 真实基准验证）

- ✅ **GNN 类型恢复真正接入**：集成 [TYGR](https://github.com/sefcom/TYGR) **官方预训练 GlowGNN 模型**（真实 TYDA 训练，产出 `char*/f32*/array/struct` 精确类型），经版本忠实复刻的 `tygr-orig` 环境由主流程子进程调用。此前的 `gat_model.pt` 是零特征空壳。
- ✅ **真实基准试点（NIST Juliet 38 例）**：标准 F1=0.75（R=0.71）→ **GNN 类型驱动 F1=0.875（R=0.921）**，救回 8 个名字匹配漏掉的 CWE121 栈溢出。详见 [JULIET_PILOT.md](docs/JULIET_PILOT.md)。
- ✅ **GNN 不可替代价值实证**：全剥离（`--strip-all`）后函数名丢失，GNN 仍恢复类型语义；自定义手工缓冲 sink 从 0/0/0 → 1.0。

| 指标基准 | Precision | Recall | F1 |
|------|-----|-----|-----|
| 6 个自建测试程序（端到端） | 100% | 100% | 100% (27/0/0) |
| **NIST Juliet 38 例（标准）** | 0.794 | 0.711 | 0.750 |
| **NIST Juliet 38 例（+GNN 类型驱动）** | 0.833 | **0.921** | **0.875** |

> 6 程序的 100% 仅验证组件协同正确（toy 基准不可外推）；**Juliet 真实数据上指标如实下降**，且量化了 GNN 的价值——这是更可信的科研证据。

## 📚 文档导航

| 文档 | 内容 |
|------|------|
| [GNN_INTEGRATION.md](docs/GNN_INTEGRATION.md) | GNN 类型恢复接入的完整说明（架构/数据流/上手）|
| [VERSION_COMPAT.md](docs/VERSION_COMPAT.md) | `tygr-orig` 环境复刻全步骤 + 依赖踩坑 |
| [JULIET_PILOT.md](docs/JULIET_PILOT.md) | NIST Juliet 真实基准试点（方法/结果/复现）|
| [IMPLEMENTATION_LOG.md](docs/IMPLEMENTATION_LOG.md) | 详细实施记录 / 技术决策 / 踩坑 |
| [PAPER_MATERIAL.md](docs/PAPER_MATERIAL.md) | 论文/大会材料 + 技术 Q&A 预案 |
| [STATUS.md](docs/STATUS.md) | 项目状态、指标演进、模块清单 |
| [architecture.md](docs/architecture.md) | 系统架构 |

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
├── tygr_original/                    # TYGR(含官方模型)——外部依赖,不随仓库分发,需自取
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
├── output/tygr/                      # GNN 复现脚本(env 构建/demo/恢复记录) — 已纳入仓库
│
├── benchmarks/juliet/                # NIST Juliet 真实基准试点(harness/用例/结果)
│
├── docs/                             # 文档
│   ├── GNN_INTEGRATION.md           # GNN 接入说明
│   ├── VERSION_COMPAT.md            # tygr-orig 环境复刻
│   ├── JULIET_PILOT.md              # Juliet 真实基准
│   ├── IMPLEMENTATION_LOG.md        # 详细实施记录
│   ├── PAPER_MATERIAL.md            # 论文/大会材料 + Q&A
│   ├── STATUS.md / architecture.md  # 状态 / 架构
│   └── INTERNAL.md                  # 内部方法学
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

### 3) 配置 TYGR GNN 类型恢复（**可选外部依赖**）

类型恢复阶段基于 **[TYGR](https://github.com/sefcom/TYGR)** 的官方 GlowGNN 模型。TYGR 未随本仓库分发（见 [致谢与许可](#-致谢与许可)）。**官方模型死绑 TYGR 原始版本**（torch1.8/PyG1.7/angr-pyvex 9.0.7491），需复刻一个独立环境 `tygr-orig`，主流程经子进程调用：

```bash
# 1) 获取 TYGR（含官方预训练模型 model/MODEL_base/x64.O0.base.model）
git clone https://github.com/sefcom/TYGR.git tygr_original   # 放在 <PROJECT_ROOT>/tygr_original
# 2) 一键复刻版本忠实环境（脚本 + 依赖清单已在 output/tygr/）
bash output/tygr/build_orig_env.sh                            # 建 conda env `tygr-orig`
# 3) 可用环境变量覆盖模型/解释器:
#    TYGR_MODEL=<...x64.O0.base.model>  TYGR_PYTHON=<.../envs/tygr-orig/bin/python>
```

完整步骤、依赖踩坑（capstone/protobuf 降级等）与数据流见 **[VERSION_COMPAT.md](docs/VERSION_COMPAT.md)** 和 **[GNN_INTEGRATION.md](docs/GNN_INTEGRATION.md)**。
> 未配置时，类型恢复阶段会**优雅回退**到自训合成模型（兜底）再到启发式，主流水线仍可运行。
> 类型驱动 sink 识别（识别全剥离 + 自定义缓冲函数）由环境变量 `OPM_TYPE_SINKS=1` 开启（默认关）。

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

> v1–v11 为 `vulnerable.c` 单程序指标；v12–v13 为**全 6 程序**汇总（v13 另含真实基准）。

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
| v12 | 100% | 100% | 100% | 生命周期状态机计分 + printf .rodata 守卫 + 注释剥离 + 可达性过滤 | 全 6 程序 (27/0/0) |
| **v13** | **100%** | **100%** | **100%** | **GNN 真正接入（官方 GlowGNN）+ PIE 基址对齐 + 类型驱动 sink + 真实基准验证** | 全 6 程序 (27/0/0) |

**v13 全 6 程序仍 100/100/100**（GNN 开启,零回归）：vulnerable、memory_vuln、format_string、buffer_overflow、taint_flow、command_injection。

### v13 详解：从"组件正确"到"真实可信"

v1–v12 一直在 6 个自建程序上打磨,**v12 的 100% 只证明各项修复正确,不能外推**。v13 做了两件让结果可信的大事:

**① GNN 从空壳变成真正工作的核心**（此前 6 程序的 100% 是在 GNN 不参与下达成的）
- 接入 TYGR **官方预训练 GlowGNN 模型**(真实 TYDA 训练 → char*/f32*/array/struct),经版本忠实复刻的 `tygr-orig` 环境子进程调用
- **PIE 基址对齐**:DWARF `low_pc` ↔ angr 重定位地址,类型精确归到真实 CFG 函数
- **类型驱动 sink 识别**(`OPM_TYPE_SINKS`):补回名字/结构启发式漏掉的自定义缓冲 sink

**② 真实第三方基准验证（NIST Juliet 38 例）**——指标如实从 toy 100% 降到真实水平,并量化 GNN 价值:

| Juliet 38 例 | Precision | Recall | F1 |
|---|---|---|---|
| ① 标准（名字/结构启发式） | 0.794 | 0.711 | 0.750 |
| ② 标准 + LLM 裁决 | 0.794 | 0.711 | 0.750（零变化）|
| **③ +GNN 类型驱动** | 0.833 | **0.921** | **0.875** |
| ④ +GNN 类型驱动 + LLM | 0.522 | 0.921 | 0.667 ⬇ |

> **GNN 召回价值是真的**(③):召回 **0.711 → 0.921**(救回 8 个名字匹配漏掉的 CWE121 栈溢出)。
> **LLM 精确率价值在本配置下未兑现(负结果)**:②中 LLM 是 no-op、④朴素叠加伤精确率——根因是批量消融只喂了 GNN 类型证据、**未喂 angr 符号约束**(判别"安全/危险 sink"的硬证据)。**敢报负结果**:完整"神经-符号-LLM"验证 + type-sink 降误报 + 扩规模,是我们明确的下一步(见 [JULIET_PILOT.md](docs/JULIET_PILOT.md) §7「待解决问题」)。详见 [GNN_INTEGRATION.md](docs/GNN_INTEGRATION.md)、[IMPLEMENTATION_LOG.md](docs/IMPLEMENTATION_LOG.md)。

## 🧪 方法学贡献（v9–v13）

1. **作用域感知 Ground Truth 与污点引擎** —— 逐函数追踪污点，消除"全局同名变量跨作用域错连"产生的幽灵漏报/误报。
2. **推理模型裁决复活** —— mimo-v2.5-pro 的隐藏推理 token 计入 `max_tokens`，1024 时可见 JSON 被截断、裁决静默默认 0.5；提升至 4096 + 容错解析 + 决策字段前置。
3. **对象生命周期状态机** —— 将数据流 source→sink 模型无法表达的 double-free / use-after-free 以 `(函数名, 漏洞类型)` 在 GT 与分析器两侧归一化对齐并计分。
4. **printf 格式串 .rodata 守卫** —— 为克服纯二进制分析中格式化字符串歧义的传统局限，用 angr 反汇编 printf/fprintf 调用点，判定格式参数寄存器是否经 `lea reg,[rip+disp]` 指向 `.rodata` 字面量；**保守**降级（仅全部确证为字面量才视为非漏洞），真实 `printf(tainted)` 一律保留。
5. **注释剥离 + 可达性过滤** —— GT 剥离 C 注释（避免把注释掉的调用当真调用）；分析器按 main 的 callee 闭包丢弃死代码中的数据流路径（生命周期漏洞豁免）。
6. **（v13）GNN 类型恢复工程化接入** —— 官方 GlowGNN 死绑 torch1.8/PyG1.7/angr-pyvex 9.0.7491（pickle 跨版本 + VEX 边词表 edge_dim=44 锁死），用独立 `tygr-orig` 环境 + 子进程隔离解决；**PIE 基址对齐**让 DWARF `low_pc` 映射到 angr 重定位地址。
7. **（v13）类型驱动 sink 识别** —— 把"无名 + GNN 标 char\* 缓冲 + 在调用图中"的自定义函数补成 sink 候选并连出污点路径,补回名字/结构启发式漏掉的检出（全剥离 + 手工缓冲拷贝场景);GT 支持 `// @vuln:` 注解。
8. **（v13）真实基准评估法** —— 用 NIST Juliet 自带 good/bad + `OMITGOOD/OMITBAD` 宏编译正/负例,正例应检出、负例不应,据此算 P/R/F1;诚实暴露指标下降与 GNN 增量召回。

## 🔧 核心功能

### 1. 二进制分析
- VEX IR提升 (angr/pyvex)
- CFG恢复 (angr CFGFast)
- DFG构建
- 调用图分析

### 2. GNN 类型恢复（真正接入）
- TYGR 官方 **GlowGNN** 模型（真实 TYDA 训练）→ char*/f32*/array/struct 精确类型
- 版本忠实复刻 `tygr-orig` 环境，主流程子进程调用；PIE 基址对齐到真实 CFG 函数
- 类型驱动 sink 识别（`OPM_TYPE_SINKS`）：补回名字/结构启发式漏掉的自定义缓冲 sink

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

> **本仓库为协作中的在研项目（WIP），非最终状态。** 6 个自建程序 100/100/100 仅验证组件协同；
> 已用 NIST Juliet 真实基准做试点（指标如实下降）。普适性仍需**更大规模**验证。

路线图（优先级从高到低，✅=本轮已完成）：

1. ✅ **GNN 真正接入** —— 官方 TYGR GlowGNN 经 `tygr-orig` 环境接入；PIE 基址对齐；类型驱动 sink 识别。见 [GNN_INTEGRATION.md](docs/GNN_INTEGRATION.md)。
2. ✅ **真实基准试点** —— NIST Juliet 38 例：标准 F1=0.75 → +GNN F1=0.875（R 0.71→0.92）。见 [JULIET_PILOT.md](docs/JULIET_PILOT.md)。**下一步：扩到数百例 + 真实 CVE + 更多流变体。**
3. **加固 GNN datagen 鲁棒性** —— 部分 `alloca` 等场景使 TYGR 符号执行断言失败（1/38 漏检）。
4. **类型驱动 sink 闭环扩展** —— 当前覆盖 buffer_overflow；扩到 UAF/命令注入等，并去掉对显式注解的依赖。
5. **提速 LLM 裁决阶段**（瓶颈 ~30–40s/路径）—— 仅对模糊路径调 LLM / 批处理 / 本地模型。
6. **函数内缓冲级数据流** —— 解决"同函数多缓冲错配"（追踪每个 source/sink 实际操作的缓冲）。

**详细实施记录 / 技术决策 / 踩坑**见 [IMPLEMENTATION_LOG.md](docs/IMPLEMENTATION_LOG.md)；**大会/论文材料 + 技术 Q&A** 见 [PAPER_MATERIAL.md](docs/PAPER_MATERIAL.md)；**指标演进**见 [STATUS.md](docs/STATUS.md)。

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
