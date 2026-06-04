# OPM 项目状态文档

> **最后更新**: 2026-06-04
> **当前版本**: v13 (**GNN 类型恢复真正接入** — TYGR 官方模型 + tygr-orig 环境 + PIE 基址对齐)
> v12: 作用域感知 + 生命周期计分 + printf .rodata 守卫 + 死代码过滤

---

## 📊 当前指标（全 6 测试程序端到端）

| 指标 | 值 | 目标 |
|------|-----|------|
| **Precision** | 100% | ≥95% ✅ |
| **Recall** | 100% | ≥90% ✅ |
| **F1-Score** | 100% | ≥90% ✅ |

> 6/6 程序均 100/100/100；汇总 TP/FP/FN = 27/0/0。
> v8 的"R=83.33%"系仅 vulnerable.c，且被**幽灵 Ground Truth（全局同名变量跨作用域错连）+ LLM 裁决静默失效（推理模型 token 截断）**双重低估——经查明并修复后实为 100%。

---

## ✅ 已完成工作

### 核心模块

| 模块 | 文件 | 状态 | 说明 |
|------|------|------|------|
| 编译模块 | `src/compilation/` | ✅ | gcc编译+strip |
| Ground Truth | `src/ground_truth/` | ✅ | 源码分析 |
| VEX IR提升 | `src/binary_analysis/vex_lift.py` | ✅ | angr/pyvex |
| CFG恢复 | `src/binary_analysis/cfg_recovery.py` | ✅ | angr CFGFast |
| DFG构建 | `src/binary_analysis/dfg_construction.py` | ✅ | 数据流分析 |
| 调用图 | `src/binary_analysis/call_analysis.py` | ✅ | 函数调用分析 |
| GNN模型 | `src/type_recovery/gat_model.py` | ✅ | GAT实现 |
| 类型注入 | `src/typed_ir/type_injector.py` | ✅ | 类型元数据 |
| 路径优先级 | `src/symbolic_exec/path_prioritizer.py` | ✅ | 路径排序 |
| 启发式剪枝 | `src/symbolic_exec/heuristic_pruning.py` | ✅ | 路径剪枝 |
| 污点引擎 | `src/taint_analysis/taint_engine_v2.py` | ✅ | 核心引擎 |
| AI Orchestrator | `src/orchestrator/` | ✅ | mimo API |
| 评估模块 | `src/evaluation/` | ✅ | P/R/F1 |
| 报告生成 | `src/evaluation/reporter.py` | ✅ | JSON/Markdown |

### 增强功能

| 功能 | 文件 | 状态 | 说明 |
|------|------|------|------|
| CoT推理 | `src/orchestrator/llm_client.py` | ✅ | 多阶段思维链 |
| GNN注意力报告 | `src/type_recovery/attention_report.py` | ✅ | 图结构证据 |
| 符号约束提取 | `src/symbolic_exec/constraint_extractor.py` | ✅ | 数学证明 |
| 生命周期追踪 | `src/taint_analysis/lifecycle_tracker.py` | ✅ | UAF检测 |
| 反事实验证 | `src/taint_analysis/counterfactual.py` | ✅ | 减少误报 |
| GNN Sink检测 | `src/taint_analysis/gnn_sink_detector.py` | ✅ | 智能检测 |
| 学习传播 | `src/taint_analysis/learned_propagation.py` | ✅ | ML传播 |
| 多模态融合 | `src/binary_analysis/multimodal_fusion.py` | ✅ | ORACAL风格 |

### 测试程序（6 个，端到端均 P/R/F1 = 100/100/100）

| 程序 | 漏洞类型 | P/R/F1 |
|------|----------|--------|
| vulnerable.c | buffer_overflow, format_string, command_injection, gets | 100/100/100 |
| buffer_overflow.c | buffer_overflow (strcpy/strcat/heap/off-by-one) | 100/100/100 |
| format_string.c | format_string (printf/fprintf/sprintf) | 100/100/100 |
| command_injection.c | command_injection (system) | 100/100/100 |
| memory_vuln.c | use_after_free, double_free | 100/100/100 |
| taint_flow.c | 复杂污点流 (global/indirect/conditional/loop/pointer) | 100/100/100 |

> **GNN 专项演示**（`output/tygr/demo_custom_sink.c`，非标准套件）：自定义手工缓冲拷贝 `store_record`（不调 libc，全靠 GNN 类型识别）。名字/结构启发式 **0/0/0** → `OPM_TYPE_SINKS=1` 类型驱动 **100/100/100**。

### 训练数据

| 数据 | 位置 | 说明 |
|------|------|------|
| vulnerable训练数据 | `data/training/vulnerable/` | 7个函数 |
| taint_flow训练数据 | `data/training/taint_flow/` | 7个函数 |
| GAT模型 | `data/models/gat_model.pt` | 已训练 |
| 传播模型 | `data/models/propagation.pt` | 已训练 |

---

## ⚠️ 未完成工作

### 1. 漏报问题 (Recall) —— ✅ 已查明真因并修复（83.33% → 100%）

原以为的两个"漏报路径" `gets→free`、`gets→strncpy` **经查明是幽灵 Ground Truth**：
- **真因 A（幽灵 GT）**：GT 提取器的 `var_to_source` 全局、无视作用域、按变量名索引。`vulnerable_stack` 里的 `gets(buffer)` 把**其它函数同名的局部 `buffer`**(vulnerable_heap 的 free、safe_function 的 strncpy)误标成 source=gets → 凭空生成两条期望路径。分析器其实正确识别真实源是 argv。
- **真因 B（LLM 静默失效）**：mimo-v2.5-pro 为推理模型，隐藏推理 token 计入 `max_tokens=1024` → 可见 JSON 被截断/为空 → 解析失败 → 每条路径默认 0.5/全接受，证据注入被丢弃。

**修复（全部已实现）**：
1. ✅ GT 提取器与污点引擎**作用域感知**（消除幽灵路径）
2. ✅ `max_tokens=4096` + 容错解析 + 决策字段前置（裁决复活）
3. ✅ 符号约束硬证据（strncpy 未受限 size、gets 无条件溢出）
4. ✅ 生命周期状态机真正检测 double-free / UAF 并计分

### 2. GNN模型集成 —— ✅ 已完成（v13）

**此前问题**：本地 `gat_model.pt` 是零特征空壳，Stage 6 类型恢复恒输出 0；过去的 100/100/100 是在 **GNN 不参与**下达成的。

**现状（已接入并验证）**：
- 改用 **TYGR 官方预训练模型** `x64.O0.base.model`（真实 TYDA 训练），经**版本忠实复刻的 `tygr-orig` conda 环境**（torch1.8/PyG1.7/angr 9.0.7491）加载；OPM 主流程在 angr-env，**子进程**调用 tygr-orig 跑 predict。
- `src/type_recovery/inference.py::_recover_with_gnn` → predict → 组装 `TypeRecoveryOutput`（char*/pointer/array/struct/int…）。
- **PIE 基址对齐**：DWARF `low_pc` ↔ angr 重定位地址，按 `mapped_base` 双键映射 → 类型精确归到真实 CFG 函数名。
- 全 6 程序端到端：Stage 6 GNN 25–37 函数、Stage 7 注入 64–108 typed variables、**P/R/F1 全 1.0、零回退**。
- **全剥离(`--strip-all`)实证**：函数名丢失成 `sub_xxxx`，GNN 仍恢复 char*/struct/指针语义 → 证明 GNN 是全剥离场景下类型语义的唯一来源。
- 详见 [GNN_INTEGRATION.md](GNN_INTEGRATION.md) 与 [VERSION_COMPAT.md](VERSION_COMPAT.md)。

**仍可继续**：把 GNN 类型真正喂进污点 sink 判定（识别全剥离 + 自定义手工缓冲拷贝函数）——见「下一步计划」。

### 3. 动态路径编排

**当前状态**:
- AI Orchestrator在流水线后端
- 符号执行完成后LLM才介入

**需要实现**:
1. LLM驱动的路径探索
2. 动态剪枝决策
3. MCTS路径搜索

### 4. 神经-符号融合

**当前状态**:
- GNN和LLM独立工作
- 没有真正的融合

**需要实现**:
1. GNN注意力权重转化为Token
2. 图嵌入向量相似度报告
3. 底层图结构支撑上层语义分析

---

## 📈 指标演进历史（v1 → 最终）

> v1–v11 为 `vulnerable.c` 单程序；v12–v13 为**全 6 程序**汇总（v13 另含 Juliet 真实基准）。

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
| v9 | 80% | 100% | 88.89% | 作用域感知 GT + 推理模型裁决复活（揭示 83% 召回为幽灵 GT+LLM 静默失效；暴露 2 真实 FP）| vulnerable.c |
| v10 | 100% | 87.5% | 93.33% | 污点引擎 4 处跨函数作用域守卫（清除 argv→gets、gets→strcpy）| vulnerable.c |
| v11 | 100% | 100% | 100% | gets 无条件栈溢出铁证（钉死 gets→gets）| vulnerable.c |
| v12 | 100% | 100% | 100% | 生命周期状态机计分 + printf .rodata 守卫 + 注释剥离 + 可达性过滤 | 全 6 程序 (27/0/0) |
| **v13** | **100%** | **100%** | **100%** | **GNN 真正接入(官方 GlowGNN)+ PIE 基址对齐 + 类型驱动 sink + NIST Juliet 真实基准** | 全 6 程序 (27/0/0) |

> **v13 真实基准(NIST Juliet 38 例)**:标准 P=0.794/R=0.711/F1=0.750 → **+GNN 类型驱动 P=0.833/R=0.921/F1=0.875**(救回 8 个 CWE121 栈溢出)。详见 [JULIET_PILOT.md](JULIET_PILOT.md)。

---

## 🔧 技术栈

| 组件 | 版本 | 说明 |
|------|------|------|
| Python | 3.10 | WSL中 |
| angr | 9.2.212 | 二进制分析（主环境 angr-env） |
| PyTorch | 2.x | 深度学习（主环境） |
| PyG | 2.7.0 | 图神经网络（主环境） |
| mimo-v2.5-pro | - | LLM API（推理模型，max_tokens≥4096） |
| **tygr-orig 环境** | py3.8 / torch1.8.1 / PyG1.7.0 / angr 9.0.7491 | **专跑 TYGR 官方 GNN 模型**（子进程调用） |
| TYGR 官方模型 | `x64.O0.base.model` | 真实 TYDA 训练的 GlowGNN 类型恢复 |

---

## 📝 运行命令

### 单个测试
```bash
wsl -d Ubuntu-20.04 -- bash -c "cd <PROJECT_ROOT> && /root/miniconda3/envs/angr-env/bin/python scripts/run_pipeline.py tests/test_programs/vulnerable.c -o output/test"
```

### 批量测试
```bash
wsl -d Ubuntu-20.04 -- bash -c "cd <PROJECT_ROOT> && /root/miniconda3/envs/angr-env/bin/python scripts/run_batch_tests.py"
```

### 训练GNN
```bash
wsl -d Ubuntu-20.04 -- bash -c "cd <PROJECT_ROOT> && /root/miniconda3/envs/angr-env/bin/python scripts/train_gat.py data/training/vulnerable -o data/models/gat_model.pt"
```

---

## 🎯 下一步计划

> ✅ **已达成（原"提高 Recall"目标）**：Recall 100%。改进 CoT prompt、符号约束硬证据
> （strncpy 未受限 size / gets 无条件溢出）、生命周期 double-free/UAF 检测 **均已完成**，
> 全 6 程序 100/100/100。

1. **更大基准（✅ Juliet 试点已做 → 继续扩大）**
   - **已完成 38 例 NIST Juliet 试点**(CWE121/122/134/78,good/bad 作 GT)：标准 F1=0.75(R=0.71)→ **GNN 类型驱动 F1=0.875(R=0.921)**。详见 [JULIET_PILOT.md](JULIET_PILOT.md)。
   - 真实数据上指标如实从 100% 降下来,且 **GNN 把召回 +21 点**(救回 8 个 libc-名漏掉的 CWE121 栈溢出)——有价值的科研数据。
   - 下一步:扩到数百例 + 真实 CVE + 更多流变体;加固 TYGR datagen 在 alloca 等场景的鲁棒性(1 例断言崩溃)。

2. **提速 LLM 裁决阶段**（当前瓶颈，~30–40s/路径）
   - 仅对"模糊路径"调 LLM、批处理、或换本地模型

3. **函数内缓冲级数据流**
   - 解决 `command_injection.c` 暴露的"同函数多缓冲错配"（fgets 污染 result 而 popen 用 command）

4. **GNN 集成**（✅ 类型恢复 + ✅ 类型驱动 sink 识别**完整闭环**）
   - `analyze()` 接 `type_recovery_output`；`_find_sinks_by_types`（`OPM_TYPE_SINKS=1` 门控）检出自定义手工缓冲 sink、分类 buffer_overflow；GT 提取器支持 `// @vuln:` 注解
   - **实证**：custom_sink（手工缓冲拷贝、不调 libc）名字/结构启发式 **0/0/0** → GNN 类型驱动 **1.0/1.0/1.0**；标准 6 程序零回归
   - **可扩展**：无注解自动识别更多自定义 sink 模式、扩到 UAF/命令注入

5. **论文 / 大会材料**（进行中）
   - 见 [PAPER_MATERIAL.md](PAPER_MATERIAL.md)：摘要、方法论、神经-符号架构、实验、新颖性、技术 Q&A 预案
   - 目标场合：布拉格 Linux Foundation 大会
