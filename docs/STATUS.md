# OPM 项目状态文档

> **最后更新**: 2026-06-03
> **当前版本**: v12 (作用域感知 + 生命周期计分 + printf .rodata 守卫 + 死代码过滤)

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

### 2. GNN模型集成

**当前状态**:
- GAT模型已训练，但未真正用于类型恢复
- TYGR组件可用，但需要WSL环境

**需要完成**:
1. 将GAT模型集成到类型恢复流程
2. 使用GNN结果指导污点分析
3. 训练更精确的模型

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

> v1–v11 为 `vulnerable.c` 单程序；v12 为**全 6 程序**汇总。

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
| **v12** | **100%** | **100%** | **100%** | 生命周期状态机计分 + printf .rodata 守卫 + 注释剥离 + 可达性过滤 | **全 6 程序 (27/0/0)** |

---

## 🔧 技术栈

| 组件 | 版本 | 说明 |
|------|------|------|
| Python | 3.10 | WSL中 |
| angr | 9.2.212 | 二进制分析 |
| PyTorch | 2.11.0 | 深度学习 |
| PyG | 2.7.0 | 图神经网络 |
| mimo-v2.5-pro | - | LLM API |

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

1. **更大基准（最高优先）**
   - NIST Juliet C/C++ 1.3 相关 CWE 子集（CWE-78/121/122/134/415/416，自带 good/bad 标签作 GT）
   - 先跑 ~20 用例试点，实测单例耗时再外推；**预期 100/100/100 会下降**——那才是有价值的科研数据

2. **提速 LLM 裁决阶段**（当前瓶颈，~30–40s/路径）
   - 仅对"模糊路径"调 LLM、批处理、或换本地模型

3. **函数内缓冲级数据流**
   - 解决 `command_injection.c` 暴露的"同函数多缓冲错配"（fgets 污染 result 而 popen 用 command）

4. **完成 GNN 集成**（仍未做）
   - 让已训练的 GAT 模型真正参与类型恢复并指导污点分析

5. **论文撰写**
   - 方法论描述、实验结果、对比分析
