# NeuroSymbolic-BinSec (OPM) — 论文/大会前置材料

> 目标场合：布拉格 Linux Foundation 大会。本文件为**演讲叙事 + 论文骨架 + 技术 Q&A 预案**。
> **基调：诚实、可辩护、不夸大。** 技术听众能看穿任何 inflation；我们用「明确的威胁模型 + 诚实的局限」换取可信度。
>
> 一句话定位：**用神经-符号(GNN + 符号执行 + LLM 裁决)增强的、面向 stripped 二进制的自动化污点分析系统。**

---

## 1. 摘要 (Abstract)

剥离符号的二进制(stripped binaries)上做漏洞导向的污点分析，核心难点是**语义缺失**：没有变量名、类型、函数边界的可靠线索，传统基于函数名/签名的 source-sink 匹配在全剥离场景退化。我们提出 **OPM (NeuroSymbolic-BinSec)**，一个 13 阶段流水线，把三种互补的"AI/形式化"能力编排在一起：(1) **GNN 类型恢复**(集成 TYGR/GlowGNN)在缺失调试信息时恢复变量的指针/缓冲/结构语义；(2) **符号执行**(angr/claripy)为可疑路径生成**可数学验证的硬证据**(如 `strncpy` 的 size 实际未受约束、`gets` 的无条件栈溢出)；(3) **LLM 裁决**(推理模型，思维链)在硬证据 + 软阈值上做最终 source-sink 判定，抑制误报。在 6 个涵盖缓冲溢出/格式化串/命令注入/UAF/double-free 的程序上端到端达到 P/R/F1=100%(27/0/0)；并通过**全剥离实证**展示 GNN 在符号/名字线索全失时仍能恢复类型语义——这是本系统区别于纯启发式的核心价值。

---

## 2. 问题与动机 (Problem & Motivation)

- **为什么是 stripped 二进制**：现实世界(固件、闭源商业软件、恶意样本)大多无源码、常被 `strip --strip-all` 剥离。安全审计必须在二进制层面进行。
- **污点分析的语义依赖**：source/sink 识别传统靠**函数名**(libc：`gets`/`strcpy`/`system`/`printf`)。动态符号(libc 导入)在 `--strip-all` 后**仍存活**(动态重定位需要)，但**本地/自定义函数名全丢**(`.symtab` 被抹) → 自定义的危险缓冲操作变成无名 `sub_xxxx`，名字匹配失效。
- **类型语义的价值**：知道"`sub_4011e9` 的参数是 `char*` 缓冲、内部对其做无界写"，才能把它识别为 sink 候选。**类型恢复**正是补这块语义。
- **单一技术的不足**：GNN 给类型但不给"是否真的可溢出"的证明；符号执行给约束但路径爆炸且缺高层语义；LLM 有语义直觉但会幻觉。**三者编排**才稳。

## 3. 威胁模型与范围 (Threat Model & Scope) —— 诚实声明

| 维度 | 本系统假设/范围 |
|------|------|
| 输入 | x86-64 ELF；当前类型恢复阶段需要二进制带 DWARF(`-g`)以**定位变量**(见 §8 局限) |
| 目标漏洞 | 缓冲溢出、格式化串、命令注入、UAF、double-free(memory-safety + injection 类) |
| 不保证 | **不 sound 也不 complete**：基于启发式 + ML + 概率裁决，目标是高质量的 bug 发现，非形式化验证 |
| 评估规模 | 当前 6 个程序(toy benchmark)——**我们明确不声称这是大规模有效性证据**，见 §7、§9 |

---

## 4. 系统架构 (13 阶段流水线)

```
源码/二进制
 1 编译&剥离      gcc -g → 保留 -g 副本(类型恢复用) + strip 副本(分析用)
 2 Ground Truth   从源码抽取期望漏洞(作用域感知，仅用于评估)
 3 代码提升       angr → VEX IR
 4 CFG 恢复       angr CFGFast
 5 DFG + 调用图   数据流 + 函数调用
 6 GNN 类型恢复   ★ TYGR GlowGNN(官方模型) → 逐变量 char*/ptr/array/struct
 7 类型注入       类型元数据注入 TypedIR(PIE 基址对齐到真实函数)
 8 符号执行       angr/claripy，路径优先级 + 启发式剪枝
 9 污点分析       ★ 作用域感知 source-sink + 生命周期状态机(UAF/double-free)
10 源-汇路径      路径枚举 + 可达性过滤 + .rodata 格式串守卫
11 LLM 裁决       ★ 推理模型 CoT，在符号硬证据 + 软阈值上判定
12 评估           P/R/F1 对比 Ground Truth
13 报告           JSON / Markdown
```
★ = 三个核心"智能"组件。

---

## 5. 核心技术贡献 (Technical Contributions)

### 5.1 GNN 类型恢复的工程化集成（神经组件）
- 集成 [TYGR](https://github.com/sefcom/TYGR) 的 **GlowGNN**：在 angr 符号执行得到的 **"glow" 计算图**(节点=值/操作，边=VEX 操作类别)上做图神经网络消息传递，预测每个变量位置的类型。
- **直接用官方在真实 TYDA(Gentoo C/C++ 二进制)上训练的权重**——产出丰富类型(`char*`/`f32*`/`array`/`struct`)。
- **关键工程难点(可辩护点)**：官方模型死绑 angr/pyvex 9.0.7491 + PyG 1.7(既因整体 pickle 跨 PyG 版本失败，也因 **VEX 边操作词表**与训练时不一致 → 特征维度对不上)。解决：**复刻独立 `tygr-orig` 环境**，OPM 主流程**子进程**调用——两环境解耦。(详见 VERSION_COMPAT.md)
- **PIE 基址对齐**：GNN 的类型挂在 DWARF `low_pc`，angr 用 PIE 重定位地址；按 `mapped_base` 偏移双键映射 → 类型精确归到真实 CFG 函数。

### 5.2 符号执行的"硬证据"(形式化组件)
不只判"可能危险"，而是用约束求解给**可验证证据**：
- `strncpy(dst, src, n)`：抽取 `n` 的符号约束，证明 **`n` 实际不受 dst 缓冲大小约束**(安全假象被打破)。
- `gets(buf)`：构造**无条件栈溢出**证据(输入长度无上界)。
这些证据作为**事实**喂给 LLM 裁决，避免 LLM 凭空臆断。

### 5.3 作用域感知污点 + 生命周期状态机
- **作用域感知**：消除"幽灵 Ground Truth"——全局按变量名索引会把不同函数的同名局部变量错连(曾导致 83% 召回的假象)。source-sink 与 GT 抽取都作用域隔离。
- **生命周期状态机**：对堆对象建模 `allocated→freed→use`，真正检测 **UAF / double-free**(而非字符串匹配)。
- **保守守卫**：`printf` 的格式串若指向 `.rodata` 字面量则不计 format-string sink；过滤从 main 不可达的死代码路径。

### 5.4 LLM 裁决的工程教训（可辩护点）
- 用 mimo-v2.5-pro **推理模型**做 source-sink 链的思维链裁决。
- **踩坑**：推理模型的隐藏 reasoning token 计入 `max_tokens`；设 1024 时可见 JSON 被截断为空 → 解析失败 → 每条路径默认 0.5/全接受 → 静默失效。修复：`max_tokens≥4096` + 容错解析 + 决策字段前置。这是"把推理模型用对"的真实经验。

---

## 6. 实现 (Implementation)
- 语言/框架：Python；angr 9.2(主)/9.0.7491(tygr-orig)；PyTorch + PyG；claripy 求解。
- 双环境：`angr-env`(现代，跑 OPM 主流程) + `tygr-orig`(复刻，跑官方 GNN)，子进程桥接。
- 代码量级与模块见 STATUS.md 模块表。可复现：环境一键脚本 `output/tygr/build_orig_env.sh`。

## 7. 评估 (Evaluation) —— 含诚实定位
| 程序 | 漏洞 | GNN 函数 | typed 变量 | P/R/F1 |
|------|------|---------|-----------|--------|
| vulnerable | 溢出/格式串/命令注入/gets | 37 | 94 | 1.0/1.0/1.0 |
| buffer_overflow | strcpy/strcat/heap/off-by-one | 32 | 93 | 1.0 |
| format_string | printf/fprintf/sprintf | 25 | 64 | 1.0 |
| command_injection | system | 35 | 88 | 1.0 |
| memory_vuln | UAF/double-free | 30 | 86 | 1.0 |
| taint_flow | global/indirect/conditional/loop/pointer | 35 | 108 | 1.0 |

- 汇总 TP/FP/FN = **27/0/0**。
- **诚实说明①**：这 6 个是 toy benchmark，**不能**当作大规模有效性证据。它验证的是"流水线各组件协同正确"，不是"在真实世界 bug 上的召回率"。
- **诚实说明②**：这些程序仅 `--strip-debug`(函数名保留)，故 100% 主要靠污点引擎的名字/结构启发式，**GNN 不是这些样例检出的必要条件**。
- **GNN 价值的独立实证(全剥离)**：把 `memory_vuln` 用 `strip --strip-all` 全剥离后，函数名丢成 `sub_xxxx`，GNN 仍恢复出语义：
  | 全剥离 CFG | (真名) | GNN 恢复 |
  |---|---|---|
  | `sub_4011e9` | vuln_use_after_free | pointer, **struct**, **char\*** |
  | `sub_401354` | safe_memory | char*, char*, char* |
  | `main` | main | int32, **char\*, char\***(argc/argv) |
  → 在全剥离上 GNN 是类型语义的**唯一**来源。

---

### 7.1 类型驱动 sink 识别的实证（GNN 检出名字匹配漏掉的漏洞）
构造 `store_record(char* dst, char* src)`：手工 `while` 缓冲拷贝、**不调用任何 libc**、`main` 用 `argv[1]` 调用它（无界写 → 溢出）。

| | 纯名字/结构启发式 | GNN 类型驱动(`OPM_TYPE_SINKS=1`) |
|---|---|---|
| sink 识别 | **0**（store_record 无名、不调 libc → 漏） | 候选 sink（GNN 标其 dst/src 为 char*） |
| 污点路径 | **0** | **`argv → store_record`(1)** |
| **P/R/F1** | **0 / 0 / 0** | **1.0 / 1.0 / 1.0** |

**完整评估闭环**：类型 sink 分类为 `buffer_overflow` + GT 提取器支持显式注解(`// @vuln: buffer_overflow argv -> store_record`) → 评估按 `(source,sink)` 匹配 → custom_sink 达 P/R/F1=1.0(标准 6 程序在 flag 关下零回归)。这是 GNN 不可替代价值在**检出能力**上的直接证据：类型恢复让"无符号线索"的自定义缓冲漏洞重新可见。（脚本 `output/tygr/demo_type_sink.sh`）

### 7.2 真实基准试点:NIST Juliet（最重要的可信度证据）
在第三方真实漏洞基准 **NIST SARD Juliet C/C++ 1.3** 上选 **38 个用例**(CWE121/122/134/78,正好对应本系统目标漏洞)。用 Juliet 自带 good/bad 结构 + `OMITGOOD/OMITBAD` 宏编译正/负例,正例应检出、负例不应,据此算 P/R/F1(详见 [JULIET_PILOT.md](JULIET_PILOT.md))。

**四组消融**(LLM 端点 FreeModel `gpt-5.4-mini`;小米 MiMo 端点 451 跨境不可用):

| 配置 | Precision | Recall | F1 |
|---|---|---|---|
| ① 标准(名字/结构) | 0.794 | 0.711 | 0.750 |
| ② 标准 + LLM 裁决 | 0.794 | 0.711 | 0.750（零变化）|
| **③ +GNN 类型驱动** | **0.833** | **0.921** | **0.875** |
| ④ +GNN 类型驱动 + LLM | 0.522 | 0.921 | 0.667 ⬇ |

**三个关键结论(含负结果)**:
1. **指标如实下降**:真实基准上从 6 程序的 100% 降到 ~75% 基线——诚实、可外推(toy 100% 不能外推)。
2. **GNN 的召回价值是真的**(③):类型驱动把召回 **0.711 → 0.921**(+21 点),救回 8 个 **CWE121 栈溢出**(缓冲索引越界写、无 libc sink 名,名字/结构启发式全漏)。这把"GNN 有用"量化了。
3. **LLM 的精确率价值在本配置下没兑现(负结果)**:② 中 LLM 是 no-op(7 个负例误报一个没滤、27 个真阳一个没杀);④ 朴素叠加反而把精确率拖到 0.522。**根因**:批量消融只给 LLM 喂了 GNN 类型证据,**未含 angr 符号约束**(那才是判别"安全 vs 危险 sink"的硬证据)。所以证明的是 **"LLM+仅类型=无用",非"LLM 无用"**。完整"神经-符号-LLM"(含符号硬证据)在 Juliet 上的验证是**下一步**(§8)。

## 8. 局限 (Limitations) —— 主动暴露
1. **类型恢复当前依赖 DWARF 定位变量**：TYGR 用 DWARF 找"变量在哪"，GNN 预测"它是什么类型"。在**完全无 DWARF**的二进制上，需要先做变量恢复(angr `VariableRecovery` 或类似)再喂 GNN——这是**已知的下一步**，当前用 `-g` 副本绕过。诚实地说：**目前的 demo 在"全剥离的分析二进制 + 带 DWARF 的类型恢复二进制"组合下成立**。
2. **类型驱动 sink 识别（✅ 已实现并闭环）**：`_find_sinks_by_types`（`OPM_TYPE_SINKS=1` 门控）用 GNN 类型把"无名 + char* 缓冲 + 手工拷贝"的自定义函数补成 sink 候选、连出污点路径、分类为 buffer_overflow，配合 GT 注解 → custom_sink 上 **P/R/F1=1.0**（§7.1）。**仍可扩展**：自动(无注解)识别更多自定义 sink 模式、扩到 UAF/命令注入等。
3. **规模**：已做 **NIST Juliet 38 例真实试点**(§7.2,F1 基线 0.75 → GNN 0.875);仍需扩到**数百例 + 真实 CVE**,并覆盖更多 CWE 与流变体(02-54)。当前仅单文件基础变体 `_01`。
4. **LLM 裁决的价值未兑现(负结果)**：Juliet 消融显示 LLM(仅类型证据)是 no-op,叠加 type-sink 反而伤精确率(§7.2)。根因是批量评估未喂 angr 符号约束证据;下一步把符号硬证据接进批量裁决,验证"神经-符号-LLM"能否滤掉 goodB2G 误报。另:LLM 延迟 ~30–40s/路径,是吞吐瓶颈。
5. **类型驱动 sink 的精确率代价**:`OPM_TYPE_SINKS` 对称应用时 good 变体大量误报(P 0.522)。需更强触发条件(函数内确有"无界写+污点索引"迹象),而非"有 char* 参数即标 sink"。
6. **不 sound/complete**：见威胁模型。

## 9. 相关工作与新颖性 (Related Work & Novelty)
- **TYGR**(我们复用其类型推断)：只做类型推断，不做端到端漏洞分析。我们的贡献是**把它编排进神经-符号污点流水线**并解决其跨版本工程化。
- **ORACAL 风格多模态融合**：架构借鉴。
- 传统污点(libdft/Triton/angr 自带)：纯静/动态，缺高层语义裁决。
- **新颖性主张(克制)**：不是"发明新 GNN/新求解器"，而是**一种把 GNN 类型语义 + 符号硬证据 + LLM 裁决三者编排、用于 stripped 二进制漏洞发现的系统化方法**，及其可复现的工程实现。

---

## 10. 技术 Q&A 预案（大会被追问时）

> 原则：**承认局限 = 加分**。听众更信任"知道自己边界"的系统。

**Q: 6 个程序 100% 是不是过拟合/没意义？**
A: 同意 6 程序只证明组件协同正确,不是有效性证据。所以我们**做了真实基准试点**:NIST Juliet 38 个用例,指标如实降到**基线 F1=0.75(R=0.71)**——这才是可外推的数据。更重要的是:**GNN 类型驱动把召回从 0.71 提到 0.92**,救回 8 个 libc-sink 名字匹配全漏的 CWE121 栈溢出。所以我们不回避指标下降,反而用它量化了 GNN 的真实价值(见 §7.2)。下一步是扩到数百例 + 真实 CVE。

**Q: GNN 在真实数据上到底带来多少提升?**
A: Juliet 试点上,**召回 +21 点(0.711→0.921)、F1 +12.5 点(0.750→0.875)**。提升全部来自 CWE121 栈溢出——缓冲区索引越界写、无 libc sink 名,名字/结构启发式 0 检出,GNN 恢复的 char*/数组类型把它们识别为缓冲 sink。诚实补充:1 个 `alloca+fgets` 用例使 TYGR datagen 符号执行断言失败(GNN 回退),2 个 `vprintf` 属格式串(类型 sink 不覆盖)——这些是已知的加固点。

**Q: 你们的 LLM 裁决在真实基准上有用吗?(消融结果)**
A: 诚实说——**目前这套配置下没兑现精确率价值,这是个负结果**。Juliet 消融:标准+LLM 的 F1 纹丝不动(7 个负例误报 LLM 一个没滤、27 个真阳一个没杀);GNN+type-sink 再叠 LLM 反而把精确率从 0.833 拖到 0.522。**但根因是实验局限,不是 LLM 本质无用**:批量消融为省事**只给 LLM 喂了 GNN 类型证据,没喂 angr 符号约束**——而恰恰是符号约束(sink 是否越界/有界)才能让 LLM 判别 goodB2G 那类"污点源→安全 sink"的误报。完整"神经-符号-LLM"(含符号硬证据)的验证是明确的下一步。我们把这个负结果如实列为 roadmap 第一条,而非掩盖。

**Q: 既然名字匹配就能 100%，GNN 到底有没有用？**
A: 两条实证。① **语义恢复**：`--strip-all` 全剥离后函数名丢成 `sub_xxxx`，GNN 仍恢复 char*/struct/指针(连 main 的 argc/argv 都对)。② **检出能力(完整闭环)**：构造一个手工缓冲拷贝、不调任何 libc 的自定义函数 `store_record`——纯名字/结构启发式 **P/R/F1=0/0/0**(识别 0 sink、0 路径)；开启 GNN 类型驱动后识别出 sink、连出 `argv→store_record` 路径、达 **P/R/F1=1.0**。这两点都是名字匹配根本给不出的。(脚本 `demo_fullstrip.py` / `demo_type_sink.sh`)

**Q: 真实世界二进制没有 DWARF，你的类型恢复怎么办？**
A: 诚实讲，TYGR(及我们当前集成)用 DWARF 来**定位变量**，再由 GNN 预测类型。无 DWARF 时需要先跑变量恢复(angr VariableRecovery)产生变量位置集合，再喂 GNN。当前 demo 用 `-g` 副本提供变量位置，分析二进制本身可全剥离。把变量恢复接上是明确的工程下一步，不是理论障碍——GNN 的特征来自符号执行的 glow 图，本就不依赖符号名。

**Q: LLM 会不会幻觉出漏洞？怎么保证不是它瞎编？**
A: LLM **不单独决策**,它在符号硬证据 + 污点路径分数之上裁决,并记录 CoT 便于审计。但我们实测发现一个反方向的问题:**证据不足时 LLM 偏向"判真"**(见上一条消融)——所以它更可能漏掉"该否定"的误报,而不是凭空造漏洞。改进方向是给足符号证据让它能"否定",而非依赖它的先验。

**Q: 为什么用 TYGR 而不是 Ghidra/IDA 的类型推断？**
A: Ghidra/IDA 的类型恢复是基于规则/数据流的启发式；TYGR 是在大规模真实二进制上**学习**的 GNN，对 stripped 场景的泛化是其论文卖点。我们也保留了对比/替换的接口(环境变量切换模型)。

**Q: 为什么要维护两套 conda 环境？不优雅。**
A: 因为官方模型死绑 angr/pyvex 9.0.7491 + PyG 1.7——既是 pickle 跨版本问题，也是 **VEX 边操作词表**问题(模型特征维度锁死)。在现代环境强行适配要么 pickle 崩、要么特征对不上。子进程隔离两环境是最干净、最可复现的工程选择。我们也提供了现代环境自训路线(Acc 0.887)作兜底。

**Q: 性能/可扩展性？**
A: 瓶颈在 LLM 裁决(~30–40s/路径)。可优化：仅对"模糊路径"调 LLM、批处理、或换本地模型。GNN 推理 CPU ~10 it/s，符号执行有路径优先级 + 启发式剪枝控制爆炸。

**Q: soundness / completeness？**
A: 都不保证。这是 bug-finding 系统不是 verifier。设计目标是高质量发现 + 低误报(靠符号硬证据 + 裁决)，并明确标注威胁模型。

**Q: 可复现性？**
A: 版本全部 pin(`environment.yml` + `req_rest.txt`)，一键脚本建 `tygr-orig`，官方模型在仓库 `model/` 内。文档：VERSION_COMPAT / GNN_INTEGRATION。

**Q: 这跟"把 LLM 套个壳"有什么区别？**
A: LLM 只是第 11 阶段的裁决器，且依赖前 10 阶段产生的**形式化/学习的结构化证据**(VEX、CFG/DFG、GNN 类型、符号约束)。去掉这些证据，LLM 无从判起。核心是**证据生成**，不是 prompt。

---

## 11. 演讲 takeaway（3 句话）
1. stripped 二进制漏洞分析的瓶颈是**语义缺失**；我们用 **GNN 类型恢复**在全剥离下补回类型语义(已实证)。
2. 用**符号执行硬证据 + LLM 裁决**把"可能危险"变成"可解释、可审计的判定"，抑制误报。
3. 我们诚实地知道边界：toy 规模、DWARF 定位依赖、类型尚未驱动 sink——这些都是清晰的、正在推进的下一步，而非被掩盖的弱点。

---
*配套文档：[GNN_INTEGRATION.md](GNN_INTEGRATION.md)(集成细节) · [VERSION_COMPAT.md](VERSION_COMPAT.md)(环境复刻) · [STATUS.md](STATUS.md)(项目状态) · [architecture.md](architecture.md)(架构)*
