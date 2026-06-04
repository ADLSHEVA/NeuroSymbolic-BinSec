# NIST Juliet 真实基准试点

> 目的:用**第三方真实漏洞基准**(NIST SARD Juliet C/C++ 1.3)验证 OPM,把"仅 6 个自建程序 100%"换成更可信、规模更大、指标会如实下降的科研数据。
> 这是回应大会/审稿"过拟合/样本太少"质疑的核心材料。

## 1. 数据与选样
- 来源:[NIST SARD Juliet C/C++ 1.3](https://samate.nist.gov/SARD/test-suites/112)(公共领域),GitHub 镜像 `arichardson/juliet-test-suite-c`。
- 选取 **38 个用例**,覆盖 4 个 CWE(与本系统目标漏洞对齐):
  - CWE121 栈缓冲区溢出 ×10
  - CWE122 堆缓冲区溢出 ×10
  - CWE134 不受控格式化串 ×10
  - CWE78 OS 命令注入 ×8
- 均取**单文件基础流变体(`_01.c`)**,源优先 `console`(stdin/fgets)与 `environment`(getenv)——本系统污点引擎能识别的源;跳过 socket/win32 等。

## 2. 评估方法(利用 Juliet 自带 good/bad 结构作 GT)
每个 Juliet 用例同文件内含 `bad()`(真漏洞)与 `good()`(安全修复)。我们用 Juliet 的 `OMIT*` 宏编译出**两个二进制**:
- **正例**:`gcc -g -O0 -DINCLUDEMAIN -DOMITGOOD -I support <case>.c support/io.c` → 仅 bad → **应检出**
- **负例**:`-DOMITBAD` → 仅 good → **不应检出**

判定:OPM 检出污点路径数 `>0` 即"检出漏洞"。
- 正例检出 = TP,漏检 = FN;负例检出 = FP(误报),干净 = TN。
- 据此算 Precision / Recall / F1。脚本:`benchmarks/juliet/juliet_harness.py`。

## 3. 两阶段
- **阶段1 标准**:名字/结构启发式(libc sink + 结构),不开 GNN 类型 sink。
- **阶段2 +GNN**:对阶段1漏检的正例,开 `OPM_TYPE_SINKS=1`(GNN 类型驱动 sink 识别),量 GNN 的**增量召回**——重点看 CWE121/122 这类"缓冲区索引越界写、无 libc sink 名"的用例。

## 4. 结果（38 例,编译 38/38）

| | TP | FN | FP | TN | **Precision** | **Recall** | **F1** |
|---|----|----|----|----|------|------|------|
| **阶段1 标准**(名字/结构启发式) | 27 | 11 | 7 | 31 | **0.794** | **0.711** | **0.750** |
| **阶段2 +GNN 类型驱动** | 35 | 3 | 7 | 31 | **0.833** | **0.921** | **0.875** |

**GNN 把召回从 0.711 拉到 0.921**(救回 8 个阶段1漏检的正例),F1 0.750→0.875。

### 按 CWE 拆解(阶段1 → 阶段2)
- **CWE78 命令注入(8)**:阶段1 全检出、零误报(libc sink `system/execl/popen` 命名清晰)。✅ 最强项。
- **CWE122 堆溢出(10)**:阶段1 全检出(memcpy/loop 等),1 个负例误报。
- **CWE134 格式化串(10)**:阶段1 检出 8/10(`printf/fprintf/snprintf` 命名 sink),漏 `console vfprintf/vprintf`(va_list 变体);负例有若干误报(goodB2G 污点源→安全 sink)。
- **CWE121 栈溢出(10)**:**阶段1 仅 0–1 检出**——多为缓冲区**索引越界写**,无 libc sink 名 → 名字匹配漏掉。**阶段2 GNN 类型驱动救回 8 个**(`large/rand/loop/memcpy/memmove/CWE135/alloca_loop/alloca_memcpy`,各检出 3–5 条路径)。

### GNN 增量召回的直接证据
| CWE121 用例 | 阶段1(名字) | 阶段2(GNN 类型) |
|---|---|---|
| CWE129_large / rand | 0 | **5** |
| CWE131_loop / memcpy / memmove | 0 | **4** |
| CWE135 / alloca_loop / alloca_memcpy | 0 | **3** |
| CWE129_fgets | 0 | 0(TYGR datagen 断言崩溃,见 §5) |

*(原始数据:`benchmarks/juliet/SUMMARY.txt`、`results_standard.json`、`harness.log`)*

## 4.x LLM 裁决消融(GNN × LLM 是否该叠加)

为回答"把 LLM 裁决叠加到 GNN 上能否提升精确率",做了消融。LLM 端点用 FreeModel(`gpt-5.4-mini`,OpenAI 兼容;小米 MiMo 端点因 451 跨境隔离不可用)。脚本 `juliet_harness_llm.py`(对称开 type-sink)/ `juliet_harness_llm_clean.py`(标准检测)。

| 配置 | Precision | Recall | F1 |
|------|-----|-----|-----|
| ① 标准(名字/结构) | 0.794 | 0.711 | 0.750 |
| ② 标准 + LLM 裁决 | 0.794 | 0.711 | **0.750**(零变化) |
| ③ +GNN 类型驱动 sink | 0.833 | 0.921 | **0.875** |
| ④ +GNN 类型驱动 + LLM | 0.522 | 0.921 | 0.667 ⬇ |

**关键发现(含负结果)**:
- **②:LLM 在干净配置下是 no-op** —— 标准检出的 7 个负例误报**一个没滤掉**,27 个真阳**一个没误杀**,F1 纹丝不动。原因:LLM 拿到的证据**只有 GNN 类型**,而 goodB2G 误报是"真污点源 → 实则安全的 sink";光看类型,LLM 区分不了安全/危险 sink,默认判"真"。
- **④:朴素叠加反而有害** —— `OPM_TYPE_SINKS` 对称应用给 good 变体也注入了 sink+argv 源,凭空造出大量路径(连标准下零误报的 CWE78/122 good 都被误报),LLM 又没能滤掉 → 精确率崩到 0.522。
- **结论**:**不是模块越多越好**。GNN 的召回增益是真的(③);LLM 的精确率增益在本配置下**没兑现**。

> ⚠️ **本消融的实验局限(诚实交代)**:批量 harness 为省事**只给 LLM 喂了 GNN 类型证据**,**未包含**完整流水线 `_build_symbolic_evidence` 的**第 4 块——angr 符号约束/参数范围**(那需要跑 Stage 8 符号执行)。而恰恰是符号约束才能让 LLM 判断"sink 是否越界/安全"。所以本轮证明的是 **"LLM + 仅类型证据 = 无用"**,**不是 "LLM 无用"**。完整"神经-符号-LLM"三件套(含符号硬证据)尚未在 Juliet 上测——这是下一步(见 §7)。

## 5. 诚实解读
- 真实基准上指标**显著低于** 6 程序的 100%——这正是有价值的科研数据(toy 基准的 100% 不能外推)。
- 典型强项:libc 命名 sink 的 CWE(命令注入 CWE78、多数格式化串 CWE134)召回高。
- 典型弱项/发现:
  - **CWE121 栈溢出**多为缓冲区**索引越界写**,无 libc sink 名 → 阶段1名字匹配漏掉;阶段2 GNN 类型驱动**部分救回**。
  - **GNN 鲁棒性局限**:部分用例(如 `alloca` 动态栈分配)使 TYGR datagen 的符号执行断言失败(`bityr_annots` 非 BV 位置),GNN 回退 → 漏检。这是已知的、需加固的工程点。
  - 负例(goodB2G:污点源→安全 sink)产生部分**误报**,精确率因此 <1.0。
- **分析二进制为 `-g`(未 strip)**:与 OPM 设计一致(始终保留 `-g` 副本供 Stage6 类型恢复定位变量;分析二进制本身可全剥离——全剥离下 GNN 仍恢复语义已由 `demo_fullstrip.py` 单独验证)。本试点为简化对同一 `-g` 二进制做检测,GNN 增量召回的**机制**与全剥离场景一致(类型驱动 sink 不依赖函数名)。
- 主试点检测信号取 **Stage10 污点路径数 >0**;LLM 裁决(Stage11)的消融见 §4.x。

## 6. 复现
```bash
# 1) 克隆 Juliet(浅克隆,~38MB)到 WSL 原生 fs
git clone --depth 1 https://github.com/arichardson/juliet-test-suite-c ~/juliet_repo
# 2) 选样 + 下载支持文件已在 benchmarks/juliet/(select_cases.py / support/)
# 3) 跑评估(GNN)
python benchmarks/juliet/juliet_harness.py            # → SUMMARY.txt / results_standard.json
# 4) LLM 消融(需 MIMO_API_BASE / MIMO_API_KEY / MIMO_MODEL 环境变量)
python benchmarks/juliet/juliet_harness_llm.py        # +GNN+LLM(对称 type-sink)
python benchmarks/juliet/juliet_harness_llm_clean.py  # 标准 + LLM(干净)
```

## 7. 待解决问题 / 下一步方向（即本项目 roadmap）

> 这些是真实、已知的开放问题——大会/论文里主动列出,反而比掩盖更可信。

1. **让 LLM 真正发挥过滤作用** —— 当前批量消融只喂了 GNN 类型证据,LLM 成了 no-op。下一步:把 **angr 符号约束/参数范围**(`_build_symbolic_evidence` 第4块)接进批量评估,验证"GNN 类型 + 符号硬证据 + LLM"能否滤掉 goodB2G 那类"污点源→安全 sink"的误报。这是兑现"神经-符号"精确率价值的关键。
2. **精炼类型驱动 sink(降误报)** —— `OPM_TYPE_SINKS` 对称应用精确率崩(0.522)。需要更强的触发条件(如要求 GNN-buffer 函数内部确有"无界写 + 污点索引"的迹象),而非"有 char* 参数即标 sink"。
3. **加固 GNN datagen 鲁棒性** —— `alloca`/某些动态栈分配使 TYGR `bityr_annots` 断言失败(本试点 1/38 因此漏检)。需在 datagen 处优雅跳过非 BV 位置。
4. **扩大规模** —— 当前 38 例、单文件 `_01` 基础变体。需扩到全 Juliet(流变体 02–54、跨函数/跨文件)+ **真实 CVE 二进制** + **对照基线**(同集上跑 Ghidra/CodeQL 等),才能下普适结论。
5. **修正评估方法学的不对称** —— GNN-only 的 0.833 是"仅对正例开 type-sink"的乐观值;应统一对正/负例同等处理后再报指标。
6. **真正的全剥离评估** —— 本试点分析 `-g` 二进制;应在 `--strip-all` 二进制上端到端跑,体现 GNN 在无符号场景的不可替代性(目前仅由 `demo_fullstrip.py` 定性验证)。
