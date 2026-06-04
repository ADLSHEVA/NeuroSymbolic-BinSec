# GNN 类型恢复接入说明（给共创伙伴）

> 本文记录本轮把 **GNN 类型恢复**真正接入 OPM 流水线的全部改动、原理、复现步骤与已知限制。
> 一句话：GNN（基于 TYGR 的 GlowGNN）此前是**空壳**（Stage 6 恒输出 0 个类型），现在用 **TYGR 官方预训练模型**真正跑通，全流水线 P/R/F1 = 1.0。

---

## 1. 背景：为什么之前 GNN 没工作

- OPM 的 Stage 6「GNN 类型恢复」原先依赖一个本地 `gat_model.pt`，但它是**零特征空壳**，推理恒返回 0 个类型。过去的 100/100/100 是在 **GNN 不参与**的情况下、靠污点引擎自身启发式达成的。
- 我们参考的 [TYGR](https://github.com/sefcom/TYGR)（USENIX Security ’24，stripped 二进制上的 GNN 类型推断）**开源了预训练模型**（仓库 `model/` 目录），按架构/优化级分：`x64.O0.base.model` 等。
- TYGR 的训练数据集 **TYDA** 也开源（README 里是官方 **Dropbox** 链接），但**100+GB 不现实**下载，所以我们直接用官方预训练模型。

## 2. 核心难点：官方模型死绑原始环境

官方模型是用 TYGR 原始环境训练并 pickle 的，**版本死绑**（见 `tygr_original/environment.yml`）：

| 组件 | 官方模型要求 | OPM 的 angr-env |
|------|------|------|
| python | 3.8.10 | 3.11 |
| pytorch | 1.8.1 | 2.x |
| torch-geometric | 1.7.0 | 2.7 |
| **angr / pyvex** | **9.0.7491** | 最新 |

两层不兼容：
1. **pickle 加载崩**：PyG 1.7 → 2.7 的内部类变了（`Inspector._cls`），`torch.load` 直接失败。
2. **特征词表对不上**：模型的图特征是 **angr/pyvex 9.0.7491** 提取的（边操作词表恰好 44 维）；用新版 angr 做 datagen，特征维度对不上（`index out of bounds for size 44`）。

**结论**：要用官方模型，必须**忠实复刻 TYGR 原始环境**，而不是在新环境里强行适配。

## 3. 解决方案：独立的 `tygr-orig` conda 环境

新建一个版本忠实的 conda 环境 **`tygr-orig`**，专门用来跑官方模型的 predict。OPM 主流程仍在 `angr-env`，通过**子进程**调用 `tygr-orig` 的 python——两环境共存、互不污染。

### 复现步骤
```bash
# 一键构建（脚本已写好）
bash output/tygr/build_orig_env.sh
# 脚本内容等价于：
conda create -y -n tygr-orig python=3.8.10
conda run -n tygr-orig pip install torch==1.8.1+cpu torchvision==0.9.1+cpu torchaudio==0.8.1 \
    -f https://download.pytorch.org/whl/torch_stable.html
conda run -n tygr-orig pip install torch-scatter==2.0.6 torch-sparse==0.6.9 \
    -f https://data.pyg.org/whl/torch-1.8.1+cpu.html
conda run -n tygr-orig pip install torch-geometric==1.7.0
conda run -n tygr-orig pip install angr==9.0.7491 archinfo==9.0.7491 claripy==9.0.7491 cle==9.0.7491 pyvex==9.0.7491
conda run -n tygr-orig pip install -r output/tygr/req_rest.txt   # 其余精确版本依赖
```
### 踩过的坑（已在脚本/依赖里固定）
- `capstone` 必须降到 **4.0.2**（新版 5.x 删了 `CS_ARCH_ARM64`，angr 9.0.7491 会崩）。
- `protobuf` 必须降到 **3.20.3**（angr 依赖，新版不兼容）。
- `numpy/networkx/numba/pandas` 等都被 `req_rest.txt` 锁回原始版本（glow 代码依赖老 API）。
- 用 **CPU 版** pytorch：`environment.yml` 里的 cudatoolkit 10.2 跑不了 40 系显卡，而**推理用 CPU 足够快**（~10 it/s）。

### 验证环境可用
```bash
cd tygr_original
# 1) 官方模型能加载？
conda run -n tygr-orig python -c "import torch; m=torch.load('model/MODEL_base/x64.O0.base.model', map_location='cpu'); print(type(m).__name__)"
# → GlowGNN
# 2) 对二进制能出类型？（二进制需带 DWARF，即 gcc -g 编译、未 strip）
conda run -n tygr-orig python -m src.index predict -v model/MODEL_base/x64.O0.base.model <带-g的二进制> /tmp/out.pkl
# → 打印 char* / f32* / array<void> 等逐变量类型
```

## 4. OPM 侧的接入改动

| 文件 | 改动 |
|------|------|
| `src/type_recovery/inference.py` | 新增 `_recover_with_gnn()`：**子进程**调 `tygr-orig` python 跑官方模型 predict → 读 var_dict → `_btype_to_str()` 把 TYGR 的 btype 元组转成 `char*/pointer/array/int32...` → 组装 `TypeRecoveryOutput`。`recover_types()` 现在**优先**走 GNN，失败才回退启发式。模型/解释器路径可用环境变量 `TYGR_MODEL` / `TYGR_PYTHON` 覆盖。 |
| `src/pipeline.py` | `OPMState` 新增 `binary_debug` 字段；Stage 1 在 strip 之前保存未 strip 的 **-g 二进制**；Stage 6 用 `binary_debug` 喂 GNN（**TYGR 靠 DWARF 定位变量、GNN 预测类型**，所以需要带调试信息的二进制）。|
| `src/typed_ir/type_injector.py` | 原 `_extract_variables_from_block` 是空桩（所以一直 0 typed）。现把 GNN 预测**直接折叠**进 `variable_types`（及 buffer/pointer map）。 |
| `tygr_original/src/predict.py`, `test.py` | `torch.load(..., weights_only=False)` 改 try/except（老 torch 1.8 无此参数）。 |

### 数据流
```
源码.c
 └─Stage1─ gcc -g 编译 → 保留 -g 二进制(binary_debug) + strip 副本(用于CFG/污点)
 └─Stage6─ recover_types(binary_debug)
            └─ 子进程: tygr-orig python  src.index predict  官方x64.O0模型  binary_debug
                 └─ TYGR datagen(DWARF定位变量 + angr9.0.7491提特征) → GlowGNN → 逐变量类型
            └─ var_dict → TypeRecoveryOutput{char*/array/int...}
 └─Stage7─ 折叠进 TypedIR.variable_types (86 个 typed variables)
 └─Stage10+ 污点分析/符号证据/评估
```

## 5. 当前效果（memory_vuln.c 全流水线）
```
Stage 6  GNN 类型恢复 → 30 函数 (char*/array)
Stage 7  类型注入     → 86 typed variables   (改之前: 0)
Stage 10 污点         → 4 sources / 11 sinks / 29 paths + UAF/double-free
Stage 12 评估         → P=1.0  R=1.0  F1=1.0
```

## 5b. GNN 不可替代价值的实证（全剥离场景）

把 `memory_vuln` 用 `strip --strip-all` **全剥离**（抹掉 `.symtab`，本地函数名全没），再做 GNN 类型恢复（脚本 `output/tygr/demo_fullstrip.py`）：

| 全剥离后 CFG 函数名 | （对照）真实名 | GNN 恢复的类型语义 |
|---|---|---|
| `sub_4011e9` | vuln_use_after_free | pointer, **struct**, **char\*** |
| `sub_401260` | vuln_double_free | pointer, struct, char* |
| `sub_401354` | safe_memory | **char\*, char\*, char\*** |
| `main` | main | **int32, char\*, char\***（argc/argv 签名） |

**结论**：全剥离后函数名彻底丢失，纯「名字匹配 + 结构启发式」只能看到无意义的 `sub_xxxx`；而 GNN 准确标出每个无名函数「处理 char\* 缓冲 / 指针 / 结构体」。**在全剥离二进制上，GNN 是类型/缓冲语义的唯一来源**——这就是它区别于源码级/符号级启发式的核心价值。

## 6. 已知限制 / 下一步（留给我们继续做）
1. **PIE 基址对齐（✅ 已解决）**：GNN 用 DWARF `low_pc`（如 `0x1149`）、angr 用 PIE 重定位地址（`0x401149+`）。现在 `_recover_with_gnn` 从 `cfg.angr_cfg.project.loader.main_object.mapped_base` 取基址，按 **绝对地址 + (地址−基址)偏移** 双键映射，GNN 类型已能精确归到真实 CFG 函数名（`vuln_use_after_free → pointer/char*/struct`、`safe_memory → char*` 等）。验证脚本 `output/tygr/verify_base_align.py`。
2. **类型驱动的 sink 识别（✅ 已实现，端到端实证）**：`analyze()` 现接收 `type_recovery_output`；新增 `_find_sinks_by_types`（环境变量 `OPM_TYPE_SINKS=1` **门控，默认关**，故标准 6 程序行为不变、无回归）。逻辑：把**名字被剥离、参数被 GNN 标为 char*/buffer(≥2 个)、出现在调用图中**的自定义函数补成候选 sink，并为其(可从 main 到达的)调用者补 argv 源 → 形成污点路径。
   - **演示**（`output/tygr/demo_custom_sink.c` + `demo_type_sink.sh`）：一个做手工 `while` 缓冲拷贝、**不调用任何 libc** 的 `store_record(char* dst, char* src)`：

     | | 关(名字/结构启发式) | 开(`OPM_TYPE_SINKS=1`) |
     |---|---|---|
     | sink 识别 | **0**（漏） | 候选（含 store_record） |
     | 污点路径 | **0** | **`argv -> store_record` (1)** |
     | **P/R/F1** | **0 / 0 / 0** | **1.0 / 1.0 / 1.0** |

     → 证明 GNN 类型能补「名字匹配 + 结构启发式都漏」的检出，**且形成完整评估闭环**。
   - **闭环已完成**：① 类型 sink 标为 `buffer_overflow`（`type_buffer_sinks` → `_get_vulnerability_type`）；② GT 提取器支持**显式注解** `// @vuln: <type> <source> -> <sink>`（`extract_annotations`，在剥注释前解析），让自定义 sink 有期望路径；③ 评估按 `(source,sink)` 匹配 → custom_sink 在 `OPM_TYPE_SINKS=1` 下 **P/R/F1=1.0**，与标准 6 程序一致；标准 6 程序（flag 默认关）**零回归**。
   - 注：`vulnerable_detected` 次要计数为 0，但这是**所有程序**一致的(依赖 Stage 11 LLM 标 `is_vulnerable`)，非 custom_sink 特有；主指标 P/R/F1 已闭环。
3. **诚实定位**：6 个测试样例的 100/100/100 主要靠污点引擎启发式，**GNN 不是这些 `--strip-debug`(函数名保留)样例检出的必要条件**。GNN 的真正价值在**全剥离 + 自定义缓冲函数**的场景——见上一条。
4. 备用自训路线：我们也跑通了「自建合成语料 → 训练 GlowGNN」（`output/tygr/`，测试 Acc 0.887），官方模型质量更高，自训模型仅作兜底（`output/tygr/model_stable.model`）。

## 7. 快速上手
```bash
# 跑单个程序（GNN 自动生效，需先建好 tygr-orig 环境）
python scripts/run_pipeline.py tests/test_programs/memory_vuln.c -o output/gnn_demo
# 看 Stage 6/7 日志里的 "GNN type recovery: N functions" 和 "N typed variables" 即说明 GNN 在工作
```
环境变量（可选）：
- `TYGR_MODEL` —— 换其他架构/优化级模型（如 `.../x64.O2.base.model`）
- `TYGR_PYTHON` —— tygr-orig 环境的 python 路径（默认 `/root/miniconda3/envs/tygr-orig/bin/python`）

---
*相关文档：版本适配细节见 [VERSION_COMPAT.md](VERSION_COMPAT.md)；恢复/进度见 `output/tygr/RESUME.md`。*
