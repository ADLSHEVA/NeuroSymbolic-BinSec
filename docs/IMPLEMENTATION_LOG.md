# 实施记录 / Implementation Log

> 本项目把 **GNN 类型恢复**真正接入污点分析流水线、并用真实基准验证的**详细实施过程、技术决策与踩坑**。
> 按主题组织(大致时间线)。配套:[GNN_INTEGRATION](GNN_INTEGRATION.md) · [VERSION_COMPAT](VERSION_COMPAT.md) · [JULIET_PILOT](JULIET_PILOT.md) · [PAPER_MATERIAL](PAPER_MATERIAL.md)。

---

## 0. 起点的真相
- 流水线 Stage6「GNN 类型恢复」原先依赖本地 `gat_model.pt`,实为**零特征空壳**,推理恒返回 0。过去 6 程序的 100/100/100 是在 **GNN 不参与**下达成的。
- 决定:用 [TYGR](https://github.com/sefcom/TYGR)(USENIX Sec'24 的 GlowGNN)真正实现类型恢复。

## 1. TYGR 在现代环境的版本适配(Path A,自训兜底)
TYGR 依赖 2021 年的 angr/torch/PyG;直接在现代 `angr-env` 跑会崩。施加于本地 `tygr_original/`(gitignore)的补丁:
- `analysis/angr/sim_exec.py`、`ast_graph.py`:`state.solver.BVV/BVS` → `cp.BVV/BVS`(新版 angr 移除 SimSolver.BVV)。修复前 datagen `Source #functions: 0`。
- `predict.py`、`test.py`:`torch.load(...)` 包 try/except(torch2 默认 `weights_only=True` 拒载整体 pickle;torch1.8 无此参数)。
- `train.py`:删 `ReduceLROnPlateau(verbose=)`;`utils/learn.py`:指标除零保护。
- `methods/glow/predict.py`:新增 `generate_glow_inputs_no_parallel`(串行,绕过多进程 Pool 的 angr RuntimeDb 崩溃)。
- `methods/glow/model.py`:`edge_dim` 硬编码 `44` → `num_edge_ops`(动态)。**根因**:旧 pyvex 边操作词表恰 44,现代 pyvex 更多 → 否则训练 `index out of bounds for size 44`。

### 1.1 自训踩坑
- 预训练模型(PyG1.7 整体 pickle)在 PyG2.7 反序列化失败(`Inspector._cls`)→ 当时放弃,转自训。
- 自建合成 C 语料(80 文件/~720 函数)。**训练卡死的真因**:默认 batch 在 4GB WSL 上 **OOM 被杀**(dmesg `Out of memory: Killed process`,RSS 3.6GB)。`0/7` 进度条 0 处理就是它。**修复:`--batch_size 1`**(内存 → ~2GB)。
- 结果:自训模型测试 Acc 0.8875(`output/tygr/model_stable.model`),仅作兜底。

## 2. 用官方模型(Path B,最终主路径)
共创伙伴提醒:官方模型已开源在仓库 `model/`,不必自训。但官方模型**死绑** torch1.8/PyG1.7/angr-pyvex **9.0.7491**(既因 pickle 跨版本,也因特征词表 edge_dim=44 锁死)。
- **解法**:复刻独立 conda 环境 **`tygr-orig`**;OPM 主流程在 angr-env,经**子进程**调用。脚本 `output/tygr/build_orig_env.sh` + `req_rest.txt`。
- **依赖踩坑**(按出现顺序):
  1. `capstone` 太新 → `module 'capstone' has no attribute 'CS_ARCH_ARM64'`(5.x 改名)→ 降 **4.0.2**。
  2. `protobuf` 太新 → 降 **3.20.3**。
  3. 缺 `sympy`/`z3`/`pysmt` 等 → `req_rest.txt` 一次锁全(含 numpy1.22/networkx2.5.1/numba0.53.1/pandas1.2.4 等老版)。
  4. CUDA 10.2 跑不了 40 系显卡 → 用 CPU 版 pytorch(推理 ~10 it/s 足够)。
- **验证**:官方 `x64.O0.base.model` 加载成功(GlowGNN);predict 产出 **char*/f32*/array/struct** 等精确类型(远超自训的 int/char*/array)。

## 3. 接入 OPM
- `src/type_recovery/inference.py::_recover_with_gnn`:子进程调 tygr-orig python 跑官方模型 predict → `_btype_to_str`(指针→char*/pointer,数组→array)→ 组装 `TypeRecoveryOutput`。env 变量 `TYGR_MODEL`/`TYGR_PYTHON` 可覆盖;失败回退自训→启发式。
- **二进制路径坑**:子进程 `cwd=tygr_original`,binary 必须转**绝对路径**(否则相对路径解析失败,rc=1 回退)。
- `src/pipeline.py`:Stage1 保留未 strip 的 `-g` 二进制 `state.binary_debug`;Stage6 用它喂 GNN(TYGR 靠 DWARF 定位变量、GNN 预测类型)。
- `src/typed_ir/type_injector.py`:原 `_extract_variables_from_block` 是空桩(一直 0 typed)。改为**直接折叠** GNN 预测进 `variable_types`/buffer/pointer map(86 typed variables)。
- **PIE 基址对齐**:GNN 用 DWARF `low_pc`(0x1149),angr 用 PIE 重定位地址(0x401149+)。从 `cfg.angr_cfg.project.loader.main_object.mapped_base` 取基址,按 绝对址+(址−基址) 双键映射 → 类型精确归到真实 CFG 函数(`vuln_use_after_free→pointer/struct/char*`)。验证 `output/tygr/verify_base_align.py`。

## 4. 验证 GNN 的不可替代价值
- **全剥离实证**(`output/tygr/demo_fullstrip.py`):`strip --strip-all` 后函数名丢成 `sub_xxxx`,GNN 仍恢复 char*/struct/指针(连 main 的 argc/argv 都对)。
- **类型驱动 sink 识别**(`OPM_TYPE_SINKS=1` 门控,默认关→6 程序零回归):
  - `taint_engine_v2.py::_find_sinks_by_types`:把"无名+GNN标char*缓冲(≥2)+在调用图中"的自定义函数补成 sink、分类 buffer_overflow,并为其 main 可达调用者补 argv 源 → 连出污点路径。
  - GT 注解:`ground_truth/extractor.py::extract_annotations` 在剥注释前解析 `// @vuln: <type> <source> -> <sink>`。
  - 实证 `output/tygr/demo_custom_sink.c`(手工 while 拷贝、不调 libc 的 store_record):关 → **0/0/0**;开 → `argv→store_record`,**P/R/F1=1.0**。

## 5. 真实基准试点:NIST Juliet
- 38 例(CWE121/122/134/78),good/bad + `OMITGOOD/OMITBAD` 宏编译正/负例作 GT。harness `benchmarks/juliet/juliet_harness.py`。
- **工程坑**:① WSL 内联 `bash -c` 的循环/变量会被吞 → 全用脚本文件/Python;② `pkill -f "git clone.*juliet"` 匹配到自身命令行 → 自杀;③ 克隆到 `/mnt/d`(DrvFs)写 5万小文件极慢 → 克隆到 WSL 原生 fs `~/juliet_repo`;④ 被杀的半截克隆残留 **544MB**,差点误传库。
- **结果**:阶段1 标准 P=0.794 R=0.711 F1=0.750;**阶段2 +GNN 类型驱动 P=0.833 R=0.921 F1=0.875**。GNN 救回 8 个名字匹配漏掉的 CWE121 栈溢出。
- **诚实局限**:1 例 alloca+fgets 使 TYGR datagen `bityr_annots` 断言(非 BV 位置)崩溃;2 例 vprintf 格式串(类型 sink 不覆盖);负例 goodB2G 有 7 误报。

## 5.1 GNN × LLM 消融(负结果 + 实验局限)
- **端点踩坑**:小米 MiMo 端点 **451 跨境隔离**("Allow Cross-border Access" 未开)→ 改用 FreeModel(`gpt-5.4-mini`,OpenAI 兼容,`/v1/models` 可列模型)。
- **harness**:`juliet_harness_llm.py`(对称开 type-sink)/ `juliet_harness_llm_clean.py`(标准检测)。复用 OPM 的 `analyze_taint_path_cot`,把 GNN 类型作证据逐路径裁决,"检出"=任一路径经裁决仍为真(阈值 0.3,首个存活即退出)。
- **四组结果**:标准 F1=0.750 → 标准+LLM 0.750(LLM **no-op**:7 误报一个没滤、27 真阳一个没杀)→ +GNN type-sink 0.875 → +GNN+LLM **0.667**(对称 type-sink 给 good 造误报,LLM 没滤掉 → P 崩 0.522)。
- **关键局限(诚实)**:批量为省事**只给 LLM 喂 GNN 类型,未喂完整流水线的 angr 符号约束**(`_build_symbolic_evidence` 第4块,需 Stage8)。所以证明的是"LLM+仅类型=无用",非"LLM 无用"。这是 roadmap 第一条(JULIET_PILOT §7)。

## 6. 跨切关键经验
- **mimo-v2.5-pro 是推理模型**:隐藏 reasoning token 计入 `max_tokens`,设 1024 时可见 JSON 被截断为空 → 裁决静默失效(每路径默认 0.5/全接受)。修:`max_tokens≥4096` + 容错解析。
- **WSL 内存**:16GB 机器(Windows 占 14GB)→ WSL 上限 6GB + swap 8GB(磁盘兜底防 OOM,不抢 RAM)。
- **WSL `/tmp` 空闲关机清空**(tmpfs)→ 中间文件写持久路径 `output/`。
- **两套 conda 环境共存**:angr-env(现代,OPM 主流程)+ tygr-orig(复刻,官方 GNN),子进程桥接,互不污染。
