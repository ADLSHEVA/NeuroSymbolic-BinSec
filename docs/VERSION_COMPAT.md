# 版本兼容与环境复刻说明 (TYGR ↔ OPM)

> GNN 类型恢复基于 [TYGR (sefcom/TYGR)](https://github.com/sefcom/TYGR)（USENIX Security '24，
> stripped 二进制上的 GNN 类型推断）。TYGR 依赖一套 **2021 年的** angr / PyTorch / PyTorch-Geometric。
> 本文件记录**版本差异**、两条路径的**最终选型**、以及**环境复刻的完整踩坑清单**，供共创者与复现者参考。
>
> **TL;DR**：我们最终走 **Path B — 复刻 TYGR 原始环境(`tygr-orig`)直接用官方预训练模型**，
> 同时保留 **Path A — 适配后的现代环境自训** 作为兜底。两条路径均已跑通。

---

## 1. 版本对照

| 组件 | TYGR 原版 (`tygr_original/environment.yml`, 2021) | OPM angr-env (现代主环境) |
|------|---------------------------------------------------|------------------------|
| Python | 3.8.10 | 3.10 / 3.11 |
| angr / pyvex / claripy / cle / archinfo | **9.0.7491** | 9.2.212（最新） |
| **PyTorch** | **1.8.1** (cuda 10.2) | **2.x (cpu)** |
| **torch-geometric** | **1.7.0** | **2.7.0** |
| torch-scatter / torch-sparse | 2.0.6 / 0.6.9 | （随 PyG 2.7） |
| capstone | 4.0.2 | 5.x/6.x |
| protobuf | 3.17.x | 4.x+ |

**两处根本性差距**：
1. **PyG `1.7 → 2.7`**：跨多个大版本，内部类布局完全改变 → 官方模型（整体 pickle）无法跨版本反序列化。
2. **angr/pyvex `9.0.7491 → 9.2.x`**：VEX 操作词表变了 → 现代 datagen 提取的图边特征维度与官方模型训练时（边词表 44 维）对不上（`index out of bounds for size 44`）。

> 结论：**官方模型死绑 angr/pyvex 9.0.7491 + PyG 1.7**——既因 pickle，也因特征词表。要用它，必须忠实复刻整套环境。

---

## 2. Path B（最终主路径）：复刻 `tygr-orig` 环境，直接用官方模型

官方预训练模型在仓库 `tygr_original/model/MODEL_base/`（按架构/优化级：`x64.O0.base.model`、`x64.O1...`、`aarch64.*`、`arm32.*`、`mips.*`、`x86.*`）。
我们新建独立 conda 环境 **`tygr-orig`** 专跑官方模型的 predict；OPM 主流程仍在 `angr-env`，**通过子进程**调用 `tygr-orig` 的 python。两环境共存、互不污染。

### 2.1 一键复刻
脚本：`output/tygr/build_orig_env.sh`（+ `output/tygr/req_rest.txt`）。等价命令：
```bash
conda create -y -n tygr-orig python=3.8.10
# pytorch 1.8.1 CPU(cuda 10.2 跑不了 40 系显卡，推理 CPU 足够)
conda run -n tygr-orig pip install torch==1.8.1+cpu torchvision==0.9.1+cpu torchaudio==0.8.1 \
    -f https://download.pytorch.org/whl/torch_stable.html
# PyG 1.7.0 栈(必须匹配 torch-1.8.1+cpu 的预编译 wheel)
conda run -n tygr-orig pip install torch-scatter==2.0.6 torch-sparse==0.6.9 \
    -f https://data.pyg.org/whl/torch-1.8.1+cpu.html
conda run -n tygr-orig pip install torch-geometric==1.7.0
# angr 全家桶 9.0.7491(官方模型特征所依赖的精确版本)
conda run -n tygr-orig pip install angr==9.0.7491 archinfo==9.0.7491 claripy==9.0.7491 \
    cle==9.0.7491 pyvex==9.0.7491
# 其余精确版本依赖(glow 代码依赖老 API)
conda run -n tygr-orig pip install -r output/tygr/req_rest.txt
```

### 2.2 踩坑清单（已在脚本/`req_rest.txt` 里固定）

| 坑 | 症状 | 解决 |
|----|------|------|
| **capstone 太新** | `module 'capstone' has no attribute 'CS_ARCH_ARM64'`（5.x 改名 `CS_ARCH_AARCH64`，angr 9.0.7491 仍用旧名）；加载模型时即触发（pickle 链导入 angr） | 降到 **`capstone==4.0.2`** |
| **protobuf 太新** | 提示 "Downgrade the protobuf package to 3.20.x or lower"（angr 依赖的生成代码不兼容 4.x） | 降到 **`protobuf==3.20.3`** |
| **缺 sympy 等** | 加载模型触发 `import src.methods.glow` → `ModuleNotFoundError: sympy`/`z3`/`pysmt`… | `req_rest.txt` 一次性装齐（含 sympy/z3-solver/pysmt/networkx 2.5.1/numba 0.53.1/pandas 1.2.4 等老版本） |
| **torch.load weights_only** | `tygr_original/src/{predict,test}.py` 用了 `weights_only=False`（torch 2 参数），torch 1.8 无此参数 → `TypeError` | 已改 `try/except`（两环境通用） |
| **CUDA 10.2 无用** | `environment.yml` 钉 cudatoolkit 10.2，跑不了 40 系显卡 | 用 **CPU 版** pytorch；推理 ~10 it/s 足够 |

### 2.3 验证环境可用
```bash
cd tygr_original
# 1) 官方模型能加载？
conda run -n tygr-orig python -c "import torch; print(type(torch.load('model/MODEL_base/x64.O0.base.model', map_location='cpu')).__name__)"
# → GlowGNN
# 2) 对带 DWARF 的二进制能出类型？
conda run -n tygr-orig python -m src.index predict -v model/MODEL_base/x64.O0.base.model <带-g二进制> /tmp/out.pkl
# → char* / f32* / array<void> / struct 等逐变量类型
```

---

## 3. Path A（兜底）：现代环境自训

为应对"官方模型万一不可用"，我们也让 TYGR 的 **datagen / train / predict 在现代 angr-env 跑通**并自训了一个模型。

### 3.1 现代环境适配补丁（施于 `tygr_original/`，已 `.gitignore`）
| 文件 | 改动 | 原因 |
|------|------|------|
| `src/analysis/angr/sim_exec.py`, `ast_graph.py` | `state.solver.BVV/BVS` → `cp.BVV/BVS`（claripy） | 新版 angr 移除 `SimSolver.BVV`；老环境 claripy 也有 `BVV`，**两环境通用** |
| `src/predict.py`, `src/test.py` | `torch.load(...)` 包 try/except（weights_only） | torch 2 默认 `weights_only=True` 拒载整体 pickle；torch 1.8 无此参数 |
| `src/train.py` | 删 `ReduceLROnPlateau(verbose=)` | torch 2.x 移除该参数 |
| `src/utils/learn.py` | precision/recall/accuracy 除零保护 | 小数据集出现 0 分母 |
| `src/methods/glow/predict.py` | 新增 `generate_glow_inputs_no_parallel`（串行） | 多进程 Pool 的 angr RuntimeDb 在现代环境崩 |
| `src/methods/glow/model.py` | `edge_dim` 由硬编码 `44` 改 `num_edge_ops`（动态） | 现代 pyvex 边操作 >44 → 否则训练 `index out of bounds`。**只影响新建模型，不影响加载官方模型** |

### 3.2 自训流程与结果
- 自建合成 C 语料（80 文件 / ~720 函数 / 类型多样）→ `output/tygr/ctr|cva|cte.pkl`。
- 训练**关键**：`--batch_size 1`（默认 batch 在 4GB WSL 上 **OOM 被杀**，dmesg 确认；batch_size=1 内存 ~2GB）。
- 结果：测试集 **Accuracy 0.8875 / F1 0.8875**；模型 `output/tygr/model_stable.model`。
- 质量**不如官方模型**（官方在真实 TYDA 上训练，能出 char*/f32*/struct；自训合成语料只到 int/char*/array），故仅作兜底。

### 3.3 为什么不直接下 TYDA 重训到高质量
TYDA（TYGR 官方数据集，README 内 **Dropbox** 链接）是真实 Gentoo C/C++ 二进制，**100+GB（`tar.lz4`）不现实**。故现代环境自训只能用自建小语料，质量受限。官方模型已解决质量问题，无需大规模重训。

---

## 4. 复现命令速查（现代 angr-env，Path A）
```bash
cd tygr_original
gcc -gdwarf-4 -O0 -w X.c -o X                                  # 需 DWARF
python -m src.index datagen X X.pkl                            # 串行可用
python -m src.index datasplit D.pkl --train tr --validation va --test te
python -m src.index train tr va -o m.model --epoch 60 --batch_size 1   # batch_size 1 防 OOM
python -m src.index test m.model.best.model te                # batch_size 1
```
> ⚠️ WSL `/tmp` 在 VM 空闲关机后会被清空（tmpfs）。中间文件写持久路径（`output/tygr/`）。

---

## 5. 在 OPM 中如何选用
`src/type_recovery/inference.py` 默认走 **官方模型 + tygr-orig**（`_recover_with_gnn`，子进程）。可用环境变量覆盖：
- `TYGR_MODEL`：换模型（如 `.../x64.O2.base.model` 或自训 `output/tygr/model_stable.model`）。
- `TYGR_PYTHON`：tygr-orig 的 python（默认 `/root/miniconda3/envs/tygr-orig/bin/python`）。

集成细节与数据流见 [GNN_INTEGRATION.md](GNN_INTEGRATION.md)。
