# GNN 接入 — 断点恢复 / 进度状态

## ✅✅✅ 最终方案:官方模型已集成进 OPM（最新，主路径）
- **用官方预训练模型,不自训**:`tygr_original/model/MODEL_base/x64.O0.base.model`(真实 TYDA 训练,产出 char*/f32*/array 等精确类型,质量远超自训合成模型)。
- **复刻原始环境** `tygr-orig`(conda,python `/root/miniconda3/envs/tygr-orig/bin/python`):严格按 `environment.yml`(torch1.8.1+PyG1.7.0+angr/pyvex 9.0.7491)。构建脚本 `build_orig_env.sh`+`req_rest.txt`。坑已记:capstone→4.0.2、protobuf→3.20.3。
- **集成已完成**:`src/type_recovery/inference.py::_recover_with_gnn` 子进程调 tygr-orig python 跑官方模型 predict → 组装 TypeRecoveryOutput;`pipeline.py` Stage1 存 `binary_debug`(-g),Stage6 用它。env 变量 `TYGR_MODEL`/`TYGR_PYTHON` 可覆盖。
- **验证**:`recover_types(c000)` → 25 函数、char*/array、src=gnn。✓
- 下一步:6 程序开 GNN 跑完整流水线 + `docs/VERSION_COMPAT.md` 补 tygr-orig 复刻步骤。
- ⚠️ 我给 `tygr_original/src` 的新环境 hack 已对老环境做兼容(`torch.load` weights_only try/except;cp.BVV/edge_dim 对老环境无害)。
---

## ✅✅ 自训路线已跑通（备用）
- **两处关键修复让训练成功**：
  1. `model.py:45` `self.edge_dim = 44`（硬编码）→ `= self.preproc_config.num_edge_ops`（动态）——消除 `index out of bounds for size 44` 崩溃。
  2. **训练加 `--batch_size 1`**——默认 batch(~32函数/批)在 4GB WSL 上 **OOM 被杀**(dmesg 确认);batch_size=1 内存降到 ~2GB，不再 OOM。
- **状态**：`corpus.model` 正在训练（60 epoch，~2-2.5 min/epoch ≈ 2 小时），**Epoch0 已 Accuracy 0.77 / F1 0.80**，日志 `output/tygr/train_full.log`，模型存 `corpus.model.best.model`。
- **若训练中断要重启**（在 tygr_original/ 下）：
  `python -m src.index train output/tygr/ctr.pkl output/tygr/cva.pkl -o output/tygr/corpus.model --epoch 60 --batch_size 1`
- 训完 test：`python -m src.index test output/tygr/corpus.model.best.model output/tygr/cte.pkl`

## (历史卡点，已解决)
- edge_dim 硬编码 44 → 已改动态；train 0/7 卡住 → 实为默认 batch OOM，已用 batch_size=1 解决。
  - 数据没问题：训练 252 函数 / 2675 变量；`type_set.num_types()=75`。
  - 怀疑方向：(a) `num_edge_ops` 在当前 pyvex 下变得很大 → edge `nn.Embedding(num_edge_ops, dim)` 巨大/首个 forward 极慢或卡；
    (b) 某个 VEX op 的处理在新版 pyvex 下 hang。
  - **调试建议**：① 在 model.py 打印 `self.edge_dim`/`num_edge_ops` 看是否异常大；② 单步只跑 1 个 batch 看是 hang 还是 crash（去掉 tqdm，或 `--no-shuffle` + 极小数据）；③ 若 num_edge_ops 异常，检查 preproc 的 `all_ops` 是否被正确填充/截断。
- 语料构建仍在后台跑（编译+datagen 全 80 文件）；`auto_train.sh` 会在语料就绪后自动训练——**但因上述卡点，它大概率也产不出模型**，需 resume 后先解决 train 卡住问题。
- 部分语料已可用于调试：`output/tygr/ptr.pkl`（252 函数）/`pva.pkl`/`pte.pkl`。
---


> 目的：网络/会话中断后，新会话或人工能完整接续 GNN 类型恢复的接入工作。
> 所有任务均为**本地 WSL 进程**，断网不影响其运行。

## 当前进度（截至本文件写入时）

1. **TYGR 版本适配：✅ 完成**（datagen + train + 自定义串行 predict 都已适配，见下「已做的版本补丁」）。
2. **合成语料构建：进行中**（`corpus_build.sh`，后台）。80 个生成的 C 文件，每个 ~9 函数、~100 变量 → 共 ~720 函数。
   - 产物：`output/tygr/corpus_ds/c*.pkl`（每文件一个），最后合并 `output/tygr/corpus_merged.pkl` + 切分 `ctr.pkl/cva.pkl/cte.pkl`。
3. **自动训练链：已排队**（`auto_train.sh`，nohup 脱离会话）。轮询 `ctr.pkl` 出现 → 训练 60 轮 → test 验证。
   - 产物：`output/tygr/corpus.model.best.model`（+ `.last.model`），日志 `output/tygr/auto_train.log`。

## 为什么要重做语料
原训练数据仅 6 个测试程序（36 函数），**太小连特征词表都建不全** → 模型 embedding 只有 44 槽，宽一点的数据出现索引 55 → `index out of bounds` 崩溃。合成语料（~720 函数、类型多样）用来**建全词表 + 训出能跑的模型**。TYDA 全量 100+GB 不现实，故走自建语料。

## 已做的版本补丁（施加于本地 `tygr_original/`，已 gitignore；另见 `docs/VERSION_COMPAT.md`）
- `src/analysis/angr/sim_exec.py`、`ast_graph.py`：`state.solver.BVV/BVS` → `cp.BVV/cp.BVS`（angr 移除了 SimSolver.BVV）。两文件已 `import claripy as cp`。
- `src/predict.py`、`src/test.py`：`torch.load(..., weights_only=False)`。
- `src/train.py`：移除 `ReduceLROnPlateau(verbose=)`。
- `src/utils/learn.py`：所有指标除法加零保护（precision/recall/accuracy/loss）。
- `src/methods/glow/predict.py`：新增 `generate_glow_inputs_no_parallel`（串行，绕过多进程 Pool 的 angr RuntimeDb 崩溃）。
- `src/methods/glow/method.py`：(a) predict 的 `model(...)` 调用打包成单个 7 元组；(b) predict-phase `preproc.Config` 补齐 `use_bitvector/bitsize/use_arch`（与 train 一致）。

## 关键环境 / 命令
- env：`/root/miniconda3/envs/angr-env/bin/python`，TYGR CLI：`cd tygr_original && python -m src.index <cmd>`
- 编译需 DWARF：`gcc -gdwarf-4 -O0 -w X.c -o X`
- datagen：`python -m src.index datagen BIN OUT.pkl`（**非并行可用**；predict 命令的并行路径有 RuntimeDb bug，已用串行版绕过）
- 训练：`python -m src.index train TR.pkl VA.pkl -o M.model --epoch N`（存 `M.model.best.model`）
- 评估：`python -m src.index test M.model.best.model TE.pkl`
- ⚠️ WSL `/tmp` 在 VM 空闲关机后清空 → 所有中间文件写 `output/tygr/`（持久）。
- WSL 内存：`.wslconfig` 现为 4GB+4GB swap（16GB 机器上 12GB 不可行）。

## 恢复后下一步（按顺序）
1. 查训练结果：`tail -40 output/tygr/auto_train.log`。看 test 是否给出 accuracy（= 词表已修、模型可推理）还是仍 `index out of bounds`（则需更大/更多样语料）。
2. 若模型 OK → **集成进 OPM**：改 `src/type_recovery/inference.py::recover_types(binary, cfg, dfg, ...)`：
   - 用 TYGR **串行** datagen 对 binary 提 glow 输入；
   - 走**训练/测试同一数据路径**（`Glow` 方法 train-phase 配置 + `dataset.GlowDataset`/`collate_fn` → `model(x)`），**不要**用陈旧的 `predict_and_bickle`；
   - `preproc_config.type_set.tensor_to_type(y_pred[i])` 解码每变量类型 → 组装成 OPM 的 `TypeRecoveryOutput`（function_name + predictions[variable_name/predicted_type/confidence]）。
   - 模型路径：`output/tygr/corpus.model.best.model`。
3. 在 6 个测试程序上**开 GNN 重跑** OPM，确认 Stage 6 类型恢复从「0 functions」变为真有类型输出，并喂进类型注入/污点。
4. 质量提升（thesis 级）：用更大/更真实语料（真实小 C 库如 cJSON，按 TYDA 的 `-g -O0 -fno-inline...` 编译）重训。

## 检查任务是否还在跑
```bash
pgrep -af "corpus_build.sh|src.index|auto_train.sh"
grep -c "Well Formed #func" output/tygr/corpus_build.log   # /80
tail output/tygr/auto_train.log
```
