#!/bin/bash
# 复刻 TYGR 原始环境(CPU),以便直接使用官方预训练模型 x64.O0.base.model
# 版本严格按 tygr_original/environment.yml(angr/pyvex 9.0.7491 是模型特征的关键)
set -e
source /root/miniconda3/etc/profile.d/conda.sh

echo "==== [1] 创建 conda 环境 tygr-orig (python 3.8.10) ===="
conda create -y -n tygr-orig python=3.8.10

echo "==== [2] 安装 pytorch 1.8.1 (CPU) ===="
conda run -n tygr-orig pip install torch==1.8.1+cpu torchvision==0.9.1+cpu torchaudio==0.8.1 \
    -f https://download.pytorch.org/whl/torch_stable.html

echo "==== [3] 安装 PyG 1.7.0 栈 (匹配 torch-1.8.1+cpu) ===="
conda run -n tygr-orig pip install torch-scatter==2.0.6 torch-sparse==0.6.9 \
    -f https://data.pyg.org/whl/torch-1.8.1+cpu.html
conda run -n tygr-orig pip install torch-geometric==1.7.0

echo "==== [4] 安装 angr/pyvex 9.0.7491 全家桶 (模型特征所依赖的精确版本) ===="
conda run -n tygr-orig pip install \
    angr==9.0.7491 archinfo==9.0.7491 claripy==9.0.7491 cle==9.0.7491 pyvex==9.0.7491

echo "==== [5] 其余依赖 ===="
conda run -n tygr-orig pip install python-louvain==0.15 gitpython python-utils networkx tqdm

echo "==== [6] 冒烟测试:能否加载官方 x64.O0.base.model ===="
cd /mnt/d/计算机资料/毕设/tygr_original
conda run -n tygr-orig python -c "import torch; m=torch.load('model/MODEL_base/x64.O0.base.model', map_location='cpu'); print('官方模型加载成功:', type(m).__name__)"

echo "==== DONE — tygr-orig 环境就绪 ===="
