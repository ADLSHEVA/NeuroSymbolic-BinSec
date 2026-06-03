#!/bin/bash
# OPM Pipeline Runner for WSL/Linux
# 在WSL中运行完整的OPM管道

set -e

# 配置
PYTHON="/root/miniconda3/envs/angr-env/bin/python"
PROJECT_DIR="/mnt/d/计算机资料/毕设"

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}OPM Pipeline Runner (WSL/Linux)${NC}"
echo -e "${GREEN}========================================${NC}"

# 检查参数
if [ $# -lt 1 ]; then
    echo -e "${RED}Usage: $0 <source_file> [output_dir]${NC}"
    echo ""
    echo "Examples:"
    echo "  $0 tests/test_programs/vulnerable.c"
    echo "  $0 tests/test_programs/vulnerable.c output/vulnerable"
    exit 1
fi

SOURCE_FILE="$1"
OUTPUT_DIR="${2:-output/$(basename "$SOURCE_FILE" .c)}"

# 转换路径
SOURCE_PATH="$PROJECT_DIR/$SOURCE_FILE"
OUTPUT_PATH="$PROJECT_DIR/$OUTPUT_DIR"

# 检查源文件
if [ ! -f "$SOURCE_PATH" ]; then
    echo -e "${RED}Error: Source file not found: $SOURCE_PATH${NC}"
    exit 1
fi

echo -e "${YELLOW}Source: $SOURCE_FILE${NC}"
echo -e "${YELLOW}Output: $OUTPUT_DIR${NC}"
echo ""

# 创建输出目录
mkdir -p "$OUTPUT_PATH"

# 运行管道
echo -e "${GREEN}Running OPM pipeline...${NC}"
cd "$PROJECT_DIR"

$PYTHON scripts/run_pipeline.py "$SOURCE_FILE" -o "$OUTPUT_DIR" -v

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Pipeline completed!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "Reports:"
echo -e "  JSON: ${YELLOW}$OUTPUT_PATH/analysis_report.json${NC}"
echo -e "  Markdown: ${YELLOW}$OUTPUT_PATH/analysis_report.md${NC}"
