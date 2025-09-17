#!/bin/bash

# 简化版SMTP监控启动脚本
# 使用方法: sudo ./simple-start.sh

# 颜色定义
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}🚀 简化版SMTP监控${NC}"

# 检查root权限
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}❌ 需要root权限，请使用: sudo $0${NC}"
   exit 1
fi

# 检查zeek
if ! command -v zeek &> /dev/null; then
    echo -e "${RED}❌ Zeek未安装${NC}"
    exit 1
fi

# 检查必要文件
if [[ ! -f "live-smtp-monitor.zeek" ]]; then
    echo -e "${RED}❌ 找不到 live-smtp-monitor.zeek${NC}"
    exit 1
fi

# 创建日志目录
LOG_DIR="smtp-monitor-$(date +%H%M%S)"
mkdir -p "$LOG_DIR"

echo -e "${GREEN}✅ 准备就绪${NC}"
echo -e "${YELLOW}📁 日志目录: $LOG_DIR${NC}"
echo -e "${YELLOW}📡 监控网卡: en0${NC}"
echo -e "${BLUE}💡 按 Ctrl+C 停止监控${NC}"
echo "=================================="

# 获取当前脚本目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 切换到日志目录
cd "$LOG_DIR"

# 启动监控
echo -e "${GREEN}🚀 开始SMTP监控...${NC}"
zeek -i en0 -f "port 25 or port 465 or port 587 or port 2525" "$SCRIPT_DIR/live-smtp-monitor.zeek"