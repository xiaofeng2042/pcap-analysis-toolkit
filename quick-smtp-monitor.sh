#!/bin/bash

# 快速SMTP监控脚本 - 一键启动
# 使用方法: sudo ./quick-smtp-monitor.sh

# 颜色定义
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}🚀 快速SMTP监控${NC}"

# 检查root权限
if [[ $EUID -ne 0 ]]; then
   echo "❌ 需要root权限，请使用: sudo $0"
   exit 1
fi

# 创建临时日志目录
LOG_DIR="smtp-live-$(date +%H%M%S)"
mkdir -p "$LOG_DIR"

echo -e "${GREEN}📡 开始监控SMTP流量...${NC}"
echo -e "${YELLOW}📁 日志保存在: $LOG_DIR/${NC}"
echo -e "${BLUE}💡 按 Ctrl+C 停止监控${NC}"
echo "=================================="

# 切换到日志目录并启动
cd "$LOG_DIR"
zeek -i en0 -f "port 25 or port 465 or port 587 or port 2525" ../live-smtp-monitor.zeek