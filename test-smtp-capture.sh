#!/bin/bash

# SMTP监控测试脚本
# 验证配置是否正确，无需root权限

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}🧪 SMTP监控配置测试${NC}"
echo "=================================="

# 检查必要文件
echo -e "${YELLOW}📋 检查配置文件...${NC}"

REQUIRED_FILES=(
    "live-smtp-monitor.zeek"
    "site-smtp-ports.zeek" 
    "smtp-starttls-flag.zeek"
    "simple-smtp-filter.bpf"
    "smtp-filter.bpf"
    "start-smtp-monitor.sh"
    "quick-smtp-monitor.sh"
)

missing_files=()
for file in "${REQUIRED_FILES[@]}"; do
    if [[ -f "$file" ]]; then
        echo -e "  ✅ $file"
    else
        echo -e "  ❌ $file"
        missing_files+=("$file")
    fi
done

if [[ ${#missing_files[@]} -gt 0 ]]; then
    echo -e "${RED}❌ 缺少必要文件，无法继续测试${NC}"
    exit 1
fi

echo -e "${GREEN}✅ 所有配置文件检查完成${NC}"
echo ""

# 检查zeek语法
echo -e "${YELLOW}🔍 检查Zeek脚本语法...${NC}"

if zeek -p live-smtp-monitor.zeek 2>/dev/null; then
    echo -e "  ✅ live-smtp-monitor.zeek 语法正确"
else
    echo -e "  ❌ live-smtp-monitor.zeek 语法错误"
    echo "详细错误信息:"
    zeek -p live-smtp-monitor.zeek
    exit 1
fi

if zeek -p site-smtp-ports.zeek 2>/dev/null; then
    echo -e "  ✅ site-smtp-ports.zeek 语法正确"
else
    echo -e "  ❌ site-smtp-ports.zeek 语法错误"
fi

if zeek -p smtp-starttls-flag.zeek 2>/dev/null; then
    echo -e "  ✅ smtp-starttls-flag.zeek 语法正确"
else
    echo -e "  ❌ smtp-starttls-flag.zeek 语法错误"
fi

echo -e "${GREEN}✅ Zeek脚本语法检查完成${NC}"
echo ""

# 检查BPF过滤器语法
echo -e "${YELLOW}🔍 检查BPF过滤器语法...${NC}"

if tcpdump -d "$(cat simple-smtp-filter.bpf)" >/dev/null 2>&1; then
    echo -e "  ✅ simple-smtp-filter.bpf 语法正确"
else
    echo -e "  ❌ simple-smtp-filter.bpf 语法错误"
fi

echo -e "${GREEN}✅ BPF过滤器检查完成${NC}"
echo ""

# 检查网卡
echo -e "${YELLOW}🌐 检查可用网卡...${NC}"
echo "可用网卡列表:"
ifconfig -l | tr ' ' '\n' | while read interface; do
    if [[ -n "$interface" ]]; then
        echo -e "  📡 $interface"
    fi
done
echo ""

# 显示使用说明
echo -e "${BLUE}📖 使用说明${NC}"
echo "=================================="
echo -e "${GREEN}🚀 快速启动 (推荐):${NC}"
echo "   sudo ./quick-smtp-monitor.sh"
echo ""
echo -e "${GREEN}🎛️  完整启动 (更多选项):${NC}"
echo "   sudo ./start-smtp-monitor.sh [网卡名称]"
echo ""
echo -e "${GREEN}📊 手动启动:${NC}"
echo "   sudo zeek -i en0 -f \"port 25 or port 465 or port 587 or port 2525\" live-smtp-monitor.zeek"
echo ""
echo -e "${YELLOW}💡 提示:${NC}"
echo "   - 监控需要root权限"
echo "   - 按 Ctrl+C 停止监控"
echo "   - 日志文件会保存在当前目录的子文件夹中"
echo "   - 每5分钟会显示一次统计报告"
echo ""

# 创建示例测试命令
echo -e "${BLUE}🧪 测试命令示例${NC}"
echo "=================================="
echo "1. 测试SMTP连接 (需要另一个终端):"
echo "   telnet smtp.gmail.com 587"
echo ""
echo "2. 发送测试邮件 (需要另一个终端):"
echo "   echo 'Test' | mail -s 'Test Subject' test@example.com"
echo ""
echo "3. 查看实时日志:"
echo "   tail -f smtp-live-*/smtp.log"
echo ""

echo -e "${GREEN}✅ 配置测试完成，可以开始监控！${NC}"