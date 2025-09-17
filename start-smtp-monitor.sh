#!/bin/bash

# SMTP实时监控启动脚本
# 使用方法: sudo ./start-smtp-monitor.sh [网卡名称]

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 默认网卡
INTERFACE=${1:-en0}

echo -e "${BLUE}🚀 SMTP实时监控启动器${NC}"
echo "=================================="

# 检查是否以root权限运行
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}❌ 此脚本需要root权限运行${NC}"
   echo "请使用: sudo $0"
   exit 1
fi

# 检查zeek是否安装
if ! command -v zeek &> /dev/null; then
    echo -e "${RED}❌ Zeek未安装或不在PATH中${NC}"
    exit 1
fi

# 检查网卡是否存在
if ! ifconfig "$INTERFACE" &> /dev/null; then
    echo -e "${RED}❌ 网卡 $INTERFACE 不存在${NC}"
    echo "可用网卡:"
    ifconfig -l
    exit 1
fi

# 检查必要文件
REQUIRED_FILES=(
    "live-smtp-monitor.zeek"
    "site-smtp-ports.zeek" 
    "smtp-starttls-flag.zeek"
    "simple-smtp-filter.bpf"
)

for file in "${REQUIRED_FILES[@]}"; do
    if [[ ! -f "$file" ]]; then
        echo -e "${RED}❌ 缺少文件: $file${NC}"
        exit 1
    fi
done

# 创建日志目录
LOG_DIR="live-logs/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$LOG_DIR"

echo -e "${GREEN}✅ 环境检查完成${NC}"
echo -e "${YELLOW}📡 监控网卡: $INTERFACE${NC}"
echo -e "${YELLOW}📁 日志目录: $LOG_DIR${NC}"

# 显示监控选项
echo ""
echo "选择监控模式:"
echo "1) 基础监控 (只监控标准SMTP端口)"
echo "2) 增强监控 (包含深度包检测)"
echo "3) 自定义过滤器"
echo "4) 无过滤器 (监控所有流量)"

read -p "请选择 [1-4]: " choice

case $choice in
    1)
        FILTER_CMD="-f \"$(cat simple-smtp-filter.bpf)\""
        echo -e "${GREEN}📊 使用基础SMTP端口过滤${NC}"
        ;;
    2)
        FILTER_CMD="-f \"$(cat smtp-filter.bpf)\""
        echo -e "${GREEN}📊 使用增强SMTP检测${NC}"
        ;;
    3)
        read -p "请输入BPF过滤规则: " custom_filter
        FILTER_CMD="-f \"$custom_filter\""
        echo -e "${GREEN}📊 使用自定义过滤器: $custom_filter${NC}"
        ;;
    4)
        FILTER_CMD=""
        echo -e "${YELLOW}⚠️  无过滤器模式 - 将监控所有网络流量${NC}"
        ;;
    *)
        echo -e "${RED}❌ 无效选择，使用默认基础监控${NC}"
        FILTER_CMD="-f \"$(cat simple-smtp-filter.bpf)\""
        ;;
esac

# 构建zeek命令
ZEEK_CMD="zeek -i $INTERFACE $FILTER_CMD live-smtp-monitor.zeek"

echo ""
echo -e "${BLUE}🎯 启动命令:${NC}"
echo "$ZEEK_CMD"
echo ""

# 创建停止脚本
cat > stop-monitor.sh << 'EOF'
#!/bin/bash
echo "🛑 停止SMTP监控..."
pkill -f "zeek.*live-smtp-monitor"
echo "✅ 监控已停止"
EOF
chmod +x stop-monitor.sh

echo -e "${GREEN}📝 已创建停止脚本: ./stop-monitor.sh${NC}"
echo ""

# 倒计时启动
echo -e "${YELLOW}⏰ 3秒后开始监控...${NC}"
for i in {3..1}; do
    echo -n "$i... "
    sleep 1
done
echo ""

echo -e "${GREEN}🚀 开始SMTP实时监控...${NC}"
echo -e "${BLUE}💡 提示: 按 Ctrl+C 停止监控${NC}"
echo "=================================="

# 切换到日志目录并启动监控
cd "$LOG_DIR"
eval $ZEEK_CMD