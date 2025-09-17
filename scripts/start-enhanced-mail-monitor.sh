#!/bin/bash

# 增强版邮件监控启动脚本
# 支持 SMTP + IMAP + POP3 协议监控

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 获取项目根目录
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# 默认网卡
DEFAULT_INTERFACE="en0"

echo -e "${BLUE}🔍 增强版邮件协议监控器${NC}"
echo "支持协议: SMTP (发送) + IMAP/POP3 (接收)"
echo ""

# 检查是否以root权限运行
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}❌ 此脚本需要root权限运行${NC}"
   echo "请使用: sudo $0"
   exit 1
fi

# 检查zeek是否安装
if ! command -v zeek &> /dev/null; then
    echo -e "${RED}❌ Zeek未安装或不在PATH中${NC}"
    echo "请先安装Zeek: brew install zeek"
    exit 1
fi

# 获取网卡信息
echo -e "${BLUE}📡 可用网络接口:${NC}"
ifconfig | grep -E "^[a-z]" | cut -d: -f1 | while read interface; do
    status=$(ifconfig $interface | grep "status: active" > /dev/null && echo "✅ 活跃" || echo "❌ 非活跃")
    echo "  $interface - $status"
done

echo ""
read -p "请输入要监控的网卡名称 (默认: $DEFAULT_INTERFACE): " INTERFACE
INTERFACE=${INTERFACE:-$DEFAULT_INTERFACE}

# 检查网卡是否存在
if ! ifconfig "$INTERFACE" &> /dev/null; then
    echo -e "${RED}❌ 网卡 $INTERFACE 不存在${NC}"
    exit 1
fi

echo -e "${GREEN}✅ 将监控网卡: $INTERFACE${NC}"

# 检查必要文件
REQUIRED_FILES=(
    "$PROJECT_ROOT/zeek-scripts/enhanced-mail-monitor.zeek"
    "$PROJECT_ROOT/configs/enhanced-mail-filter.bpf"
)

echo ""
echo -e "${BLUE}🔍 检查必要文件...${NC}"
for file in "${REQUIRED_FILES[@]}"; do
    if [[ -f "$file" ]]; then
        echo -e "${GREEN}✅ $file${NC}"
    else
        echo -e "${RED}❌ 缺少文件: $file${NC}"
        exit 1
    fi
done

echo -e "${GREEN}✅ 环境检查完成${NC}"

# 显示监控选项
echo ""
echo "选择监控模式:"
echo "1) 完整邮件监控 (SMTP + IMAP + POP3)"
echo "2) 使用BPF配置文件"
echo "3) 自定义过滤器"
echo "4) 无过滤器 (监控所有流量)"

read -p "请选择 [1-4]: " choice

case $choice in
    1)
        FILTER_CMD="-f \"port 25 or port 465 or port 587 or port 2525 or port 143 or port 993 or port 110 or port 995\""
        echo -e "${GREEN}📧 使用完整邮件协议监控${NC}"
        ;;
    2)
        FILTER_CMD="-f \"$(cat $PROJECT_ROOT/configs/enhanced-mail-filter.bpf)\""
        echo -e "${GREEN}📋 使用BPF配置文件${NC}"
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
        echo -e "${RED}❌ 无效选择，使用默认完整邮件监控${NC}"
        FILTER_CMD="-f \"port 25 or port 465 or port 587 or port 2525 or port 143 or port 993 or port 110 or port 995\""
        ;;
esac

# 构建zeek命令
ZEEK_CMD="zeek -i $INTERFACE $FILTER_CMD $PROJECT_ROOT/zeek-scripts/enhanced-mail-monitor.zeek"

echo ""
echo -e "${BLUE}🎯 启动命令:${NC}"
echo "$ZEEK_CMD"
echo ""

# 创建停止脚本
cat > "$PROJECT_ROOT/scripts/stop-enhanced-monitor.sh" << 'EOF'
#!/bin/bash
echo "🛑 停止邮件监控..."
sudo pkill -f "zeek.*enhanced-mail-monitor"
echo "✅ 监控已停止"
EOF

chmod +x "$PROJECT_ROOT/scripts/stop-enhanced-monitor.sh"

echo -e "${GREEN}📝 已创建停止脚本: $PROJECT_ROOT/scripts/stop-enhanced-monitor.sh${NC}"

# 创建日志目录
LOG_DIR="$PROJECT_ROOT/logs/live-logs/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$LOG_DIR"

echo ""
echo -e "${YELLOW}📂 日志将保存到: $LOG_DIR${NC}"
echo ""

# 倒计时
for i in {3..1}; do
    echo -e "${BLUE}🚀 $i 秒后开始监控...${NC}"
    sleep 1
done

echo -e "${GREEN}🎯 开始监控邮件流量...${NC}"
echo -e "${BLUE}💡 按 Ctrl+C 停止监控${NC}"
echo ""

# 切换到日志目录并启动zeek
cd "$LOG_DIR"
SCRIPT_DIR="$PROJECT_ROOT/zeek-scripts"
eval "$ZEEK_CMD"