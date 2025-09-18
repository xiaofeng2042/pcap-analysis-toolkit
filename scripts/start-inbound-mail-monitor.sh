#!/bin/bash

# 收信监控集成启动脚本
# 启动 GreenMail 服务器和 Zeek 收信监控

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
ZEEK_SCRIPTS_DIR="$PROJECT_ROOT/zeek-scripts"
LOGS_DIR="$PROJECT_ROOT/logs/inbound-mail-$(date '+%Y%m%d_%H%M%S')"

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo "=== 收信监控系统启动 ==="

# 检查必要工具
check_requirements() {
    echo "检查系统要求..."
    
    # 检查 Docker
    if ! command -v docker &> /dev/null; then
        echo -e "${RED}错误: Docker 未安装${NC}"
        exit 1
    fi
    
    if ! docker info >/dev/null 2>&1; then
        echo -e "${RED}错误: Docker 未运行${NC}"
        exit 1
    fi
    
    # 检查 Zeek
    if ! command -v zeek &> /dev/null; then
        echo -e "${RED}错误: Zeek 未安装${NC}"
        echo "安装方法："
        echo "  macOS: brew install zeek"
        echo "  Ubuntu: sudo apt-get install zeek"
        exit 1
    fi
    
    echo -e "${GREEN}✅ 系统要求检查通过${NC}"
}

# 创建日志目录
setup_logging() {
    echo "设置日志目录: $LOGS_DIR"
    mkdir -p "$LOGS_DIR"
    
    # 创建符号链接到最新日志
    local latest_link="$PROJECT_ROOT/logs/latest-inbound"
    rm -f "$latest_link"
    ln -sf "$LOGS_DIR" "$latest_link"
    
    echo -e "${GREEN}✅ 日志目录已创建${NC}"
}

# 启动 GreenMail 服务
start_greenmail() {
    echo ""
    echo -e "${YELLOW}启动 GreenMail 邮件服务器...${NC}"
    
    cd "$PROJECT_ROOT" || exit 1
    
    # 检查是否已经运行
    if docker ps | grep -q "greenmail-server"; then
        echo -e "${BLUE}GreenMail 已在运行，重启服务...${NC}"
        ./scripts/stop-greenmail.sh >/dev/null 2>&1
        sleep 2
    fi
    
    # 启动服务
    ./scripts/start-greenmail.sh
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅ GreenMail 服务启动成功${NC}"
    else
        echo -e "${RED}❌ GreenMail 服务启动失败${NC}"
        exit 1
    fi
}

# 启动 Zeek 监控
start_zeek_monitoring() {
    echo ""
    echo -e "${YELLOW}启动 Zeek 收信监控...${NC}"
    
    cd "$LOGS_DIR" || exit 1
    
    # 构建 Zeek 命令
    local zeek_cmd="zeek -i lo0"
    zeek_cmd="$zeek_cmd $ZEEK_SCRIPTS_DIR/mail-inbound-monitor.zeek"
    zeek_cmd="$zeek_cmd $ZEEK_SCRIPTS_DIR/site-mail-ports.zeek"
    
    # 添加过滤器以监控邮件端口
    local filter="port 3025 or port 3110 or port 3143 or port 3465 or port 3993 or port 3995"
    zeek_cmd="$zeek_cmd -f \"$filter\""
    
    # 设置 Zeek 选项
    zeek_cmd="$zeek_cmd -C"  # 忽略校验和
    
    echo "Zeek 命令: $zeek_cmd"
    echo "监控接口: lo0 (回环接口)"
    echo "监控端口: 3025(SMTP), 3110(POP3), 3143(IMAP), 3465(SMTPS), 3993(IMAPS), 3995(POP3S)"
    echo "日志目录: $LOGS_DIR"
    echo ""
    
    # 在后台启动 Zeek
    nohup bash -c "$zeek_cmd" > zeek_output.log 2>&1 &
    local zeek_pid=$!
    
    # 保存 PID
    echo $zeek_pid > zeek.pid
    
    # 等待 Zeek 启动
    sleep 3
    
    # 检查 Zeek 是否正在运行
    if kill -0 $zeek_pid 2>/dev/null; then
        echo -e "${GREEN}✅ Zeek 监控启动成功 (PID: $zeek_pid)${NC}"
    else
        echo -e "${RED}❌ Zeek 监控启动失败${NC}"
        echo "查看错误日志:"
        cat zeek_output.log
        exit 1
    fi
}

# 显示监控状态
show_status() {
    echo ""
    echo -e "${BLUE}=== 监控系统状态 ===${NC}"
    
    # GreenMail 状态
    if docker ps | grep -q "greenmail-server"; then
        echo -e "${GREEN}✅ GreenMail 服务: 运行中${NC}"
    else
        echo -e "${RED}❌ GreenMail 服务: 未运行${NC}"
    fi
    
    # Zeek 状态
    if [ -f "$LOGS_DIR/zeek.pid" ]; then
        local zeek_pid=$(cat "$LOGS_DIR/zeek.pid")
        if kill -0 $zeek_pid 2>/dev/null; then
            echo -e "${GREEN}✅ Zeek 监控: 运行中 (PID: $zeek_pid)${NC}"
        else
            echo -e "${RED}❌ Zeek 监控: 未运行${NC}"
        fi
    else
        echo -e "${RED}❌ Zeek 监控: 未启动${NC}"
    fi
    
    echo ""
    echo -e "${BLUE}服务端点:${NC}"
    echo "  SMTP:  localhost:3025"
    echo "  POP3:  localhost:3110"
    echo "  IMAP:  localhost:3143"
    echo "  SMTPS: localhost:3465"
    echo "  IMAPS: localhost:3993"
    echo "  POP3S: localhost:3995"
    
    echo ""
    echo -e "${BLUE}测试账号:${NC}"
    echo "  用户名: test@local"
    echo "  密码:   secret"
    
    echo ""
    echo -e "${BLUE}日志位置:${NC}"
    echo "  实时日志: $LOGS_DIR"
    echo "  最新链接: $PROJECT_ROOT/logs/latest-inbound"
    
    echo ""
    echo -e "${BLUE}测试命令:${NC}"
    echo "  发送邮件: ./scripts/test-mail-delivery.sh"
    echo "  收取邮件: ./scripts/test-mail-retrieval.sh"
    echo "  停止监控: ./scripts/stop-inbound-mail-monitor.sh"
}

# 创建停止脚本
create_stop_script() {
    local stop_script="$SCRIPT_DIR/stop-inbound-mail-monitor.sh"
    
    cat > "$stop_script" << 'EOF'
#!/bin/bash

# 停止收信监控系统

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
LATEST_LOGS="$PROJECT_ROOT/logs/latest-inbound"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "=== 停止收信监控系统 ==="

# 停止 Zeek
if [ -L "$LATEST_LOGS" ] && [ -f "$LATEST_LOGS/zeek.pid" ]; then
    ZEEK_PID=$(cat "$LATEST_LOGS/zeek.pid")
    if kill -0 $ZEEK_PID 2>/dev/null; then
        echo "停止 Zeek 监控 (PID: $ZEEK_PID)..."
        kill $ZEEK_PID
        sleep 2
        if kill -0 $ZEEK_PID 2>/dev/null; then
            kill -9 $ZEEK_PID
        fi
        echo -e "${GREEN}✅ Zeek 监控已停止${NC}"
    else
        echo -e "${YELLOW}Zeek 监控未运行${NC}"
    fi
    rm -f "$LATEST_LOGS/zeek.pid"
else
    echo -e "${YELLOW}未找到 Zeek PID 文件${NC}"
fi

# 停止 GreenMail
echo "停止 GreenMail 服务..."
cd "$PROJECT_ROOT" || exit 1
./scripts/stop-greenmail.sh

echo -e "${GREEN}=== 收信监控系统已停止 ===${NC}"
EOF
    
    chmod +x "$stop_script"
    echo "已创建停止脚本: $stop_script"
}

# 主程序
main() {
    check_requirements
    setup_logging
    start_greenmail
    start_zeek_monitoring
    create_stop_script
    show_status
    
    echo ""
    echo -e "${GREEN}=== 收信监控系统启动完成 ===${NC}"
    echo ""
    echo "系统已准备就绪，可以开始测试："
    echo "1. 发送测试邮件: ./scripts/test-mail-delivery.sh"
    echo "2. 验证邮件接收: ./scripts/test-mail-retrieval.sh"
    echo "3. 查看实时日志: tail -f $LOGS_DIR/*.log"
    echo "4. 停止监控: ./scripts/stop-inbound-mail-monitor.sh"
    echo ""
    echo "监控将持续运行，按 Ctrl+C 不会停止后台服务"
}

# 运行主程序
main