#!/bin/bash

# 邮件收取验证脚本
# 支持 POP3 和 IMAP 协议测试

# 默认配置
SERVER="127.0.0.1"
POP3_PORT="3110"
IMAP_PORT="3143"
USERNAME="test@local"
PASSWORD="secret"

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo "=== 邮件收取验证测试 ==="

# 检查必要工具
check_tools() {
    local missing_tools=()
    
    if ! command -v telnet &> /dev/null; then
        missing_tools+=("telnet")
    fi
    
    if ! command -v nc &> /dev/null; then
        missing_tools+=("nc (netcat)")
    fi
    
    if [ ${#missing_tools[@]} -gt 0 ]; then
        echo -e "${RED}错误: 缺少必要工具: ${missing_tools[*]}${NC}"
        echo "安装方法："
        echo "  macOS: brew install telnet netcat"
        echo "  Ubuntu: sudo apt-get install telnet netcat"
        exit 1
    fi
}

# 检查服务连通性
check_services() {
    echo "检查服务连通性..."
    
    if nc -z "$SERVER" "$POP3_PORT" 2>/dev/null; then
        echo -e "${GREEN}✅ POP3 服务 ($SERVER:$POP3_PORT) 可访问${NC}"
    else
        echo -e "${RED}❌ POP3 服务 ($SERVER:$POP3_PORT) 不可访问${NC}"
    fi
    
    if nc -z "$SERVER" "$IMAP_PORT" 2>/dev/null; then
        echo -e "${GREEN}✅ IMAP 服务 ($SERVER:$IMAP_PORT) 可访问${NC}"
    else
        echo -e "${RED}❌ IMAP 服务 ($SERVER:$IMAP_PORT) 不可访问${NC}"
    fi
    echo ""
}

# POP3 测试函数
test_pop3() {
    echo -e "${YELLOW}=== POP3 协议测试 ===${NC}"
    
    if ! nc -z "$SERVER" "$POP3_PORT" 2>/dev/null; then
        echo -e "${RED}POP3 服务不可用，跳过测试${NC}"
        return 1
    fi
    
    echo "连接到 POP3 服务器..."
    
    # 创建 POP3 命令脚本
    cat > /tmp/pop3_commands.txt << EOF
USER $USERNAME
PASS $PASSWORD
STAT
LIST
RETR 1
QUIT
EOF
    
    echo -e "${BLUE}执行 POP3 命令:${NC}"
    echo "USER $USERNAME"
    echo "PASS $PASSWORD"
    echo "STAT (查看邮箱状态)"
    echo "LIST (列出邮件)"
    echo "RETR 1 (获取第一封邮件)"
    echo "QUIT"
    echo ""
    
    # 执行 POP3 测试
    echo -e "${BLUE}POP3 服务器响应:${NC}"
    (
        sleep 1
        while IFS= read -r cmd; do
            echo "$cmd"
            sleep 1
        done < /tmp/pop3_commands.txt
    ) | telnet "$SERVER" "$POP3_PORT" 2>/dev/null | grep -v "^Trying\|^Connected\|^Escape"
    
    # 清理临时文件
    rm -f /tmp/pop3_commands.txt
    
    echo -e "${GREEN}POP3 测试完成${NC}"
    echo ""
}

# IMAP 测试函数
test_imap() {
    echo -e "${YELLOW}=== IMAP 协议测试 ===${NC}"
    
    if ! nc -z "$SERVER" "$IMAP_PORT" 2>/dev/null; then
        echo -e "${RED}IMAP 服务不可用，跳过测试${NC}"
        return 1
    fi
    
    echo "连接到 IMAP 服务器..."
    
    # 创建 IMAP 命令脚本
    cat > /tmp/imap_commands.txt << EOF
A001 LOGIN $USERNAME $PASSWORD
A002 SELECT INBOX
A003 FETCH 1 BODY[]
A004 LOGOUT
EOF
    
    echo -e "${BLUE}执行 IMAP 命令:${NC}"
    echo "A001 LOGIN $USERNAME $PASSWORD"
    echo "A002 SELECT INBOX (选择收件箱)"
    echo "A003 FETCH 1 BODY[] (获取第一封邮件内容)"
    echo "A004 LOGOUT"
    echo ""
    
    # 执行 IMAP 测试
    echo -e "${BLUE}IMAP 服务器响应:${NC}"
    (
        sleep 1
        while IFS= read -r cmd; do
            echo "$cmd"
            sleep 1
        done < /tmp/imap_commands.txt
    ) | telnet "$SERVER" "$IMAP_PORT" 2>/dev/null | grep -v "^Trying\|^Connected\|^Escape"
    
    # 清理临时文件
    rm -f /tmp/imap_commands.txt
    
    echo -e "${GREEN}IMAP 测试完成${NC}"
    echo ""
}

# 简化的 POP3 测试（仅检查连接和认证）
test_pop3_simple() {
    echo -e "${YELLOW}=== POP3 简单连接测试 ===${NC}"
    
    echo "测试 POP3 连接和认证..."
    
    {
        echo "USER $USERNAME"
        sleep 1
        echo "PASS $PASSWORD"
        sleep 1
        echo "STAT"
        sleep 1
        echo "QUIT"
    } | nc "$SERVER" "$POP3_PORT" 2>/dev/null
    
    echo -e "${GREEN}POP3 简单测试完成${NC}"
    echo ""
}

# 简化的 IMAP 测试（仅检查连接和认证）
test_imap_simple() {
    echo -e "${YELLOW}=== IMAP 简单连接测试 ===${NC}"
    
    echo "测试 IMAP 连接和认证..."
    
    {
        echo "A001 LOGIN $USERNAME $PASSWORD"
        sleep 1
        echo "A002 SELECT INBOX"
        sleep 1
        echo "A003 LOGOUT"
    } | nc "$SERVER" "$IMAP_PORT" 2>/dev/null
    
    echo -e "${GREEN}IMAP 简单测试完成${NC}"
    echo ""
}

# 邮箱状态检查
check_mailbox_status() {
    echo -e "${YELLOW}=== 邮箱状态检查 ===${NC}"
    
    echo "检查 POP3 邮箱状态..."
    {
        echo "USER $USERNAME"
        sleep 1
        echo "PASS $PASSWORD"
        sleep 1
        echo "STAT"
        sleep 1
        echo "LIST"
        sleep 1
        echo "QUIT"
    } | nc "$SERVER" "$POP3_PORT" 2>/dev/null | grep -E "^\+OK|^[0-9]"
    
    echo ""
    echo "检查 IMAP 邮箱状态..."
    {
        echo "A001 LOGIN $USERNAME $PASSWORD"
        sleep 1
        echo "A002 STATUS INBOX (MESSAGES UNSEEN)"
        sleep 1
        echo "A003 LOGOUT"
    } | nc "$SERVER" "$IMAP_PORT" 2>/dev/null | grep -E "^\* STATUS|^A00[0-9] OK"
    
    echo -e "${GREEN}邮箱状态检查完成${NC}"
    echo ""
}

# 主程序
main() {
    check_tools
    check_services
    
    echo "请选择测试类型："
    echo "1) POP3 完整测试"
    echo "2) IMAP 完整测试"
    echo "3) POP3 简单测试"
    echo "4) IMAP 简单测试"
    echo "5) 邮箱状态检查"
    echo "6) 运行所有测试"
    echo "q) 退出"
    echo ""
    
    read -p "请输入选择 [1-6/q]: " choice
    
    case $choice in
        1)
            test_pop3
            ;;
        2)
            test_imap
            ;;
        3)
            test_pop3_simple
            ;;
        4)
            test_imap_simple
            ;;
        5)
            check_mailbox_status
            ;;
        6)
            test_pop3_simple
            test_imap_simple
            check_mailbox_status
            echo -e "${BLUE}如需查看完整邮件内容，请选择选项 1 或 2${NC}"
            ;;
        q|Q)
            echo "退出测试"
            exit 0
            ;;
        *)
            echo -e "${RED}无效选择${NC}"
            exit 1
            ;;
    esac
    
    echo ""
    echo -e "${GREEN}=== 邮件收取验证完成 ===${NC}"
    echo "提示："
    echo "- 如果看到 '+OK' 或 'A001 OK' 响应，说明操作成功"
    echo "- 查看 Zeek 日志了解协议分析结果"
    echo "- 使用 './test-mail-delivery.sh' 发送更多测试邮件"
}

# 运行主程序
main