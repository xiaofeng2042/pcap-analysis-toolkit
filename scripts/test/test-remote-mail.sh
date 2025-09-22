#!/bin/bash

# 远程邮件服务器测试脚本
# 用于测试远程邮件服务器 192.168.1.189 的连接和功能

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 远程服务器配置
REMOTE_SERVER="192.168.1.189"
SMTP_PORT="25"
POP3_PORT="110"
IMAP_PORT="143"

echo -e "${BLUE}=== 远程邮件服务器测试 ===${NC}"
echo "目标服务器: $REMOTE_SERVER"
echo ""

# 检查网络连接
check_network() {
    echo -e "${YELLOW}[INFO] 检查网络连接...${NC}"
    
    if ping -c 3 "$REMOTE_SERVER" &>/dev/null; then
        echo -e "${GREEN}✅ 网络连接正常${NC}"
    else
        echo -e "${RED}❌ 无法连接到远程服务器${NC}"
        exit 1
    fi
}

# 检查端口可用性
check_ports() {
    echo -e "${YELLOW}[INFO] 检查邮件服务端口...${NC}"
    
    # 检查SMTP端口
    if nc -z "$REMOTE_SERVER" "$SMTP_PORT" 2>/dev/null; then
        echo -e "${GREEN}✅ SMTP 端口 ($SMTP_PORT) 可访问${NC}"
    else
        echo -e "${RED}❌ SMTP 端口 ($SMTP_PORT) 不可访问${NC}"
    fi
    
    # 检查POP3端口
    if nc -z "$REMOTE_SERVER" "$POP3_PORT" 2>/dev/null; then
        echo -e "${GREEN}✅ POP3 端口 ($POP3_PORT) 可访问${NC}"
    else
        echo -e "${RED}❌ POP3 端口 ($POP3_PORT) 不可访问${NC}"
    fi
    
    # 检查IMAP端口
    if nc -z "$REMOTE_SERVER" "$IMAP_PORT" 2>/dev/null; then
        echo -e "${GREEN}✅ IMAP 端口 ($IMAP_PORT) 可访问${NC}"
    else
        echo -e "${RED}❌ IMAP 端口 ($IMAP_PORT) 不可访问${NC}"
    fi
}

# 测试SMTP连接
test_smtp() {
    echo -e "${YELLOW}[INFO] 测试SMTP连接...${NC}"
    
    # 使用telnet测试SMTP握手
    {
        echo "EHLO test.local"
        sleep 1
        echo "QUIT"
    } | telnet "$REMOTE_SERVER" "$SMTP_PORT" 2>/dev/null | grep -q "220"
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅ SMTP 握手成功${NC}"
    else
        echo -e "${RED}❌ SMTP 握手失败${NC}"
    fi
}

# 测试POP3连接
test_pop3() {
    echo -e "${YELLOW}[INFO] 测试POP3连接...${NC}"
    
    # 使用telnet测试POP3握手
    {
        echo "QUIT"
    } | telnet "$REMOTE_SERVER" "$POP3_PORT" 2>/dev/null | grep -q "+OK"
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅ POP3 握手成功${NC}"
    else
        echo -e "${RED}❌ POP3 握手失败${NC}"
    fi
}

# 运行SMTP测试
run_smtp_test() {
    echo -e "${YELLOW}[INFO] 运行SMTP邮件发送测试...${NC}"
    ./test-smtp.sh remote
}

# 运行POP3测试
run_pop3_test() {
    echo -e "${YELLOW}[INFO] 运行POP3邮件接收测试...${NC}"
    ./test-pop3.sh remote
}

# 显示使用说明
show_usage() {
    echo -e "${BLUE}使用说明：${NC}"
    echo "  $0                    # 运行完整测试"
    echo "  $0 check             # 仅检查连接和端口"
    echo "  $0 smtp              # 仅测试SMTP"
    echo "  $0 pop3              # 仅测试POP3"
    echo "  $0 send              # 发送测试邮件"
    echo "  $0 receive           # 接收测试邮件"
    echo ""
    echo -e "${YELLOW}环境变量配置：${NC}"
    echo "  REMOTE_SERVER=x.x.x.x    # 指定远程服务器IP"
    echo "  SMTP_PORT=25             # 指定SMTP端口"
    echo "  POP3_PORT=110            # 指定POP3端口"
}

# 主函数
main() {
    case "$1" in
        "check")
            check_network
            check_ports
            test_smtp
            test_pop3
            ;;
        "smtp")
            check_network
            run_smtp_test
            ;;
        "pop3")
            check_network
            run_pop3_test
            ;;
        "send")
            check_network
            run_smtp_test
            ;;
        "receive")
            check_network
            run_pop3_test
            ;;
        "help"|"-h"|"--help")
            show_usage
            ;;
        "")
            # 完整测试流程
            check_network
            check_ports
            test_smtp
            test_pop3
            echo ""
            echo -e "${BLUE}=== 可选的详细测试 ===${NC}"
            echo "运行 '$0 send' 发送测试邮件"
            echo "运行 '$0 receive' 接收测试邮件"
            ;;
        *)
            echo -e "${RED}未知参数: $1${NC}"
            show_usage
            exit 1
            ;;
    esac
}

# 检查必要工具
if ! command -v nc &> /dev/null; then
    echo -e "${RED}❌ netcat 未安装${NC}"
    exit 1
fi

if ! command -v telnet &> /dev/null; then
    echo -e "${RED}❌ telnet 未安装${NC}"
    exit 1
fi

# 运行主函数
main "$@"

echo ""
echo -e "${BLUE}=== 远程测试完成 ===${NC}"