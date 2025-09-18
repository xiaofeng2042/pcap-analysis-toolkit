#!/bin/bash

# POP3 邮件接收测试脚本
# 用于测试 GreenMail POP3 服务和 Zeek 监控

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 配置参数
POP3_SERVER="localhost"
POP3_PORT="3110"
USERNAME="demo"
PASSWORD="demo"

echo -e "${BLUE}=== POP3 邮件接收测试 ===${NC}"
echo "服务器: $POP3_SERVER:$POP3_PORT"
echo "用户名: $USERNAME"
echo ""

# 检查必要工具
check_tools() {
    echo "检查必要工具..."
    
    if ! command -v nc &> /dev/null; then
        echo -e "${RED}❌ netcat 未安装${NC}"
        exit 1
    fi
    
    if ! command -v telnet &> /dev/null; then
        echo -e "${YELLOW}⚠️  telnet 未安装，将使用 nc 替代${NC}"
    fi
    
    echo -e "${GREEN}✅ 工具检查完成${NC}"
}

# 检查 POP3 服务
check_pop3_service() {
    echo "检查 POP3 服务..."
    
    if nc -z "$POP3_SERVER" "$POP3_PORT" 2>/dev/null; then
        echo -e "${GREEN}✅ POP3 服务 ($POP3_SERVER:$POP3_PORT) 可访问${NC}"
    else
        echo -e "${RED}❌ POP3 服务不可访问${NC}"
        echo "请确保 GreenMail 服务正在运行："
        echo "docker compose -f docker/greenmail/docker-compose.yml up -d"
        exit 1
    fi
    echo ""
}

# POP3 连接测试
test_pop3_connection() {
    echo -e "${YELLOW}测试 POP3 连接...${NC}"
    
    response=$(echo "QUIT" | nc "$POP3_SERVER" "$POP3_PORT" 2>/dev/null | head -1)
    
    if [[ $response == *"+OK"* ]]; then
        echo -e "${GREEN}✅ POP3 连接成功${NC}"
        echo "服务器响应: $response"
    else
        echo -e "${RED}❌ POP3 连接失败${NC}"
        echo "服务器响应: $response"
        return 1
    fi
}

# POP3 认证测试
test_pop3_auth() {
    echo -e "${YELLOW}测试 POP3 认证...${NC}"
    
    {
        sleep 1
        echo "USER $USERNAME"
        sleep 1
        echo "PASS $PASSWORD"
        sleep 1
        echo "QUIT"
    } | nc "$POP3_SERVER" "$POP3_PORT" 2>/dev/null > /tmp/pop3_auth_test.log
    
    if awk '/^\+OK($| .*)/ { ok_count++ } END { exit ok_count < 3 }' /tmp/pop3_auth_test.log; then
        echo -e "${GREEN}✅ POP3 认证成功${NC}"
        echo "服务器响应:"
        grep '^\+OK' /tmp/pop3_auth_test.log
    else
        echo -e "${RED}❌ POP3 认证失败${NC}"
        echo "完整响应:"
        cat /tmp/pop3_auth_test.log
    fi
    
    rm -f /tmp/pop3_auth_test.log
}

# 检查邮箱状态
check_mailbox_status() {
    echo -e "${YELLOW}检查邮箱状态...${NC}"
    
    {
        sleep 1
        echo "USER $USERNAME"
        sleep 1
        echo "PASS $PASSWORD"
        sleep 1
        echo "STAT"
        sleep 1
        echo "LIST"
        sleep 1
        echo "QUIT"
    } | nc "$POP3_SERVER" "$POP3_PORT" 2>/dev/null > /tmp/pop3_status.log
    
    echo "邮箱统计信息:"
    grep "^+OK.*messages" /tmp/pop3_status.log || echo "未找到邮件统计"
    
    echo ""
    echo "邮件列表:"
    grep "^[0-9]" /tmp/pop3_status.log | head -10 || echo "邮箱为空或无法获取邮件列表"
    
    rm -f /tmp/pop3_status.log
}

# 接收邮件头信息
retrieve_mail_headers() {
    echo -e "${YELLOW}获取邮件头信息...${NC}"
    
    {
        sleep 1
        echo "USER $USERNAME"
        sleep 1
        echo "PASS $PASSWORD"
        sleep 1
        echo "LIST"
        sleep 1
        echo "TOP 1 0"  # 获取第一封邮件的头信息
        sleep 1
        echo "QUIT"
    } | nc "$POP3_SERVER" "$POP3_PORT" 2>/dev/null > /tmp/pop3_headers.log
    
    if grep -q "^+OK.*octets" /tmp/pop3_headers.log; then
        echo -e "${GREEN}✅ 成功获取邮件头${NC}"
        echo ""
        echo "邮件头信息:"
        sed -n '/^+OK.*octets/,/^\./p' /tmp/pop3_headers.log | grep -E "^(Subject|From|To|Date):" | head -10
    else
        echo -e "${YELLOW}⚠️  没有邮件或无法获取邮件头${NC}"
        echo "建议先使用 test-smtp.sh 发送测试邮件"
    fi
    
    rm -f /tmp/pop3_headers.log
}

# 接收完整邮件
retrieve_full_mail() {
    echo -e "${YELLOW}接收完整邮件内容...${NC}"
    
    {
        sleep 1
        echo "USER $USERNAME"
        sleep 1
        echo "PASS $PASSWORD"
        sleep 1
        echo "RETR 1"  # 获取第一封邮件的完整内容
        sleep 1
        echo "QUIT"
    } | nc "$POP3_SERVER" "$POP3_PORT" 2>/dev/null > /tmp/pop3_full_mail.log
    
    if grep -q "^+OK.*octets" /tmp/pop3_full_mail.log; then
        echo -e "${GREEN}✅ 成功接收邮件${NC}"
        echo ""
        echo "邮件内容 (前20行):"
        sed -n '/^+OK.*octets/,/^\./p' /tmp/pop3_full_mail.log | head -20
        echo ""
        echo "完整邮件已保存到: /tmp/pop3_full_mail.log"
    else
        echo -e "${YELLOW}⚠️  没有邮件可接收${NC}"
        echo "建议先使用 test-smtp.sh 发送测试邮件"
    fi
    
    # 不删除文件，供用户查看
    echo "提示: 使用 'cat /tmp/pop3_full_mail.log' 查看完整邮件内容"
}

# 删除邮件测试
test_mail_deletion() {
    echo -e "${YELLOW}测试邮件删除功能...${NC}"
    
    # 首先检查是否有邮件
    mail_count=$({
        sleep 1
        echo "USER $USERNAME"
        sleep 1
        echo "PASS $PASSWORD"
        sleep 1
        echo "STAT"
        sleep 1
        echo "QUIT"
    } | nc "$POP3_SERVER" "$POP3_PORT" 2>/dev/null | grep "^+OK.*messages" | awk '{print $2}')
    
    if [[ "$mail_count" =~ ^[0-9]+$ ]] && [ "$mail_count" -gt 0 ]; then
        echo "发现 $mail_count 封邮件，测试删除最后一封..."
        
        {
            sleep 1
            echo "USER $USERNAME"
            sleep 1
            echo "PASS $PASSWORD"
            sleep 1
            echo "DELE $mail_count"  # 删除最后一封邮件
            sleep 1
            echo "STAT"  # 检查删除后的状态
            sleep 1
            echo "QUIT"
        } | nc "$POP3_SERVER" "$POP3_PORT" 2>/dev/null > /tmp/pop3_delete.log
        
        if grep -q "+OK.*deleted" /tmp/pop3_delete.log; then
            echo -e "${GREEN}✅ 邮件删除成功${NC}"
            grep "+OK" /tmp/pop3_delete.log | tail -2
        else
            echo -e "${RED}❌ 邮件删除失败${NC}"
            cat /tmp/pop3_delete.log
        fi
        
        rm -f /tmp/pop3_delete.log
    else
        echo -e "${YELLOW}⚠️  没有邮件可删除${NC}"
        echo "建议先使用 test-smtp.sh 发送测试邮件"
    fi
}

# 原始 POP3 协议交互
test_raw_pop3() {
    echo -e "${YELLOW}原始 POP3 协议交互演示...${NC}"
    echo "将显示完整的 POP3 协议对话过程"
    echo ""
    
    {
        sleep 1
        echo "USER $USERNAME"
        sleep 1
        echo "PASS $PASSWORD"
        sleep 1
        echo "STAT"
        sleep 1
        echo "LIST"
        sleep 1
        echo "NOOP"  # 无操作命令
        sleep 1
        echo "QUIT"
    } | nc "$POP3_SERVER" "$POP3_PORT" 2>/dev/null
    
    echo ""
    echo -e "${GREEN}✅ 原始 POP3 协议交互完成${NC}"
}

# 主菜单
main() {
    check_tools
    check_pop3_service
    
    echo "请选择测试类型："
    echo "1) POP3 连接测试"
    echo "2) POP3 认证测试"
    echo "3) 检查邮箱状态"
    echo "4) 获取邮件头信息"
    echo "5) 接收完整邮件"
    echo "6) 测试邮件删除"
    echo "7) 原始 POP3 协议交互"
    echo "8) 运行所有测试"
    echo "q) 退出"
    echo ""
    
    read -p "请输入选择 [1-8/q]: " choice
    
    case $choice in
        1)
            test_pop3_connection
            ;;
        2)
            test_pop3_auth
            ;;
        3)
            check_mailbox_status
            ;;
        4)
            retrieve_mail_headers
            ;;
        5)
            retrieve_full_mail
            ;;
        6)
            test_mail_deletion
            ;;
        7)
            test_raw_pop3
            ;;
        8)
            test_pop3_connection
            echo ""
            test_pop3_auth
            echo ""
            check_mailbox_status
            echo ""
            retrieve_mail_headers
            echo ""
            echo "跳过完整邮件接收和删除测试（避免影响邮箱状态）"
            echo ""
            test_raw_pop3
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
    echo -e "${GREEN}=== POP3 测试完成 ===${NC}"
    echo "提示："
    echo "- 使用 './test-smtp.sh' 发送测试邮件"
    echo "- 查看 Zeek 日志了解流量分析结果"
    echo "- 检查 output/ 目录中的监控日志"
}

# 运行主程序
main
