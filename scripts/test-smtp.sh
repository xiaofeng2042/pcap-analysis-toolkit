#!/bin/bash

# SMTP 邮件发送测试脚本
# 用于测试 GreenMail SMTP 服务和 Zeek 监控

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 配置参数
SMTP_SERVER="localhost"
SMTP_PORT="3025"
FROM_ADDR="test@localhost.local"
TO_ADDR="demo@localhost.local"

echo -e "${BLUE}=== SMTP 邮件发送测试 ===${NC}"
echo "服务器: $SMTP_SERVER:$SMTP_PORT"
echo "发件人: $FROM_ADDR"
echo "收件人: $TO_ADDR"
echo ""

# 检查必要工具
check_tools() {
    echo "检查必要工具..."
    
    if ! command -v swaks &> /dev/null; then
        echo -e "${RED}❌ swaks 未安装${NC}"
        echo "请安装 swaks: brew install swaks"
        exit 1
    fi
    
    if ! command -v nc &> /dev/null; then
        echo -e "${RED}❌ netcat 未安装${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✅ 工具检查完成${NC}"
}

# 检查 SMTP 服务
check_smtp_service() {
    echo "检查 SMTP 服务..."
    
    if nc -z "$SMTP_SERVER" "$SMTP_PORT" 2>/dev/null; then
        echo -e "${GREEN}✅ SMTP 服务 ($SMTP_SERVER:$SMTP_PORT) 可访问${NC}"
    else
        echo -e "${RED}❌ SMTP 服务不可访问${NC}"
        echo "请确保 GreenMail 服务正在运行："
        echo "docker compose -f docker/greenmail/docker-compose.yml up -d"
        exit 1
    fi
    echo ""
}

# 发送简单文本邮件
send_simple_mail() {
    echo -e "${YELLOW}发送简单文本邮件...${NC}"
    
    swaks --to "$TO_ADDR" \
          --from "$FROM_ADDR" \
          --server "$SMTP_SERVER:$SMTP_PORT" \
          --data "Subject: SMTP 测试邮件 - $(date '+%Y-%m-%d %H:%M:%S')

这是一封 SMTP 测试邮件。

测试信息:
- 发送时间: $(date)
- 服务器: $SMTP_SERVER:$SMTP_PORT
- 协议: SMTP
- 测试目的: 验证基本邮件发送功能

-- 
SMTP 测试系统"

    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅ 简单文本邮件发送成功${NC}"
    else
        echo -e "${RED}❌ 简单文本邮件发送失败${NC}"
    fi
}

# 发送带附件的邮件
send_mail_with_attachment() {
    echo -e "${YELLOW}发送带附件邮件...${NC}"
    
    # 创建临时附件
    TEMP_FILE="/tmp/smtp_test_attachment.txt"
    echo "这是一个测试附件文件
创建时间: $(date)
文件大小: 约100字节
用途: SMTP 附件传输测试" > "$TEMP_FILE"
    
    swaks --to "$TO_ADDR" \
          --from "$FROM_ADDR" \
          --server "$SMTP_SERVER:$SMTP_PORT" \
          --attach "$TEMP_FILE" \
          --data "Subject: SMTP 附件测试 - $(date '+%Y-%m-%d %H:%M:%S')

这是一封带附件的 SMTP 测试邮件。

附件信息:
- 文件名: smtp_test_attachment.txt
- 文件大小: ~100 字节
- 内容类型: 文本文件

请检查附件是否正确接收。

-- 
SMTP 测试系统"

    # 清理临时文件
    rm -f "$TEMP_FILE"

    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅ 带附件邮件发送成功${NC}"
    else
        echo -e "${RED}❌ 带附件邮件发送失败${NC}"
    fi
}

# 发送 HTML 格式邮件
send_html_mail() {
    echo -e "${YELLOW}发送 HTML 格式邮件...${NC}"
    
    swaks --to "$TO_ADDR" \
          --from "$FROM_ADDR" \
          --server "$SMTP_SERVER:$SMTP_PORT" \
          --add-header "Content-Type: text/html; charset=UTF-8" \
          --data "Subject: SMTP HTML 测试 - $(date '+%Y-%m-%d %H:%M:%S')
Content-Type: text/html; charset=UTF-8

<!DOCTYPE html>
<html>
<head>
    <title>SMTP HTML 测试邮件</title>
</head>
<body>
    <h1 style='color: #2E86AB;'>SMTP HTML 测试邮件</h1>
    
    <p>这是一封 <strong>HTML 格式</strong>的测试邮件。</p>
    
    <h2>测试信息</h2>
    <ul>
        <li><strong>发送时间:</strong> $(date)</li>
        <li><strong>服务器:</strong> $SMTP_SERVER:$SMTP_PORT</li>
        <li><strong>协议:</strong> SMTP</li>
        <li><strong>格式:</strong> HTML</li>
    </ul>
    
    <p style='color: #A23B72;'>如果您能看到这些样式，说明 HTML 邮件解析正常。</p>
    
    <hr>
    <p><em>SMTP 测试系统</em></p>
</body>
</html>"

    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅ HTML 邮件发送成功${NC}"
    else
        echo -e "${RED}❌ HTML 邮件发送失败${NC}"
    fi
}

# 批量发送邮件
send_batch_mails() {
    echo -e "${YELLOW}批量发送测试邮件 (3封)...${NC}"
    
    for i in {1..3}; do
        echo "发送第 $i 封邮件..."
        swaks --to "$TO_ADDR" \
              --from "$FROM_ADDR" \
              --server "$SMTP_SERVER:$SMTP_PORT" \
              --data "Subject: 批量测试邮件 #$i - $(date '+%H:%M:%S')

这是第 $i 封批量测试邮件。

批次信息:
- 邮件编号: $i/3
- 发送时间: $(date)
- 测试目的: 验证批量邮件处理能力

-- 
SMTP 测试系统" \
              --silent
        
        if [ $? -eq 0 ]; then
            echo -e "  ${GREEN}✅ 第 $i 封邮件发送成功${NC}"
        else
            echo -e "  ${RED}❌ 第 $i 封邮件发送失败${NC}"
        fi
        
        # 短暂延迟
        sleep 1
    done
}

# 测试原始 SMTP 协议
test_raw_smtp() {
    echo -e "${YELLOW}测试原始 SMTP 协议交互...${NC}"
    
    {
        sleep 1
        echo "HELO localhost"
        sleep 1
        echo "MAIL FROM:<$FROM_ADDR>"
        sleep 1
        echo "RCPT TO:<$TO_ADDR>"
        sleep 1
        echo "DATA"
        sleep 1
        echo "Subject: 原始 SMTP 测试 - $(date '+%Y-%m-%d %H:%M:%S')"
        echo ""
        echo "这是通过原始 SMTP 协议发送的测试邮件。"
        echo ""
        echo "测试时间: $(date)"
        echo "协议: 原始 SMTP 命令"
        echo ""
        echo "-- "
        echo "SMTP 协议测试"
        echo "."
        sleep 1
        echo "QUIT"
    } | nc "$SMTP_SERVER" "$SMTP_PORT"
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅ 原始 SMTP 协议测试完成${NC}"
    else
        echo -e "${RED}❌ 原始 SMTP 协议测试失败${NC}"
    fi
}

# 主菜单
main() {
    check_tools
    check_smtp_service
    
    echo "请选择测试类型："
    echo "1) 发送简单文本邮件"
    echo "2) 发送带附件邮件"
    echo "3) 发送 HTML 格式邮件"
    echo "4) 批量发送邮件 (3封)"
    echo "5) 测试原始 SMTP 协议"
    echo "6) 运行所有测试"
    echo "q) 退出"
    echo ""
    
    read -p "请输入选择 [1-6/q]: " choice
    
    case $choice in
        1)
            send_simple_mail
            ;;
        2)
            send_mail_with_attachment
            ;;
        3)
            send_html_mail
            ;;
        4)
            send_batch_mails
            ;;
        5)
            test_raw_smtp
            ;;
        6)
            send_simple_mail
            echo ""
            send_mail_with_attachment
            echo ""
            send_html_mail
            echo ""
            send_batch_mails
            echo ""
            test_raw_smtp
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
    echo -e "${GREEN}=== SMTP 测试完成 ===${NC}"
    echo "提示："
    echo "- 使用 './test-pop3.sh' 验证邮件接收"
    echo "- 查看 Zeek 日志了解流量分析结果"
    echo "- 检查 output/ 目录中的监控日志"
}

# 运行主程序
main