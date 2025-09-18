#!/bin/bash

# 邮件投递测试脚本
# 使用 swaks 向 GreenMail 发送测试邮件

# 默认配置
SMTP_SERVER="127.0.0.1"
SMTP_PORT="3025"
FROM_ADDR="demo@local"
TO_ADDR="test@local"
SUBJECT="Inbound Test $(date '+%Y-%m-%d %H:%M:%S')"

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=== 邮件投递测试 ==="

# 检查 swaks 是否安装
if ! command -v swaks &> /dev/null; then
    echo -e "${RED}错误: swaks 未安装${NC}"
    echo "安装方法："
    echo "  macOS: brew install swaks"
    echo "  Ubuntu: sudo apt-get install swaks"
    echo "  CentOS: sudo yum install swaks"
    exit 1
fi

# 检查 GreenMail 是否运行
if ! nc -z "$SMTP_SERVER" "$SMTP_PORT" 2>/dev/null; then
    echo -e "${RED}错误: GreenMail SMTP 服务未运行 ($SMTP_SERVER:$SMTP_PORT)${NC}"
    echo "请先运行: ./start-greenmail.sh"
    exit 1
fi

echo -e "${GREEN}✅ GreenMail SMTP 服务正在运行${NC}"

# 函数：发送简单测试邮件
send_simple_mail() {
    echo ""
    echo -e "${YELLOW}发送简单测试邮件...${NC}"
    
    swaks --to "$TO_ADDR" \
          --from "$FROM_ADDR" \
          --server "$SMTP_SERVER:$SMTP_PORT" \
          --data "Subject: $SUBJECT

这是一封测试邮件。

发送时间: $(date)
测试类型: 简单文本邮件
收件人: $TO_ADDR
发件人: $FROM_ADDR

-- 
邮件投递测试系统"
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅ 简单邮件发送成功${NC}"
    else
        echo -e "${RED}❌ 简单邮件发送失败${NC}"
    fi
}

# 函数：发送带附件的邮件
send_mail_with_attachment() {
    echo ""
    echo -e "${YELLOW}发送带附件的测试邮件...${NC}"
    
    # 创建临时附件
    local temp_file="/tmp/test_attachment.txt"
    echo "这是一个测试附件文件
创建时间: $(date)
文件大小: 约100字节" > "$temp_file"
    
    swaks --to "$TO_ADDR" \
          --from "$FROM_ADDR" \
          --server "$SMTP_SERVER:$SMTP_PORT" \
          --attach "$temp_file" \
          --data "Subject: $SUBJECT - 带附件

这是一封带附件的测试邮件。

附件信息:
- 文件名: test_attachment.txt
- 类型: 文本文件
- 大小: 约100字节

-- 
邮件投递测试系统"
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅ 带附件邮件发送成功${NC}"
    else
        echo -e "${RED}❌ 带附件邮件发送失败${NC}"
    fi
    
    # 清理临时文件
    rm -f "$temp_file"
}

# 函数：发送 HTML 邮件
send_html_mail() {
    echo ""
    echo -e "${YELLOW}发送 HTML 格式邮件...${NC}"
    
    swaks --to "$TO_ADDR" \
          --from "$FROM_ADDR" \
          --server "$SMTP_SERVER:$SMTP_PORT" \
          --add-header "Content-Type: text/html; charset=UTF-8" \
          --data "Subject: $SUBJECT - HTML格式

<!DOCTYPE html>
<html>
<head>
    <meta charset=\"UTF-8\">
    <title>测试邮件</title>
</head>
<body>
    <h1 style=\"color: #2E86AB;\">HTML 测试邮件</h1>
    <p>这是一封 <strong>HTML 格式</strong>的测试邮件。</p>
    
    <h2>测试信息</h2>
    <ul>
        <li><strong>发送时间:</strong> $(date)</li>
        <li><strong>收件人:</strong> $TO_ADDR</li>
        <li><strong>发件人:</strong> $FROM_ADDR</li>
        <li><strong>服务器:</strong> $SMTP_SERVER:$SMTP_PORT</li>
    </ul>
    
    <p style=\"color: #A23B72;\">如果您能看到这些样式，说明 HTML 邮件解析正常。</p>
    
    <hr>
    <p><em>邮件投递测试系统</em></p>
</body>
</html>"
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅ HTML 邮件发送成功${NC}"
    else
        echo -e "${RED}❌ HTML 邮件发送失败${NC}"
    fi
}

# 函数：批量发送邮件
send_batch_mails() {
    echo ""
    echo -e "${YELLOW}批量发送测试邮件 (5封)...${NC}"
    
    for i in {1..5}; do
        echo "发送第 $i 封邮件..."
        swaks --to "$TO_ADDR" \
              --from "$FROM_ADDR" \
              --server "$SMTP_SERVER:$SMTP_PORT" \
              --data "Subject: 批量测试邮件 #$i - $(date '+%H:%M:%S')

这是第 $i 封批量测试邮件。

批次信息:
- 邮件编号: $i/5
- 发送时间: $(date)
- 测试目的: 验证批量邮件处理能力

-- 
邮件投递测试系统" \
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

# 主菜单
echo ""
echo "请选择测试类型："
echo "1) 发送简单文本邮件"
echo "2) 发送带附件邮件"
echo "3) 发送 HTML 格式邮件"
echo "4) 批量发送邮件 (5封)"
echo "5) 运行所有测试"
echo "q) 退出"
echo ""

read -p "请输入选择 [1-5/q]: " choice

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
        send_simple_mail
        send_mail_with_attachment
        send_html_mail
        send_batch_mails
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
echo -e "${GREEN}=== 邮件投递测试完成 ===${NC}"
echo "提示："
echo "- 使用 './test-mail-retrieval.sh' 验证邮件接收"
echo "- 查看 Zeek 日志了解流量分析结果"