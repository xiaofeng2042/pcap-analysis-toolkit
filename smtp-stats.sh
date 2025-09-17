#!/bin/bash
# SMTP加密/非加密统计脚本
# 分析STARTTLS场景下的SMTP流量统计

echo "=== SMTP流量统计分析 ==="
echo

# 检查必要的日志文件
if [ ! -f "smtp.log" ] || [ ! -f "ssl.log" ] || [ ! -f "notice.log" ]; then
    echo "错误: 缺少必要的日志文件 (smtp.log, ssl.log, notice.log)"
    exit 1
fi

# 1. 统计有明文SMTP活动的连接
echo "1. 明文SMTP连接统计:"
smtp_uids=$(jq -r '.uid' smtp.log | sort -u)
smtp_count=$(echo "$smtp_uids" | wc -l)
echo "   总SMTP连接数: $smtp_count"

# 2. 统计TLS握手成功的SMTP连接
echo
echo "2. TLS加密SMTP连接统计:"
tls_uids=$(jq -r 'select(.["id.resp_p"] == 2525 and .established == true) | .uid' ssl.log 2>/dev/null | sort -u)
tls_count=$(echo "$tls_uids" | grep -v '^$' | wc -l)
echo "   TLS握手成功数: $tls_count"

# 3. 统计STARTTLS事件
echo
echo "3. STARTTLS事件统计:"
starttls_offered=$(jq -r 'select(.note == "SMTPSTAT::STARTTLS_Offered") | .uid' notice.log 2>/dev/null | wc -l)
starttls_succeeded=$(jq -r 'select(.note == "SMTPSTAT::STARTTLS_Succeeded") | .uid' notice.log 2>/dev/null | wc -l)
echo "   STARTTLS提供次数: $starttls_offered"
echo "   STARTTLS成功次数: $starttls_succeeded"

# 4. 交集分析 - 明文升级为加密的连接
echo
echo "4. 连接类型分析:"
if [ -n "$smtp_uids" ] && [ -n "$tls_uids" ]; then
    # 创建临时文件
    echo "$smtp_uids" > /tmp/smtp_uids.txt
    echo "$tls_uids" > /tmp/tls_uids.txt
    
    # 计算交集和差集
    encrypted_count=$(comm -12 /tmp/smtp_uids.txt /tmp/tls_uids.txt | wc -l)
    plaintext_count=$(comm -23 /tmp/smtp_uids.txt /tmp/tls_uids.txt | wc -l)
    
    echo "   加密SMTP连接 (明文→TLS): $encrypted_count"
    echo "   纯明文SMTP连接: $plaintext_count"
    
    # 清理临时文件
    rm -f /tmp/smtp_uids.txt /tmp/tls_uids.txt
else
    echo "   无法计算连接类型统计"
fi

# 5. 详细连接信息
echo
echo "5. 详细连接信息:"
echo "   SMTP连接详情:"
jq -r '"   UID: " + .uid + " | HELO: " + (.helo // "N/A") + " | TLS: " + (.tls | tostring)' smtp.log 2>/dev/null

echo
echo "   TLS连接详情:"
jq -r '"   UID: " + .uid + " | 版本: " + (.version // "N/A") + " | 密码套件: " + (.cipher // "N/A")' ssl.log 2>/dev/null

# 6. 时间线分析
echo
echo "6. 时间线分析:"
echo "   按时间戳排序的事件:"
{
    jq -r '"SMTP " + (.ts | tostring) + " " + .uid + " HELO:" + (.helo // "N/A")' smtp.log 2>/dev/null
    jq -r '"TLS  " + (.ts | tostring) + " " + .uid + " " + (.version // "N/A")' ssl.log 2>/dev/null
    jq -r '"NOTICE " + (.ts | tostring) + " " + .uid + " " + .note' notice.log 2>/dev/null
} | sort -k2 -n

echo
echo "=== 统计完成 ==="