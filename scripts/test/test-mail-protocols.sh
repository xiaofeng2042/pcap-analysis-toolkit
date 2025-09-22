#!/bin/bash

# 邮件协议综合测试脚本
# 整合 SMTP 和 POP3 测试，配合 Zeek 监控

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# 配置参数
SMTP_SERVER="localhost"
SMTP_PORT="3025"
POP3_SERVER="localhost"
POP3_PORT="3110"
USERNAME="demo"
PASSWORD="demo"
FROM_EMAIL="test@local"
TO_EMAIL="demo@local"

# 脚本路径
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SMTP_SCRIPT="$SCRIPT_DIR/test-smtp.sh"
POP3_SCRIPT="$SCRIPT_DIR/test-pop3.sh"

echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║                    邮件协议综合测试套件                        ║${NC}"
echo -e "${CYAN}║                  SMTP + POP3 + Zeek 监控                     ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# 检查必要工具和服务
check_prerequisites() {
    echo -e "${BLUE}=== 环境检查 ===${NC}"
    
    # 检查脚本文件
    if [[ ! -f "$SMTP_SCRIPT" ]]; then
        echo -e "${RED}❌ SMTP 测试脚本不存在: $SMTP_SCRIPT${NC}"
        exit 1
    fi
    
    if [[ ! -f "$POP3_SCRIPT" ]]; then
        echo -e "${RED}❌ POP3 测试脚本不存在: $POP3_SCRIPT${NC}"
        exit 1
    fi
    
    # 检查工具
    local missing_tools=()
    
    if ! command -v nc &> /dev/null; then
        missing_tools+=("netcat")
    fi
    
    if ! command -v docker &> /dev/null; then
        missing_tools+=("docker")
    fi
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        echo -e "${RED}❌ 缺少必要工具: ${missing_tools[*]}${NC}"
        exit 1
    fi
    
    # 检查 GreenMail 服务
    echo "检查 GreenMail 服务状态..."
    
    if ! nc -z "$SMTP_SERVER" "$SMTP_PORT" 2>/dev/null; then
        echo -e "${RED}❌ SMTP 服务 ($SMTP_SERVER:$SMTP_PORT) 不可访问${NC}"
        echo "尝试启动 GreenMail 服务..."
        docker compose -f docker/greenmail/docker-compose.yml up -d
        sleep 3
        
        if ! nc -z "$SMTP_SERVER" "$SMTP_PORT" 2>/dev/null; then
            echo -e "${RED}❌ 无法启动 SMTP 服务${NC}"
            exit 1
        fi
    fi
    
    if ! nc -z "$POP3_SERVER" "$POP3_PORT" 2>/dev/null; then
        echo -e "${RED}❌ POP3 服务 ($POP3_SERVER:$POP3_PORT) 不可访问${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✅ 环境检查完成${NC}"
    echo ""
}

# 检查 Zeek 监控状态
check_zeek_monitoring() {
    echo -e "${BLUE}=== Zeek 监控状态 ===${NC}"
    
    # 检查是否有 Zeek 进程在运行
    if pgrep -f "zeek.*lo0" > /dev/null; then
        echo -e "${GREEN}✅ Zeek 监控正在运行${NC}"
        
        # 显示最新的输出目录
        latest_output=$(ls -t output/ 2>/dev/null | head -1)
        if [[ -n "$latest_output" ]]; then
            echo "最新监控日志目录: output/$latest_output"
        fi
    else
        echo -e "${YELLOW}⚠️  Zeek 监控未运行${NC}"
        echo "建议在另一个终端运行: sudo ./scripts/run-live.sh lo0"
    fi
    echo ""
}

# 快速连通性测试
quick_connectivity_test() {
    echo -e "${BLUE}=== 快速连通性测试 ===${NC}"
    
    # SMTP 连通性
    echo -n "SMTP 服务连通性... "
    if echo "QUIT" | nc "$SMTP_SERVER" "$SMTP_PORT" 2>/dev/null | grep -q "220"; then
        echo -e "${GREEN}✅ 正常${NC}"
    else
        echo -e "${RED}❌ 异常${NC}"
        return 1
    fi
    
    # POP3 连通性
    echo -n "POP3 服务连通性... "
    if echo "QUIT" | nc "$POP3_SERVER" "$POP3_PORT" 2>/dev/null | grep -q "+OK"; then
        echo -e "${GREEN}✅ 正常${NC}"
    else
        echo -e "${RED}❌ 异常${NC}"
        return 1
    fi
    
    echo ""
}

# 完整邮件流程测试
full_mail_flow_test() {
    echo -e "${PURPLE}=== 完整邮件流程测试 ===${NC}"
    echo "测试流程: 发送邮件 → 等待 → 接收邮件 → 验证"
    echo ""
    
    # 1. 清空邮箱（可选）
    echo "1. 清理邮箱..."
    {
        sleep 1
        echo "USER $USERNAME"
        sleep 1
        echo "PASS $PASSWORD"
        sleep 1
        echo "STAT"
        sleep 1
        echo "QUIT"
    } | nc "$POP3_SERVER" "$POP3_PORT" 2>/dev/null > /tmp/mailbox_before.log
    
    local mail_count_before=$(grep "^+OK.*messages" /tmp/mailbox_before.log | awk '{print $2}' || echo "0")
    echo "发送前邮箱邮件数: $mail_count_before"
    
    # 2. 发送测试邮件
    echo ""
    echo "2. 发送测试邮件..."
    
    local test_subject="Flow-Test-$(date +%s)"
    local test_body="这是完整流程测试邮件，时间戳: $(date)"
    
    {
        sleep 1
        echo "EHLO test-client"
        sleep 1
        echo "MAIL FROM:<$FROM_EMAIL>"
        sleep 1
        echo "RCPT TO:<$TO_EMAIL>"
        sleep 1
        echo "DATA"
        sleep 1
        echo "Subject: $test_subject"
        echo "From: $FROM_EMAIL"
        echo "To: $TO_EMAIL"
        echo "Date: $(date -R)"
        echo ""
        echo "$test_body"
        echo "."
        sleep 1
        echo "QUIT"
    } | nc "$SMTP_SERVER" "$SMTP_PORT" 2>/dev/null > /tmp/smtp_send.log
    
    if grep -q "250.*OK" /tmp/smtp_send.log; then
        echo -e "${GREEN}✅ 邮件发送成功${NC}"
    else
        echo -e "${RED}❌ 邮件发送失败${NC}"
        cat /tmp/smtp_send.log
        return 1
    fi
    
    # 3. 等待邮件处理
    echo ""
    echo "3. 等待邮件处理 (3秒)..."
    sleep 3
    
    # 4. 检查邮件接收
    echo ""
    echo "4. 检查邮件接收..."
    
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
        echo "TOP 1 10"  # 获取最新邮件的头部
        sleep 1
        echo "QUIT"
    } | nc "$POP3_SERVER" "$POP3_PORT" 2>/dev/null > /tmp/mailbox_after.log
    
    local mail_count_after=$(grep "^+OK.*messages" /tmp/mailbox_after.log | awk '{print $2}' || echo "0")
    echo "接收后邮箱邮件数: $mail_count_after"
    
    # 5. 验证邮件内容
    if [[ "$mail_count_after" -gt "$mail_count_before" ]]; then
        echo -e "${GREEN}✅ 邮件接收成功${NC}"
        
        # 检查邮件主题
        if grep -q "$test_subject" /tmp/mailbox_after.log; then
            echo -e "${GREEN}✅ 邮件主题匹配${NC}"
        else
            echo -e "${YELLOW}⚠️  邮件主题不匹配${NC}"
        fi
        
        echo ""
        echo "最新邮件头信息:"
        sed -n '/^+OK.*octets/,/^\./p' /tmp/mailbox_after.log | head -15
        
    else
        echo -e "${RED}❌ 邮件接收失败${NC}"
        return 1
    fi
    
    # 清理临时文件
    rm -f /tmp/smtp_send.log /tmp/mailbox_before.log /tmp/mailbox_after.log
    
    echo ""
    echo -e "${GREEN}✅ 完整邮件流程测试成功${NC}"
}

# 性能压力测试
performance_test() {
    echo -e "${PURPLE}=== 性能压力测试 ===${NC}"
    echo "将发送多封邮件测试系统性能"
    echo ""
    
    read -p "请输入要发送的邮件数量 [默认: 5]: " mail_count
    mail_count=${mail_count:-5}
    
    if ! [[ "$mail_count" =~ ^[0-9]+$ ]] || [ "$mail_count" -lt 1 ] || [ "$mail_count" -gt 50 ]; then
        echo -e "${RED}❌ 无效的邮件数量 (1-50)${NC}"
        return 1
    fi
    
    echo "开始发送 $mail_count 封测试邮件..."
    
    local success_count=0
    local start_time=$(date +%s)
    
    for ((i=1; i<=mail_count; i++)); do
        echo -n "发送邮件 $i/$mail_count... "
        
        local subject="Perf-Test-$i-$(date +%s)"
        local body="性能测试邮件 #$i，发送时间: $(date)"
        
        {
            sleep 0.5
            echo "EHLO test-client"
            sleep 0.5
            echo "MAIL FROM:<$FROM_EMAIL>"
            sleep 0.5
            echo "RCPT TO:<$TO_EMAIL>"
            sleep 0.5
            echo "DATA"
            sleep 0.5
            echo "Subject: $subject"
            echo "From: $FROM_EMAIL"
            echo "To: $TO_EMAIL"
            echo ""
            echo "$body"
            echo "."
            sleep 0.5
            echo "QUIT"
        } | nc "$SMTP_SERVER" "$SMTP_PORT" 2>/dev/null > /tmp/perf_test_$i.log
        
        if grep -q "250.*OK" /tmp/perf_test_$i.log; then
            echo -e "${GREEN}✅${NC}"
            ((success_count++))
        else
            echo -e "${RED}❌${NC}"
        fi
        
        rm -f /tmp/perf_test_$i.log
        
        # 短暂延迟避免过载
        sleep 0.2
    done
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    echo ""
    echo "性能测试结果:"
    echo "- 总邮件数: $mail_count"
    echo "- 成功发送: $success_count"
    echo "- 失败数量: $((mail_count - success_count))"
    echo "- 总耗时: ${duration}秒"
    echo "- 平均速度: $(echo "scale=2; $success_count / $duration" | bc 2>/dev/null || echo "N/A") 邮件/秒"
    
    if [ "$success_count" -eq "$mail_count" ]; then
        echo -e "${GREEN}✅ 性能测试全部成功${NC}"
    else
        echo -e "${YELLOW}⚠️  部分邮件发送失败${NC}"
    fi
}

# 查看 Zeek 日志
view_zeek_logs() {
    echo -e "${BLUE}=== Zeek 监控日志 ===${NC}"
    
    local latest_output=$(ls -t output/ 2>/dev/null | head -1)
    
    if [[ -z "$latest_output" ]]; then
        echo -e "${YELLOW}⚠️  未找到 Zeek 输出目录${NC}"
        echo "请确保已运行: sudo ./scripts/run-live.sh lo0"
        return 1
    fi
    
    local log_dir="output/$latest_output"
    echo "日志目录: $log_dir"
    echo ""
    
    # SMTP 日志
    if [[ -f "$log_dir/smtp.log" ]]; then
        echo "=== SMTP 日志 (最近10条) ==="
        tail -10 "$log_dir/smtp.log" | while IFS=$'\t' read -r ts uid id_orig_h id_orig_p id_resp_h id_resp_p trans_depth helo mailfrom rcptto date from to cc reply_to msg_id in_reply_to subject x_originating_ip first_received second_received last_reply path user_agent tls fuids is_webmail; do
            echo "时间: $(date -r ${ts%.*} 2>/dev/null || echo $ts)"
            echo "发件人: $mailfrom → 收件人: $rcptto"
            echo "主题: $subject"
            echo "---"
        done 2>/dev/null
    else
        echo -e "${YELLOW}⚠️  未找到 SMTP 日志文件${NC}"
    fi
    
    echo ""
    
    # POP3 日志 (如果存在)
    if [[ -f "$log_dir/pop3.log" ]]; then
        echo "=== POP3 日志 (最近5条) ==="
        tail -5 "$log_dir/pop3.log"
    else
        echo -e "${YELLOW}⚠️  未找到 POP3 日志文件${NC}"
    fi
    
    echo ""
    
    # 连接日志
    if [[ -f "$log_dir/conn.log" ]]; then
        echo "=== 邮件相关连接 (最近10条) ==="
        grep -E ":(3025|3110|25|110|465|587|995)" "$log_dir/conn.log" | tail -10 | while IFS=$'\t' read -r ts uid id_orig_h id_orig_p id_resp_h id_resp_p proto service duration orig_bytes resp_bytes conn_state local_orig local_resp missed_bytes history orig_pkts orig_ip_bytes resp_pkts resp_ip_bytes tunnel_parents; do
            echo "$(date -r ${ts%.*} 2>/dev/null || echo $ts): $id_orig_h:$id_orig_p → $id_resp_h:$id_resp_p ($service)"
        done 2>/dev/null
    fi
}

# 主菜单
main_menu() {
    while true; do
        echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${CYAN}║                        主菜单选项                            ║${NC}"
        echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo "1) 环境检查和服务状态"
        echo "2) 快速连通性测试"
        echo "3) 完整邮件流程测试 (推荐)"
        echo "4) SMTP 发送测试 (调用专用脚本)"
        echo "5) POP3 接收测试 (调用专用脚本)"
        echo "6) 性能压力测试"
        echo "7) 查看 Zeek 监控日志"
        echo "8) 运行所有测试"
        echo "q) 退出"
        echo ""
        
        read -p "请选择操作 [1-8/q]: " choice
        echo ""
        
        case $choice in
            1)
                check_prerequisites
                check_zeek_monitoring
                ;;
            2)
                quick_connectivity_test
                ;;
            3)
                full_mail_flow_test
                ;;
            4)
                echo -e "${BLUE}=== 调用 SMTP 测试脚本 ===${NC}"
                if [[ -x "$SMTP_SCRIPT" ]]; then
                    "$SMTP_SCRIPT"
                else
                    echo -e "${RED}❌ SMTP 脚本不可执行${NC}"
                fi
                ;;
            5)
                echo -e "${BLUE}=== 调用 POP3 测试脚本 ===${NC}"
                if [[ -x "$POP3_SCRIPT" ]]; then
                    "$POP3_SCRIPT"
                else
                    echo -e "${RED}❌ POP3 脚本不可执行${NC}"
                fi
                ;;
            6)
                performance_test
                ;;
            7)
                view_zeek_logs
                ;;
            8)
                echo -e "${PURPLE}=== 运行所有测试 ===${NC}"
                check_prerequisites
                check_zeek_monitoring
                quick_connectivity_test
                echo ""
                full_mail_flow_test
                echo ""
                view_zeek_logs
                ;;
            q|Q)
                echo -e "${GREEN}测试完成，感谢使用！${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}❌ 无效选择，请重新输入${NC}"
                ;;
        esac
        
        echo ""
        echo -e "${CYAN}按 Enter 键返回主菜单...${NC}"
        read
        clear
    done
}

# 启动脚本
main() {
    clear
    check_prerequisites
    main_menu
}

# 运行主程序
main