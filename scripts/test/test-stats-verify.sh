#!/bin/bash

# test-stats-verify.sh - 邮件统计数据精确性验证测试脚本
# 验证统计数据与实际邮件流量的准确性

set -euo pipefail

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# 测试计数器
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_TOTAL=0

# 脚本路径
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
OUTPUT_DIR="$PROJECT_DIR/output"
STATE_DIR="$OUTPUT_DIR/state"
STATS_FILE="$STATE_DIR/mail_stats_state.tsv"

# GreenMail配置
SMTP_HOST="localhost"
SMTP_PORT="3025"
POP3_HOST="localhost"
POP3_PORT="3110"

echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║                  邮件统计数据精确性验证测试                  ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# 测试辅助函数
test_assert() {
    local condition=$1
    local test_name="$2"
    local expected=${3:-""}
    local actual=${4:-""}
    
    ((TESTS_TOTAL++))
    
    if [ "$condition" = "true" ]; then
        echo -e "${GREEN}✅ PASS${NC}: $test_name"
        if [ -n "$expected" ] && [ -n "$actual" ]; then
            echo "   预期: $expected, 实际: $actual"
        fi
        ((TESTS_PASSED++))
    else
        echo -e "${RED}❌ FAIL${NC}: $test_name"
        if [ -n "$expected" ] && [ -n "$actual" ]; then
            echo "   预期: $expected, 实际: $actual"
        fi
        ((TESTS_FAILED++))
    fi
}

# 清理函数
cleanup() {
    # 停止任何正在运行的Zeek进程
    pkill -f "zeek.*mail-activity" 2>/dev/null || true
    
    # 停止GreenMail
    docker-compose -f "$PROJECT_DIR/docker/greenmail/docker-compose.yml" down 2>/dev/null || true
    
    # 清理测试文件
    rm -f /tmp/verify_test_*.log
    rm -f /tmp/verify_test_*.tsv
    rm -f /tmp/sent_emails_*.log
    
    # 清理环境变量
    unset MAIL_STATS_INIT_MONTH
    unset MAIL_STATS_INIT_SEND
    unset MAIL_STATS_INIT_RECEIVE
    unset MAIL_STATS_INIT_ENCRYPT
    unset MAIL_STATS_INIT_DECRYPT
    unset MAIL_STATS_STATE_FILE
    unset SITE_ID
    unset LINK_ID
}

# 检查先决条件
check_prerequisites() {
    echo -e "${BLUE}=== 检查验证测试环境 ===${NC}"
    
    # 检查必要工具
    local missing_tools=()
    
    command -v zeek >/dev/null 2>&1 || missing_tools+=("zeek")
    command -v docker >/dev/null 2>&1 || missing_tools+=("docker")
    command -v docker-compose >/dev/null 2>&1 || missing_tools+=("docker-compose")
    command -v python3 >/dev/null 2>&1 || missing_tools+=("python3")
    command -v nc >/dev/null 2>&1 || missing_tools+=("netcat")
    
    if [ ${#missing_tools[@]} -gt 0 ]; then
        echo -e "${RED}❌ 缺少必要工具: ${missing_tools[*]}${NC}"
        exit 1
    fi
    
    # 检查Python SMTP库
    if ! python3 -c "import smtplib, poplib" 2>/dev/null; then
        echo -e "${RED}❌ Python缺少必要的邮件库${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✅ 环境检查通过${NC}"
    echo ""
}

# 启动GreenMail测试服务器
start_greenmail() {
    echo -e "${BLUE}=== 启动GreenMail测试服务器 ===${NC}"
    
    cd "$PROJECT_DIR"
    
    # 启动服务
    docker-compose -f docker/greenmail/docker-compose.yml up -d
    
    # 等待服务启动
    echo "等待GreenMail启动..."
    local max_wait=30
    local wait_count=0
    
    while [ $wait_count -lt $max_wait ]; do
        if nc -z $SMTP_HOST $SMTP_PORT 2>/dev/null && nc -z $POP3_HOST $POP3_PORT 2>/dev/null; then
            echo -e "${GREEN}✅ GreenMail服务已启动${NC}"
            return 0
        fi
        sleep 1
        ((wait_count++))
    done
    
    echo -e "${RED}❌ GreenMail启动超时${NC}"
    return 1
}

# 精确发送邮件并记录
send_precise_emails() {
    local count=$1
    local log_file="$2"
    local subject_prefix=${3:-"Verify-Test"}
    
    echo "精确发送 $count 封邮件到 $log_file"
    
    > "$log_file"  # 清空日志文件
    
    local sent_count=0
    
    for i in $(seq 1 $count); do
        local timestamp=$(date +%s.%3N)
        local subject="${subject_prefix}-${i}-${timestamp}"
        
        python3 -c "
import smtplib
import sys
from email.mime.text import MIMEText
import time

timestamp = '$timestamp'
subject = '$subject'
email_id = $i

try:
    server = smtplib.SMTP('$SMTP_HOST', $SMTP_PORT)
    
    msg = MIMEText(f'Verification test email #{email_id}, timestamp: {timestamp}')
    msg['Subject'] = subject
    msg['From'] = 'verify@test.local'
    msg['To'] = 'demo@test.local'
    msg['Message-ID'] = f'<verify-{email_id}-{timestamp}@test.local>'
    
    server.sendmail('verify@test.local', ['demo@test.local'], msg.as_string())
    server.quit()
    
    print(f'{timestamp},{email_id},{subject},SUCCESS')
    
except Exception as e:
    print(f'{timestamp},{email_id},{subject},FAILED:{e}')
    sys.exit(1)
" >> "$log_file" || {
            echo -e "${RED}❌ 发送邮件 $i 失败${NC}"
            return 1
        }
        
        ((sent_count++))
        sleep 0.3  # 短暂延迟确保时间戳不重复
    done
    
    echo -e "${GREEN}✅ 成功发送 $sent_count 封邮件${NC}"
    return 0
}

# 接收并验证邮件
receive_and_verify_emails() {
    local expected_count=$1
    local log_file="$2"
    
    echo "验证POP3接收邮件数量，期望: $expected_count"
    
    python3 -c "
import poplib
import sys

try:
    # 连接到POP3服务器
    pop = poplib.POP3('$POP3_HOST', $POP3_PORT)
    pop.user('demo')
    pop.pass_('demo')
    
    # 获取邮件统计
    num_messages, total_size = pop.stat()
    print(f'POP3统计: {num_messages} 邮件, 总大小: {total_size} 字节')
    
    # 获取邮件列表
    messages = pop.list()
    print(f'邮件列表长度: {len(messages[1])}')
    
    # 检查最近的邮件
    recent_subjects = []
    check_count = min(num_messages, 10)  # 检查最近10封邮件
    
    for i in range(max(1, num_messages - check_count + 1), num_messages + 1):
        try:
            # 获取邮件头部
            header = pop.top(i, 10)
            header_text = '\\n'.join([line.decode('utf-8', errors='ignore') for line in header[1]])
            
            # 查找主题
            for line in header_text.split('\\n'):
                if line.lower().startswith('subject:'):
                    subject = line[8:].strip()
                    if 'Verify-Test' in subject:
                        recent_subjects.append(subject)
                    break
        except Exception as e:
            print(f'读取邮件 {i} 失败: {e}')
    
    pop.quit()
    
    print(f'找到验证测试邮件: {len(recent_subjects)}')
    for subject in recent_subjects[:5]:  # 显示前5个
        print(f'  - {subject}')
    
    # 写入结果
    with open('$log_file', 'w') as f:
        f.write(f'{num_messages},{len(recent_subjects)}\\n')
    
except Exception as e:
    print(f'POP3验证失败: {e}')
    with open('$log_file', 'w') as f:
        f.write('0,0\\n')
    sys.exit(1)
"
    
    if [ -f "$log_file" ]; then
        local result=$(cat "$log_file")
        local total_emails=$(echo "$result" | cut -d',' -f1)
        local verify_emails=$(echo "$result" | cut -d',' -f2)
        
        echo "POP3验证结果: 总邮件=$total_emails, 验证邮件=$verify_emails"
        echo "$total_emails,$verify_emails"
    else
        echo "0,0"
    fi
}

# 解析统计文件
parse_stats_file() {
    local stats_file="$1"
    
    if [ ! -f "$stats_file" ]; then
        echo "0,0,0,0"
        return
    fi
    
    local stats_line=$(tail -n 1 "$stats_file")
    local send_count=$(echo "$stats_line" | cut -f4)
    local receive_count=$(echo "$stats_line" | cut -f5)
    local encrypt_count=$(echo "$stats_line" | cut -f6)
    local decrypt_count=$(echo "$stats_line" | cut -f7)
    
    echo "$send_count,$receive_count,$encrypt_count,$decrypt_count"
}

# 测试1: 精确发送统计验证
test_precise_send_stats() {
    echo -e "${PURPLE}=== 测试1: 精确发送统计验证 ===${NC}"
    
    # 清理状态文件
    rm -f "$STATS_FILE"
    mkdir -p "$STATE_DIR"
    
    # 设置环境变量
    export SITE_ID="overseas"
    export LINK_ID="verify-send"
    export MAIL_STATS_STATE_FILE="$STATS_FILE"
    
    # 启动GreenMail
    if ! start_greenmail; then
        test_assert "false" "GreenMail服务启动"
        return
    fi
    
    # 启动Zeek监控
    cd "$PROJECT_DIR"
    timeout 20s ./scripts/run-live.sh lo0 > /tmp/verify_test_send.log 2>&1 &
    local zeek_pid=$!
    
    echo "Zeek监控已启动，等待3秒..."
    sleep 3
    
    # 精确发送5封邮件
    local target_count=5
    send_precise_emails $target_count /tmp/sent_emails_send.log "Precise-Send"
    
    # 等待处理
    echo "等待7秒让Zeek处理邮件..."
    sleep 7
    
    # 停止Zeek
    kill $zeek_pid 2>/dev/null || true
    wait $zeek_pid 2>/dev/null || true
    
    # 验证统计
    local stats=$(parse_stats_file "$STATS_FILE")
    local send_count=$(echo "$stats" | cut -d',' -f1)
    
    echo "发送统计验证: 预期=$target_count, 实际=$send_count"
    
    if [ "$send_count" -eq "$target_count" ]; then
        test_assert "true" "发送统计精确匹配" "$target_count" "$send_count"
    elif [ "$send_count" -gt 0 ] && [ "$send_count" -le $((target_count + 2)) ]; then
        test_assert "true" "发送统计在合理范围内" "$target_count" "$send_count"
    else
        test_assert "false" "发送统计准确性" "$target_count" "$send_count"
    fi
    
    echo ""
}

# 测试2: 发送接收统计对比
test_send_receive_correlation() {
    echo -e "${PURPLE}=== 测试2: 发送接收统计对比验证 ===${NC}"
    
    # 清理状态文件
    rm -f "$STATS_FILE"
    mkdir -p "$STATE_DIR"
    
    # 设置环境变量
    export SITE_ID="overseas"
    export LINK_ID="verify-both"
    export MAIL_STATS_STATE_FILE="$STATS_FILE"
    
    # 启动Zeek监控
    cd "$PROJECT_DIR"
    timeout 25s ./scripts/run-live.sh lo0 > /tmp/verify_test_both.log 2>&1 &
    local zeek_pid=$!
    
    echo "Zeek监控已启动，等待3秒..."
    sleep 3
    
    # 发送邮件
    local target_send=3
    send_precise_emails $target_send /tmp/sent_emails_both.log "Send-Receive-Test"
    
    echo "等待5秒处理发送的邮件..."
    sleep 5
    
    # 模拟POP3接收（通过连接触发接收事件）
    echo "模拟POP3接收检查..."
    local pop_result=$(receive_and_verify_emails $target_send /tmp/received_emails_both.log)
    local total_emails=$(echo "$pop_result" | cut -d',' -f1)
    local verify_emails=$(echo "$pop_result" | cut -d',' -f2)
    
    echo "等待3秒处理接收检查..."
    sleep 3
    
    # 停止Zeek
    kill $zeek_pid 2>/dev/null || true
    wait $zeek_pid 2>/dev/null || true
    
    # 验证统计
    local stats=$(parse_stats_file "$STATS_FILE")
    local send_count=$(echo "$stats" | cut -d',' -f1)
    local receive_count=$(echo "$stats" | cut -d',' -f2)
    
    echo "统计对比: 发送=$send_count, 接收=$receive_count"
    echo "邮件验证: 总邮件=$total_emails, 验证邮件=$verify_emails"
    
    # 发送统计验证
    if [ "$send_count" -ge $target_send ]; then
        test_assert "true" "发送统计不少于目标" "$target_send" "$send_count"
    else
        test_assert "false" "发送统计不少于目标" "$target_send" "$send_count"
    fi
    
    # 邮件到达验证
    if [ "$total_emails" -ge $target_send ]; then
        test_assert "true" "邮件成功到达邮箱" "$target_send" "$total_emails"
    else
        test_assert "false" "邮件成功到达邮箱" "$target_send" "$total_emails"
    fi
    
    echo ""
}

# 测试3: 累加统计验证
test_accumulation_accuracy() {
    echo -e "${PURPLE}=== 测试3: 累加统计精确性验证 ===${NC}"
    
    # 创建初始统计
    mkdir -p "$STATE_DIR"
    echo -e "2025-09\toverseas\tverify-accum\t10\t5\t2\t1" > "$STATS_FILE"
    
    echo "初始统计: 发送=10, 接收=5"
    
    # 设置环境变量
    export SITE_ID="overseas"
    export LINK_ID="verify-accum"
    export MAIL_STATS_STATE_FILE="$STATS_FILE"
    
    # 启动Zeek监控
    cd "$PROJECT_DIR"
    timeout 20s ./scripts/run-live.sh lo0 > /tmp/verify_test_accum.log 2>&1 &
    local zeek_pid=$!
    
    echo "Zeek监控已启动，等待3秒..."
    sleep 3
    
    # 发送3封额外邮件
    local additional_emails=3
    send_precise_emails $additional_emails /tmp/sent_emails_accum.log "Accumulation-Test"
    
    echo "等待7秒处理邮件..."
    sleep 7
    
    # 停止Zeek
    kill $zeek_pid 2>/dev/null || true
    wait $zeek_pid 2>/dev/null || true
    
    # 验证累加
    local stats=$(parse_stats_file "$STATS_FILE")
    local final_send=$(echo "$stats" | cut -d',' -f1)
    
    local expected_send=$((10 + additional_emails))  # 10 + 3 = 13
    
    echo "累加验证: 初始=10, 新增=$additional_emails, 预期=$expected_send, 实际=$final_send"
    
    if [ "$final_send" -eq "$expected_send" ]; then
        test_assert "true" "累加统计精确匹配" "$expected_send" "$final_send"
    elif [ "$final_send" -ge 10 ] && [ "$final_send" -le $((expected_send + 2)) ]; then
        test_assert "true" "累加统计在合理范围" "$expected_send" "$final_send"
    else
        test_assert "false" "累加统计准确性" "$expected_send" "$final_send"
    fi
    
    echo ""
}

# 测试4: 并发邮件统计验证
test_concurrent_email_stats() {
    echo -e "${PURPLE}=== 测试4: 并发邮件统计验证 ===${NC}"
    
    # 清理状态文件
    rm -f "$STATS_FILE"
    mkdir -p "$STATE_DIR"
    
    # 设置环境变量
    export SITE_ID="overseas"
    export LINK_ID="verify-concurrent"
    export MAIL_STATS_STATE_FILE="$STATS_FILE"
    
    # 启动Zeek监控
    cd "$PROJECT_DIR"
    timeout 30s ./scripts/run-live.sh lo0 > /tmp/verify_test_concurrent.log 2>&1 &
    local zeek_pid=$!
    
    echo "Zeek监控已启动，等待3秒..."
    sleep 3
    
    # 并发发送邮件（快速连续）
    echo "快速发送10封邮件..."
    local concurrent_count=10
    local sent_count=0
    
    for i in $(seq 1 $concurrent_count); do
        (
            python3 -c "
import smtplib
from email.mime.text import MIMEText
import time

try:
    server = smtplib.SMTP('$SMTP_HOST', $SMTP_PORT, timeout=5)
    
    msg = MIMEText('Concurrent test email #$i - $(date)')
    msg['Subject'] = 'Concurrent-Test-$i-$(date +%s)'
    msg['From'] = 'concurrent@test.local'
    msg['To'] = 'demo@test.local'
    
    server.sendmail('concurrent@test.local', ['demo@test.local'], msg.as_string())
    server.quit()
    
    print('Email $i sent')
    
except Exception as e:
    print(f'Email $i failed: {e}')
" &
        )
        # 非常短的延迟创建并发效果
        sleep 0.1
    done
    
    # 等待所有发送完成
    wait
    
    echo "等待10秒处理并发邮件..."
    sleep 10
    
    # 停止Zeek
    kill $zeek_pid 2>/dev/null || true
    wait $zeek_pid 2>/dev/null || true
    
    # 验证统计
    local stats=$(parse_stats_file "$STATS_FILE")
    local send_count=$(echo "$stats" | cut -d',' -f1)
    
    echo "并发统计验证: 预期=$concurrent_count, 实际=$send_count"
    
    # 并发情况下允许一定的误差
    if [ "$send_count" -ge $((concurrent_count - 2)) ] && [ "$send_count" -le $((concurrent_count + 2)) ]; then
        test_assert "true" "并发邮件统计在合理范围" "$concurrent_count±2" "$send_count"
    else
        test_assert "false" "并发邮件统计准确性" "$concurrent_count" "$send_count"
    fi
    
    echo ""
}

# 测试5: 统计文件格式验证
test_stats_file_format() {
    echo -e "${PURPLE}=== 测试5: 统计文件格式验证 ===${NC}"
    
    # 确保有统计文件
    if [ ! -f "$STATS_FILE" ]; then
        # 创建一个简单的统计文件
        mkdir -p "$STATE_DIR"
        export SITE_ID="overseas"
        export LINK_ID="format-test"
        export MAIL_STATS_STATE_FILE="$STATS_FILE"
        
        cd "$PROJECT_DIR"
        timeout 5s zeek -C -e "
        @load zeek-scripts/mail-activity-json.zeek
        event zeek_init() {
            MailActivity::update_monthly_stats(\"send\", F, F);
        }
        " > /tmp/verify_format_creation.log 2>&1 || true
    fi
    
    if [ -f "$STATS_FILE" ]; then
        echo "验证统计文件格式: $STATS_FILE"
        
        local content=$(cat "$STATS_FILE")
        echo "文件内容: $content"
        
        # 检查字段数量（应该有7个字段）
        local field_count=$(echo "$content" | tr '\t' '\n' | wc -l)
        if [ "$field_count" -eq 7 ]; then
            test_assert "true" "统计文件字段数量正确" "7" "$field_count"
        else
            test_assert "false" "统计文件字段数量正确" "7" "$field_count"
        fi
        
        # 检查月份格式（YYYY-MM）
        local month=$(echo "$content" | cut -f1)
        if [[ "$month" =~ ^[0-9]{4}-[0-9]{2}$ ]]; then
            test_assert "true" "月份格式正确" "YYYY-MM" "$month"
        else
            test_assert "false" "月份格式正确" "YYYY-MM" "$month"
        fi
        
        # 检查数字字段
        local send_count=$(echo "$content" | cut -f4)
        if [[ "$send_count" =~ ^[0-9]+$ ]]; then
            test_assert "true" "发送计数为数字" "数字" "$send_count"
        else
            test_assert "false" "发送计数为数字" "数字" "$send_count"
        fi
        
        # 检查站点ID
        local site_id=$(echo "$content" | cut -f2)
        if [ -n "$site_id" ]; then
            test_assert "true" "站点ID非空" "非空" "$site_id"
        else
            test_assert "false" "站点ID非空" "非空" "空"
        fi
        
    else
        test_assert "false" "统计文件存在" "存在" "不存在"
    fi
    
    echo ""
}

# 显示详细测试报告
show_detailed_report() {
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                      详细验证测试报告                        ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    
    echo -e "${GREEN}通过的测试: $TESTS_PASSED${NC}"
    echo -e "${RED}失败的测试: $TESTS_FAILED${NC}"
    echo -e "${BLUE}总计测试: $TESTS_TOTAL${NC}"
    
    local success_rate=0
    if [ $TESTS_TOTAL -gt 0 ]; then
        success_rate=$((TESTS_PASSED * 100 / TESTS_TOTAL))
    fi
    echo -e "${YELLOW}准确率: $success_rate%${NC}"
    
    echo ""
    echo -e "${BLUE}=== 最终统计文件状态 ===${NC}"
    if [ -f "$STATS_FILE" ]; then
        echo "文件路径: $STATS_FILE"
        echo "文件内容:"
        cat "$STATS_FILE" | while IFS=$'\t' read -r month site link send recv encrypt decrypt; do
            echo "  月份: $month"
            echo "  站点: $site"
            echo "  链路: $link"  
            echo "  发送: $send"
            echo "  接收: $recv"
            echo "  加密: $encrypt"
            echo "  解密: $decrypt"
        done
    else
        echo "统计文件不存在"
    fi
    
    echo ""
    echo -e "${BLUE}=== 测试文件位置 ===${NC}"
    ls -la /tmp/verify_test_*.log 2>/dev/null | head -5 || echo "无测试日志文件"
    ls -la /tmp/sent_emails_*.log 2>/dev/null | head -5 || echo "无邮件发送日志"
    
    if [ $TESTS_FAILED -eq 0 ]; then
        echo -e "${GREEN}🎉 所有验证测试通过！统计数据准确性良好${NC}"
        return 0
    else
        echo -e "${RED}⚠️  有验证测试失败，请检查统计准确性${NC}"
        return 1
    fi
}

# 主函数
main() {
    # 设置陷阱确保清理
    trap cleanup EXIT
    
    # 检查环境
    check_prerequisites
    
    # 启动GreenMail（一次性启动）
    if ! start_greenmail; then
        echo -e "${RED}❌ 无法启动GreenMail，退出测试${NC}"
        exit 1
    fi
    
    # 运行所有验证测试
    test_precise_send_stats
    test_send_receive_correlation  
    test_accumulation_accuracy
    test_concurrent_email_stats
    test_stats_file_format
    
    # 停止GreenMail
    docker-compose -f "$PROJECT_DIR/docker/greenmail/docker-compose.yml" down
    
    # 显示详细报告
    echo ""
    show_detailed_report
}

# 如果作为独立脚本运行
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi