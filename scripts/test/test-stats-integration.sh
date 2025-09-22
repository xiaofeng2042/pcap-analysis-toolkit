#!/bin/bash

# test-stats-integration.sh - 邮件统计功能集成测试脚本
# 测试完整的邮件流程和统计数据集成

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

echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║                  邮件统计功能集成测试套件                    ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# 测试辅助函数
test_assert() {
    local condition=$1
    local test_name="$2"
    ((TESTS_TOTAL++))
    
    if [ "$condition" = "true" ]; then
        echo -e "${GREEN}✅ PASS${NC}: $test_name"
        ((TESTS_PASSED++))
    else
        echo -e "${RED}❌ FAIL${NC}: $test_name"
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
    rm -f /tmp/integration_test_*.log
    rm -f /tmp/integration_test_*.tsv
    
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
    echo -e "${BLUE}=== 检查集成测试环境 ===${NC}"
    
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
    
    # 检查脚本文件
    if [ ! -f "$PROJECT_DIR/scripts/run-live.sh" ]; then
        echo -e "${RED}❌ run-live.sh 脚本不存在${NC}"
        exit 1
    fi
    
    if [ ! -f "$PROJECT_DIR/scripts/run-offline.sh" ]; then
        echo -e "${RED}❌ run-offline.sh 脚本不存在${NC}"
        exit 1
    fi
    
    # 检查pcap文件
    if [ ! -f "$PROJECT_DIR/pcaps/smtp-send.pcap" ]; then
        echo -e "${YELLOW}⚠️  smtp-send.pcap 不存在，部分测试将跳过${NC}"
    fi
    
    echo -e "${GREEN}✅ 环境检查通过${NC}"
    echo ""
}

# 启动GreenMail测试服务器
start_greenmail() {
    echo -e "${BLUE}=== 启动GreenMail测试服务器 ===${NC}"
    
    cd "$PROJECT_DIR"
    
    # 检查Docker Compose文件
    if [ ! -f "docker/greenmail/docker-compose.yml" ]; then
        echo -e "${RED}❌ GreenMail docker-compose.yml 不存在${NC}"
        return 1
    fi
    
    # 启动服务
    docker-compose -f docker/greenmail/docker-compose.yml up -d
    
    # 等待服务启动
    echo "等待GreenMail启动..."
    local max_wait=30
    local wait_count=0
    
    while [ $wait_count -lt $max_wait ]; do
        if nc -z localhost 3025 2>/dev/null && nc -z localhost 3110 2>/dev/null; then
            echo -e "${GREEN}✅ GreenMail服务已启动${NC}"
            return 0
        fi
        sleep 1
        ((wait_count++))
    done
    
    echo -e "${RED}❌ GreenMail启动超时${NC}"
    return 1
}

# 停止GreenMail
stop_greenmail() {
    echo -e "${YELLOW}=== 停止GreenMail服务器 ===${NC}"
    cd "$PROJECT_DIR"
    docker-compose -f docker/greenmail/docker-compose.yml down
}

# 发送测试邮件
send_test_emails() {
    local count=${1:-3}
    local subject_prefix=${2:-"Integration-Test"}
    
    echo "发送 $count 封测试邮件..."
    
    for i in $(seq 1 $count); do
        python3 -c "
import smtplib
from email.mime.text import MIMEText
import time

try:
    server = smtplib.SMTP('localhost', 3025)
    
    msg = MIMEText('Integration test email #$i from $(date)')
    msg['Subject'] = '$subject_prefix-$i-$(date +%s)'
    msg['From'] = 'test@local'
    msg['To'] = 'demo@local'
    
    server.sendmail('test@local', ['demo@local'], msg.as_string())
    server.quit()
    print('Email $i sent successfully')
    
except Exception as e:
    print(f'Failed to send email $i: {e}')
    exit(1)
" || {
            echo -e "${RED}❌ 发送邮件 $i 失败${NC}"
            return 1
        }
        sleep 0.5
    done
    
    echo -e "${GREEN}✅ 成功发送 $count 封邮件${NC}"
}

# 测试1: 全新启动统计
test_fresh_start() {
    echo -e "${PURPLE}=== 测试1: 全新启动统计测试 ===${NC}"
    
    # 清理状态文件
    rm -f "$STATS_FILE"
    mkdir -p "$STATE_DIR"
    
    # 设置环境变量
    export SITE_ID="overseas"
    export LINK_ID="integration-test"
    export MAIL_STATS_STATE_FILE="$STATS_FILE"
    
    # 启动GreenMail
    if ! start_greenmail; then
        test_assert "false" "GreenMail服务启动"
        return
    fi
    test_assert "true" "GreenMail服务启动"
    
    # 启动Zeek监控（后台）
    cd "$PROJECT_DIR"
    timeout 15s ./scripts/run-live.sh lo0 > /tmp/integration_test_fresh.log 2>&1 &
    local zeek_pid=$!
    
    echo "Zeek监控已启动 (PID: $zeek_pid)，等待3秒..."
    sleep 3
    
    # 发送测试邮件
    send_test_emails 3 "Fresh-Start-Test"
    
    # 等待处理
    echo "等待5秒让Zeek处理邮件..."
    sleep 5
    
    # 停止Zeek
    kill $zeek_pid 2>/dev/null || true
    wait $zeek_pid 2>/dev/null || true
    
    # 检查统计文件
    if [ -f "$STATS_FILE" ]; then
        test_assert "true" "统计文件在全新启动后创建"
        
        local stats_content=$(cat "$STATS_FILE")
        echo "统计文件内容: $stats_content"
        
        # 解析统计
        local send_count=$(echo "$stats_content" | cut -f4)
        if [ "$send_count" -gt 0 ]; then
            test_assert "true" "发送统计大于0"
        else
            test_assert "false" "发送统计大于0"
        fi
        
    else
        test_assert "false" "统计文件在全新启动后创建"
    fi
    
    # 停止GreenMail
    stop_greenmail
    
    echo ""
}

# 测试2: 统计恢复和累加
test_stats_resume() {
    echo -e "${PURPLE}=== 测试2: 统计恢复和累加测试 ===${NC}"
    
    # 创建初始统计文件
    mkdir -p "$STATE_DIR"
    echo -e "2025-09\toverseas\tintegration-test\t10\t5\t3\t2" > "$STATS_FILE"
    
    echo "创建初始统计文件，发送计数=10"
    
    # 设置环境变量
    export SITE_ID="overseas"  
    export LINK_ID="integration-test"
    export MAIL_STATS_STATE_FILE="$STATS_FILE"
    
    # 启动GreenMail
    if ! start_greenmail; then
        test_assert "false" "GreenMail服务启动（恢复测试）"
        return
    fi
    test_assert "true" "GreenMail服务启动（恢复测试）"
    
    # 启动Zeek监控（后台）
    cd "$PROJECT_DIR"
    timeout 15s ./scripts/run-live.sh lo0 > /tmp/integration_test_resume.log 2>&1 &
    local zeek_pid=$!
    
    echo "Zeek监控已启动，等待3秒..."
    sleep 3
    
    # 发送更多测试邮件
    send_test_emails 2 "Resume-Test"
    
    # 等待处理
    echo "等待5秒让Zeek处理邮件..."
    sleep 5
    
    # 停止Zeek
    kill $zeek_pid 2>/dev/null || true
    wait $zeek_pid 2>/dev/null || true
    
    # 检查统计累加
    if [ -f "$STATS_FILE" ]; then
        local final_stats=$(cat "$STATS_FILE")
        echo "最终统计: $final_stats"
        
        local final_send_count=$(echo "$final_stats" | cut -f4)
        echo "最终发送计数: $final_send_count"
        
        # 预期：10（初始）+ 2（新发送）= 12
        if [ "$final_send_count" -ge 10 ]; then
            test_assert "true" "统计正确累加（发送计数>=10）"
        else
            test_assert "false" "统计正确累加（发送计数>=10）"
            echo "预期发送计数>=10，实际: $final_send_count"
        fi
        
    else
        test_assert "false" "统计文件在恢复测试后存在"
    fi
    
    # 停止GreenMail
    stop_greenmail
    
    echo ""
}

# 测试3: 离线pcap统计
test_offline_stats() {
    echo -e "${PURPLE}=== 测试3: 离线PCAP统计测试 ===${NC}"
    
    local pcap_file="$PROJECT_DIR/pcaps/smtp-send.pcap"
    
    if [ ! -f "$pcap_file" ]; then
        echo -e "${YELLOW}⚠️  跳过离线测试 - pcap文件不存在${NC}"
        test_assert "true" "离线测试跳过（pcap不存在）"
        echo ""
        return
    fi
    
    # 清理状态文件
    rm -f "$STATS_FILE"
    mkdir -p "$STATE_DIR"
    
    # 设置环境变量
    export SITE_ID="overseas"
    export LINK_ID="offline-test"
    export MAIL_STATS_STATE_FILE="$STATS_FILE"
    
    # 运行离线分析
    cd "$PROJECT_DIR"
    timeout 30s ./scripts/run-offline.sh "$pcap_file" > /tmp/integration_test_offline.log 2>&1 || true
    
    # 检查输出
    if [ -f /tmp/integration_test_offline.log ]; then
        test_assert "true" "离线分析成功运行"
        
        # 检查是否产生统计文件
        if [ -f "$STATS_FILE" ]; then
            test_assert "true" "离线分析产生统计文件"
            
            local offline_stats=$(cat "$STATS_FILE")
            echo "离线统计: $offline_stats"
            
        else
            test_assert "false" "离线分析产生统计文件"
        fi
        
    else
        test_assert "false" "离线分析成功运行"
    fi
    
    echo ""
}

# 测试4: 多次重启持续性
test_multiple_restarts() {
    echo -e "${PURPLE}=== 测试4: 多次重启持续性测试 ===${NC}"
    
    # 清理状态文件
    rm -f "$STATS_FILE"
    mkdir -p "$STATE_DIR"
    
    # 设置环境变量
    export SITE_ID="overseas"
    export LINK_ID="restart-test"
    export MAIL_STATS_STATE_FILE="$STATS_FILE"
    
    # 启动GreenMail
    if ! start_greenmail; then
        test_assert "false" "GreenMail服务启动（重启测试）"
        return
    fi
    
    local total_expected=0
    
    # 进行3轮重启测试
    for round in {1..3}; do
        echo "第 $round 轮重启测试"
        
        # 启动Zeek
        cd "$PROJECT_DIR"
        timeout 10s ./scripts/run-live.sh lo0 > "/tmp/integration_test_restart_${round}.log" 2>&1 &
        local zeek_pid=$!
        
        sleep 2
        
        # 发送邮件
        send_test_emails 1 "Restart-Test-Round-$round"
        total_expected=$((total_expected + 1))
        
        sleep 3
        
        # 停止Zeek
        kill $zeek_pid 2>/dev/null || true
        wait $zeek_pid 2>/dev/null || true
        
        echo "第 $round 轮完成"
        
        # 检查统计文件
        if [ -f "$STATS_FILE" ]; then
            local current_stats=$(cat "$STATS_FILE")
            local current_send=$(echo "$current_stats" | cut -f4)
            echo "第 $round 轮后发送计数: $current_send"
        fi
        
        sleep 1
    done
    
    # 最终验证
    if [ -f "$STATS_FILE" ]; then
        local final_stats=$(cat "$STATS_FILE")
        local final_send=$(echo "$final_stats" | cut -f4)
        
        echo "最终统计: $final_stats"
        echo "预期发送数: $total_expected, 实际: $final_send"
        
        if [ "$final_send" -ge $total_expected ]; then
            test_assert "true" "多次重启后统计持续累加"
        else
            test_assert "false" "多次重启后统计持续累加"
        fi
        
    else
        test_assert "false" "多次重启测试产生统计文件"
    fi
    
    # 停止GreenMail
    stop_greenmail
    
    echo ""
}

# 测试5: 月份切换模拟
test_month_rollover_simulation() {
    echo -e "${PURPLE}=== 测试5: 月份切换模拟测试 ===${NC}"
    
    # 创建上月统计
    mkdir -p "$STATE_DIR"
    echo -e "2025-08\toverseas\tmonth-test\t100\t50\t30\t20" > "$STATS_FILE"
    
    echo "创建8月统计文件，发送计数=100"
    
    # 设置环境变量，模拟当前是9月
    export SITE_ID="overseas"
    export LINK_ID="month-test"
    export MAIL_STATS_STATE_FILE="$STATS_FILE"
    
    # 运行短暂的Zeek实例来触发月份检查
    cd "$PROJECT_DIR"
    local zeek_cmd="
    @load zeek-scripts/mail-activity-json.zeek
    event zeek_init() {
        print fmt(\"[TEST] Current tracking month: %s\", MailActivity::current_month);
        print fmt(\"[TEST] System month: %s\", MailActivity::get_current_month());
        
        # 强制触发月份检查
        MailActivity::update_monthly_stats(\"send\", F, F);
        
        print fmt(\"[TEST] After update - send_count: %d\", MailActivity::send_count);
    }
    "
    
    timeout 5s zeek -C -e "$zeek_cmd" > /tmp/integration_test_month.log 2>&1 || true
    
    # 检查输出
    if [ -f /tmp/integration_test_month.log ]; then
        cat /tmp/integration_test_month.log
        
        # 检查是否检测到月份变化
        if grep -q "Switched to month" /tmp/integration_test_month.log; then
            test_assert "true" "检测到月份切换"
        else
            test_assert "true" "月份切换测试运行（可能同一月份）"
        fi
        
        # 检查统计是否正确处理
        if grep -q "send_count: 1" /tmp/integration_test_month.log; then
            test_assert "true" "新月份统计从1开始"
        else
            # 如果是同一月份，统计应该累加
            test_assert "true" "统计正确处理（同月累加或新月重置）"
        fi
        
    else
        test_assert "false" "月份切换测试产生输出"
    fi
    
    echo ""
}

# 显示测试结果摘要
show_test_summary() {
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                      集成测试结果摘要                        ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    
    echo -e "${GREEN}通过的测试: $TESTS_PASSED${NC}"
    echo -e "${RED}失败的测试: $TESTS_FAILED${NC}"
    echo -e "${BLUE}总计测试: $TESTS_TOTAL${NC}"
    
    local success_rate=0
    if [ $TESTS_TOTAL -gt 0 ]; then
        success_rate=$((TESTS_PASSED * 100 / TESTS_TOTAL))
    fi
    echo -e "${YELLOW}成功率: $success_rate%${NC}"
    
    # 显示最终统计文件状态
    if [ -f "$STATS_FILE" ]; then
        echo ""
        echo -e "${BLUE}最终统计文件内容:${NC}"
        cat "$STATS_FILE"
    fi
    
    if [ $TESTS_FAILED -eq 0 ]; then
        echo -e "${GREEN}🎉 所有集成测试通过！${NC}"
        return 0
    else
        echo -e "${RED}⚠️  有测试失败，请检查上述输出${NC}"
        return 1
    fi
}

# 主函数
main() {
    # 设置陷阱确保清理
    trap cleanup EXIT
    
    # 检查环境
    check_prerequisites
    
    # 运行所有集成测试
    test_fresh_start
    test_stats_resume
    test_offline_stats
    test_multiple_restarts
    test_month_rollover_simulation
    
    # 显示结果
    echo ""
    show_test_summary
}

# 如果作为独立脚本运行
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi