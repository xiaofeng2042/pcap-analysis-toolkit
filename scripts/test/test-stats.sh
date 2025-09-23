#!/bin/bash

# 统计功能测试脚本
# 用于快速测试邮件监控系统的统计功能

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 配置
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
OUTPUT_DIR="$PROJECT_DIR/output"
STATE_DIR="$OUTPUT_DIR/state"
STATS_FILE="$STATE_DIR/mail_stats_state.tsv"

echo -e "${BLUE}[INFO] 邮件统计功能测试${NC}"
echo "======================================"

# 函数：显示当前统计状态
show_current_stats() {
    echo -e "${YELLOW}[STATS] 当前统计状态:${NC}"
    if [ -f "$STATS_FILE" ]; then
        echo "统计文件: $STATS_FILE"
        echo "内容:"
        # 处理 \x09 编码的制表符
        sed 's/\\x09/\t/g' "$STATS_FILE" | while IFS=$'\t' read -r date site_id link_id send_count receive_count encrypt_count decrypt_count; do
            echo "  日期: $date"
            echo "  站点: $site_id"
            echo "  链路: $link_id"
            echo "  发送数: $send_count"
            echo "  接收数: $receive_count"
            echo "  加密数: $encrypt_count"
            echo "  解密数: $decrypt_count"
        done
    else
        echo "统计文件不存在: $STATS_FILE"
    fi
    echo ""
}

# 函数：清理统计状态
reset_stats() {
    echo -e "${YELLOW}[RESET] 重置统计状态...${NC}"
    rm -f "$STATS_FILE"
    echo "统计文件已删除"
    echo ""
}

# 函数：启动GreenMail测试服务器
start_greenmail() {
    echo -e "${BLUE}[GREENMAIL] 启动测试邮件服务器...${NC}"
    
    # 检查是否已经运行
    if docker-compose -f "$PROJECT_DIR/docker/greenmail/docker-compose.yml" ps | grep -q "Up"; then
        echo "GreenMail 已经在运行"
    else
        docker-compose -f "$PROJECT_DIR/docker/greenmail/docker-compose.yml" up -d
        echo "等待 GreenMail 启动..."
        sleep 5
    fi
    cd "$PROJECT_DIR"
    echo ""
}

# 函数：停止GreenMail
stop_greenmail() {
    echo -e "${YELLOW}[GREENMAIL] 停止测试邮件服务器...${NC}"
    docker-compose -f "$PROJECT_DIR/docker/greenmail/docker-compose.yml" down
    echo ""
}

# 函数：发送测试邮件
send_test_emails() {
    local count=${1:-3}
    echo -e "${GREEN}[TEST] 发送 $count 封测试邮件...${NC}"
    
    for i in $(seq 1 $count); do
        echo "发送第 $i 封邮件..."
        python3 -c "
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import time

# 连接到GreenMail SMTP服务器
server = smtplib.SMTP('localhost', 3025)

# 创建邮件
msg = MIMEMultipart()
msg['From'] = 'test@local'
msg['To'] = 'user@remote'
msg['Subject'] = f'Test Email {$i} - {time.strftime(\"%Y-%m-%d %H:%M:%S\")}'

body = f'This is test email number {$i} sent at {time.strftime(\"%Y-%m-%d %H:%M:%S\")}'
msg.attach(MIMEText(body, 'plain'))

# 发送邮件
try:
    server.sendmail('test@local', ['user@remote'], msg.as_string())
    print(f'邮件 {$i} 发送成功')
except Exception as e:
    print(f'邮件 {$i} 发送失败: {e}')
finally:
    server.quit()
    # 确保连接完全关闭后再继续
    time.sleep(0.5)
"
        sleep 1
    done
    echo ""
}

# 函数：运行Zeek监控
run_zeek_monitoring() {
    local duration=${1:-10}
    echo -e "${BLUE}[ZEEK] 启动Zeek监控 (${duration}秒)...${NC}"
    
    # 创建输出目录
    mkdir -p "$STATE_DIR"
    
    # 设置环境变量
    export SITE_ID="overseas"
    export LINK_ID="test_link"
    export MAIL_STATS_STATE_FILE="$STATS_FILE"
    
    # 启动Zeek监控 - 显示调试输出，忽略校验和错误
    cd "$PROJECT_DIR"
    
    # 使用后台进程和sleep模拟timeout，显式传递环境变量
    env SITE_ID="overseas" LINK_ID="test_link" MAIL_STATS_STATE_FILE="$STATS_FILE" \
        zeek -C -i lo0 zeek-scripts/mail-activity-json.zeek &
    local zeek_pid=$!
    echo "Zeek PID: $zeek_pid"
    sleep ${duration}
    kill $zeek_pid 2>/dev/null || true
    wait $zeek_pid 2>/dev/null || true
    
    echo "Zeek监控完成"
    echo ""
}

# 函数：完整测试流程
run_full_test() {
    local email_count=${1:-3}
    local monitor_duration=${2:-15}
    
    echo -e "${GREEN}[FULL TEST] 开始完整统计功能测试${NC}"
    echo "参数: 邮件数量=$email_count, 监控时长=${monitor_duration}秒"
    echo ""
    
    # 1. 显示初始状态
    echo "=== 步骤1: 初始状态 ==="
    show_current_stats
    
    # 2. 启动GreenMail
    echo "=== 步骤2: 启动测试服务器 ==="
    start_greenmail
    
    # 启动Zeek监控（后台）
    echo "=== 步骤3: 启动Zeek监控 ==="
    export SITE_ID="overseas"
    export LINK_ID="test_link"
    export MAIL_STATS_STATE_FILE="$STATS_FILE"
    
    # 如果统计文件存在，预读取其内容并通过环境变量传递给Zeek
    if [ -f "$STATS_FILE" ]; then
        # 获取当前日期（YYYY-MM-DD格式）
        local current_date=$(date "+%Y-%m-%d")
        
        # 查找当前日期的数据行，如果没找到则使用最新日期的数据
        local stats_line=$(sed 's/\\x09/\t/g' "$STATS_FILE" | grep "^$current_date" | head -n 1)
        
        # 如果当前日期没有数据，查找最新的日期数据（按时间倒序）
        if [ -z "$stats_line" ]; then
            echo "当前日期 $current_date 没有数据，使用最新日期数据"
            stats_line=$(sed 's/\\x09/\t/g' "$STATS_FILE" | sort -t$'\t' -k1,1r | head -n 1)
        fi
        
        if [ -n "$stats_line" ]; then
            local date=$(echo "$stats_line" | cut -f1)
            local send_count=$(echo "$stats_line" | cut -f4)
            local receive_count=$(echo "$stats_line" | cut -f5)
            local encrypt_count=$(echo "$stats_line" | cut -f6)
            local decrypt_count=$(echo "$stats_line" | cut -f7)
            
            export MAIL_STATS_INIT_DATE="$date"
            export MAIL_STATS_INIT_SEND="$send_count"
            export MAIL_STATS_INIT_RECEIVE="$receive_count"
            export MAIL_STATS_INIT_ENCRYPT="$encrypt_count"
            export MAIL_STATS_INIT_DECRYPT="$decrypt_count"
            
            if [ "$date" = "$current_date" ]; then
                echo "预加载统计数据（当前日期）: date=$date send=$send_count receive=$receive_count encrypt=$encrypt_count decrypt=$decrypt_count"
            else
                echo "预加载统计数据（使用 $date 数据，当前日期 $current_date 无数据）: send=$send_count receive=$receive_count encrypt=$encrypt_count decrypt=$decrypt_count"
            fi
        else
            echo "统计文件为空或格式错误"
        fi
        
        # 新增：为所有行设置环境变量，供Zeek的read_all_stats()函数使用
        echo "设置所有历史统计数据的环境变量..."
        while IFS=$'\t' read -r date_field site_id link_id send_count receive_count encrypt_count decrypt_count; do
            if [ -n "$date_field" ] && [ "$site_id" = "overseas" ] && [ "$link_id" = "test_link" ]; then
                # 如果是YYYY-MM格式，转换为YYYY-MM-01
                if [[ "$date_field" =~ ^[0-9]{4}-[0-9]{2}$ ]]; then
                    date_field="${date_field}-01"
                fi
                # 创建环境变量名（将-替换为_）
                local env_var_name="MAIL_STATS_ROW_${date_field//-/_}"
                local env_var_value="$date_field,$site_id,$link_id,$send_count,$receive_count,$encrypt_count,$decrypt_count"
                export "$env_var_name"="$env_var_value"
                echo "设置环境变量: $env_var_name=$env_var_value"
            fi
        done < <(sed 's/\\x09/\t/g' "$STATS_FILE")
    fi
    
    cd "$PROJECT_DIR"
    zeek -C -i lo0 zeek-scripts/mail-activity-json.zeek &
    ZEEK_PID=$!
    echo "Zeek PID: $ZEEK_PID"
    echo "等待Zeek完全启动..."
    sleep 5  # 增加等待时间确保Zeek完全就绪
    
    # 4. 发送测试邮件
    echo "=== 步骤4: 发送测试邮件 ==="
    send_test_emails $email_count
    
    # 5. 等待处理
    echo "=== 步骤5: 等待处理 ==="
    echo "等待所有邮件完全处理完成..."
    
    # 等待足够长的时间确保所有邮件都被处理（每封邮件1.5秒 + 额外缓冲）
    local wait_time=$((email_count * 2 + 5))
    echo "等待 $wait_time 秒让Zeek处理 $email_count 封邮件..."
    sleep $wait_time
    
    # 额外等待以确保所有连接完全关闭
    echo "额外等待 5 秒确保所有连接完全关闭..."
    sleep 5
    
    # 6. 停止Zeek
    echo "=== 步骤6: 停止监控 ==="
    echo "优雅关闭Zeek进程..."
    kill -TERM $ZEEK_PID 2>/dev/null || true
    sleep 3  # 给Zeek时间完成清理工作
    wait $ZEEK_PID 2>/dev/null || true
    
    # 7. 显示最终统计
    echo "=== 步骤7: 最终统计结果 ==="
    show_current_stats
    
    # 8. 清理
    echo "=== 步骤8: 清理环境 ==="
    stop_greenmail
    
    echo -e "${GREEN}[FULL TEST] 测试完成!${NC}"
}

# 主菜单
case "${1:-menu}" in
    "reset")
        reset_stats
        ;;
    "stats")
        show_current_stats
        ;;
    "greenmail-start")
        start_greenmail
        ;;
    "greenmail-stop")
        stop_greenmail
        ;;
    "send")
        count=${2:-3}
        start_greenmail
        send_test_emails $count
        ;;
    "monitor")
        duration=${2:-10}
        run_zeek_monitoring $duration
        ;;
    "full")
        email_count=${2:-3}
        monitor_duration=${3:-15}
        run_full_test $email_count $monitor_duration
        ;;
    "menu"|*)
        echo "用法: $0 [命令] [参数]"
        echo ""
        echo "命令:"
        echo "  stats              - 显示当前统计状态"
        echo "  reset              - 重置统计状态"
        echo "  greenmail-start    - 启动GreenMail测试服务器"
        echo "  greenmail-stop     - 停止GreenMail测试服务器"
        echo "  send [数量]        - 发送测试邮件 (默认3封)"
        echo "  monitor [秒数]     - 运行Zeek监控 (默认10秒)"
        echo "  full [邮件数] [秒数] - 完整测试流程 (默认3封邮件,15秒监控)"
        echo ""
        echo "示例:"
        echo "  $0 stats           # 查看当前统计"
        echo "  $0 reset           # 重置统计"
        echo "  $0 full 5 20       # 发送5封邮件,监控20秒"
        echo "  $0 send 10         # 只发送10封测试邮件"
        ;;
esac