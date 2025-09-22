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
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
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
        cat "$STATS_FILE" | while IFS=$'\t' read -r month site_id link_id send_count receive_count encrypt_count decrypt_count; do
            echo "  月份: $month"
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
    cd "$PROJECT_DIR/docker/greenmail"
    
    # 检查是否已经运行
    if docker-compose ps | grep -q "Up"; then
        echo "GreenMail 已经在运行"
    else
        docker-compose up -d
        echo "等待 GreenMail 启动..."
        sleep 5
    fi
    cd "$PROJECT_DIR"
    echo ""
}

# 函数：停止GreenMail
stop_greenmail() {
    echo -e "${YELLOW}[GREENMAIL] 停止测试邮件服务器...${NC}"
    cd "$PROJECT_DIR/docker/greenmail"
    docker-compose down
    cd "$PROJECT_DIR"
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
    export STATS_STATE_FILE="$STATS_FILE"
    
    # 启动Zeek监控 - 显示调试输出，忽略校验和错误
    cd "$PROJECT_DIR"
    
    # 使用后台进程和sleep模拟timeout
    zeek -C -i lo0 zeek-scripts/mail-activity-json.zeek &
    local zeek_pid=$!
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
    export STATS_STATE_FILE="$STATS_FILE"
    
    cd "$PROJECT_DIR"
    zeek -i lo0 zeek-scripts/mail-activity-json.zeek &
    ZEEK_PID=$!
    echo "Zeek PID: $ZEEK_PID"
    sleep 3
    
    # 4. 发送测试邮件
    echo "=== 步骤4: 发送测试邮件 ==="
    send_test_emails $email_count
    
    # 5. 等待处理
    echo "=== 步骤5: 等待处理 ==="
    echo "等待 5 秒让Zeek处理邮件..."
    sleep 5
    
    # 6. 停止Zeek
    echo "=== 步骤6: 停止监控 ==="
    kill $ZEEK_PID 2>/dev/null || true
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