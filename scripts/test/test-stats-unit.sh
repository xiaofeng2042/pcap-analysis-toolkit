#!/bin/bash

# test-stats-unit.sh - 邮件统计功能单元测试脚本
# 测试统计数据的各个组件功能

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
ZEEK_SCRIPT="$PROJECT_DIR/zeek-scripts/test/test-stats.zeek"
MAIN_SCRIPT="$PROJECT_DIR/zeek-scripts/mail-activity-json.zeek"

echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║                  邮件统计功能单元测试套件                    ║${NC}"
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
    rm -f /tmp/test_stats_*.tsv
    rm -f /tmp/zeek_test_*.log
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
    echo -e "${BLUE}=== 检查测试环境 ===${NC}"
    
    # 检查Zeek
    if ! command -v zeek &> /dev/null; then
        echo -e "${RED}❌ Zeek 未安装或不在PATH中${NC}"
        exit 1
    fi
    
    # 检查测试脚本
    if [ ! -f "$ZEEK_SCRIPT" ]; then
        echo -e "${RED}❌ Zeek测试脚本不存在: $ZEEK_SCRIPT${NC}"
        exit 1
    fi
    
    # 检查主脚本
    if [ ! -f "$MAIN_SCRIPT" ]; then
        echo -e "${RED}❌ 主Zeek脚本不存在: $MAIN_SCRIPT${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✅ 环境检查通过${NC}"
    echo ""
}

# 测试1: 基础Zeek脚本语法
test_zeek_syntax() {
    echo -e "${PURPLE}=== 测试1: Zeek脚本语法检查 ===${NC}"
    
    # 测试主脚本语法
    if zeek -T "$MAIN_SCRIPT" 2>/dev/null; then
        test_assert "true" "主脚本语法正确"
    else
        test_assert "false" "主脚本语法正确"
        echo "语法错误输出:"
        zeek -T "$MAIN_SCRIPT" 2>&1 | head -10
    fi
    
    # 测试测试脚本语法
    if zeek -T "$ZEEK_SCRIPT" 2>/dev/null; then
        test_assert "true" "测试脚本语法正确"
    else
        test_assert "false" "测试脚本语法正确"
        echo "语法错误输出:"
        zeek -T "$ZEEK_SCRIPT" 2>&1 | head -10
    fi
    
    echo ""
}

# 测试2: 环境变量初始化
test_env_initialization() {
    echo -e "${PURPLE}=== 测试2: 环境变量初始化 ===${NC}"
    
    # 设置测试环境变量
    export MAIL_STATS_INIT_MONTH="2025-09"
    export MAIL_STATS_INIT_SEND="10"
    export MAIL_STATS_INIT_RECEIVE="5" 
    export MAIL_STATS_INIT_ENCRYPT="3"
    export MAIL_STATS_INIT_DECRYPT="2"
    export SITE_ID="overseas"
    export LINK_ID="test-link"
    
    # 运行Zeek测试脚本
    local output_file="/tmp/zeek_test_env.log"
    timeout 10s zeek -C "$ZEEK_SCRIPT" > "$output_file" 2>&1 || true
    
    # 检查输出
    if [ -f "$output_file" ]; then
        # 检查是否找到环境变量恢复信息
        if grep -q "MAIL_STATS_INIT_MONTH: 2025-09" "$output_file"; then
            test_assert "true" "环境变量月份正确读取"
        else
            test_assert "false" "环境变量月份正确读取"
        fi
        
        if grep -q "MAIL_STATS_INIT_SEND: 10" "$output_file"; then
            test_assert "true" "环境变量发送计数正确读取"
        else
            test_assert "false" "环境变量发送计数正确读取"
        fi
        
        # 检查测试是否运行
        if grep -q "所有测试通过" "$output_file" || grep -q "有测试失败" "$output_file"; then
            test_assert "true" "Zeek测试脚本成功运行"
        else
            test_assert "false" "Zeek测试脚本成功运行"
            echo "Zeek输出:"
            cat "$output_file" | head -20
        fi
    else
        test_assert "false" "Zeek测试产生输出文件"
    fi
    
    echo ""
}

# 测试3: 状态文件保存
test_state_file_save() {
    echo -e "${PURPLE}=== 测试3: 状态文件保存 ===${NC}"
    
    local test_state_file="/tmp/test_stats_save.tsv"
    
    # 清理之前的测试文件
    rm -f "$test_state_file"
    
    # 设置状态文件路径
    export MAIL_STATS_STATE_FILE="$test_state_file"
    export SITE_ID="overseas"
    export LINK_ID="test-link"
    
    # 运行简单的Zeek脚本来触发保存
    local zeek_cmd="
    @load $MAIN_SCRIPT
    event zeek_init() {
        MailActivity::update_monthly_stats(\"send\", F, F);
        MailActivity::update_monthly_stats(\"receive\", T, F);
    }
    "
    
    timeout 5s zeek -C -e "$zeek_cmd" > /tmp/zeek_save_test.log 2>&1 || true
    
    # 检查状态文件是否创建
    if [ -f "$test_state_file" ]; then
        test_assert "true" "状态文件成功创建"
        
        # 检查文件内容格式
        local content=$(cat "$test_state_file")
        echo "状态文件内容: $content"
        
        # 检查是否包含制表符分隔的字段
        local field_count=$(echo "$content" | tr '\t' '\n' | wc -l)
        if [ "$field_count" -ge 7 ]; then
            test_assert "true" "状态文件格式正确（包含所需字段数）"
        else
            test_assert "false" "状态文件格式正确（包含所需字段数）"
            echo "字段数: $field_count, 预期: >=7"
        fi
        
        # 检查是否包含站点ID
        if echo "$content" | grep -q "overseas"; then
            test_assert "true" "状态文件包含站点ID"
        else
            test_assert "false" "状态文件包含站点ID"
        fi
        
    else
        test_assert "false" "状态文件成功创建"
    fi
    
    echo ""
}

# 测试4: 状态文件恢复
test_state_file_restore() {
    echo -e "${PURPLE}=== 测试4: 状态文件恢复 ===${NC}"
    
    local test_state_file="/tmp/test_stats_restore.tsv"
    
    # 创建测试状态文件
    echo -e "2025-09\toverseas\ttest-link\t15\t8\t4\t3" > "$test_state_file"
    
    # 设置环境变量使用shell读取的方式
    export MAIL_STATS_STATE_FILE="$test_state_file"
    export SITE_ID="overseas"
    export LINK_ID="test-link"
    
    # 从状态文件读取并设置环境变量（模拟run-live.sh的行为）
    if [ -f "$test_state_file" ]; then
        local state_line=$(tail -n 1 "$test_state_file")
        IFS=$'\t' read -r MONTH SITE LINK SEND RECEIVE ENCRYPT DECRYPT <<< "$state_line"
        
        export MAIL_STATS_INIT_MONTH="$MONTH"
        export MAIL_STATS_INIT_SEND="$SEND"
        export MAIL_STATS_INIT_RECEIVE="$RECEIVE"
        export MAIL_STATS_INIT_ENCRYPT="$ENCRYPT"
        export MAIL_STATS_INIT_DECRYPT="$DECRYPT"
        
        echo "从状态文件读取: month=$MONTH, send=$SEND, receive=$RECEIVE"
        
        # 运行测试
        local output_file="/tmp/zeek_test_restore.log"
        timeout 10s zeek -C "$ZEEK_SCRIPT" > "$output_file" 2>&1 || true
        
        if [ -f "$output_file" ]; then
            # 检查是否正确恢复了统计
            if grep -q "send=15" "$output_file" || grep -q "send_count.*15" "$output_file"; then
                test_assert "true" "发送计数正确恢复"
            else
                test_assert "false" "发送计数正确恢复"
                echo "查找send=15的输出:"
                grep -i "send" "$output_file" | head -5
            fi
            
            if grep -q "receive=8" "$output_file" || grep -q "receive_count.*8" "$output_file"; then
                test_assert "true" "接收计数正确恢复"
            else
                test_assert "false" "接收计数正确恢复"
            fi
        else
            test_assert "false" "恢复测试产生输出"
        fi
        
    else
        test_assert "false" "测试状态文件存在"
    fi
    
    echo ""
}

# 测试5: 统计累加功能
test_stats_accumulation() {
    echo -e "${PURPLE}=== 测试5: 统计累加功能 ===${NC}"
    
    # 设置初始值
    export MAIL_STATS_INIT_SEND="10"
    export MAIL_STATS_INIT_RECEIVE="5"
    export SITE_ID="overseas"
    export LINK_ID="test-link"
    
    # 运行脚本进行多次统计更新
    local zeek_cmd="
    @load $MAIN_SCRIPT
    event zeek_init() {
        print fmt(\"[TEST] Initial send_count: %d\", MailActivity::send_count);
        
        # 增加2次发送
        MailActivity::update_monthly_stats(\"send\", F, F);
        MailActivity::update_monthly_stats(\"send\", F, F);
        
        print fmt(\"[TEST] Final send_count: %d\", MailActivity::send_count);
        
        # 预期结果：10 + 2 = 12
        if ( MailActivity::send_count == 12 ) {
            print \"[TEST] ✅ Accumulation test passed\";
        } else {
            print fmt(\"[TEST] ❌ Accumulation test failed: expected 12, got %d\", MailActivity::send_count);
        }
    }
    "
    
    local output_file="/tmp/zeek_test_accumulation.log"
    timeout 5s zeek -C -e "$zeek_cmd" > "$output_file" 2>&1 || true
    
    if [ -f "$output_file" ]; then
        echo "累加测试输出:"
        cat "$output_file"
        
        if grep -q "✅ Accumulation test passed" "$output_file"; then
            test_assert "true" "统计累加功能正常"
        else
            test_assert "false" "统计累加功能正常"
        fi
        
        # 检查是否显示了正确的初始和最终值
        if grep -q "Initial send_count: 10" "$output_file"; then
            test_assert "true" "初始值正确加载"
        else
            test_assert "false" "初始值正确加载"
        fi
        
    else
        test_assert "false" "累加测试产生输出"
    fi
    
    echo ""
}

# 测试6: 错误处理
test_error_handling() {
    echo -e "${PURPLE}=== 测试6: 错误处理 ===${NC}"
    
    # 测试无效的环境变量值
    export MAIL_STATS_INIT_SEND="invalid"
    export MAIL_STATS_INIT_RECEIVE="not_a_number"
    export SITE_ID="overseas"
    export LINK_ID="test-link"
    
    local zeek_cmd="
    @load $MAIN_SCRIPT
    event zeek_init() {
        print fmt(\"[TEST] Error handling - send_count: %d\", MailActivity::send_count);
        print fmt(\"[TEST] Error handling - receive_count: %d\", MailActivity::receive_count);
    }
    "
    
    local output_file="/tmp/zeek_test_error.log"
    timeout 5s zeek -C -e "$zeek_cmd" > "$output_file" 2>&1 || true
    
    if [ -f "$output_file" ]; then
        # 检查是否优雅处理了无效值（应该默认为0）
        if grep -q "send_count: 0" "$output_file" && grep -q "receive_count: 0" "$output_file"; then
            test_assert "true" "无效环境变量值优雅处理"
        else
            test_assert "false" "无效环境变量值优雅处理"
            echo "错误处理输出:"
            cat "$output_file"
        fi
    else
        test_assert "false" "错误处理测试产生输出"
    fi
    
    echo ""
}

# 显示测试结果摘要
show_test_summary() {
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                        测试结果摘要                          ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    
    echo -e "${GREEN}通过的测试: $TESTS_PASSED${NC}"
    echo -e "${RED}失败的测试: $TESTS_FAILED${NC}"
    echo -e "${BLUE}总计测试: $TESTS_TOTAL${NC}"
    
    local success_rate=0
    if [ $TESTS_TOTAL -gt 0 ]; then
        success_rate=$((TESTS_PASSED * 100 / TESTS_TOTAL))
    fi
    echo -e "${YELLOW}成功率: $success_rate%${NC}"
    
    if [ $TESTS_FAILED -eq 0 ]; then
        echo -e "${GREEN}🎉 所有单元测试通过！${NC}"
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
    
    # 运行所有测试
    test_zeek_syntax
    test_env_initialization
    test_state_file_save
    test_state_file_restore
    test_stats_accumulation
    test_error_handling
    
    # 显示结果
    echo ""
    show_test_summary
}

# 如果作为独立脚本运行
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi