#!/bin/bash

# 网络恢复脚本
# 功能：恢复网络桥接之前的配置，删除br0桥接
# 作者：自动生成
# 日期：$(date)

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# 日志函数
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 检查是否以root权限运行
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "此脚本需要root权限运行"
        echo "请使用: sudo $0"
        exit 1
    fi
}

# 恢复网络配置
restore_network() {
    local eth_interface="eth0"
    local tap_interface="tap_tap"
    local bridge_interface="br0"
    
    log_info "开始恢复网络配置..."
    
    # 获取br0的IP配置（如果存在）
    local br_ip=""
    if ip link show "$bridge_interface" &>/dev/null; then
        br_ip=$(ip addr show "$bridge_interface" | grep "inet " | head -n1 | awk '{print $2}')
        log_info "检测到桥接IP地址: $br_ip"
    fi
    
    # 1. 停止并删除桥接
    if ip link show "$bridge_interface" &>/dev/null; then
        log_info "删除桥接接口 $bridge_interface..."
        
        # 从桥接中移除接口
        if bridge link show | grep -q "$eth_interface"; then
            log_info "从桥接中移除 $eth_interface..."
            ip link set "$eth_interface" nomaster
        fi
        
        if bridge link show | grep -q "$tap_interface" 2>/dev/null; then
            log_info "从桥接中移除 $tap_interface..."
            ip link set "$tap_interface" nomaster 2>/dev/null || true
        fi
        
        # 关闭并删除桥接
        ip link set "$bridge_interface" down
        ip link delete "$bridge_interface"
    else
        log_warn "桥接接口 $bridge_interface 不存在"
    fi
    
    # 2. 恢复eth0配置
    if [[ -n "$br_ip" ]]; then
        log_info "将IP地址恢复到 $eth_interface..."
        ip addr add "$br_ip" dev "$eth_interface"
        
        # 恢复默认路由
        local gateway=$(echo "$br_ip" | sed 's/\.[0-9]*\//.1\//' | cut -d'/' -f1)
        log_info "设置默认路由到 $gateway..."
        ip route add default via "$gateway" dev "$eth_interface" 2>/dev/null || true
    fi
    
    # 3. 确保eth0启动
    log_info "启动 $eth_interface 接口..."
    ip link set "$eth_interface" up
    
    # 4. 重启NetworkManager
    log_info "重启NetworkManager服务..."
    systemctl start NetworkManager 2>/dev/null || true
    
    log_info "网络配置恢复完成！"
    echo
    echo "=== 当前网络配置 ==="
    ip addr show "$eth_interface"
    echo
    echo "路由信息："
    ip route show
}

# 显示使用说明
show_usage() {
    echo "网络恢复脚本"
    echo
    echo "用法: $0"
    echo
    echo "功能:"
    echo "  - 删除br0桥接接口"
    echo "  - 将IP配置恢复到eth0"
    echo "  - 重启NetworkManager服务"
    echo
    echo "注意:"
    echo "  - 需要root权限运行"
    echo "  - 会自动检测并恢复桥接前的配置"
}

# 主程序
main() {
    case "${1:-}" in
        -h|--help)
            show_usage
            exit 0
            ;;
        "")
            check_root
            restore_network
            ;;
        *)
            log_error "未知选项: $1"
            show_usage
            exit 1
            ;;
    esac
}

# 执行主程序
main "$@"