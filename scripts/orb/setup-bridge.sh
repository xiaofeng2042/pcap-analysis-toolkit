#!/bin/bash

# 网络桥接设置脚本
# 功能：自动读取eth0的IP配置，创建br0桥接，并将eth0和tap_tap加入桥接
# 作者：自动生成
# 日期：$(date)

set -e  # 遇到错误立即退出

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

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

# 检查网络接口是否存在
check_interface() {
    local interface=$1
    if ! ip link show "$interface" &>/dev/null; then
        log_error "网络接口 $interface 不存在"
        return 1
    fi
    return 0
}

# 获取接口的IP地址和子网掩码
get_ip_info() {
    local interface=$1
    local ip_info=$(ip addr show "$interface" | grep "inet " | head -n1 | awk '{print $2}')
    echo "$ip_info"
}

# 获取默认网关
get_default_gateway() {
    local gateway=$(ip route show default | grep "dev eth0" | awk '{print $3}' | head -n1)
    echo "$gateway"
}

# 检查VPN进程是否运行
check_vpn_processes() {
    local vpnbridge_running=false
    local vpnserver_running=false
    
    # 检查vpnbridge进程
    if pgrep -f "vpnbridge" >/dev/null 2>&1; then
        vpnbridge_running=true
        log_info "检测到vpnbridge进程正在运行"
    fi
    
    # 检查vpnserver进程
    if pgrep -f "vpnserver" >/dev/null 2>&1; then
        vpnserver_running=true
        log_info "检测到vpnserver进程正在运行"
    fi
    
    # 返回检测结果（通过全局变量）
    VPN_BRIDGE_RUNNING=$vpnbridge_running
    VPN_SERVER_RUNNING=$vpnserver_running
}

# 配置VPN相关的桥接IP
configure_vpn_bridge_ip() {
    local bridge_interface="br0"
    
    # 检查VPN进程
    check_vpn_processes
    
    # 根据VPN进程配置相应的IP
    if [[ "$VPN_BRIDGE_RUNNING" == true ]]; then
        log_info "为vpnbridge配置桥接IP: br0:0 1.1.0.100/24"
        ifconfig "${bridge_interface}:0" 1.1.0.100/24 2>/dev/null || {
            log_warn "使用ifconfig配置失败，尝试使用ip命令"
            ip addr add 1.1.0.100/24 dev "$bridge_interface" label "${bridge_interface}:0" 2>/dev/null || {
                log_error "配置vpnbridge IP失败"
                return 1
            }
        }
        log_info "vpnbridge IP配置成功: 1.1.0.100/24"
    fi
    
    if [[ "$VPN_SERVER_RUNNING" == true ]]; then
        log_info "为vpnserver配置桥接IP: br0:0 1.1.0.2/24"
        ifconfig "${bridge_interface}:0" 1.1.0.2/24 2>/dev/null || {
            log_warn "使用ifconfig配置失败，尝试使用ip命令"
            ip addr add 1.1.0.2/24 dev "$bridge_interface" label "${bridge_interface}:0" 2>/dev/null || {
                log_error "配置vpnserver IP失败"
                return 1
            }
        }
        log_info "vpnserver IP配置成功: 1.1.0.2/24"
    fi
    
    # 如果两个进程都在运行，给出警告
    if [[ "$VPN_BRIDGE_RUNNING" == true && "$VPN_SERVER_RUNNING" == true ]]; then
        log_warn "检测到vpnbridge和vpnserver同时运行，可能存在IP冲突"
        log_warn "vpnserver配置将覆盖vpnbridge配置"
    fi
    
    # 如果没有检测到VPN进程
    if [[ "$VPN_BRIDGE_RUNNING" == false && "$VPN_SERVER_RUNNING" == false ]]; then
        log_info "未检测到VPN进程，跳过VPN桥接IP配置"
    fi
}

# 备份当前网络配置
backup_config() {
    log_info "备份当前网络配置..."
    ip addr show > /tmp/network_backup_$(date +%Y%m%d_%H%M%S).txt
    ip route show >> /tmp/network_backup_$(date +%Y%m%d_%H%M%S).txt
}

# 主要的桥接设置函数
setup_bridge() {
    local eth_interface="eth0"
    local tap_interface="tap_tap"
    local bridge_interface="br0"
    
    log_info "开始设置网络桥接..."
    
    # 检查必要的网络接口
    if ! check_interface "$eth_interface"; then
        exit 1
    fi
    
    if ! check_interface "$tap_interface"; then
        log_warn "tap_tap 接口不存在，将跳过添加到桥接"
        tap_interface=""
    fi
    
    # 获取eth0的IP配置
    log_info "读取 $eth_interface 的网络配置..."
    local eth_ip=$(get_ip_info "$eth_interface")
    local gateway=$(get_default_gateway)
    
    if [[ -z "$eth_ip" ]]; then
        log_error "无法获取 $eth_interface 的IP地址"
        exit 1
    fi
    
    log_info "检测到IP地址: $eth_ip"
    log_info "检测到网关: $gateway"
    
    # 备份配置
    backup_config
    
    # 1. 停止NetworkManager（如果运行）
    log_info "停止NetworkManager服务（如果运行）..."
    systemctl stop NetworkManager 2>/dev/null || true
    
    # 2. 清空接口地址（避免IP冲突）
    log_info "清空网络接口地址..."
    ip addr flush dev "$eth_interface" 2>/dev/null || true
    if [[ -n "$tap_interface" ]]; then
        ip addr flush dev "$tap_interface" 2>/dev/null || true
    fi
    
    # 3. 创建桥接 br0
    log_info "创建桥接接口 $bridge_interface..."
    if ip link show "$bridge_interface" &>/dev/null; then
        log_warn "桥接接口 $bridge_interface 已存在，删除后重新创建..."
        ip link set "$bridge_interface" down 2>/dev/null || true
        ip link delete "$bridge_interface" 2>/dev/null || true
    fi
    ip link add name "$bridge_interface" type bridge
    
    # 4. 将接口加入桥接
    log_info "将 $eth_interface 加入桥接..."
    ip link set "$eth_interface" master "$bridge_interface"
    
    if [[ -n "$tap_interface" ]]; then
        log_info "将 $tap_interface 加入桥接..."
        ip link set "$tap_interface" master "$bridge_interface"
    fi
    
    # 5. 启动所有接口
    log_info "启动网络接口..."
    ip link set "$eth_interface" up
    if [[ -n "$tap_interface" ]]; then
        ip link set "$tap_interface" up
    fi
    ip link set "$bridge_interface" up
    
    # 6. 将原来eth0的地址迁移到br0
    log_info "将IP地址迁移到桥接接口..."
    ip addr add "$eth_ip" dev "$bridge_interface"
    
    # 7. 设置默认路由
    if [[ -n "$gateway" ]]; then
        log_info "设置默认路由..."
        ip route add default via "$gateway" dev "$bridge_interface"
    fi
    
    # 8. 配置VPN相关的桥接IP（如果有VPN进程运行）
    log_info "检查VPN进程并配置相应的桥接IP..."
    configure_vpn_bridge_ip
    
    # 9. 显示配置结果
    log_info "桥接设置完成！"
    echo
    echo "=== 当前网络配置 ==="
    echo "桥接接口信息："
    ip addr show "$bridge_interface"
    echo
    echo "路由信息："
    ip route show
    echo
    echo "桥接成员："
    bridge link show
}

# 清理函数（出错时恢复）
cleanup() {
    log_warn "检测到错误，尝试恢复网络配置..."
    # 这里可以添加恢复逻辑
    systemctl start NetworkManager 2>/dev/null || true
}

# 设置错误处理
trap cleanup ERR

# 显示使用说明
show_usage() {
    echo "网络桥接设置脚本"
    echo
    echo "用法: $0 [选项]"
    echo
    echo "选项:"
    echo "  -h, --help     显示此帮助信息"
    echo "  -d, --dry-run  仅显示将要执行的操作，不实际执行"
    echo
    echo "功能:"
    echo "  - 自动读取eth0的IP地址和路由配置"
    echo "  - 创建br0桥接接口"
    echo "  - 将eth0和tap_tap加入桥接"
    echo "  - 将IP配置迁移到br0"
    echo "  - 自动检测VPN进程并配置相应的桥接IP："
    echo "    * vpnbridge进程 -> br0:0 配置为 1.1.0.100/24"
    echo "    * vpnserver进程 -> br0:0 配置为 1.1.0.2/24"
    echo
    echo "注意:"
    echo "  - 需要root权限运行"
    echo "  - 会自动备份当前网络配置到/tmp/"
    echo "  - 如果tap_tap不存在会自动跳过"
}

# 干运行模式
dry_run() {
    local eth_interface="eth0"
    local eth_ip=$(get_ip_info "$eth_interface")
    local gateway=$(get_default_gateway)
    
    echo "=== 干运行模式 - 将要执行的操作 ==="
    echo "1. 停止NetworkManager"
    echo "2. 清空 eth0 和 tap_tap 的IP地址"
    echo "3. 创建桥接接口 br0"
    echo "4. 将 eth0 加入 br0"
    echo "5. 将 tap_tap 加入 br0（如果存在）"
    echo "6. 启动所有接口"
    echo "7. 将IP地址 $eth_ip 设置到 br0"
    echo "8. 设置默认路由到网关 $gateway"
    echo "9. 检测VPN进程并配置相应的桥接IP"
    echo
    echo "当前检测到的配置："
    echo "  eth0 IP: $eth_ip"
    echo "  网关: $gateway"
    echo "  tap_tap存在: $(check_interface tap_tap && echo "是" || echo "否")"
    echo "  VPN进程状态:"
    check_vpn_processes
}

# 主程序
main() {
    case "${1:-}" in
        -h|--help)
            show_usage
            exit 0
            ;;
        -d|--dry-run)
            dry_run
            exit 0
            ;;
        "")
            check_root
            setup_bridge
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