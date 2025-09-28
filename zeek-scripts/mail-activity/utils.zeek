# utils.zeek - 工具函数和TLS/SSL处理模块
# 提供通用工具函数和TLS/SSL加密处理功能

@load base/protocols/ssl
@load base/utils/site

module MailActivity;

# 定义隧道加密网络段
const TUNNEL_NETWORKS: set[subnet] = {
    1.1.0.0/24,      # VPN隧道网络段
} &redef;

# 内部网络配置
const INTERNAL_NETWORKS: set[subnet] = {
    10.0.0.0/8,      # RFC 1918 私有网络
    172.16.0.0/12,   # RFC 1918 私有网络  
    192.168.0.0/16,  # RFC 1918 私有网络
    127.0.0.0/8,     # 回环地址
} &redef;

# 扩展 Site::local_nets 包含我们的内部网络定义
redef Site::local_nets += INTERNAL_NETWORKS;
# 同时将隧道网络也加入本地网络，这样可以正确识别方向
redef Site::local_nets += TUNNEL_NETWORKS;

# 检查IP地址是否在隧道网络中
function is_tunnel_address(ip: addr): bool
{
    for (net in TUNNEL_NETWORKS) {
        if (ip in net) {
            return T;
        }
    }
    return F;
}

# 检查IP地址是否为内部地址
function is_internal_address(ip: addr): bool
{
    return Site::is_local_addr(ip);
}

# 检查连接是否涉及隧道网络
function is_tunnel_connection(c: connection): bool
{
    return is_tunnel_address(c$id$orig_h) || is_tunnel_address(c$id$resp_h);
}

# 检查隧道IP是否为本地设备IP
function is_local_tunnel_ip(ip: addr): bool
{
    # 首先确认IP在隧道网段内
    if (!is_tunnel_address(ip)) {
        return F;
    }
    
    # 精确检查是否为配置的本地隧道IP
    return ip == LOCAL_TUNNEL_IP;
}

# 工具函数：创建基础Info记录
function create_base_info(c: connection): Info
{
    return [$ts = network_time(),
            $uid = c$uid,
            $id = c$id];
}

# 工具函数：检查是否为邮件协议端口
function is_mail_port(p: port): bool
{
    return (p in SMTP_PORTS || p in POP3_PORTS || p in IMAP_PORTS);
}

# 工具函数：识别协议类型
function identify_protocol(p: port): string
{
    if (p in SMTP_PORTS)
        return "SMTP";
    else if (p in POP3_PORTS)
        return "POP3";
    else if (p in IMAP_PORTS)
        return "IMAP";
    else
        return "UNKNOWN";
}

# 工具函数：检查是否为隐式TLS端口
function is_implicit_tls_port(p: port): bool
{
    return (p == 465/tcp || p == 993/tcp || p == 995/tcp ||
            p == 3465/tcp || p == 3993/tcp || p == 3995/tcp);
}

# 工具函数：清理登录信息（脱敏处理）
function sanitize_login_info(line: string): string
{
    local sanitized = line;
    
    # 脱敏IMAP LOGIN命令
    sanitized = sub(sanitized, /LOGIN [^ ]+ [^ ]+/, "LOGIN [USER] [PASS]");
    
    # 脱敏POP3 PASS命令
    if (/^PASS / in sanitized)
        sanitized = "PASS [REDACTED]";
    
    return sanitized;
}

# SSL/TLS 连接建立事件处理
event ssl_established(c: connection)
{
    # 检查是否为邮件协议端口
    if (!is_mail_port(c$id$resp_p))
        return;
        
    local uid = c$uid;
    local protocol = identify_protocol(c$id$resp_p);
    local is_implicit_tls = is_implicit_tls_port(c$id$resp_p);
    
    # 增加加密连接计数
    ++encrypted_connections;
    
    # 处理现有会话的 TLS 升级
    if (uid in smtp_sessions) {
        local smtp_info = smtp_sessions[uid];
        smtp_info$tls = T;
        if (c$ssl?$version)
            smtp_info$tls_version = c$ssl$version;
        smtp_sessions[uid] = smtp_info;
        Log::write(LOG, smtp_info);
    }
    else if (uid in pop3_sessions) {
        local pop3_info = pop3_sessions[uid];
        pop3_info$tls = T;
        if (c$ssl?$version)
            pop3_info$tls_version = c$ssl$version;
        pop3_sessions[uid] = pop3_info;
        Log::write(LOG, pop3_info);
    }
    else if (uid in imap_sessions) {
        local imap_info = imap_sessions[uid];
        imap_info$tls = T;
        if (c$ssl?$version)
            imap_info$tls_version = c$ssl$version;
        imap_sessions[uid] = imap_info;
        Log::write(LOG, imap_info);
    }
    # 处理隐式 TLS 连接（从连接开始就是加密的）
    else if (is_implicit_tls) {
        local tls_info = create_base_info(c);
        tls_info$protocol = protocol;
        tls_info$tls = T;
        tls_info$role = "client";
        tls_info$activity = fmt("%sS_TLS_ESTABLISHED", protocol);
        
        if (c$ssl?$version)
            tls_info$tls_version = c$ssl$version;
        
        Log::write(LOG, tls_info);
        
        print fmt("[%s] Implicit TLS connection established: %s:%d -> %s:%d (TLS: %s)", 
                  protocol, c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p, 
                  c$ssl?$version ? c$ssl$version : "unknown");
    }
    
    print fmt("[TLS] SSL/TLS Connection Established: %s:%d -> %s:%d (%s)", 
              c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p, protocol);
}

# 连接状态移除事件处理
event connection_state_remove(c: connection)
{
    local uid = c$uid;
    
    # 清理SMTP会话
    if (uid in smtp_sessions) {
        local smtp_info = smtp_sessions[uid];
        smtp_info$activity = "SMTP_CONNECTION_END";
        Log::write(LOG, smtp_info);
        delete smtp_sessions[uid];
        print fmt("[SMTP] Connection ended: %s", uid);
    }
    
    # 清理POP3会话
    if (uid in pop3_sessions) {
        local pop3_info = pop3_sessions[uid];
        pop3_info$activity = "POP3_CONNECTION_END";
        Log::write(LOG, pop3_info);
        delete pop3_sessions[uid];
        
        # 清理POP3会话状态
        if (uid in pop3_session_states)
            delete pop3_session_states[uid];
            
        print fmt("[POP3] Connection ended: %s", uid);
    }
    
    # 清理IMAP会话
    if (uid in imap_sessions) {
        local imap_info = imap_sessions[uid];
        imap_info$activity = "IMAP_CONNECTION_END";
        Log::write(LOG, imap_info);
        delete imap_sessions[uid];
        print fmt("[IMAP] Connection ended: %s", uid);
    }
}