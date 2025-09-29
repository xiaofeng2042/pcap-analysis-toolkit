##! 双端邮件监控 - 方向判定模块
##! 基于SYN路径跟踪实现智能方向判定
##! 支持多接口监控和链路状态分析

@load base/protocols/conn
@load base/protocols/ssl
@load base/frameworks/packet-filter
@load base/utils/site

module MailActivity;

# 接口路径跟踪表已在主模块中定义

# TCP包分析事件 - 捕获SYN包路径并检测链路加密
event new_packet(c: connection, p: pkt_hdr)
{
    # 只处理邮件协议端口
    if (!(c$id$resp_p in SMTP_PORTS || c$id$resp_p in POP3_PORTS || c$id$resp_p in IMAP_PORTS))
        return;
    
    local uid = c$uid;
    local is_tunnel_conn = is_tunnel_connection(c);
    
    # 检查TCP标志位
    if (p$tcp?$flags && p$tcp$flags & TH_SYN != 0 && p$tcp$flags & TH_ACK == 0) {
        # 这是首个SYN包
        local src_is_internal = is_internal_address(c$id$orig_h);
        local dst_is_internal = is_internal_address(c$id$resp_h);
        local src_is_tunnel = is_tunnel_address(c$id$orig_h);
        local dst_is_tunnel = is_tunnel_address(c$id$resp_h);
        
        # 简化的接口推断（基于IP地址范围）
        local syn_path = "";
        local is_encrypted = F;
        local is_decrypted = F;
        
        # 隧道网络优先检测
        if (src_is_tunnel || dst_is_tunnel) {
            # 任何涉及1.1.0.*网段的连接都是加密的
            if (src_is_tunnel && !dst_is_tunnel) {
                # 从隧道网络向外发送
                syn_path = fmt("%s->%s", TUNNEL_INTERFACE, LAN_INTERFACE);
                is_encrypted = T;
                print fmt("[TUNNEL] Encrypted outbound from tunnel network: %s", c$id$orig_h);
            } else if (!src_is_tunnel && dst_is_tunnel) {
                # 向隧道网络发送
                syn_path = fmt("%s->%s", LAN_INTERFACE, TUNNEL_INTERFACE);
                is_encrypted = T;
                print fmt("[TUNNEL] Encrypted inbound to tunnel network: %s", c$id$resp_h);
            } else if (src_is_tunnel && dst_is_tunnel) {
                # 隧道内部通信
                syn_path = fmt("%s->%s", TUNNEL_INTERFACE, TUNNEL_INTERFACE);
                is_encrypted = T;
                print fmt("[TUNNEL] Encrypted tunnel-to-tunnel communication");
            }
            
            # 标记隧道加密
            mark_connection_encrypted(uid, is_encrypted, F);
        } else {
            # 传统逻辑处理非隧道流量
            if (src_is_internal && !dst_is_internal) {
                # 内网向外网发起连接，SYN路径: eno1 -> tap_tap
                syn_path = fmt("%s->%s", LAN_INTERFACE, TUNNEL_INTERFACE);
                # 标记为加密出站（通过隧道）
                mark_connection_encrypted(uid, T, F);
            } else if (!src_is_internal && dst_is_internal) {
                # 外网向内网发起连接，SYN路径: tap_tap -> eno1  
                syn_path = fmt("%s->%s", TUNNEL_INTERFACE, LAN_INTERFACE);
                # 标记为解密入站（来自隧道）
                mark_connection_encrypted(uid, F, T);
            } else {
                # 内网互连或外网中转
                syn_path = "unknown";
            }
        }
        
        interface_paths[uid] = syn_path;
        print fmt("[SYN] Detected SYN packet: %s path=%s tunnel=%s", uid, syn_path, is_tunnel_conn ? "yes" : "no");
    }
}

# 标记连接的加密状态
function mark_connection_encrypted(uid: string, is_encrypted: bool, is_decrypted: bool)
{
    # 先确保连接跟踪记录存在
    if (uid !in connection_tracks) {
        local track: ConnectionTrack;
        connection_tracks[uid] = track;
    }
    
    connection_tracks[uid]$link_encrypted = is_encrypted;
    connection_tracks[uid]$link_decrypted = is_decrypted;
    
    print fmt("[LINK] Connection %s: encrypted=%s decrypted=%s", 
              uid, is_encrypted ? "true" : "false", is_decrypted ? "true" : "false");
}

# 检查连接是否通过tap_tap接口（基于路径推断）
function is_through_tap_interface(c: connection): bool
{
    local uid = c$uid;
    if (uid in interface_paths) {
        local path = interface_paths[uid];
        # 检查路径是否涉及tap_tap接口
        return (TUNNEL_INTERFACE in path);
    }
    return F;
}

# 改进的方向判定函数
function determine_direction(c: connection, track: ConnectionTrack): DirectionInfo
{
    local result: DirectionInfo;
    result$direction_raw = "unknown";
    result$action = "unknown";
    result$evidence = vector();
    result$confidence = 0.0;
    
    local uid = c$uid;
    local orig_addr = c$id$orig_h;
    local resp_addr = c$id$resp_h;
    local syn_path = "";
    
    # 1. SYN路径分析（主要证据）
    if (uid in interface_paths) {
        syn_path = interface_paths[uid];
        result$evidence += fmt("SYN_PATH:%s", syn_path);
        
        if (syn_path == fmt("%s->%s", LAN_INTERFACE, TUNNEL_INTERFACE)) {
            # eno1 -> tap_tap: 发送到对端
            result$direction_raw = "outbound";
            result$confidence = 0.8;
        } else if (syn_path == fmt("%s->%s", TUNNEL_INTERFACE, LAN_INTERFACE)) {
            # tap_tap -> eno1: 从对端接收
            result$direction_raw = "inbound";
            result$confidence = 0.8;
        } else {
            result$confidence = 0.5;  # 未知路径，降低置信度
        }
    }
    
    # 2. 隧道流量特殊处理（优先级最高）
    local orig_is_internal = is_internal_address(orig_addr);
    local resp_is_internal = is_internal_address(resp_addr);
    local orig_is_tunnel = is_tunnel_address(orig_addr);
    local resp_is_tunnel = is_tunnel_address(resp_addr);
    local is_tunnel_conn = orig_is_tunnel || resp_is_tunnel;
    local is_tap_interface = is_through_tap_interface(c);
    
    # 特殊处理：隧道流量方向判定（基于本地IP检测）
    if (is_tunnel_conn) {
        if (orig_is_tunnel) {
            if (is_local_tunnel_ip(orig_addr)) {
                # 本地隧道IP发出的流量：待加密的出站邮件
                result$evidence += fmt("TUNNEL_LOCAL_IP:encrypt_outbound_%s", orig_addr);
                result$direction_raw = "outbound_from_local";
                result$confidence = 0.98;  # 极高置信度
                print fmt("[TUNNEL] Local tunnel IP sending mail (encrypt): %s", uid);
            } else {
                # 远端隧道IP发来的流量：解密后的入站邮件
                result$evidence += fmt("TUNNEL_REMOTE_IP:decrypt_inbound_%s", orig_addr);
                result$direction_raw = "inbound_to_local";
                result$confidence = 0.98;  # 极高置信度
                print fmt("[TUNNEL] Remote tunnel IP sending mail (decrypt): %s", uid);
            }
        } else if (resp_is_tunnel) {
            if (is_local_tunnel_ip(resp_addr)) {
                # 发往本地隧道IP的流量：内部流量（不常见）
                result$evidence += fmt("TUNNEL_LOCAL_IP:internal_%s", resp_addr);
                result$direction_raw = "internal_to_local";
                result$confidence = 0.90;
                print fmt("[TUNNEL] Mail to local tunnel IP (internal): %s", uid);
            } else {
                # 发往远端隧道IP的流量：待加密的出站邮件
                result$evidence += fmt("TUNNEL_REMOTE_IP:encrypt_outbound_%s", resp_addr);
                result$direction_raw = "outbound_from_local";
                result$confidence = 0.98;  # 极高置信度
                print fmt("[TUNNEL] Mail to remote tunnel IP (encrypt): %s", uid);
            }
        }
        
        # 添加SYN路径作为辅助证据（如果可用）
        if (uid in interface_paths) {
            syn_path = interface_paths[uid];
            result$evidence += fmt("SYN_PATH:%s", syn_path);
        }
    }
    
    # 3. 常规IP地址分析（隧道流量已处理的情况下执行）
    if (result$confidence < 0.8) {  # 只有隧道检测置信度不高时才执行常规检测
        # 优先检测投入本机的包（目标为本机的连接）
        if (resp_is_internal) {
            if (!orig_is_internal) {
                # 外部向本机发送邮件 - 这是我们重点关注的"投入本机"的包
                result$evidence += fmt("IP_FLOW:external->local_machine");
                result$direction_raw = "inbound_to_local";
                result$confidence = 0.9;  # 高置信度，这是我们的主要目标
            } else {
                # 内网向本机发送 - 也是投入本机的包
                result$evidence += fmt("IP_FLOW:internal->local_machine");
                result$direction_raw = "internal_to_local";
                result$confidence = 0.8;
            }
        } else if (orig_is_internal && !resp_is_internal) {
            # 本机向外部发送 - 次要关注
            result$evidence += fmt("IP_FLOW:local_machine->external");
            result$direction_raw = "outbound_from_local";
            result$confidence = 0.6;
        } else if (orig_is_internal && resp_is_internal) {
            # 内网互连 - 可能包含本机
            result$evidence += fmt("IP_FLOW:internal->internal");
            result$direction_raw = "internal";
            result$confidence = 0.5;
        } else {
            # 外网中转 - 不是我们关注的重点
            result$evidence += fmt("IP_FLOW:external->external");
            result$direction_raw = "transit";
            result$confidence = 0.2;  # 低置信度，不是重点
        }
    }
    
    # 4. SMTP角色验证（如果有相关信息）
    if (track?$smtp_role) {
        result$evidence += fmt("SMTP_ROLE:%s", track$smtp_role);
        
        # SMTP角色与方向的一致性检查
        if (track$smtp_role == "client_first" && result$direction_raw == "outbound") {
            result$confidence += 0.05;  # 一致性奖励
        } else if (track$smtp_role == "server_first" && result$direction_raw == "inbound") {
            result$confidence += 0.05;  # 一致性奖励
        } else if (track$smtp_role == "client_first" && result$direction_raw == "inbound") {
            result$confidence -= 0.1;   # 不一致惩罚
        } else if (track$smtp_role == "server_first" && result$direction_raw == "outbound") {
            result$confidence -= 0.1;   # 不一致惩罚
        }
    }
    
    # 5. 协议端口兜底逻辑（优先考虑投入本机的包）
    if (result$direction_raw == "unknown" || result$confidence < 0.6) {
        local service_port = c$id$resp_p;
        
        # 检查是否为投入本机的邮件服务连接
        if (resp_is_internal) {
            if (service_port in SMTP_PORTS) {
                # 外部向本机SMTP服务器发送邮件
                result$direction_raw = "inbound_to_local";
                result$confidence = 0.8;
                result$evidence += fmt("PORT_HEURISTIC:SMTP_to_local");
            } else if (service_port in POP3_PORTS || service_port in IMAP_PORTS) {
                # 客户端连接本机的POP3/IMAP服务器收取邮件
                result$direction_raw = "inbound_to_local";
                result$confidence = 0.8;
                result$evidence += fmt("PORT_HEURISTIC:%s_to_local", identify_protocol(service_port));
            }
        } else {
            # 非本机目标的连接，降低优先级
            if (service_port in SMTP_PORTS) {
                result$direction_raw = "outbound_from_local";
                result$confidence = 0.5;  # 降低置信度
                result$evidence += fmt("PORT_HEURISTIC:SMTP_from_local");
            } else if (service_port in POP3_PORTS || service_port in IMAP_PORTS) {
                result$direction_raw = "outbound_from_local";
                result$confidence = 0.5;  # 降低置信度
                result$evidence += fmt("PORT_HEURISTIC:%s_from_local", identify_protocol(service_port));
            }
        }
    }

    # 6. 隧道网络加密检测（已整合到第2步，保留兼容性）
    if (is_tunnel_conn) {
        if (orig_is_tunnel) {
            result$evidence += fmt("TUNNEL:%s", orig_addr);
        }
        if (resp_is_tunnel) {
            result$evidence += fmt("TUNNEL:%s", resp_addr);
        }
        
        # 隧道网络流量被认为是加密的
        result$confidence += 0.1;
        
        # 对于投入本机的隧道流量，进一步提高置信度
        if (resp_is_internal && (orig_is_tunnel || resp_is_tunnel)) {
            result$confidence += 0.05;
            result$evidence += "TUNNEL_TO_LOCAL";
        }
    }
    
    # 7. tap_tap接口加密检测（已整合到第2步，保留兼容性）
    if (is_tap_interface) {
        result$evidence += fmt("INTERFACE:%s", TUNNEL_INTERFACE);
        result$confidence += 0.08;
    }
    
    # 8. 链路加密状态验证（原有逻辑）
    if (track$link_encrypted) {
        result$evidence += "LINK:encrypted";
        # 加密连接通常表示出站流量
        if (result$direction_raw == "outbound") {
            result$confidence += 0.03;
        }
    }
    
    if (track$link_decrypted) {
        result$evidence += "LINK:decrypted";
        # 解密连接通常表示入站流量
        if (result$direction_raw == "inbound") {
            result$confidence += 0.03;
        }
    }
    
    # 限制置信度范围 [0.0, 1.0]
    if (result$confidence > 1.0) {
        result$confidence = 1.0;
    } else if (result$confidence < 0.0) {
        result$confidence = 0.0;
    }
    
    # 生成标准化动作描述
    result$action = standardize_action(SITE_ID, result$direction_raw);
    
    print fmt("[DIRECTION] %s: %s (confidence=%.2f) evidence=%s", 
              uid, result$action, result$confidence, result$evidence);
    
    return result;
}

# 改进的标准化动作函数（重点关注投入本机的动作）
function standardize_action(site_id: string, direction: string): string
{
    # 优先处理投入本机的动作
    if (direction == "inbound_to_local") {
        return "receive_to_local_machine";
    } else if (direction == "internal_to_local") {
        return "internal_to_local_machine";
    } else if (direction == "outbound_from_local") {
        return "send_from_local_machine";
    }
    
    # 原有的站点间逻辑保持不变，但优先级降低
    if (site_id == "overseas") {
        if (direction == "outbound") {
            return "send_to_hq";
        } else if (direction == "inbound") {
            return "receive_from_hq"; 
        } else if (direction == "internal") {
            return "overseas_internal";
        } else {
            return "overseas_transit";
        }
    } else if (site_id == "hq") {
        if (direction == "outbound") {
            return "send_to_overseas";
        } else if (direction == "inbound") {
            return "receive_from_overseas";
        } else if (direction == "internal") {
            return "hq_internal";
        } else {
            return "hq_transit";
        }
    } else {
        # 通用站点 - 重点关注本机相关动作
        if (direction == "outbound") {
            return "send_to_peer";
        } else if (direction == "inbound") {
            return "receive_from_peer";
        } else if (direction == "internal") {
            return "internal_transfer";
        } else {
            return "transit";
        }
    }
}

# 连接建立事件 - 创建连接跟踪
event connection_established(c: connection)
{
    # 检查是否为邮件协议端口
    if (!(c$id$resp_p in SMTP_PORTS || c$id$resp_p in POP3_PORTS || c$id$resp_p in IMAP_PORTS)) {
        return;
    }
    
    local uid = c$uid;
    
    # 创建连接跟踪记录
    local track: ConnectionTrack;
    
    # 获取SYN路径信息
    if (uid in interface_paths) {
        track$syn_path = interface_paths[uid];
    } else {
        track$syn_path = "unknown";
    }
    
    # 检查是否为隧道连接并标记加密状态
    if (is_tunnel_connection(c)) {
        track$link_encrypted = T;
        print fmt("[TRACK] Tunnel connection detected and marked as encrypted: %s", uid);
    }
    
    # 检查是否通过tap_tap接口
    if (is_through_tap_interface(c)) {
        track$link_encrypted = T;
        print fmt("[TRACK] tap_tap interface connection detected and marked as encrypted: %s", uid);
    }
    
    # 存储连接跟踪
    connection_tracks[uid] = track;
    
    print fmt("[TRACK] New mail connection: %s %s:%d -> %s:%d tunnel=%s tap=%s", 
              uid, c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p,
              is_tunnel_connection(c) ? "yes" : "no",
              is_through_tap_interface(c) ? "yes" : "no");
}

# 连接结束事件 - 清理跟踪数据
event connection_state_remove(c: connection)
{
    local uid = c$uid;
    
    # 清理连接跟踪
    if (uid in connection_tracks) {
        delete connection_tracks[uid];
    }
    
    # 清理接口路径记录
    if (uid in interface_paths) {
        delete interface_paths[uid];
    }
    
    # 清理日志分离的方向信息
    cleanup_connection_direction(uid);
}

# SMTP角色检测函数（将在smtp.zeek中调用）
function update_smtp_role(uid: string, role: string)
{
    if (uid in connection_tracks) {
        connection_tracks[uid]$smtp_role = role;
        print fmt("[SMTP_ROLE] %s: %s", uid, role);
    }
}

event zeek_init()
{
    print "[INFO] Enhanced direction determination module loaded";
}
