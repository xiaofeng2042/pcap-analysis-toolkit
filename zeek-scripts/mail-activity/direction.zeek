##! 双端邮件监控 - 方向判定模块
##! 基于SYN路径跟踪实现智能方向判定
##! 支持多接口监控和链路状态分析

@load base/protocols/conn
@load base/protocols/ssl
@load base/frameworks/packet-filter

module MailActivity;

# 接口路径跟踪表
global interface_paths: table[string] of string;  # uid -> interface_path

# TCP包分析事件 - 捕获SYN包路径并检测链路加密
event new_packet(c: connection, p: pkt_hdr)
{
    # 只处理邮件协议端口
    if (!(c$id$resp_p in SMTP_PORTS || c$id$resp_p in POP3_PORTS || c$id$resp_p in IMAP_PORTS))
        return;
    
    local uid = c$uid;
    
    # 检查TCP标志位
    if (p$tcp?$flags && p$tcp$flags & TH_SYN != 0 && p$tcp$flags & TH_ACK == 0) {
        # 这是首个SYN包
        local src_is_internal = Site::is_local_addr(c$id$orig_h);
        local dst_is_internal = Site::is_local_addr(c$id$resp_h);
        
        # 简化的接口推断（基于IP地址范围）
        local syn_path = "";
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
        
        interface_paths[uid] = syn_path;
        print fmt("[SYN] Detected SYN packet: %s path=%s", uid, syn_path);
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
    
    # 1. SYN路径分析（主要证据）
    if (uid in interface_paths) {
        local syn_path = interface_paths[uid];
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
    
    # 2. IP地址分析（辅助证据）
    local orig_is_internal = Site::is_local_addr(orig_addr);
    local resp_is_internal = Site::is_local_addr(resp_addr);
    
    if (orig_is_internal && !resp_is_internal) {
        result$evidence += fmt("IP_FLOW:internal->external");
        if (result$direction_raw == "unknown") {
            result$direction_raw = "outbound";
            result$confidence = 0.7;
        } else if (result$direction_raw == "outbound") {
            result$confidence += 0.1;  # 增强置信度
        }
    } else if (!orig_is_internal && resp_is_internal) {
        result$evidence += fmt("IP_FLOW:external->internal");
        if (result$direction_raw == "unknown") {
            result$direction_raw = "inbound";
            result$confidence = 0.7;
        } else if (result$direction_raw == "inbound") {
            result$confidence += 0.1;  # 增强置信度
        }
    } else if (orig_is_internal && resp_is_internal) {
        result$direction_raw = "internal";
        result$confidence = 0.8;
        result$evidence += "IP_FLOW:internal->internal";
    } else {
        result$direction_raw = "transit";
        result$confidence = 0.6;
        result$evidence += "IP_FLOW:external->external";
    }
    
    # 3. SMTP角色验证（如果有相关信息）
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
    
    # 4. 链路加密状态验证
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

# 改进的标准化动作函数
function standardize_action(site_id: string, direction: string): string
{
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
        # 通用站点
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
    
    # 存储连接跟踪
    connection_tracks[uid] = track;
    
    print fmt("[TRACK] New mail connection: %s %s:%d -> %s:%d", 
              uid, c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p);
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
}

# SMTP角色检测函数（将在smtp.zeek中调用）
function update_smtp_role(uid: string, role: string)
{
    if (uid in connection_tracks) {
        connection_tracks[uid]$smtp_role = role;
        print fmt("[SMTP_ROLE] %s: %s", uid, role);
    }
}

print "[INFO] Enhanced direction determination module loaded";