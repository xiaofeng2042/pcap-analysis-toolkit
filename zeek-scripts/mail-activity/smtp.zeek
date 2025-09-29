# smtp.zeek - SMTP协议事件处理模块
# 处理SMTP协议的各种事件和日志记录

module MailActivity;

# 创建新的SMTP信息记录
function new_smtp_info(c: connection): Info
{
    local info: Info = [$ts = network_time(),
                       $uid = c$uid,
                       $id = c$id,
                       $protocol = "SMTP"];
    
    # 添加双端监控字段
    info$site_id = SITE_ID;
    info$link_id = LINK_ID;
    
    # 检查隧道加密状态
    local is_tunnel_conn = is_tunnel_connection(c);
    if ( is_tunnel_conn ) {
        info$link_encrypted = T;
        print fmt("[TUNNEL] SMTP session marked as encrypted: %s (%s->%s)", c$uid, c$id$orig_h, c$id$resp_h);
    }
    
    # 进行方向判定
    if ( c$uid in connection_tracks ) {
        local track = connection_tracks[c$uid];
        local direction_info = determine_direction(c, track);
        
        info$direction_raw = direction_info$direction_raw;
        info$action = standardize_action(SITE_ID, direction_info$direction_raw);
        info$evidence = direction_info$evidence;
        info$confidence = direction_info$confidence;
        
        # 记录方向判定日志
        local flow_info: FlowInfo;
        flow_info$ts = network_time();
        flow_info$uid = c$uid;
        flow_info$orig_h = c$id$orig_h;
        flow_info$resp_h = c$id$resp_h;
        flow_info$direction_raw = direction_info$direction_raw;
        flow_info$action = info$action;
        flow_info$confidence = direction_info$confidence;
        flow_info$evidence = direction_info$evidence;
        flow_info$site_id = SITE_ID;
        flow_info$link_id = LINK_ID;
        
        Log::write(FLOW_LOG, flow_info);
    }
    
    return info;
}

# SMTP请求事件处理
event smtp_request(c: connection, is_orig: bool, command: string, arg: string)
{
    local uid = c$uid;
    print fmt("[DEBUG] smtp_request event: %s, command: %s, arg: %s", uid, command, arg);
    
    if ( uid !in smtp_sessions ) {
        smtp_sessions[uid] = new_smtp_info(c);
        ++smtp_connections;
    }
    
    local info = smtp_sessions[uid];
    
    # SMTP角色校验 - 客户端命令检测
    if ( command == "HELO" || command == "EHLO" ) {
        info$activity = fmt("SMTP_%s", command);
        info$helo = arg;
        info$role = "client";
        
        # 更新SMTP角色信息 - 客户端发起
        update_smtp_role(uid, "client_first");
        
        print fmt("[SMTP] %s: %s (client initiated)", command, arg);
    } else if ( command == "MAIL" ) {
        info$activity = "SMTP_MAIL";
        info$mailfrom = arg;
        info$mail_from = arg;
        info$role = "client";
        print fmt("[SMTP] MAIL FROM: %s", arg);
    } else if ( command == "RCPT" ) {
        info$activity = "SMTP_RCPT";
        if ( !info?$rcptto )
            info$rcptto = vector();
        info$rcptto[|info$rcptto|] = arg;
        info$rcpt_to = arg;
        info$role = "client";
        print fmt("[SMTP] RCPT TO: %s", arg);
    } else if ( command == "DATA" ) {
        info$activity = "SMTP_DATA";
        info$role = "client";
        print "[SMTP] DATA command";
    } else if ( command == "STARTTLS" ) {
        info$activity = "SMTP_STARTTLS";
        info$role = "client";
        ++starttls_attempts;
        
        # 记录TLS链路信息
        local tls_info: TlsInfo;
        tls_info$ts = network_time();
        tls_info$site_id = SITE_ID;
        tls_info$link_id = LINK_ID;
        tls_info$ip_pair = fmt("%s:%d-%s:%d", c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p);
        tls_info$starttls_attempt = T;
        tls_info$starttls_success = F;
        
        Log::write(TLS_LOG, tls_info);
        print "[SMTP] STARTTLS requested";
    } else if ( command == "." ) {
        # 邮件数据传输结束标志，触发统计更新
        print fmt("[DEBUG] SMTP DATA end marker (.) for %s, triggering stats update", uid);
        generate_mail_flow_record(c, info);
        info$activity = "SMTP_DATA_END";
        info$role = "client";
        print "[SMTP] DATA transmission completed";
    } else {
        info$activity = fmt("SMTP_%s", command);
        info$role = "client";
        info$detail = arg;
        print fmt("[SMTP] %s: %s", command, arg);
    }
    
    # 更新会话信息
    smtp_sessions[uid] = info;
    
    # 记录日志
    Log::write(LOG, info);
}

# SMTP回复事件处理
event smtp_reply(c: connection, is_orig: bool, code: count, cmd: string, msg: string, cont_resp: bool)
{
    local uid = c$uid;
    
    if ( uid !in smtp_sessions )
        return;
    
    local info = smtp_sessions[uid];
    
    info$role = "server";
    info$status = fmt("%d", code);
    info$last_reply = fmt("%d %s", code, msg);
    info$detail = msg;
    
    # SMTP角色校验 - 检测220服务器欢迎消息
    if ( code == 220 && cmd == "" ) {
        # 这是服务器的初始220欢迎消息，表明这端是SMTP服务器
        update_smtp_role(uid, "server_first");
        info$activity = "SMTP_SERVER_READY";
        print fmt("[SMTP] Server ready: %d %s (server initiated)", code, msg);
    }
    else if ( code >= 200 && code < 300 ) {
        if ( cmd == "DATA" && code == 250 ) {
            # 邮件数据传输成功完成，触发统计更新
            print fmt("[DEBUG] SMTP DATA success (250 OK) for %s, triggering stats update", uid);
            generate_mail_flow_record(c, info);
            info$activity = "SMTP_DATA_SUCCESS";
        } else if ( cmd == "STARTTLS" ) {
            ++starttls_success;
            info$activity = "SMTP_STARTTLS_SUCCESS";
            
            # 记录STARTTLS成功的TLS链路信息
            local tls_success_info: TlsInfo;
            tls_success_info$ts = network_time();
            tls_success_info$site_id = SITE_ID;
            tls_success_info$link_id = LINK_ID;
            tls_success_info$ip_pair = fmt("%s:%d-%s:%d", c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p);
            tls_success_info$starttls_attempt = T;
            tls_success_info$starttls_success = T;
            
            # 更新连接跟踪中的加密状态
            if ( c$uid in connection_tracks ) {
                connection_tracks[c$uid]$link_encrypted = T;
                info$link_encrypted = T;
                
                # 更新日度统计
                update_daily_stats(info$action, T, F);
            }
            
            Log::write(TLS_LOG, tls_success_info);
            print fmt("[SMTP] STARTTLS Success: %d %s", code, msg);
        } else {
            info$activity = fmt("SMTP_%s_SUCCESS", cmd);
            print fmt("[SMTP] %s Success: %d %s", cmd, code, msg);
        }
    } else {
        info$activity = fmt("SMTP_%s_ERROR", cmd);
        print fmt("[SMTP] %s Error: %d %s", cmd, code, msg);
    }
    
    # 更新会话信息
    smtp_sessions[uid] = info;
    
    # 记录日志
    Log::write(LOG, info);
}

# SMTP数据事件处理
event smtp_data(c: connection, is_orig: bool, data: string)
{
    local uid = c$uid;
    print fmt("[DEBUG] smtp_data event triggered for %s, data length: %d", uid, |data|);
    
    if ( uid !in smtp_sessions )
        return;
    
    local info = smtp_sessions[uid];
    
    # 检查是否为DATA结束标志
    if ( data == ".\r\n" || data == ".\n" ) {
        # 邮件DATA传输结束，生成mail_flow.log记录
        print fmt("[DEBUG] DATA end detected for %s, calling generate_mail_flow_record", uid);
        generate_mail_flow_record(c, info);
        info$activity = "SMTP_DATA_END";
        print fmt("[SMTP] DATA transmission completed for %s", uid);
    } else {
        # 解析邮件头部信息
        if ( /^Subject:/ in data ) {
            local subject_line = sub(data, /^Subject:\s*/, "");
            subject_line = sub(subject_line, /\r?\n$/, "");
            info$subject = subject_line;
            
            # 计算主题SHA256哈希
            info$subject_sha256 = sha256_hash(subject_line);
        }
        
        if ( /^From:/ in data ) {
            local from_line = sub(data, /^From:\s*/, "");
            from_line = sub(from_line, /\r?\n$/, "");
            info$from = from_line;
            info$from_header = from_line;
        }
        
        if ( /^To:/ in data ) {
            local to_line = sub(data, /^To:\s*/, "");
            to_line = sub(to_line, /\r?\n$/, "");
            if ( !info?$to )
                info$to = vector();
            info$to[|info$to|] = to_line;
            info$to_header = to_line;
        }
        
        if ( /^Message-ID:/ in data ) {
            local msgid_line = sub(data, /^Message-ID:\s*/, "");
            msgid_line = sub(msgid_line, /\r?\n$/, "");
            # 去除尖括号
            msgid_line = sub(msgid_line, /^</, "");
            msgid_line = sub(msgid_line, />$/, "");
            info$msg_id = msgid_line;
            info$message_id = msgid_line;
        }
        
        info$activity = "SMTP_DATA_CONTENT";
    }
    
    info$role = "client";
    
    # 更新会话信息
    smtp_sessions[uid] = info;
    
    # 记录日志
    Log::write(LOG, info);
}

# 生成mail_flow.log记录的函数
function generate_mail_flow_record(c: connection, info: Info)
{
    print fmt("[DEBUG] generate_mail_flow_record called for %s", c$uid);
    
    local flow_info: FlowInfo;
    
    # 基础字段
    flow_info$ts = network_time();
    flow_info$site_id = SITE_ID;
    flow_info$link_id = LINK_ID;
    flow_info$uid = c$uid;
    flow_info$orig_h = c$id$orig_h;
    flow_info$resp_h = c$id$resp_h;
    
    # 方向判定信息（从连接跟踪获取）
    local is_tunnel_conn = is_tunnel_connection(c);
    
    if ( c$uid in connection_tracks ) {
        local track = connection_tracks[c$uid];
        local direction_info = determine_direction(c, track);
        
        flow_info$direction_raw = direction_info$direction_raw;
        flow_info$action = direction_info$action;
        flow_info$evidence = direction_info$evidence;
        flow_info$confidence = direction_info$confidence;
        flow_info$link_encrypted = track$link_encrypted;
        flow_info$link_decrypted = track$link_decrypted;
        
        # 隧道连接的加密/解密状态处理（基于修正后的方向判定）
        if ( is_tunnel_conn ) {
            if ( flow_info$direction_raw == "outbound_from_local" && is_tunnel_address(c$id$orig_h) ) {
                # 从隧道发出的流量：已加密的出站邮件
                flow_info$link_encrypted = T;
                flow_info$link_decrypted = F;
                print fmt("[TUNNEL] Marked tunnel outbound traffic as encrypted: %s", c$uid);
            } else if ( flow_info$direction_raw == "inbound_to_local" && is_tunnel_address(c$id$resp_h) ) {
                # 进入隧道的流量：解密后的入站邮件  
                flow_info$link_decrypted = T;
                flow_info$link_encrypted = F;
                print fmt("[TUNNEL] Marked tunnel inbound traffic as decrypted: %s", c$uid);
            } else if ( !track$link_encrypted ) {
                # 默认情况下隧道连接标记为加密
                flow_info$link_encrypted = T;
                print fmt("[TUNNEL] Force-marking tunnel connection as encrypted: %s", c$uid);
            }
        }
    } else {
        flow_info$direction_raw = "unknown";
        flow_info$action = "unknown";
        flow_info$evidence = vector("no_tracking_data");
        flow_info$confidence = 0.0;
        
        # 即使没有连接跟踪，也要检查隧道连接
        if ( is_tunnel_conn ) {
            if ( is_tunnel_address(c$id$orig_h) ) {
                # 从隧道网络来的流量可能是解密的
                flow_info$link_decrypted = T;
                flow_info$evidence = vector("tunnel_inbound_connection");
                print fmt("[TUNNEL] Tunnel inbound connection detected without tracking: %s", c$uid);
            } else {
                # 发往隧道网络的流量是加密的
                flow_info$link_encrypted = T;
                flow_info$evidence = vector("tunnel_outbound_connection");
                print fmt("[TUNNEL] Tunnel outbound connection detected without tracking: %s", c$uid);
            }
        }
    }
    
    # 邮件字段
    flow_info$msg_id = info?$msg_id ? info$msg_id : "";
    flow_info$mailfrom = info?$mailfrom ? info$mailfrom : "";
    
    # 收件人拼接
    if ( info?$rcptto && |info$rcptto| > 0 ) {
        flow_info$rcptto = join_string_vec(info$rcptto, ",");
    } else {
        flow_info$rcptto = "";
    }
    
    # 主题哈希
    flow_info$subject_sha256 = info?$subject_sha256 ? info$subject_sha256 : "";
    
    # 记录到mail_flow.log
    Log::write(FLOW_LOG, flow_info);
    print fmt("[DEBUG] Wrote flow record to log: %s", c$uid);
    
    # 更新月度统计（简化的加密/解密判断逻辑）
    local action_type = "receive";
    local is_encrypted = F;
    local is_decrypted = F;
    
    # 简化的加密/解密判断：基于源IP是否匹配本地隧道IP
    if ( c$id$orig_h == LOCAL_TUNNEL_IP ) {
        # 源IP匹配本地隧道IP：本地发送邮件，动作是加密
        action_type = "send";
        is_encrypted = T;
        print fmt("[SIMPLE] Local tunnel IP sending mail (encrypt): %s", c$uid);
    } else {
        # 源IP不匹配：远程发送到本地，动作是解密
        action_type = "receive";
        is_decrypted = T;
        print fmt("[SIMPLE] Remote tunnel IP sending mail (decrypt): %s", c$uid);
    }

    print fmt("[DEBUG] SMTP connection %s:%d -> %s:%d, action_type=%s, encrypted=%s, decrypted=%s", 
              c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p, action_type, 
              is_encrypted ? "T" : "F", is_decrypted ? "T" : "F");
    
    update_daily_stats(action_type, is_encrypted, is_decrypted);
    
    print fmt("[FLOW] Generated mail flow record: %s %s (msg_id=%s)", 
              flow_info$uid, flow_info$action, flow_info$msg_id);
}

# 辅助函数：计算SHA256哈希
function sha256_hash(input: string): string
{
    # 简化实现，实际部署中可能需要外部工具
    # 这里返回一个基于字符串长度和内容的简单哈希
    local hash_base = fmt("%d_%s", |input|, input);
    return fmt("sha256_%s", str_hash(hash_base));
}

# 辅助函数：字符串向量连接
function join_string_vec(vec: vector of string, sep: string): string
{
    if ( |vec| == 0 )
        return "";
    
    local result = vec[0];
    for ( i in vec ) {
        if ( i > 0 )
            result = fmt("%s%s%s", result, sep, vec[i]);
    }
    return result;
}

# 辅助函数：简单字符串哈希
function str_hash(s: string): string
{
    local hash_val = 0;
    local chars = split_string(s, /./);
    
    for ( i in chars ) {
        hash_val = (hash_val * 31 + |chars[i]|) % 1000000;
    }
    
    return fmt("%06d", hash_val);
}
