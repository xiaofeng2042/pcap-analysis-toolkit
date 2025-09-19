# pop3.zeek - POP3协议事件处理模块
# 处理POP3协议的各种事件和业务逻辑记录

module MailActivity;

# POP3会话状态增强
type Pop3SessionData: record {
    user: string &optional;                    # 用户名
    authenticated: bool &default=F;            # 是否已认证
    message_count: count &default=0;           # 邮件总数
    total_size: count &default=0;              # 邮箱总大小
    messages_retrieved: set[count] &default=set(); # 已检索的邮件编号
    messages_deleted: set[count] &default=set();   # 已删除的邮件编号
    current_retr_msg: count &optional;         # 当前正在检索的邮件编号
    retr_bytes_received: count &default=0;     # 当前RETR接收的字节数
    headers_complete: bool &default=F;         # 邮件头部是否解析完成
};

# POP3会话数据表
global pop3_session_data: table[string] of Pop3SessionData;

# POP3请求事件处理
event pop3_request(c: connection, is_orig: bool, command: string, arg: string)
{
    if (!is_orig)
        return;
        
    local uid = c$uid;
    
    # 初始化会话数据
    if (uid !in pop3_session_data) {
        pop3_session_data[uid] = [$authenticated=F];
    }
    
    local session_data = pop3_session_data[uid];
    
    # 创建命令记录
    local info = create_base_info(c);
    info$protocol = "POP3";
    info$role = "client";
    info$activity = fmt("POP3_%s", command);
    info$pop3_command = command;
    info$pop3_arguments = arg;
    info$mailbox_host = fmt("%s", c$id$resp_h);
    
    # 添加双端监控字段
    info$site_id = SITE_ID;
    info$link_id = LINK_ID;
    
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
    
    # 处理不同的POP3命令
    if (command == "USER") {
        session_data$user = arg;
        info$user = arg;
        info$mailbox_user = arg;
        info$detail = fmt("User authentication: %s", arg);
        print fmt("[POP3] User login attempt: %s", arg);
        
    } else if (command == "PASS") {
        info$detail = "Password authentication [REDACTED]";
        # 不记录密码，但记录认证尝试
        if (session_data?$user) {
            info$mailbox_user = session_data$user;
        }
        print fmt("[POP3] Password authentication for user: %s", 
                  session_data?$user ? session_data$user : "unknown");
        
    } else if (command == "STAT") {
        info$activity = "POP3_STAT";
        info$detail = "Get mailbox statistics";
        print fmt("[POP3] STAT command - requesting mailbox statistics");
        
    } else if (command == "LIST") {
        info$activity = "POP3_LIST";
        if (arg == "") {
            info$detail = "List all messages";
            print fmt("[POP3] LIST command - requesting all message list");
        } else {
            info$detail = fmt("List message %s", arg);
            print fmt("[POP3] LIST command - requesting message %s info", arg);
        }
        
    } else if (command == "RETR") {
        info$activity = "POP3_RETR";
        info$action = "RETRIEVE";
        if (arg != "") {
            local retr_msg_num = to_count(arg);
            session_data$current_retr_msg = retr_msg_num;
            session_data$retr_bytes_received = 0;
            session_data$headers_complete = F;
            add session_data$messages_retrieved[retr_msg_num];
            info$detail = fmt("Retrieve message %s", arg);
            print fmt("[POP3] RETR command - retrieving message %s", arg);
        }
        
    } else if (command == "DELE") {
        info$activity = "POP3_DELE";
        if (arg != "") {
            local dele_msg_num = to_count(arg);
            add session_data$messages_deleted[dele_msg_num];
            info$detail = fmt("Mark message %s for deletion", arg);
            print fmt("[POP3] DELE command - marking message %s for deletion", arg);
        }
        
    } else if (command == "TOP") {
        info$activity = "POP3_TOP";
        info$detail = fmt("Get message headers and lines: %s", arg);
        print fmt("[POP3] TOP command - getting headers for %s", arg);
        
    } else if (command == "UIDL") {
        info$activity = "POP3_UIDL";
        if (arg == "") {
            info$detail = "List unique IDs for all messages";
            print fmt("[POP3] UIDL command - requesting all unique IDs");
        } else {
            info$detail = fmt("Get unique ID for message %s", arg);
            print fmt("[POP3] UIDL command - requesting unique ID for message %s", arg);
        }
        
    } else if (command == "RSET") {
        info$activity = "POP3_RSET";
        info$detail = "Reset session (unmark deleted messages)";
        # 清除删除标记
        session_data$messages_deleted = set();
        print fmt("[POP3] RSET command - resetting session");
        
    } else if (command == "QUIT") {
        info$activity = "POP3_QUIT";
        info$detail = "End POP3 session";
        print fmt("[POP3] QUIT command - ending session");
        
    } else if (command == "NOOP") {
        info$activity = "POP3_NOOP";
        info$detail = "No operation";
        print fmt("[POP3] NOOP command");
        
    } else {
        info$activity = "POP3_OTHER";
        info$detail = fmt("Other command: %s %s", command, arg);
        print fmt("[POP3] Unknown command: %s %s", command, arg);
    }
    
    # 添加会话统计信息
    if (session_data?$user) {
        info$mailbox_user = session_data$user;
    }
    
    # 存储会话信息并记录日志
    pop3_sessions[uid] = info;
    pop3_session_data[uid] = session_data;
    Log::write(LOG, info);
    
    # 如果启用了POP3专用日志，也记录到专用日志
    if (enable_pop3_log) {
        local pop_info: PopInfo = [
            $ts = network_time(),
            $uid = uid,
            $id = c$id,
            $activity = fmt("POP3_%s", command)
        ];
        
        if (command == "USER") {
            pop_info$user = arg;
        } else if (command == "PASS") {
            pop_info$argument = "[REDACTED]";
        } else {
            pop_info$argument = arg;
        }
        
        Log::write(POP_LOG, pop_info);
    }
}

# POP3回复事件处理
event pop3_reply(c: connection, is_orig: bool, cmd: string, msg: string)
{
    if (is_orig)
        return;
        
    local uid = c$uid;
    
    # 创建回复记录
    local reply_info = create_base_info(c);
    reply_info$protocol = "POP3";
    reply_info$role = "server";
    reply_info$activity = fmt("POP3_%s_REPLY", cmd);
    reply_info$pop3_response = msg;
    reply_info$detail = msg;
    
    # 解析响应状态
    local is_success = F;
    if (/^\+OK/ in msg) {
        reply_info$pop3_status = "+OK";
        reply_info$status = "SUCCESS";
        is_success = T;
        print fmt("[OK] POP3 %s success: %s", cmd, msg);
    } else if (/^-ERR/ in msg) {
        reply_info$pop3_status = "-ERR";
        reply_info$status = "ERROR";
        print fmt("[ERROR] POP3 %s error: %s", cmd, msg);
    } else {
        reply_info$pop3_status = "UNKNOWN";
        reply_info$status = "UNKNOWN";
        print fmt("[POP3] %s response: %s", cmd, msg);
    }
    
    # 更新会话状态
    if (uid in pop3_session_data) {
        local session_data = pop3_session_data[uid];
        
        if (cmd == "USER" && is_success) {
            # USER命令成功，用户名有效
            reply_info$mailbox_user = session_data$user;
            
        } else if (cmd == "PASS" && is_success) {
            # 认证成功
            session_data$authenticated = T;
            reply_info$mailbox_user = session_data$user;
            reply_info$detail = fmt("Authentication successful for user: %s", session_data$user);
            
        } else if (cmd == "STAT" && is_success) {
            # 解析STAT响应：+OK nn nnnn（邮件数量和总大小）
            local stat_parts = split_string(msg, / /);
            if (|stat_parts| >= 3) {
                session_data$message_count = to_count(stat_parts[1]);
                session_data$total_size = to_count(stat_parts[2]);
                reply_info$detail = fmt("Mailbox: %d messages, %d bytes total", 
                                       session_data$message_count, session_data$total_size);
                print fmt("[POP3] Mailbox statistics: %d messages, %d bytes", 
                          session_data$message_count, session_data$total_size);
            }
        }
        
        pop3_session_data[uid] = session_data;
    }
    
    # 记录日志
    Log::write(LOG, reply_info);
    
    # 如果启用了POP3专用日志
    if (enable_pop3_log) {
        local pop_reply: PopInfo = [
            $ts = network_time(),
            $uid = uid,
            $id = c$id,
            $activity = fmt("POP3_%s_REPLY", cmd),
            $status = reply_info$pop3_status
        ];
        
        Log::write(POP_LOG, pop_reply);
    }
}

# POP3数据事件处理 - 邮件内容解析
event pop3_data(c: connection, is_orig: bool, data: string)
{
    if (is_orig)
        return;
        
    local uid = c$uid;
    
    # 检查是否有相关的RETR会话
    if (uid !in pop3_session_data)
        return;
        
    local session_data = pop3_session_data[uid];
    
    # 只处理RETR命令的数据
    if (!session_data?$current_retr_msg)
        return;
    
    # 累计接收字节数
    session_data$retr_bytes_received += |data|;
    
    # 检查是否为消息结束标志
    if (data == ".\r\n" || data == ".\n") {
        # 邮件传输结束，创建完整的RETR记录
        local retr_info = create_base_info(c);
        retr_info$protocol = "POP3";
        retr_info$role = "server";
        retr_info$activity = "POP3_RETR_COMPLETE";
        retr_info$action = "RETRIEVE";
        retr_info$size_bytes = session_data$retr_bytes_received;
        retr_info$detail = fmt("Message %d retrieval completed: %d bytes", 
                              session_data$current_retr_msg, session_data$retr_bytes_received);
        
        if (session_data?$user) {
            retr_info$mailbox_user = session_data$user;
        }
        
        # 记录日志
        Log::write(LOG, retr_info);
        
        print fmt("[POP3] Message %d retrieval completed: %d bytes", 
                  session_data$current_retr_msg, session_data$retr_bytes_received);
        
        # 清理RETR状态
        delete session_data$current_retr_msg;
        session_data$retr_bytes_received = 0;
        session_data$headers_complete = F;
        
        pop3_session_data[uid] = session_data;
        return;
    }
    
    # 如果还在解析头部
    if (!session_data$headers_complete) {
        # 检查是否为空行（头部结束标志）
        if (data == "\r\n" || data == "\n") {
            session_data$headers_complete = T;
            pop3_session_data[uid] = session_data;
            return;
        }
        
        # 解析邮件头部字段并更新会话信息
        if (uid in pop3_sessions) {
            local info = pop3_sessions[uid];
            
            if (/^[Ss]ubject:/ in data) {
                info$subject = sub(data, /^[Ss]ubject:\s*/, "");
                info$subject = sub(info$subject, /\r?\n$/, "");
            }
            else if (/^[Ff]rom:/ in data) {
                info$from_header = sub(data, /^[Ff]rom:\s*/, "");
                info$from_header = sub(info$from_header, /\r?\n$/, "");
                info$from = info$from_header;
            }
            else if (/^[Tt]o:/ in data) {
                info$to_header = sub(data, /^[Tt]o:\s*/, "");
                info$to_header = sub(info$to_header, /\r?\n$/, "");
                if (!info?$to)
                    info$to = vector();
                info$to[|info$to|] = info$to_header;
            }
            else if (/^[Mm]essage-[Ii][Dd]:/ in data) {
                info$message_id = sub(data, /^[Mm]essage-[Ii][Dd]:\s*/, "");
                info$message_id = sub(info$message_id, /\r?\n$/, "");
                info$msg_id = info$message_id;
            }
            else if (/^[Dd]ate:/ in data) {
                local date_str = sub(data, /^[Dd]ate:\s*/, "");
                date_str = sub(date_str, /\r?\n$/, "");
                info$date = date_str;
            }
            
            pop3_sessions[uid] = info;
        }
        
        pop3_session_data[uid] = session_data;
    }
}