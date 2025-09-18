# smtp.zeek - SMTP协议事件处理模块
# 处理SMTP协议的各种事件和日志记录

module MailActivity;

# 创建新的SMTP信息记录
function new_smtp_info(c: connection): Info
{
    return [$ts = network_time(),
            $uid = c$uid,
            $id = c$id,
            $protocol = "SMTP"];
}

# SMTP请求事件处理
event smtp_request(c: connection, is_orig: bool, command: string, arg: string)
{
    local uid = c$uid;
    
    if ( uid !in smtp_sessions ) {
        smtp_sessions[uid] = new_smtp_info(c);
        ++smtp_connections;
    }
    
    local info = smtp_sessions[uid];
    
    if ( command == "HELO" || command == "EHLO" ) {
        info$activity = fmt("SMTP_%s", command);
        info$helo = arg;
        info$role = "client";
        print fmt("[SMTP] %s: %s", command, arg);
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
        print "[SMTP] STARTTLS requested";
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
    
    if ( code >= 200 && code < 300 ) {
        if ( cmd == "STARTTLS" ) {
            ++starttls_success;
            print fmt("[SMTP] STARTTLS Success: %d %s", code, msg);
        } else {
            print fmt("[SMTP] %s Success: %d %s", cmd, code, msg);
        }
    } else {
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
    
    if ( uid !in smtp_sessions )
        return;
    
    local info = smtp_sessions[uid];
    
    # 解析邮件头部信息
    if ( /^Subject:/ in data ) {
        local subject_match = match_pattern(data, /Subject: *(.*)$/);
        if ( subject_match$matched ) {
            info$subject = subject_match$str;
            info$from_header = subject_match$str;  # 兼容性字段
        }
    }
    
    if ( /^From:/ in data ) {
        local from_match = match_pattern(data, /From: *(.*)$/);
        if ( from_match$matched ) {
            info$from = from_match$str;
            info$from_header = from_match$str;
        }
    }
    
    if ( /^To:/ in data ) {
        local to_match = match_pattern(data, /To: *(.*)$/);
        if ( to_match$matched ) {
            info$to = vector(to_match$str);
            info$to_header = to_match$str;
        }
    }
    
    if ( /^Message-ID:/ in data ) {
        local msgid_match = match_pattern(data, /Message-ID: *(.*)$/);
        if ( msgid_match$matched ) {
            info$msg_id = msgid_match$str;
            info$message_id = msgid_match$str;  # 兼容性字段
        }
    }
    
    info$activity = "SMTP_DATA_CONTENT";
    info$role = "client";
    
    # 更新会话信息
    smtp_sessions[uid] = info;
    
    # 记录日志
    Log::write(LOG, info);
}