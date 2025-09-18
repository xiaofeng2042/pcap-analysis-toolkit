# mail-activity-json.zeek
# Enhanced Zeek script to record detailed SMTP send activity and POP3 retrieval events.

@load base/protocols/smtp
@load base/protocols/pop3
@load base/protocols/conn
@load base/protocols/ssl
redef LogAscii::use_json = T;

module MailActivity;

export {
    type Info: record {
        # 基础连接信息
        ts: time &log;
        uid: string &log;
        id: conn_id &log;
        
        # SMTP 标准字段
        trans_depth: count &log &optional;
        helo: string &log &optional;
        mailfrom: string &log &optional;
        rcptto: vector of string &log &optional;
        date: string &log &optional;
        from: string &log &optional;
        to: vector of string &log &optional;
        cc: vector of string &log &optional;
        reply_to: string &log &optional;
        msg_id: string &log &optional;
        in_reply_to: string &log &optional;
        subject: string &log &optional;
        x_originating_ip: string &log &optional;
        first_received: string &log &optional;
        second_received: string &log &optional;
        last_reply: string &log &optional;
        path: vector of addr &log &optional;
        user_agent: string &log &optional;
        tls: bool &log &optional;
        fuids: vector of string &log &optional;
        is_webmail: bool &log &optional;
        
        # 兼容性字段（保留原有功能）
        protocol: string &log &optional;
        role: string &log &optional;
        activity: string &log &optional;
        mail_from: string &log &optional;
        rcpt_to: string &log &optional;
        user: string &log &optional;
        status: string &log &optional;
        detail: string &log &optional;
        from_header: string &log &optional;
        to_header: string &log &optional;
        message_id: string &log &optional;
        tls_version: string &log &optional;
        attachment_count: count &log &optional;
    };

    redef enum Log::ID += { LOG };

    option enable_pop3_log: bool = T &redef;
    option pop3_log_path: string = "pop3" &redef;

    type PopInfo: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;
        activity: string &log;
        user: string &log &optional;
        argument: string &log &optional;
        status: string &log &optional;
        detail: string &log &optional;
    };

    redef enum Log::ID += { POP_LOG };
    
    # 全局常量定义
    const SMTP_PORTS: set[port] = {
        25/tcp, 465/tcp, 587/tcp, 2525/tcp, 1025/tcp,
        3025/tcp, 3465/tcp
    } &redef;

    const POP3_PORTS: set[port] = {
        110/tcp, 995/tcp, 3110/tcp, 3995/tcp
    } &redef;

    # 报告间隔
    const report_interval: interval = 30sec &redef;
    
    # 前向声明事件
    global mail_stats_report: event();
    
    # 全局统计变量
    global smtp_connections: count;
    global starttls_attempts: count;
    global starttls_success: count;
    global encrypted_connections: count;
    
    # 全局变量存储SMTP会话信息
    global smtp_sessions: table[string] of Info;
}

event zeek_init()
{
    # 初始化全局统计变量
    smtp_connections = 0;
    starttls_attempts = 0;
    starttls_success = 0;
    encrypted_connections = 0;
    Log::create_stream(MailActivity::LOG, [$columns=MailActivity::Info, $path="mail_activity"]);
    if ( MailActivity::enable_pop3_log )
        Log::create_stream(MailActivity::POP_LOG, [$columns=MailActivity::PopInfo, $path=MailActivity::pop3_log_path]);
    print "[MAIL] Enhanced Mail Activity Monitor Started";
    schedule MailActivity::report_interval { MailActivity::mail_stats_report() };
}

function new_smtp_info(c: connection): MailActivity::Info
{
    return [$ts = network_time(),
            $uid = c$uid,
            $id = c$id];
}

event MailActivity::mail_stats_report()
{
    print "+==============================================================+";
    print fmt("|| [STATS] Mail Traffic Statistics [%s] ||", strftime("%Y-%m-%d %H:%M:%S", current_time()));
    print "+==============================================================+";
    print fmt("|| SMTP Connections: %d", smtp_connections);
    print fmt("|| STARTTLS Attempts: %d", starttls_attempts);
    print fmt("|| STARTTLS Success: %d", starttls_success);
    print fmt("|| Encrypted Connections: %d", encrypted_connections);
    if ( starttls_attempts > 0 )
        print fmt("|| Encryption Success Rate: %.1f%%", (starttls_success * 100.0) / starttls_attempts);
    print "+==============================================================+";
    
    # 重新调度下一次报告
    schedule MailActivity::report_interval { MailActivity::mail_stats_report() };
}

event smtp_request(c: connection, is_orig: bool, command: string, arg: string)
{
    if ( ! is_orig )
        return;
        
    local uid = c$uid;
    
    if ( uid !in MailActivity::smtp_sessions )
        MailActivity::smtp_sessions[uid] = new_smtp_info(c);
    
    local info = MailActivity::smtp_sessions[uid];
    
    if ( command == "HELO" || command == "EHLO" ) {
        info$helo = arg;
        info$protocol = "SMTP";
        info$role = "sender";
        info$activity = fmt("SMTP_%s", command);
        ++smtp_connections;
        print fmt("[SMTP] New SMTP Connection: %s:%d -> %s:%d (HELO: %s)", 
                  c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p, arg);
    }
    else if ( command == "MAIL" ) {
        info$mailfrom = arg;
        info$mail_from = arg;
        info$activity = "SMTP_MAIL";
        print fmt("[SMTP] Mail From: %s", arg);
    }
    else if ( command == "RCPT" ) {
        if ( ! info?$rcptto )
            info$rcptto = vector();
        info$rcptto[|info$rcptto|] = arg;
        info$rcpt_to = arg;
        info$activity = "SMTP_RCPT";
        print fmt("[SMTP] Rcpt To: %s", arg);
    }
    else if ( command == "DATA" ) {
        info$activity = "SMTP_DATA";
        print fmt("[SMTP] Data Transfer Started");
    }
    else if ( command == "STARTTLS" ) {
        info$activity = "SMTP_STARTTLS";
        ++starttls_attempts;
        print fmt("[TLS] STARTTLS Attempt");
    }
    
    Log::write(MailActivity::LOG, info);
}

event smtp_reply(c: connection, is_orig: bool, code: count, cmd: string, msg: string, cont_resp: bool)
{
    if ( is_orig )
        return;
        
    local uid = c$uid;
    
    if ( uid !in MailActivity::smtp_sessions )
        return;
    
    local info = MailActivity::smtp_sessions[uid];
    info$last_reply = fmt("%d %s", code, msg);
    
    if ( cmd == "STARTTLS" && code == 220 ) {
        ++starttls_success;
        print fmt("[OK] STARTTLS Success: %d %s", code, msg);
    }
    else if ( code >= 400 ) {
        print fmt("[ERROR] SMTP %s Error: %d %s", cmd, code, msg);
    }
    else {
        print fmt("[OK] SMTP %s Success: %d %s", cmd, code, msg);
    }
    
    Log::write(MailActivity::LOG, info);
}

event smtp_data(c: connection, is_orig: bool, data: string)
{
    if ( ! is_orig )
        return;
        
    local uid = c$uid;
    
    if ( uid !in MailActivity::smtp_sessions )
        return;
    
    local info = MailActivity::smtp_sessions[uid];
    
    # 解析邮件头部信息
    if ( /^Subject:/ in data ) {
        local subject_line = sub(data, /^Subject:\s*/, "");
        info$subject = subject_line;
    }
    
    if ( /^From:/ in data ) {
        local from_line = sub(data, /^From:\s*/, "");
        info$from_header = from_line;
        info$from = from_line;
    }
    
    if ( /^To:/ in data ) {
        local to_line = sub(data, /^To:\s*/, "");
        info$to_header = to_line;
        if ( ! info?$to )
            info$to = vector();
        info$to[|info$to|] = to_line;
    }
    
    if ( /^Message-ID:/ in data ) {
        local msgid_line = sub(data, /^Message-ID:\s*/, "");
        info$message_id = msgid_line;
        info$msg_id = msgid_line;
    }
    
    if ( /^Date:/ in data ) {
        local date_line = sub(data, /^Date:\s*/, "");
        info$date = date_line;
    }
    
    Log::write(MailActivity::LOG, info);
}

event ssl_established(c: connection)
{
    if ( c$id$resp_p in MailActivity::SMTP_PORTS || c$id$resp_p in MailActivity::POP3_PORTS ) {
        ++encrypted_connections;
        
        local uid = c$uid;
        if ( uid in MailActivity::smtp_sessions ) {
            local info = MailActivity::smtp_sessions[uid];
            info$tls = T;
            if ( c$ssl?$version )
                info$tls_version = c$ssl$version;
            Log::write(MailActivity::LOG, info);
        }
        
        print fmt("[TLS] SSL/TLS Connection Established: %s:%d -> %s:%d", 
                  c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p);
    }
}

event connection_state_remove(c: connection)
{
    local uid = c$uid;
    
    if ( uid in MailActivity::smtp_sessions ) {
        local info = MailActivity::smtp_sessions[uid];
        info$activity = "SMTP_CONNECTION_END";
        Log::write(MailActivity::LOG, info);
        delete MailActivity::smtp_sessions[uid];
        print fmt("[SMTP] Connection Ended: %s", uid);
    }
}

# POP3 事件处理
event pop3_request(c: connection, is_orig: bool, command: string, arg: string)
{
    if ( ! is_orig || ! MailActivity::enable_pop3_log )
        return;
    
    local info: MailActivity::PopInfo = [
        $ts = network_time(),
        $uid = c$uid,
        $id = c$id,
        $activity = fmt("POP3_%s", command)
    ];
    
    if ( command == "USER" ) {
        info$user = arg;
        print fmt("[POP3] User Login Attempt: %s", arg);
    }
    else if ( command == "PASS" ) {
        info$activity = "POP3_PASS";
        print fmt("[POP3] Password Authentication");
    }
    else if ( command == "RETR" ) {
        info$argument = arg;
        print fmt("[POP3] Retrieve Message: %s", arg);
    }
    
    Log::write(MailActivity::POP_LOG, info);
}

event pop3_reply(c: connection, is_orig: bool, cmd: string, msg: string)
{
    if ( is_orig || ! MailActivity::enable_pop3_log )
        return;
    
    local info: MailActivity::PopInfo = [
        $ts = network_time(),
        $uid = c$uid,
        $id = c$id,
        $activity = fmt("POP3_%s_REPLY", cmd),
        $status = msg
    ];
    
    if ( /^\+OK/ in msg ) {
        print fmt("[OK] POP3 %s Success: %s", cmd, msg);
    }
    else if ( /^-ERR/ in msg ) {
        print fmt("[ERROR] POP3 %s Error: %s", cmd, msg);
    }
    
    Log::write(MailActivity::POP_LOG, info);
}
