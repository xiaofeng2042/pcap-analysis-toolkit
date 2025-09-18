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
}

const SMTP_PORTS: set[port] = {
    25/tcp, 465/tcp, 587/tcp, 2525/tcp, 1025/tcp,
    3025/tcp, 3465/tcp
} &redef;

const POP3_PORTS: set[port] = {
    110/tcp, 995/tcp, 3110/tcp, 3995/tcp
} &redef;

# 全局统计变量
global smtp_connections = 0;
global starttls_attempts = 0;
global starttls_success = 0;
global encrypted_connections = 0;

# 报告间隔
const report_interval = 30sec &redef;

# 前向声明事件
global mail_stats_report: event();

# 全局变量存储SMTP会话信息
global smtp_sessions: table[string] of Info;

event zeek_init()
{
    Log::create_stream(LOG, [$columns=Info, $path="mail_activity"]);
    print "[MAIL] Enhanced Mail Activity Monitor Started";
    schedule report_interval { mail_stats_report() };
}

function new_smtp_info(c: connection): Info
{
    return [$ts = network_time(),
            $uid = c$uid,
            $id = c$id,
            $trans_depth = 1,
            $tls = F,
            $fuids = vector(),
            $is_webmail = F];
}

function new_info(c: connection, proto: string, role: string, ev: string): Info
{
    return [$ts = network_time(),
            $uid = c$uid,
            $id = c$id,
            $protocol = proto,
            $role = role,
            $activity = ev];
}

event smtp_request(c: connection, is_orig: bool, command: string, arg: string)
{
    if ( ! is_orig )
        return;

    if ( c$id$resp_p !in SMTP_PORTS )
        return;

    # 获取或创建SMTP会话信息
    local session_key = c$uid;
    if ( session_key !in smtp_sessions ) {
        smtp_sessions[session_key] = new_smtp_info(c);
        smtp_sessions[session_key]$trans_depth = 1;
    }
    
    local info = smtp_sessions[session_key];
    
    if ( command == "MAIL" ) {
        info$mailfrom = arg;
        print fmt("[SMTP] MAIL FROM: %s", arg);
    }
    else if ( command == "RCPT" ) {
        if ( ! info?$rcptto )
            info$rcptto = vector();
        info$rcptto[|info$rcptto|] = arg;
        print fmt("[SMTP] RCPT TO: %s", arg);
    }
    else if ( command == "HELO" || command == "EHLO" ) {
        info$helo = arg;
        ++smtp_connections;
        print fmt("[SMTP] New SMTP Connection: %s:%d -> %s:%d (HELO: %s)", 
                 c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p, arg);
    }
    else if ( command == "STARTTLS" ) {
        ++starttls_attempts;
        info$tls = F;  # 初始设置为false，等SSL建立后更新
        print fmt("[TLS] STARTTLS Attempt: %s:%d", c$id$orig_h, c$id$orig_p);
    }
    else if ( command == "DATA" ) {
        print fmt("[SMTP] DATA command received");
    }
}

event smtp_reply(c: connection, is_orig: bool, code: count, cmd: string, msg: string, cont_resp: bool)
{
    if ( is_orig )
        return;

    if ( c$id$resp_p !in SMTP_PORTS )
        return;

    # 获取SMTP会话信息
    local session_key = c$uid;
    if ( session_key in smtp_sessions ) {
        local info = smtp_sessions[session_key];
        info$last_reply = fmt("%d %s", code, msg);
        
        # 处理成功的回复
        if ( code >= 200 && code < 300 ) {
            if ( cmd == "HELO" || cmd == "EHLO" ) {
                print fmt("[OK] SMTP %s Success: %d %s", cmd, code, msg);
            }
            else if ( cmd == "MAIL" ) {
                print fmt("[OK] SMTP MAIL Success: %d %s", code, msg);
            }
            else if ( cmd == "RCPT" ) {
                print fmt("[OK] SMTP RCPT Success: %d %s", code, msg);
            }
            else if ( cmd == "DATA" ) {
                print fmt("[OK] SMTP DATA Success: %d %s", code, msg);
                
                # DATA命令成功后，记录完整的SMTP事务日志
                if ( ! info?$path )
                    info$path = vector();
                info$path[|info$path|] = c$id$resp_h;
                info$path[|info$path|] = c$id$orig_h;
                
                # 设置默认TLS状态（如果未设置）
                if ( ! info?$tls )
                    info$tls = F;
                
                # 记录标准SMTP日志
                Log::write(LOG, info);
                print fmt("[MAIL] SMTP Transaction Logged: %s", info$uid);
            }
        }
        else {
            print fmt("[ERROR] SMTP %s Error: %d %s", cmd, code, msg);
        }
    }
}

# 新增：SMTP数据事件处理，解析邮件头信息
event smtp_data(c: connection, is_orig: bool, data: string)
{
    if ( ! is_orig )
        return;

    if ( c$id$resp_p !in SMTP_PORTS )
        return;

    # 只处理邮件头部信息，避免重复输出
    local lines = split_string(data, /\r?\n/);
    local line: string;
    local line2: string;
    local lines2: vector of string;
    local i: count;
    local attachment_count2 = 0;
    
    # 检查是否已经处理过这个会话的邮件头
    local session_key = c$uid;
    if ( session_key in smtp_sessions && smtp_sessions[session_key]?$subject ) {
        return;  # 已经处理过邮件头，避免重复
    }

    # 兼容性日志记录
    local compat_info = new_info(c, "SMTP", "send", "SMTP_DATA");
    
    lines2 = split_string(data, /\r?\n/);
    for ( i in lines2 ) {
        line2 = lines2[i];
        if ( /^Subject:/ in line2 ) {
            compat_info$subject = sub(line2, /^Subject:\s*/, "");
            # 只在第一次发现Subject时打印
            if ( session_key in smtp_sessions ) {
                smtp_sessions[session_key]$subject = compat_info$subject;
                print fmt("[MAIL] Email Subject: %s", compat_info$subject);
            }
        } else if ( /^From:/ in line2 ) {
            compat_info$from_header = sub(line2, /^From:\s*/, "");
        } else if ( /^To:/ in line2 ) {
            compat_info$to_header = sub(line2, /^To:\s*/, "");
        } else if ( /^Message-ID:/ in line2 ) {
            compat_info$message_id = sub(line2, /^Message-ID:\s*/, "");
        } else if ( /^Content-Disposition:.*attachment/ in line2 ) {
            ++attachment_count2;
        }
    }

    if ( attachment_count2 > 0 ) {
        compat_info$attachment_count = attachment_count2;
    }

    Log::write(LOG, compat_info);
}

# SSL/TLS 事件处理
event ssl_established(c: connection)
{
    if ( c$id$resp_p in SMTP_PORTS )
    {
        ++encrypted_connections;
        ++starttls_success;
        local tls_ver = c$ssl?$version ? c$ssl$version : "unknown";
        print fmt("[TLS] SMTP TLS Established: %s:%d (Version: %s)", 
                 c$id$orig_h, c$id$orig_p, tls_ver);
        
        # 更新SMTP会话的TLS状态
        local session_key = c$uid;
        if ( session_key in smtp_sessions ) {
            smtp_sessions[session_key]$tls = T;
        }
    }
}

event pop3_request(c: connection, is_orig: bool, command: string, arg: string)
{
    if ( ! is_orig )
        return;

    if ( c$id$resp_p !in POP3_PORTS )
        return;

    local info = new_info(c, "POP3", "receive", fmt("POP3_%s", command));

    if ( command == "USER" ) {
        info$user = arg;
        print fmt("👤 POP3 Login Attempt: %s", arg);
    } else if ( command == "PASS" ) {
        info$detail = "<hidden>";
    } else if ( command == "RETR" ) {
        info$detail = fmt("retrieve message %s", arg);
        print fmt("📥 Retrieving message: %s", arg);
    } else if ( command == "LIST" || command == "STAT" ) {
        info$detail = arg;
    } else if ( arg != "" ) {
        info$detail = arg;
    }

    Log::write(LOG, info);
}

event pop3_reply(c: connection, is_orig: bool, cmd: string, msg: string)
{
    if ( is_orig )
        return;

    if ( c$id$resp_p !in POP3_PORTS )
        return;

    local label = cmd != "" ? cmd : "POP3_REPLY";
    local info = new_info(c, "POP3", "receive", fmt("POP3_REPLY_%s", cmd == "" ? "GENERIC" : cmd));
    info$status = label;
    if ( msg != "" )
        info$detail = msg;

    # 特殊处理登录成功
    if ( cmd == "PASS" && /^\+OK/ in msg ) {
        print fmt("[OK] POP3 Login Success: %s", msg);
    }

    Log::write(LOG, info);
}

# 新增：SSL建立事件
event ssl_established(c: connection)
{
    if ( c$id$resp_p in SMTP_PORTS )
    {
        ++encrypted_connections;
        ++starttls_success;
        local tls_ver = c$ssl?$version ? c$ssl$version : "unknown";
        print fmt("🔒 SMTP TLS Established: %s:%d (Version: %s)", 
                 c$id$orig_h, c$id$orig_p, tls_ver);
        
        # 记录TLS建立事件
        local info = new_info(c, "SMTP", "send", "SMTP_TLS_ESTABLISHED");
        info$status = "success";
        info$tls_version = tls_ver;
        info$detail = fmt("TLS version: %s", tls_ver);
        Log::write(LOG, info);
    }
}

# Provide a single summary entry when the connection finishes.
event connection_state_remove(c: connection)
{
    local resp_p = c$id$resp_p;

    if ( resp_p in SMTP_PORTS )
    {
        local info = new_info(c, "SMTP", "send", "SMTP_CONNECTION_END");
        info$status = "closed";
        info$detail = fmt("duration %.2fs, size %d/%d", c$duration, c$orig$size, c$resp$size);
        Log::write(LOG, info);
        
        print fmt("[STATS] SMTP Connection Closed: %s:%d (Duration: %.2fs, Data: %d/%d bytes)", 
                 c$id$orig_h, c$id$orig_p, c$duration, c$orig$size, c$resp$size);
    }
    else if ( resp_p in POP3_PORTS )
    {
        local info2 = new_info(c, "POP3", "receive", "POP3_CONNECTION_END");
        info2$status = "closed";
        info2$detail = fmt("duration %.2fs, size %d/%d", c$duration, c$orig$size, c$resp$size);
        Log::write(LOG, info2);
        
        print fmt("[STATS] POP3 Connection Closed: %s:%d (Duration: %.2fs, Data: %d/%d bytes)", 
                 c$id$orig_h, c$id$orig_p, c$duration, c$orig$size, c$resp$size);
    }
}

# 新增：定时统计报告事件
event mail_stats_report()
{
    print "+==============================================================+";
    print fmt("|| [STATS] Mail Traffic Statistics [%s] ||", strftime("%Y-%m-%d %H:%M:%S", current_time()));
    print "+==============================================================+";
    print fmt("||   SMTP Connections: %-10d                              ||", smtp_connections);
    print fmt("||   STARTTLS Attempts: %-10d                             ||", starttls_attempts);
    print fmt("||   STARTTLS Success: %-10d                              ||", starttls_success);
    print fmt("||   Encrypted Connections: %-10d                         ||", encrypted_connections);
    
    local encryption_rate = starttls_attempts > 0 ? 
        (starttls_success * 100.0 / starttls_attempts) : 0.0;
    print fmt("||   Encryption Success Rate: %.1f%%                           ||", encryption_rate);
    print "+==============================================================+";
    
    # 安排下次报告
    schedule report_interval { mail_stats_report() };
}
