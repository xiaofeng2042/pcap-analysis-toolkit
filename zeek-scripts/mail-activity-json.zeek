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
        ts: time &log;
        uid: string &log;
        id: conn_id &log;
        protocol: string &log;
        role: string &log;
        activity: string &log;
        mail_from: string &log &optional;
        rcpt_to: string &log &optional;
        user: string &log &optional;
        status: string &log &optional;
        detail: string &log &optional;
        # 新增字段用于详细邮件信息
        subject: string &log &optional;
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

event zeek_init()
{
    Log::create_stream(LOG, [$columns=Info, $path="mail_activity"]);
    print "📧 Enhanced Mail Activity Monitor Started";
    schedule report_interval { mail_stats_report() };
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

    local info = new_info(c, "SMTP", "send", fmt("SMTP_%s", command));

    if ( command == "MAIL" )
        info$mail_from = arg;
    else if ( command == "RCPT" )
        info$rcpt_to = arg;
    else if ( command == "HELO" || command == "EHLO" ) {
        info$detail = arg;
        ++smtp_connections;
        print fmt("📧 New SMTP Connection: %s:%d -> %s:%d (HELO: %s)", 
                 c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p, arg);
    }
    else if ( command == "STARTTLS" ) {
        ++starttls_attempts;
        info$detail = "STARTTLS negotiation";
        print fmt("🔐 STARTTLS Attempt: %s:%d", c$id$orig_h, c$id$orig_p);
    }
    else
        info$detail = arg;

    Log::write(LOG, info);
}

event smtp_reply(c: connection, is_orig: bool, code: count, cmd: string, msg: string, cont_resp: bool)
{
    if ( is_orig )
        return;

    if ( c$id$resp_p !in SMTP_PORTS )
        return;

    local info = new_info(c, "SMTP", "send", fmt("SMTP_REPLY_%s", cmd));
    info$status = fmt("%d", code);
    info$detail = msg;
    
    # 特殊处理一些重要的回复
    if ( code >= 200 && code < 300 ) {
        if ( cmd == "MAIL" || cmd == "RCPT" || cmd == "DATA" ) {
            print fmt("✅ SMTP %s Success: %d %s", cmd, code, msg);
        }
    } else if ( code >= 400 ) {
        print fmt("❌ SMTP %s Error: %d %s", cmd, code, msg);
    }
    
    Log::write(LOG, info);
}

# 新增：SMTP数据事件处理，解析邮件头信息
event smtp_data(c: connection, is_orig: bool, data: string)
{
    if ( ! is_orig )
        return;

    if ( c$id$resp_p !in SMTP_PORTS )
        return;

    # 解析邮件头信息
    local lines = split_string(data, /\r?\n/);
    local info = new_info(c, "SMTP", "send", "SMTP_DATA");
    local attachment_count = 0;

    for ( i in lines ) {
        local line = lines[i];
        if ( /^Subject:/ in line ) {
            info$subject = sub(line, /^Subject:\s*/, "");
        } else if ( /^From:/ in line ) {
            info$from_header = sub(line, /^From:\s*/, "");
        } else if ( /^To:/ in line ) {
            info$to_header = sub(line, /^To:\s*/, "");
        } else if ( /^Message-ID:/ in line ) {
            info$message_id = sub(line, /^Message-ID:\s*/, "");
        } else if ( /^Content-Disposition:.*attachment/ in line ) {
            ++attachment_count;
        }
    }

    if ( attachment_count > 0 ) {
        info$attachment_count = attachment_count;
        print fmt("📎 Email with %d attachments detected", attachment_count);
    }

    if ( info?$subject ) {
        print fmt("📨 Email Subject: %s", info$subject);
    }
    if ( info?$from_header ) {
        print fmt("👤 From: %s", info$from_header);
    }

    Log::write(LOG, info);
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
        print fmt("✅ POP3 Login Success: %s", msg);
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
        
        print fmt("📊 SMTP Connection Closed: %s:%d (Duration: %.2fs, Data: %d/%d bytes)", 
                 c$id$orig_h, c$id$orig_p, c$duration, c$orig$size, c$resp$size);
    }
    else if ( resp_p in POP3_PORTS )
    {
        local info2 = new_info(c, "POP3", "receive", "POP3_CONNECTION_END");
        info2$status = "closed";
        info2$detail = fmt("duration %.2fs, size %d/%d", c$duration, c$orig$size, c$resp$size);
        Log::write(LOG, info2);
        
        print fmt("📊 POP3 Connection Closed: %s:%d (Duration: %.2fs, Data: %d/%d bytes)", 
                 c$id$orig_h, c$id$orig_p, c$duration, c$orig$size, c$resp$size);
    }
}

# 新增：定时统计报告事件
event mail_stats_report()
{
    print "╔══════════════════════════════════════════════════════════════╗";
    print fmt("║ 📊 Mail Traffic Statistics [%s] ║", strftime("%Y-%m-%d %H:%M:%S", current_time()));
    print "╠══════════════════════════════════════════════════════════════╣";
    print fmt("║   SMTP Connections: %-10d                              ║", smtp_connections);
    print fmt("║   STARTTLS Attempts: %-10d                             ║", starttls_attempts);
    print fmt("║   STARTTLS Success: %-10d                              ║", starttls_success);
    print fmt("║   Encrypted Connections: %-10d                         ║", encrypted_connections);
    
    local encryption_rate = starttls_attempts > 0 ? 
        (starttls_success * 100.0 / starttls_attempts) : 0.0;
    print fmt("║   Encryption Success Rate: %.1f%%                           ║", encryption_rate);
    print "╚══════════════════════════════════════════════════════════════╝";
    
    # 安排下次报告
    schedule report_interval { mail_stats_report() };
}
