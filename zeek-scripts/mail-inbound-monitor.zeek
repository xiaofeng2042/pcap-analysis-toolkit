# 文件：mail-inbound-monitor.zeek
# 收信监控脚本 - 专门监控 SMTP、IMAP、POP3 收信活动

@load base/protocols/smtp
@load base/protocols/imap
@load base/protocols/pop3
@load base/protocols/conn
@load ./site-mail-ports.zeek

module MailInbound;

export {
    # 日志记录结构
    type Info: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;
        protocol: string &log;
        action: string &log;
        user: string &log &optional;
        mailbox: string &log &optional;
        subject: string &log &optional;
        from_addr: string &log &optional;
        to_addr: string &log &optional;
        message_id: string &log &optional;
        status: string &log &optional;
        details: string &log &optional;
    };
    
    # 日志流
    redef enum Log::ID += { LOG };
}

# 初始化日志
event zeek_init() &priority=5
{
    Log::create_stream(MailInbound::LOG, [$columns=Info, $path="mail_inbound"]);
    print "收信监控已启动 - 监控 SMTP/IMAP/POP3 活动";
}

# SMTP 事件监控
event smtp_request(c: connection, is_orig: bool, command: string, arg: string) &priority=5
{
    if ( command == "MAIL" && /FROM:/ in arg ) {
        local info: Info;
        info$ts = network_time();
        info$uid = c$uid;
        info$id = c$id;
        info$protocol = "SMTP";
        info$action = "MAIL_FROM";
        info$from_addr = arg;
        info$status = "REQUEST";
        Log::write(MailInbound::LOG, info);
    }
    
    if ( command == "RCPT" && /TO:/ in arg ) {
        local info2: Info;
        info2$ts = network_time();
        info2$uid = c$uid;
        info2$id = c$id;
        info2$protocol = "SMTP";
        info2$action = "RCPT_TO";
        info2$to_addr = arg;
        info2$status = "REQUEST";
        Log::write(MailInbound::LOG, info2);
    }
    
    if ( command == "DATA" ) {
        local info3: Info;
        info3$ts = network_time();
        info3$uid = c$uid;
        info3$id = c$id;
        info3$protocol = "SMTP";
        info3$action = "DATA_START";
        info3$status = "REQUEST";
        Log::write(MailInbound::LOG, info3);
    }
}

event smtp_reply(c: connection, is_orig: bool, code: count, cmd: string, msg: string, cont_resp: bool) &priority=5
{
    if ( code == 250 && /OK/ in msg ) {
        local info: Info;
        info$ts = network_time();
        info$uid = c$uid;
        info$id = c$id;
        info$protocol = "SMTP";
        info$action = "ACCEPT";
        info$status = fmt("250_%s", cmd);
        info$details = msg;
        Log::write(MailInbound::LOG, info);
    }
}

# IMAP 事件监控
event imap_request(c: connection, is_orig: bool, tag: string, command: string, arg: string) &priority=5
{
    local info: Info;
    info$ts = network_time();
    info$uid = c$uid;
    info$id = c$id;
    info$protocol = "IMAP";
    info$action = command;
    info$status = "REQUEST";
    
    if ( command == "LOGIN" ) {
        info$user = arg;
        info$details = "用户登录";
    }
    else if ( command == "SELECT" || command == "EXAMINE" ) {
        info$mailbox = arg;
        info$details = fmt("选择邮箱: %s", arg);
    }
    else if ( command == "FETCH" ) {
        info$details = fmt("获取邮件: %s", arg);
    }
    
    Log::write(MailInbound::LOG, info);
}

event imap_reply(c: connection, is_orig: bool, tag: string, command: string, reply: string) &priority=5
{
    if ( /OK/ in reply ) {
        local info: Info;
        info$ts = network_time();
        info$uid = c$uid;
        info$id = c$id;
        info$protocol = "IMAP";
        info$action = command;
        info$status = "OK";
        info$details = reply;
        Log::write(MailInbound::LOG, info);
    }
}

# POP3 事件监控
event pop3_request(c: connection, is_orig: bool, command: string, arg: string) &priority=5
{
    local info: Info;
    info$ts = network_time();
    info$uid = c$uid;
    info$id = c$id;
    info$protocol = "POP3";
    info$action = command;
    info$status = "REQUEST";
    
    if ( command == "USER" ) {
        info$user = arg;
        info$details = "用户名验证";
    }
    else if ( command == "RETR" ) {
        info$details = fmt("检索邮件 #%s", arg);
    }
    else if ( command == "LIST" ) {
        info$details = "列出邮件";
    }
    
    Log::write(MailInbound::LOG, info);
}

event pop3_reply(c: connection, is_orig: bool, cmd: string, msg: string) &priority=5
{
    if ( /\+OK/ in msg ) {
        local info: Info;
        info$ts = network_time();
        info$uid = c$uid;
        info$id = c$id;
        info$protocol = "POP3";
        info$action = cmd;
        info$status = "OK";
        info$details = msg;
        Log::write(MailInbound::LOG, info);
    }
}

# 连接结束时的汇总
event connection_state_remove(c: connection) &priority=5
{
    # 检查是否是邮件相关连接
    local is_mail_conn = F;
    local service_type = "";
    
    if ( c$id$resp_p in set(25/tcp, 465/tcp, 587/tcp, 2525/tcp, 1025/tcp, 3025/tcp, 3465/tcp) ) {
        is_mail_conn = T;
        service_type = "SMTP";
    }
    else if ( c$id$resp_p in set(143/tcp, 993/tcp, 3143/tcp, 3993/tcp) ) {
        is_mail_conn = T;
        service_type = "IMAP";
    }
    else if ( c$id$resp_p in set(110/tcp, 995/tcp, 3110/tcp, 3995/tcp) ) {
        is_mail_conn = T;
        service_type = "POP3";
    }
    
    if ( is_mail_conn ) {
        local info: Info;
        info$ts = network_time();
        info$uid = c$uid;
        info$id = c$id;
        info$protocol = service_type;
        info$action = "CONNECTION_END";
        info$status = "CLOSED";
        info$details = fmt("连接持续时间: %.2f秒", c$duration);
        Log::write(MailInbound::LOG, info);
    }
}