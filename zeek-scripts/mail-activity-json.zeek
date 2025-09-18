# mail-activity-json.zeek
# Enhanced Zeek script to record detailed SMTP/POP3 send activity and retrieval events.

@load base/protocols/smtp
@load base/protocols/pop3
@load base/protocols/imap
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
        
        # 内容聚焦字段
        action: string &log &optional;           # "SEND", "RETRIEVE", "FORWARD"
        mailbox_user: string &log &optional;     # POP3用户名或SMTP认证用户
        mailbox_host: string &log &optional;     # 邮箱服务器主机
        size_bytes: count &log &optional;        # 邮件大小（字节）
        encrypted: bool &log &optional;          # 是否加密传输
        
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

    # 优化后的POP3日志配置 - 默认关闭以减少协议噪音
    option enable_pop3_log: bool = F &redef;
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
    
    # SMTP 端口（基于现有配置）
    const SMTP_PORTS: set[port] = {
        25/tcp,    # 标准 SMTP
        465/tcp,   # SMTPS (SSL)
        587/tcp,   # SMTP 提交端口
        2525/tcp,  # 备用 SMTP
        1025/tcp,  # 非标准端口
        3025/tcp,  # 测试端口（GreenMail）
        3465/tcp   # 测试 SMTPS
    } &redef;

    # IMAP 端口
    const IMAP_PORTS: set[port] = {
        143/tcp,   # 标准 IMAP
        993/tcp,   # IMAPS (SSL)
        3143/tcp,  # 测试端口（GreenMail）
        3993/tcp   # 测试 IMAPS
    } &redef;

    # POP3 端口（基于现有配置）
    const POP3_PORTS: set[port] = {
        110/tcp,   # 标准 POP3
        995/tcp,   # POP3S (SSL)
        3110/tcp,  # 测试端口（GreenMail）
        3995/tcp   # 测试 POP3S
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
    
    # POP3会话跟踪表
    global pop3_sessions: table[string] of Info;
    
    # IMAP会话跟踪表
    global imap_sessions: table[string] of Info;
    
    # POP3会话状态记录
    type Pop3SessionState: record {
        message_number: count &optional;    # 当前检索的消息编号
        bytes_received: count &default=0;   # 已接收字节数
        headers_complete: bool &default=F;  # 头部是否解析完成
    };
    
    global pop3_session_states: table[string] of Pop3SessionState;
}

event zeek_init()
{
    # 初始化全局统计变量
    smtp_connections = 0;
    starttls_attempts = 0;
    starttls_success = 0;
    encrypted_connections = 0;
    
    # 注册非标准端口到相应的协议分析器
    # 注册 POP3 非标准端口
    Analyzer::register_for_ports(Analyzer::ANALYZER_POP3, MailActivity::POP3_PORTS);
    
    # 注册 SMTP 非标准端口
    Analyzer::register_for_ports(Analyzer::ANALYZER_SMTP, MailActivity::SMTP_PORTS);
    
    Log::create_stream(MailActivity::LOG, [$columns=MailActivity::Info, $path="mail_activity"]);
    if ( MailActivity::enable_pop3_log )
        Log::create_stream(MailActivity::POP_LOG, [$columns=MailActivity::PopInfo, $path=MailActivity::pop3_log_path]);
    print "[MAIL] Enhanced Mail Activity Monitor Started (SMTP/POP3/IMAP)";
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
    print fmt("|| SMTP/POP3/IMAP Connections: %d                          ||", smtp_connections);
    print fmt("|| STARTTLS Attempts: %d                                   ||", starttls_attempts);
    print fmt("|| STARTTLS Success: %d                                    ||", starttls_success);
    print fmt("|| Encrypted Connections: %d                              ||", encrypted_connections);
    if ( starttls_attempts > 0 ) {
        local success_rate = (starttls_success * 100) / starttls_attempts;
        print fmt("|| Encryption Success Rate: %d%%                          ||", success_rate);
    }
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
        info$action = "SEND";
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
    if ( c$id$resp_p in MailActivity::SMTP_PORTS || c$id$resp_p in MailActivity::POP3_PORTS || c$id$resp_p in MailActivity::IMAP_PORTS ) {
        ++encrypted_connections;
        
        local uid = c$uid;
        local tls_info: MailActivity::Info;
        local is_implicit_tls = F;
        
        # 检查是否为隐式 TLS 端口
        if ( c$id$resp_p == 465/tcp || c$id$resp_p == 993/tcp || c$id$resp_p == 995/tcp ||
             c$id$resp_p == 3465/tcp || c$id$resp_p == 3993/tcp || c$id$resp_p == 3995/tcp ) {
            is_implicit_tls = T;
        }
        
        # 处理现有会话的 TLS 升级
        if ( uid in MailActivity::smtp_sessions ) {
            local info = MailActivity::smtp_sessions[uid];
            info$tls = T;
            info$encrypted = T;
            if ( c$ssl?$version )
                info$tls_version = c$ssl$version;
            Log::write(MailActivity::LOG, info);
        }
        else if ( uid in MailActivity::pop3_sessions ) {
            local pop_info = MailActivity::pop3_sessions[uid];
            pop_info$tls = T;
            pop_info$encrypted = T;
            if ( c$ssl?$version )
                pop_info$tls_version = c$ssl$version;
            MailActivity::pop3_sessions[uid] = pop_info;
        }
        # 处理隐式 TLS 连接（从连接开始就是加密的）
        else if ( is_implicit_tls ) {
            tls_info = new_smtp_info(c);
            tls_info$tls = T;
            tls_info$encrypted = T;
            tls_info$is_webmail = F;
            
            if ( c$ssl?$version )
                tls_info$tls_version = c$ssl$version;
            
            # 识别协议类型
            local protocol = "UNKNOWN";
            if ( c$id$resp_p in MailActivity::SMTP_PORTS )
                protocol = "SMTP";
            else if ( c$id$resp_p in MailActivity::POP3_PORTS )
                protocol = "POP3";
            else if ( c$id$resp_p in MailActivity::IMAP_PORTS )
                protocol = "IMAP";
                
            # 根据端口确定协议类型并记录
            if ( protocol == "SMTP" ) {
                tls_info$protocol = "SMTP";
                tls_info$activity = "SMTPS_TLS_ESTABLISHED";
                tls_info$role = "client";
                print fmt("[SMTPS] Implicit TLS connection established: %s:%d -> %s:%d (TLS: %s)", 
                          c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p, 
                          c$ssl?$version ? c$ssl$version : "unknown");
            }
            else if ( protocol == "POP3" ) {
                tls_info$protocol = "POP3";
                tls_info$activity = "POP3S_TLS_ESTABLISHED";
                tls_info$role = "client";
                print fmt("[POP3S] Implicit TLS connection established: %s:%d -> %s:%d (TLS: %s)", 
                          c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p, 
                          c$ssl?$version ? c$ssl$version : "unknown");
            }
            else if ( protocol == "IMAP" ) {
                tls_info$protocol = "IMAP";
                tls_info$activity = "IMAPS_TLS_ESTABLISHED";
                tls_info$role = "client";
                print fmt("[IMAPS] Implicit TLS connection established: %s:%d -> %s:%d (TLS: %s)", 
                          c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p, 
                          c$ssl?$version ? c$ssl$version : "unknown");
            }
            
            # 记录隐式 TLS 连接
            Log::write(MailActivity::LOG, tls_info);
        }
        
        print fmt("[TLS] SSL/TLS Connection Established: %s:%d -> %s:%d", 
                  c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p);
    }
}

# POP3 事件处理 - 优化后的版本，减少协议噪音
event pop3_request(c: connection, is_orig: bool, command: string, arg: string)
{
    if ( ! is_orig )
        return;
    
    local uid = c$uid;
    
    # 处理RETR命令 - 创建内容聚焦的会话记录
    if ( command == "RETR" ) {
        local info: MailActivity::Info = [
            $ts = network_time(),
            $uid = uid,
            $id = c$id,
            $protocol = "POP3",
            $role = "receiver",
            $action = "RETRIEVE",
            $activity = "POP3_RETR",
            $mailbox_host = fmt("%s", c$id$resp_h)
        ];
        
        # 解析消息编号
        if ( arg != "" ) {
            info$detail = fmt("Message #%s", arg);
        }
        
        # 存储到POP3会话表中，等待数据解析
        MailActivity::pop3_sessions[uid] = info;
        
        # 初始化会话状态
        local state: MailActivity::Pop3SessionState = [
            $bytes_received = 0,
            $headers_complete = F
        ];
        
        if ( arg != "" ) {
            state$message_number = to_count(arg);
        }
        
        MailActivity::pop3_session_states[uid] = state;
        
        print fmt("[POP3] Starting message retrieval: %s (UID: %s)", arg, uid);
    }
    
    # 只记录重要的POP3命令到单独日志（如果启用）
    if ( MailActivity::enable_pop3_log ) {
        # 只记录认证和重要操作，跳过LIST、STAT等噪音命令
        if ( command == "USER" || command == "PASS" || command == "RETR" || command == "DELE" ) {
            local pop_info: MailActivity::PopInfo = [
                $ts = network_time(),
                $uid = uid,
                $id = c$id,
                $activity = fmt("POP3_%s", command)
            ];
            
            if ( command == "USER" ) {
                pop_info$user = arg;
                print fmt("[POP3] User Login Attempt: %s", arg);
                
                # 记录用户信息到可能的会话中
                if ( uid in MailActivity::pop3_sessions ) {
                    MailActivity::pop3_sessions[uid]$mailbox_user = arg;
                }
            }
            else if ( command == "PASS" ) {
                pop_info$activity = "POP3_PASS";
                print fmt("[POP3] Password Authentication");
            }
            else if ( command == "RETR" ) {
                pop_info$argument = arg;
            }
            else if ( command == "DELE" ) {
                pop_info$argument = arg;
                print fmt("[POP3] Message Deletion: %s", arg);
            }
            
            Log::write(MailActivity::POP_LOG, pop_info);
        }
    }
    
    # 处理USER命令，记录用户信息到内容聚焦会话
    if ( command == "USER" ) {
        # 为后续的RETR会话预设用户信息
        # 这里我们可以创建一个临时记录来存储用户信息
        print fmt("[POP3] User Login Attempt: %s", arg);
    }
}

event pop3_reply(c: connection, is_orig: bool, cmd: string, msg: string)
{
    if ( is_orig )
        return;
    
    # 只记录重要的回复到POP3日志（如果启用）
    if ( MailActivity::enable_pop3_log ) {
        # 只记录认证结果和重要操作的回复
        if ( cmd == "USER" || cmd == "PASS" || cmd == "RETR" || cmd == "DELE" ) {
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
    }
    
    # 处理USER命令成功回复，更新用户信息
    if ( cmd == "USER" && /^\+OK/ in msg ) {
        local uid = c$uid;
        # 如果有活跃的POP3会话，更新用户信息
        if ( uid in MailActivity::pop3_sessions ) {
            # 用户信息将在RETR时设置
        }
    }
}

# ========== IMAP 监控 ==========
# 注意：Zeek的IMAP协议分析器只支持StartTLS功能，没有提供imap_request和imap_reply事件
# 我们通过连接跟踪和TLS事件来监控IMAP活动

# IMAP连接通过ssl_established事件和端口识别来处理

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
    
    # 清理 IMAP 会话数据
    if ( uid in MailActivity::imap_sessions ) {
        local imap_info = MailActivity::imap_sessions[uid];
        imap_info$activity = "IMAP_CONNECTION_END";
        Log::write(MailActivity::LOG, imap_info);
        delete MailActivity::imap_sessions[uid];
        print fmt("[IMAP] Connection ended: %s", uid);
    }
    
    # 处理 POP3 会话
    if ( uid in MailActivity::pop3_sessions ) {
        local pop_info = MailActivity::pop3_sessions[uid];
        pop_info$activity = "POP3_CONNECTION_END";
        Log::write(MailActivity::LOG, pop_info);
        delete MailActivity::pop3_sessions[uid];
        print fmt("[POP3] Connection ended: %s", uid);
    }
}

# POP3数据事件 - 解析邮件头部和内容聚焦
event pop3_data(c: connection, is_orig: bool, data: string)
{
    local uid = c$uid;
    
    # 只处理服务器发送的数据（邮件内容）
    if ( is_orig )
        return;
    
    # 检查是否为RETR会话
    if ( uid !in MailActivity::pop3_sessions || uid !in MailActivity::pop3_session_states )
        return;
    
    local info = MailActivity::pop3_sessions[uid];
    local state = MailActivity::pop3_session_states[uid];
    
    # 累计接收字节数
    state$bytes_received += |data|;
    
    # 检查是否为消息结束标志（单独的"."行）
    if ( data == ".\r\n" || data == ".\n" ) {
        # 消息结束，完成内容聚焦记录
        info$size_bytes = state$bytes_received;
        
        # 写入主要邮件活动日志
        Log::write(MailActivity::LOG, info);
        
        print fmt("[POP3] Message retrieval completed: UID %s, Size: %d bytes", uid, state$bytes_received);
        
        # 清理会话数据
        delete MailActivity::pop3_sessions[uid];
        delete MailActivity::pop3_session_states[uid];
        return;
    }
    
    # 如果还在解析头部
    if ( !state$headers_complete ) {
        # 检查是否为空行（头部结束标志）
        if ( data == "\r\n" || data == "\n" ) {
            state$headers_complete = T;
            print fmt("[POP3] Header parsing completed for UID: %s", uid);
            return;
        }
        
        # 解析邮件头部字段
        if ( /^[Ss]ubject:/ in data ) {
            info$subject = sub(data, /^[Ss]ubject:\s*/, "");
            info$subject = sub(info$subject, /\r?\n$/, "");
        }
        else if ( /^[Ff]rom:/ in data ) {
            info$from_header = sub(data, /^[Ff]rom:\s*/, "");
            info$from_header = sub(info$from_header, /\r?\n$/, "");
        }
        else if ( /^[Tt]o:/ in data ) {
            info$to_header = sub(data, /^[Tt]o:\s*/, "");
            info$to_header = sub(info$to_header, /\r?\n$/, "");
        }
        else if ( /^[Mm]essage-[Ii][Dd]:/ in data ) {
            info$message_id = sub(data, /^[Mm]essage-[Ii][Dd]:\s*/, "");
            info$message_id = sub(info$message_id, /\r?\n$/, "");
        }
        else if ( /^[Dd]ate:/ in data ) {
            local date_str = sub(data, /^[Dd]ate:\s*/, "");
            date_str = sub(date_str, /\r?\n$/, "");
            info$detail = date_str;
        }
    }
}
