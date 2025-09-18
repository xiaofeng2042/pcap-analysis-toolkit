# logging.zeek - 日志记录和统计报告模块
# 处理邮件活动的日志记录和统计报告功能

module MailActivity;

# 邮件统计报告事件
event mail_stats_report()
{
    # 计算加密成功率
    local encryption_rate = 0.0;
    if ( starttls_attempts > 0 ) {
        encryption_rate = (starttls_success * 100.0) / starttls_attempts;
    }
    
    # 创建统计报告记录
    local stats_info: Info = [
        $ts = network_time(),
        $uid = "STATS_REPORT",
        $id = [$orig_h = 0.0.0.0, $orig_p = 0/tcp, $resp_h = 0.0.0.0, $resp_p = 0/tcp],
        $protocol = "STATS",
        $role = "system",
        $activity = "MAIL_STATISTICS_REPORT",
        $detail = fmt("SMTP: %d connections, TLS: %d/%d attempts (%.1f%% success), Encrypted: %d",
                     smtp_connections, starttls_success, starttls_attempts, 
                     encryption_rate, encrypted_connections)
    ];
    
    # 记录统计信息到日志
    Log::write(LOG, stats_info);
    
    # 打印统计报告到控制台
    print "+==============================================================+";
    print fmt("|| [STATS] Mail Traffic Statistics [%s] ||", strftime("%Y-%m-%d %H:%M:%S", network_time()));
    print "+==============================================================+";
    print fmt("|| SMTP Connections: %d", smtp_connections);
    print fmt("|| STARTTLS Attempts: %d", starttls_attempts);
    print fmt("|| STARTTLS Success: %d", starttls_success);
    print fmt("|| Encryption Success Rate: %.1f%%", encryption_rate);
    print fmt("|| Encrypted Connections: %d", encrypted_connections);
    print "+==============================================================+";
    
    # 重新调度下一次统计报告
    schedule report_interval { mail_stats_report() };
}

# 清理登录参数的辅助函数
function sanitize_login_args(args: string): string
{
    # 移除密码信息，保护隐私
    local sanitized = args;
    
    # 处理IMAP LOGIN命令格式: tag LOGIN username password
    if ( /LOGIN/ in sanitized ) {
        # 查找LOGIN关键字后的参数
        local parts = split_string(sanitized, / /);
        if ( |parts| >= 4 ) {
            # 保留tag和LOGIN，用户名，密码用[REDACTED]替换
            sanitized = fmt("%s %s %s [REDACTED]", parts[0], parts[1], parts[2]);
        } else if ( |parts| >= 3 ) {
            # 只有用户名，没有密码
            sanitized = fmt("%s %s %s", parts[0], parts[1], parts[2]);
        }
    }
    
    # 处理POP3 USER/PASS命令
    if ( /PASS/ in sanitized ) {
        sanitized = sub(sanitized, /PASS\s+\S+/, "PASS [REDACTED]");
    }
    
    # 处理SMTP AUTH命令
    if ( /AUTH/ in sanitized ) {
        # 保留AUTH类型，但隐藏认证数据
        if ( /AUTH\s+PLAIN/ in sanitized ) {
            sanitized = sub(sanitized, /AUTH\s+PLAIN\s+\S+/, "AUTH PLAIN [REDACTED]");
        } else if ( /AUTH\s+LOGIN/ in sanitized ) {
            sanitized = sub(sanitized, /AUTH\s+LOGIN\s+\S+/, "AUTH LOGIN [REDACTED]");
        } else {
            sanitized = sub(sanitized, /AUTH\s+\S+\s+\S+/, "AUTH [TYPE] [REDACTED]");
        }
    }
    
    return sanitized;
}

# 邮件会话结束处理函数
function finalize_mail_session(uid: string, protocol: string)
{
    # 创建会话结束记录
    local end_info: Info = [
        $ts = network_time(),
        $uid = uid,
        $id = [$orig_h = 0.0.0.0, $orig_p = 0/tcp, $resp_h = 0.0.0.0, $resp_p = 0/tcp],
        $protocol = protocol,
        $role = "session",
        $activity = fmt("%s_SESSION_END", protocol),
        $detail = "Mail session completed"
    ];
    
    # 记录会话结束
    Log::write(LOG, end_info);
    
    print fmt("[%s] Session ended: %s", protocol, uid);
}

# 邮件内容分析函数
function analyze_mail_content(content: string, info: Info)
{
    # 分析邮件内容，提取关键信息
    local lines = split_string(content, /\r?\n/);
    local in_headers = T;
    local attachment_count = 0;
    
    for ( i in lines ) {
        local line = lines[i];
        
        # 检查是否还在头部
        if ( in_headers ) {
            if ( |line| == 0 ) {
                in_headers = F;
                next;
            }
            
            # 解析邮件头部
            if ( /^[Ss]ubject:/ in line ) {
                info$subject = sub(line, /^[Ss]ubject:\s*/, "");
            } else if ( /^[Ff]rom:/ in line ) {
                info$from_header = sub(line, /^[Ff]rom:\s*/, "");
            } else if ( /^[Tt]o:/ in line ) {
                info$to_header = sub(line, /^[Tt]o:\s*/, "");
            } else if ( /^[Mm]essage-[Ii][Dd]:/ in line ) {
                info$message_id = sub(line, /^[Mm]essage-[Ii][Dd]:\s*/, "");
            } else if ( /^[Dd]ate:/ in line ) {
                local date_str = sub(line, /^[Dd]ate:\s*/, "");
                info$detail = date_str;
            } else if ( /^[Cc]ontent-[Tt]ype:.*attachment/ in line ) {
                ++attachment_count;
            }
        } else {
            # 在邮件正文中查找附件
            if ( /Content-Disposition:.*attachment/ in line ) {
                ++attachment_count;
            }
        }
    }
    
    # 设置附件数量
    if ( attachment_count > 0 ) {
        info$attachment_count = attachment_count;
        info$detail = fmt("%s (Attachments: %d)", 
                         info$detail != "" ? info$detail : "Mail with attachments", 
                         attachment_count);
    }
}

# 错误处理和日志记录函数
function log_error(protocol: string, uid: string, error_msg: string)
{
    local error_info: Info = [
        $ts = network_time(),
        $uid = uid,
        $id = [$orig_h = 0.0.0.0, $orig_p = 0/tcp, $resp_h = 0.0.0.0, $resp_p = 0/tcp],
        $protocol = protocol,
        $role = "system",
        $activity = fmt("%s_ERROR", protocol),
        $status = "ERROR",
        $detail = error_msg
    ];
    
    # 记录错误信息
    Log::write(LOG, error_info);
    
    print fmt("[ERROR] %s Error: %s (UID: %s)", protocol, error_msg, uid);
}

# 性能监控函数
function monitor_performance()
{
    # 监控会话表大小
    local smtp_session_count = |smtp_sessions|;
    local pop3_session_count = |pop3_sessions|;
    local imap_session_count = |imap_sessions|;
    
    # 如果会话表过大，记录警告
    if ( smtp_session_count > 1000 || pop3_session_count > 1000 || imap_session_count > 1000 ) {
        local perf_info: Info = [
            $ts = network_time(),
            $uid = "PERFORMANCE_MONITOR",
            $id = [$orig_h = 0.0.0.0, $orig_p = 0/tcp, $resp_h = 0.0.0.0, $resp_p = 0/tcp],
            $protocol = "SYSTEM",
            $role = "monitor",
            $activity = "PERFORMANCE_WARNING",
            $detail = fmt("Large session tables: SMTP=%d, POP3=%d, IMAP=%d", 
                         smtp_session_count, pop3_session_count, imap_session_count)
        ];
        
        Log::write(LOG, perf_info);
        
        print fmt("[WARN] Large session tables detected: SMTP=%d, POP3=%d, IMAP=%d", 
                 smtp_session_count, pop3_session_count, imap_session_count);
    }
}