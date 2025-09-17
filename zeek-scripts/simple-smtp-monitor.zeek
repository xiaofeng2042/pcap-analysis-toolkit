# 简化版实时SMTP流量监控
# 用于 zeek -i en0 simple-smtp-monitor.zeek

@load base/protocols/smtp
@load base/protocols/ssl

# 启用JSON输出
redef LogAscii::use_json = T;

# 设置日志轮转
redef Log::default_rotation_interval = 1hr;

# 只记录SMTP相关的日志
redef Log::enable_local_logging = T;

# 统计变量
global smtp_connections: count = 0;
global starttls_attempts: count = 0;
global starttls_success: count = 0;
global encrypted_connections: count = 0;

# 定时报告间隔（秒）
const report_interval = 300sec &redef;

# 定义统计报告事件
global print_stats_event: event();

# 连接统计
event smtp_request(c: connection, is_orig: bool, command: string, arg: string)
{
    if ( is_orig && (to_upper(command) == "EHLO" || to_upper(command) == "HELO") )
    {
        ++smtp_connections;
        print fmt("New SMTP Connection: %s:%d -> %s:%d", 
                 c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p);
    }
    
    if ( to_upper(command) == "STARTTLS" )
    {
        ++starttls_attempts;
        print fmt("STARTTLS Attempt: %s:%d", c$id$orig_h, c$id$orig_p);
    }
}

# SSL建立统计
event ssl_established(c: connection)
{
    if ( c$id$resp_p == 25/tcp || c$id$resp_p == 465/tcp ||
         c$id$resp_p == 587/tcp || c$id$resp_p == 2525/tcp )
    {
        ++encrypted_connections;
        ++starttls_success;
        print fmt("TLS Handshake Success: %s:%d", c$id$orig_h, c$id$orig_p);
    }
}

# 定时统计报告
event zeek_init()
{
    print "SMTP Monitor Started";
    print fmt("Report Interval: %s", report_interval);
    schedule report_interval { print_stats_event() };
}

event print_stats_event()
{
    print "==================================================";
    print fmt("SMTP Traffic Statistics [%s]", strftime("%Y-%m-%d %H:%M:%S", current_time()));
    print fmt("   Total SMTP Connections: %d", smtp_connections);
    print fmt("   STARTTLS Attempts: %d", starttls_attempts);
    print fmt("   STARTTLS Success: %d", starttls_success);
    print fmt("   Encrypted Connections: %d", encrypted_connections);
    
    local encryption_rate = starttls_attempts > 0 ? 
        (starttls_success * 100.0 / starttls_attempts) : 0.0;
    print fmt("   Encryption Success Rate: %.1f%%", encryption_rate);
    print "==================================================";
    
    # 安排下次报告
    schedule report_interval { print_stats_event() };
}