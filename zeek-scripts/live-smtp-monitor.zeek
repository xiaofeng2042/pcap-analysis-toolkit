# 实时SMTP流量监控配置
# 用于 zeek -i en0 live-smtp-monitor.zeek

@load base/protocols/smtp
@load base/protocols/ssl
@load base/frameworks/files
@load base/frameworks/notice

# 加载我们的自定义脚本
@load ./site-smtp-ports.zeek
@load ./smtp-starttls-flag.zeek

# 启用JSON输出
redef LogAscii::use_json = T;

# 设置日志轮转（每小时一个文件）
redef Log::default_rotation_interval = 1hr;

# 只记录SMTP相关的日志
redef Log::enable_local_logging = T;

# 注释掉不支持的过滤器配置
# redef restrict_filters += {
#     ["smtp-only"] = "port 25 or port 465 or port 587 or port 2525"
# };

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
    if ( is_orig && to_upper(command) == "EHLO" || to_upper(command) == "HELO" )
    {
        ++smtp_connections;
        print fmt("📧 新SMTP连接: %s:%d -> %s:%d", 
                 c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p);
    }
    
    if ( to_upper(command) == "STARTTLS" )
    {
        ++starttls_attempts;
        print fmt("🔐 STARTTLS尝试: %s:%d", c$id$orig_h, c$id$orig_p);
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
        print fmt("✅ TLS握手成功: %s:%d (版本: %s)", 
                 c$id$orig_h, c$id$orig_p, c$ssl$version);
    }
}

# 定时统计报告
event zeek_init()
{
    print "🚀 实时SMTP监控已启动";
    print fmt("📊 统计报告间隔: %s", report_interval);
    schedule report_interval { print_stats_event() };
}

event print_stats_event()
{
    print string_cat("|", string_fill(50, "="), "|");
    print fmt("📊 SMTP流量统计 [%s]", strftime("%Y-%m-%d %H:%M:%S", current_time()));
    print fmt("   SMTP连接总数: %d", smtp_connections);
    print fmt("   STARTTLS尝试: %d", starttls_attempts);
    print fmt("   STARTTLS成功: %d", starttls_success);
    print fmt("   加密连接数: %d", encrypted_connections);
    
    local encryption_rate = starttls_attempts > 0 ? 
        (starttls_success * 100.0 / starttls_attempts) : 0.0;
    print fmt("   加密成功率: %.1f%%", encryption_rate);
    print string_cat("|", string_fill(50, "="), "|");
    
    # 安排下次报告
    schedule report_interval { print_stats_event() };
}

# 邮件附件检测
event file_new(f: fa_file)
{
    if ( f$source == "SMTP" )
    {
        local filename = f?$info && f$info?$filename ? f$info$filename : "未知文件";
        local filesize = f?$info && f$info?$size ? fmt("%d", f$info$size) : "未知大小";
        print fmt("📎 检测到邮件附件: %s (大小: %s)", filename, filesize);
    }
}