# Enhanced Mail Protocol Monitor
# 增强版邮件协议监控脚本 - 支持SMTP/IMAP/POP3

@load base/protocols/smtp
@load base/protocols/imap
@load base/protocols/pop3
@load base/protocols/ssl
@load ./site-smtp-ports.zeek

# macOS回环接口上校验和常为0，否则Zeek会丢包
redef ignore_checksums = T;

# 全局统计变量
global smtp_connections = 0;
global imap_connections = 0;
global pop3_connections = 0;
global ssl_connections = 0;

# 邮件协议端口定义
const SMTP_PORTS: set[port] = { 25/tcp, 465/tcp, 587/tcp, 2525/tcp, 1025/tcp } &redef;
const IMAP_PORTS: set[port] = { 143/tcp, 993/tcp } &redef;
const POP3_PORTS: set[port] = { 110/tcp, 995/tcp } &redef;

# 定时统计事件
global print_stats_event: event();

event zeek_init()
{
    print "Enhanced Mail Protocol Monitor Started";
    print "Monitoring SMTP (send) + IMAP/POP3 (receive) protocols";
    print "Report interval: 60 seconds";
    print "=====================================";
    
    # 每60秒输出一次统计
    schedule 60sec { print_stats_event() };
}

event print_stats_event()
{
    print "";
    print "=== Mail Protocol Statistics ===";
    print fmt("SMTP Connections (Send): %d", smtp_connections);
    print fmt("IMAP Connections (Receive): %d", imap_connections);
    print fmt("POP3 Connections (Receive): %d", pop3_connections);
    print fmt("SSL/TLS Connections: %d", ssl_connections);
    print fmt("Total Mail Connections: %d", smtp_connections + imap_connections + pop3_connections);
    print "================================";
    
    # 重新调度下一次统计
    schedule 60sec { print_stats_event() };
}

# SMTP事件处理 (发送邮件)
event smtp_request(c: connection, is_orig: bool, command: string, arg: string)
{
    if ( c$id$resp_p in SMTP_PORTS )
    {
        print fmt("📤 SMTP Command: %s:%d -> %s:%d | %s %s", 
                  c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p,
                  command, arg);
    }
}

event connection_established(c: connection)
{
    local resp_port = c$id$resp_p;
    
    if ( resp_port in SMTP_PORTS )
    {
        ++smtp_connections;
        print fmt("🔗 SMTP Connection: %s:%d -> %s:%d", 
                  c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p);
    }
    else if ( resp_port in IMAP_PORTS )
    {
        ++imap_connections;
        print fmt("🔗 IMAP Connection: %s:%d -> %s:%d", 
                  c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p);
    }
    else if ( resp_port in POP3_PORTS )
    {
        ++pop3_connections;
        print fmt("🔗 POP3 Connection: %s:%d -> %s:%d", 
                  c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p);
    }
}

# SSL/TLS连接建立事件
event ssl_established(c: connection)
{
    local resp_port = c$id$resp_p;
    
    if ( resp_port in SMTP_PORTS || resp_port in IMAP_PORTS || resp_port in POP3_PORTS )
    {
        ++ssl_connections;
        local protocol = "Unknown";
        
        if ( resp_port in SMTP_PORTS )
            protocol = "SMTP/SMTPS";
        else if ( resp_port in IMAP_PORTS )
            protocol = "IMAP/IMAPS";
        else if ( resp_port in POP3_PORTS )
            protocol = "POP3/POP3S";
            
        print fmt("🔐 TLS Established: %s:%d -> %s:%d | Protocol: %s", 
                 c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p, protocol);
    }
}
