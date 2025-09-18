# mail-activity-json.zeek
# 邮件活动监控脚本 - 支持SMTP和POP3协议的JSON格式日志记录
# 
# 功能特性：
# - 监控SMTP和POP3邮件协议活动
# - 生成结构化的JSON格式日志
# - 支持TLS/SSL加密连接监控
# - 提供详细的邮件头部信息解析
# - 包含统计报告和性能监控

# 引入基础协议模块
@load base/protocols/smtp
@load base/protocols/pop3
@load base/protocols/ssl

# JSON日志配置
redef LogAscii::use_json = T;

module MailActivity;

export {
    # 主要信息记录结构
    type Info: record {
        # 基础连接信息
        ts: time &log;
        uid: string &log;
        id: conn_id &log;
        
        # SMTP 标准字段（基于Zeek内置SMTP分析器）
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
        action: string &log &optional;
        mailbox_host: string &log &optional;
        mailbox_user: string &log &optional;
        size_bytes: count &log &optional;
        
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
        
        # POP3 特定字段
        pop3_command: string &log &optional;
        pop3_arguments: string &log &optional;
        pop3_response: string &log &optional;
        pop3_status: string &log &optional;
    };
    
    # 日志ID
    redef enum Log::ID += { LOG };

    # POP3日志配置选项
    option enable_pop3_log = F;
    
    # POP3专用日志记录
    type PopInfo: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;
        activity: string &log;
        user: string &log &optional;
        argument: string &log &optional;
        status: string &log &optional;
    };
    
    # POP3日志ID
    redef enum Log::ID += { POP_LOG };
    
    # POP3会话状态类型
    type Pop3SessionState: record {
        message_number: count &optional;
        bytes_received: count &default=0;
        headers_complete: bool &default=F;
    };
    
    # 全局变量和会话表
    global smtp_connections: count = 0;
    global starttls_attempts: count = 0;
    global starttls_success: count = 0;
    global encrypted_connections: count = 0;
    
    global smtp_sessions: table[string] of Info;
    global imap_sessions: table[string] of Info;
    global pop3_sessions: table[string] of Info;
    global pop3_session_states: table[string] of Pop3SessionState;
    
    # 统计报告间隔
    const report_interval = 30sec &redef;
}

# SMTP端口配置（包括标准端口和测试端口）
const SMTP_PORTS: set[port] = {
    25/tcp,    # 标准SMTP
    465/tcp,   # SMTPS (SSL)
    587/tcp,   # SMTP提交端口
    2525/tcp,  # 备用SMTP
    1025/tcp,  # 非标准端口
    3025/tcp,  # 测试端口（GreenMail）
    3465/tcp   # 测试SMTPS
} &redef;

# POP3端口配置
const POP3_PORTS: set[port] = {
    110/tcp,   # 标准POP3
    995/tcp,   # POP3S (SSL)
    3110/tcp,  # 测试端口（GreenMail）
    3995/tcp   # 测试POP3S
} &redef;

# IMAP端口配置
const IMAP_PORTS: set[port] = {
    143/tcp,   # 标准IMAP
    993/tcp,   # IMAPS (SSL)
    3143/tcp,  # 测试端口（GreenMail）
    3993/tcp   # 测试IMAPS
} &redef;

# 前向声明事件
global mail_stats_report: event();

# Zeek初始化事件
event zeek_init()
{
    # 创建主日志流
    Log::create_stream(MailActivity::LOG, [$columns=MailActivity::Info, $path="mail_activity"]);
    
    # 创建POP3日志流（如果启用）
    if ( MailActivity::enable_pop3_log ) {
        Log::create_stream(MailActivity::POP_LOG, [$columns=MailActivity::PopInfo, $path="pop3_activity"]);
    }
    
    # 初始化全局统计变量
    MailActivity::smtp_connections = 0;
    MailActivity::starttls_attempts = 0;
    MailActivity::starttls_success = 0;
    MailActivity::encrypted_connections = 0;
    
    # 注册协议分析器
    Analyzer::register_for_ports(Analyzer::ANALYZER_SMTP, MailActivity::SMTP_PORTS);
    Analyzer::register_for_ports(Analyzer::ANALYZER_POP3, MailActivity::POP3_PORTS);
    
    # 启动统计报告
    schedule MailActivity::report_interval { mail_stats_report() };
    
    print "[INFO] MailActivity module initialized with modular structure";
    print fmt("[INFO] Monitoring SMTP ports: %s", MailActivity::SMTP_PORTS);
    print fmt("[INFO] Monitoring POP3 ports: %s", MailActivity::POP3_PORTS);
    print fmt("[INFO] Monitoring IMAP ports: %s", MailActivity::IMAP_PORTS);
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



# 引入子模块（按依赖顺序加载）
@load ./mail-activity/utils
@load ./mail-activity/smtp
@load ./mail-activity/pop3
@load ./mail-activity/imap
