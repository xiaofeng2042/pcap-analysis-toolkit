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
@load base/utils/files

# JSON日志配置
redef LogAscii::use_json = T;

module MailActivity;

export {
    # 双端监控配置参数 - 支持从环境变量读取
    option SITE_ID = getenv("SITE_ID") != "" ? getenv("SITE_ID") : "" &redef;                    # 必填：overseas/hq
    option LINK_ID = getenv("LINK_ID") != "" ? getenv("LINK_ID") : "" &redef;                    # 可选：链路标识，如overseas↔hq-1
    option LAN_INTERFACE = getenv("LAN_INTERFACE") != "" ? getenv("LAN_INTERFACE") : "eno1" &redef;          # 主采集口（邮件流水）
    option TUNNEL_INTERFACE = getenv("TUNNEL_INTERFACE") != "" ? getenv("TUNNEL_INTERFACE") : "tap_tap" &redef;    # 副采集口（链路画像）
    option STATS_STATE_FILE = getenv("MAIL_STATS_STATE_FILE") != "" ? 
                              getenv("MAIL_STATS_STATE_FILE") : "" &redef;                      # 统计状态文件路径
    
    # 方向判定结果类型
    type DirectionInfo: record {
        direction_raw: string;                     # outbound/inbound
        action: string;                           # 标准化动作描述
        evidence: vector of string;               # 证据列表
        confidence: double;                       # 置信度 0.5-1.0
    };
    
    # 连接跟踪信息
    type ConnectionTrack: record {
        syn_path: string &optional;               # SYN包路径：eno1->tap_tap 或 tap_tap->eno1
        smtp_role: string &optional;              # SMTP角色：client_first/server_first
        first_interface: string &optional;        # 首次观察到的接口
        link_encrypted: bool &default=F;          # 链路加密状态
        link_decrypted: bool &default=F;          # 链路解密状态
        direction_info: DirectionInfo &optional;  # 方向判定结果
    };

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
        
        # 双端监控新增字段
        site_id: string &log &optional;           # 站点标识：overseas/hq
        link_id: string &log &optional;           # 链路标识
        direction_raw: string &log &optional;     # 原始方向：outbound/inbound
        action: string &log &optional;            # 标准化动作
        evidence: vector of string &log &optional; # 方向判定证据
        confidence: double &log &optional;        # 方向判定置信度
        link_encrypted: bool &log &optional;      # 链路加密状态
        link_decrypted: bool &log &optional;      # 链路解密状态
        subject_sha256: string &log &optional;    # 主题SHA256哈希
        
        # 内容聚焦字段
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
    
    # 日志ID枚举
    redef enum Log::ID += { 
        LOG,           # 主邮件活动日志
        FLOW_LOG,      # 逐封流水日志
        STATS_LOG,     # 月度统计日志
        TLS_LOG        # TLS链路画像日志
    };

    # 逐封流水日志结构（mail_flow.log）
    type FlowInfo: record {
        ts: time &log;                             # ISO8601时间戳
        site_id: string &log;                      # 站点标识
        link_id: string &log &optional;           # 链路标识
        direction_raw: string &log;                # 原始方向：outbound/inbound
        action: string &log;                       # 标准化动作
        msg_id: string &log &optional;            # Message-ID（去尖括号）
        mailfrom: string &log &optional;          # 发件人
        rcptto: string &log &optional;            # 收件人（拼接）
        subject_sha256: string &log &optional;    # 主题SHA256哈希
        link_encrypted: bool &log &optional;      # 链路加密状态
        link_decrypted: bool &log &optional;      # 链路解密状态
        orig_h: addr &log;                        # 源IP
        resp_h: addr &log;                        # 目标IP
        uid: string &log;                         # Zeek连接UID
        evidence: vector of string &log;          # 方向判定证据
        confidence: double &log;                  # 方向判定置信度
    };

    # 月度统计日志结构
    type StatsInfo: record {
        month: string &log;                        # YYYY-MM格式
        site_id: string &log;
        link_id: string &log &optional;
        send_count: count &log;
        receive_count: count &log;
        encrypt_count: count &log;                 # 链路加密计数
        decrypt_count: count &log;                 # 链路解密计数
        last_update: time &log;
    };

    # TLS链路画像日志结构
    type TlsInfo: record {
        ts: time &log;
        site_id: string &log;
        link_id: string &log &optional;
        ip_pair: string &log;                      # IP:PORT-IP:PORT格式
        starttls_attempt: bool &log;
        starttls_success: bool &log;
        tls_version: string &log &optional;
        cipher: string &log &optional;
        sni: string &log &optional;
        ja3: string &log &optional;
        ja3s: string &log &optional;
        handshake_ms: double &log &optional;
    };

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
    
    # 双端监控新增全局变量
    global connection_tracks: table[string] of ConnectionTrack;  # 连接跟踪表
    global monthly_stats: StatsInfo;                             # 当前月度统计
    global current_month: string = "";                           # 当前月份
    
    # 月度计数器
    global send_count: count = 0;
    global receive_count: count = 0;
    global encrypt_count: count = 0;
    global decrypt_count: count = 0;
    
    global smtp_sessions: table[string] of Info;
    global imap_sessions: table[string] of Info;
    global pop3_sessions: table[string] of Info;
    global pop3_session_states: table[string] of Pop3SessionState;
    
    # 统计报告间隔
    const report_interval = 30sec &redef;
    const stats_save_interval = 60sec &redef;      # 状态文件保存间隔
    const stats_file_path = "mail_stats.tsv" &redef; # 状态文件路径
    
    # 前向声明函数
    global determine_direction: function(c: connection, track: ConnectionTrack): DirectionInfo;
    global standardize_action: function(site_id: string, direction: string): string;
    global update_monthly_stats: function(action: string, encrypted: bool, decrypted: bool);
    global save_stats_to_file: function();
    global load_stats_from_file: function();
    global get_current_month: function(): string;
    global is_mail_port: function(p: port): bool;
    global identify_protocol: function(p: port): string;
    global update_smtp_role: function(uid: string, role: string);
    global generate_mail_flow_record: function(c: connection, info: Info);
    global sha256_hash: function(input: string): string;
    global join_string_vec: function(vec: vector of string, sep: string): string;
    global str_hash: function(s: string): string;
    global mark_connection_encrypted: function(uid: string, is_encrypted: bool, is_decrypted: bool);
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

const stats_state_delim = "\t";
global stats_state_loaded: bool = F;

function parse_count(value: string): count
{
    if ( value == "" )
        return 0;

    return to_count(value);
}

function restore_stats_from_env(): bool
{
    local init_month = getenv("MAIL_STATS_INIT_MONTH");
    local init_send = getenv("MAIL_STATS_INIT_SEND");
    local init_receive = getenv("MAIL_STATS_INIT_RECEIVE");
    local init_encrypt = getenv("MAIL_STATS_INIT_ENCRYPT");
    local init_decrypt = getenv("MAIL_STATS_INIT_DECRYPT");

    if ( init_month == "" )
        return F;

    current_month = init_month;
    send_count = parse_count(init_send);
    receive_count = parse_count(init_receive);
    encrypt_count = parse_count(init_encrypt);
    decrypt_count = parse_count(init_decrypt);

    stats_state_loaded = T;

    print fmt("[PERSISTENCE] Restored stats from environment: month=%s send=%d receive=%d encrypt=%d decrypt=%d",
              current_month, send_count, receive_count, encrypt_count, decrypt_count);

    return T;
}

function get_current_month(): string
{
    return strftime("%Y-%m", current_time());
}

function load_stats_from_file()
{
    if ( stats_state_loaded )
        return;

    if ( restore_stats_from_env() )
        return;

    if ( STATS_STATE_FILE != "" )
        print fmt("[PERSISTENCE] State file %s not preloaded; starting fresh", STATS_STATE_FILE);
    else
        print "[PERSISTENCE] No state file configured; statistics start fresh";

    stats_state_loaded = T;
}

function save_stats_to_file()
{
    if ( STATS_STATE_FILE == "" )
        return;

    if ( current_month == "" )
        current_month = get_current_month();

    local f = open(STATS_STATE_FILE);

    local line = fmt("%s%s%s%s%s%s%d%s%d%s%d%s%d",
                     current_month, stats_state_delim,
                     SITE_ID, stats_state_delim,
                     LINK_ID, stats_state_delim,
                     send_count, stats_state_delim,
                     receive_count, stats_state_delim,
                     encrypt_count, stats_state_delim,
                     decrypt_count);

    print f, line;
    close(f);

    print fmt("[PERSISTENCE] Stats snapshot saved to %s", STATS_STATE_FILE);
}

function update_monthly_stats(action: string, encrypted: bool, decrypted: bool)
{
    if ( !stats_state_loaded )
        load_stats_from_file();

    local current = get_current_month();
    if ( current_month == "" )
        current_month = current;

    if ( current_month != current ) {
        save_stats_to_file();

        current_month = current;
        send_count = 0;
        receive_count = 0;
        encrypt_count = 0;
        decrypt_count = 0;

        print fmt("[PERSISTENCE] Switched to month: %s", current_month);
    }

    if ( action == "send" )
        ++send_count;
    else if ( action == "receive" )
        ++receive_count;

    if ( encrypted )
        ++encrypt_count;

    if ( decrypted )
        ++decrypt_count;

    save_stats_to_file();
}

# Zeek初始化事件
event zeek_init()
{
    # 验证必填配置
    if ( MailActivity::SITE_ID == "" ) {
        print "[ERROR] SITE_ID is required! Please set to 'overseas' or 'hq'";
        exit(1);
    }
    
    if ( MailActivity::SITE_ID != "overseas" && MailActivity::SITE_ID != "hq" ) {
        print fmt("[ERROR] Invalid SITE_ID: %s. Must be 'overseas' or 'hq'", MailActivity::SITE_ID);
        exit(1);
    }
    
    # 创建日志流
    Log::create_stream(MailActivity::LOG, [$columns=MailActivity::Info, $path="mail_activity"]);
    Log::create_stream(MailActivity::FLOW_LOG, [$columns=MailActivity::FlowInfo, $path="mail_flow"]);
    Log::create_stream(MailActivity::STATS_LOG, [$columns=MailActivity::StatsInfo, $path="mail_stats"]);
    Log::create_stream(MailActivity::TLS_LOG, [$columns=MailActivity::TlsInfo, $path="link_tls"]);
    
    # 创建POP3日志流（如果启用）
    if ( MailActivity::enable_pop3_log ) {
        Log::create_stream(MailActivity::POP_LOG, [$columns=MailActivity::PopInfo, $path="pop3_activity"]);
    }
    
    # 初始化全局统计变量
    MailActivity::smtp_connections = 0;
    MailActivity::starttls_attempts = 0;
    MailActivity::starttls_success = 0;
    MailActivity::encrypted_connections = 0;
    
    # 初始化双端监控变量
    MailActivity::send_count = 0;
    MailActivity::receive_count = 0;
    MailActivity::encrypt_count = 0;
    MailActivity::decrypt_count = 0;
    MailActivity::current_month = get_current_month();
    
    # 从文件加载月度统计
    load_stats_from_file();
    
    # 注册协议分析器
    Analyzer::register_for_ports(Analyzer::ANALYZER_SMTP, MailActivity::SMTP_PORTS);
    Analyzer::register_for_ports(Analyzer::ANALYZER_POP3, MailActivity::POP3_PORTS);
    
    # 启动定时任务
    schedule MailActivity::report_interval { MailActivity::mail_stats_report() };
    # 注释掉save_monthly_stats调用，该功能由persistence模块处理
    # schedule MailActivity::stats_save_interval { MailActivity::save_monthly_stats() };
    
    print "[INFO] MailActivity module initialized with dual-interface monitoring";
    print fmt("[INFO] Site ID: %s, Link ID: %s", MailActivity::SITE_ID, MailActivity::LINK_ID);
    print fmt("[INFO] LAN Interface: %s, Tunnel Interface: %s", MailActivity::LAN_INTERFACE, MailActivity::TUNNEL_INTERFACE);
    print fmt("[INFO] Monitoring SMTP ports: %s", MailActivity::SMTP_PORTS);
    print fmt("[INFO] Monitoring POP3 ports: %s", MailActivity::POP3_PORTS);
    print fmt("[INFO] Monitoring IMAP ports: %s", MailActivity::IMAP_PORTS);
}

# 月度统计保存事件（由persistence模块处理）
# event MailActivity::save_monthly_stats()
# {
#     MailActivity::save_stats_to_file();
#     schedule MailActivity::stats_save_interval { MailActivity::save_monthly_stats() };
# }

event MailActivity::mail_stats_report()
{
    print "+==============================================================+";
    print fmt("|| [STATS] Mail Traffic Statistics [%s] ||", strftime("%Y-%m-%d %H:%M:%S", current_time()));
    print "+==============================================================+";
    print fmt("|| SMTP Connections: %d", MailActivity::smtp_connections);
    print fmt("|| STARTTLS Attempts: %d", MailActivity::starttls_attempts);
    print fmt("|| STARTTLS Success: %d", MailActivity::starttls_success);
    print fmt("|| Encrypted Connections: %d", MailActivity::encrypted_connections);
    print fmt("|| Send Count: %d", MailActivity::send_count);
    print fmt("|| Receive Count: %d", MailActivity::receive_count);
    print fmt("|| Encrypt Count: %d", MailActivity::encrypt_count);
    print fmt("|| Decrypt Count: %d", MailActivity::decrypt_count);
    print "+==============================================================+";
    
    # 计算加密成功率
    local success_rate = 0.0;
    if ( MailActivity::starttls_attempts > 0 ) {
        success_rate = (MailActivity::starttls_success * 100.0) / MailActivity::starttls_attempts;
    }
    print fmt("|| STARTTLS Success Rate: %.2f%%", success_rate);
    print "+==============================================================+";
    
    # 重新调度下次报告
    schedule MailActivity::report_interval { MailActivity::mail_stats_report() };
}


event zeek_done()
{
    save_stats_to_file();
}



# 加载子模块
@load ./mail-activity/utils
@load ./mail-activity/smtp
@load ./mail-activity/pop3
@load ./mail-activity/imap
@load ./mail-activity/direction
# @load ./mail-activity/persistence_simple  # Module syntax issue
