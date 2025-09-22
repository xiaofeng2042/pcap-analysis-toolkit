# persistence.zeek - 持久化模块
# 处理月度统计的持久化存储

@load base/utils/time
@load ../mail-activity-json.zeek

module MailActivity;

# 导入必要的全局变量声明
# STATS_STATE_FILE 已在主文件中定义为 option 变量
global SITE_ID: string;
global LINK_ID: string;
global current_month: string;
global send_count: count;
global receive_count: count;
global encrypt_count: count;
global decrypt_count: count;

# 状态文件分隔符
const state_delim = "\t";

# 获取当前月份字符串
function get_current_month(): string
{
    return strftime("%Y-%m", current_time());
}

# 保存统计到文件
function save_stats_to_file()
{
    if ( STATS_STATE_FILE == "" )
        return;

    local f = open(STATS_STATE_FILE, "w");
    if ( f == nil ) {
        print fmt("[PERSISTENCE] Unable to open %s for write", STATS_STATE_FILE);
        return;
    }

    local line = fmt("%s%s%s%s%s%s%d%s%d%s%d%s%d",
                    current_month, state_delim,
                    SITE_ID, state_delim,
                    LINK_ID, state_delim,
                    send_count, state_delim,
                    receive_count, state_delim,
                    encrypt_count, state_delim,
                    decrypt_count);

    print f, line;
    close(f);
    print fmt("[PERSISTENCE] Stats snapshot saved to %s", STATS_STATE_FILE);
}

# 从文件加载统计数据
function load_stats_from_file()
{
    if ( STATS_STATE_FILE == "" )
        return;

    local f = open(STATS_STATE_FILE, "r");
    if ( f == nil ) {
        print fmt("[PERSISTENCE] No existing state at %s, starting fresh", STATS_STATE_FILE);
        return;
    }

    local line = read_line(f);
    close(f);

    if ( line == "" )
        return;

    local fields = split(line, state_delim);
    if ( |fields| < 7 ) {
        print fmt("[PERSISTENCE] Corrupted state line: %s", line);
        return;
    }

    current_month = fields[0];
    send_count    = to_count(fields[3]);
    receive_count = to_count(fields[4]);
    encrypt_count = to_count(fields[5]);
    decrypt_count = to_count(fields[6]);

    print fmt("[PERSISTENCE] Restored stats: month=%s send=%d receive=%d encrypt=%d decrypt=%d",
              current_month, send_count, receive_count, encrypt_count, decrypt_count);
}

# 更新月度统计
function update_monthly_stats(action: string, encrypted: bool, decrypted: bool)
{
    # 检查是否需要切换月份
    local current = get_current_month();
    if ( current_month != current ) {
        # 保存当前月度统计
        if ( current_month != "" ) {
            save_stats_to_file();
        }
        
        # 切换到新月份
        current_month = current;
        send_count = 0;
        receive_count = 0;
        encrypt_count = 0;
        decrypt_count = 0;
        
        # 加载新月份的统计数据
        load_stats_from_file();
        
        print fmt("[PERSISTENCE] Switched to month: %s", current_month);
    }
    
    # 更新统计计数
    if ( action == "send" ) {
        ++send_count;
    } else if ( action == "receive" ) {
        ++receive_count;
    }
    
    # 更新加密统计
    if ( encrypted ) {
        ++encrypt_count;
    }
    
    if ( decrypted ) {
        ++decrypt_count;
    }
}

# Zeek 正常退出时保存状态
event zeek_done()
{
    save_stats_to_file();
}
