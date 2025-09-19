# persistence.zeek - 持久化模块
# 处理月度统计的持久化存储

@load base/utils/time

module MailActivity;

# 获取当前月份字符串
function get_current_month(): string
{
    return strftime("%Y-%m", current_time());
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

# 保存统计到文件 - 简化实现
function save_stats_to_file()
{
    # 简化版本：直接记录到 mail_stats.log
    local stats_info: StatsInfo;
    stats_info$month = current_month;
    stats_info$site_id = SITE_ID;
    stats_info$link_id = LINK_ID;
    stats_info$send_count = send_count;
    stats_info$receive_count = receive_count;
    stats_info$encrypt_count = encrypt_count;
    stats_info$decrypt_count = decrypt_count;
    stats_info$last_update = current_time();
    
    Log::write(STATS_LOG, stats_info);
    
    print fmt("[PERSISTENCE] Stats saved to log for month: %s (send:%d receive:%d encrypt:%d decrypt:%d)", 
              current_month, send_count, receive_count,
              encrypt_count, decrypt_count);
}

# 从文件加载统计数据 - 简化实现
function load_stats_from_file()
{
    # 简化版本：从文件加载在实际部署中由外部脚本处理
    # 这里初始化为0，重启后统计重新开始
    send_count = 0;
    receive_count = 0;
    encrypt_count = 0;
    decrypt_count = 0;
    
    print fmt("[PERSISTENCE] Initialized stats for month: %s (stats reset to 0)", current_month);
    
    # 在mail_stats.log中记录重启事件
    local restart_info: StatsInfo;
    restart_info$month = current_month;
    restart_info$site_id = SITE_ID;
    restart_info$link_id = LINK_ID;
    restart_info$send_count = 0;
    restart_info$receive_count = 0;
    restart_info$encrypt_count = 0;
    restart_info$decrypt_count = 0;
    restart_info$last_update = current_time();
    
    Log::write(STATS_LOG, restart_info);
}
