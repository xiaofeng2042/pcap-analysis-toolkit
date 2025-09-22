# test-stats-simple.zeek - 简化的邮件统计功能测试脚本

@load ../mail-activity-json.zeek

event zeek_init()
{
    print "=== 邮件统计功能简单测试 ===";
    print "";
    
    # 显示当前配置
    print "配置信息:";
    print fmt("  SITE_ID: %s", MailActivity::SITE_ID);
    print fmt("  LINK_ID: %s", MailActivity::LINK_ID);
    print fmt("  STATS_STATE_FILE: %s", MailActivity::STATS_STATE_FILE != "" ? MailActivity::STATS_STATE_FILE : "未设置");
    print "";
    
    # 显示初始统计
    print "初始统计:";
    print fmt("  发送计数: %d", MailActivity::send_count);
    print fmt("  接收计数: %d", MailActivity::receive_count);
    print fmt("  加密计数: %d", MailActivity::encrypt_count);
    print fmt("  解密计数: %d", MailActivity::decrypt_count);
    print fmt("  当前月份: %s", MailActivity::current_month);
    print "";
    
    # 测试统计更新
    print "测试统计更新:";
    print "  执行 update_monthly_stats(\"send\", F, F)";
    MailActivity::update_monthly_stats("send", F, F);
    print fmt("  更新后发送计数: %d", MailActivity::send_count);
    
    print "  执行 update_monthly_stats(\"receive\", T, F)";
    MailActivity::update_monthly_stats("receive", T, F);
    print fmt("  更新后接收计数: %d", MailActivity::receive_count);
    print fmt("  更新后加密计数: %d", MailActivity::encrypt_count);
    print "";
    
    # 测试状态文件保存
    if ( MailActivity::STATS_STATE_FILE != "" ) {
        print "测试状态文件保存:";
        MailActivity::save_stats_to_file();
        print "  状态保存完成";
    } else {
        print "未配置状态文件，跳过保存测试";
    }
    
    print "";
    print "=== 测试完成 ===";
}

event zeek_done()
{
    print "";
    print "最终统计:";
    print fmt("  发送计数: %d", MailActivity::send_count);
    print fmt("  接收计数: %d", MailActivity::receive_count);
    print fmt("  加密计数: %d", MailActivity::encrypt_count);
    print fmt("  解密计数: %d", MailActivity::decrypt_count);
}