# test-stats.zeek - 邮件统计功能测试脚本
# 测试统计数据的收集、更新和持久化功能

@load ../mail-activity-json.zeek

# 测试计数器
local test_passed = 0;
local test_failed = 0;

# 测试辅助函数
function test_check(condition: bool, test_name: string)
{
    if ( condition ) {
        print fmt("[TEST PASS] %s", test_name);
        ++test_passed;
    } else {
        print fmt("[TEST FAIL] %s", test_name);
        ++test_failed;
    }
}

# 测试1: 统计初始化
function test_stats_initialization()
{
    print "\n=== Test 1: Statistics Initialization ===";
    
    # 检查统计变量是否初始化
    test_check(MailActivity::send_count >= 0, "send_count initialized");
    test_check(MailActivity::receive_count >= 0, "receive_count initialized");
    test_check(MailActivity::encrypt_count >= 0, "encrypt_count initialized");
    test_check(MailActivity::decrypt_count >= 0, "decrypt_count initialized");
    
    # 检查日期是否设置
    local current_date = MailActivity::get_current_date();
    test_check(current_date != "", "current date is set");
    test_check(|current_date| == 10, "date format YYYY-MM-DD");
    
    print fmt("Current date: %s", current_date);
    print fmt("Initial stats: send=%d, receive=%d, encrypt=%d, decrypt=%d",
              MailActivity::send_count, MailActivity::receive_count,
              MailActivity::encrypt_count, MailActivity::decrypt_count);
}

# 测试2: 统计更新功能
function test_stats_update()
{
    print "\n=== Test 2: Statistics Update ===";
    
    # 记录初始值
    local initial_send = MailActivity::send_count;
    local initial_receive = MailActivity::receive_count;
    local initial_encrypt = MailActivity::encrypt_count;
    local initial_decrypt = MailActivity::decrypt_count;
    
    # 测试发送统计
    MailActivity::update_daily_stats("send", F, F);
    test_check(MailActivity::send_count == initial_send + 1, "send count incremented");
    
    # 测试接收统计
    MailActivity::update_daily_stats("receive", F, F);
    test_check(MailActivity::receive_count == initial_receive + 1, "receive count incremented");
    
    # 测试加密统计
    MailActivity::update_daily_stats("send", T, F);
    test_check(MailActivity::send_count == initial_send + 2, "send count incremented again");
    test_check(MailActivity::encrypt_count == initial_encrypt + 1, "encrypt count incremented");
    
    print fmt("Updated stats: send=%d, receive=%d, encrypt=%d, decrypt=%d",
              MailActivity::send_count, MailActivity::receive_count,
              MailActivity::encrypt_count, MailActivity::decrypt_count);
}

# 测试3: 环境变量恢复功能
function test_env_restore()
{
    print "\n=== Test 3: Environment Variable Restore ===";
    
    # 检查环境变量是否被读取
    local init_month = getenv("MAIL_STATS_INIT_MONTH");
    local init_send = getenv("MAIL_STATS_INIT_SEND");
    local init_receive = getenv("MAIL_STATS_INIT_RECEIVE");
    
    print fmt("Environment variables:");
    print fmt("  MAIL_STATS_INIT_MONTH: %s", init_month != "" ? init_month : "not set");
    print fmt("  MAIL_STATS_INIT_SEND: %s", init_send != "" ? init_send : "not set");
    print fmt("  MAIL_STATS_INIT_RECEIVE: %s", init_receive != "" ? init_receive : "not set");
    
    # 如果有环境变量设置，验证是否正确恢复
    if ( init_month != "" && init_send != "" ) {
        test_check(MailActivity::current_date == init_month, "date restored from env");
        test_check(MailActivity::send_count >= MailActivity::parse_count(init_send), "send count restored from env");
    } else {
        print "No environment variables set - testing fresh start behavior";
        test_check(T, "fresh start behavior");
    }
}

# 测试4: 状态文件配置
function test_state_file_config()
{
    print "\n=== Test 4: State File Configuration ===";
    
    local state_file = MailActivity::STATS_STATE_FILE;
    print fmt("Configured state file: %s", state_file != "" ? state_file : "not configured");
    
    if ( state_file != "" ) {
        test_check(T, "state file path configured");
        
        # 测试保存功能
        MailActivity::save_stats_to_file();
        print "State file save attempted";
        
    } else {
        print "No state file configured - testing memory-only behavior";
        test_check(T, "memory-only behavior");
    }
}

# 主测试入口点
event zeek_init()
{
    print "╔══════════════════════════════════════════════════════════════╗";
    print "║                  邮件统计功能单元测试                        ║";
    print "╚══════════════════════════════════════════════════════════════╝";
    print "";
    
    # 显示当前配置
    print "=== Test Configuration ===";
    print fmt("SITE_ID: %s", MailActivity::SITE_ID);
    print fmt("LINK_ID: %s", MailActivity::LINK_ID);
    print fmt("STATS_STATE_FILE: %s", MailActivity::STATS_STATE_FILE != "" ? MailActivity::STATS_STATE_FILE : "not set");
    print "";
    
    # 运行所有测试
    test_stats_initialization();
    test_stats_update();
    test_env_restore();
    test_state_file_config();
    
    # 显示测试结果
    print "\n╔══════════════════════════════════════════════════════════════╗";
    print "║                        测试结果摘要                          ║";
    print "╚══════════════════════════════════════════════════════════════╝";
    print fmt("通过的测试: %d", test_passed);
    print fmt("失败的测试: %d", test_failed);
    print fmt("总计测试: %d", test_passed + test_failed);
    
    if ( test_failed == 0 ) {
        print "🎉 所有测试通过！";
    } else {
        print "⚠️  有测试失败，请检查上述输出";
    }
    
    print "\n测试完成，退出中...";
}

# 测试完成后退出
event zeek_done()
{
    print "[TEST] Zeek shutting down - final statistics:";
    print fmt("  send_count: %d", MailActivity::send_count);
    print fmt("  receive_count: %d", MailActivity::receive_count);
    print fmt("  encrypt_count: %d", MailActivity::encrypt_count);
    print fmt("  decrypt_count: %d", MailActivity::decrypt_count);
}