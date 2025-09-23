@load zeek-scripts/mail-activity-json.zeek

event zeek_init()
{
    print "=== Testing Daily Statistics Aggregation ===";
    
    # Test monthly aggregation for September 2025
    local sept_stats = MailActivity::get_month_stats("2025-09");
    print fmt("September 2025 totals: send=%d receive=%d encrypt=%d decrypt=%d", 
              sept_stats$send_count, sept_stats$receive_count, 
              sept_stats$encrypt_count, sept_stats$decrypt_count);
    
    # Test date range aggregation  
    local range_stats = MailActivity::get_date_range_stats("2025-09-20", "2025-09-22");
    print fmt("Sept 20-22 range totals: send=%d receive=%d encrypt=%d decrypt=%d",
              range_stats$send_count, range_stats$receive_count,
              range_stats$encrypt_count, range_stats$decrypt_count);
}