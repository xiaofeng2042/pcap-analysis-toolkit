# 文件：site-smtp-ports.zeek
# 注册非标准端口2525为SMTP，确保Zeek能识别并分析SMTP流量

@load base/frameworks/analyzer

redef likely_server_ports += { 2525/tcp };

event zeek_init()
{
    Analyzer::register_for_ports(Analyzer::ANALYZER_SMTP, set(2525/tcp));
}