# 文件：site-smtp-ports.zeek
# 注册常见的非标准SMTP端口（如2525、MailHog的1025），确保Zeek能识别并分析SMTP流量

@load base/frameworks/analyzer

redef likely_server_ports += { 2525/tcp, 1025/tcp };

event zeek_init()
{
    Analyzer::register_for_ports(Analyzer::ANALYZER_SMTP, set(2525/tcp, 1025/tcp));
}
