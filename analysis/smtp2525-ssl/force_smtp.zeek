@load base/protocols/smtp
@load ../../zeek-json.zeek

event zeek_init() {
    # 添加端口2525作为SMTP端口
    Analyzer::register_for_ports(Analyzer::ANALYZER_SMTP, set(2525/tcp));
}
