@load base/protocols/smtp

# 注册SMTP分析器到端口3025
event zeek_init()
{
    Analyzer::register_for_ports(Analyzer::ANALYZER_SMTP, set(3025/tcp));
}

event smtp_request(c: connection, is_orig: bool, command: string, arg: string)
{
    print fmt("[SMTP_REQUEST] %s:%d -> %s:%d CMD: %s ARG: %s", 
              c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p, command, arg);
}

event smtp_reply(c: connection, is_orig: bool, code: count, cmd: string, msg: string, cont_resp: bool)
{
    print fmt("[SMTP_REPLY] %s:%d -> %s:%d CODE: %d CMD: %s MSG: %s", 
              c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p, code, cmd, msg);
}

event new_connection(c: connection)
{
    if (c$id$resp_p == 3025/tcp) {
        print fmt("[NEW_CONNECTION] SMTP connection: %s:%d -> %s:%d", 
                  c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p);
    }
}

event connection_established(c: connection)
{
    if (c$id$resp_p == 3025/tcp) {
        print fmt("[CONNECTION_ESTABLISHED] SMTP connection: %s:%d -> %s:%d", 
                  c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p);
    }
}
