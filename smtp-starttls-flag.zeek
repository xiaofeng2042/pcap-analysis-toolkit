# 文件：smtp-starttls-flag.zeek
# 监控SMTP STARTTLS事件，标记明文到加密的升级过程

@load base/protocols/smtp
@load base/protocols/ssl

module SMTPSTAT;

export {
    redef enum Notice::Type += {
        STARTTLS_Offered,
        STARTTLS_Succeeded
    };
}

event smtp_request(c: connection, is_orig: bool, command: string, arg: string)
{
    if ( to_upper(command) == "STARTTLS" )
        NOTICE([$note=STARTTLS_Offered, $conn=c, $msg="SMTP STARTTLS offered"]);
}

event ssl_established(c: connection)
{
    if ( c$id$resp_p == 25/tcp || c$id$resp_p == 465/tcp ||
         c$id$resp_p == 587/tcp || c$id$resp_p == 2525/tcp )
        NOTICE([$note=STARTTLS_Succeeded, $conn=c, $msg="TLS established on SMTP flow"]);
}