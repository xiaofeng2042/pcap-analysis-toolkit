# 文件：site-mail-ports.zeek
# 注册邮件服务端口（SMTP、IMAP、POP3）包括 GreenMail 和标准端口
# 确保 Zeek 能识别并分析所有邮件协议流量

@load base/frameworks/analyzer

# SMTP 端口（包括标准和非标准端口）
redef likely_server_ports += { 
    # 标准 SMTP 端口
    25/tcp,     # SMTP
    465/tcp,    # SMTPS (SSL)
    587/tcp,    # SMTP (STARTTLS)
    
    # 非标准 SMTP 端口
    2525/tcp,   # 常用替代端口
    1025/tcp,   # MailHog
    3025/tcp,   # GreenMail SMTP
    3465/tcp,   # GreenMail SMTPS
    
    # IMAP 端口
    143/tcp,    # IMAP
    993/tcp,    # IMAPS (SSL)
    3143/tcp,   # GreenMail IMAP
    3993/tcp,   # GreenMail IMAPS
    
    # POP3 端口
    110/tcp,    # POP3
    995/tcp,    # POP3S (SSL)
    3110/tcp,   # GreenMail POP3
    3995/tcp    # GreenMail POP3S
};

event zeek_init()
{
    # 注册 SMTP 分析器
    Analyzer::register_for_ports(Analyzer::ANALYZER_SMTP, set(
        25/tcp, 465/tcp, 587/tcp,      # 标准端口
        2525/tcp, 1025/tcp,            # 非标准端口
        3025/tcp, 3465/tcp             # GreenMail SMTP
    ));
    
    # 注册 IMAP 分析器
    Analyzer::register_for_ports(Analyzer::ANALYZER_IMAP, set(
        143/tcp, 993/tcp,              # 标准端口
        3143/tcp, 3993/tcp             # GreenMail IMAP
    ));
    
    # 注册 POP3 分析器
    Analyzer::register_for_ports(Analyzer::ANALYZER_POP3, set(
        110/tcp, 995/tcp,              # 标准端口
        3110/tcp, 3995/tcp             # GreenMail POP3
    ));
    
    print "邮件端口分析器已注册：";
    print "  SMTP: 25, 465, 587, 2525, 1025, 3025, 3465";
    print "  IMAP: 143, 993, 3143, 3993";
    print "  POP3: 110, 995, 3110, 3995";
}