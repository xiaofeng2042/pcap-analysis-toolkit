# mail-activity-json.zeek
# Minimal Zeek script to record outbound SMTP send activity and inbound POP3 retrieval events.

@load base/protocols/smtp
@load base/protocols/pop3
@load base/protocols/conn
redef LogAscii::use_json = T;

module MailActivity;

export {
    type Info: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;
        protocol: string &log;
        role: string &log;
        activity: string &log;
        mail_from: string &log &optional;
        rcpt_to: string &log &optional;
        user: string &log &optional;
        status: string &log &optional;
        detail: string &log &optional;
    };

    redef enum Log::ID += { LOG };
}

const SMTP_PORTS: set[port] = {
    25/tcp, 465/tcp, 587/tcp, 2525/tcp, 1025/tcp,
    3025/tcp, 3465/tcp
} &redef;

const POP3_PORTS: set[port] = {
    110/tcp, 995/tcp, 3110/tcp, 3995/tcp
} &redef;

event zeek_init()
{
    Log::create_stream(LOG, [$columns=Info, $path="mail_activity"]);
}

function new_info(c: connection, proto: string, role: string, ev: string): Info
    {
        return [$ts = network_time(),
                $uid = c$uid,
                $id = c$id,
                $protocol = proto,
                $role = role,
                $activity = ev];
    }

event smtp_request(c: connection, is_orig: bool, command: string, arg: string)
{
    if ( ! is_orig )
        return;

    if ( c$id$resp_p !in SMTP_PORTS )
        return;

    local info = new_info(c, "SMTP", "send", fmt("SMTP_%s", command));

    if ( command == "MAIL" )
        info$mail_from = arg;
    else if ( command == "RCPT" )
        info$rcpt_to = arg;
    else
        info$detail = arg;

    Log::write(LOG, info);
}

event smtp_reply(c: connection, is_orig: bool, code: count, cmd: string, msg: string, cont_resp: bool)
{
    if ( is_orig )
        return;

    if ( c$id$resp_p !in SMTP_PORTS )
        return;

    local info = new_info(c, "SMTP", "send", fmt("SMTP_REPLY_%s", cmd));
    info$status = fmt("%d", code);
    info$detail = msg;
    Log::write(LOG, info);
}

event pop3_request(c: connection, is_orig: bool, command: string, arg: string)
{
    if ( ! is_orig )
        return;

    if ( c$id$resp_p !in POP3_PORTS )
        return;

    local info = new_info(c, "POP3", "receive", fmt("POP3_%s", command));

    if ( command == "USER" )
        info$user = arg;
    else if ( command == "RETR" )
        info$detail = fmt("retrieve message %s", arg);
    else if ( command == "LIST" || command == "STAT" )
        info$detail = arg;
    else if ( arg != "" )
        info$detail = arg;

    Log::write(LOG, info);
}

event pop3_reply(c: connection, is_orig: bool, cmd: string, msg: string)
{
    if ( is_orig )
        return;

    if ( c$id$resp_p !in POP3_PORTS )
        return;

    local info = new_info(c, "POP3", "receive", fmt("POP3_REPLY_%s", cmd));
    info$status = "+OK" in msg ? "+OK" : msg;
    if ( msg != "" )
        info$detail = msg;

    Log::write(LOG, info);
}

# Provide a single summary entry when the connection finishes.
event connection_state_remove(c: connection)
{
    local resp_p = c$id$resp_p;

    if ( resp_p in SMTP_PORTS )
    {
        local info = new_info(c, "SMTP", "send", "SMTP_CONNECTION_END");
        info$status = "closed";
        info$detail = fmt("duration %.2fs, size %d/%d", c$duration, c$orig$size, c$resp$size);
        Log::write(LOG, info);
    }
    else if ( resp_p in POP3_PORTS )
    {
        local info2 = new_info(c, "POP3", "receive", "POP3_CONNECTION_END");
        info2$status = "closed";
        info2$detail = fmt("duration %.2fs, size %d/%d", c$duration, c$orig$size, c$resp$size);
        Log::write(LOG, info2);
    }
}
