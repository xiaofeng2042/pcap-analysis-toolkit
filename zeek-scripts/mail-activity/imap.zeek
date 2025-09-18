# imap.zeek - IMAP协议处理模块
# 通过TCP内容分析实现IMAP协议的业务逻辑记录

module MailActivity;

# IMAP会话状态
type ImapSessionData: record {
    user: string &optional;                      # 用户名
    authenticated: bool &default=F;              # 是否已认证
    selected_mailbox: string &optional;          # 当前选中的邮箱
    mailbox_messages: count &default=0;          # 邮箱中的邮件数量
    mailbox_recent: count &default=0;            # 最近的邮件数量
    mailbox_unseen: count &default=0;            # 未读邮件数量
    capability_list: vector of string &optional; # 服务器能力列表
    command_tag: string &optional;               # 当前命令标签
    pending_command: string &optional;           # 待响应的命令
    fetch_count: count &default=0;               # FETCH操作计数
    search_count: count &default=0;              # SEARCH操作计数
};

# IMAP会话数据表
global imap_session_data: table[string] of ImapSessionData;

# 检查是否为IMAP连接
function is_imap_connection(c: connection): bool
{
    return (c$id$resp_p in IMAP_PORTS || c$uid in imap_sessions);
}

# 解析IMAP命令标签
function parse_imap_tag(line: string): string
{
    local parts = split_string(line, / /);
    if (|parts| > 0) {
        return parts[0];
    }
    return "";
}

# 解析IMAP命令
function parse_imap_command(line: string): string
{
    local parts = split_string(line, / /);
    if (|parts| > 1) {
        return to_upper(parts[1]);
    }
    return "";
}

# 处理IMAP客户端命令
function handle_imap_client_command(c: connection, line: string)
{
    local uid = c$uid;
    
    # 初始化会话数据
    if (uid !in imap_session_data) {
        imap_session_data[uid] = [$authenticated=F];
    }
    
    local session_data = imap_session_data[uid];
    local tag = parse_imap_tag(line);
    local command = parse_imap_command(line);
    
    # 更新会话状态
    session_data$command_tag = tag;
    session_data$pending_command = command;
    
    # 创建命令记录
    local info = create_base_info(c);
    info$protocol = "IMAP";
    info$role = "client";
    info$activity = fmt("IMAP_%s", command);
    info$detail = sanitize_login_info(line);
    info$mailbox_host = fmt("%s", c$id$resp_h);
    
    # 处理不同的IMAP命令
    if (command == "LOGIN") {
        info$activity = "IMAP_LOGIN";
        info$detail = sanitize_login_info(line);
        # 从登录命令中提取用户名（第3个参数）
        local login_parts = split_string(line, / /);
        if (|login_parts| >= 3) {
            session_data$user = login_parts[2];
            info$mailbox_user = session_data$user;
        }
        print fmt("[IMAP] Login attempt for user: %s", 
                  session_data?$user ? session_data$user : "unknown");
        
    } else if (command == "AUTHENTICATE") {
        info$activity = "IMAP_AUTHENTICATE";
        info$detail = "SASL authentication";
        print fmt("[IMAP] SASL authentication attempt");
        
    } else if (command == "CAPABILITY") {
        info$activity = "IMAP_CAPABILITY";
        info$detail = "Request server capabilities";
        print fmt("[IMAP] CAPABILITY request");
        
    } else if (command == "SELECT") {
        info$activity = "IMAP_SELECT";
        local select_parts = split_string(line, / /);
        if (|select_parts| >= 3) {
            local select_mailbox = select_parts[2];
            session_data$selected_mailbox = select_mailbox;
            info$detail = fmt("Select mailbox: %s", select_mailbox);
            print fmt("[IMAP] SELECT mailbox: %s", select_mailbox);
        }
        
    } else if (command == "EXAMINE") {
        info$activity = "IMAP_EXAMINE";
        local examine_parts = split_string(line, / /);
        if (|examine_parts| >= 3) {
            local examine_mailbox = examine_parts[2];
            info$detail = fmt("Examine mailbox: %s", examine_mailbox);
            print fmt("[IMAP] EXAMINE mailbox: %s", examine_mailbox);
        }
        
    } else if (command == "FETCH") {
        info$activity = "IMAP_FETCH";
        info$action = "RETRIEVE";
        ++session_data$fetch_count;
        # 解析FETCH参数
        local fetch_args = sub(line, /^[^ ]+ +FETCH +/, "");
        info$detail = fmt("Fetch messages: %s", fetch_args);
        print fmt("[IMAP] FETCH command: %s", fetch_args);
        
    } else if (command == "SEARCH") {
        info$activity = "IMAP_SEARCH";
        ++session_data$search_count;
        local search_args = sub(line, /^[^ ]+ +SEARCH +/, "");
        info$detail = fmt("Search messages: %s", search_args);
        print fmt("[IMAP] SEARCH command: %s", search_args);
        
    } else if (command == "STORE") {
        info$activity = "IMAP_STORE";
        local store_args = sub(line, /^[^ ]+ +STORE +/, "");
        info$detail = fmt("Store flags: %s", store_args);
        print fmt("[IMAP] STORE command: %s", store_args);
        
    } else if (command == "COPY") {
        info$activity = "IMAP_COPY";
        local copy_args = sub(line, /^[^ ]+ +COPY +/, "");
        info$detail = fmt("Copy messages: %s", copy_args);
        print fmt("[IMAP] COPY command: %s", copy_args);
        
    } else if (command == "MOVE") {
        info$activity = "IMAP_MOVE";
        local move_args = sub(line, /^[^ ]+ +MOVE +/, "");
        info$detail = fmt("Move messages: %s", move_args);
        print fmt("[IMAP] MOVE command: %s", move_args);
        
    } else if (command == "EXPUNGE") {
        info$activity = "IMAP_EXPUNGE";
        info$detail = "Expunge deleted messages";
        print fmt("[IMAP] EXPUNGE command");
        
    } else if (command == "CLOSE") {
        info$activity = "IMAP_CLOSE";
        info$detail = "Close current mailbox";
        session_data$selected_mailbox = "";
        print fmt("[IMAP] CLOSE command");
        
    } else if (command == "LOGOUT") {
        info$activity = "IMAP_LOGOUT";
        info$detail = "Logout from server";
        print fmt("[IMAP] LOGOUT command");
        
    } else if (command == "STARTTLS") {
        info$activity = "IMAP_STARTTLS";
        info$detail = "Start TLS encryption";
        ++starttls_attempts;
        print fmt("[IMAP] STARTTLS command");
        
    } else if (command == "NOOP") {
        info$activity = "IMAP_NOOP";
        info$detail = "No operation";
        print fmt("[IMAP] NOOP command");
        
    } else if (command == "LIST") {
        info$activity = "IMAP_LIST";
        local list_args = sub(line, /^[^ ]+ +LIST +/, "");
        info$detail = fmt("List mailboxes: %s", list_args);
        print fmt("[IMAP] LIST command: %s", list_args);
        
    } else if (command == "LSUB") {
        info$activity = "IMAP_LSUB";
        local lsub_args = sub(line, /^[^ ]+ +LSUB +/, "");
        info$detail = fmt("List subscribed mailboxes: %s", lsub_args);
        print fmt("[IMAP] LSUB command: %s", lsub_args);
        
    } else if (command == "CREATE") {
        info$activity = "IMAP_CREATE";
        local create_args = sub(line, /^[^ ]+ +CREATE +/, "");
        info$detail = fmt("Create mailbox: %s", create_args);
        print fmt("[IMAP] CREATE command: %s", create_args);
        
    } else if (command == "DELETE") {
        info$activity = "IMAP_DELETE";
        local delete_args = sub(line, /^[^ ]+ +DELETE +/, "");
        info$detail = fmt("Delete mailbox: %s", delete_args);
        print fmt("[IMAP] DELETE command: %s", delete_args);
        
    } else if (command == "SUBSCRIBE") {
        info$activity = "IMAP_SUBSCRIBE";
        local sub_args = sub(line, /^[^ ]+ +SUBSCRIBE +/, "");
        info$detail = fmt("Subscribe to mailbox: %s", sub_args);
        print fmt("[IMAP] SUBSCRIBE command: %s", sub_args);
        
    } else if (command == "UNSUBSCRIBE") {
        info$activity = "IMAP_UNSUBSCRIBE";
        local unsub_args = sub(line, /^[^ ]+ +UNSUBSCRIBE +/, "");
        info$detail = fmt("Unsubscribe from mailbox: %s", unsub_args);
        print fmt("[IMAP] UNSUBSCRIBE command: %s", unsub_args);
        
    } else {
        info$activity = "IMAP_OTHER";
        info$detail = fmt("Other command: %s", command);
        print fmt("[IMAP] Other command: %s", command);
    }
    
    # 添加会话信息
    if (session_data?$user) {
        info$mailbox_user = session_data$user;
    }
    if (session_data?$selected_mailbox && session_data$selected_mailbox != "") {
        info$detail = fmt("%s (Mailbox: %s)", info$detail, session_data$selected_mailbox);
    }
    
    # 存储会话信息并记录日志
    imap_sessions[uid] = info;
    imap_session_data[uid] = session_data;
    Log::write(LOG, info);
}

# 处理IMAP服务器响应
function handle_imap_server_response(c: connection, line: string)
{
    local uid = c$uid;
    
    # 创建响应记录
    local info = create_base_info(c);
    info$protocol = "IMAP";
    info$role = "server";
    info$activity = "IMAP_RESPONSE";
    info$detail = line;
    
    # 获取会话数据
    local session_data: ImapSessionData;
    if (uid in imap_session_data) {
        session_data = imap_session_data[uid];
    } else {
        session_data = [$authenticated=F];
    }
    
    # 解析不同类型的响应
    if (/^\* OK/ in line) {
        info$status = "OK";
        info$activity = "IMAP_SERVER_READY";
        print fmt("[IMAP] Server ready: %s", line);
        
    } else if (/^\* BYE/ in line) {
        info$status = "BYE";
        info$activity = "IMAP_SERVER_BYE";
        print fmt("[IMAP] Server goodbye: %s", line);
        
    } else if (/^\* \d+ EXISTS/ in line) {
        info$activity = "IMAP_EXISTS";
        # 简化处理：从EXISTS响应中提取数字
        local exists_line = sub(line, /^\* /, "");
        local exists_parts = split_string(exists_line, / /);
        if (|exists_parts| >= 1) {
            session_data$mailbox_messages = to_count(exists_parts[0]);
            info$detail = fmt("Mailbox contains %d messages", session_data$mailbox_messages);
        }
        print fmt("[IMAP] Mailbox exists: %s", line);
        
    } else if (/^\* \d+ RECENT/ in line) {
        info$activity = "IMAP_RECENT";
        # 简化处理：从RECENT响应中提取数字
        local recent_line = sub(line, /^\* /, "");
        local recent_parts = split_string(recent_line, / /);
        if (|recent_parts| >= 1) {
            session_data$mailbox_recent = to_count(recent_parts[0]);
            info$detail = fmt("Mailbox has %d recent messages", session_data$mailbox_recent);
        }
        print fmt("[IMAP] Recent messages: %s", line);
        
    } else if (/^\* FLAGS/ in line) {
        info$activity = "IMAP_FLAGS";
        print fmt("[IMAP] Flags: %s", line);
        
    } else if (/^\* CAPABILITY/ in line) {
        info$activity = "IMAP_CAPABILITY_RESPONSE";
        # 解析能力列表
        local cap_line = sub(line, /^\* CAPABILITY /, "");
        local capabilities = split_string(cap_line, / /);
        session_data$capability_list = capabilities;
        print fmt("[IMAP] Capabilities: %s", cap_line);
        
    } else if (/^[A-Za-z0-9]+ OK/ in line) {
        info$status = "OK";
        info$activity = "IMAP_COMMAND_OK";
        
        # 检查是否是LOGIN响应
        if (session_data?$pending_command && session_data$pending_command == "LOGIN") {
            session_data$authenticated = T;
            info$detail = fmt("Login successful for user: %s", 
                             session_data?$user ? session_data$user : "unknown");
        }
        print fmt("[OK] IMAP command success: %s", line);
        
    } else if (/^[A-Za-z0-9]+ NO/ in line) {
        info$status = "NO";
        info$activity = "IMAP_COMMAND_NO";
        print fmt("[ERROR] IMAP command failed: %s", line);
        
    } else if (/^[A-Za-z0-9]+ BAD/ in line) {
        info$status = "BAD";
        info$activity = "IMAP_COMMAND_BAD";
        print fmt("[ERROR] IMAP bad command: %s", line);
        
    } else if (/^\* \d+ FETCH/ in line) {
        info$activity = "IMAP_FETCH_RESPONSE";
        print fmt("[IMAP] Fetch response: %s", line);
        
    } else if (/^\* SEARCH/ in line) {
        info$activity = "IMAP_SEARCH_RESPONSE";
        local search_line = sub(line, /^\* SEARCH /, "");
        local search_results = split_string(search_line, / /);
        info$detail = fmt("Search found %d results", |search_results|);
        print fmt("[IMAP] Search response: %d results", |search_results|);
        
    } else {
        info$activity = "IMAP_SERVER_DATA";
        print fmt("[IMAP] Server data: %s", line);
    }
    
    # 添加会话信息
    if (session_data?$user) {
        info$mailbox_user = session_data$user;
    }
    if (session_data?$selected_mailbox && session_data$selected_mailbox != "") {
        info$detail = fmt("%s (Mailbox: %s)", info$detail, session_data$selected_mailbox);
    }
    
    # 清除待处理命令
    if (/^[A-Za-z0-9]+ (OK|NO|BAD)/ in line) {
        delete session_data$pending_command;
    }
    
    # 更新会话数据并记录日志
    imap_session_data[uid] = session_data;
    Log::write(LOG, info);
}

# TCP内容事件处理 - IMAP协议分析
event tcp_contents(c: connection, is_orig: bool, seq: count, contents: string)
{
    # 只处理IMAP连接
    if (!is_imap_connection(c))
        return;
    
    local uid = c$uid;
    
    # 分行处理内容
    local lines = split_string(contents, /\r?\n/);
    
    for (i in lines) {
        local line = lines[i];
        
        # 跳过空行
        if (|line| == 0)
            next;
        
        # 根据数据方向处理
        if (is_orig) {
            # 客户端到服务器的数据
            handle_imap_client_command(c, line);
        } else {
            # 服务器到客户端的数据
            handle_imap_server_response(c, line);
        }
    }
    
    # 创建或更新会话记录
    if (uid !in imap_sessions) {
        local session_info = create_base_info(c);
        session_info$protocol = "IMAP";
        session_info$role = "session";
        session_info$activity = "IMAP_SESSION_START";
        imap_sessions[uid] = session_info;
    }
}