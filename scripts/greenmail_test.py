#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import ssl
import socket
import time
import uuid
from dataclasses import dataclass
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
import smtplib
import imaplib
import poplib

DEFAULT_TIMEOUT = 10
POLL_INTERVAL = 0.5
POLL_TIMEOUT = 20  # 等待服务器“投递到 INBOX”的最长轮询秒数

@dataclass
class Ports:
    smtp: int = 3025
    smtps: int = 3465
    imap: int = 3143
    imaps: int = 3993
    pop3: int = 3110
    pop3s: int = 3995
    webui: int = 8280  # 仅提示用途

def wait_port(host: str, port: int, timeout: int = DEFAULT_TIMEOUT):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            with socket.create_connection((host, port), timeout=1):
                return
        except OSError:
            time.sleep(0.2)
    raise TimeoutError(f"等待 {host}:{port} 开放端口超时")

def build_message(sender: str, rcpt: str, subject: str, body: str):
    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = rcpt
    msg["Date"] = formatdate(localtime=True)
    msg["Subject"] = subject
    msg["Message-ID"] = make_msgid(domain="test.local")
    msg.set_content(body)
    # 附件示例（选用）：小文本
    msg.add_attachment("hello greenmail\n".encode("utf-8"),
                       maintype="text", subtype="plain", filename="note.txt")
    return msg

def smtp_send_starttls(host, port, sender, rcpt, msg, starttls_hostname=None):
    print(f"[SMTP:STARTTLS] 连接 {host}:{port}")
    with smtplib.SMTP(host=host, port=port, timeout=DEFAULT_TIMEOUT) as s:
        s.ehlo_or_helo_if_needed()
        features = getattr(s, "esmtp_features", {})
        if "starttls" in features:
            ctx = ssl.create_default_context()
            # GreenMail 使用自签证书时可放宽校验（仅测试环境）
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s.starttls(context=ctx)
            s.ehlo()
            print("[SMTP:STARTTLS] 已升级为 TLS")
        else:
            print("[SMTP:STARTTLS] 服务器未提供 STARTTLS，按明文发送（仅测试）")
        s.send_message(msg, from_addr=sender, to_addrs=[rcpt])
        print("[SMTP:STARTTLS] 已发送")

def smtp_send_ssl(host, port, sender, rcpt, msg):
    print(f"[SMTPS] 连接 {host}:{port}")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with smtplib.SMTP_SSL(host=host, port=port, context=ctx, timeout=DEFAULT_TIMEOUT) as s:
        s.send_message(msg, from_addr=sender, to_addrs=[rcpt])
        print("[SMTPS] 已发送")

def imap_fetch_latest(host, port, user, password, use_ssl):
    print(f"[IMAP{'S' if use_ssl else ''}] 连接 {host}:{port}")
    if use_ssl:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        imap = imaplib.IMAP4_SSL(host=host, port=port, ssl_context=ctx, timeout=DEFAULT_TIMEOUT)
    else:
        imap = imaplib.IMAP4(host=host, port=port, timeout=DEFAULT_TIMEOUT)

    try:
        # GreenMail 在禁用认证时，任意凭据都会被接受
        typ, _ = imap.login(user, password)
        if typ != "OK":
            raise RuntimeError("IMAP 登录失败")

        # 轮询等待邮件进入 INBOX
        deadline = time.time() + POLL_TIMEOUT
        while True:
            imap.select("INBOX", readonly=True)
            typ, data = imap.search(None, "ALL")
            ids = data[0].split() if data and data[0] else []
            if ids:
                last_id = ids[-1]
                typ, msg_data = imap.fetch(last_id, "(RFC822)")
                raw = msg_data[0][1] if msg_data and msg_data[0] else b""
                return raw.decode("utf-8", errors="replace")
            if time.time() > deadline:
                raise TimeoutError("IMAP 轮询等待邮件超时")
            time.sleep(POLL_INTERVAL)
    finally:
        try:
            imap.logout()
        except Exception:
            pass

def pop3_fetch_latest(host, port, user, password, use_ssl):
    print(f"[POP3{'S' if use_ssl else ''}] 连接 {host}:{port}")
    if use_ssl:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        pop = poplib.POP3_SSL(host=host, port=port, context=ctx, timeout=DEFAULT_TIMEOUT)
    else:
        pop = poplib.POP3(host=host, port=port, timeout=DEFAULT_TIMEOUT)

    try:
        pop.user(user)
        pop.pass_(password)

        # 轮询等待
        deadline = time.time() + POLL_TIMEOUT
        while True:
            num, _ = pop.stat()
            if num > 0:
                resp, lines, octets = pop.retr(num)  # 取最后一封
                raw = b"\n".join(lines)
                return raw.decode("utf-8", errors="replace")
            if time.time() > deadline:
                raise TimeoutError("POP3 轮询等待邮件超时")
            time.sleep(POLL_INTERVAL)
    finally:
        try:
            pop.quit()
        except Exception:
            pass

def assert_contains(text: str, needle: str, label: str):
    if needle not in text:
        raise AssertionError(f"缺少 {label}: {needle!r}")
    print(f"[ASSERT] 包含 {label}: {needle!r}")

def main():
    parser = argparse.ArgumentParser(description="GreenMail end-to-end tester (SMTP/POP3/IMAP incl. TLS)")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--user", default="demo")
    parser.add_argument("--password", default="demo")
    parser.add_argument("--sender", default="sender@test.local")
    parser.add_argument("--rcpt", required=True, help="收件人（例如 demo@localhost.local）")
    parser.add_argument("--modes", default="all",
                        help="逗号分隔：smtp,smtps,imap,imaps,pop3,pop3s 或 all")
    parser.add_argument("--smtp-port", type=int, default=Ports.smtp)
    parser.add_argument("--smtps-port", type=int, default=Ports.smtps)
    parser.add_argument("--imap-port", type=int, default=Ports.imap)
    parser.add_argument("--imaps-port", type=int, default=Ports.imaps)
    parser.add_argument("--pop3-port", type=int, default=Ports.pop3)
    parser.add_argument("--pop3s-port", type=int, default=Ports.pop3s)
    args = parser.parse_args()

    # 等待端口就绪（你也可以只等待会用到的端口）
    to_wait = {
        "smtp": args.smtp_port,
        "smtps": args.smtps_port,
        "imap": args.imap_port,
        "imaps": args.imaps_port,
        "pop3": args.pop3_port,
        "pop3s": args.pop3s_port,
    }
    modes = [m.strip().lower() for m in (args.modes.split(",") if args.modes != "all" else to_wait.keys())]

    for m in modes:
        wait_port(args.host, to_wait[m])

    # 为不同通道生成不同主题，便于区分
    stamp = uuid.uuid4().hex[:8]
    subjects = {
        "smtp":  f"[SMTP-STARTTLS] test-{stamp}",
        "smtps": f"[SMTPS] test-{stamp}",
    }

    # 发送（尽量两封：STARTTLS 和 SMTPS）
    if "smtp" in modes:
        msg = build_message(args.sender, args.rcpt, subjects["smtp"],
                            "Hello via SMTP (STARTTLS if available).")
        smtp_send_starttls(args.host, args.smtp_port, args.sender, args.rcpt, msg)

    if "smtps" in modes:
        msg = build_message(args.sender, args.rcpt, subjects["smtps"],
                            "Hello via SMTPS (implicit TLS).")
        smtp_send_ssl(args.host, args.smtps_port, args.sender, args.rcpt, msg)

    # 通过 IMAP/POP3（明文或 TLS）各取一封（取最新一封），并断言包含关键信息
    # 你可以按需只跑其中某些协议
    if "imaps" in modes:
        raw = imap_fetch_latest(args.host, args.imaps_port, args.user, args.password, use_ssl=True)
        # 断言：至少有一个我们刚发的主题
        ok = any(s in raw for s in subjects.values() if s)
        if not ok:
            raise AssertionError("IMAPS 未检索到刚发送的邮件")
        print("[IMAPS] 检索并通过断言 ✅")

    if "imap" in modes:
        raw = imap_fetch_latest(args.host, args.imap_port, args.user, args.password, use_ssl=False)
        ok = any(s in raw for s in subjects.values() if s)
        if not ok:
            raise AssertionError("IMAP 未检索到刚发送的邮件")
        print("[IMAP] 检索并通过断言 ✅")

    if "pop3s" in modes:
        raw = pop3_fetch_latest(args.host, args.pop3s_port, args.user, args.password, use_ssl=True)
        ok = any(s in raw for s in subjects.values() if s)
        if not ok:
            raise AssertionError("POP3S 未检索到刚发送的邮件")
        print("[POP3S] 检索并通过断言 ✅")

    if "pop3" in modes:
        raw = pop3_fetch_latest(args.host, args.pop3_port, args.user, args.password, use_ssl=False)
        ok = any(s in raw for s in subjects.values() if s)
        if not ok:
            raise AssertionError("POP3 未检索到刚发送的邮件")
        print("[POP3] 检索并通过断言 ✅")

    print("\n🎉 全部选定的协议测试完成！")

if __name__ == "__main__":
    main()
