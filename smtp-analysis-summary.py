#!/usr/bin/env python3
"""
SMTP STARTTLS 流量分析脚本
提供详细的统计分析和可视化输出
"""

import json
import sys
from datetime import datetime
from collections import defaultdict, Counter

def load_json_log(filename):
    """加载JSON格式的Zeek日志文件"""
    try:
        with open(filename, 'r') as f:
            return [json.loads(line.strip()) for line in f if line.strip()]
    except FileNotFoundError:
        print(f"警告: 文件 {filename} 不存在")
        return []
    except json.JSONDecodeError as e:
        print(f"错误: 解析 {filename} 时出错: {e}")
        return []

def format_timestamp(ts):
    """格式化时间戳"""
    try:
        return datetime.fromtimestamp(float(ts)).strftime('%Y-%m-%d %H:%M:%S')
    except:
        return str(ts)

def analyze_smtp_traffic():
    """分析SMTP流量"""
    print("=" * 60)
    print("SMTP STARTTLS 流量分析报告")
    print("=" * 60)
    
    # 加载日志文件
    smtp_logs = load_json_log('smtp.log')
    ssl_logs = load_json_log('ssl.log')
    notice_logs = load_json_log('notice.log')
    conn_logs = load_json_log('conn.log')
    
    # 基础统计
    print(f"\n📊 基础统计:")
    print(f"   SMTP日志条目: {len(smtp_logs)}")
    print(f"   SSL日志条目: {len(ssl_logs)}")
    print(f"   通知日志条目: {len(notice_logs)}")
    print(f"   连接日志条目: {len(conn_logs)}")
    
    # SMTP连接分析
    smtp_connections = {}
    for log in smtp_logs:
        uid = log.get('uid')
        if uid:
            smtp_connections[uid] = {
                'helo': log.get('helo', 'N/A'),
                'tls': log.get('tls', False),
                'last_reply': log.get('last_reply', 'N/A'),
                'timestamp': log.get('ts')
            }
    
    # SSL连接分析
    ssl_connections = {}
    for log in ssl_logs:
        uid = log.get('uid')
        if uid and log.get('id.resp_p') == 2525:
            ssl_connections[uid] = {
                'version': log.get('version', 'N/A'),
                'cipher': log.get('cipher', 'N/A'),
                'established': log.get('established', False),
                'timestamp': log.get('ts')
            }
    
    # STARTTLS事件分析
    starttls_events = defaultdict(list)
    for log in notice_logs:
        uid = log.get('uid')
        note = log.get('note', '')
        if 'STARTTLS' in note:
            starttls_events[uid].append({
                'type': note.split('::')[-1],
                'timestamp': log.get('ts'),
                'message': log.get('msg', '')
            })
    
    print(f"\n🔐 STARTTLS 分析:")
    print(f"   SMTP连接总数: {len(smtp_connections)}")
    print(f"   SSL握手成功: {len(ssl_connections)}")
    print(f"   STARTTLS事件: {len(starttls_events)}")
    
    # 连接类型分类
    encrypted_connections = set(smtp_connections.keys()) & set(ssl_connections.keys())
    plaintext_only = set(smtp_connections.keys()) - set(ssl_connections.keys())
    
    print(f"\n📈 连接类型统计:")
    print(f"   加密连接 (STARTTLS成功): {len(encrypted_connections)}")
    print(f"   纯明文连接: {len(plaintext_only)}")
    
    # 详细连接信息
    print(f"\n📋 详细连接信息:")
    for uid in smtp_connections:
        smtp_info = smtp_connections[uid]
        ssl_info = ssl_connections.get(uid, {})
        events = starttls_events.get(uid, [])
        
        print(f"\n   连接 {uid}:")
        print(f"     时间: {format_timestamp(smtp_info['timestamp'])}")
        print(f"     HELO: {smtp_info['helo']}")
        print(f"     最后回复: {smtp_info['last_reply']}")
        print(f"     TLS标记: {smtp_info['tls']}")
        
        if ssl_info:
            print(f"     TLS版本: {ssl_info['version']}")
            print(f"     密码套件: {ssl_info['cipher']}")
            print(f"     握手状态: {'成功' if ssl_info['established'] else '失败'}")
        
        if events:
            print(f"     STARTTLS事件:")
            for event in events:
                print(f"       - {event['type']}: {event['message']}")
    
    # 时间线分析
    print(f"\n⏰ 时间线分析:")
    timeline = []
    
    for uid, info in smtp_connections.items():
        timeline.append((info['timestamp'], 'SMTP', uid, f"HELO: {info['helo']}"))
    
    for uid, info in ssl_connections.items():
        timeline.append((info['timestamp'], 'TLS', uid, f"{info['version']} - {info['cipher']}"))
    
    for uid, events in starttls_events.items():
        for event in events:
            timeline.append((event['timestamp'], 'STARTTLS', uid, event['message']))
    
    timeline.sort(key=lambda x: float(x[0]) if x[0] else 0)
    
    for ts, event_type, uid, details in timeline:
        print(f"   {format_timestamp(ts)} | {event_type:9} | {uid} | {details}")
    
    # 统计摘要
    print(f"\n📊 统计摘要:")
    print(f"   总体评估: 在 {len(smtp_connections)} 个SMTP连接中")
    if encrypted_connections:
        print(f"   ✅ {len(encrypted_connections)} 个连接成功升级为TLS加密")
    if plaintext_only:
        print(f"   ⚠️  {len(plaintext_only)} 个连接保持明文传输")
    
    # 安全建议
    print(f"\n🔒 安全建议:")
    if len(encrypted_connections) > 0:
        print("   ✅ 检测到STARTTLS正常工作")
        print("   ✅ 邮件传输已加密保护")
    if len(plaintext_only) > 0:
        print("   ⚠️  存在未加密的SMTP连接")
        print("   💡 建议强制要求STARTTLS")
    
    return {
        'total_smtp': len(smtp_connections),
        'encrypted': len(encrypted_connections),
        'plaintext': len(plaintext_only),
        'starttls_events': len(starttls_events)
    }

if __name__ == "__main__":
    try:
        stats = analyze_smtp_traffic()
        print(f"\n" + "=" * 60)
        print("分析完成!")
        print("=" * 60)
    except Exception as e:
        print(f"错误: {e}")
        sys.exit(1)