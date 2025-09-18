#!/bin/bash
echo "🛑 停止邮件监控..."
sudo pkill -f "zeek.*enhanced-mail-monitor"
echo "✅ 监控已停止"
