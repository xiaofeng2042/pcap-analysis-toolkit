#!/bin/bash
echo "🛑 停止SMTP监控..."
pkill -f "zeek.*simple-smtp-monitor"
echo "✅ 监控已停止"
