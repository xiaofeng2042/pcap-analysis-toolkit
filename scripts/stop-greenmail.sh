#!/bin/bash

# GreenMail 邮件服务器停止脚本

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
GREENMAIL_DIR="$PROJECT_ROOT/docker/greenmail"

echo "=== 停止 GreenMail 邮件服务器 ==="

# 进入 GreenMail 目录
cd "$GREENMAIL_DIR" || {
    echo "错误: 无法进入目录 $GREENMAIL_DIR"
    exit 1
}

# 停止服务
echo "停止 GreenMail 容器..."
docker-compose down

echo "✅ GreenMail 服务已停止"

# 可选：清理数据卷（取消注释以启用）
# echo "清理数据卷..."
# docker-compose down -v