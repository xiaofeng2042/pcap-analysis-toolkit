#!/bin/bash

# GreenMail 邮件服务器启动脚本
# 提供 SMTP、POP3、IMAP 服务用于收信测试

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
GREENMAIL_DIR="$PROJECT_ROOT/docker/greenmail"

echo "=== 启动 GreenMail 邮件服务器 ==="

# 检查 Docker 是否运行
if ! docker info >/dev/null 2>&1; then
    echo "错误: Docker 未运行，请先启动 Docker"
    exit 1
fi

# 进入 GreenMail 目录
cd "$GREENMAIL_DIR" || {
    echo "错误: 无法进入目录 $GREENMAIL_DIR"
    exit 1
}

# 启动 GreenMail 服务
echo "启动 GreenMail 容器..."
docker-compose up -d

# 等待服务启动
echo "等待服务启动..."
sleep 5

# 检查容器状态
if docker-compose ps | grep -q "Up"; then
    echo ""
    echo "✅ GreenMail 服务已成功启动！"
    echo ""
    echo "服务端口："
    echo "  SMTP (非加密):  localhost:3025"
    echo "  POP3:          localhost:3110"
    echo "  IMAP:          localhost:3143"
    echo "  SMTPS (SSL):   localhost:3465"
    echo "  IMAPS (SSL):   localhost:3993"
    echo "  POP3S (SSL):   localhost:3995"
    echo ""
    echo "测试账号："
    echo "  用户名: test@local"
    echo "  密码:   secret"
    echo ""
    echo "  用户名: admin@local"
    echo "  密码:   admin123"
    echo ""
    echo "使用 './stop-greenmail.sh' 停止服务"
else
    echo "❌ GreenMail 服务启动失败"
    echo "查看日志："
    docker-compose logs
    exit 1
fi