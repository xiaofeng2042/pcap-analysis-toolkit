#!/bin/bash

# 停止收信监控系统

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
LATEST_LOGS="$PROJECT_ROOT/logs/latest-inbound"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "=== 停止收信监控系统 ==="

# 停止 Zeek
if [ -L "$LATEST_LOGS" ] && [ -f "$LATEST_LOGS/zeek.pid" ]; then
    ZEEK_PID=$(cat "$LATEST_LOGS/zeek.pid")
    if kill -0 $ZEEK_PID 2>/dev/null; then
        echo "停止 Zeek 监控 (PID: $ZEEK_PID)..."
        kill $ZEEK_PID
        sleep 2
        if kill -0 $ZEEK_PID 2>/dev/null; then
            kill -9 $ZEEK_PID
        fi
        echo -e "${GREEN}✅ Zeek 监控已停止${NC}"
    else
        echo -e "${YELLOW}Zeek 监控未运行${NC}"
    fi
    rm -f "$LATEST_LOGS/zeek.pid"
else
    echo -e "${YELLOW}未找到 Zeek PID 文件${NC}"
fi

# 停止 GreenMail
echo "停止 GreenMail 服务..."
cd "$PROJECT_ROOT" || exit 1
./scripts/stop-greenmail.sh

echo -e "${GREEN}=== 收信监控系统已停止 ===${NC}"
