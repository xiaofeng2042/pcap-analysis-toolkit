#!/usr/bin/env bash
# Start a live Zeek capture for SMTP/POP3/IMAP traffic with JSON logging.
# Supports both native Zeek installation and Docker-based execution.

set -euo pipefail

# Function to show usage
show_usage() {
  echo "Usage: $0 [--docker] <interface> [output-dir]" >&2
  echo "" >&2
  echo "Options:" >&2
  echo "  --docker    Run Zeek in Docker container (requires Docker)" >&2
  echo "" >&2
  echo "Arguments:" >&2
  echo "  interface   Network interface to capture (e.g., eth0, en0)" >&2
  echo "  output-dir  Output directory for logs (optional)" >&2
  echo "" >&2
  echo "Examples:" >&2
  echo "  sudo $0 eth0                    # Native Zeek" >&2
  echo "  sudo $0 --docker eth0           # Docker Zeek" >&2
  echo "  sudo $0 --docker eth0 /tmp/logs # Docker with custom output" >&2
  exit 1
}

# Parse arguments
USE_DOCKER=false
if [[ $# -gt 0 && "$1" == "--docker" ]]; then
  USE_DOCKER=true
  shift
fi

if [[ $# -lt 1 ]]; then
  show_usage
fi

IFACE=$1
ROOT_DIR=$(cd "$(dirname "$0")/.." && pwd)
OUTPUT_DIR=${2:-"$ROOT_DIR/output/live-$(date +%Y%m%d-%H%M%S)"}
STATE_DIR=${STATE_DIR:-"$ROOT_DIR/output/state"}
SCRIPT="$ROOT_DIR/zeek-scripts/mail-activity-json.zeek"

# Load environment variables from .env file if it exists
ENV_FILE="$ROOT_DIR/.env"
if [[ -f "$ENV_FILE" ]]; then
  echo "[INFO] Loading configuration from $ENV_FILE"
  # Export variables from .env file
  set -a  # automatically export all variables
  source "$ENV_FILE"
  set +a  # stop automatically exporting
  echo "[INFO] Configuration loaded: SITE_ID=${SITE_ID:-"not set"}, LINK_ID=${LINK_ID:-"not set"}"
else
  echo "[WARN] No .env file found at $ENV_FILE"
  echo "[WARN] SITE_ID must be set manually or via environment variable"
fi

# Mail protocol ports filter
# SMTP: 25 (standard), 465 (SMTPS), 587 (submission), 1025 (non-standard), 2525 (alternative)
# POP3: 110 (standard), 995 (POP3S)
# IMAP: 143 (standard), 993 (IMAPS)
# GreenMail test ports: 3025 (SMTP), 3110 (POP3), 3143 (IMAP), 3465 (SMTPS), 3993 (IMAPS), 3995 (POP3S)
FILTER=${FILTER:-"port 25 or port 465 or port 587 or port 1025 or port 2525 or port 110 or port 995 or port 143 or port 993 or port 3025 or port 3110 or port 3143 or port 3465 or port 3993 or port 3995"}

mkdir -p "$OUTPUT_DIR" "$STATE_DIR"

# 从状态文件恢复环境变量（如果存在）
STATE_FILE="$STATE_DIR/mail_stats_state.tsv"
if [[ -f "$STATE_FILE" ]]; then
  echo "[INFO] Loading previous stats from $STATE_FILE"
  # 读取状态文件并设置环境变量
  if [[ -s "$STATE_FILE" ]]; then
    STATE_LINE_RAW=$(tail -n 1 "$STATE_FILE")
    STATE_LINE="$STATE_LINE_RAW"

    if [[ "$STATE_LINE" == *\\x09* ]]; then
      echo "[INFO] Normalizing legacy tab encoding in state file"
      STATE_LINE=${STATE_LINE//\\x09/$'\t'}
    fi

    IFS=$'\t' read -r MAIL_STATS_INIT_MONTH SITE_FROM_FILE LINK_FROM_FILE MAIL_STATS_INIT_SEND MAIL_STATS_INIT_RECEIVE MAIL_STATS_INIT_ENCRYPT MAIL_STATS_INIT_DECRYPT <<< "$STATE_LINE"

    export MAIL_STATS_INIT_MONTH
    export MAIL_STATS_INIT_SEND
    export MAIL_STATS_INIT_RECEIVE
    export MAIL_STATS_INIT_ENCRYPT
    export MAIL_STATS_INIT_DECRYPT

    echo "[INFO] Restored stats: month=$MAIL_STATS_INIT_MONTH site=$SITE_FROM_FILE link=$LINK_FROM_FILE send=$MAIL_STATS_INIT_SEND receive=$MAIL_STATS_INIT_RECEIVE encrypt=$MAIL_STATS_INIT_ENCRYPT decrypt=$MAIL_STATS_INIT_DECRYPT"
  fi
else
  echo "[INFO] No previous state file found, starting fresh"
fi

echo "[INFO] Writing logs to $OUTPUT_DIR"
echo "[INFO] Capture filter: $FILTER"

if [[ "$USE_DOCKER" == "true" ]]; then
  echo "[INFO] Starting Zeek in Docker container on interface $IFACE (Ctrl-C to stop)"
  echo "[INFO] Using Docker image: zeek/zeek"
  
  # Check if Docker is available
  if ! command -v docker &> /dev/null; then
    echo "[ERROR] Docker is not installed or not in PATH" >&2
    exit 1
  fi
  
  # Check if Docker daemon is running
  if ! docker info &> /dev/null; then
    echo "[ERROR] Docker daemon is not running" >&2
    exit 1
  fi
  
  # 运行 Docker 容器（使用宿主机网络和必要特权）
  docker run -it --rm \
    --name zeek-mail-monitor \
    --net=host \
    --privileged \
    --cap-add=NET_ADMIN \
    --cap-add=NET_RAW \
    -v "$OUTPUT_DIR:/logs" \
    -v "$STATE_DIR:/state" \
    -v "$ROOT_DIR/zeek-scripts:/scripts" \
    -w /logs \
    -e "SITE_ID=${SITE_ID:-}" \
    -e "LINK_ID=${LINK_ID:-}" \
    -e "LAN_INTERFACE=${LAN_INTERFACE:-eno1}" \
    -e "TUNNEL_INTERFACE=${TUNNEL_INTERFACE:-tap_tap}" \
    -e "REPORT_INTERVAL=${REPORT_INTERVAL:-30}" \
    -e "MAIL_STATS_STATE_FILE=/state/mail_stats_state.tsv" \
    -e "MAIL_STATS_INIT_MONTH=${MAIL_STATS_INIT_MONTH:-}" \
    -e "MAIL_STATS_INIT_SEND=${MAIL_STATS_INIT_SEND:-}" \
    -e "MAIL_STATS_INIT_RECEIVE=${MAIL_STATS_INIT_RECEIVE:-}" \
    -e "MAIL_STATS_INIT_ENCRYPT=${MAIL_STATS_INIT_ENCRYPT:-}" \
    -e "MAIL_STATS_INIT_DECRYPT=${MAIL_STATS_INIT_DECRYPT:-}" \
    zeek/zeek \
    zeek -C -i "$IFACE" -f "$FILTER" /scripts/mail-activity-json.zeek
else
  echo "[INFO] Starting native Zeek on interface $IFACE (Ctrl-C to stop)"
  
  # Check if Zeek is available
  if ! command -v zeek &> /dev/null; then
    echo "[ERROR] Zeek is not installed or not in PATH" >&2
    echo "[INFO] Try using --docker option to run with Docker" >&2
    exit 1
  fi
  
  cd "$OUTPUT_DIR"
  MAIL_STATS_STATE_FILE="$STATE_DIR/mail_stats_state.tsv" \
    zeek -C -i "$IFACE" -f "$FILTER" "$SCRIPT"
fi
