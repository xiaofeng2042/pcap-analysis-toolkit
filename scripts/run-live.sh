#!/usr/bin/env bash
# Start a live Zeek capture for SMTP/POP3 traffic with JSON logging.

set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: sudo $0 <interface> [output-dir]" >&2
  exit 1
fi

IFACE=$1
ROOT_DIR=$(cd "$(dirname "$0")/.." && pwd)
OUTPUT_DIR=${2:-"$ROOT_DIR/output/live-$(date +%Y%m%d-%H%M%S)"}
SCRIPT="$ROOT_DIR/zeek-scripts/mail-activity-json.zeek"
FILTER=${FILTER:-"port 25 or port 465 or port 587 or port 110 or port 995 or port 1025 or port 1110 or port 3025 or port 3110"}

mkdir -p "$OUTPUT_DIR"

echo "[*] Writing logs to $OUTPUT_DIR"
echo "[*] Capture filter: $FILTER"
echo "[*] Starting Zeek on interface $IFACE (Ctrl-C to stop)"

cd "$OUTPUT_DIR"
zeek -C -i "$IFACE" -f "$FILTER" "$SCRIPT"
