#!/usr/bin/env bash
# Start a live Zeek capture for SMTP/POP3/IMAP traffic with JSON logging.

set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: sudo $0 <interface> [output-dir]" >&2
  exit 1
fi

IFACE=$1
ROOT_DIR=$(cd "$(dirname "$0")/.." && pwd)
OUTPUT_DIR=${2:-"$ROOT_DIR/output/live-$(date +%Y%m%d-%H%M%S)"}
SCRIPT="$ROOT_DIR/zeek-scripts/mail-activity-json.zeek"

# Mail protocol ports filter
# SMTP: 25 (standard), 465 (SMTPS), 587 (submission), 1025 (non-standard), 2525 (alternative)
# POP3: 110 (standard), 995 (POP3S)
# IMAP: 143 (standard), 993 (IMAPS)
# GreenMail test ports: 3025 (SMTP), 3110 (POP3), 3143 (IMAP), 3465 (SMTPS), 3993 (IMAPS), 3995 (POP3S)
FILTER=${FILTER:-"port 25 or port 465 or port 587 or port 1025 or port 2525 or port 110 or port 995 or port 143 or port 993 or port 3025 or port 3110 or port 3143 or port 3465 or port 3993 or port 3995"}

mkdir -p "$OUTPUT_DIR"

echo "[*] Writing logs to $OUTPUT_DIR"
echo "[*] Capture filter: $FILTER"
echo "[*] Starting Zeek on interface $IFACE (Ctrl-C to stop)"

cd "$OUTPUT_DIR"
zeek -C -i "$IFACE" -f "$FILTER" "$SCRIPT"
