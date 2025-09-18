#!/usr/bin/env bash
# Run Zeek against the bundled sample pcaps and collect JSON logs.

set -euo pipefail

ROOT_DIR=$(cd "$(dirname "$0")/.." && pwd)
OUTPUT_DIR=${1:-"$ROOT_DIR/output/offline"}
SCRIPT="$ROOT_DIR/zeek-scripts/mail-activity-json.zeek"

mkdir -p "$OUTPUT_DIR"

run_sample() {
  local name=$1
  local pcap="$ROOT_DIR/pcaps/${name}.pcap"
  local out_dir="$OUTPUT_DIR/$name"

  if [[ ! -f "$pcap" ]]; then
    echo "[!] Missing pcap: $pcap" >&2
    return 1
  fi

  rm -rf "$out_dir"
  mkdir -p "$out_dir"
  echo "[*] Processing $name -> $out_dir"
  (cd "$out_dir" && zeek -Cr "$pcap" "$SCRIPT")
  echo "    view: jq '.' '$out_dir/mail_activity.log' | head"
}

run_sample "smtp-send"
run_sample "pop3-receive"

echo "\nDone. Logs written under $OUTPUT_DIR/<sample>/mail_activity.log"
