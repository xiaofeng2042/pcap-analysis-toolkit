#!/bin/bash
# cron-daily-rotation.sh - Daily cron job for mail stats rotation
# Add to crontab with: 5 0 * * * /path/to/scripts/cron-daily-rotation.sh

set -euo pipefail

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Configuration
LOG_FILE="${PROJECT_DIR}/output/state/rotation.log"
LOCK_FILE="${PROJECT_DIR}/output/state/rotation.lock"

# Logging function
log_cron() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [CRON] $1" >> "$LOG_FILE"
}

# Change to project directory
cd "$PROJECT_DIR"

# Run daily rotation with error handling
if "$SCRIPT_DIR/rotate-mail-stats.sh" daily >> "$LOG_FILE" 2>&1; then
    log_cron "Daily rotation completed successfully"
    exit 0
else
    log_cron "Daily rotation failed with exit code $?"
    exit 1
fi