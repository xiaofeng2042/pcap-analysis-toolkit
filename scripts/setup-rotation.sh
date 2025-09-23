#!/bin/bash
# setup-rotation.sh - Setup rotation system

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

log_info() {
    echo -e "${BLUE}[SETUP]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SETUP]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[SETUP]${NC} $1"
}

log_error() {
    echo -e "${RED}[SETUP]${NC} $1"
}

usage() {
    cat << EOF
Usage: $0 [COMMAND]

Commands:
  init          Initialize rotation system (create directories, index)
  cron          Setup cron job for daily rotation
  launchd       Setup macOS LaunchAgent for daily rotation
  test          Run rotation test suite
  env           Show environment variables for Zeek integration
  status        Show current rotation system status
  help          Show this help

Examples:
  $0 init       # Initialize the system
  $0 cron       # Setup cron job
  $0 test       # Run tests
EOF
}

# Initialize rotation system
setup_init() {
    log_info "Initializing rotation system..."
    
    # Create directories
    mkdir -p "$PROJECT_DIR/output/state/archive"
    log_info "Created archive directory"
    
    # Initialize archive index if it doesn't exist
    if [ ! -f "$PROJECT_DIR/output/state/archive/index.json" ]; then
        cat > "$PROJECT_DIR/output/state/archive/index.json" << 'EOF'
{
  "archives": [],
  "last_rotation": null,
  "total_archived_rows": 0,
  "retention_days": 90,
  "max_active_size_mb": 1,
  "rotation_strategy": "monthly",
  "created": "2025-09-23T10:15:00Z",
  "version": "1.0"
}
EOF
        log_info "Created archive index"
    fi
    
    # Test rotation script
    if "$PROJECT_DIR/scripts/rotate-mail-stats.sh" status > /dev/null 2>&1; then
        log_success "Rotation system initialized successfully"
    else
        log_error "Rotation script test failed"
        return 1
    fi
}

# Setup cron job
setup_cron() {
    log_info "Setting up cron job for daily rotation..."
    
    local cron_line="5 0 * * * $PROJECT_DIR/scripts/cron-daily-rotation.sh"
    
    # Check if cron job already exists
    if crontab -l 2>/dev/null | grep -q "cron-daily-rotation.sh"; then
        log_warn "Cron job already exists"
        return 0
    fi
    
    # Add to crontab
    (crontab -l 2>/dev/null; echo "$cron_line") | crontab -
    
    log_success "Cron job added: $cron_line"
    log_info "Daily rotation will run at 00:05"
}

# Setup macOS LaunchAgent
setup_launchd() {
    log_info "Setting up macOS LaunchAgent for daily rotation..."
    
    local plist_src="$PROJECT_DIR/scripts/com.mail-stats.rotation.plist"
    local plist_dst="$HOME/Library/LaunchAgents/com.mail-stats.rotation.plist"
    
    # Copy plist to LaunchAgents directory
    mkdir -p "$HOME/Library/LaunchAgents"
    cp "$plist_src" "$plist_dst"
    
    # Load the agent
    launchctl unload "$plist_dst" 2>/dev/null || true
    launchctl load "$plist_dst"
    
    log_success "LaunchAgent installed and loaded"
    log_info "Daily rotation will run at 00:05"
    log_info "To check status: launchctl list | grep mail-stats"
}

# Run test suite
setup_test() {
    log_info "Running rotation test suite..."
    "$PROJECT_DIR/scripts/test/test-rotation.sh"
}

# Show environment variables
setup_env() {
    cat << EOF
Environment Variables for Zeek Integration:
==========================================

Required for archive support:
export MAIL_STATS_ENABLE_ARCHIVE="true"
export MAIL_STATS_ARCHIVE_DIR="$PROJECT_DIR/output/state/archive"

Optional:
export MAIL_STATS_ARCHIVE_WINDOW="30"  # Days to load from archives

Standard mail stats variables:
export MAIL_STATS_STATE_FILE="$PROJECT_DIR/output/state/mail_stats_state.tsv"
export SITE_ID="overseas"
export LINK_ID="test_link"

Add these to your shell profile or Zeek startup script.
EOF
}

# Show system status
setup_status() {
    log_info "Rotation System Status"
    echo "======================"
    
    # Archive status
    "$PROJECT_DIR/scripts/rotate-mail-stats.sh" status
    
    echo ""
    echo "Automation Status:"
    echo "=================="
    
    # Check cron
    if crontab -l 2>/dev/null | grep -q "cron-daily-rotation.sh"; then
        log_success "Cron job configured"
    else
        log_warn "Cron job not configured"
    fi
    
    # Check LaunchAgent (macOS)
    if [ -f "$HOME/Library/LaunchAgents/com.mail-stats.rotation.plist" ]; then
        if launchctl list | grep -q "mail-stats"; then
            log_success "LaunchAgent configured and running"
        else
            log_warn "LaunchAgent configured but not running"
        fi
    else
        log_info "LaunchAgent not configured"
    fi
    
    # Check log file
    local log_file="$PROJECT_DIR/output/state/rotation.log"
    if [ -f "$log_file" ]; then
        echo ""
        echo "Recent rotation log entries:"
        tail -n 5 "$log_file" 2>/dev/null || log_info "No recent log entries"
    fi
}

# Main function
main() {
    local command="${1:-help}"
    
    case "$command" in
        "init")
            setup_init
            ;;
        "cron")
            setup_cron
            ;;
        "launchd")
            setup_launchd
            ;;
        "test")
            setup_test
            ;;
        "env")
            setup_env
            ;;
        "status")
            setup_status
            ;;
        "help"|*)
            usage
            ;;
    esac
}

# Change to project directory
cd "$PROJECT_DIR"

# Run main function
main "$@"