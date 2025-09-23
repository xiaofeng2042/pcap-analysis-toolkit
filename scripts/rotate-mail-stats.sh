#!/bin/bash
# rotate-mail-stats.sh - Main rotation script for mail statistics
# Supports monthly, retention-based, and size-based rotation triggers

set -euo pipefail

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Source the archive library
source "$SCRIPT_DIR/lib/stats-archive.sh"

# Configuration
STATS_FILE="${PROJECT_DIR}/output/state/mail_stats_state.tsv"
LOCK_FILE="${PROJECT_DIR}/output/state/rotation.lock"
LOG_FILE="${PROJECT_DIR}/output/state/rotation.log"

# Usage information
usage() {
    cat << EOF
Usage: $0 [COMMAND] [OPTIONS]

Commands:
  monthly           Perform monthly rotation (archive previous month)
  retention         Rotate based on retention policy (remove old data)
  size              Check and rotate if file size exceeds limit
  daily             Run daily maintenance (all checks)
  force-monthly     Force monthly rotation regardless of date
  status            Show archive status
  query START END   Query archives for date range (YYYY-MM-DD format)
  cleanup           Clean up old archives beyond retention
  help              Show this help

Options:
  --dry-run         Show what would be done without executing
  --verbose         Enable verbose output
  --retention DAYS  Override retention days (default: 90)
  --max-size MB     Override max size in MB (default: 1)

Examples:
  $0 daily                        # Run daily maintenance
  $0 monthly --dry-run           # Preview monthly rotation
  $0 query 2025-08-01 2025-08-31 # Query August data
  $0 status                      # Show archive status
EOF
}

# Logging
log_rotation() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

# Lock management
acquire_lock() {
    if [ -f "$LOCK_FILE" ]; then
        local lock_pid=$(cat "$LOCK_FILE" 2>/dev/null || echo "")
        if [ -n "$lock_pid" ] && kill -0 "$lock_pid" 2>/dev/null; then
            log_error "Rotation already in progress (PID: $lock_pid)"
            exit 1
        else
            log_warn "Removing stale lock file"
            rm -f "$LOCK_FILE"
        fi
    fi
    
    echo $$ > "$LOCK_FILE"
    trap 'rm -f "$LOCK_FILE"' EXIT
}

# Remove old data from active file
trim_active_file() {
    local cutoff_date="$1"
    local temp_file=$(mktemp)
    
    log_info "Trimming active file: removing data before $cutoff_date"
    
    if [ ! -f "$STATS_FILE" ]; then
        log_warn "Stats file not found: $STATS_FILE"
        return 0
    fi
    
    # Keep only rows from cutoff date onwards
    sed 's/\\x09/\t/g' "$STATS_FILE" | while IFS=$'\t' read -r date_field site_id link_id send_count receive_count encrypt_count decrypt_count; do
        if [ -n "$date_field" ] && [ "$date_field" ">=" "$cutoff_date" ]; then
            printf "%s\\x09%s\\x09%s\\x09%s\\x09%s\\x09%s\\x09%s\n" "$date_field" "$site_id" "$link_id" "$send_count" "$receive_count" "$encrypt_count" "$decrypt_count"
        fi
    done > "$temp_file"
    
    local before_rows=$(wc -l < "$STATS_FILE" 2>/dev/null || echo "0")
    local after_rows=$(wc -l < "$temp_file")
    local removed_rows=$((before_rows - after_rows))
    
    if [ "$removed_rows" -gt 0 ]; then
        mv "$temp_file" "$STATS_FILE"
        log_success "Trimmed $removed_rows rows from active file"
    else
        rm -f "$temp_file"
        log_info "No rows to trim"
    fi
}

# Monthly rotation
rotate_monthly() {
    local dry_run="$1"
    local force="$2"
    
    log_rotation "Starting monthly rotation check"
    
    if [ "$force" != "true" ] && ! should_rotate "$STATS_FILE" "monthly"; then
        log_info "Monthly rotation not needed"
        return 0
    fi
    
    # Determine previous month
    local current_month=$(date +%Y-%m)
    local prev_month
    if [ "$(date +%m)" = "01" ]; then
        # January - previous month is December of last year
        prev_month=$(date -d "last month" +%Y-%m 2>/dev/null || date -j -v-1m +%Y-%m)
    else
        prev_month=$(date -d "last month" +%Y-%m 2>/dev/null || date -j -v-1m +%Y-%m)
    fi
    
    local start_date="${prev_month}-01"
    local end_date="${prev_month}-31"  # Will be filtered correctly by date comparison
    local archive_name="mail_stats_${prev_month}"
    
    log_info "Monthly rotation: archiving $prev_month data"
    
    if [ "$dry_run" = "true" ]; then
        log_info "[DRY RUN] Would create archive: $archive_name"
        log_info "[DRY RUN] Would archive date range: $start_date to $end_date"
        return 0
    fi
    
    # Create archive for previous month
    if create_archive "$STATS_FILE" "$start_date" "$end_date" "$archive_name"; then
        # Remove archived data from active file
        local keep_from_date="${current_month}-01"
        trim_active_file "$keep_from_date"
        log_success "Monthly rotation completed"
    else
        log_error "Monthly rotation failed"
        return 1
    fi
}

# Retention-based rotation
rotate_retention() {
    local dry_run="$1"
    local retention_days="$2"
    
    log_rotation "Starting retention rotation check (${retention_days} days)"
    
    if ! should_rotate "$STATS_FILE" "retention"; then
        log_info "Retention rotation not needed"
        return 0
    fi
    
    local cutoff_date=$(date -d "$retention_days days ago" +%Y-%m-%d 2>/dev/null || date -j -v-${retention_days}d +%Y-%m-%d)
    local cutoff_month=$(echo "$cutoff_date" | cut -d'-' -f1,2)
    local archive_name="mail_stats_${cutoff_month}_retention"
    
    log_info "Retention rotation: archiving data older than $cutoff_date"
    
    if [ "$dry_run" = "true" ]; then
        log_info "[DRY RUN] Would archive data older than: $cutoff_date"
        log_info "[DRY RUN] Would create archive: $archive_name"
        return 0
    fi
    
    # Archive old data
    if create_archive "$STATS_FILE" "1900-01-01" "$cutoff_date" "$archive_name"; then
        # Remove archived data from active file
        trim_active_file "$cutoff_date"
        log_success "Retention rotation completed"
    else
        log_error "Retention rotation failed"
        return 1
    fi
}

# Size-based rotation
rotate_size() {
    local dry_run="$1"
    local max_size_mb="$2"
    
    log_rotation "Starting size rotation check (${max_size_mb}MB limit)"
    
    if ! should_rotate "$STATS_FILE" "size"; then
        log_info "Size rotation not needed"
        return 0
    fi
    
    local current_size=$(get_file_size_mb "$STATS_FILE")
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local archive_name="mail_stats_emergency_${timestamp}"
    
    log_warn "File size ($current_size MB) exceeds limit ($max_size_mb MB)"
    
    if [ "$dry_run" = "true" ]; then
        log_info "[DRY RUN] Would create emergency archive: $archive_name"
        log_info "[DRY RUN] Would keep only current day in active file"
        return 0
    fi
    
    # Archive everything except current day
    local today=$(date +%Y-%m-%d)
    local yesterday=$(date -d "1 day ago" +%Y-%m-%d 2>/dev/null || date -j -v-1d +%Y-%m-%d)
    
    if create_archive "$STATS_FILE" "1900-01-01" "$yesterday" "$archive_name"; then
        # Keep only today's data
        trim_active_file "$today"
        log_success "Emergency size rotation completed"
    else
        log_error "Size rotation failed"
        return 1
    fi
}

# Daily maintenance
run_daily() {
    local dry_run="$1"
    local retention_days="$2"
    local max_size_mb="$3"
    
    log_rotation "Starting daily maintenance"
    
    # Check in order: size, retention, monthly
    rotate_size "$dry_run" "$max_size_mb"
    rotate_retention "$dry_run" "$retention_days"
    rotate_monthly "$dry_run" "false"
    
    # Cleanup old archives
    if [ "$dry_run" != "true" ]; then
        cleanup_old_archives
    fi
    
    log_rotation "Daily maintenance completed"
}

# Query archives
query_archives_range() {
    local start_date="$1"
    local end_date="$2"
    
    log_info "Querying archives for range: $start_date to $end_date"
    
    local archives=$(query_archives "$start_date" "$end_date")
    
    if [ -n "$archives" ]; then
        echo "Found data in archives:"
        while read -r archive; do
            echo "  $archive"
            extract_archive_data "$archive" "$start_date" "$end_date"
        done <<< "$archives"
    else
        log_info "No archived data found for date range"
    fi
    
    # Also check active file
    if [ -f "$STATS_FILE" ]; then
        echo ""
        echo "Active file data:"
        sed 's/\\x09/\t/g' "$STATS_FILE" | while IFS=$'\t' read -r date_field site_id link_id send_count receive_count encrypt_count decrypt_count; do
            if [ -n "$date_field" ] && [ "$date_field" ">=" "$start_date" ] && [ "$date_field" "<=" "$end_date" ]; then
                printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\n" "$date_field" "$site_id" "$link_id" "$send_count" "$receive_count" "$encrypt_count" "$decrypt_count"
            fi
        done
    fi
}

# Main script
main() {
    local command="${1:-help}"
    local dry_run="false"
    local verbose="false"
    local retention_days="$RETENTION_DAYS"
    local max_size_mb="$MAX_ACTIVE_SIZE_MB"
    
    # Parse options
    shift || true
    while [[ $# -gt 0 ]]; do
        case $1 in
            --dry-run)
                dry_run="true"
                shift
                ;;
            --verbose)
                verbose="true"
                shift
                ;;
            --retention)
                retention_days="$2"
                shift 2
                ;;
            --max-size)
                max_size_mb="$2"
                shift 2
                ;;
            *)
                break
                ;;
        esac
    done
    
    # Initialize archive
    init_archive
    
    case "$command" in
        "monthly")
            acquire_lock
            rotate_monthly "$dry_run" "false"
            ;;
        "force-monthly")
            acquire_lock
            rotate_monthly "$dry_run" "true"
            ;;
        "retention")
            acquire_lock
            rotate_retention "$dry_run" "$retention_days"
            ;;
        "size")
            acquire_lock
            rotate_size "$dry_run" "$max_size_mb"
            ;;
        "daily")
            acquire_lock
            run_daily "$dry_run" "$retention_days" "$max_size_mb"
            ;;
        "status")
            show_archive_status
            ;;
        "query")
            if [ $# -lt 2 ]; then
                log_error "Query requires start and end dates (YYYY-MM-DD)"
                exit 1
            fi
            query_archives_range "$1" "$2"
            ;;
        "cleanup")
            acquire_lock
            cleanup_old_archives
            ;;
        "help"|*)
            usage
            ;;
    esac
}

# Initialize archive directory if it doesn't exist
mkdir -p "$(dirname "$STATS_FILE")"
mkdir -p "$(dirname "$LOG_FILE")"

# Run main function
main "$@"