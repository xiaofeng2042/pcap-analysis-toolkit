# Mail Statistics Rotation System

## Overview

This document describes the mail statistics rotation system that prevents unbounded growth of the TSV state file while maintaining complete historical data through compressed archives.

## Architecture

```
output/state/
├── mail_stats_state.tsv          # Active daily stats (current + recent)
├── archive/                       # Historical data storage
│   ├── mail_stats_2025-08.tsv.gz # Monthly archives (compressed)
│   ├── mail_stats_2025-09.tsv.gz
│   └── index.json                # Archive metadata for fast lookups
└── rotation.lock                  # Prevents concurrent rotations
```

## Quick Start

1. **Initialize the system:**
   ```bash
   ./scripts/setup-rotation.sh init
   ```

2. **Check status:**
   ```bash
   ./scripts/setup-rotation.sh status
   ```

3. **Setup automation (choose one):**
   ```bash
   # For cron-based systems
   ./scripts/setup-rotation.sh cron
   
   # For macOS LaunchAgent
   ./scripts/setup-rotation.sh launchd
   ```

4. **Test the system:**
   ```bash
   ./scripts/setup-rotation.sh test
   ```

## Rotation Triggers

### 1. Monthly Rotation (1st of month)
- Archives previous month's data automatically
- Keeps only current month in active file
- Compresses archived data with gzip

### 2. Retention-Based Rotation (90-day default)
- Removes data older than retention period
- Archives old data before removal
- Configurable retention period

### 3. Size-Based Emergency Rotation (1MB default)
- Triggers when active file exceeds size limit
- Creates emergency archive snapshot
- Starts fresh with current day only

## Manual Operations

### Archive Previous Month
```bash
./scripts/rotate-mail-stats.sh force-monthly
```

### Check Archive Status
```bash
./scripts/rotate-mail-stats.sh status
```

### Query Historical Data
```bash
./scripts/rotate-mail-stats.sh query 2025-08-01 2025-08-31
```

### Dry Run (Preview Changes)
```bash
./scripts/rotate-mail-stats.sh monthly --dry-run
```

### Clean Up Old Archives
```bash
./scripts/rotate-mail-stats.sh cleanup
```

## Zeek Integration

### Enable Archive Support
Set these environment variables before running Zeek:

```bash
export MAIL_STATS_ENABLE_ARCHIVE="true"
export MAIL_STATS_ARCHIVE_DIR="/path/to/output/state/archive"
export MAIL_STATS_ARCHIVE_WINDOW="30"  # Days to load from archives
```

### Environment Variables Summary
```bash
# Required for basic stats
export SITE_ID="overseas"
export LINK_ID="test_link"
export MAIL_STATS_STATE_FILE="/path/to/output/state/mail_stats_state.tsv"

# Archive support (optional)
export MAIL_STATS_ENABLE_ARCHIVE="true"
export MAIL_STATS_ARCHIVE_DIR="/path/to/output/state/archive"
export MAIL_STATS_ARCHIVE_WINDOW="30"
```

### Get Environment Setup
```bash
./scripts/setup-rotation.sh env
```

## Archive Index Format

The `archive/index.json` file contains metadata about all archives:

```json
{
  "archives": [
    {
      "filename": "mail_stats_2025-08.tsv.gz",
      "date_range": ["2025-08-01", "2025-08-31"],
      "row_count": 31,
      "compressed_size_kb": 2,
      "sites": "overseas",
      "created": "2025-09-01T00:05:00Z"
    }
  ],
  "last_rotation": "2025-09-01T00:05:00Z",
  "total_archived_rows": 31,
  "retention_days": 90,
  "max_active_size_mb": 1
}
```

## Automation Setup

### Cron Job (Linux/macOS)
```bash
# Add to crontab (runs daily at 00:05)
5 0 * * * /path/to/scripts/cron-daily-rotation.sh
```

### macOS LaunchAgent
The system includes a LaunchAgent plist file for macOS automation:
```bash
# Install and start
./scripts/setup-rotation.sh launchd

# Check status
launchctl list | grep mail-stats

# Stop
launchctl unload ~/Library/LaunchAgents/com.mail-stats.rotation.plist
```

## Monitoring and Logs

### Rotation Logs
Check `output/state/rotation.log` for rotation history:
```bash
tail -f output/state/rotation.log
```

### Archive Statistics
```bash
# Show detailed archive status
./scripts/rotate-mail-stats.sh status

# Show recent log entries
./scripts/setup-rotation.sh status
```

## Testing

### Run Full Test Suite
```bash
./scripts/test/test-rotation.sh
```

### Test Individual Components
```bash
# Test monthly rotation
./scripts/rotate-mail-stats.sh force-monthly --dry-run

# Test size-based rotation
./scripts/rotate-mail-stats.sh size --max-size 0 --dry-run

# Test archive query
./scripts/rotate-mail-stats.sh query 2025-01-01 2025-12-31
```

## Troubleshooting

### Common Issues

1. **Permission Denied**
   ```bash
   chmod +x scripts/*.sh scripts/test/*.sh scripts/lib/*.sh
   ```

2. **Archive Directory Not Found**
   ```bash
   ./scripts/setup-rotation.sh init
   ```

3. **Rotation Lock File Stuck**
   ```bash
   rm -f output/state/rotation.lock
   ```

4. **Cron Job Not Running**
   ```bash
   # Check cron service is running
   sudo systemctl status cron  # Linux
   sudo launchctl list | grep cron  # macOS
   
   # Check crontab entry
   crontab -l | grep rotation
   ```

### Debug Mode
Run rotation with verbose output:
```bash
./scripts/rotate-mail-stats.sh daily --verbose
```

## Configuration

### Retention Period
Modify `RETENTION_DAYS` in the archive library:
```bash
# Edit scripts/lib/stats-archive.sh
RETENTION_DAYS="${RETENTION_DAYS:-60}"  # 60 days instead of 90
```

### File Size Limit
Modify `MAX_ACTIVE_SIZE_MB`:
```bash
# Edit scripts/lib/stats-archive.sh
MAX_ACTIVE_SIZE_MB="${MAX_ACTIVE_SIZE_MB:-5}"  # 5MB instead of 1MB
```

### Archive Window for Zeek
Set how many days of archived data Zeek should load:
```bash
export MAIL_STATS_ARCHIVE_WINDOW="60"  # Load 60 days from archives
```

## Benefits

- **Performance**: Active TSV stays small for fast Zeek loading
- **History**: Complete audit trail in compressed archives
- **Space Efficiency**: Gzip compression reduces storage ~10x
- **Flexibility**: Multiple rotation triggers for different scenarios
- **Recovery**: Archive index enables quick historical queries
- **Automation**: Set-and-forget daily maintenance

## File Organization

After rotation, your directory structure will look like:
```
output/state/
├── mail_stats_state.tsv (small, recent data only)
├── archive/
│   ├── index.json
│   ├── mail_stats_2025-07.tsv.gz (compressed historical data)
│   ├── mail_stats_2025-08.tsv.gz
│   └── mail_stats_2025-09.tsv.gz
├── rotation.log
└── rotation.lock (temporary)
```

This keeps the active file lean while preserving complete history, preventing the performance degradation seen when tables grow unbounded.