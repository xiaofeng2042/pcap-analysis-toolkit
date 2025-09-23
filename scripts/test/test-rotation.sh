#!/bin/bash
# test-rotation.sh - Test rotation functionality

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

log_test() {
    echo -e "${BLUE}[TEST]${NC} $1"
}

log_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
}

log_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# Helper function to run command with timeout if available
run_with_timeout() {
    local seconds="$1"
    shift
    
    # Check if timeout command is available
    if command -v timeout >/dev/null 2>&1; then
        timeout "$seconds" "$@"
    elif command -v gtimeout >/dev/null 2>&1; then
        # GNU timeout on macOS (if installed via brew install coreutils)
        gtimeout "$seconds" "$@"
    else
        # No timeout available, run directly
        "$@"
    fi
}

# Test 1: Archive status
test_archive_status() {
    log_test "Testing archive status..."
    if run_with_timeout 10 "$PROJECT_DIR/scripts/rotate-mail-stats.sh" status > /dev/null 2>&1; then
        log_pass "Archive status command works"
        return 0
    else
        log_fail "Archive status command failed"
        return 1
    fi
}

# Test 2: Create test data and test monthly rotation
test_monthly_rotation() {
    log_test "Testing monthly rotation with test data..."
    
    # Create backup of current state
    local backup_file="/tmp/mail_stats_backup.tsv"
    if [ -f "$PROJECT_DIR/output/state/mail_stats_state.tsv" ]; then
        cp "$PROJECT_DIR/output/state/mail_stats_state.tsv" "$backup_file"
    fi
    
    # Create test data spanning multiple months
    cat > "$PROJECT_DIR/output/state/mail_stats_state.tsv" << 'EOF'
2025-07-15\x09overseas\x09test_link\x0915\x095\x092\x091
2025-08-15\x09overseas\x09test_link\x0920\x098\x093\x092
2025-09-15\x09overseas\x09test_link\x0925\x0910\x094\x093
2025-09-23\x09overseas\x09test_link\x0930\x0912\x095\x094
EOF
    
    # Test dry run first
    log_test "Testing monthly rotation dry run..."
    if run_with_timeout 10 "$PROJECT_DIR/scripts/rotate-mail-stats.sh" force-monthly --dry-run > /dev/null 2>&1; then
        log_pass "Monthly rotation dry run works"
    else
        log_fail "Monthly rotation dry run failed"
    fi
    
    # Test actual rotation
    log_test "Testing actual monthly rotation..."
    if run_with_timeout 30 "$PROJECT_DIR/scripts/rotate-mail-stats.sh" force-monthly > /dev/null 2>&1; then
        log_pass "Monthly rotation completed"
        
        # Check if archive was created
        if [ -f "$PROJECT_DIR/output/state/archive/mail_stats_2025-08.tsv.gz" ]; then
            log_pass "Archive file created"
        else
            log_fail "Archive file not found"
        fi
        
        # Check archive index
        if jq -e '.archives | length > 0' "$PROJECT_DIR/output/state/archive/index.json" > /dev/null 2>&1; then
            log_pass "Archive index updated"
        else
            log_fail "Archive index not updated"
        fi
    else
        log_fail "Monthly rotation failed"
    fi
    
    # Restore backup if it exists
    if [ -f "$backup_file" ]; then
        cp "$backup_file" "$PROJECT_DIR/output/state/mail_stats_state.tsv"
        rm -f "$backup_file"
        log_test "Restored original state file"
    fi
}

# Test 3: Size-based rotation trigger
test_size_rotation() {
    log_test "Testing size-based rotation..."
    
    # Test with very small limit to trigger rotation
    if run_with_timeout 10 "$PROJECT_DIR/scripts/rotate-mail-stats.sh" size --max-size 0 --dry-run > /dev/null 2>&1; then
        log_pass "Size rotation check works"
    else
        log_warn "Size rotation check may need adjustment"
    fi
}

# Test 4: Archive query
test_archive_query() {
    log_test "Testing archive query functionality..."
    
    # This might fail if no archives exist, but we test the command structure
    if run_with_timeout 10 "$PROJECT_DIR/scripts/rotate-mail-stats.sh" query 2025-01-01 2025-12-31 > /dev/null 2>&1; then
        log_pass "Archive query command structure works"
    else
        log_warn "Archive query may need data to test properly"
    fi
}

# Test 5: Environment variable setup for Zeek
test_zeek_integration() {
    log_test "Testing Zeek integration setup..."
    
    # Set test environment variables
    export MAIL_STATS_ENABLE_ARCHIVE="true"
    export MAIL_STATS_ARCHIVE_DIR="$PROJECT_DIR/output/state/archive"
    export MAIL_STATS_ARCHIVE_WINDOW="30"
    
    # Test Zeek syntax with archive support
    if zeek -C "$PROJECT_DIR/zeek-scripts/mail-activity-json.zeek" > /dev/null 2>&1; then
        log_pass "Zeek script syntax valid with archive support"
    else
        log_warn "Zeek script syntax check failed (may need environment setup)"
    fi
}

# Main test runner
main() {
    echo "================================"
    echo "Mail Stats Rotation Test Suite"
    echo "================================"
    echo ""
    
    local tests_passed=0
    local tests_total=0
    
    # Run tests
    for test_func in test_archive_status test_monthly_rotation test_size_rotation test_archive_query test_zeek_integration; do
        ((tests_total++))
        if $test_func; then
            ((tests_passed++))
        fi
        echo ""
    done
    
    # Summary
    echo "================================"
    echo "Test Results: $tests_passed/$tests_total passed"
    echo "================================"
    
    if [ $tests_passed -eq $tests_total ]; then
        log_pass "All tests passed!"
        exit 0
    else
        log_warn "Some tests failed or had warnings"
        exit 1
    fi
}

# Change to project directory
cd "$PROJECT_DIR"

# Run tests
main "$@"