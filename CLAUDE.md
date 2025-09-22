# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

### Offline Testing
- `./scripts/run-offline.sh [output-dir]` — Replays sample captures through Zeek for deterministic testing
- `jq '.["protocol","activity","status"]' output/offline/<sample>/mail_activity.log | head` — Inspect JSON output

### Live Capture
- `sudo ./scripts/run-live.sh <interface> [output-dir]` — Capture live mail traffic on network interface
- `FILTER="port 25 or port 587" sudo ./scripts/run-live.sh en0` — Custom port filter for live capture

### Test Environment
- `docker compose -f docker/greenmail/docker-compose.yml up -d` — Start GreenMail test server (SMTP:3025, POP3:3110)
- `docker compose -f docker/greenmail/docker-compose.yml down` — Stop test server

### Protocol Testing Scripts
- `./scripts/test-smtp.sh` — Test SMTP functionality
- `./scripts/test-pop3.sh` — Test POP3 functionality  
- `./scripts/test-mail-protocols.sh` — Comprehensive protocol testing

## Code Architecture

### Core Components
- **zeek-scripts/mail-activity-json.zeek** — Main Zeek script for SMTP/POP3/IMAP monitoring with JSON output
- **scripts/** — Shell utilities for offline replay and live capture
- **pcaps/** — Sample captures for testing (smtp-send.pcap, pop3-receive.pcap)
- **output/** — Generated logs (git-ignored, organized by run type and timestamp)

### Zeek Script Structure
The main Zeek script implements enhanced mail activity monitoring:
- **MailActivity::Info** record — Unified logging schema with SMTP standard fields plus content-focused fields
- **Protocol Support** — SMTP (ports 25,465,587,2525,1025,3025), POP3 (110,995,3110), IMAP (143,993,3143)
- **TLS Monitoring** — Both explicit STARTTLS and implicit TLS connections
- **Session Tracking** — Global tables for smtp_sessions, pop3_sessions, imap_sessions
- **Content Parsing** — Email headers (Subject, From, To, Message-ID) extracted during SMTP DATA and POP3 RETR

### Output Logs
- **mail_activity.log** — Primary JSON log with unified mail activity records
- **pop3.log** — Optional detailed POP3 request/reply log (disabled by default: `enable_pop3_log=F`)

## Zeek Script Development

### Port Configuration
Mail protocol ports are defined in const sets (SMTP_PORTS, POP3_PORTS, IMAP_PORTS) and registered with Zeek analyzers in zeek_init().

### Session Management
- Each connection gets tracked in protocol-specific global tables
- Sessions are cleaned up in connection_state_remove() event
- TLS connections are detected via ssl_established() with both explicit and implicit TLS support

### Content Extraction
- SMTP: Headers parsed during smtp_data() event
- POP3: Headers extracted during pop3_data() event with session state tracking
- All content uses case-insensitive regex patterns for header matching

### Testing Workflow
1. Run offline tests first for deterministic output verification
2. Use GreenMail for controlled integration testing  
3. Validate JSON schema compatibility when adding new fields
4. Update sample pcaps if behavior changes materially

## File Conventions

### Script Standards
- Bash scripts use `set -euo pipefail` and POSIX-compatible syntax
- Uppercase constants (ROOT_DIR, OUTPUT_DIR, FILTER)
- Four-space indentation in Zeek scripts
- Lower_snake_case for new record fields

### Output Organization
- `output/offline/<sample>/` — Offline replay results
- `output/live-<timestamp>/` — Live capture sessions
- Each run creates isolated subdirectory to prevent log mixing
- Root-owned files require manual cleanup: `sudo rm -rf output/problematic-dir`

## Security Notes
- Live capture requires root privileges for network interface access
- Never commit sensitive pcaps — sanitize traces before sharing
- Generated logs in output/ are git-ignored to prevent accidental commits
- Use BPF filters to limit capture scope and reduce noise
- 验证seek文件语法要用 zeek -C