# Repository Guidelines

## Project Structure & Module Organization
The repository centers on Zeek scripts that capture SMTP and POP3 activity. `zeek-scripts/mail-activity-json.zeek` holds the logging pipeline and is the only Zeek module to extend. Operational helpers live under `scripts/`: offline runs process bundled traces, while live captures depend on an interface argument. Sample traffic for regression checks is stored in `pcaps/`, and optional GreenMail fixtures reside in `docker/greenmail/`. Generated artifacts must stay under `output/`; each run should create its own subdirectory to keep JSON logs isolated and git-ignored.

## Build, Test, and Development Commands
- `./scripts/run-offline.sh [output-dir]` — Replays `pcaps/*.pcap` through Zeek and writes JSON to `output/offline/<sample>/mail_activity.log`.
- `sudo ./scripts/run-live.sh <iface> [output-dir]` — Starts a capture on the chosen interface using the default mail BPF. Set `FILTER="..."` for custom ports.
- `docker compose -f docker/greenmail/docker-compose.yml up -d` — Boots the demo SMTP/POP3 stack (ports 3025/3110) for controlled integration tests.
Inspect logs with `jq '.["protocol","activity","status"]' output/.../mail_activity.log | head`.

## Coding Style & Naming Conventions
Zeek code uses four-space indentation and places public definitions at the top of the module. Extend the exported `Info` record instead of introducing parallel logs, and prefer lower_snake_case for new fields. Bash utilities follow `set -euo pipefail`, uppercase constants (e.g., `ROOT_DIR`), and POSIX-compatible syntax. Keep comments concise, mirroring the existing bilingual tone only when necessary.

## Testing Guidelines
Every change affecting parsing or logging must exercise both SMTP and POP3 flows. Run the offline replay first to ensure deterministic output, then live-capture or re-use the GreenMail stack when the change touches TLS or command sequencing. Validate that new fields appear in `mail_activity.log` and that existing keys remain JSON-compatible. Update or add sample pcaps if behavior changes materially, and document verification steps in the PR.

## Commit & Pull Request Guidelines
Commits follow conventional commit syntax (`feat(scripts): ...`, `fix(zeek-scripts): ...`). Keep subject lines under 72 characters and write bodies that explain protocol or logging impact. Pull requests should link related issues, describe reproduction steps, attach relevant log excerpts, and call out any required root privileges or environment variables. Include before/after samples when altering JSON layout to simplify reviewer diffing.

## Security & Capture Tips
Live capture requires `sudo`; keep permissions tidy by running commands from a user-owned `output/` directory and cleaning up root-owned artifacts manually. Never check sensitive pcaps into the repo—sanitize trace files before sharing by trimming payloads or anonymizing addresses.
