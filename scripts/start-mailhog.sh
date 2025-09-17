#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
COMPOSE_FILE="$PROJECT_ROOT/docker/mailhog/docker-compose.yml"

if ! command -v docker >/dev/null 2>&1; then
  echo "docker command not found. Install Docker Desktop for Mac first." >&2
  exit 1
fi

echo "Starting MailHog (SMTP:1025, WebUI:8025)..."
docker compose -f "$COMPOSE_FILE" up -d

echo "MailHog is running. Open http://localhost:8025 to view captured mail."
