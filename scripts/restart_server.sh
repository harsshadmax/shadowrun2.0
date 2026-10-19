#!/usr/bin/env bash
# Stop whatever listens on the dashboard port, then start a fresh server in the foreground.
cd "$(dirname "$0")/.."
PORT="${1:-8000}"
fuser -k "${PORT}/tcp" >/dev/null 2>&1
sleep 1
exec .venv/bin/python -m shadowrun.cli serve --port "$PORT"
