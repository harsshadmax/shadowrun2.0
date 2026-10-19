#!/usr/bin/env bash
docker rm -f sink >/dev/null 2>&1 || true
pkill -f "pypi-server run" || true
echo "down"
