#!/usr/bin/env bash
# Vendor pinned front-end libraries so the dashboard works offline.
set -e
cd "$(dirname "$0")/.."
mkdir -p dashboard/static/vendor
curl -fsSL -o dashboard/static/vendor/htmx.min.js https://cdn.jsdelivr.net/npm/htmx.org@1.9.12/dist/htmx.min.js
curl -fsSL -o dashboard/static/vendor/chart.umd.js https://cdn.jsdelivr.net/npm/chart.js@4.4.3/dist/chart.umd.js
sha256sum dashboard/static/vendor/*
