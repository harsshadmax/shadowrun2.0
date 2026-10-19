#!/usr/bin/env bash
# Prebuild images, create the internal network, start sink + pypiserver.
set -e
cd "$(dirname "$0")/.."
docker info >/dev/null 2>&1 || { sudo -n service docker start >/dev/null 2>&1 || true; sleep 3; }
docker build -q -t shadowrun-sandbox -f docker/sandbox.Dockerfile docker
docker build -q -t shadowrun-sink sink
docker network inspect shadowrun_net >/dev/null 2>&1 || docker network create --internal shadowrun_net >/dev/null
mkdir -p .data/sink packages/dist
docker rm -f sink >/dev/null 2>&1 || true
docker run -d --name sink --network shadowrun_net --user "$(id -u):$(id -g)" \
  --read-only --cap-drop ALL --security-opt no-new-privileges:true \
  -v "$PWD/.data/sink:/data" shadowrun-sink >/dev/null
if ! curl -fs http://127.0.0.1:8080/ >/dev/null 2>&1; then
  nohup .venv/bin/pypi-server run -i 127.0.0.1 -p 8080 -a . -P . packages/dist >.data/pypi.log 2>&1 &
  sleep 2
fi
echo "up: sink + pypiserver started"
