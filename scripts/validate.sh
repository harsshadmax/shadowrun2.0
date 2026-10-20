#!/usr/bin/env bash
# Linux/WSL2 validation: environment, doctor, compile check, full pytest, benchmark. Real output, real exit codes.
# Usage: bash scripts/validate.sh   (writes evidence/validation.log; nothing is pushed anywhere)
cd "$(dirname "$0")/.."
mkdir -p evidence
LOG=evidence/validation.log
PY=.venv/bin/python
: > "$LOG"
say() { printf '\n$ %s\n' "$*" | tee -a "$LOG"; }
run() { say "$*"; "$@" 2>&1 | tee -a "$LOG"; rc=${PIPESTATUS[0]}; echo "[exit code: $rc]" | tee -a "$LOG"; return 0; }

{
  echo "# Shadow-Run validation $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "## Environment"
  uname -a
  grep PRETTY_NAME /etc/os-release
  $PY --version
  docker version --format 'docker server {{.Server.Version}}, client {{.Client.Version}}'
  docker run --rm --entrypoint strace shadowrun-sandbox -V | head -1
  git rev-parse --abbrev-ref HEAD
  git rev-parse --short HEAD
  git status --short | wc -l | xargs echo "uncommitted files:"
} 2>&1 | tee -a "$LOG"

docker rm -f $(docker ps -aq --filter ancestor=shadowrun-sandbox) >/dev/null 2>&1
bash scripts/up.sh 2>&1 | tail -1 | tee -a "$LOG"
run $PY -m shadowrun.cli doctor
run $PY -m compileall -q shadowrun eval agent packages
run $PY -m pip check
run $PY -m shadowrun.cli reset
run $PY -m pytest -q -p no:cacheprovider
run $PY -m shadowrun.cli reset
run $PY -m shadowrun.cli eval --repeats 3
run $PY -m shadowrun.cli audit verify
echo "== done $(date -u +%H:%M:%S)" | tee -a "$LOG"
